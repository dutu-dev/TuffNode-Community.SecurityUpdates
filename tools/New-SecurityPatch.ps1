[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PatchDescriptorPath,

    [Parameter(Mandatory = $true)]
    [string]$PayloadRoot,

    [Parameter(Mandatory = $true)]
    [string]$PatchId,

    [Parameter(Mandatory = $true)]
    [long]$Sequence,

    [Parameter(Mandatory = $true)]
    [string]$MinimumAppVersion,

    [Parameter(Mandatory = $true)]
    [string]$MaximumAppVersion,

    [Parameter(Mandatory = $true)]
    [ValidateSet("low", "moderate", "high", "critical")]
    [string]$Severity,

    [Parameter(Mandatory = $true)]
    [string]$Title,

    [Parameter(Mandatory = $true)]
    [string]$Summary,

    [string]$ReleaseNotes = "",

    [Parameter(Mandatory = $true)]
    [string]$PrivateKeyPath,

    [string]$OpenSslPath = "openssl"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$KeyId = "tuffnode-security-2026-rsa3072-v1"
$MaximumFileBytes = 50MB
$MaximumPackageBytes = 100MB
$ForbiddenExtensions = @(".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".com", ".msi", ".msp", ".vbs", ".js", ".hta", ".lnk", ".url", ".reg", ".scr", ".sys")
$ForbiddenDirectories = @("PatchRunner", "SecurityPatches", "servers", "backups", "logs", "user-data", "userdata", ".tuffnode-patch-staging")

function Assert-Version([string]$Value, [string]$Name) {
    if ($Value -notmatch '^\d+\.\d+\.\d+$') {
        throw "$Name must use MAJOR.MINOR.PATCH format."
    }
}

function Assert-SafeRelativePath([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value.Length -gt 240 -or
        $Value.StartsWith("/") -or
        $Value.Contains("\") -or
        $Value.Contains(":") -or
        $Value -match '[\x00-\x1f\x7f]') {
        throw "Unsafe patch path: $Value"
    }

    $segments = $Value.Split("/")
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment) -or
            $segment -in @(".", "..") -or
            $segment.EndsWith(".") -or
            $segment.EndsWith(" ")) {
            throw "Unsafe patch path segment in: $Value"
        }

        $deviceName = ($segment -split "\.")[0]
        if ($deviceName -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            throw "Reserved Windows device name in patch path: $Value"
        }
    }

    if ($segments[0] -in $ForbiddenDirectories -or
        [IO.Path]::GetExtension($segments[-1]) -in $ForbiddenExtensions -or
        $segments[-1] -ieq "TuffNode.PatchRunner.exe") {
        throw "Patch path is outside the application-owned allowlist: $Value"
    }
}

function Assert-NoReparsePoint([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse points are not permitted in patch source paths: $current"
            }
        }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) { break }
        $current = $parent
    }
}

Assert-Version $MinimumAppVersion "MinimumAppVersion"
Assert-Version $MaximumAppVersion "MaximumAppVersion"

if ($PatchId -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]{2,79}$') {
    throw "PatchId must be 3-80 characters and contain only letters, numbers, dot, underscore or hyphen."
}
if ($Sequence -lt 1) { throw "Sequence must be a positive integer." }
if ($Title.Length -lt 1 -or $Title.Length -gt 120) { throw "Title must be 1-120 characters." }
if ($Summary.Length -lt 1 -or $Summary.Length -gt 1000) { throw "Summary must be 1-1000 characters." }
if ($ReleaseNotes.Length -gt 10000) { throw "ReleaseNotes cannot exceed 10000 characters." }

$PatchDescriptorPath = (Resolve-Path -LiteralPath $PatchDescriptorPath).Path
$PayloadRoot = (Resolve-Path -LiteralPath $PayloadRoot).Path
$PrivateKeyPath = (Resolve-Path -LiteralPath $PrivateKeyPath).Path
Assert-NoReparsePoint $PatchDescriptorPath
Assert-NoReparsePoint $PayloadRoot
Assert-NoReparsePoint $PrivateKeyPath

$descriptor = Get-Content -LiteralPath $PatchDescriptorPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($descriptor.schemaVersion -ne 1 -or
    $descriptor.patchId -cne $PatchId -or
    [long]$descriptor.sequence -ne $Sequence -or
    $null -eq $descriptor.operations -or
    $descriptor.operations.Count -lt 1 -or
    $descriptor.operations.Count -gt 512) {
    throw "patch.json does not match the requested patch ID/sequence or operation limits."
}

$seenPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$payloadFiles = [Collections.Generic.List[object]]::new()
$totalExpandedBytes = 0L

foreach ($operation in $descriptor.operations) {
    Assert-SafeRelativePath ([string]$operation.path)
    if (-not $seenPaths.Add([string]$operation.path)) {
        throw "Duplicate patch destination: $($operation.path)"
    }

    switch ([string]$operation.operation) {
        "replace" {
            if ($operation.expectedCurrentSha256 -notmatch '^[a-fA-F0-9]{64}$' -or
                $operation.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or
                [long]$operation.sizeBytes -lt 1 -or
                [long]$operation.sizeBytes -gt $MaximumFileBytes) {
                throw "Invalid replace operation: $($operation.path)"
            }
        }
        "add" {
            if ($null -ne $operation.expectedCurrentSha256 -or
                $operation.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or
                [long]$operation.sizeBytes -lt 1 -or
                [long]$operation.sizeBytes -gt $MaximumFileBytes) {
                throw "Invalid add operation: $($operation.path)"
            }
        }
        "delete" {
            if ($operation.expectedCurrentSha256 -notmatch '^[a-fA-F0-9]{64}$' -or
                $null -ne $operation.sha256 -or
                $null -ne $operation.sizeBytes) {
                throw "Invalid delete operation: $($operation.path)"
            }
        }
        default {
            throw "Unsupported patch operation: $($operation.operation)"
        }
    }

    if ($operation.operation -in @("replace", "add")) {
        $relativePayloadPath = [string]$operation.path -replace "/", [IO.Path]::DirectorySeparatorChar
        $payloadPath = Join-Path $PayloadRoot $relativePayloadPath
        if (-not (Test-Path -LiteralPath $payloadPath -PathType Leaf)) {
            throw "Missing payload file: $payloadPath"
        }
        Assert-NoReparsePoint $payloadPath

        $payloadInfo = Get-Item -LiteralPath $payloadPath -Force
        if ($payloadInfo.Length -ne [long]$operation.sizeBytes -or $payloadInfo.Length -gt $MaximumFileBytes) {
            throw "Payload size mismatch: $($operation.path)"
        }

        $payloadHash = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($payloadHash -ne ([string]$operation.sha256).ToLowerInvariant()) {
            throw "Payload SHA-256 mismatch: $($operation.path)"
        }

        $totalExpandedBytes += $payloadInfo.Length
        $payloadFiles.Add([pscustomobject]@{ RelativePath = [string]$operation.path; FullPath = $payloadPath })
    }
}

if ($totalExpandedBytes -gt $MaximumPackageBytes) {
    throw "Expanded payload exceeds the 100 MiB package limit."
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$repoRoot = Split-Path -Parent $PSScriptRoot
$publicKeyPath = Join-Path $repoRoot "keys\security-updates-rsa-public.pem"
if (-not (Test-Path -LiteralPath $publicKeyPath -PathType Leaf)) {
    throw "Pinned public key is missing: $publicKeyPath"
}

$outputDirectory = Join-Path $repoRoot ("dist\" + $PatchId)
if (Test-Path -LiteralPath $outputDirectory) {
    Remove-Item -LiteralPath $outputDirectory -Recurse -Force
}
New-Item -ItemType Directory -Path $outputDirectory | Out-Null

$packageAssetName = "security-patch-$Sequence.zip"
$packagePath = Join-Path $outputDirectory $packageAssetName
$manifestPath = Join-Path $outputDirectory "manifest.json"
$signaturePath = Join-Path $outputDirectory "manifest.sig"
$signatureBinaryPath = Join-Path $outputDirectory "manifest.sig.bin"

$fileStream = [IO.File]::Open($packagePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
$archive = [IO.Compression.ZipArchive]::new($fileStream, [IO.Compression.ZipArchiveMode]::Create, $false)
try {
    $descriptorEntry = $archive.CreateEntry("patch.json", [IO.Compression.CompressionLevel]::Optimal)
    $descriptorStream = $descriptorEntry.Open()
    try {
        $descriptorBytes = [IO.File]::ReadAllBytes($PatchDescriptorPath)
        $descriptorStream.Write($descriptorBytes, 0, $descriptorBytes.Length)
    }
    finally {
        $descriptorStream.Dispose()
    }

    foreach ($payload in $payloadFiles) {
        $entryName = "payload/" + $payload.RelativePath
        $entry = $archive.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
        $entryStream = $entry.Open()
        $sourceStream = [IO.File]::OpenRead($payload.FullPath)
        try {
            $sourceStream.CopyTo($entryStream)
        }
        finally {
            $sourceStream.Dispose()
            $entryStream.Dispose()
        }
    }
}
finally {
    $archive.Dispose()
}

$packageInfo = Get-Item -LiteralPath $packagePath
if ($packageInfo.Length -lt 1 -or $packageInfo.Length -gt $MaximumPackageBytes) {
    throw "Compressed patch package exceeds the 100 MiB limit."
}
$packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
$now = [DateTimeOffset]::UtcNow
$manifest = [ordered]@{
    schemaVersion = 1
    product = "TuffNode.Community"
    channel = "stable"
    patchId = $PatchId
    sequence = $Sequence
    issuedAtUtc = $now.ToString("yyyy-MM-ddTHH:mm:ssZ", [Globalization.CultureInfo]::InvariantCulture)
    expiresAtUtc = $now.AddDays(60).ToString("yyyy-MM-ddTHH:mm:ssZ", [Globalization.CultureInfo]::InvariantCulture)
    signingKeyId = $KeyId
    minimumAppVersion = $MinimumAppVersion
    maximumAppVersion = $MaximumAppVersion
    severity = $Severity
    title = $Title
    summary = $Summary
    releaseNotes = $ReleaseNotes
    requiresRestart = $true
    package = [ordered]@{
        assetName = $packageAssetName
        sizeBytes = [long]$packageInfo.Length
        sha256 = $packageHash
        contentType = "application/zip"
    }
}

$manifestJson = $manifest | ConvertTo-Json -Depth 10
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($manifestPath, $manifestJson, $utf8NoBom)

& $OpenSslPath dgst -sha256 -sign $PrivateKeyPath -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -out $signatureBinaryPath $manifestPath
if ($LASTEXITCODE -ne 0) {
    throw "OpenSSL failed to sign the manifest."
}

& $OpenSslPath dgst -sha256 -verify $publicKeyPath -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -signature $signatureBinaryPath $manifestPath
if ($LASTEXITCODE -ne 0) {
    throw "Local signature verification failed."
}

$signatureBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($signatureBinaryPath))
[IO.File]::WriteAllText($signaturePath, $signatureBase64, [System.Text.Encoding]::ASCII)
Remove-Item -LiteralPath $signatureBinaryPath -Force

Write-Host ""
Write-Host "Security patch package created and locally verified:"
Write-Host "  $outputDirectory"
Write-Host ""
Write-Host "Create a GitHub Release with tag: security-$Sequence-$PatchId"
Write-Host "Upload exactly these assets:"
Write-Host "  manifest.json"
Write-Host "  manifest.sig"
Write-Host "  $packageAssetName"
Write-Host ""
Write-Warning "Keep the private signing key offline. Never commit or upload it."
