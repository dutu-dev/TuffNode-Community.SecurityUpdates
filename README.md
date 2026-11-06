# TuffNode Community Security Updates

This public repository distributes **signed security patch releases** for TuffNode Community.

It is a distribution channel, not a trust root. The TuffNode client must verify the detached signature of every manifest with a public key embedded in the application before it trusts release metadata or downloads a patch package.

## Release asset contract

Every published GitHub Release must contain exactly one current patch set with these assets:

- `manifest.json` — UTF-8 security update manifest.
- `manifest.sig` — Base64-encoded RSA-PSS/SHA-256 signature over the exact bytes of `manifest.json`.
- The package asset named by `manifest.json.package.assetName` — ZIP archive containing `patch.json` and the declared payload files.

The manifest schema is in [schemas/manifest.schema.json](schemas/manifest.schema.json). The package descriptor is in [schemas/patch.schema.json](schemas/patch.schema.json).

## Trust and signing

- The client pins one or more public signing keys and key IDs in its shipped code.
- The private signing key must be generated and kept offline. **Never commit it, upload it as a repository file, or place it in a public Actions artifact.**
- A manifest is signed as raw bytes. Do not reformat, reserialize, or normalize it after signing.
- The signature authenticates the manifest; the signed SHA-256 digest authenticates the package bytes.
- Key rotation must be delivered by an application release trusted by the currently pinned key. A new key cannot authorize itself.

## Patch safety contract

Patch packages are declarative. They may only add, replace, or delete explicitly listed files beneath the TuffNode application installation directory.

Packages must not contain executable scripts, commands, symbolic links, hard links, reparse points, absolute paths, traversal paths, alternate data stream syntax, or undeclared archive entries. The client validates all paths, sizes, hashes, compatibility constraints, and current-file preconditions before installation.

A client downloads and verifies a patch automatically, but **must ask the user for explicit approval before applying it**. Installation runs unattended after approval. Application binaries are applied through a staged transaction and require an application restart; no separate installer window is shown. Failed transactions must roll back.

## Release sequence

Each manifest has a monotonically increasing `sequence`. Clients persist the highest successfully applied sequence and reject older releases. A patch must declare the supported application version range and a unique `patchId`.

No patch should be published until the package has passed schema validation, signature verification, archive/path validation, compatibility tests, and a clean application build.
