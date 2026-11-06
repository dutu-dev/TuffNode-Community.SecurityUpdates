# Security policy

Do not open public issues containing exploit details, private signing material, access tokens, or unpublished patch payloads.

The security update channel is fail-closed. The client verifies the RSA-PSS/SHA-256 signature against a public key pinned in the application before trusting the manifest. Package hashes, operation preconditions, archive entries and destination paths are independently validated by the client and updater host.

The RSA private signing key is an offline release secret. It must never be committed, uploaded to a release, added to CI secrets, or included in build artifacts. If compromise is suspected, stop publishing patches and prepare a new client release with a rotated trust key.
