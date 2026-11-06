# Security patch package format

A release package is a ZIP archive with this exact logical layout:

```text
patch.zip
├── patch.json
└── payload/
    ├── TuffNode.App.dll
    └── ...
```

The archive must contain `patch.json` plus exactly the payload files referenced by its `operations`. Undeclared entries are rejected.

## Operations

- `replace`: replace an existing application-owned file. The descriptor must include the expected SHA-256 of the currently installed file and the SHA-256 and byte length of the replacement.
- `add`: create a new application-owned file. The destination must not already exist.
- `delete`: remove an existing application-owned file only when its current SHA-256 matches `expectedCurrentSha256`.

Payload entry names are derived as `payload/{path}`; a descriptor cannot supply an external URL or an arbitrary source path.

## Mandatory client validation

Before staging, the client must:

1. Verify the detached manifest signature against a pinned public key.
2. Validate the manifest schema, product, channel, patch sequence, timestamps, app version range, and package size.
3. Verify the complete package SHA-256 and byte length.
4. Reject duplicate ZIP entry names, case-insensitive path collisions, traversal, rooted paths, drive/UNC paths, alternate data streams, reserved Windows device names, control characters, symlinks, reparse points, and hard-link metadata.
5. Enforce archive entry-count, per-file, total-expanded-size, and compression-ratio limits.
6. Validate `patch.json` and require exact correspondence between declared operations and ZIP payload entries.
7. Verify every payload hash and size, plus every expected-current-file hash.
8. Restrict all destinations to the verified application installation root. User data, server directories, settings, logs, update-host binaries, and files outside the application root are not patch targets.

## Installation transaction

The client stages verified files in an app-private directory with user-only access. After explicit user approval, a minimal updater host waits for the main process to exit, applies only the validated operations, and records each completed operation in a transaction journal. Existing files are backed up before replacement. Any failure triggers rollback in reverse order.

The updater host runs with the current user's token. It never requests elevation silently and never executes package-provided commands or scripts. If the installation directory is not writable, installation fails safely and asks the user to use the normal installer or an explicitly elevated maintenance path.

The main application restarts and reads the transaction result. Progress and status are presented in the TuffNode interface; the updater host has no separate installer UI.
