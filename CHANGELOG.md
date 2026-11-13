# Changelog

All notable changes to goraz are listed here. Versions follow [Semantic Versioning](https://semver.org/). Before version 1, a minor release may change the Go API or command-line flags, and every such change is listed. The v1 file format is frozen by golden tests, and no release has changed it.

## [Unreleased]

### Breaking changes

- `password.HIBP` and `password.NewHIBP` moved to the new package `password/hibp`, as `hibp.Client` and `hibp.New`. Programs that don't check passwords against Have I Been Pwned no longer link `net/http`.
- `vault.CreateOptions.Profile`, `vault.RekeyOptions.Profile` and `Vault.ChangePassphrase` take the new public type `vault.Profile`. Before, callers outside the module could only get the default profile.
- `vault.Options.State` is replaced by `vault.Options.Memory`, of the new type `vault.MemoryState`.
- `vault.VaultIDFromFile` is renamed `vault.IDFromFile`.
- The command line exits with code 2 for wrong usage, and refuses arguments a command doesn't take.

### Added

- Exported errors to check with `errors.Is`: `vault.ErrNotVault`, `vault.ErrInvalidInput`, `vault.ErrNotDurable`, `vault.ErrUnknownProfile`, `token.ErrInvalidArgument`, `audit.ErrInvalidEvent`, `service.ErrInvalidOptions` and `service.ErrUnsafeKeyFile`.
- `vault.IDSize`, `token.IDSize` and runnable examples for every public package.

### Changed

- Waiting for a lock gives up after 10 seconds instead of waiting forever.
- New directories, and the directory of a new audit log, are synced, so they survive a power loss. An existing state directory must be owned by the user and not writable by others.
- After a failed sync, the audit log refuses further writes in that process. A write that fails after its audit entry adds a "failed" entry.
- `goraz export` creates its file in one step, so it can never replace an existing file or follow a symlink.
- `goraz run --env-file` reads at most 1 MiB.
- Token names can't contain control characters.
- The command-line binary runs with data-independent timing on CPUs that support it.

### Fixed

- The Docker guide mounted the service file as a single file. A single-file bind mount never sees `service sync` replace the file, so a running container silently kept old data. The guide now mounts a directory, and explains how file-backed Compose secrets keep their host owner and mode.

### Performance

- `audit.JSONSink.Record` makes no allocations, down from 5.
- `vault.Get` makes about 97% fewer allocations, because a process verifies only new audit entries after its first full check.
- Verifying a token makes 30% fewer allocations, and verifying from a service file makes 48% fewer.
- Parsing a token makes 2 allocations instead of 11, and no longer passes the secret through `math/big` or a string.

### Tests

- Wycheproof vectors for XChaCha20-Poly1305, HKDF-SHA-256 and HMAC-SHA-256, the Argon2id reference vectors, and frozen outputs for every goraz key derivation.
- A corpus of damaged vault files, each with its expected error, which also seeds fuzzing.
- New fuzz targets for state files, rollback decisions and padding.
- Allocation budgets for the hot paths, and module-wide checks of dependencies, the public API and examples.

## [0.1.1] - 2026-11-12

### Security

- Release binaries are built with Go 1.27.4, which fixes GO-2026-6859 (CVE-2026-97054) in `net/http`. goraz runs no HTTP server: its only use of `net/http` is the opt-in breach check, `goraz report --hibp`.

### Changed

- The module requires Go 1.26.11 or later, so programs that import goraz also build with a fixed standard library.
- The documentation site has a new layout, and the README names the author.

## [0.1.0] - 2026-11-06

The first public release.

### Added

- An encrypted vault with hidden metadata, version history, and tamper, rollback and fork detection.
- Per-service encrypted files, with a runtime client that reloads changed files, fails closed when data is stale, and supports key rotation without an outage.
- Issuing, verifying, revoking and rotating API tokens, with only a keyed hash stored.
- Passwords, passphrases, TOTP and HOTP, automatic clipboard clearing and an opt-in breach check.
- A hash-chained audit log that records no names or values.

[0.1.1]: https://github.com/mtnaskari/goraz/releases/tag/v0.1.1
[0.1.0]: https://github.com/mtnaskari/goraz/releases/tag/v0.1.0
