# Changelog

All notable changes to goraz are listed here. Versions follow [Semantic Versioning](https://semver.org/). Before version 1, a minor release may change the Go API or command-line flags, and every such change is listed. The v1 file format is frozen by golden tests, and no release has changed it.

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
