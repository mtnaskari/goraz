The first public release of goraz: an encrypted vault, API token manager and password manager for Go services and the command line. It needs no server.

**This is an early release, and goraz has not had an independent security audit.** Don't make it the only protection for highly sensitive credentials. Read [what it does not defend against](https://mtnaskari.github.io/goraz/threat-model#4-what-goraz-does-not-defend-against). The Go API and command-line flags may change before version 1. The v1 file format is frozen by golden tests.

## Included

- An encrypted vault with hidden metadata, version history and tamper and rollback detection
- Per-service encrypted files, with reload, staleness limits and rotation without an outage
- API token issuing, verifying, revoking and rotating, with only a keyed hash stored
- Passwords, passphrases, TOTP and HOTP, automatic clipboard clearing and opt-in breach checks
- A hash-chained audit log with no names or values

## Install

```bash
go install github.com/mtnaskari/goraz/cmd/goraz@v0.1.0
```

Or download a binary below, then check it:

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify goraz_v0.1.0_linux_amd64 --repo mtnaskari/goraz
```

macOS and Linux only. [Start here](https://mtnaskari.github.io/goraz/guides/getting-started).
