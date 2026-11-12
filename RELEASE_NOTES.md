A security update that builds goraz with a Go release containing the fix for GO-2026-6859.

**goraz has not had an independent security audit.** Don't make it the only protection for highly sensitive credentials. Read [what it does not defend against](https://mtnaskari.github.io/goraz/threat-model#4-what-goraz-does-not-defend-against). The Go API and command-line flags may change before version 1. The v1 file format is unchanged.

## Changes

- **Security:** release binaries are built with Go 1.27.4. GO-2026-6859 (CVE-2026-97054) is a header race in the `net/http` standard library package, which can crash an HTTP/1 server. goraz runs no HTTP server: its only use of `net/http` is the opt-in breach check, `goraz report --hibp`.
- **Go version:** the module now requires Go 1.26.11 or later, so programs that import goraz also build with a fixed standard library.
- **Documentation:** the site at [mtnaskari.github.io/goraz](https://mtnaskari.github.io/goraz/) has a new layout, and the README names the author.

Vaults, service files and tokens from v0.1.0 work unchanged.

## Install

```bash
go install github.com/mtnaskari/goraz/cmd/goraz@v0.1.1
```

Or download a binary below, then check it:

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify goraz_v0.1.1_linux_amd64 --repo mtnaskari/goraz
```

macOS and Linux only. [Start here](https://mtnaskari.github.io/goraz/guides/getting-started).
