A refactor release: clearer errors, safer writes, far fewer allocations on hot paths, and much broader tests. It changes a few Go API names and the command-line exit code for wrong usage. The file format is unchanged.

**goraz has not had an independent security audit.** Don't make it the only protection for highly sensitive credentials. Read [what it does not defend against](https://mtnaskari.github.io/goraz/threat-model#4-what-goraz-does-not-defend-against). The Go API and command-line flags may change before version 1.

## Breaking changes

- `password.HIBP` and `password.NewHIBP` moved to the new package `password/hibp`, as `hibp.Client` and `hibp.New`. Programs that don't use the breach check no longer link `net/http`.
- `vault.CreateOptions.Profile`, `vault.RekeyOptions.Profile` and `Vault.ChangePassphrase` take the new public type `vault.Profile`.
- `vault.Options.State` is replaced by `vault.Options.Memory`, of type `vault.MemoryState`.
- `vault.VaultIDFromFile` is renamed `vault.IDFromFile`.
- The command line exits with code 2 for wrong usage, and refuses arguments a command doesn't take. Scripts that only check for a non-zero exit code are unaffected.

## Other changes

- **Errors:** new exported errors to check with `errors.Is`, such as `vault.ErrNotVault`, `vault.ErrNotDurable` and `service.ErrUnsafeKeyFile`.
- **Durability:** waiting for a lock gives up after 10 seconds, new directories are synced, and the audit log refuses writes after a failed sync.
- **Performance:** `vault.Get` makes about 97% fewer allocations, the JSON audit sink makes none, and parsing a token makes 2 allocations instead of 11.
- **Tests:** Wycheproof and Argon2id reference vectors, a corpus of damaged vault files, new fuzz targets and allocation budgets.
- **Documentation:** the Docker guide now mounts the service file's directory, because a single-file bind mount never sees an update. [goraz-example](https://github.com/mtnaskari/goraz-example) is a complete service that runs the documented setup.

Vaults, service files and tokens from v0.1.x work unchanged. The full list is in the [changelog](https://github.com/mtnaskari/goraz/blob/v0.2.0/CHANGELOG.md).

## Install

```bash
go install github.com/mtnaskari/goraz/cmd/goraz@v0.2.0
```

Or download a binary below, then check it:

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify goraz_v0.2.0_linux_amd64 --repo mtnaskari/goraz
```

macOS and Linux only. [Start here](https://mtnaskari.github.io/goraz/guides/getting-started).
