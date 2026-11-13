A refactor release: clearer errors, safer writes, far fewer allocations on hot paths, and much broader tests. It changes a few Go API names and the command-line exit code for wrong usage. The file format is unchanged.

**goraz has not had an independent security audit.** Don't make it the only protection for highly sensitive credentials. Read [what it does not defend against](https://mtnaskari.github.io/goraz/threat-model#4-what-goraz-does-not-defend-against). The Go API and command-line flags may change before version 1.

## Breaking changes and how to migrate

**Breach check moved to `password/hibp`.** Programs that don't use it no longer link `net/http`.

```go
// v0.1.x
h := password.NewHIBP()
// v0.2.0
import "github.com/mtnaskari/goraz/password/hibp"
h := hibp.New() // *hibp.Client; Count works as before.
```

**KDF profiles have a public type, `vault.Profile`.** `CreateOptions.Profile`, `RekeyOptions.Profile` and `Vault.ChangePassphrase` took a type from an internal package, so callers outside the module could only pass the zero value. Leave it empty for the default, or name a profile:

```go
vault.CreateOptions{Passphrase: pass, Profile: vault.ProfileStrong}
v.ChangePassphrase(pass, nil, vault.ProfileStandard, false)
```

**`vault.Options.State` is replaced by `vault.Options.Memory`.** The old field took an internal type. To keep rollback state in memory instead of on disk, share one `*vault.MemoryState` across opens:

```go
mem := vault.NewMemoryState()
v, err := vault.Open(path, cred, vault.Options{Memory: mem})
```

**`vault.VaultIDFromFile` is renamed `vault.IDFromFile`**, and returns `[vault.IDSize]byte`. Rename the call; the value is the same.

**Command line:** wrong usage now exits with code 2 instead of 1, and a command refuses arguments it doesn't take. Scripts that only check for a non-zero exit code are unaffected.

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
