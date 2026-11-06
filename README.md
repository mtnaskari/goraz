# goraz

`goraz` is a Go library and command-line tool for keeping secrets. It combines a vault, a token manager and a password manager, and it gives each production service its own encrypted file.

The name evokes the Persian word for wild boar, and combines "Go" with the Persian word *raz*, meaning secret.

> **Status: pre-release. goraz has not had an independent security audit.** Its cryptographic composition has not been reviewed by an outside party. Please read [What goraz does not defend against](docs/threat-model.md#4-what-goraz-does-not-defend-against) before relying on it, and don't make it the only protection for highly sensitive credentials.

The official source is `github.com/mtnaskari/goraz`. The `github.com/goraz` organization is an unrelated project.

## What it does

**Vault**
- Keeps everything in one authenticated file, with all names and metadata encrypted.
- Detects changed, swapped, removed or older data.
- Keeps version history, and has explicit destroy.
- Gives secrets to programs with `goraz run` and `goraz://` references.

**Token manager**
- Tracks third-party tokens and their expiry.
- Issues opaque tokens with a 256-bit secret and a scanner-friendly prefix.
- Stores only a keyed hash, requires an expiry and supports immediate revocation and rotation with overlap.

**Password manager**
- Generates passwords and passphrases.
- Produces TOTP and HOTP codes.
- Clears the clipboard automatically.
- Reports weak and reused passwords, with an opt-in breach check.

**Production services**
- Gives each service a separate vault file holding only its own items, so the limit is enforced by encryption.
- Reloads changed files without a restart, and refuses tampered or older ones.
- Fails closed when data is stale or past its validity window.
- Supports key delivery through Kubernetes, Docker and systemd, and rotation without an outage.

It has no server, no network listener and no network use, other than the breach check you ask for.

## Install

Requires Go 1.26 or later. macOS and Linux only for now.

```bash
go install github.com/mtnaskari/goraz/cmd/goraz@latest
```

## Quick start

```bash
goraz init
```

Store the recovery code it prints somewhere other than beside the vault. If the passphrase and the code are both lost, the data can't be recovered.

```bash
goraz put prod/db/password
```

```bash
goraz run --env DB_PASSWORD=goraz://prod/db/password -- ./my-app
```

```bash
goraz generate --words 6
```

Secrets are read from a hidden prompt, stdin or a file descriptor, and never from command-line arguments or environment variables.

## Using it in a production service

Create a service vault on the operator's machine. It holds only the items below the given prefix:

```bash
goraz service create api --prefix prod/api --out api.goraz --key-out api.key
```

Deploy `api.goraz` and `api.key` separately, then read secrets in the service:

```go
c, err := service.Open(ctx, service.Options{
	Path:  "/etc/goraz/api.goraz",
	Key:   service.KeyFile("/run/secrets/goraz-key"),
	Audit: audit.NewJSONSink(os.Stdout),
})
if err != nil {
	return err
}
defer c.Close()

stripeKey, err := c.Value("prod/api/stripe")
```

Or, without changing the program:

```bash
goraz run --vault api.goraz --machine-key-file api.key --audit stderr --no-warn --env STRIPE_KEY=goraz://prod/api/stripe -- ./my-app
```

The key file must not be readable by others:

- **Docker:** `secrets: [{source: goraz, uid: "1000", mode: 0400}]`
- **Kubernetes:** `defaultMode: 0440` with `securityContext.fsGroup`
- **systemd:** `LoadCredential=`

**Be clear about what this does and doesn't do.** The file is protected at rest, and services are separated from each other. An attacker who controls a running service gets everything that service can read. Revocation reaches a service through a sync, a deployment and a reload, so it isn't immediate. If you need central control or instant revocation across many servers, or dynamic credentials, use a server such as [OpenBao](https://openbao.org/) instead. See [section 14A of the design](docs/security-design.md#14a-service-mode).

## Issuing tokens from your own service

```go
m, err := token.New(token.Config{
	Keys:  verifierKeys,
	Store: myDatabaseStore, // Implements token.Store.
	Sink:  audit.NewJSONSink(os.Stdout),
})

tok, rec, err := m.Issue(ctx, token.IssueRequest{Name: "billing", Scopes: []string{"payments:read"}, TTL: time.Hour})

rec, err = m.Verify(ctx, presented, "payments:read")
```

## Rotation and revocation

**`goraz passwd` and `goraz slot remove` do not revoke anything.** Someone with the old credential and an old copy of the file can still get the master key. **Only `goraz rekey` ends access for future files.** It also means every service must then run `goraz service rotate`. Secrets that may have been read are exposed regardless, so rotate them at their source.

## Cryptography

Argon2id, HKDF-SHA-256 and XChaCha20-Poly1305 from the Go standard library and `golang.org/x/crypto`. There is one algorithm suite with no negotiation. Key commitment uses the published generic transform of Albertini et al. (2022). The full format is in [docs/security-design.md](docs/security-design.md).

## Documentation

- [Threat model](docs/threat-model.md), including what isn't defended
- [Security design and format](docs/security-design.md)
- [Feature matrix](docs/feature-matrix.md): what is included, deferred or rejected, and why
- [Comparison with other projects](docs/research/comparison.md)
- [Security policy](SECURITY.md)

## Not covered yet

Server or API, policy language, identity integrations, dynamic secrets, sync with merging, team sharing, public-key features, OS keyring, local agent, hardware keys, browser autofill, GUI, mobile, FIPS mode and Windows. The [feature matrix](docs/feature-matrix.md) explains each.

## License

[Apache-2.0](LICENSE). The embedded word list is from the [Electronic Frontier Foundation](https://www.eff.org/dice), under CC BY 3.0 US.
