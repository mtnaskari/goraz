# goraz: encrypted secrets, API tokens and passwords for Go

[![CI](https://github.com/mtnaskari/goraz/actions/workflows/ci.yml/badge.svg)](https://github.com/mtnaskari/goraz/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mtnaskari/goraz.svg)](https://pkg.go.dev/github.com/mtnaskari/goraz)

goraz is a Go library and command-line tool that keeps API tokens, secrets and passwords in an encrypted file. It needs no server. Each production service gets its own file holding only what it needs.

> **goraz 0.1 is an early release and has not had an independent security audit.** Don't make it the only protection for highly sensitive credentials. Read [what it does not defend against](docs/threat-model.md#4-what-goraz-does-not-defend-against).

The official source is `github.com/mtnaskari/goraz`. The `github.com/goraz` organization is an unrelated project.

## Install

Requires Go 1.26 or later, on macOS or Linux.

```bash
go install github.com/mtnaskari/goraz/cmd/goraz@latest
```

Prebuilt binaries with checksums and build attestations are on the [releases page](https://github.com/mtnaskari/goraz/releases).

## Quick start

```bash
goraz init
```

```bash
goraz put prod/db/password
```

```bash
goraz run --env DB_PASSWORD=goraz://prod/db/password -- ./my-app
```

## Find what you need

| I want to | Guide |
|---|---|
| Store API tokens in a production Go service | [Guide](docs/guides/api-tokens-in-go-service.md) |
| Use secrets in [Docker](docs/guides/docker-secrets.md), [Kubernetes](docs/guides/kubernetes-secrets.md), [systemd](docs/guides/systemd-credentials.md) or [CI](docs/guides/ci-secrets.md) | Follow the link for each |
| Issue and verify API tokens from my own Go API | [Guide](docs/guides/issue-api-tokens-in-go.md) |
| Replace a `.env` file | [Guide](docs/guides/replace-dotenv-file.md) |
| Manage passwords and TOTP codes in the terminal | [Guide](docs/guides/password-manager-cli.md) |
| Respond to a leaked secret or key | [Guide](docs/guides/secret-or-key-leaked.md) |
| Fix an error | [Troubleshooting](docs/guides/troubleshooting.md) |
| Compare it with Vault, OpenBao, SOPS or gopass | [Comparison](docs/guides/alternatives.md) |

The [documentation site](https://mtnaskari.github.io/goraz/) has everything, including the [command reference](docs/cli-reference.md), [limits](docs/limits.md), [threat model](docs/threat-model.md) and [file format](docs/security-design.md).

## Read a token in a Go service

Create a file holding only this service's items:

```bash
goraz service create api --prefix prod/api --out api.goraz --key-out api.key
```

Deploy the two files separately, then:

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

The client picks up new files with no restart, refuses tampered or older ones, and fails closed when its data is stale.

## Issue API tokens from your own service

```go
m, err := token.New(token.Config{Keys: keys, Store: myDatabaseStore, Sink: audit.NewJSONSink(os.Stdout)})

tok, rec, err := m.Issue(ctx, token.IssueRequest{Name: "billing", Scopes: []string{"payments:read"}, TTL: time.Hour})

rec, err = m.Verify(ctx, presented, "payments:read")
```

Only a keyed hash is stored. Every token expires, and it can be revoked or rotated with an overlap.

## What's different

- **All metadata is encrypted.** Names, usernames and URLs aren't visible in the file.
- **Tampering is detected.** Changed, swapped, removed or older data is refused. Older-file detection has [documented limits](docs/threat-model.md#5-rollback-an-honest-limit).
- **Per-service limits come from encryption.** A service's file doesn't contain anyone else's secrets.
- **Secrets stay off the command line.** They're never read from arguments or environment variables.
- **Audit by default.** A read fails if it can't be logged, and the log holds no names or values.
- **Few dependencies.** Only Go's standard library and `golang.org/x` modules.

## When to use something else

goraz has no server, policies, dynamic credentials, team sharing, sync or browser extension. If you need central control or instant revocation across many servers, [OpenBao](https://openbao.org/) or Vault fits better. An attacker who controls a running service gets everything that service can read, with goraz or any other local tool. See the [full comparison](docs/guides/alternatives.md) and the [feature matrix](docs/feature-matrix.md).

## Cryptography

Argon2id, HKDF-SHA-256 and XChaCha20-Poly1305, from Go's standard library and `golang.org/x/crypto`, as one fixed suite. The [file format](docs/security-design.md) is published. Its key-commitment composition follows Albertini et al. (2022), and it hasn't been independently reviewed. Review is very welcome: see [SECURITY.md](SECURITY.md).

## The name

*Goraz* evokes the Persian word for wild boar, and combines "Go" with the Persian word *raz*, meaning secret.

## Author

goraz is written and maintained by [Matin Askari](https://www.askari.pro) ([@mtnaskari](https://github.com/mtnaskari)).

## License

Copyright 2026 Matin Askari. Licensed under [Apache-2.0](LICENSE). The embedded word list is from the [Electronic Frontier Foundation](https://www.eff.org/dice), under CC BY 3.0 US.
