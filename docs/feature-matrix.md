# Feature matrix

The goal is for goraz to eventually carry every good idea from earlier projects. Not all of them are realistic or safe in a first release, so this document records each decision, including the deferrals, rather than dropping anything silently.

**Tiers**

- **v0.1:** in the first release.
- **v0.2:** the next release. The design leaves room for it.
- **Later:** planned, but it needs a new subsystem or significant design work.
- **Not planned:** rejected for a stated security or scope reason. It can be reconsidered.

⚠ marks an item that is unrealistic for a first release even though it is valuable.

## Vault and secret management

| Feature | Learned from | Tier | Notes |
|---|---|---|---|
| Encrypted store over untrusted storage | Vault, KeePassXC | v0.1 | Single authenticated file |
| All metadata encrypted, including names | KeePassXC, LastPass lesson | v0.1 | Item count and approximate sizes remain visible |
| Ciphertext bound to vault, item and version | SOPS path AAD, ETH Zurich | v0.1 | |
| Whole-vault integrity, with swap and deletion detected | KDBX, ETH Zurich | v0.1 | |
| Key commitment | Len et al., Albertini et al. | v0.1 | Hard to add later, costs 32 bytes per blob |
| Rollback detection | TUF, KeePassXC audit | v0.1 | Local state. Limits are documented. Vault and OpenBao exclude this entirely |
| Multiple unlock slots | LUKS pattern, Vault recovery keys | v0.1 | One passphrase, plus recovery code and machine keys |
| Fork detection between devices | Original, TUF | v0.1 | Hash lineage in the manifest. Conflicts are refused, not merged |
| Optional key file | KeePassXC, 1Password two-secret idea | v0.1 | Raw random bytes, no parser |
| Passphrase rotation without re-encryption | Vault rekey | v0.1 | Replaces a slot |
| Full vault rekey | Vault rekey, SOPS rotate | v0.1 | New master key, every item re-encrypted |
| Secret version history and rollback | Vault KV v2, Infisical | v0.1 | Rollback records a new version |
| Explicit destroy | Vault KV v2 | v0.1 | Backups and filesystem snapshots may still hold old data |
| Secret references (`goraz://`), `read`, `run` | 1Password, Teller, chamber | v0.1 | `run` warns about environment exposure |
| `inject` with plain substitution | 1Password | v0.2 | No template engine, because of the Conjur and gopass findings |
| `redact` and output masking | Teller, 1Password | v0.2 | Documented as a convenience, not a boundary |
| `scan` for leaked secrets in CI | Teller | v0.2 | Prefixed tokens make this practical |
| `doctor` diagnostics | gopass `fsck`, `runtime/secret` honesty | v0.1 | Reports real protections and vault integrity |
| Local session agent | gopass, Bitwarden sessions | v0.2 | ⚠ Local IPC is a trust boundary (CVE-2024-42219). Needs peer credential checks |
| OS keyring integration | go-keyring, 99designs | v0.2 | ⚠ See section below |
| Team sharing with recipients | age, SOPS, gopass | Later | ⚠ Needs public-key authentication first. The ETH Zurich attacks concentrate here |
| Hybrid post-quantum recipients | age v1.3 | Later | Via `filippo.io/age`, with sharing. At-rest symmetric keys are already 256-bit |
| Recipient pinning and review | gopass, SOPS `updatekeys` | Later | With sharing |
| Git-friendly per-value encryption | SOPS | Later | ⚠ A separate `seal` format. It exposes key names by design, so it can't be the default store |
| Service vaults for scoped production and CI access | 1Password service accounts | v0.1 | Scope enforced by cryptography, not by checks |
| Runtime client with reload and fail-closed staleness | Vault agent, Doppler | v0.1 | `service` package. No listener or server |
| Key delivery through Kubernetes, Docker, systemd | 1Password Connect | v0.1 | File or descriptor. Not through environment variables |
| Audit to stdout for containers | Vault audit devices | v0.1 | JSON sink. Integrity depends on the receiving log system |
| Sync with conflict handling | Bitwarden, KeePassXC | Later | v0.1 detects forks and refuses to overwrite. It doesn't merge |
| Pluggable blob backends (S3 and others) | Vault storage | Later | An internal interface exists in v0.1 and isn't public yet |
| Shamir unlock quorum | Vault, SOPS key groups | Later | Would use a reviewed implementation |
| Dynamic secrets | Vault, Infisical | Later | ⚠ Needs a server and per-provider code. Every integration is a hostile parser |
| Leases | Vault | Later | ⚠ Needs a running service |
| Encryption as a service (transit) | Vault | Later | ⚠ Needs a server |
| Automatic rotation with two active secrets | Infisical, Doppler | Later | Token rotation with overlap is in v0.1. Rotating third-party credentials needs integrations |
| Server, HTTP API, HA, namespaces | Vault, OpenBao, Infisical | Later | ⚠ See the explanation below |
| Policy language, RBAC, ABAC | Vault, Conjur, Infisical | Later | ⚠ Needs a server. Almond's audit recommends keeping policies basic |
| Cloud KMS auto-unseal, HSM | Vault, Infisical | Later | ⚠ Network credentials and vendor SDKs, against the small-dependency goal |
| Identity integrations (OIDC, cloud IAM, Kubernetes) | Vault, Conjur | Later | ⚠ The most repeated source of authentication bypasses in this research |
| Plugins | age, Vault, pass | Not planned for now | The route to code execution in several incidents. Would need a strict grammar and no data-driven lookup |
| Templates over stored data | Conjur, gopass | Not planned | CVE-2025-49828 and gopass findings |
| FIPS 140-3 mode | Infisical, Go `GOFIPS140` | Later | ⚠ Argon2id and XChaCha20 are outside the Go FIPS module. It needs a separate PBKDF2 and AES-GCM profile, which adds a second format |

## Token management

| Feature | Learned from | Tier | Notes |
|---|---|---|---|
| Store third-party tokens with expiry tracking | Vault KV, Doppler | v0.1 | `goraz token expiring` |
| Issue opaque tokens with at least 256-bit secret | Vault service tokens, GitHub | v0.1 | Library and CLI |
| Prefix and checksum for scanners | GitHub, Stripe, Doppler | v0.1 | CRC32 is a filter only, never authentication |
| Only a keyed hash stored | GitHub, Bitwarden Secrets Manager | v0.1 | HMAC-SHA-256 with a separate verifier key |
| Shown once | Stripe | v0.1 | |
| Public token ID for lookup and revocation | Vault accessors | v0.1 | Can't act as the token |
| Mandatory expiry, checked at each use | OpenBao AppRole lesson | v0.1 | No "never expires" option |
| Immediate revocation, fail-closed on store errors | Infisical, Doppler lessons | v0.1 | Staleness limit for long-running services |
| Rotation with an overlap period | Stripe, Infisical, Doppler | v0.1 | |
| Exact-match scopes | Doppler | v0.1 | No wildcards or patterns |
| Pluggable token store for services | Original | v0.1 | Interface for a service's own database |
| Rate limiting and lockout | Vault, Infisical | v0.2 | Left to the host service in v0.1, with guidance. Tokens have 256-bit secrets, so guessing isn't practical |
| Token hierarchy with cascading revocation | Vault | v0.2 | |
| Stateless signed tokens (PASETO v4) | PASETO | Later | Can't be revoked without state, so opaque tokens come first |
| JWT issuance | RFC 8725, RFC 9068 | Not planned for now | Algorithm confusion is a known class. Interoperability may justify it later |
| Macaroons, Biscuit | Google, Biscuit | Later | Attenuation is valuable, but the policy language is large |
| Response wrapping | Vault | Later | ⚠ Needs a server to be meaningful |
| Sender-constrained tokens | 1Password Okta lesson | Later | |
| GitHub secret scanning partnership | GitHub | Later | Needs a public verification endpoint and project adoption |

## Password management

| Feature | Learned from | Tier | Notes |
|---|---|---|---|
| Login items: username, password, URLs, notes | All | v0.1 | Stored entirely inside the encrypted item |
| Password and passphrase generator | Bitwarden, KeePassXC | v0.1 | `crypto/rand`, unbiased, EFF wordlist |
| TOTP and HOTP codes | gopass, Bitwarden | v0.1 | RFC vectors, strict `otpauth://` parser. Warns that this reduces 2FA separation, as KeePassXC does |
| Clipboard with automatic clearing | pass, KeePassXC | v0.1 | Default 20 seconds. Clipboard history tools remain a documented limit |
| Vault password report: reused, weak, old | gopass, KeePassXC | v0.1 | Offline |
| Breach check by k-anonymity | KeePassXC, HIBP API | v0.1 | Opt-in by flag. No other network use exists in v0.1 |
| Offline breach check file | KeePassXC | v0.2 | |
| Master passphrase policy | NIST SP 800-63B-4 | v0.1 | 15 characters minimum, blocklist, no composition rules |
| No "zero knowledge" claim | ETH Zurich | v0.1 | Documentation |
| Plain export, explicit and audited | All | v0.1 | Refuses to write to a terminal without a flag |
| Import from `.env` | SOPS, dotenvx | v0.1 | Fuzzed |
| Import from Bitwarden, KeePassXC, 1Password | All | v0.2 | KeePassXC's 2026 advisories show importers need care. Legacy `.kdb` isn't planned |
| Attachments | Bitwarden, KeePassXC | v0.2 | v0.1 limits values to 1 MiB, per Vaultwarden's attachment advisory |
| Emergency access | Bitwarden | Later | ⚠ Needs a server and authenticated public keys. BW01 and BW02 show the danger |
| Secure send | Bitwarden | Later | ⚠ Needs a server |
| Hardware keys (YubiKey, FIDO2) | KeePassXC, passage | Later | ⚠ Needs device libraries and possibly cgo. The per-use touch from passage is valuable |
| Secret-key style device factor | 1Password | v0.1, as key file | The key file gives the same offline resistance when kept off the synced path |
| Passkeys | KeePassXC | Later | ⚠ Needs browser or OS integration |
| SSH agent | KeePassXC | Later | Inherits the `x/crypto/ssh` advisory stream |
| Browser extension and autofill | Bitwarden, KeePassXC | Later | ⚠ A separate product. Clickjacking research affected 10 of 11 tested managers (secondary) |
| Auto-Type | KeePassXC | Later | ⚠ OS-specific GUI work |
| Desktop and mobile apps | Bitwarden, KeePassXC, 1Password | Later | ⚠ Each one is a separate product |
| Website icons | Bitwarden, LastPass | Not planned | The BW06 and LP03 exfiltration channel |
| Organisations and SSO | Bitwarden, 1Password | Later | ⚠ Needs a server and identity integrations |

## Assurance and project practice

| Item | Learned from | Tier | Notes |
|---|---|---|---|
| Published threat model and non-goals | 1Password, gopass, Vault | v0.1 | |
| Published format spec with golden vectors | age, SOPS #2243 | v0.1 | |
| Tests: KAT, tamper, fuzz, race, canary | Standard practice, Vault lessons | v0.1 | |
| `go vet`, staticcheck, gosec, govulncheck | Project requirement | v0.1 | |
| `SECURITY.md` stating there has been no audit | Honest reporting | v0.1 | |
| Static binaries, no install scripts | Bitwarden npm lesson | v0.1 | `CGO_ENABLED=0 -trimpath` |
| Signed releases, GitHub attestations | KeeLoader, `slsa-github-generator` deprecation | When publishing | SLSA Build L2 through attestations, without the unmaintained generator |
| OpenSSF Scorecard, Best Practices badge | OpenSSF | When publishing | |
| OSS-Fuzz | OSS-Fuzz | Later | Acceptance usually depends on adoption |
| Independent cryptographic review | Bitwarden, KeePassXC, Almond | Later | ⚠ Needs funding or a volunteer reviewer. It can't be claimed until it has happened, and it matters more than most features |
| SOC 2, FedRAMP and similar | Doppler, 1Password | Not planned | Organisational certifications, not applicable to a personal open-source project |

## Why a server isn't in the first release

A server is the feature that people will most expect, and it is the largest deferral. It should be understood as a deliberate choice.

1. **It is a different attack surface.** Almost every serious server incident in the research came from authentication, authorization, policy, plugin or audit-sink code. The file-based design has none of that code. A local file tool can reach a defensible state as a one-person project in a way a multi-tenant server can't.
2. **The scale is large.** Vault's public audit alone spent 60 person-days on an existing mature code base, and still found a traversal issue. OpenBao's advisories for code inherited from Vault show how long these classes persist.
3. **A secure local core is a prerequisite.** A later server can reuse the format, keys and audit log, and treat the file format as its storage layer. The reverse order doesn't work as well.

## Why the OS keyring waits for v0.2

Each current option has a real cost. go-keyring's default macOS path leaves items owned by `/usr/bin/security`. 99designs/keyring appears dormant. ByteNess/keyring is maintained but pulls in a large dependency tree and cgo on macOS. Cgo conflicts with reproducible builds, and frequently rebuilt unsigned binaries cause repeated keychain prompts. The cost of waiting is that each command asks for the passphrase and spends about the time of one KDF run.
