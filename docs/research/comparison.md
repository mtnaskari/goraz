---
title: Comparison of secret management projects
description: Strengths, threat models, encryption design, licenses and security incidents of Vault, OpenBao, Infisical, SOPS, age, gopass, Bitwarden, KeePassXC and others.
---

# Comparison of existing secret-management projects

Research date: 2026-11-06. This document records what `goraz` learned from earlier projects. It is a summary of published material, not an assessment of those projects' overall quality.

**How to read the evidence**

- A linked claim comes from a page that was read during this research.
- **(secondary)** means the claim comes from a third-party article or a search excerpt, not from the project or the original researcher.
- **(unconfirmed)** means no page that was read supports the claim. Do not cite it without checking.
- "None found" means only that the searches found nothing. It does not show that nothing exists.
- CVE scores and fixed versions vary between sources. Check the original advisory before relying on one.

## 1. The findings that shaped the design

| # | Finding | Evidence | Consequence for goraz |
|---|---|---|---|
| 1 | Storage and servers must be treated as hostile. Researchers presented 12 attacks on Bitwarden, 7 on LastPass, 6 on Dashlane and 6 on 1Password under a malicious server. Causes include unauthenticated metadata and KDF settings, missing key separation, and legacy code paths. | [ETH Zurich and USI, ePrint 2026/058](https://eprint.iacr.org/2026/058), [USENIX Security 2026 version](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf) | Allowlisted KDF parameters, every ciphertext bound to its context, all metadata encrypted, no legacy path |
| 2 | Most recent incidents are not cryptographic failures. They are parser, path, canonicalization and authorization bugs. | Vault [CVE-2026-3605](https://almond.eu/wp-content/uploads/ETR-PUBLIC-Vault.pdf), [CVE-2025-6014](https://discuss.hashicorp.com/t/hcsec-2025-17-vault-totp-secrets-engine-code-reuse/76036); gopass [GHSA-v4c2-4fvx-chr3](https://github.com/gopasspw/gopass/security/advisories/GHSA-v4c2-4fvx-chr3); SOPS [GHSA-jgf3-f6rg-8x3h](https://github.com/getsops/sops/security/advisories/GHSA-jgf3-f6rg-8x3h) | One canonicalizer, strict parsers, fuzzing, and a single-file store with no path derived from data |
| 3 | Administrative features become code execution. | Vault [CVE-2025-6000](https://csoonline.com/article/4035274/researchers-uncover-rce-attack-chains-in-popular-enterprise-credential-vaults.html) (secondary) and its bypass [CVE-2026-5051](https://discuss.hashicorp.com/t/hcsec-2026-16-vault-audit-device-plugin-directory-guard-bypass-via-legacy-path-option/77536); Conjur [CVE-2025-49828](https://github.com/cyberark/conjur/security/advisories/GHSA-93hx-v9pv-qrm4); OpenBao [GHSA-j6wc-jpvg-xfxq](https://github.com/openbao/openbao/security/advisories/GHSA-j6wc-jpvg-xfxq) | No plugins, no template evaluation, no log path or binary path taken from data in the first release |
| 4 | Audit redaction regresses. | Vault [CVE-2024-8365](https://discuss.hashicorp.com/t/hcsec-2024-18-vault-leaks-client-token-and-token-accessor-in-audit-devices/69669); OpenBao [GHSA-ghfh-fmx4-26h8](https://osv.dev/vulnerability/GHSA-ghfh-fmx4-26h8) | Typed audit events with no free-form field, plus canary tests in CI |
| 5 | Revocation and sealing are often weaker than they sound. | [Almond audit](https://almond.eu/wp-content/uploads/ETR-PUBLIC-Vault.pdf) found Vault keys in memory after sealing; [Infisical](https://infisical.com/docs/documentation/platform/identities/machine-identities) may accept a revoked token for up to 12 minutes during a Redis outage; [OpenBao](https://openbao.org/community/release-notes/2-7-0/) AppRole secret IDs outlived expiry until tidy ran | Check expiry and revocation at each use, fail closed, and state the limits plainly |
| 6 | Secrets tools are prime supply-chain targets. | [Bitwarden CLI 2026.4.0 on npm](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127), [KeeLoader](https://www.withsecure.com/en/resources-hub/w-labs/keepass-trojanised-in-advanced-malware-campaign/), [LastPass 2022](https://www.theregister.com/2025/12/11/lastpass_ico_fine/) | Few dependencies, static binaries, no install scripts, signed and attested releases |
| 7 | Honest documentation of non-goals is a security feature. | [1Password's "Beware of the leopard"](https://agilebits.github.io/security-design/leopard.html), [gopass security.md](https://github.com/gopasspw/gopass/blob/master/docs/security.md), [Vault security model](https://developer.hashicorp.com/vault/docs/internals/security) | A published list of what is not defended, and no use of the phrase "zero knowledge" |

## 2. Summary table

| Project | Kind | License | Data encryption | KDF or root protection | Metadata protected | Public third-party audit |
|---|---|---|---|---|---|---|
| HashiCorp Vault | Server | [BSL 1.1](https://raw.githubusercontent.com/hashicorp/vault/main/LICENSE) | AES-256-GCM | Shamir or KMS | Stored data, yes | [Almond for ANSSI, 2026](https://almond.eu/wp-content/uploads/ETR-PUBLIC-Vault.pdf) |
| OpenBao | Server | [MPL-2.0](https://raw.githubusercontent.com/openbao/openbao/main/LICENSE) | [AES-256-GCM](https://openbao.org/docs/internals/security/) | Shamir, KMS, static key | Stored data, yes | None found |
| Infisical | Server | [MIT, with `ee/` separately licensed](https://github.com/Infisical/infisical/blob/main/LICENSE) | [AES-256-GCM](https://infisical.com/docs/internals/security) | Operator key or HSM | Stored data, yes | Pen tests stated, reports on request |
| Doppler | SaaS | Commercial; details unconfirmed | [AES-GCM, per-workplace key](https://docs.doppler.com/docs/security-fact-sheet) | HSM-backed KMS | Self-reported | None found |
| CyberArk Conjur OSS | Server | [LGPL-3.0 server](https://raw.githubusercontent.com/cyberark/conjur/master/README.md) | [AES-256-GCM (Slosilo)](https://raw.githubusercontent.com/cyberark/slosilo/master/README.md) | `CONJUR_DATA_KEY` environment variable | Not established | Unsupported README claim |
| SOPS | File tool | [MPL-2.0](https://github.com/getsops/sops) | [AES-256-GCM per value](https://getsops.io/docs/reference/) | Age, PGP or cloud KMS wrap | No, keys are cleartext by design | None found |
| age | File format and tool | [BSD-3-Clause](https://github.com/FiloSottile/age) | [ChaCha20-Poly1305 STREAM](https://github.com/C2SP/C2SP/blob/main/age.md) | X25519, ML-KEM-768 hybrid, scrypt | Not applicable | None found |
| pass | CLI | [GPL-2.0-or-later](https://www.passwordstore.org/) | GPG | GPG key | No, names are file names | None found |
| gopass | CLI | [MIT](https://github.com/gopasspw/gopass) | GPG by default, age experimental | GPG or age identity | [No](https://github.com/gopasspw/gopass/blob/master/docs/security.md) | None found |
| Teller | Broker CLI | [Apache-2.0](https://github.com/tellerops/teller) | Delegated to backend | Delegated | Delegated | None found |
| Bitwarden | Password manager | [AGPL-3.0 server, with a separately licensed part](https://github.com/bitwarden/server/blob/main/LICENSE.txt) | [AES-256-CBC with HMAC-SHA-256](https://bitwarden.com/help/what-encryption-is-used/) | [PBKDF2 600,000 or Argon2id 32 MiB, t=6, p=4](https://bitwarden.com/help/kdf-algorithms/) | [Partly](https://bitwarden.com/help/vault-data/) | [Several, listed by vendor](https://bitwarden.com/help/is-bitwarden-audited/) |
| Vaultwarden | Server for Bitwarden clients | [AGPL-3.0](https://github.com/dani-garcia/vaultwarden) | Client side | Client side | As Bitwarden | None found |
| KeePassXC | Password manager | [GPL-3.0](https://keepassxc.org/docs/#faq-security) | [AES-256-CBC or ChaCha20 with HMAC blocks](https://keepass.info/help/kb/kdbx.html) | [Argon2, 64 MiB, 10 rounds, p=4 constants](https://raw.githubusercontent.com/keepassxreboot/keepassxc/develop/src/crypto/kdf/Argon2Kdf.h) | Yes, whole database | [Molotnikov, 2023](https://keepassxc.org/assets/pdf/KeePassXC-Review-V1-Molotnikov.pdf) |
| 1Password | Password manager and CLI | Unconfirmed; white paper public | [AES-256-GCM](https://agilebits.github.io/security-design/deepKeys.html) | PBKDF2 650,000 plus 128-bit Secret Key | Item overview and details, yes | Claims not reviewed here |
| go-keyring | OS keyring library | [MIT](https://github.com/zalando/go-keyring) | Delegated to OS | OS | OS | None found |
| 99designs/keyring | OS keyring library | [MIT](https://github.com/99designs/keyring) | Delegated to OS or JWT file | OS or passphrase | OS | None found |

## 3. Server and platform managers

### HashiCorp Vault

- **Worth keeping:** the [encrypted barrier over untrusted storage](https://developer.hashicorp.com/vault/docs/internals/architecture), [recovery keys separate from unseal](https://developer.hashicorp.com/vault/docs/concepts/seal), [leases](https://developer.hashicorp.com/vault/docs/concepts/lease), [response wrapping](https://developer.hashicorp.com/vault/docs/concepts/response-wrapping), [transit with versioned ciphertext and rewrap](https://developer.hashicorp.com/vault/docs/secrets/transit), [token accessors](https://developer.hashicorp.com/vault/docs/concepts/tokens), and [audit that refuses a request it cannot log](https://developer.hashicorp.com/vault/docs/audit).
- **Threat model:** [storage is untrusted for confidentiality and tampering](https://developer.hashicorp.com/vault/docs/internals/security). Storage rollback, memory inspection, malicious plugins and compromised clients are out of scope.
- **Keys:** unseal key, root key, keyring, data. [Rotation adds a keyring key, and rekey replaces root and unseal keys. Vault rotates before about 2^32 encryptions under AES-GCM](https://developer.hashicorp.com/vault/docs/internals/rotation).
- **Audit:** [Almond for ANSSI](https://almond.eu/wp-content/uploads/ETR-PUBLIC-Vault.pdf) spent 60 person-days on 1.21.0 and found one vulnerability, 12 minor technical facts and 18 recommendations. Keys remained in memory after sealing (TF 6). Tokens sit in plaintext in `~/.vault-token` (REC 2). Audit is off by default (REC 6).
- **Incidents and lessons:**
  - [Project Zero 2020](https://projectzero.google/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html): lenient identity-provider response parsing. Lesson: integrations are hostile parsers.
  - [CVE-2025-6004](https://discuss.hashicorp.com/t/hcsec-2025-16-vault-userpass-and-ldap-user-lockout-bypass/76035) and [CVE-2025-6014](https://discuss.hashicorp.com/t/hcsec-2025-17-vault-totp-secrets-engine-code-reuse/76036): case and trailing whitespace defeated lockout and TOTP replay protection. Lesson: canonicalize before any check.
  - [CVE-2025-6011](https://discuss.hashicorp.com/t/hcsec-2025-15-timing-side-channel-in-vault-s-userpass-auth-method/76034): a malformed dummy hash exposed timing. Lesson: make the failure path do the same work.
  - [CVE-2026-5807](https://discuss.hashicorp.com/t/hcsec-2026-08-vault-vulnerable-to-denial-of-service-via-unauthenticated-root-token-generation-rekey-operations/77345): unauthenticated control endpoints caused denial of service.
- **Note:** no breach of the Vault product itself was found in the pages read. Misconfigured deployments were not researched.

### OpenBao

- **Worth keeping:** [open governance](https://openbao.org/docs/), namespaces in the open-source build, a shrinking core ([2.7 moves auth methods and seals out of the main binary](https://openbao.org/community/release-notes/2-7-0/)), and very detailed advisories.
- **Threat model:** [largely Vault's, and adds fingerprinting as out of scope](https://openbao.org/docs/internals/security/).
- **Incidents:** [GHSA-rh46-vc3j-w2w3](https://github.com/openbao/openbao/security/advisories/GHSA-rh46-vc3j-w2w3) (internal requests treated as login), [GHSA-34fc-gh42-pj53](https://github.com/openbao/openbao/security/advisories/GHSA-34fc-gh42-pj53) (timing attack on the recovery token), and [GHSA-59w7-v8rr-pr4p](https://github.com/openbao/openbao/security/advisories/GHSA-59w7-v8rr-pr4p) (user data widened policies).
- **Lesson:** use constant-time comparison on break-glass paths, and never interpolate user data into policy patterns. A fork inherits history and needs its own review.

### Infisical

- **Worth keeping:** [per-tenant data keys](https://infisical.com/docs/internals/security), [dual-phase rotation](https://infisical.com/docs/documentation/platform/secret-rotation/overview), and [rollback as a new commit](https://infisical.com/docs/documentation/platform/pit-recovery).
- **Threat model:** [excludes uncontrolled storage access, runtime memory intrusion and compromised clients](https://infisical.com/docs/internals/security).
- **Keys:** operator root key or HSM, then internal KMS root, then org and project keys.
- **Record:** the [advisory page is empty](https://github.com/Infisical/infisical/security/advisories), and pen test reports are available by email. This limits outside assessment.
- **Lesson:** keep audit logs out of the paid tier ([self-hosted audit logs require Enterprise](https://infisical.com/docs/documentation/platform/audit-logs)), and publish reports.

### Doppler

- **Worth keeping:** [tokenization split between web tier and crypto service](https://docs.doppler.com/docs/security-fact-sheet), [read-only scoped service tokens with visible prefixes](https://docs.doppler.com/docs/service-tokens), and [two-secret rotation](https://docs.doppler.com/docs/secrets-rotation).
- **Threat model:** no formal document found. The claims are self-reported.
- **Lesson:** after revocation, [the CLI may serve the last secrets from its fallback file](https://docs.doppler.com/docs/service-tokens). Offline caches need a TTL and documented behaviour.

### CyberArk Conjur

- **Worth keeping:** [policy as code and machine identity first](https://github.com/cyberark/conjur).
- **Threat model:** no official document could be read.
- **Keys:** a [master data key in an environment variable, with no quorum](https://raw.githubusercontent.com/cyberark/conjur/master/README.md). [Slosilo needed a CBC to GCM migration](https://raw.githubusercontent.com/cyberark/slosilo/master/README.md).
- **Incidents:** the "Vault Fault" chain of [CVE-2025-49827](https://github.com/cyberark/conjur/security/advisories/GHSA-gmc5-9mpc-xg75) and [CVE-2025-49828](https://github.com/cyberark/conjur/security/advisories/GHSA-93hx-v9pv-qrm4), [as described by CSO Online](https://csoonline.com/article/4035274/researchers-uncover-rce-attack-chains-in-popular-enterprise-credential-vaults.html) (secondary). Also [JWTs with no `iss`](https://github.com/cyberark/conjur/security/advisories/GHSA-87jq-rmr9-fwj3) accepted when an issuer was configured.
- **Lesson:** do not store executable content beside data. Each step looked minor alone, so review for chains.

## 4. File and CLI tools

### SOPS

- **Worth keeping:** [value-level encryption with the key path as AEAD additional data](https://getsops.io/docs/reference/), [key groups with Shamir](https://getsops.io/docs/usage/identities/key-groups/), and the [separation of `updatekeys` from `rotate`](https://getsops.io/docs/usage/key-management/).
- **Threat model:** the [security page](https://getsops.io/docs/security/) orders risks by likelihood, from compromised cloud credentials to weak AES. It does not discuss integrity.
- **Integrity detail, confirmed in [`sops.go`](https://raw.githubusercontent.com/getsops/sops/main/sops.go):** the MAC is SHA-512 over the walked leaf values, written with no length framing. Key names and recipient metadata are not written to that hash within `Tree.Encrypt`.
- **Incidents:**
  - [GHSA-jgf3-f6rg-8x3h](https://github.com/getsops/sops/security/advisories/GHSA-jgf3-f6rg-8x3h) (High, 7.4): decrypting an untrusted file sends the user's Vault token to the address named in that file. Lesson: file metadata must never select a network endpoint that receives a credential.
  - [GHSA-x4cm-pcq4-39j4](https://github.com/getsops/sops/security/advisories/GHSA-x4cm-pcq4-39j4): `exec-file --filename ../x` writes plaintext outside the temporary directory.
  - [Issue #2243](https://github.com/getsops/sops/issues/2243): a refactor changed MAC input and broke existing files. Lesson: authenticate exact bytes, and freeze formats with golden vectors.

### age

- **Worth keeping:** [a single version line, no cipher negotiation, one extension point, strict canonical parsing, labelled HKDF keys, and truncation detection](https://github.com/C2SP/C2SP/blob/main/age.md). [Hybrid ML-KEM-768 recipients exist since v1.3.0](https://github.com/FiloSottile/age/releases). The current module is `filippo.io/age` v1.3.2.
- **Threat model:** ["integrity and confidentiality, not authentication"](https://words.filippo.io/dispatches/age-authentication/). Any recipient can alter a file and re-encrypt it for the others.
- **Incidents:** [GHSA-32gq-x56h-299c](https://github.com/advisories/GHSA-32gq-x56h-299c): a plugin name with a path separator could execute an arbitrary binary. Lesson: identifiers that become exec targets need an allowlist.
- **Audit:** no formal audit of age found, so goraz will not imply one by using it.

### pass

- **Worth keeping:** simplicity, per-folder recipients, and clipboard clearing after 45 seconds.
- **Threat model:** no formal document. [Names and folder structure are visible](https://lists.zx2c4.com/pipermail/password-store/2017-February/002785.html) (secondary), and [file size reveals password length](https://lists.zx2c4.com/pipermail/password-store/2014-May/000938.html).
- **Incidents:** [CVE-2018-12356](https://www.notcve.org/cve/CVE-2018-12356): unanchored parsing of GPG output allowed signature spoofing. [CVE-2020-28086](https://vuldb.com/cve/CVE-2020-28086) (secondary): content was not bound to file name. Lessons: do not parse tool output for security decisions, and bind content to its name.

### gopass

- **Worth keeping:** [recipient hash pinning with a review step, `fsck`, `audit`, TOTP, and elided secrets in debug logs](https://github.com/gopasspw/gopass/blob/master/docs/security.md). CGO is disabled and no shell is used.
- **Threat model:** [no attackers on the local machine; names are visible to repository readers; rotate after revocation](https://github.com/gopasspw/gopass/blob/master/docs/security.md).
- **Incidents:** [GHSA-rw43-4vhf-hcvj](https://github.com/gopasspw/gopass/security/advisories/GHSA-rw43-4vhf-hcvj) and [GHSA-v4c2-4fvx-chr3](https://github.com/gopasspw/gopass/security/advisories/GHSA-v4c2-4fvx-chr3): a collaborator's crafted names and symlinks caused writes or deletes outside the store. Lesson: a store full of per-secret files inherits this whole class of bug.

### Teller

- **Worth keeping:** [`run`, `scan` with a CI failure mode, `redact`, and `copy` between providers](https://github.com/tellerops/teller). The current code base is Rust.
- **Threat model:** none found. It inherits each backend's.
- **Lesson:** redaction is a convenience, not a security boundary, because encoded values bypass it.

### Others reviewed briefly

- **[git-crypt](https://github.com/AGWA/git-crypt):** no revocation; an edit to `.gitattributes` can turn off encryption. Lesson: fail closed.
- **[transcrypt](https://github.com/elasticdog/transcrypt):** unauthenticated CBC. An example to avoid.
- **[dotenvx](https://github.com/dotenvx/dotenvx):** good developer experience; [look-alike packages exist](https://vulert.com/vuln-db/malicious-code-in-dotenvx-int--npm-) (secondary).
- **[chamber](https://github.com/segmentio/chamber):** explicit precedence rules for `exec`.
- **[Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets):** the clearest explanation of key renewal versus secret rotation.
- **[Passbolt](https://www.passbolt.com/incidents/passbolt-v5-1-security-audit-results):** published Cure53 results, including a High finding that clients do not verify metadata signatures. Lesson: signing without verifying gives no integrity.
- **[Akeyless](https://docs.akeyless.io/docs/dfc-deep-dive):** novel fragment cryptography. Lesson: new constructions need independent review.

## 5. Password managers

### Bitwarden

- **Worth keeping:** [generators, per-terminal session keys, a local-only API that blocks requests with an `Origin` header](https://bitwarden.com/help/cli/), [emergency access](https://bitwarden.com/help/emergency-access/), and [never storing access token values](https://bitwarden.com/help/vault-data/).
- **Threat model:** [device security is the user's responsibility](https://bitwarden.com/help/bitwarden-security-white-paper/). A stolen vault faces offline guessing against the KDF.
- **Keys:** master key, HKDF stretch, random user key, per-item keys. The [salt is the account email](https://bitwarden.com/help/kdf-algorithms/).
- **Incidents and reviews:**
  - [Palant 2023](https://palant.info/2023/01/23/bitwarden-design-flaw-server-side-iterations/): server-side iterations do not protect the encryption key.
  - [ETH Zurich](https://bitwarden.com/assets/Kki4W785JIPOdFj6EeWB5/dbf51066c1041aa90dc503ca0c911194/2025_Bitwarden_Cryptography_Report.pdf): KDF removal gave a 300,000 times cracking speed-up. A ciphertext swapped into the URL field was sent to the icon server. An unprotected type prefix allowed a downgrade to CBC.
  - [Vendor response](https://bitwarden.com/blog/security-through-transparency-eth-zurich-audits-bitwarden-cryptography/): ten issues, seven resolved or in remediation, three accepted by design.
  - [CLI 2026.4.0 on npm](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127), CVE-2026-42994: malicious package between 5:57 and 7:30 PM ET on 2026-04-22. Bitwarden reports no evidence that vault data was accessed. A forum comment gives a slightly earlier publish time.

### Vaultwarden

- **Worth keeping:** a small self-hosted server.
- **Threat model:** vault cryptography lives in the Bitwarden clients.
- **Record:** the [October 2026 advisories](https://github.com/dani-garcia/vaultwarden/security/advisories) include a revoked member keeping organisation access, and 2FA remember tokens that survive an administrator removing 2FA.
- **Lesson:** end-to-end encryption does not make server authorization irrelevant.

### KeePassXC and KDBX 4

- **Worth keeping:** [a whole-database authenticated format with block HMACs](https://keepass.info/help/kb/kdbx.html), offline-first operation, [key files, and honesty about storing TOTP with passwords](https://keepassxc.org/docs/#faq-security), [opt-in breach checks with an offline mode](https://man.archlinux.org/man/keepassxc-cli.1.txt).
- **Threat model:** the [audit](https://keepassxc.org/assets/pdf/KeePassXC-Review-V1-Molotnikov.pdf) excludes an untrustworthy OS and side channels. A sync provider can still roll the file back.
- **Audit:** [no major problems in core cryptography](https://keepassxc.org/blog/2023-04-15-audit-report/). The auditor recommended Argon2id and higher defaults. TOTP, browser integration, Auto-Type and HIBP were not reviewed.
- **Incidents:** [2026 advisories](https://github.com/keepassxreboot/keepassxc/security/advisories) include memory bugs in the legacy `.kdb` importer and in browser integration. Lesson: importers and IPC are where bugs land.
- **KeePass (not XC):** [CVE-2023-32784](https://github.com/vdohney/keepass-password-dumper) recovered the master password from memory dumps. [CVE-2023-24055](https://nvd.nist.gov/vuln/detail/CVE-2023-24055) (disputed) exported cleartext through a config trigger. Lessons: immutable strings leave residue, and config must not be able to weaken protection without authentication.

### 1Password

- **Worth keeping:** [secret references, `read`, `inject`](https://www.1password.dev/cli/secret-references/), [`run` with an honest warning about environment variables](https://www.1password.dev/cli/secrets-environment-variables/), [scoped service accounts](https://www.1password.dev/service-accounts/security), and [the two-secret key derivation](https://agilebits.github.io/security-design/modernauth.html).
- **Threat model:** [Appendix A](https://agilebits.github.io/security-design/leopard.html) states that a malicious server could perform a man-in-the-middle attack on public keys, that removal does not change keys, and that malware can read an unlocked client.
- **Incidents:** [Okta support incident, 2023](https://1password.com/blog/okta-incident): a [HAR file carried a live session](https://www.helpnetsecurity.com/2023/10/24/1password-okta-support-breach/). [CVE-2024-42219](https://support.1password.com/kb/202408a/): a local process impersonated a trusted integration over XPC. Lessons: debug artefacts carry bearer tokens, and local IPC is a trust boundary.

### LastPass (as a lesson)

- [The 2022 breach](https://blog.lastpass.com/posts/notice-of-recent-security-incident) took vault backups containing unencrypted URLs. [Older accounts had far lower iteration counts](https://palant.info/2022/12/28/lastpass-breach-the-significance-of-these-password-iterations/). A [DevOps engineer's home computer was the entry point](https://www.theregister.com/2025/12/11/lastpass_ico_fine/). Whether vaults were decrypted is contested between the ICO and later reports.
- **Lesson:** stolen ciphertext lasts forever, URLs are a targeting map, and legacy parameters must not remain in place.

## 6. Go building blocks

### OS keyring libraries

| | zalando/go-keyring | 99designs/keyring | ByteNess/keyring |
|---|---|---|---|
| Latest version | v0.2.8 (2026-03) | v1.2.2 (2022-12) | v1.15.1 (2026-11) |
| Status | Maintained | [Maintenance question unanswered](https://github.com/99designs/keyring/issues/138) | [Maintained fork](https://github.com/ByteNess/keyring) |
| macOS path | `/usr/bin/security`, no cgo | Security framework, cgo | Security framework, cgo |

- The argv exposure in go-keyring was [fixed in 2021](https://github.com/zalando/go-keyring/pull/65). The remaining macOS issue is [ownership of items by `/usr/bin/security`](https://github.com/zalando/go-keyring/issues/110), which weakens per-application access control. A [security-framework backend](https://github.com/zalando/go-keyring/pull/158) is still an open pull request.
- On Linux, go-keyring [requests the "plain" Secret Service session](https://github.com/zalando/go-keyring/blob/master/secret_service/secret_service.go).
- A native macOS path needs cgo, which conflicts with the [reproducible `CGO_ENABLED=0` recipe](https://go.dev/blog/rebuild).
- The Go vulnerability database has no entry for these modules. As go-keyring #110 shows, that is weak evidence.

### Go memory handling

- The Go garbage collector is [non-moving](https://go.dev/doc/gc-guide), but [goroutine stacks are copied on growth](https://go.dev/doc/go1.4), and libraries copy key material.
- [`runtime/secret`](https://pkg.go.dev/runtime/secret) requires `GOEXPERIMENT=runtimesecret`, carries no compatibility promise, and does nothing outside Linux amd64 and arm64 in the released documentation.
- [`x/crypto/argon2`](https://pkg.go.dev/golang.org/x/crypto/argon2) allocates its matrix on the ordinary heap, has no wiping code and panics on invalid parameters. [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) advises memory wiping where side channels are a concern, so this is a known gap.
- [memguard](https://github.com/awnumar/memguard) offers off-heap locked memory, but key bytes still enter the Go heap when passed to standard cipher packages.

### Parameters and standards

| Source | Recommendation |
|---|---|
| [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) first | Argon2id, t=1, p=4, 2 GiB, 128-bit salt |
| RFC 9106 second | Argon2id, t=3, p=4, 64 MiB |
| [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | Minimums for login verifiers, such as 19 MiB, t=2, p=1. Not suitable for an offline vault file |
| [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) | Minimum 15 characters for single-factor passwords, no composition rules, blocklist, NFC normalization, paste allowed |
| [Len et al., 2021](https://www.usenix.org/system/files/sec21-len.pdf) | Non-committing AEADs enable partitioning oracles |
| [Albertini et al., 2022](https://www.usenix.org/system/files/sec22-albertini.pdf) | Generic key commitment through two derived keys |
| [GitHub token format](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) | Identifiable prefix and CRC32 checksum |
| [GitHub, 2014](https://developer.github.com/changes/2014-12-08-removing-authorizations-token) | SHA-256 digests for high-entropy tokens at rest, because a slow KDF is unnecessary for them |

### Current versions checked on 2026-11-06

Go 1.27.3 and 1.26.10, `golang.org/x/crypto` v0.58.0, `filippo.io/age` v1.3.2, `golang.org/x/vuln` v1.9.0, gosec v2.30.0, staticcheck 2026.2.2.

## 7. Gaps in this research

- NVD pages rendered empty, so several CVE details come from project advisories or aggregators.
- Cyata's and CyberArk's own write-ups on Vault Fault could not be opened, so that chain rests on secondary reporting.
- OpenBao advisory list pages 4 and 6 were not read.
- The Cure53 reports on Bitwarden were not read in full.
- No formal threat model was available for Doppler, Conjur or Teller, and no audit report was available for many others. A "None found" entry should not be read as a criticism.
