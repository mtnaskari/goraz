---
title: goraz threat model
description: What goraz defends against, what it does not, and the limits of its rollback detection, audit log and service mode.
---

# Threat model

This applies to goraz 0.1. Any new feature must update this document first.

goraz 0.1 is a local tool and Go library. It keeps secrets, tokens and passwords in one encrypted file, and it can give each production service its own smaller encrypted file. It has no server and no network use, other than one opt-in breach check.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Secret values, passwords, TOTP seeds | The main purpose of the tool |
| Item names, URLs, usernames, tags | Names and URLs are a targeting map, as the LastPass breach showed |
| Vault master key (VMK) and derived keys | Compromise exposes everything |
| Master passphrase, key file, recovery code, machine key | Each one can unlock the vault |
| Issued tokens | Bearer credentials for other systems |
| Token verifier key | Lets a holder test candidate tokens, and is needed by every verifier |
| Audit log | Evidence of what happened |
| The release artefacts and signing identity | A compromise reaches every user |

## 2. Trust assumptions

goraz trusts these while it is running:

- The CPU, kernel and hardware.
- The Go toolchain and the small set of dependencies listed in the design document.
- The user's terminal, at the moment of entering a passphrase.
- The system clock, for token expiry. A wrong clock extends or shortens token lifetime.
- The operating system's process isolation and random number generator.

goraz does **not** trust:

- The vault file's contents, until they have been authenticated.
- Where the file is stored, such as a sync provider, backup, shared disk or git remote.
- Input files, such as imports and `otpauth://` URIs.
- Any secret-like value given to it by another program.

## 3. Attackers and what goraz does about them

### A1. Someone has a copy of the vault file

Examples: stolen laptop without disk encryption, cloud sync breach, old backup.

| Goal | Defence | Residual risk |
|---|---|---|
| Read secrets | XChaCha20-Poly1305 with 256-bit keys; all names and metadata encrypted | None known, assuming the primitives hold |
| Guess the passphrase offline | Argon2id at 1 GiB by default; 15-character minimum; optional key file kept elsewhere | **A weak passphrase can still be guessed.** Stolen ciphertext stays attackable forever |
| Learn about contents | Names hidden, values padded in steps | **Visible in the vault file:** format version, vault ID, generation, slot types, KDF parameters, item count, approximate sizes, and file modification time. **Visible if the audit log is also taken:** access times, event types and a stable HMAC per item |

### A2. Someone can modify the vault file

Examples: malicious sync provider, shared folder, tampered backup.

| Goal | Defence | Residual risk |
|---|---|---|
| Change or forge an item | AEAD with key commitment; every item bound to vault, item ID and version | **Someone who holds the VMK can forge anything.** That includes anyone with an old credential and an old file copy, until `rekey` runs |
| Swap, reorder or delete items | The encrypted manifest lists each blob's hash | Same as above |
| Lower the KDF cost | Parameters must match an exact built-in allowlist, and are authenticated in each slot | None known |
| Trigger huge memory use | Allowlist caps memory at 2 GiB; all lengths are bounded before allocation | A low-memory host can still run out of memory on a 2 GiB profile. Go can't recover from that |
| Add an unlock slot | The manifest authenticates the full header | Same as above |
| Force many KDF runs | At most one passphrase slot is allowed | None known |
| Restore an older valid file, or replace history | Generation and lineage are compared with local state | **Partial.** See section 5 |
| Destroy the file | Not prevented | **Availability is not protected.** Keep backups |
| Learn from success or failure | Key commitment closes partitioning oracles | v0.1 has no remote party, so this mainly protects later features |

### A3. Malicious input

Examples: a crafted import file, a hostile `otpauth://` URI, a malformed vault file.

Defence: strict parsers with fixed bounds, fuzz tests, Go's memory safety, and a single name canonicalizer. No field in a vault or import file may select a network address, a file path, a program or a template. That rule comes directly from the SOPS Vault token exfiltration advisory and the gopass path findings.

Residual risk: logic bugs remain possible. Fuzzing finds crashes, not every semantic error.

### A4. Logs, crash output and debug material

Examples: support bundle, shell history, CI logs, core dumps.

Defence:

- Secrets aren't accepted on argv or in environment variables.
- Audit events are typed, with no free-form field. Item names are written as HMACs.
- The `Secret` type redacts itself in formatting and JSON.
- Core dumps are disabled at startup.
- A canary test fails the build if a known secret reaches logs, errors or the audit file.

Residual risk: `goraz run` deliberately places secrets in a child's environment, and that program may log them. `GOTRACEBACK=crash` set by the user can't be fully neutralized from code.

### A5. Other local users on the same machine

Defence: file mode 0600 and directory mode 0700; checks on the open descriptor for a regular file with the correct owner and no group or world write permission; no symlinks followed, for the vault and its lock, state and audit files; and no secrets on argv.

Residual risk: root and administrators are not defended against.

### A6. Someone who steals a token or reads the token store

Defence: at least 256 bits of random secret, only an HMAC stored under a separate verifier key, mandatory expiry, revocation at each use, fail-closed on store errors, canonical parsing, and constant-time comparison.

Residual risk:

- A stolen bearer token works until it expires or is revoked. There is no sender binding in v0.1.
- With a custom store, a caching verifier may hold revocation data up to its staleness limit, 60 seconds by default. With a service file, see A9.
- A person holding the verifier key and write access to the store can't recover tokens, but can create records that verify.
- A person with store write access but no verifier key can't forge a token or change its scopes or expiry. They can clear a revocation or delete a record, unless the store itself is authenticated, as the vault file store is.

### A7. Network observer

v0.1 has only one network feature, the opt-in breach check. It sends the first five hex characters of a SHA-1 hash over TLS, and it requests padded responses. The observer learns that a check took place. HIBP sees the prefixes and the source address.

### A8. Supply chain

Defence: few dependencies, all from the Go project in v0.1; `go.sum` and the checksum database; `govulncheck`; no install scripts; static binaries; and signed, attested releases once publishing starts.

Residual risk: the maintainer's machine and GitHub account are single points of failure. The project currently has one maintainer. A bad tag can't be removed from the Go module proxy.

### A9. Attacks on a production service

| Goal | Defence | Residual risk |
|---|---|---|
| Read a service vault from an image, volume or backup | Encrypted. The machine key is delivered separately | **If the key and the file leak together, every secret in that service vault is exposed.** Use `service rotate`, then rotate the real credentials |
| Use one compromised service to reach another's secrets | Each service vault holds only its own items and has its own key | Shared items are exposed to each service that includes them |
| Reach the main vault from a service | The service holds no credential or file for it | None known |
| Replace the file with a tampered one | Full authentication on every reload; the current snapshot is kept | None known |
| Serve an older file | Refused within a running process; `MinGeneration` across restarts | **A restarted container trusts the first file it sees, unless a minimum is pinned** |
| Keep a revoked token valid by blocking or undoing updates | `MaxStale` fails closed on failures. Opt-in `valid_until` fails closed against an attacker | **Without `valid_until`, someone who can write the file volume can keep an old file in place, and only the token's own TTL limits it** |
| Use old service keys after the main vault is compromised | `rekey` marks all services, and `sync` refuses until `service rotate` | Service files already delivered stay readable with the old key until rotated |
| Learn or forge another service's tokens | Each service has its own records and verifier key | None known |
| Compromise the running service | Not defended | **The attacker gets everything that service can read.** No local tool can prevent this |
| Find secrets in the service's environment | `goraz run` warns; the `service` library avoids the environment entirely | Other processes of the same user can read an environment |

## 4. What goraz does not defend against

This list is as important as the sections above. Please read it before relying on goraz.

1. **Malware running as your user.** It can read the vault file, log your keystrokes, read process memory and read your clipboard. While a goraz command is running, its keys are in memory.
2. **Root, administrators, a compromised kernel or hypervisor.**
3. **A weak or reused passphrase.** The KDF only slows guessing.
4. **Physical and hardware attacks**, including cold boot, DMA and microarchitectural side channels. The Argon2 implementation isn't hardened for this.
5. **Memory forensics.** Go can't guarantee that secrets are erased. See the memory section of the design document. Swap and hibernation files may hold secrets, so use full-disk encryption.
6. **Loss.** If the passphrase and recovery code are both lost, the data can't be recovered. There is no backdoor and no reset.
7. **Deletion or denial of service.** Anyone who can write the file can destroy it.
8. **Old copies and old credentials.** Backups, sync history and snapshots stay decryptable with the credentials that were valid at that time. **`passwd` and `slot remove` do not revoke anything:** an old credential plus an old copy still yields the current master key, which reads and can forge current files. Only `rekey` ends this for future files, and it can't change the old copies. SSDs and copy-on-write filesystems may retain old data after `destroy`.
9. **What programs do with secrets you give them.** That includes `goraz run` children, clipboard history tools and terminal scrollback.
10. **Coercion.** There is no plausible-deniability feature.
11. **Secrets already exposed.** Revocation and removal stop future use, not past reads. Rotate the real credential at its source.
12. **TOTP as a separate factor.** A TOTP seed kept in the same vault as the password removes factor separation if the vault is compromised. It is still better than no second factor.
13. **Quantum computers, partly.** Symmetric encryption at 256 bits isn't considered at practical risk. v0.1 uses no public-key cryptography. The TLS connection for the breach check depends on the Go standard library's defaults.

## 5. Rollback: an honest limit

An AEAD can't tell that a valid file is old. goraz records the highest generation and the last accepted file per vault in a local state file, authenticated with a key held in the manifest. It refuses a lower generation or a different history unless the user passes `--accept-rollback` or `--accept-fork`.

This protects against a sync provider, shared drive or backup medium replaying an older file. It also surfaces a sync conflict, which would otherwise lose one device's writes silently. It does not protect against:

- A new device, which has no state yet and trusts what it first sees.
- An attacker who can restore both the vault and the state file together.
- A same-user attacker, who is out of scope anyway.
- A jump of more than 32 generations, where continuity can't be checked. goraz accepts this with a warning.

Restoring a Time Machine or VM snapshot, or deliberately restoring a backup, will produce a legitimate rollback error. That is why the override exists. Using it is written to the audit log, and it discards the other history, because v0.1 doesn't merge.

## 6. Audit log limits

The audit log detects edits and gaps under a hash chain with an HMAC key. It is **tamper-evident, not tamper-proof.**

- Whoever holds the audit key can rewrite the log. Everyone who can unlock the vault holds that key.
- Removing recent entries is only detected back to the last vault write, because each device's position is anchored in the manifest at each write.
- Each device keeps its own log, which isn't synced or part of a vault backup. Losing that device's state directory loses its log and gives the device a new identity.
- It is not encrypted. Timestamps, event types and per-item HMACs are visible to anyone who reads it.
- It records what goraz did, on the machine it ran on. A client-side log can't prove that nothing else read the file.
- On a read-only filesystem without an explicit sink, reads fail. A service supplies a sink, and that stream has no hash chain, so its integrity depends on the receiving log system.

## 7. Claims goraz will not make

- It has **not had an independent security audit.**
- It will not describe itself as "zero knowledge", "unhackable" or "military grade".
- It will not claim that memory is wiped. Only that it attempts to reduce exposure.
- It will not claim FIPS compliance.

## 8. Rules for future features

A new feature must answer these before it is built:

1. Does any data field choose a network address, path, program or template? It must not.
2. Who authenticates this input, and when, compared with when it is parsed?
3. Does it add a key that isn't separated by purpose?
4. Does it add a code path for older or weaker formats? It must not.
5. Does it need public keys? They must be authenticated first.
6. What does it add to section 4?
