---
title: goraz security design and file format
description: The cryptography, key hierarchy, file format, token design and memory limits of goraz, written to serve as its format specification.
---

# Security design

This describes goraz 0.1, and it serves as the format specification, so it is deliberately precise. The threat model is in [threat-model.md](threat-model.md).

## 1. Principles

1. **No new cryptography.** goraz composes vetted primitives using published constructions. Section 4 cites each composition, because a composition can still be wrong. It needs independent review, and it hasn't had one.
2. **One suite, no negotiation.** Format v1 has exactly one algorithm set. A change of algorithm is a new format version and a one-way migration, following age's approach.
3. **No legacy paths.** There is no fallback to any older or weaker format. ETH Zurich's BW10 to BW12 attacks all came from such paths.
4. **Authenticate exact bytes, not a re-serialized structure.** This avoids the canonicalization failure in SOPS issue #2243.
5. **Nothing in a vault chooses a network address, path, program or template.**
6. **Parse with limits, authenticate, then use.** Plaintext is never released before verification.
7. **Few dependencies.**

## 2. Primitives

| Purpose | Primitive | Source |
|---|---|---|
| Password KDF | Argon2id v1.3 | `golang.org/x/crypto/argon2` |
| Key derivation | HKDF-SHA-256 | `crypto/hkdf` |
| AEAD | XChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` |
| Hash | SHA-256 | `crypto/sha256` |
| MAC | HMAC-SHA-256 | `crypto/hmac` |
| Randomness | Only `crypto/rand` | Standard library |
| Comparison | `crypto/subtle.ConstantTimeCompare` | Standard library |
| Breach check prefix, TOTP default | SHA-1 | Required by HIBP and RFC 6238 compatibility. Never used for vault integrity |

**Why XChaCha20-Poly1305 and not AES-256-GCM.** Random 96-bit GCM nonces carry a [limit of 2^32 encryptions per key](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf). That needs counting, and counting is unreliable once a file moves between devices. A 192-bit nonce removes this class of problem. The cost is that XChaCha20 is outside the Go FIPS module, and its [IETF draft expired](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha) without becoming an RFC.

**Allowed dependencies in v0.1:** `golang.org/x/crypto`, `golang.org/x/term`, `golang.org/x/sys`, `golang.org/x/text`. The CLI uses the standard `flag` package. Any addition needs a written reason.

## 3. Key hierarchy

```
passphrase (NFC) ──Argon2id──┐
key file (optional, 32 B) ───┴─HKDF─► slot key ─┐
recovery code (256-bit) ───────HKDF─► slot key ─┼─ unwraps ─► VMK (random, 256-bit)
machine key (256-bit) ─────────HKDF─► slot key ─┘               │
                                                                ├─ HKDF "manifest" ─► manifest key
                                                                └─ HKDF "item" ─────► item root key

stored inside the encrypted manifest, independent of the VMK:
  token verifier keys (random, 256-bit, each with a key ID)
  audit keys (random, 256-bit, each with a key ID)
  local state key (random, 256-bit)
```

- **Why slots:** several independent credentials can open one vault, and a passphrase can change quickly.
- **At most one passphrase slot.** v0.1 is a single-user tool. This keeps every command to one Argon2 run, and it means tampering can't force many expensive runs. Slots of other types use HKDF only.
- **Why these keys are random and separate:** a service with its own token store can receive only the verifier key. The state key must also survive a rekey, so that a device that hasn't seen the rekey can still check its local state.
- **No key is used for two purposes.** All HKDF labels are unique and listed in section 4.

### Rotation and revocation

**Only `rekey` revokes access.** `passwd` and `slot remove` don't change the VMK. Anyone who holds an old credential and an old copy of the file, for example from sync history or a backup, can recover the unchanged VMK. With it they can decrypt current and future files, and they can forge files that verify, including new slots and changed settings. Both commands say this when they run, and offer `rekey`.

| Operation | What changes | Limits |
|---|---|---|
| `goraz passwd` | Replaces the passphrase slot | **Doesn't revoke the old passphrase.** Use it for routine changes only |
| `goraz slot add` or `remove` | Adds or removes a slot | **Doesn't revoke the removed credential.** Use `rekey` after a suspected exposure |
| `goraz rekey` | New VMK, all items re-encrypted, new audit and verifier keys, generation raised | See below |
| `goraz audit rotate-key`, `goraz token rotate-verifier` | Adds a new active key. Old audit keys are kept for verifying old entries only | Verifier keys may overlap for a set period, otherwise tokens under the old key stop working |
| Rotating a secret value | The real credential, at its source | goraz can only store the new value. Secrets that were readable before the rekey must be treated as exposed |

**`rekey` behaviour:**

- The passphrase is entered again. A new recovery code is displayed, and the user must confirm having saved it **before** the file is replaced, so a crash can't lose it.
- Machine slots are dropped unless `--reissue-machine` is given. New machine keys are written to the requested descriptor before the file is replaced.
- Every service vault is marked as needing rotation (section 14A).
- Audit and verifier keys are rotated by default, because an ex-holder could otherwise forge audit entries or, with store write access, tokens. This invalidates issued tokens. `--keep-tokens` retains the verifier key for a routine rekey with no suspected compromise.
- The local state key is preserved. It only protects a local file, so it doesn't extend what an ex-holder can do without local write access.

This keeps "who can decrypt" separate from "what the secret is", as SOPS does with `updatekeys` and `rotate`. `rekey` avoids [1Password's documented gap](https://agilebits.github.io/security-design/leopard.html), in which a credential change doesn't create new keys.

## 4. Sealed envelope

Every encrypted object in the format uses one construction. It applies the generic key-commitment transform from [Albertini et al., USENIX Security 2022](https://www.usenix.org/system/files/sec22-albertini.pdf) to XChaCha20-Poly1305, and it is motivated by the partitioning oracles of [Len et al., 2021](https://www.usenix.org/system/files/sec21-len.pdf).

```
seal(K, domain, context, plaintext):
    nonce  = random(24)
    ad     = "goraz/v1/ad" || LP(domain) || LP(context)
    prk    = HKDF-Extract(SHA-256, secret = K, salt = nonce)
    h      = SHA-256(ad)
    Kenc   = HKDF-Expand(prk, "goraz/v1/enc" || 0x00 || h, 32)
    Kcom   = HKDF-Expand(prk, "goraz/v1/com" || 0x00 || h, 32)
    ct     = XChaCha20-Poly1305(Kenc, nonce, plaintext, ad)
    return nonce || Kcom || ct

open(K, domain, context, blob):
    derive Kenc and Kcom the same way from blob's nonce
    if not ConstantTimeCompare(Kcom, blob.Kcom): fail
    return XChaCha20-Poly1305.Open(Kenc, nonce, ct, ad)
```

`LP(x)` is a 4-byte big-endian length followed by `x`. Overhead is 24 + 32 + 16 = 72 bytes.

**Properties sought:**

- **Key commitment:** a blob opens under one key only, because `Kcom` is a collision-resistant function of `K`, the nonce and the context.
- **Context binding:** a blob can't be moved to another slot, vault, item or version. This defeats the BW05 field swap and CVE-2020-28086 in pass.
- **Nonce safety:** a fresh `Kenc` per nonce, and a 192-bit random nonce.

**Review needed:** the transform is published, but this instantiation with HKDF and XChaCha20-Poly1305 hasn't been analysed by anyone other than its authors. This is the first thing an external reviewer should check.

**Domains:** `"slot"`, `"manifest"`, `"item"`, each with a fixed context as defined below.

**VMK subkeys:** `HKDF(SHA-256, secret = VMK, salt = vault_id, info = label)`, where the label is `goraz/v1/key/manifest` or `goraz/v1/key/item`.

## 5. File format v1

All integers are big-endian. The file is parsed sequentially, and any trailing byte is an error.

```
Header
  magic          8    "GORAZv1\n"
  vault_id       16   random
  generation     8    uint64, strictly increases on every write
  slot_count     1    1..16
  slots          variable
  manifest_len   4    uint32, at most 64 MiB

Body
  manifest blob  manifest_len bytes
  item blobs     in manifest order, with lengths from the manifest
```

The magic is the only version indicator. Unknown magic is refused. There is no "minimum version" or optional-feature negotiation.

### Slots

The type byte fixes the length. An unknown type is refused rather than skipped, because a new type means a new format version. A file with more than one passphrase slot is refused before any KDF run.

```
Passphrase slot (type 0x01), 147 bytes
  type 1 | slot_id 16 | salt 16 | m_kib 4 | t 4 | p 1 | has_keyfile 1 | blob 104

Recovery slot (0x02) and machine slot (0x03), 121 bytes
  type 1 | slot_id 16 | blob 104
```

A blob is 104 bytes: 72 bytes of overhead plus the 32-byte VMK.

```
slot_context = vault_id || all slot fields before the blob
slot blob    = seal(slot_key, "slot", slot_context, VMK)

passphrase:  a = Argon2id(NFC(passphrase), salt, t, m_kib, p, 32)
             slot_key = HKDF(secret = LP(a) || LP(keyfile or empty), salt = vault_id,
                             info = "goraz/v1/unlock/passphrase")
recovery:    slot_key = HKDF(secret = code, salt = vault_id, info = "goraz/v1/unlock/recovery")
machine:     slot_key = HKDF(secret = key,  salt = vault_id, info = "goraz/v1/unlock/machine")
```

Recovery codes and machine keys have 256 bits of entropy from `crypto/rand`, so they skip Argon2.

### KDF allowlist

The header's parameters must match one of these exact tuples before Argon2 is called. Otherwise the file is refused. This addresses both downgrade and memory exhaustion. It also prevents the panic that `x/crypto/argon2` raises on invalid values.

| Profile | Memory | t | p | Use |
|---|---|---|---|---|
| `interactive` | 64 MiB | 3 | 4 | RFC 9106 second recommendation. Explicit flag only, for constrained hosts |
| `standard` | 256 MiB | 3 | 4 | Explicit flag |
| `strong` (default) | 1 GiB | 3 | 4 | Default for new vaults |
| `max` | 2 GiB | 1 | 4 | RFC 9106 first recommendation |

The authentication of KDF parameters alone would be [circular, as the ETH paper notes](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf), because the key comes from them. The client allowlist is what actually defends against a downgrade.

Measured on one Apple Silicon Mac, a command that unlocks a vault took about 0.13 s with `standard`, 0.5 s with `strong` and 0.37 s with `max`, including process start. Slower or memory-limited hosts will differ, and a host that can't allocate the profile's memory will run out of memory. A KDF run happens at most once per command.

### Manifest

```
manifest blob = seal(manifest_key, "manifest", SHA-256(all header bytes), JSON)
```

The header hash covers the slots and generation, so **this single blob authenticates the whole header**. It is the root of trust, and there is no separate header MAC.

The JSON holds settings, keys, the file's lineage, audit anchors, and the item list:

```
{
  "created": ..., "audit_required": true,
  "keys": {
    "state": "...",
    "token_verifier": [{"id": 2, "key": "...", "retire_at": null}],
    "audit": [{"id": 3, "key": "...", "active": true}]
  },
  "lineage": [{"generation": 41, "sha256": "..."}],
  "audit_anchors": {"<device_id>": {"seq": 120, "mac": "..."}},
  "items": [{
    "id": "<16 random bytes, base64>", "name": "prod/db/password",
    "type": "secret|login|token|totp", "tags": [...],
    "created": ..., "updated": ..., "expires": ...,
    "versions": [{"version": 3, "length": 512, "sha256": "...", "created": ...}]
  }]
}
```

`lineage` holds the whole-file SHA-256 of up to the last 32 generations, which section 7 uses to detect forks. `audit_anchors` holds up to 64 devices.

Byte fields are base64-encoded by JSON. JSON is used only after authentication. Its bytes are authenticated as they are and never re-serialized for checking.

### Items

```
item blob = seal(item_root_key, "item", vault_id || item_id || version_u32, padded)
padded    = len_u32 || content || zero padding to the next multiple of 256 bytes
```

- After decryption, the padding must be all zeros and the length must fit.
- Content is one JSON object holding all fields, so a field can't be swapped into another. Values are stored base64-encoded through a dedicated storage type, so non-UTF-8 values survive. The public `Secret` type always redacts itself, and is never used for storage encoding.
- Values are limited to 1 MiB in v0.1. At most 10 versions are kept by default.
- The total file limit in v0.1 is 1 GiB.

Item blobs are verified and decrypted one at a time, so reading one secret doesn't place every secret in memory.

## 6. Opening a vault

The exceptions for read-only service vaults are stated in section 14A.

1. Take a shared lock on `<vault>.lock`. Open the vault with `O_NOFOLLOW | O_NONBLOCK`, so a FIFO can't block the process. Call `fstat` on the descriptor and require a regular file owned by the current user, with no group or world write permission. The same checks apply to the lock, state and audit files.
2. Read with a size limit. Parse the header strictly.
3. Validate KDF parameters against the allowlist.
4. Try the given credential against the slot of that type. A failure returns `ErrWrongCredential`, because a wrong passphrase and a tampered slot are indistinguishable at this stage.
5. Derive the manifest key and open the manifest. A failure now returns `ErrTampered`.
6. Check that the body's total length matches the manifest exactly.
7. Compare with local state (section 7).
8. Release the shared lock.
9. On each item request, verify that blob's SHA-256, then open it. A failure returns `ErrTampered` **for that item only**, so one damaged blob doesn't make every other secret unreadable. Because no `.bak` exists, this matters for recovery.

Before any rewrite, all blob hashes are verified. A write is refused if any of them fails, so that a damaged file isn't silently carried forward. `goraz doctor` runs the same check on demand.

## 7. Writes and rollback

**Writing:**

1. Take an exclusive lock on `<vault>.lock`.
2. Re-read the file and confirm that its **whole-file hash** matches the one this process opened. A generation comparison alone would miss a same-generation file delivered by sync.
3. Verify all blob hashes.
4. Build the new file with generation = max(file generation, recorded high generation) + 1, and append the previous file's generation and hash to `lineage`.
5. Write to a temporary file in the same directory with `O_EXCL` and mode 0600, `fsync` it, rename it into place, then `fsync` the directory.
6. Update local state, and only then release the lock.

If a crash happens between steps 5 and 6, the file is simply ahead of the state, which is accepted on the next open.

**No automatic `.bak`.** A backup would keep removed slots and destroyed secrets alive. Crash safety comes from the atomic rename. This is a deliberate trade-off.

**Local state:** `$XDG_STATE_HOME/goraz/vaults/<vault_id>.state` is updated under its own lock, and holds:

- `high_generation`, the highest generation ever accepted. **It never goes down.**
- `pinned`, the generation and hash of the last accepted file.
- `device_id`, a random local identifier used by the audit log.
- An HMAC under the state key from the manifest.

On a lower generation or a mismatch, the file is re-read once under the shared lock before an error is returned, to avoid false alarms from a concurrent writer.

| Situation | Result |
|---|---|
| No state yet | Trust on first use, and record it |
| File hash equals `pinned` | Accepted |
| Generation above `pinned`, and `lineage` contains `pinned` | Accepted, `pinned` moves forward |
| Generation above `pinned`, and `lineage` disagrees with `pinned` | `ErrFork`. Another device's writes replaced this one's |
| Generation above `pinned` by more than the lineage window | Accepted with a warning that continuity can't be verified |
| Same generation as `pinned`, different hash | `ErrFork`, for example two devices writing through sync |
| Generation below `high_generation` | `ErrRollback` |
| State MAC invalid | `ErrStateInvalid`. Resetting state is an explicit command, and returns to trust on first use |

`--accept-rollback` and `--accept-fork` pin this exact file, leave `high_generation` unchanged and write an audit entry. They **discard** the other history: v0.1 doesn't merge. A later write takes a generation above `high_generation`, so other devices that hold the abandoned history see `ErrFork` rather than losing data silently.

The limits are stated in [threat-model.md](threat-model.md#5-rollback-an-honest-limit).

## 8. Names

One function canonicalizes names, and every operation passes through it before any check or lookup. Vault CVE-2026-3605, CVE-2025-6004 and CVE-2025-6014, and OpenBao GHSA-fg5x-7whg-6c28, are all failures of this rule.

- Segments are separated by `/`. Each segment matches `[A-Za-z0-9._-]+`, with no `.` or `..` segment.
- Maximum 255 bytes and 16 segments.
- **Non-canonical input is rejected, not corrected.** No percent decoding, no whitespace trimming, no Unicode.
- Names that differ only by case are refused as duplicates.

Names never become file paths, so the gopass class of path and symlink bugs doesn't apply to the store.

## 9. Passphrases

- Read from a terminal with `x/term` into `[]byte`, or from a file descriptor with `--passphrase-fd`. **Never from argv or an environment variable.**
- With `--passphrase-fd`, exactly one trailing `\n` or `\r\n` is removed, and nothing else is changed. A NUL byte is refused.
- NFC-normalized before use, per [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html). Without this, one passphrase typed on two systems could fail to unlock.
- Maximum 512 bytes, enforced with an error. Terminals in canonical mode can silently truncate long lines at about 1 KiB, and a silent truncation could lock a user out.
- Minimum 15 characters, a blocklist of common values, no composition rules and no truncation. `goraz init` offers a generated passphrase of at least 6 words from the EFF large wordlist, about 77 bits.

## 10. Memory handling and its limits

**Memory protection in goraz is best-effort hardening, not a guarantee.** Go offers no way to guarantee erasure.

**What goraz does:**

- Holds secrets in `[]byte` where the API allows it, and clears them with `clear()` when finished.
- Keeps the VMK in an `mmap`ed, `mlock`ed region with `MADV_DONTDUMP` on Linux where available. It falls back with a diagnostic if this fails.
- Sets `RLIMIT_CORE` to 0 at startup, and `PR_SET_DUMPABLE` to 0 on Linux. On macOS only `RLIMIT_CORE` is used. `PT_DENY_ATTACH` isn't used, because same-user attackers are out of scope and it would carry over to programs started by `goraz run`.
- `goraz run` replaces its own process with the target program, so the keys don't stay in a parent process. The core limit is restored first, so that the program behaves normally.
- Has short-lived CLI processes, which limit exposure.
- Provides `goraz doctor`, which reports the protections actually active on that machine.

**What can't be guaranteed:**

- Key bytes are copied into heap state when passed to standard cipher packages.
- `x/crypto/argon2` allocates its full matrix on the heap, spawns goroutines and doesn't wipe it. The matrix is derived from the passphrase. RFC 9106 advises wiping where side channels matter, and this library has no such option.
- Goroutine stacks are copied when they grow, leaving old copies behind.
- Strings can't be wiped. Parsing JSON into strings means that names, usernames, URLs and notes can't be erased. Password and secret values are decoded to `[]byte` where possible, but `encoding/json` makes temporary copies.
- Swap, hibernation and suspend can write memory to disk regardless of `mlock`.

**`runtime/secret`:** it is experimental, has no compatibility promise and silently does nothing on macOS and Windows. goraz will support it behind a build tag on Linux, and `doctor` reports `secret.Enabled()`. It isn't relied on, and no security claim depends on it. `memguard` isn't used, because it doesn't solve the library boundary and it adds `unsafe` and a dependency.

## 11. Randomness and comparison

- `crypto/rand` is the only randomness source. `math/rand` is banned by gosec rule G404 and a review rule. Since Go 1.24, `crypto/rand.Read` doesn't return an error. It crashes on failure, which is the correct behaviour here.
- Generators use rejection sampling to avoid modulo bias.
- `subtle.ConstantTimeCompare` is used for commitment values, token verifiers, MACs and TOTP codes. Note that it doesn't hide length, so compared values must have a fixed length.
- AEAD and HMAC checks use the library's own verification.

## 12. Tamper detection summary

| Change | Detected by |
|---|---|
| Any header byte | Manifest blob's context, the header hash |
| A slot's KDF parameters | Allowlist, then slot context |
| A slot from another vault | Slot context contains `vault_id` |
| Manifest byte | AEAD and commitment |
| Item byte | SHA-256 in the manifest when read or before a rewrite, then AEAD |
| Item moved to another name or version | Item context |
| Item deleted or added | Manifest list and exact length check |
| Trailing data | Exact length check |
| Older whole file | Generation against local state |
| A different history with a higher generation | `lineage` against the pinned file |
| Audit entry altered, or removed from the middle | HMAC chain |
| Audit log truncated or deleted | Anchor in the manifest, checked before each append |

**One thing this doesn't detect:** a holder of the unchanged VMK can produce a file that passes every check above. See section 3.

A test will flip each bit in a golden vault file, and assert that the vault fails to open or that the affected read fails, and never returns altered data.

## 13. Audit log

File: `$XDG_STATE_HOME/goraz/audit/<vault_id>/<device_id>.log`. Each device has its own log, and it isn't stored beside the vault, so a synced folder can't produce conflicting appends. The location can't be set from vault data, to avoid the CVE-2025-6000 class.

```
entry_n = seq | timestamp | key_id | event_type | outcome | actor | object_hmac | prev_mac | mac
mac     = HMAC-SHA-256(audit_key[key_id], canonical bytes of the fields before mac)
```

- **Typed events only.** The event struct has no free-form string, no error text and no value field. This makes accidental secret logging structurally difficult.
- **Names are HMACed** with the audit key. `goraz audit hash <name>` computes a value for searching, like Vault's `audit-hash`. The log itself is not encrypted, so timestamps, event types and stable per-item HMACs can be seen by anyone who reads it.
- **Fail closed.** An operation that releases a secret writes its audit entry first. If the write fails, the secret isn't released, and `ErrAuditUnavailable` is returned. `audit_required` lives in the authenticated manifest, so an edit to an outside config can't disable it (the CVE-2023-24055 lesson).
- **Read-only environments.** A service gives an explicit sink (section 14A), which needs no writable disk. Without a sink, the rule stops every read on a read-only mount or a full disk, and returns `ErrAuditUnavailable`.
- **Appending.** Each append takes an exclusive lock on the log, and holds it across reading the tail, confirming that the vault hash hasn't changed (so a stale key isn't used), appending, and `fsync`. Two concurrent readers therefore can't fork the chain. A key rotation takes the same lock.
- **Anchored.** Each vault write stores this device's sequence number and MAC in `audit_anchors`. Before each append, goraz confirms that the log contains that entry and that the chain from it to the tail is valid. On a failure, it returns `ErrAuditTruncated`. `--accept-audit-gap` continues and writes a gap entry.
- **Canary test.** CI runs all commands with a known secret value and token, then searches the audit file and all output for them, in raw, base64 and hex forms.

A crash or a full disk can leave an incomplete last line. The next append removes it, because it was never a whole entry, and the anchor still catches removal of whole entries. A failed write is also truncated back at once.

A forward-secure key ratchet and remote log forwarding are candidates for v0.2.

## 14. Tokens

### Format

```
<prefix>_<kind>_<body><check>

prefix  "goraz", or an application prefix matching [a-z]{2,10}
kind    "st" service token, "mk" machine key
body    fixed-width base62 of id(16 bytes) || secret(32 bytes), 65 characters
check   6-character base62 CRC32 of everything before it
```

The prefix and checksum exist so that [scanners can find tokens with few false positives, as with GitHub's format](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/). **CRC32 is not a security check.**

Parsing is strict: exact length, exact alphabet, canonical encoding, and valid checksum, all before any store lookup. This is the CVE-2025-6014 lesson. `token.Verify` accepts only kind `st` with the expected prefix, so a machine key pasted by mistake never reaches a service's store or log. The machine key parser accepts only `goraz_mk_`, and its `id` is the slot ID.

Recovery codes use a different format, because a person may have to type them: `GORAZ-RC-` followed by case-insensitive Crockford base32 of 32 random bytes plus a checksum, in groups of four.

### Issue

- The secret comes from `crypto/rand`. Tokens chosen by a user are never accepted.
- A TTL is required. Default 24 hours, maximum 90 days unless configured. "Never expires" doesn't exist.
- The token is displayed once and can't be recovered.
- The `id` works like a Vault accessor. It can list and revoke but can't authenticate.
- The store records the following, plus the mutable `revoked` and `revoke_at` fields:

```
id, key_id, name, kind, prefix, scopes, issued, expires, mac

mac = HMAC-SHA-256(verifier_key[key_id],
        "goraz/v1/token" || LP(kind) || LP(prefix) || LP(id) || LP(secret)
        || LP(sorted scopes, each LP-encoded) || issued_u64 || expires_u64)
```

The MAC covers the record's immutable fields, so a party that can write to the store, but lacks the verifier key, can't raise a token's scopes or extend its expiry.

### Verify

```
parse strictly (kind and prefix) → ErrInvalidToken
look up id                       → store error: fail closed, ErrUnavailable
                                 → not found or unknown key_id: compute a dummy HMAC, ErrInvalidToken
compare MAC in constant time     → ErrInvalidToken
revoked?                         → ErrInvalidToken
now >= min(expires, revoke_at)?  → ErrInvalidToken
required scope exact match?      → ErrForbidden
send the outcome to the audit sink
```

All credential failures return the same error to the caller, and the audit log records the reason. Scopes are opaque strings matched exactly. There are no wildcards, so the OpenBao policy expansion and glob-priority problems don't arise.

**Limit: the store must be trusted for revocation.** A store writer can't forge a token, but it can clear `revoked` or delete a record. In the vault file store, revocation is authenticated by the manifest. In a service's own database, it is only as trustworthy as that database.

### Revoke and rotate

- `Revoke` takes effect on the next check against the store. A long-running verifier that caches a custom store must refresh within a staleness limit, default 60 seconds. Past this limit, it fails closed. Section 14A states the limits for a service file.
- `Rotate` issues a successor and sets the old token's `revoke_at` to the end of an overlap period, as with [Stripe](https://docs.stripe.com/keys) and [Doppler's two-secret rotation](https://docs.doppler.com/docs/secrets-rotation).
- The library defines `Store` and `AuditSink` interfaces. The included stores are the vault file and an in-memory store for tests.
- `token.NewVerifier(keys, store, sink)` lets a service verify tokens with its own store and with only the verifier keys. It doesn't need the VMK or the audit key. With the included vault file store, the vault has to be unlocked, so this separation applies only to a custom store.

**Why HMAC and not Argon2 for tokens:** these secrets have 256 bits of entropy, so offline guessing isn't practical, and verification runs on each request. [GitHub made the same choice](https://developer.github.com/changes/2014-12-08-removing-authorizations-token). The HMAC key adds protection when only the database is stolen.

**Why no signed tokens yet:** a stateless token can't be revoked before it expires. Revocation is a stated requirement. PASETO v4 is a candidate later, and JWT is avoided for its [known algorithm-confusion pitfalls](https://www.rfc-editor.org/rfc/rfc8725.html).

## 14A. Service mode

Service mode lets a production service read its tokens and secrets without a person present. It adds no server and no network listener.

### Service vaults

A service never receives the main vault. An operator exports a **service vault**, which is an ordinary v1 file with its own random VMK and a single machine slot. It contains only the selected items, so **the limit on what a service can read is enforced by encryption, not by a policy check.**

```
goraz service create api --prefix prod/api --out api.goraz --key-out api.key [--valid-for 24h]
goraz service sync   api --out api.goraz
goraz service rotate api --out api.goraz --key-out api.key
goraz service remove api
goraz token issue --service api --name billing --scope payments:read
```

- `--prefix` matches whole name segments: `prod/api` selects `prod/api` and `prod/api/x`, and never `prod/apiary`.
- Only the latest version of each selected item is copied. History stays in the main vault.
- **Output paths come from the command line only**, and are never stored in the vault. This keeps principle 5.
- **The main manifest stores each service's full state:** name, prefixes, machine key, VMK, vault ID, generation, last file hash, lineage, keys, freshness window and tokens. Anyone who can unlock the main vault can already read those items, so this adds no new access. It means `sync` works from any device that can open the main vault, without the previous file.
- **Write order.** `sync` builds the new service file, commits the main vault with its generation and hash, and then writes the service file. If a crash happens between them, the next sync uses a later generation whose lineage still contains the last delivered file, so replicas accept it.
- **Two operators** can't silently produce conflicting service files, because the main vault's own fork detection catches concurrent syncs.

### Revocation and rotation of a service

- `service rotate` gives the service vault a new VMK, machine key, audit key, state key and verifier key. **It is the only way to revoke a leaked service key.** The old key still opens old copies of the file. Tokens issued for that service stop working, because a compromise means they should.
- **`rekey` of the main vault marks every service as needing rotation**, because an ex-holder of the main vault may have extracted the stored machine keys. `service sync` refuses a marked service until `service rotate` has run, so new secrets aren't sent under a key that may be exposed.

### Tokens for a service

Tokens for a service belong to that service. `token issue --service api` creates a record under a **verifier key unique to that service**, and stores it with the service's state. The service file holds only its own records and key. A compromised service therefore learns nothing about other services' tokens and can't forge them.

### Delivering the key

| Method | Flag or API | Notes |
|---|---|---|
| Kubernetes secret, Docker secret, systemd credential | `--machine-key-file`, `service.KeyFile(path)` | Symlinks are followed, because Kubernetes mounts secrets through them |
| Inherited file descriptor | `--machine-key-fd`, `service.KeyFD(fd)` | Read once and kept in memory |
| Environment variable | Not supported | Readable by same-user processes and often logged |

A key file must be a regular file, owned by the current user or by root, not writable by group or others, and not readable by others. Group read is allowed. It holds one key per line, up to four, and the client picks the one whose ID matches the file's slot.

Working configurations, which are also given in the error message:

- **Docker:** `secrets: [{source: goraz, uid: "1000", mode: 0400}]`. The default mode is world-readable, and with the default uid a non-root process can't read mode 0400. File-backed Compose secrets may ignore `mode`.
- **Kubernetes:** `defaultMode: 0440` with `securityContext.fsGroup` set to the service's group. The default 0644 is refused.
- **systemd:** `LoadCredential=`. No extra setting is needed.

**The first key is a real limit.** The machine key has to exist somewhere on the host. goraz protects the file at rest and separates services from each other. It can't protect a service's own secrets from an attacker who controls that service.

### Rotating without an outage

A new VMK means each file opens under exactly one key, and a file and its key can't be replaced at the same instant. So rotation has an order:

1. Add the new key to the key file, which now has two lines. Running services re-read it at each reload.
2. Deploy the new service file.
3. Remove the old key line.

A method that fixes the key at startup, such as `KeyFD` or a credential that only changes on restart, needs a restart at step 2. The client reports this through `OnReloadError` rather than failing silently.

### Runtime

```go
c, err := service.Open(ctx, service.Options{
    Path:     "/etc/goraz/api.goraz",
    Key:      service.KeyFile("/run/secrets/goraz-key"),
    Audit:    audit.NewJSONSink(os.Stdout),
    Interval: 30 * time.Second,
    MaxStale: 15 * time.Minute,
})
token, err := c.Value("prod/api/stripe")
```

**Reloading.** Every `Interval`, the client reads the file, and re-reads the key source if it can. A changed file goes through the full open sequence, and it is swapped in only after it succeeds. A file that is damaged, tampered with, older, or from a different history is rejected, the current snapshot stays in place, and `OnReloadError` reports it. A snapshot holds its own bytes, so a later file swap can't cause a false `ErrTampered`.

**Staleness.** Keeping the old snapshot is correct for a short deployment glitch, but it must not hide a permanent failure. `Value` computes staleness from the time of the last successful check, so a blocked reload can't stop the timer. After `MaxStale`, it returns `ErrStale`. The default is 15 minutes, and `service.NoStaleLimit` must be set explicitly to turn it off. An unchanged file counts as a successful check.

**Freshness.** `MaxStale` catches failures, **not an attacker**. Someone who can write the file volume can restore the last accepted bytes, which look unchanged, so revoked tokens stay valid. A frozen `subPath` mount or Docker secret causes the same effect by accident. `--valid-for` writes an authenticated `valid_until` into the service file, and after that time the client returns `ErrExpired`. This requires a scheduled `service sync`, so it is opt-in. **Without it, only a token's own TTL limits how long a revoked token can keep working.** `service sync` warns when a service has tokens and no window.

**Audit.** A service must be given an `Audit` sink if `audit_required` is on, which is the default. `audit.NewJSONSink` writes one typed JSON event per line to any `io.Writer`, so read-only containers can send audit data to stdout. A write failure stops the secret being released. This sink has no hash chain, so integrity depends on the log system that receives it. The CLI equivalent is `--audit stderr`.

**Rollback in containers.** A container often has no persistent state. Inside one process, the client keeps the highest generation and refuses to go below it, but **a restarted container trusts the file it first sees**. `MinGeneration` lets a deployment pin a minimum, and `valid_until` limits how old an accepted file can be.

**Exceptions to the general file rules.** A service vault is opened read-only, with these differences from section 6: no lock is taken and no state is written; the path may be a symlink; and the owner may be root. The regular-file check on the open descriptor, `O_NONBLOCK`, the size limit and the no-write-by-others rule all still apply, so a symlink to a FIFO can't block the client.

### Tokens in a service

```go
v, err := c.Verifier(sink)
rec, err := v.Verify(ctx, presented, "payments:read")
```

Revocation reaches a service through `token revoke`, then `service sync`, then deploying the file, then the next reload. **That is not immediate.** A service needing immediate revocation should implement `token.Store` on its own database and use `token.NewVerifier` directly. In that setup, the 60-second cache limit in section 14 applies. For a service file, the limit is `MaxStale` for failures, and `valid_until` for an attacker.

## 15. Password management

- **Generator:** `crypto/rand`, default 24 characters from a safe alphabet, or passphrases from the EFF large wordlist. The list is embedded and its hash is checked in a test.
- **TOTP and HOTP:** implemented on `crypto/hmac` with RFC 4226 and RFC 6238 test vectors. This is a small amount of code, and it avoids a dependency that brings QR libraries. MD5 isn't offered. `otpauth://` parsing is strict and fuzzed.
- **Clipboard:** `pbcopy`, `wl-copy` or `xclip`, each resolved to an absolute path, with the value passed on stdin. A detached process that holds only the SHA-256 of the value clears the clipboard after 20 seconds, if it still contains that value.
- **Breach check:** only with `--hibp`. It sends the first 5 hex characters of the SHA-1 to [the range API](https://haveibeenpwned.com/API/v3) with `Add-Padding: true`, and it compares suffixes locally.
- **No icons, no autofill, no other network requests.**

## 16. Safe defaults

| Setting | Default | Override |
|---|---|---|
| KDF | `strong`, 1 GiB | Allowlisted profiles only |
| Passphrase length | Minimum 15 | `--accept-weak-passphrase`, with a warning |
| Token TTL | 24 hours, required | Up to the configured maximum |
| Audit | On, fail-closed | Only through an authenticated setting change. A service supplies its own sink |
| Network | Off | `--hibp` per run |
| Clipboard clear | 20 seconds | Configurable, can't be disabled |
| Secret to a terminal | Refused for `export`, explicit for `read` | `--force` |
| Environment injection | Only through `goraz run` | A warning is displayed, `--no-warn` hides it |
| File permissions | 0600 for files, 0700 for directories goraz creates | None. Opening a vault others can write to is refused |
| Service staleness | Fails after 15 minutes of failed reloads | `MaxStale`, explicit `NoStaleLimit` |
| Service machine key | Refused if others can read it | None |
| Rollback, fork | Refused | `--accept-rollback`, `--accept-fork`, audited, discarding the other history |
| `rekey` | Rotates audit and verifier keys, drops machine slots | `--keep-tokens`, `--reissue-machine` |

## 17. Library and CLI surface

```
github.com/mtnaskari/goraz            (module path is pending a decision)
  vault      Create, Open, Get, Put, List, Delete, History, Rekey, slots
  token      Issue, Verify, Revoke, Rotate, Store interface
  password   Generate, Passphrase, Check, TOTP, HOTP
  service    Open, Value, Get, Verifier: runtime client for production services
  audit      Event types, Sink interface, JSON sink, chained log, Verify
  secret     Secret type: redacted String, GoString, Format and MarshalJSON; Wipe
  internal/  envelope, format, kdf, audit, harden, names, state
  cmd/goraz  CLI, using only the public packages
```

CLI commands: `init`, `put`, `get`, `ls`, `rm`, `destroy`, `history`, `restore`, `run`, `read`, `passwd`, `slot`, `rekey`, `generate`, `totp`, `clip`, `report`, `token issue|list|revoke|rotate|verify|expiring|rotate-verifier`, `audit verify|hash|tail|rotate-key`, `state reset`, `service create|sync|rotate|remove|list`, `import`, `export`, `doctor`.

`vault` holds no background goroutine and no global state. Only a `service.Client` runs one, and `Close` stops it. All errors are exported sentinels, and no error message contains a secret or a value.

## 18. Verification plan

| Check | Coverage |
|---|---|
| Known-answer tests | Argon2id (the reference-implementation vector used by `x/crypto`, because its API can't express RFC 9106's secret and associated data inputs), HKDF (RFC 5869), XChaCha20-Poly1305 (draft vectors), HOTP (RFC 4226), TOTP (RFC 6238) |
| Golden vectors | A committed v1 vault and envelope fixtures, which must open forever. Any format change fails them |
| Tamper tests | Each bit of a golden file, plus slot, item and version swaps, cross-vault blobs, generation regression, truncation |
| Fuzz tests | Header parser, envelope, manifest loader, token parser, name canonicalizer, `otpauth://` parser, `.env` importer. Each runs with a time budget in CI |
| Property tests | Round trips, and commitment rejection under a wrong key |
| Crash test | Fault injection between write, fsync, rename and state update, showing the old or the new file, never a mix, and no false rollback |
| State machine | Every row of the section 7 table, including a rekeyed file arriving at a device that hasn't seen it, and sync conflicts between two simulated devices |
| Concurrency | `go test -race`, parallel writers, a reader racing a writer, and parallel audit appends that must leave a valid chain |
| Canary | No secret in logs, errors or audit, in raw, base64 or hex |
| Timing sanity | Dummy path taken on an unknown token ID. Timing can't be proven by unit test, so this is documented as a code-review check |
| Static | `go vet`, `staticcheck`, `gosec`, `govulncheck`, `-trimpath` and `CGO_ENABLED=0` build |
| Coverage goal | At least 85% on `internal/envelope`, `internal/format` and `token`, as a floor rather than a security claim |

## 19. Not covered by v0.1

Summarized from [feature-matrix.md](feature-matrix.md): no server, API, policy language, identity integration, dynamic secrets, sync or merge, team sharing, public-key features, keyring, agent, hardware keys, autofill, GUI, mobile, FIPS mode or Windows support. No independent review.

## 20. Open items to settle during implementation

- Confirm the `MADV_DONTDUMP` and `mlock` behaviour under Linux `RLIMIT_MEMLOCK` limits.
- Decide on the exact EFF list licence attribution text (CC BY 3.0 US).
