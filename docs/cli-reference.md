---
title: goraz command reference
description: Every goraz command and flag for vaults, tokens, passwords, services and audit logs.
---

# Command reference

Run `goraz help` for a short list, or `goraz COMMAND --help` for the flags of a command.

Secrets are read from a hidden prompt, stdin or a file descriptor. They are never accepted as arguments or from environment variables.

## Flags for commands that open a vault

| Flag | Meaning |
|---|---|
| `--vault PATH` | Vault path. Also `GORAZ_VAULT`. Default `~/.local/share/goraz/vault.goraz` |
| `--passphrase-fd N` | Read the passphrase from a file descriptor |
| `--keyfile PATH` | A file of exactly 32 random bytes, used with the passphrase |
| `--recovery` | Unlock with a recovery code |
| `--machine-key-file PATH` | Read machine keys from a file, one per line |
| `--machine-key-fd N` | Read machine keys from a file descriptor |
| `--audit stderr` | Open a service vault read-only, with audit events on stderr |
| `--accept-rollback` | Accept an older file, discarding newer history. Audited |
| `--accept-fork` | Accept a file with a different history, discarding this device's. Audited |
| `--accept-audit-gap` | Continue after a damaged audit log, recording a gap |
| `--min-generation N` | Refuse a file older than this |

`GORAZ_STATE_DIR` sets where local state and the audit log live. The default is `$XDG_STATE_HOME/goraz` or `~/.local/state/goraz`.

## Vault

| Command | What it does |
|---|---|
| `init [--kdf PROFILE] [--generate-passphrase] [--accept-weak-passphrase]` | Create a vault. Profiles: `interactive`, `standard`, `strong` (default), `max`. The last flag skips the passphrase policy, with a warning |
| `put NAME [--type T] [--username U] [--url U] [--notes N] [--expires-in D] [--generate N] [--otp]` | Store a new version. Types: `secret`, `login`, `token`, `totp` |
| `get NAME [--version N] [--force]` | Print a value. Refuses a terminal unless forced |
| `read goraz://NAME[#FIELD] [--force]` | Print a field: `value`, `username`, `url`, `notes` or `otp` |
| `ls` | List items |
| `history NAME` | List versions |
| `restore NAME [--version N]` | Make a version the latest, or bring back a deleted item |
| `rm NAME` | Hide an item. History remains |
| `destroy NAME` | Remove an item and its history from the file |
| `run [--env K=REF] [--env-file F] [--no-warn] -- CMD` | Run a program with secrets in its environment |
| `import FILE [--prefix P]` | Import a `.env` file |
| `export --out FILE` | Write everything in plain text. Won't overwrite |

## Keys

| Command | What it does |
|---|---|
| `passwd [--kdf P] [--new-passphrase-fd N] [--accept-weak-passphrase]` | Replace the passphrase. **Doesn't revoke the old one** |
| `slot list` | List unlock slots |
| `slot add-machine`, `slot add-recovery` | Add a credential. A machine key opens the whole vault |
| `slot remove ID` | Remove a slot. **Doesn't revoke it** |
| `rekey [--kdf P] [--keep-tokens] [--reissue-machine N] [--new-passphrase-fd N] [--confirm-saved]` | New master key. **The only way to end old credentials' access** |
| `state reset` | Forget this device's record of the vault |

## Passwords

| Command | What it does |
|---|---|
| `generate [--length N] [--symbols] [--words N] [--separator S]` | Generate a password or passphrase |
| `totp NAME` | Print a one-time code |
| `clip NAME [--field F] [--clear-after D]` | Copy to the clipboard, cleared automatically |
| `report [--hibp] [--max-age D]` | Report weak, reused and old values |

## Tokens

| Command | What it does |
|---|---|
| `token issue --name N [--scope S] [--ttl D] [--service S]` | Issue a token, shown once |
| `token list [--service S]` | List tokens without their secrets |
| `token verify [--scope S] [--service S]` | Check a token from stdin |
| `token revoke ID [--service S]` | Revoke a token |
| `token rotate ID [--overlap D] [--service S]` | Issue a successor, ending the old token after the overlap |
| `token rotate-verifier [--overlap D]` | New verifier key for the main vault's tokens |
| `token expiring [--within D]` | List stored tokens that expire soon |

## Services

| Command | What it does |
|---|---|
| `service create NAME --prefix P --out F --key-out F [--valid-for D]` | Create a service file and key |
| `service sync NAME --out F` | Write a fresh service file |
| `service rotate NAME --out F --key-out F` | New keys for a service. Adds the new key to the key file |
| `service remove NAME` | Forget a service |
| `service list` | List services |

## Audit and diagnostics

| Command | What it does |
|---|---|
| `audit verify` | Check this device's log |
| `audit tail` | Print entries |
| `audit hash NAME` | Print the value the log uses for a name |
| `audit rotate-key` | New audit key |
| `doctor [--no-vault]` | Report active protections, and check the vault and log |
| `version` | Print the version |
