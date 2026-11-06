---
title: What to do when a secret or key leaks
description: Step-by-step response when an API token, service key, vault passphrase or recovery code is exposed, including what rotation does and does not undo.
---

# What to do when a secret or key leaks

**Start at the source.** Nothing in goraz can make an exposed value safe. Only replacing it where it was issued can.

## An API token or password you stored

1. Revoke or change it at the provider, such as Stripe or your database.
2. Store the new value: `goraz put prod/api/stripe`.
3. Update services: `goraz service sync api --out api.goraz`, then deploy the file.

## A token issued by goraz

```bash
goraz token list
goraz token revoke TOKEN_ID
```

Add `--service api` for a service's token, then run `service sync` and deploy, because revocation reaches a service only through its file.

## A service key, such as `api.key`

```bash
goraz service rotate api --out api.goraz --key-out api.key
```

This creates a new key and stops that service's issued tokens working. `--key-out` adds the new key on a second line, so you can avoid an outage:

1. Deploy the key file with both lines.
2. Deploy the new service file.
3. Delete the old key's line, and deploy the key file again.

**Then replace every secret in that service file at its source.** Someone with the old key and a copy of the old file has read them.

## Your passphrase or recovery code, or a copy of your vault with either

`goraz passwd` and `goraz slot remove` **don't revoke access**. Someone holding the old credential and any old copy of the file can still get the master key, read your current files and forge new ones.

Run a rekey:

```bash
goraz rekey
```

It creates a new master key, recovery code and audit and verifier keys. Issued tokens stop working. Save the new recovery code and type `SAVED` when asked. Nothing changes until you do.

Then:

1. Rotate each service: `goraz service rotate NAME --out FILE --key-out FILE`. `service sync` refuses until you do, because their stored keys may be exposed.
2. Replace every stored secret at its source. Old file copies still open with the old credentials, and nothing can change those copies.

## Check what happened

```bash
goraz audit verify
goraz audit tail
goraz audit hash prod/api/stripe
```

The log uses a hash in place of each name, and `audit hash` gives you the value to search for. Remember its limits: it records what goraz did on this machine, and anyone who has unlocked the vault can rewrite it. [Read more](../threat-model.md#6-audit-log-limits).
