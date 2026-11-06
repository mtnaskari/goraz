---
title: Fix common goraz errors
description: What each goraz error means and how to fix it, including rollback, fork, audit log, key file permission and wrong credential errors.
---

# Fix common goraz errors

## "wrong credential, or the unlock data has been altered"

The passphrase, key file, recovery code or machine key doesn't match. If the vault was created with `--keyfile`, you need the same file.

**On a service, after a rotation:** the file was deployed before its key. Add the new key to the key file. A running client keeps its current data meanwhile.

## "the file failed authentication"

The file is corrupted or was altered. Restore it from a backup. If only one item is damaged, other items are still readable, and `goraz doctor` names the damaged one. Writes are refused until the file is replaced.

## "this file is older than one already seen on this device"

Someone replaced the file with an older one, or you restored a backup. If you restored it deliberately:

```bash
goraz ls --accept-rollback
```

This is written to the audit log, and it discards the newer history.

## "this file has a different history"

Usually two devices wrote to a synced file. goraz doesn't merge, so choose one. On the device whose changes you can lose:

```bash
goraz ls --accept-fork
```

Note what was added on that device first, because those changes are dropped.

## "the file changed since it was opened"

Another process wrote to the vault. Run your command again.

## "the audit log failed verification" or "is shorter than its anchor"

The local audit log was edited, damaged or deleted. If you know why:

```bash
goraz audit verify --accept-audit-gap
```

The damaged file is kept beside the log, and the gap is recorded.

## "the audit log can't be written"

The disk is full, or it's read-only. In a container, send audit events to a stream: `--audit stderr`, or `audit.NewJSONSink` in Go.

## "open ...lock: read-only file system"

You're running on a read-only filesystem without an audit stream. Add `--audit stderr`, which is for service vaults.

## "this file has a passphrase slot, so it is a main vault"

Service mode refuses your main vault. Create a service file with `goraz service create`.

## "the machine key file must be a regular file..."

The key file is readable by others. It needs mode 0400 or 0440, owned by your user or root.

- **Docker:** `uid: "1000"` and `mode: 0400` on the secret
- **Kubernetes:** `defaultMode: 0440`, with `securityContext.fsGroup`

## "file is unsafe"

The vault or a file beside it is a symlink, is owned by someone else, or can be written by others. Run `chmod 600` on it, and check its owner.

## "the main vault was rekeyed, so this service's key may be exposed"

Run `goraz service rotate NAME --out FILE --key-out FILE`.

## ErrStale or ErrExpired in a service

- **`ErrStale`:** reloads have been failing for longer than `MaxStale`. `OnReloadError` reports why.
- **`ErrExpired`:** the file passed its `--valid-for` window. Run `service sync` and deploy it.

## The process is killed on startup

An unlock uses up to 2 GiB of memory, depending on the vault's profile, and the default is 1 GiB. On a small host, create the vault with `--kdf standard` or `--kdf interactive`. Service files use no such memory, because machine keys skip this step.
