---
title: goraz limits and performance
description: File size limits, supported platforms and measured performance of goraz, and how they should affect the way you use it.
---

# Limits and performance

## Limits

| Item | Limit |
|---|---|
| Vault or service file | 1 GiB |
| Encrypted index of a file | 64 MiB |
| One value | 1 MiB |
| Versions kept per item | 10 |
| Item name | 255 bytes, 16 segments |
| Unlock slots | 16, with at most one passphrase |
| Services per vault | 256 |
| Passphrase | 15 characters to 512 bytes |
| Token lifetime | 90 days by default, and always limited |
| Platforms | macOS and Linux |

## Measurements

These were measured once on one Apple Silicon Mac with Go 1.27. Treat them as a rough guide, and measure on your own hardware.

| Operation | Time |
|---|---|
| Unlock with a passphrase, `standard` (256 MiB) | About 0.13 s for a whole command |
| Unlock with a passphrase, `strong` (1 GiB, default) | About 0.5 s for a whole command |
| Unlock with a passphrase, `max` (2 GiB) | About 0.37 s for a whole command |
| `service.Client.Value`, no audit cost included | About 3 µs |
| Verify a token from a service file, no audit cost included | About 3 µs |
| `vault.Get` with the chained file log, on a short log | About 5 ms |
| `vault.Put` with 100 items | About 23 ms |

A vault with 301 items, 300 of them holding 4 KiB and one holding 1 MiB, is about 3.2 MB.

## What this means for you

- **In a hot path, use the `service` package.** Reading from memory is fast. Your audit sink adds its own cost, because every read writes an event.
- **`vault.Get` slows as its log grows.** Every read re-verifies this device's whole audit log, and the log isn't rotated yet. This is fine for a person using the command line. It's not meant for a long-running service, which should use a stream instead.
- **Every write rewrites the whole file.** That's fine for hundreds of items written occasionally, and it isn't a database.
- **An unlock needs its full memory.** A host that can't allocate it runs out of memory, and Go can't recover from that. Machine keys need no such memory, so services aren't affected.
