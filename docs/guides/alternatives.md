---
title: goraz compared with HashiCorp Vault, OpenBao, SOPS and gopass
description: When to use goraz and when a secrets server, SOPS, age, gopass or KeePassXC is the better choice, with an honest comparison of features and maturity.
---

# goraz compared with HashiCorp Vault, OpenBao, SOPS and gopass

**goraz is young and hasn't been audited.** All the projects below have far longer track records. Choose goraz when its design fits your need and you accept that.

## Which should I use?

| You need | Consider |
|---|---|
| Central control, instant revocation across many servers, teams and policies | [OpenBao](https://openbao.org/) or [HashiCorp Vault](https://developer.hashicorp.com/vault) |
| Short-lived database or cloud credentials | OpenBao or Vault |
| Encrypted config files reviewed in git, with cloud KMS | [SOPS](https://getsops.io/) |
| To encrypt a file for someone | [age](https://age-encryption.org/) |
| A team password store in git | [gopass](https://github.com/gopasspw/gopass) |
| A desktop password manager with browser integration | [KeePassXC](https://keepassxc.org/) or [Bitwarden](https://bitwarden.com/) |
| A hosted service you don't run yourself | [Doppler](https://www.doppler.com/) or [1Password](https://1password.com/) |
| Secrets for a few services without running a server, and token issuing in Go | goraz |

## How goraz differs

| | goraz | Vault, OpenBao | SOPS | gopass |
|---|---|---|---|---|
| Needs a server | No | Yes | No | No |
| Item names hidden | Yes | At rest | No, by design | No |
| Detects older files | Yes, with limits | Out of their threat model | No | No |
| Per-service access | A separate encrypted file | Policies | Separate files | Per-store recipients |
| Dynamic credentials | No | Yes | No | No |
| Team sharing | No | Yes | Yes | Yes |
| Merge-friendly in git | No | Not applicable | Yes | Per file |
| Issues API tokens for your app | Yes | Its own tokens | No | No |
| Independent audit | **None** | [Vault, 2026](https://almond.eu/wp-content/uploads/ETR-PUBLIC-Vault.pdf); none found for OpenBao | None found | None found |

## Where this comes from

The full research, with sources, is in [the comparison of earlier projects](../research/comparison.md). What goraz leaves out is in [the feature matrix](../feature-matrix.md).
