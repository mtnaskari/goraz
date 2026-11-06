---
title: Manage passwords and one-time codes from the terminal
description: Use goraz as an offline command-line password manager with password generation, TOTP codes, an automatically cleared clipboard and breach checks.
---

# Manage passwords and one-time codes from the terminal

goraz works offline and stores everything, including site names and usernames, in one encrypted file.

## Save a login

Generate a password and store it:

```bash
goraz put sites/github --type login --username alice --url https://github.com --generate 24
```

Or enter your own at the prompt:

```bash
goraz put sites/example --type login --username alice
```

## Copy a password

```bash
goraz clip sites/github
```

The clipboard is cleared after 20 seconds if it still holds that value. Clipboard history tools may keep their own copy. On Linux you need `wl-copy` or `xclip`.

## Generate without saving

```bash
goraz generate --length 32
goraz generate --words 6
```

## One-time codes

Paste the `otpauth://` link from a site's setup page:

```bash
goraz put sites/github/otp --otp
goraz totp sites/github/otp
```

A one-time seed in the same vault as the password removes the separation between the two factors if the vault is compromised. A separate vault keeps them apart.

## Check your passwords

```bash
goraz report
goraz report --hibp
```

`report` lists reused, short and old values, offline. `--hibp` also checks [Have I Been Pwned](https://haveibeenpwned.com/Passwords). It sends only the first five characters of each password's SHA-1 hash, and it is the only network request goraz ever makes.

## Back up

The vault is one file, so copy it. Remember that **a backup keeps working with the passphrase that was valid when you made it.**

## What it doesn't have

There's no browser extension, autofill, mobile app, sync or sharing yet. [See why](../feature-matrix.md).
