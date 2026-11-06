---
title: Get started with goraz
description: Install goraz, create an encrypted vault, store a secret and pass it to a program without putting it in a file or shell history.
---

# Get started with goraz

You will create an encrypted vault, store a secret and give it to a program.

## Install

You need Go 1.26 or later, on macOS or Linux.

```bash
go install github.com/mtnaskari/goraz/cmd/goraz@latest
```

## Create a vault

```bash
goraz init
```

Choose a passphrase of at least 15 characters, or run `goraz init --generate-passphrase` to get one.

goraz prints a **recovery code once**. Store it away from the vault. If you lose both the passphrase and the code, nobody can recover the data.

The vault is at `~/.local/share/goraz/vault.goraz`. Use `--vault PATH` or `GORAZ_VAULT` to choose another place.

## Store a secret

```bash
goraz put prod/db/password
```

goraz reads the value from a hidden prompt, so it doesn't reach your shell history. You can also pipe it in:

```bash
printf '%s' "$VALUE" | goraz put prod/db/password
```

Names are segments of letters, digits, `.`, `_` and `-`, separated by `/`.

## Give it to a program

```bash
goraz run --env DB_PASSWORD=goraz://prod/db/password -- ./my-app
```

goraz replaces itself with `./my-app`, which sees `DB_PASSWORD` in its environment. Other processes of your user can read an environment, and programs may log it. goraz warns you about this each time.

## Read it back

`goraz get` refuses to print to a terminal unless you add `--force`, so a secret doesn't land in your scrollback.

```bash
goraz get prod/db/password | pbcopy
```

## Next steps

- [Replace a .env file](replace-dotenv-file.md)
- [Store API tokens in a Go service](api-tokens-in-go-service.md)
- [Manage passwords](password-manager-cli.md)
