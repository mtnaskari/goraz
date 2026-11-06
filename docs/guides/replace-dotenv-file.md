---
title: Replace a .env file with encrypted secrets
description: Move secrets out of a plaintext .env file into an encrypted vault, and commit a file of references instead of real values.
---

# Replace a .env file with encrypted secrets

A `.env` file keeps secrets in plain text, one mistaken commit away from being public. You can import it into goraz and commit references instead.

## 1. Import it

```bash
goraz import .env --prefix myapp
```

Each `KEY=value` becomes the item `myapp/KEY`. The importer takes quoted values and `export` prefixes. It doesn't expand variables or run commands, and it stops with a line number on anything else.

## 2. Create a references file

This file holds no secrets, so it's safe to commit. Call it `.env.goraz`:

```bash
DATABASE_URL=goraz://myapp/DATABASE_URL
STRIPE_KEY=goraz://myapp/STRIPE_KEY
```

## 3. Run your program

```bash
goraz run --env-file .env.goraz -- npm start
```

## 4. Delete the old file

Delete `.env`. **If it was ever committed or shared, treat those values as leaked** and [replace them](secret-or-key-leaked.md).

## Limits

Secrets still reach your program as environment variables, so other processes of your user can read them, and your program might log them. For a Go service, [reading them directly](api-tokens-in-go-service.md) avoids this.
