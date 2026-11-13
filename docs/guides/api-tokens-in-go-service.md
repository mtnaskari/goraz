---
title: Store API tokens securely in a Go service
description: Keep third-party API tokens encrypted at rest in a production Go service, without a secrets server, and update them without a restart.
---

# Store API tokens securely in a Go service

Your service needs tokens such as a Stripe key or a database password. With goraz, it reads them from its own encrypted file, which holds only the items that service needs.

## 1. Add the tokens on your machine

```bash
goraz put prod/api/stripe
goraz put prod/api/db-password
```

## 2. Create a file for the service

```bash
goraz service create api --prefix prod/api --out api.goraz --key-out api.key
```

- `api.goraz` holds only items below `prod/api`, encrypted under its own key.
- `api.key` opens that file and nothing else. **Deploy the two separately**, because together they expose the file's contents.

## 3. Deploy them

Put `api.goraz` in your image or on a volume. Deliver `api.key` as a secret:

- [Docker](docker-secrets.md)
- [Kubernetes](kubernetes-secrets.md)
- [systemd](systemd-credentials.md)

## 4. Read tokens in your code

```bash
go get github.com/mtnaskari/goraz@latest
```

```go
c, err := service.Open(ctx, service.Options{
	Path:  "/etc/goraz/api.goraz",
	Key:   service.KeyFile("/run/secrets/goraz-key"),
	Audit: audit.NewJSONSink(os.Stdout),
})
if err != nil {
	return err
}
defer c.Close()

stripeKey, err := c.Value("prod/api/stripe")
if err != nil {
	return err
}
defer stripeKey.Wipe()
```

The audit stream records each read on stdout, with no names or values. If it can't be written, the read fails.

If you can't change the program, use `goraz run`:

```bash
goraz run --vault /etc/goraz/api.goraz --machine-key-file /run/secrets/goraz-key \
  --audit stderr --no-warn --env STRIPE_KEY=goraz://prod/api/stripe -- ./my-app
```

## 5. Update a token

```bash
goraz put prod/api/stripe
goraz service sync api --out api.goraz
```

Deploy the new `api.goraz`. A running client checks the file every 30 seconds and switches to it with no restart. A damaged, tampered or older file is refused, and the client keeps its current data.

## Patterns for real secrets

These snippets come from a complete example service: an orders API with Postgres, rotating session keys, a payment webhook and a Telegram bot, run with Docker Compose.

**Read the database password for each new connection**, so a rotated password takes effect without a restart. With pgx:

```go
cfg, err := pgxpool.ParseConfig("postgres://orders@db:5432/orders") // No password in the URL.
cfg.BeforeConnect = func(_ context.Context, c *pgx.ConnConfig) error {
	p, err := client.Value("orders/db/password")
	if err != nil {
		return err
	}
	defer p.Wipe()
	c.Password = string(p.Bytes())
	return nil
}
```

**Keep two signing keys during a rotation.** Store the old key as `previous`, then accept either one until tokens signed with it expire:

```go
current, err := client.Value("orders/jwt/current")
// ...
previous, err := client.Value("orders/jwt/previous")
if errors.Is(err, vault.ErrNotFound) {
	previous, err = secret.Secret{}, nil // No rotation in progress.
}
```

The same pattern works for a webhook secret: accept signatures made with `webhook-secret` or `webhook-secret-previous` while the provider switches.

**Answer 503 when secrets can't be trusted**, rather than serving with old ones:

```go
if errors.Is(err, service.ErrStale) || errors.Is(err, service.ErrExpired) {
	http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	return
}
```

**Let clients exchange an API key for a short session.** Issue the key with `goraz token issue --service api`, then verify it in the service:

```go
v, err := client.Verifier(nil)
rec, err := v.Verify(r.Context(), apiKey, "orders")
// rec.Name and rec.Scopes describe the client.
```

## What happens when something fails

| Situation | Result |
|---|---|
| Reloads keep failing for 15 minutes | `Value` returns `ErrStale`. Change this with `MaxStale` |
| The file is past its `--valid-for` window | `Value` returns `ErrExpired` |
| The audit stream can't be written | The read fails |
| The container restarts with an older file | It's accepted, unless you set `MinGeneration` or use `--valid-for` |

Use `--valid-for 24h` with a scheduled `service sync` if someone able to write to the file's volume is a concern.

## What this doesn't protect against

An attacker who controls the running service gets everything that service can read. The key also has to exist on the host. goraz protects the file at rest and keeps services apart from each other.

If you need central control across many servers or short-lived database credentials, [use a secrets server](alternatives.md).
