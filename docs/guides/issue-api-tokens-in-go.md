---
title: Issue and verify API tokens in Go
description: Generate secure opaque API tokens in Go with expiry, scopes, revocation and rotation, while storing only a keyed hash in your database.
---

# Issue and verify API tokens in Go

The `token` package gives your API opaque bearer tokens. Each has a 256-bit secret, a required expiry and exact-match scopes. Your database holds only a keyed hash.

## Issue a token

```go
m, err := token.New(token.Config{
	Keys:   []token.Key{{ID: 1, Key: verifierKey}}, // 32 random bytes, kept out of the database.
	Store:  myStore,                                // Implements token.Store.
	Sink:   audit.NewJSONSink(os.Stdout),
	Prefix: "acme",                                 // Tokens look like acme_st_...
})

tok, rec, err := m.Issue(ctx, token.IssueRequest{
	Name:   "billing-worker",
	Scopes: []string{"payments:read"},
	TTL:    24 * time.Hour,
})
```

Show `tok` to the user once. It can't be recovered. `rec` is what the store holds.

## Verify on each request

```go
rec, err := m.Verify(ctx, presented, "payments:read")
switch {
case errors.Is(err, token.ErrInvalidToken):
	// 401: malformed, unknown, wrong, expired or revoked. All look the same.
case errors.Is(err, token.ErrForbidden):
	// 403: valid, but without this scope.
case errors.Is(err, token.ErrUnavailable):
	// 503: the store or the audit log failed. It fails closed.
}
```

## Revoke and rotate

```go
id, _ := token.ParseID(rec.ID)
err = m.Revoke(ctx, id)

// A new token now, with the old one working for an hour during your rollout.
next, _, err := m.Rotate(ctx, id, time.Hour)
```

## Implement the store

`token.Store` has three methods: `Get`, `Put` and `List`. `Get` must return `token.ErrNotFound` when a record doesn't exist, and another error when the database can't answer. That difference is what makes verification fail closed.

To avoid a database query per request, wrap your store. A cached record is used for at most 60 seconds, so a revocation can take that long to reach other processes:

```go
store := token.NewCachedStore(myStore, token.DefaultCacheLimit, nil)
```

## Why not JWT?

A JWT can't be revoked before it expires without keeping state, and its format has a history of [algorithm confusion problems](https://www.rfc-editor.org/rfc/rfc8725.html). Opaque tokens need a store lookup in exchange for immediate revocation.

## Security properties and limits

- Someone who can write to your database can't forge a token or change its scopes or expiry without the verifier key.
- They can clear a revocation or delete a record, so your database must be trusted for revocation.
- A stolen token works until it expires or is revoked. Tokens aren't bound to a client.
- The package doesn't rate-limit. 256-bit secrets can't be guessed, but add rate limiting to protect your store from load.
- Prefix and checksum let scanners find leaked tokens. To get GitHub to scan for yours, apply to its [secret scanning partner program](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partnership-program/secret-scanning-partner-program).
