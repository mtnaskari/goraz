package token_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/token"
)

// A service issues an API token, verifies it on each request and revokes it. A real
// service would implement token.Store on its own database, and pass a real audit sink.
func Example() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	m, err := token.New(token.Config{
		Keys:  []token.Key{{ID: 1, Key: key}},
		Store: token.NewMemoryStore(),
		Sink:  audit.Discard,
	})
	if err != nil {
		panic(err)
	}
	ctx := context.Background()

	// The secret is returned once, and only a keyed hash is stored.
	tok, rec, err := m.Issue(ctx, token.IssueRequest{
		Name:   "billing-worker",
		Scopes: []string{"payments:read"},
		TTL:    time.Hour,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(strings.HasPrefix(string(tok.Bytes()), "goraz_st_"))

	// Verify on each request.
	got, err := m.Verify(ctx, tok.Bytes(), "payments:read")
	fmt.Println(got.Name, err)

	// A scope the token doesn't hold.
	_, err = m.Verify(ctx, tok.Bytes(), "payments:write")
	fmt.Println(err)

	// Revocation takes effect on the next check.
	id, _ := token.ParseID(rec.ID)
	if err := m.Revoke(ctx, id); err != nil {
		panic(err)
	}
	_, err = m.Verify(ctx, tok.Bytes())
	fmt.Println(err)

	// Output:
	// true
	// billing-worker <nil>
	// token: missing required scope
	// token: invalid token
}
