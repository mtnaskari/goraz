package token

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/mtnaskari/goraz/audit"
)

func TestAllocationBudgets(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("allocation counts differ under the race detector")
	}
	m, err := New(Config{Keys: []Key{{ID: 1, Key: bytes.Repeat([]byte{1}, 32)}}, Store: NewMemoryStore(), Sink: audit.Discard})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tok, _, err := m.Issue(ctx, IssueRequest{Name: "n", Scopes: []string{"a", "b"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(200, func() { _, _ = m.Verify(ctx, tok.Bytes(), "a") }); n > 16 {
		t.Errorf("Verify: %.0f allocations, budget 16", n)
	}
}
