package token

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/tokfmt"
)

func BenchmarkVerify(b *testing.B) {
	m, err := New(Config{Keys: []Key{{ID: 1, Key: bytes.Repeat([]byte{1}, 32)}}, Store: NewMemoryStore(), Sink: audit.Discard})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	tok, _, err := m.Issue(ctx, IssueRequest{Name: "n", Scopes: []string{"a", "b"}, TTL: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := m.Verify(ctx, tok.Bytes(), "a"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseToken(b *testing.B) {
	tok, err := tokfmt.Encode("goraz", tokfmt.KindService, make([]byte, tokfmt.IDSize), bytes.Repeat([]byte{7}, tokfmt.SecretSize))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := tokfmt.Parse(tok); err != nil {
			b.Fatal(err)
		}
	}
}
