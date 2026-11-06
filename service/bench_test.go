package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/kdf"
	"github.com/mtnaskari/goraz/secret"
	"github.com/mtnaskari/goraz/token"
	"github.com/mtnaskari/goraz/vault"
)

func benchClient(b *testing.B) (*Client, []byte) {
	b.Helper()
	dir := b.TempDir()
	v, _, err := vault.Create(filepath.Join(dir, "m"), vault.CreateOptions{
		Passphrase: []byte(pass), Profile: kdf.Interactive, Options: vault.Options{StateDir: filepath.Join(dir, "s")},
	})
	if err != nil {
		b.Fatal(err)
	}
	defer v.Close()
	if err := v.Put(&vault.Item{Name: "prod/api/x", Value: secret.New([]byte("value"))}); err != nil {
		b.Fatal(err)
	}
	out := filepath.Join(dir, "api")
	key, err := v.CreateService("api", out, vault.ServiceOptions{Prefixes: []string{"prod/api"}})
	if err != nil {
		b.Fatal(err)
	}
	m, err := v.ServiceTokens("api", nil)
	if err != nil {
		b.Fatal(err)
	}
	tok, _, err := m.Issue(context.Background(), token.IssueRequest{Name: "n", Scopes: []string{"s"}, TTL: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	if err := v.SyncService("api", out); err != nil {
		b.Fatal(err)
	}
	c, err := Open(context.Background(), Options{Path: out, Key: StaticKeys(key.Bytes()), Audit: audit.Discard, Interval: time.Hour, MaxStale: NoStaleLimit})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(c.Close)
	return c, tok.Bytes()
}

func BenchmarkServiceValue(b *testing.B) {
	c, _ := benchClient(b)
	b.ResetTimer()
	for b.Loop() {
		if _, err := c.Value("prod/api/x"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServiceVerifyToken(b *testing.B) {
	c, tok := benchClient(b)
	v, err := c.Verifier(nil)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		if _, err := v.Verify(ctx, tok, "s"); err != nil {
			b.Fatal(err)
		}
	}
}
