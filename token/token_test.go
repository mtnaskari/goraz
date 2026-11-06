package token

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/tokfmt"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type recordingSink struct {
	events []audit.Event
	err    error
}

func (s *recordingSink) Record(e audit.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, e)
	return nil
}

func setup(t *testing.T) (*Manager, *MemoryStore, *clock, *recordingSink) {
	t.Helper()
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := NewMemoryStore()
	sink := &recordingSink{}
	m, err := New(Config{
		Keys:  []Key{{ID: 1, Key: bytes.Repeat([]byte{1}, 32)}},
		Store: store, Sink: sink, Now: c.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, store, c, sink
}

func TestIssueVerify(t *testing.T) {
	m, store, _, sink := setup(t)
	ctx := context.Background()
	tok, rec, err := m.Issue(ctx, IssueRequest{Name: "api", Scopes: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(tok.Bytes()), "goraz_st_") {
		t.Error("prefix missing")
	}
	got, err := m.Verify(ctx, tok.Bytes(), "read")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "api" {
		t.Errorf("got %+v", got)
	}

	// The store must never hold the secret.
	p, err := tokfmt.Parse(tok.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ParseID(rec.ID)
	stored, err := store.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored.MAC, p.Secret[:]) {
		t.Error("store holds the secret")
	}
	if len(sink.events) != 2 || sink.events[1].Type != audit.EventTokenVerify || sink.events[1].Outcome != audit.OK {
		t.Errorf("events: %+v", sink.events)
	}
}

func TestDefaultsAndLimits(t *testing.T) {
	m, _, c, _ := setup(t)
	ctx := context.Background()
	_, rec, err := m.Issue(ctx, IssueRequest{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Expires.Sub(c.t) != DefaultTTL {
		t.Errorf("default TTL: %v", rec.Expires.Sub(c.t))
	}
	for _, q := range []IssueRequest{
		{Name: "a", TTL: MaxTTL + 1},
		{Name: "a", TTL: -1},
		{Name: ""},
		{Name: strings.Repeat("x", 129)},
		{Name: "a", Scopes: []string{"*"}},
		{Name: "a", Scopes: []string{""}},
		{Name: "a", Scopes: []string{"a b"}},
	} {
		if _, _, err := m.Issue(ctx, q); err == nil {
			t.Errorf("accepted %+v", q)
		}
	}
}

func TestExpiryAtEachUse(t *testing.T) {
	m, _, c, _ := setup(t)
	ctx := context.Background()
	tok, _, err := m.Issue(ctx, IssueRequest{Name: "a", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Hour - time.Second)
	if _, err := m.Verify(ctx, tok.Bytes()); err != nil {
		t.Error("expired too early")
	}
	c.t = c.t.Add(time.Second)
	if _, err := m.Verify(ctx, tok.Bytes()); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v", err)
	}
}

func TestRevoke(t *testing.T) {
	m, _, _, _ := setup(t)
	ctx := context.Background()
	tok, rec, err := m.Issue(ctx, IssueRequest{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ParseID(rec.ID)
	if err := m.Revoke(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(ctx, tok.Bytes()); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v", err)
	}
	if err := m.Revoke(ctx, ID{9}); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestRotateOverlap(t *testing.T) {
	m, _, c, _ := setup(t)
	ctx := context.Background()
	old, rec, err := m.Issue(ctx, IssueRequest{Name: "a", Scopes: []string{"s"}})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ParseID(rec.ID)
	next, nrec, err := m.Rotate(ctx, id, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if nrec.Scopes[0] != "s" {
		t.Error("scopes not carried over")
	}
	if _, err := m.Verify(ctx, old.Bytes()); err != nil {
		t.Error("old token should work during the overlap")
	}
	if _, err := m.Verify(ctx, next.Bytes()); err != nil {
		t.Error("new token should work")
	}
	c.t = c.t.Add(time.Minute)
	if _, err := m.Verify(ctx, old.Bytes()); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("old token after overlap: %v", err)
	}
	if _, err := m.Verify(ctx, next.Bytes()); err != nil {
		t.Error("new token stopped working")
	}
}

func TestRotateCantReviveDeadTokens(t *testing.T) {
	m, _, c, _ := setup(t)
	ctx := context.Background()
	old, rec, err := m.Issue(ctx, IssueRequest{Name: "a", TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ParseID(rec.ID)
	if _, _, err := m.Rotate(ctx, id, time.Minute); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Hour)
	if _, _, err := m.Rotate(ctx, id, 10*time.Hour); err == nil {
		t.Error("rotated a token past its end")
	}
	if _, err := m.Verify(ctx, old.Bytes()); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("the old token came back: %v", err)
	}

	_, exp, err := m.Issue(ctx, IssueRequest{Name: "b", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Hour)
	eid, _ := ParseID(exp.ID)
	if _, _, err := m.Rotate(ctx, eid, 0); err == nil {
		t.Error("an expired token was renewed")
	}
}

func TestRotateNeverMovesEndLater(t *testing.T) {
	m, store, _, _ := setup(t)
	ctx := context.Background()
	_, rec, err := m.Issue(ctx, IssueRequest{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ParseID(rec.ID)
	if _, _, err := m.Rotate(ctx, id, time.Minute); err != nil {
		t.Fatal(err)
	}
	first, _ := store.Get(ctx, id)
	if _, _, err := m.Rotate(ctx, id, time.Hour); err != nil {
		t.Fatal(err)
	}
	second, _ := store.Get(ctx, id)
	if second.RevokeAt.After(*first.RevokeAt) {
		t.Error("a second rotation extended the old token")
	}
}

func TestScopesAreExact(t *testing.T) {
	m, _, _, _ := setup(t)
	ctx := context.Background()
	tok, _, err := m.Issue(ctx, IssueRequest{Name: "a", Scopes: []string{"payments:read"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, need := range []string{"payments", "payments:", "payments:*", "PAYMENTS:READ", "payments:read "} {
		if _, err := m.Verify(ctx, tok.Bytes(), need); !errors.Is(err, ErrForbidden) {
			t.Errorf("%q: err = %v", need, err)
		}
	}
}

func TestStoreWriterCantEscalate(t *testing.T) {
	m, store, c, _ := setup(t)
	ctx := context.Background()
	tok, rec, err := m.Issue(ctx, IssueRequest{Name: "a", Scopes: []string{"read"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ParseID(rec.ID)

	raised := rec
	raised.Scopes = []string{"read", "admin"}
	if err := store.Put(ctx, raised); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(ctx, tok.Bytes(), "admin"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("raised scope: %v", err)
	}

	extended := rec
	extended.Expires = rec.Expires.Add(1000 * time.Hour)
	if err := store.Put(ctx, extended); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(2 * time.Hour)
	if _, err := m.Verify(ctx, tok.Bytes()); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("extended expiry: %v", err)
	}
	_ = id
}

func TestWrongSecretRejected(t *testing.T) {
	m, _, _, _ := setup(t)
	ctx := context.Background()
	_, rec, err := m.Issue(ctx, IssueRequest{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	// Correct ID, wrong secret, valid checksum.
	forged, err := tokfmt.Encode("goraz", tokfmt.KindService, rec.ID, make([]byte, tokfmt.SecretSize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(ctx, forged); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v", err)
	}
	unknown, err := tokfmt.Encode("goraz", tokfmt.KindService, make([]byte, tokfmt.IDSize), make([]byte, tokfmt.SecretSize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(ctx, unknown); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("unknown: %v", err)
	}
}

func TestKindAndPrefixAreBound(t *testing.T) {
	m, _, _, _ := setup(t)
	ctx := context.Background()
	tok, _, err := m.Issue(ctx, IssueRequest{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := tokfmt.Parse(tok.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// A relabelled token with a recomputed checksum must not verify.
	asMachine, err := tokfmt.Encode("goraz", tokfmt.KindMachine, p.ID[:], p.Secret[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(ctx, asMachine); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("machine kind: %v", err)
	}
	asOther, err := tokfmt.Encode("acme", tokfmt.KindService, p.ID[:], p.Secret[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(ctx, asOther); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("other prefix: %v", err)
	}
}

func TestErrorsAreUniform(t *testing.T) {
	m, _, c, _ := setup(t)
	ctx := context.Background()
	exp, _, err := m.Issue(ctx, IssueRequest{Name: "a", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(2 * time.Hour)
	_, errExpired := m.Verify(ctx, exp.Bytes())
	_, errGarbage := m.Verify(ctx, []byte("garbage"))
	if errExpired != errGarbage { //nolint:errorlint // Identity is the point of this test.
		t.Errorf("errors differ: %v, %v", errExpired, errGarbage)
	}
}

type failingStore struct{ *MemoryStore }

func (failingStore) Get(context.Context, ID) (Record, error) {
	return Record{}, errors.New("database down")
}

func TestFailClosedOnStoreError(t *testing.T) {
	m, store, c, sink := setup(t)
	ctx := context.Background()
	tok, _, err := m.Issue(ctx, IssueRequest{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	broken, err := New(Config{Keys: m.keys, Store: failingStore{store}, Sink: sink, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.Verify(ctx, tok.Bytes()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v", err)
	}
}

func TestFailClosedOnAuditError(t *testing.T) {
	m, _, _, sink := setup(t)
	ctx := context.Background()
	tok, _, err := m.Issue(ctx, IssueRequest{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	sink.err = errors.New("log down")
	if _, err := m.Verify(ctx, tok.Bytes()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v", err)
	}
	if _, _, err := m.Issue(ctx, IssueRequest{Name: "b"}); err == nil {
		t.Error("issue succeeded without an audit entry")
	}
}

func TestVerifierKeyRotationOverlap(t *testing.T) {
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := NewMemoryStore()
	k1 := Key{ID: 1, Key: bytes.Repeat([]byte{1}, 32)}
	m1, err := New(Config{Keys: []Key{k1}, Store: store, Sink: audit.Discard, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tok, _, err := m1.Issue(ctx, IssueRequest{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	retire := c.t.Add(time.Hour)
	k1r := k1
	k1r.RetireAt = &retire
	k2 := Key{ID: 2, Key: bytes.Repeat([]byte{2}, 32)}
	m2, err := New(Config{Keys: []Key{k1r, k2}, Store: store, Sink: audit.Discard, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Verify(ctx, tok.Bytes()); err != nil {
		t.Error("old key should verify during overlap")
	}
	_, nrec, err := m2.Issue(ctx, IssueRequest{Name: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if nrec.KeyID != 2 {
		t.Errorf("new token uses key %d", nrec.KeyID)
	}
	c.t = retire
	if _, err := m2.Verify(ctx, tok.Bytes()); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("retired key: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	good := []Key{{ID: 1, Key: make([]byte, 32)}}
	store := NewMemoryStore()
	cases := []Config{
		{Keys: good, Sink: audit.Discard},
		{Keys: good, Store: store},
		{Store: store, Sink: audit.Discard},
		{Keys: []Key{{ID: 1, Key: make([]byte, 16)}}, Store: store, Sink: audit.Discard},
		{Keys: good, Store: store, Sink: audit.Discard, Prefix: "BAD"},
	}
	for i, c := range cases {
		if _, err := New(c); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := NewVerifier(good, store, audit.Discard); err != nil {
		t.Error(err)
	}
}

func TestCustomPrefix(t *testing.T) {
	m, err := New(Config{Keys: []Key{{ID: 1, Key: make([]byte, 32)}}, Store: NewMemoryStore(), Sink: audit.Discard, Prefix: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tok, _, err := m.Issue(ctx, IssueRequest{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(tok.Bytes()), "acme_st_") {
		t.Errorf("prefix: %s", tok.Bytes()[:8])
	}
	if _, err := m.Verify(ctx, tok.Bytes()); err != nil {
		t.Error(err)
	}
}

func TestCachedStoreLimit(t *testing.T) {
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	inner := NewMemoryStore()
	cs := NewCachedStore(inner, time.Minute, c.now)
	m, err := New(Config{Keys: []Key{{ID: 1, Key: make([]byte, 32)}}, Store: cs, Sink: audit.Discard, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tok, rec, err := m.Issue(ctx, IssueRequest{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(ctx, tok.Bytes()); err != nil {
		t.Fatal(err)
	}
	// Another process revokes directly in the store.
	revoked := rec
	revoked.Revoked = true
	if err := inner.Put(ctx, revoked); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(ctx, tok.Bytes()); err != nil {
		t.Error("within the cache limit, the cached record is used")
	}
	c.t = c.t.Add(time.Minute)
	if _, err := m.Verify(ctx, tok.Bytes()); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("past the limit: %v", err)
	}
	// A failing store must not be hidden by the cache.
	broken := NewCachedStore(failingStore{inner}, time.Minute, c.now)
	mb, err := New(Config{Keys: m.keys, Store: broken, Sink: audit.Discard, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mb.Verify(ctx, tok.Bytes()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("failing store: %v", err)
	}
}

func FuzzVerify(f *testing.F) {
	m, err := New(Config{Keys: []Key{{ID: 1, Key: make([]byte, 32)}}, Store: NewMemoryStore(), Sink: audit.Discard})
	if err != nil {
		f.Fatal(err)
	}
	tok, _, err := m.Issue(context.Background(), IssueRequest{Name: "a"})
	if err != nil {
		f.Fatal(err)
	}
	// This token exists only in this worker's store, so a token from another worker
	// is rejected like any other. Only this one may verify.
	f.Add(tok.Bytes())
	f.Add([]byte("goraz_st_"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := m.Verify(context.Background(), b); err == nil && !bytes.Equal(b, tok.Bytes()) {
			t.Fatalf("forged token accepted: %q", b)
		}
	})
}
