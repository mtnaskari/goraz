package service

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/kdf"
	"github.com/mtnaskari/goraz/secret"
	"github.com/mtnaskari/goraz/token"
	"github.com/mtnaskari/goraz/vault"
)

const pass = "violet granite ocean drift lantern"

type fixture struct {
	main *vault.Vault
	dir  string
	out  string
	key  secret.Secret
	now  atomic.Int64
}

func (f *fixture) clock() time.Time { return time.Unix(0, f.now.Load()) }

func (f *fixture) advance(d time.Duration) { f.now.Add(int64(d)) }

func setup(t *testing.T, o vault.ServiceOptions) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{dir: dir, out: filepath.Join(dir, "api.goraz")}
	f.now.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	v, _, err := vault.Create(filepath.Join(dir, "main.goraz"), vault.CreateOptions{
		Passphrase: []byte(pass), Profile: kdf.Interactive,
		Options: vault.Options{StateDir: filepath.Join(dir, "state"), Now: f.clock},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	f.main = v
	put(t, v, "prod/api/stripe", "sk-api")
	put(t, v, "prod/apiary/x", "other-apiary")
	put(t, v, "prod/web/secret", "web-secret")
	if len(o.Prefixes) == 0 {
		o.Prefixes = []string{"prod/api"}
	}
	f.key, err = v.CreateService("api", f.out, o)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func put(t *testing.T, v *vault.Vault, name, value string) {
	t.Helper()
	if err := v.Put(&vault.Item{Name: name, Value: secret.New([]byte(value))}); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) open(t *testing.T, mod func(*Options)) *Client {
	t.Helper()
	o := Options{
		Path: f.out, Key: StaticKeys(f.key.Bytes()), Audit: audit.Discard, Interval: time.Hour, Now: f.clock,
	}
	if mod != nil {
		mod(&o)
	}
	c, err := Open(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func value(t *testing.T, c *Client, name string) string {
	t.Helper()
	s, err := c.Value(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(s.Bytes())
}

func TestReadsOnlyItsOwnItems(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	c := f.open(t, nil)
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("wrong value")
	}
	for _, name := range []string{"prod/web/secret", "prod/apiary/x"} {
		if _, err := c.Value(name); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Enforced by encryption: the other values aren't in the file at all, under any key.
	data, err := os.ReadFile(f.out)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("web-secret")) || bytes.Contains(data, []byte("prod/web")) {
		t.Error("plaintext in the service file")
	}
}

func TestServiceCantOpenMainVault(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	_, err := vault.Open(filepath.Join(f.dir, "main.goraz"), vault.WithMachineKeys(f.key.Bytes()), vault.Options{StateDir: filepath.Join(f.dir, "s2")})
	if !errors.Is(err, vault.ErrWrongCredential) {
		t.Errorf("err = %v", err)
	}
}

func TestReloadOnSync(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	var got atomic.Uint64
	c := f.open(t, func(o *Options) { o.OnReload = func(g uint64) { got.Store(g) } })
	first := c.Generation()
	put(t, f.main, "prod/api/stripe", "sk-new")
	put(t, f.main, "prod/api/added", "added")
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("changed before the reload")
	}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	if value(t, c, "prod/api/stripe") != "sk-new" || value(t, c, "prod/api/added") != "added" {
		t.Error("reload missed the update")
	}
	if c.Generation() <= first || got.Load() != c.Generation() {
		t.Errorf("generation %d, reported %d", c.Generation(), got.Load())
	}
}

func TestBackgroundReload(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	c := f.open(t, func(o *Options) { o.Interval = 5 * time.Millisecond })
	first := c.Generation()
	put(t, f.main, "prod/api/stripe", "sk-bg")
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for c.Generation() == first {
		if time.Now().After(deadline) {
			t.Fatal("the background reload never happened")
		}
		time.Sleep(time.Millisecond)
	}
	if value(t, c, "prod/api/stripe") != "sk-bg" {
		t.Error("wrong value")
	}
}

func TestTamperedReloadKeepsSnapshot(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	var reported atomic.Int32
	c := f.open(t, func(o *Options) { o.OnReloadError = func(error) { reported.Add(1) } })
	data, err := os.ReadFile(f.out)
	if err != nil {
		t.Fatal(err)
	}
	m := bytes.Clone(data)
	m[len(m)/2] ^= 1
	if err := os.WriteFile(f.out, m, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err == nil {
		t.Fatal("tampered file accepted")
	}
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("snapshot lost")
	}
}

func TestStaleFailsClosed(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	c := f.open(t, func(o *Options) { o.MaxStale = time.Minute })
	if err := os.Remove(f.out); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err == nil {
		t.Fatal("reload of a missing file succeeded")
	}
	f.advance(30 * time.Second)
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("should serve the snapshot within the limit")
	}
	f.advance(31 * time.Second)
	if _, err := c.Value("prod/api/stripe"); !errors.Is(err, ErrStale) {
		t.Errorf("err = %v", err)
	}
}

func TestUnchangedFileIsNotStale(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	c := f.open(t, func(o *Options) { o.MaxStale = time.Minute })
	f.advance(time.Hour)
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("an unchanged file counted as stale")
	}
}

func TestNoStaleLimitMustBeExplicit(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	c := f.open(t, func(o *Options) { o.MaxStale = NoStaleLimit })
	f.advance(1000 * time.Hour)
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("explicit NoStaleLimit ignored")
	}
	d := f.open(t, nil)
	f.advance(DefaultMaxStale + time.Second)
	if _, err := d.Value("prod/api/stripe"); !errors.Is(err, ErrStale) {
		t.Errorf("default limit: %v", err)
	}
}

// A file reader can hold back updates. An authenticated window stops that.
func TestValidUntil(t *testing.T) {
	f := setup(t, vault.ServiceOptions{ValidFor: time.Hour})
	c := f.open(t, nil)
	f.advance(59 * time.Minute)
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("expired too early")
	}
	f.advance(2 * time.Minute)
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Value("prod/api/stripe"); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v", err)
	}
	// A restart with the same file also fails.
	_, err := Open(context.Background(), Options{Path: f.out, Key: StaticKeys(f.key.Bytes()), Audit: audit.Discard, Now: f.clock})
	if !errors.Is(err, ErrExpired) {
		t.Errorf("restart: %v", err)
	}
	// A new sync restores service.
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("not restored")
	}
}

func TestRollbackRefusedWithinProcess(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	old, err := os.ReadFile(f.out)
	if err != nil {
		t.Fatal(err)
	}
	put(t, f.main, "prod/api/stripe", "sk-new")
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	c := f.open(t, nil)
	if err := os.WriteFile(f.out, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); !errors.Is(err, vault.ErrRollback) {
		t.Errorf("err = %v", err)
	}
	if value(t, c, "prod/api/stripe") != "sk-new" {
		t.Error("rolled back")
	}
}

func TestMinGenerationAcrossRestart(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	old, err := os.ReadFile(f.out)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	c := f.open(t, nil)
	min := c.Generation()
	if err := os.WriteFile(f.out, old, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Open(context.Background(), Options{Path: f.out, Key: StaticKeys(f.key.Bytes()), Audit: audit.Discard, MinGeneration: min, Now: f.clock})
	if !errors.Is(err, vault.ErrRollback) {
		t.Errorf("err = %v", err)
	}
}

// A sync must work from another device, with no previous service file.
func TestSyncWithoutPreviousFile(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	c := f.open(t, nil)
	first := c.Generation()
	if err := os.Remove(f.out); err != nil {
		t.Fatal(err)
	}
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatalf("a running client must accept it: %v", err)
	}
	if c.Generation() != first+1 {
		t.Errorf("generation %d", c.Generation())
	}
}

// If a crash stops the file being written after the main vault commits, the next sync
// still continues the history.
func TestLostServiceFileContinuesLineage(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	c := f.open(t, nil)
	if err := f.main.SyncService("api", filepath.Join(f.dir, "lost.goraz")); err != nil {
		t.Fatal(err)
	}
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestRotationWithoutOutage(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	keyPath := filepath.Join(f.dir, "api.key")
	if err := os.WriteFile(keyPath, f.key.Bytes(), 0o400); err != nil {
		t.Fatal(err)
	}
	var reloadErrs atomic.Int32
	c := f.open(t, func(o *Options) {
		o.Key = KeyFile(keyPath)
		o.OnReloadError = func(error) { reloadErrs.Add(1) }
	})

	// Rotate into a separate file, as an operator would before deploying it.
	staged := filepath.Join(f.dir, "staged.goraz")
	next, err := f.main.RotateService("api", staged, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Step 1: add the new key beside the old one.
	both := append(append(bytes.Clone(f.key.Bytes()), '\n'), next.Bytes()...)
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, both, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	// Step 2: deploy the new file.
	data, err := os.ReadFile(staged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.out, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatalf("new file with both keys: %v", err)
	}
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("wrong value")
	}
	// Step 3: remove the old key. The old key alone no longer opens the new file.
	if err := os.WriteFile(keyPath, next.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), Options{Path: f.out, Key: StaticKeys(f.key.Bytes()), Audit: audit.Discard, Now: f.clock}); !errors.Is(err, vault.ErrWrongCredential) {
		t.Errorf("old key after rotation: %v", err)
	}
	r := f.open(t, func(o *Options) { o.Key = KeyFile(keyPath) })
	if value(t, r, "prod/api/stripe") != "sk-api" {
		t.Error("new key failed")
	}
}

func TestRotationBeforeKeyDeployKeepsRunning(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	var reported atomic.Int32
	c := f.open(t, func(o *Options) { o.OnReloadError = func(error) { reported.Add(1) } })
	if _, err := f.main.RotateService("api", f.out, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); !errors.Is(err, vault.ErrWrongCredential) {
		t.Errorf("err = %v", err)
	}
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("the running snapshot should stay in place")
	}
}

func TestRekeyForcesServiceRotation(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	if err := f.main.Rekey(vault.RekeyOptions{
		Passphrase: []byte(pass), Profile: kdf.Interactive,
		Confirm: func(vault.RekeyResult) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.main.SyncService("api", f.out); !errors.Is(err, vault.ErrNeedsRotation) {
		t.Fatalf("err = %v", err)
	}
	if !f.main.Services()[0].NeedsRotation {
		t.Error("not marked")
	}
	k, err := f.main.RotateService("api", f.out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	f.key = k
	c := f.open(t, nil)
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("wrong value")
	}
}

func TestServiceTokensAreSeparate(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	ctx := context.Background()
	webOut := filepath.Join(f.dir, "web.goraz")
	webKey, err := f.main.CreateService("web", webOut, vault.ServiceOptions{Prefixes: []string{"prod/web"}})
	if err != nil {
		t.Fatal(err)
	}

	apiTokens, err := f.main.ServiceTokens("api", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, rec, err := apiTokens.Issue(ctx, token.IssueRequest{Name: "billing", Scopes: []string{"payments:read"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	if err := f.main.SyncService("web", webOut); err != nil {
		t.Fatal(err)
	}

	c := f.open(t, nil)
	v, err := c.Verifier(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(ctx, tok.Bytes(), "payments:read")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "billing" {
		t.Errorf("%+v", got)
	}

	// Another service neither holds the record nor can verify the token.
	web, err := Open(ctx, Options{Path: webOut, Key: StaticKeys(webKey.Bytes()), Audit: audit.Discard, Interval: time.Hour, Now: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer web.Close()
	wv, err := web.Verifier(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wv.Verify(ctx, tok.Bytes()); !errors.Is(err, token.ErrInvalidToken) {
		t.Errorf("another service: %v", err)
	}
	// A service file is read-only.
	if err := (snapshotStore{c}).Put(ctx, rec); !errors.Is(err, token.ErrReadOnly) {
		t.Errorf("put: %v", err)
	}

	// Revocation reaches the service through a sync and a reload.
	id, _ := token.ParseID(rec.ID)
	if err := apiTokens.Revoke(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, tok.Bytes()); err != nil {
		t.Error("revocation shouldn't arrive before a sync")
	}
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, tok.Bytes()); !errors.Is(err, token.ErrInvalidToken) {
		t.Errorf("after revocation: %v", err)
	}
}

func TestVerifierFailsClosedWhenStale(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	ctx := context.Background()
	m, err := f.main.ServiceTokens("api", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := m.Issue(ctx, token.IssueRequest{Name: "x", TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	c := f.open(t, func(o *Options) { o.MaxStale = time.Minute })
	v, err := c.Verifier(audit.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, tok.Bytes()); err != nil {
		t.Fatal(err)
	}
	f.advance(2 * time.Minute)
	if _, err := v.Verify(ctx, tok.Bytes()); !errors.Is(err, token.ErrUnavailable) {
		t.Errorf("err = %v", err)
	}
}

func TestRotateInvalidatesServiceTokens(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	ctx := context.Background()
	m, err := f.main.ServiceTokens("api", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := m.Issue(ctx, token.IssueRequest{Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	k, err := f.main.RotateService("api", f.out, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.key = k
	c := f.open(t, nil)
	v, err := c.Verifier(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, tok.Bytes()); !errors.Is(err, token.ErrInvalidToken) {
		t.Errorf("err = %v", err)
	}
}

func TestAuditRequiredForService(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	_, err := Open(context.Background(), Options{Path: f.out, Key: StaticKeys(f.key.Bytes()), Now: f.clock})
	if !errors.Is(err, vault.ErrAuditUnavailable) {
		t.Errorf("no sink: %v", err)
	}
	var buf syncBuffer
	c := f.open(t, func(o *Options) { o.Audit = audit.NewJSONSink(&buf) })
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("wrong value")
	}
	out := buf.String()
	if !strings.Contains(out, `"item.read"`) || !strings.Contains(out, `"machine"`) {
		t.Errorf("audit stream: %s", out)
	}
	for _, canary := range []string{"sk-api", "prod/api", "stripe"} {
		if strings.Contains(out, canary) {
			t.Errorf("audit stream leaked %q: %s", canary, out)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type failWriter struct{ fail atomic.Bool }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.fail.Load() {
		return 0, errors.New("stdout closed")
	}
	return len(p), nil
}

func TestBrokenAuditStreamStopsReads(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	w := &failWriter{}
	c := f.open(t, func(o *Options) { o.Audit = audit.NewJSONSink(w) })
	w.fail.Store(true)
	if _, err := c.Value("prod/api/stripe"); !errors.Is(err, vault.ErrAuditUnavailable) {
		t.Errorf("err = %v", err)
	}
}

func TestKeyFileRules(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	if err := os.WriteFile(p, []byte("goraz_mk_a\ngoraz_mk_b\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	keys, err := KeyFile(p).Keys()
	if err != nil || len(keys) != 2 {
		t.Fatalf("%v %v", keys, err)
	}
	if err := os.Chmod(p, 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := KeyFile(p).Keys(); err != nil {
		t.Errorf("group read must be allowed: %v", err)
	}
	for _, mode := range []os.FileMode{0o644, 0o444, 0o660, 0o666} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		_, err := KeyFile(p).Keys()
		if err == nil {
			t.Errorf("mode %o accepted", mode)
		} else if !strings.Contains(err.Error(), "defaultMode") {
			t.Errorf("mode %o: error lacks guidance: %v", mode, err)
		}
	}
	// Kubernetes mounts secrets through a symlink.
	if err := os.Chmod(p, 0o400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := KeyFile(link).Keys(); err != nil {
		t.Errorf("symlink: %v", err)
	}
}

func TestParseKeys(t *testing.T) {
	got, err := ParseKeys([]byte("a\r\nb\n\n"))
	if err != nil || len(got) != 2 || string(got[0]) != "a" {
		t.Errorf("%v %v", got, err)
	}
	if _, err := ParseKeys([]byte("\n\n")); err == nil {
		t.Error("empty accepted")
	}
	if _, err := ParseKeys([]byte("a\nb\nc\nd\ne\n")); err == nil {
		t.Error("too many accepted")
	}
}

func TestKeyFD(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("goraz_mk_a\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// A duplicate has no finalizer, so the garbage collector can't close it first.
	fd, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	src := KeyFD(uintptr(fd))
	for range 2 { // Read once, then served from memory.
		keys, err := src.Keys()
		if err != nil || len(keys) != 1 || string(keys[0]) != "goraz_mk_a" {
			t.Fatalf("%v %v", keys, err)
		}
	}
}

func TestOpenValidation(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, Options{}); err == nil {
		t.Error("empty options accepted")
	}
	if _, err := Open(ctx, Options{Path: "x", Key: StaticKeys(), Interval: -1}); err == nil {
		t.Error("negative interval accepted")
	}
	if _, err := Open(ctx, Options{Path: "/does/not/exist", Key: StaticKeys()}); err == nil {
		t.Error("missing file accepted")
	}
}

func TestSymlinkToFIFODoesNotBlock(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	c := f.open(t, func(o *Options) { o.MaxStale = time.Minute })
	fifo := filepath.Join(f.dir, "fifo")
	if err := mkfifo(fifo); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.out); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, f.out); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Reload() }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload blocked on a FIFO")
	}
	f.advance(2 * time.Minute)
	if _, err := c.Value("prod/api/stripe"); !errors.Is(err, ErrStale) {
		t.Errorf("err = %v", err)
	}
}

func TestConcurrentReadersDuringReload(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	c := f.open(t, nil)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := c.Value("prod/api/stripe"); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	for i := range 20 {
		put(t, f.main, "prod/api/stripe", strings.Repeat("v", i+1))
		if err := f.main.SyncService("api", f.out); err != nil {
			t.Fatal(err)
		}
		if err := c.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestMainVaultRefusedInServiceMode(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	k, err := f.main.AddMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(context.Background(), Options{
		Path: filepath.Join(f.dir, "main.goraz"), Key: StaticKeys(k.Bytes()), Audit: audit.Discard, Now: f.clock,
	})
	if !errors.Is(err, vault.ErrNotServiceVault) {
		t.Errorf("err = %v", err)
	}
}

func TestCallbackCanUseClient(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	var c *Client
	seen := make(chan uint64, 1)
	c = f.open(t, func(o *Options) {
		o.OnReload = func(uint64) {
			if c != nil {
				seen <- c.Generation()
			}
		}
	})
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Reload() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a callback using the client deadlocked")
	}
	if <-seen == 0 {
		t.Error("no generation")
	}
}

func TestFailedKeySaveChangesNothing(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	before, err := os.ReadFile(f.out)
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("can't write the key")
	if _, err := f.main.RotateService("api", f.out, func([]byte) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("err = %v", err)
	}
	after, err := os.ReadFile(f.out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the service file changed")
	}
	// The old key must still be the one in effect after a sync.
	if err := f.main.SyncService("api", f.out); err != nil {
		t.Fatal(err)
	}
	c := f.open(t, nil)
	if value(t, c, "prod/api/stripe") != "sk-api" {
		t.Error("the old key stopped working")
	}
}

func TestCloseIsSafe(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	c := f.open(t, nil)
	c.Close()
	c.Close()
	if _, err := c.Value("prod/api/stripe"); !errors.Is(err, ErrClosed) {
		t.Errorf("err = %v", err)
	}
	if err := c.Reload(); !errors.Is(err, ErrClosed) {
		t.Errorf("reload: %v", err)
	}
	if c.Generation() != 0 {
		t.Error("generation after close")
	}
}

func TestServiceManagement(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	if _, err := f.main.CreateService("api", f.out, vault.ServiceOptions{Prefixes: []string{"x"}}); !errors.Is(err, vault.ErrExists) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := f.main.CreateService("no-prefix", f.out, vault.ServiceOptions{}); err == nil {
		t.Error("no prefix accepted")
	}
	if _, err := f.main.CreateService("bad", f.out, vault.ServiceOptions{Prefixes: []string{"../x"}}); err == nil {
		t.Error("bad prefix accepted")
	}
	if _, err := f.main.CreateService("../bad", f.out, vault.ServiceOptions{Prefixes: []string{"x"}}); err == nil {
		t.Error("bad name accepted")
	}
	if _, err := f.main.CreateService("neg", f.out, vault.ServiceOptions{Prefixes: []string{"x"}, ValidFor: -1}); err == nil {
		t.Error("negative window accepted")
	}
	if err := f.main.SyncService("nope", f.out); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := f.main.ServiceTokens("nope", nil); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("unknown tokens: %v", err)
	}
	if len(f.main.Services()) != 1 {
		t.Error("list wrong")
	}
	if err := f.main.RemoveService("api"); err != nil {
		t.Fatal(err)
	}
	if err := f.main.RemoveService("api"); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("second remove: %v", err)
	}
	if len(f.main.Services()) != 0 {
		t.Error("not removed")
	}
}

// The service file must carry no path, because no field may choose a path.
func TestReadOnlyVaultRefusesWrites(t *testing.T) {
	f := setup(t, vault.ServiceOptions{})
	data, err := os.ReadFile(f.out)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.OpenService(data, vault.WithMachineKeys(f.key.Bytes()), vault.Options{Audit: audit.Discard, Now: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Put(&vault.Item{Name: "x", Value: secret.New([]byte("y"))}); !errors.Is(err, vault.ErrReadOnly) {
		t.Errorf("err = %v", err)
	}
}
