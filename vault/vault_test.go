package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/envelope"
	"github.com/mtnaskari/goraz/internal/format"
	"github.com/mtnaskari/goraz/internal/fsutil"
	"github.com/mtnaskari/goraz/internal/kdf"
	"github.com/mtnaskari/goraz/secret"
	"github.com/mtnaskari/goraz/token"
)

var update = flag.Bool("update", false, "rewrite the golden vault")

const testPass = "violet granite ocean drift lantern"

type env struct {
	dir, path, stateDir string
	code                secret.Secret
}

func newEnv(t testing.TB) (*env, *Vault) {
	t.Helper()
	dir := t.TempDir()
	e := &env{dir: dir, path: filepath.Join(dir, "v.goraz"), stateDir: filepath.Join(dir, "state")}
	v, code, err := Create(e.path, CreateOptions{
		Passphrase: []byte(testPass), Profile: ProfileInteractive, Options: Options{StateDir: e.stateDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.code = code
	t.Cleanup(v.Close)
	return e, v
}

func (e *env) open(t testing.TB, o Options) (*Vault, error) {
	t.Helper()
	if o.StateDir == "" {
		o.StateDir = e.stateDir
	}
	v, err := Open(e.path, WithPassphrase([]byte(testPass), nil), o)
	if err == nil {
		t.Cleanup(v.Close)
	}
	return v, err
}

func put(t testing.TB, v *Vault, name, value string) {
	t.Helper()
	if err := v.Put(&Item{Name: name, Value: secret.New([]byte(value))}); err != nil {
		t.Fatal(err)
	}
}

func get(t testing.TB, v *Vault, name string) string {
	t.Helper()
	it, err := v.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(it.Value.Bytes())
}

func TestCreateReopenRoundTrip(t *testing.T) {
	e, v := newEnv(t)
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	raw := []byte{0xff, 0x00, 0xfe, 'a'} // Not valid UTF-8.
	if err := v.Put(&Item{
		Name: "prod/login", Type: TypeLogin, Value: secret.New(raw), Username: "alice",
		URLs: []string{"https://example.com"}, Notes: "n", Tags: []string{"t"}, Expires: &exp,
	}); err != nil {
		t.Fatal(err)
	}
	v.Close()
	if _, err := v.Get("prod/login"); !errors.Is(err, ErrClosed) {
		t.Errorf("closed vault: %v", err)
	}

	r, err := e.open(t, Options{})
	if err != nil {
		t.Fatal(err)
	}
	it, err := r.Get("prod/login")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(it.Value.Bytes(), raw) || it.Username != "alice" || it.URLs[0] != "https://example.com" ||
		it.Notes != "n" || it.Type != TypeLogin || !it.Expires.Equal(exp) || it.Tags[0] != "t" {
		t.Fatalf("mismatch: %+v", it)
	}
	st, err := os.Stat(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
}

func TestPassphrasePolicyAtCreate(t *testing.T) {
	dir := t.TempDir()
	o := CreateOptions{Passphrase: []byte("short"), Profile: ProfileInteractive, Options: Options{StateDir: dir}}
	if _, _, err := Create(filepath.Join(dir, "a"), o); err == nil {
		t.Error("weak passphrase accepted")
	}
	o.AcceptWeakPassphrase = true
	v, _, err := Create(filepath.Join(dir, "a"), o)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	if _, _, err := Create(filepath.Join(dir, "a"), o); err == nil {
		t.Error("overwrote an existing vault")
	}
}

func TestDefaultKDFIsStrong(t *testing.T) {
	if kdf.Default != kdf.Strong {
		t.Error("the default profile changed")
	}
}

func TestWrongCredentials(t *testing.T) {
	e, _ := newEnv(t)
	for name, c := range map[string]Credential{
		"passphrase": WithPassphrase([]byte("wrong wrong wrong wrong"), nil),
		"keyfile":    WithPassphrase([]byte(testPass), bytes.Repeat([]byte{1}, 32)),
		"recovery":   WithRecoveryCode([]byte("GORAZ-RC-AAAA")),
		"machine":    WithMachineKeys([]byte("goraz_mk_x")),
	} {
		if _, err := Open(e.path, c, Options{StateDir: e.stateDir}); !errors.Is(err, ErrWrongCredential) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestRecoveryCodeOpens(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "1")
	r, err := Open(e.path, WithRecoveryCode(e.code.Bytes()), Options{StateDir: e.stateDir})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if get(t, r, "a") != "1" {
		t.Error("wrong value")
	}
}

func TestKeyfile(t *testing.T) {
	dir := t.TempDir()
	kf := bytes.Repeat([]byte{7}, 32)
	p := filepath.Join(dir, "v")
	v, _, err := Create(p, CreateOptions{Passphrase: []byte(testPass), Keyfile: kf, Profile: ProfileInteractive, Options: Options{StateDir: dir}})
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	if _, err := Open(p, WithPassphrase([]byte(testPass), nil), Options{StateDir: dir}); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("no key file: %v", err)
	}
	r, err := Open(p, WithPassphrase([]byte(testPass), kf), Options{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if _, _, err := Create(filepath.Join(dir, "w"), CreateOptions{Passphrase: []byte(testPass), Keyfile: kf[:10], Profile: ProfileInteractive, Options: Options{StateDir: dir}}); err == nil {
		t.Error("short key file accepted")
	}
}

func TestNamesAreValidatedEverywhere(t *testing.T) {
	_, v := newEnv(t)
	for _, bad := range []string{"", "../x", "a//b", "a/../b", "a b", "a%2e", "a\x00"} {
		if err := v.Put(&Item{Name: bad, Value: secret.New([]byte("x"))}); err == nil {
			t.Errorf("Put(%q) accepted", bad)
		}
		if _, err := v.Get(bad); err == nil {
			t.Errorf("Get(%q) accepted", bad)
		}
		if err := v.Delete(bad); err == nil {
			t.Errorf("Delete(%q) accepted", bad)
		}
		if err := v.Destroy(bad); err == nil {
			t.Errorf("Destroy(%q) accepted", bad)
		}
		if err := v.Restore(bad, 0); err == nil {
			t.Errorf("Restore(%q) accepted", bad)
		}
		if _, err := v.History(bad); err == nil {
			t.Errorf("History(%q) accepted", bad)
		}
	}
}

func TestCaseCollisionRefused(t *testing.T) {
	_, v := newEnv(t)
	put(t, v, "prod/db", "1")
	if err := v.Put(&Item{Name: "PROD/db", Value: secret.New([]byte("2"))}); !errors.Is(err, ErrExists) {
		t.Errorf("err = %v", err)
	}
}

func TestSizeLimit(t *testing.T) {
	_, v := newEnv(t)
	if err := v.Put(&Item{Name: "big", Value: secret.New(make([]byte, format.MaxValueSize+1))}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v", err)
	}
	if err := v.Put(&Item{Name: "ok", Value: secret.New(make([]byte, format.MaxValueSize))}); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestVersionsHistoryRestore(t *testing.T) {
	_, v := newEnv(t)
	for i := 1; i <= maxVersions+3; i++ {
		put(t, v, "a", fmt.Sprint(i))
	}
	h, err := v.History("a")
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Versions) != maxVersions || h.Versions[0] != 4 {
		t.Fatalf("%v", h.Versions)
	}
	if _, err := v.GetVersion("a", 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("pruned version: %v", err)
	}
	it, err := v.GetVersion("a", 5)
	if err != nil || string(it.Value.Bytes()) != "5" {
		t.Fatalf("%v %v", it, err)
	}
	if err := v.Restore("a", 5); err != nil {
		t.Fatal(err)
	}
	if get(t, v, "a") != "5" {
		t.Error("restore failed")
	}
	h, _ = v.History("a")
	if h.Versions[len(h.Versions)-1] != maxVersions+4 {
		t.Errorf("restore should add a version: %v", h.Versions)
	}
}

func TestDeleteAndDestroy(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "TOPSECRETVALUE")
	if err := v.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted: %v", err)
	}
	if list, _ := v.List(); len(list) != 0 {
		t.Errorf("listed: %v", list)
	}
	if err := v.Delete("a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
	if err := v.Restore("a", 0); err != nil {
		t.Fatal(err)
	}
	if get(t, v, "a") != "TOPSECRETVALUE" {
		t.Error("restore lost the value")
	}
	before, _ := os.Stat(e.path)
	if err := v.Destroy("a"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(e.path)
	if after.Size() >= before.Size() {
		t.Error("destroy did not remove the blobs")
	}
	if _, err := v.History("a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("history after destroy: %v", err)
	}
	if err := v.Destroy("a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second destroy: %v", err)
	}
}

// Nothing a reader of the file can see may reveal names or values.
func TestFileRevealsNoPlaintext(t *testing.T) {
	e, v := newEnv(t)
	if err := v.Put(&Item{
		Name: "prodcanaryname", Type: TypeLogin, Value: secret.New([]byte("valuecanary")),
		Username: "usercanary", URLs: []string{"https://urlcanary.example"}, Notes: "notecanary", Tags: []string{"tagcanary"},
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"prodcanaryname", "valuecanary", "usercanary", "urlcanary", "notecanary", "tagcanary"} {
		if bytes.Contains(data, []byte(c)) {
			t.Errorf("%s found in the file", c)
		}
	}
}

// Sizes are padded, so the difference between short values doesn't show.
func TestPaddingHidesShortLengths(t *testing.T) {
	_, v := newEnv(t)
	put(t, v, "a", "x")
	put(t, v, "b", strings.Repeat("x", 40))
	v.mu.RLock()
	defer v.mu.RUnlock()
	a := v.m.find("a").Versions[0].Length
	b := v.m.find("b").Versions[0].Length
	if a != b {
		t.Errorf("lengths differ: %d, %d", a, b)
	}
}

func TestPadUnpad(t *testing.T) {
	for _, n := range []int{0, 1, 251, 252, 253, 256, 1000} {
		p := pad(make([]byte, n))
		if len(p)%padBlock != 0 {
			t.Errorf("%d: bad length %d", n, len(p))
		}
		got, err := unpad(p)
		if err != nil || len(got) != n {
			t.Errorf("%d: %v", n, err)
		}
	}
	p := pad([]byte("abc"))
	p[len(p)-1] = 1
	if _, err := unpad(p); err == nil {
		t.Error("non-zero padding accepted")
	}
	q := pad([]byte("abc"))
	q[0] = 0xff
	if _, err := unpad(q); err == nil {
		t.Error("oversized length accepted")
	}
	if _, err := unpad(make([]byte, 100)); err == nil {
		t.Error("wrong block size accepted")
	}
	if _, err := unpad(nil); err == nil {
		t.Error("empty accepted")
	}
}

func machineVault(t testing.TB) (*env, *Vault, []byte) {
	t.Helper()
	e, v := newEnv(t)
	put(t, v, "a", "alpha")
	put(t, v, "b", "beta")
	k, err := v.AddMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	return e, v, k.Bytes()
}

// Every bit of the file is flipped. The vault must fail to open, or the affected
// read must fail. It must never return altered data.
func TestEveryBitFlipIsDetected(t *testing.T) {
	e, v, key := machineVault(t)
	v.Close()
	data, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	stride := 1
	if testing.Short() {
		stride = 37
	}
	for bit := 0; bit < len(data)*8; bit += stride {
		m := bytes.Clone(data)
		m[bit/8] ^= 1 << (bit % 8)
		r, err := openReadOnly(m, WithMachineKeys(key), Options{Audit: audit.Discard})
		if err != nil {
			continue
		}
		for name, want := range map[string]string{"a": "alpha", "b": "beta"} {
			it, err := r.Get(name)
			if err != nil {
				continue
			}
			if string(it.Value.Bytes()) != want {
				t.Fatalf("bit %d: read returned altered data", bit)
			}
		}
		bad, _ := r.FullCheck()
		if len(bad) == 0 {
			t.Fatalf("bit %d: accepted with no damage reported", bit)
		}
		r.Close()
	}
}

func TestTruncationAndAppendRejected(t *testing.T) {
	e, v, key := machineVault(t)
	v.Close()
	data, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 8, 100, len(data) / 2, len(data) - 1} {
		if _, err := openReadOnly(data[:n], WithMachineKeys(key), Options{Audit: audit.Discard}); err == nil {
			t.Errorf("truncation to %d accepted", n)
		}
	}
	if _, err := openReadOnly(append(bytes.Clone(data), 0), WithMachineKeys(key), Options{Audit: audit.Discard}); !errors.Is(err, ErrTampered) {
		t.Errorf("appended byte: %v", err)
	}
}

// One damaged item must not make the others unreadable, and a write must be refused.
func TestDamagedItemIsIsolated(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "alpha")
	put(t, v, "b", "beta")
	data, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1 // The last blob belongs to "b".
	if err := os.WriteFile(e.path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(e.path, WithPassphrase([]byte(testPass), nil), Options{StateDir: e.stateDir, AcceptFork: true}); err != nil {
		t.Fatal(err)
	}
	r, err := Open(e.path, WithPassphrase([]byte(testPass), nil), Options{StateDir: e.stateDir})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if get(t, r, "a") != "alpha" {
		t.Error("intact item unreadable")
	}
	if _, err := r.Get("b"); !errors.Is(err, ErrTampered) {
		t.Errorf("damaged item: %v", err)
	}
	if err := r.Put(&Item{Name: "c", Value: secret.New([]byte("x"))}); !errors.Is(err, ErrTampered) {
		t.Errorf("write over a damaged file: %v", err)
	}
	bad, err := r.FullCheck()
	if err != nil || len(bad) != 1 || bad[0] != "b" {
		t.Errorf("FullCheck: %v %v", bad, err)
	}
}

// Build a file by hand with valid keys, to test what authentication alone doesn't
// reach, and to confirm blobs are bound to their place.
func TestBlobsCantMoveBetweenItems(t *testing.T) {
	_, v := newEnv(t)
	put(t, v, "a", "alpha")
	put(t, v, "b", "beta")
	v.mu.Lock()
	ea, eb := v.m.find("a"), v.m.find("b")
	blobA := v.blobs[blobKey(ea.ID, 1)]
	blobB := v.blobs[blobKey(eb.ID, 1)]
	// Swap both the blobs and their hashes, as someone rewriting the manifest would.
	v.blobs[blobKey(ea.ID, 1)], v.blobs[blobKey(eb.ID, 1)] = blobB, blobA
	ea.Versions[0].SHA256, eb.Versions[0].SHA256 = sha256Sum(blobB), sha256Sum(blobA)
	v.mu.Unlock()
	if _, err := v.Get("a"); !errors.Is(err, ErrTampered) {
		t.Errorf("swapped blob opened: %v", err)
	}
}

func TestOldVersionCantReplaceNew(t *testing.T) {
	_, v := newEnv(t)
	put(t, v, "a", "one")
	put(t, v, "a", "two")
	v.mu.Lock()
	e := v.m.find("a")
	old := v.blobs[blobKey(e.ID, 1)]
	v.blobs[blobKey(e.ID, 2)] = old
	e.Versions[1].SHA256 = sha256Sum(old)
	v.mu.Unlock()
	if _, err := v.Get("a"); !errors.Is(err, ErrTampered) {
		t.Errorf("old version opened as new: %v", err)
	}
}

func TestSlotFromAnotherVaultRejected(t *testing.T) {
	a, _ := newEnv(t)
	b, _ := newEnv(t)
	ad, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := os.ReadFile(b.path)
	if err != nil {
		t.Fatal(err)
	}
	// Give vault B vault A's ID. Its slots are bound to B's ID.
	copy(bd[len(format.Magic):], ad[len(format.Magic):len(format.Magic)+format.IDSize])
	if err := os.WriteFile(b.path, bd, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(b.path, WithPassphrase([]byte(testPass), nil), Options{StateDir: b.stateDir}); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("err = %v", err)
	}
}

func TestAddedSlotDetected(t *testing.T) {
	e, v, key := machineVault(t)
	v.Close()
	data, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	h, n, err := format.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	extra := format.Slot{Type: format.SlotRecovery, Blob: make([]byte, format.SlotBlobSize)}
	extra.ID[0] = 0xee
	h.Slots = append(h.Slots, extra)
	head, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	forged := append(head, data[n:]...)
	if _, err := openReadOnly(forged, WithMachineKeys(key), Options{Audit: audit.Discard}); !errors.Is(err, ErrTampered) {
		t.Errorf("err = %v", err)
	}
}

func TestDowngradedKDFRefusedBeforeUse(t *testing.T) {
	e, v := newEnv(t)
	v.Close()
	data, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	h, _, err := format.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if h.Slots[0].Params != kdf.Interactive.Params {
		t.Fatal("unexpected profile")
	}
	off := len(format.Magic) + format.IDSize + 8 + 1 + 1 + format.IDSize + kdf.SaltSize
	data[off+2], data[off+3] = 0, 1 // Memory becomes a tiny value.
	if err := os.WriteFile(e.path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := Open(e.path, WithPassphrase([]byte(testPass), nil), Options{StateDir: e.stateDir}); !errors.Is(err, ErrTampered) {
		t.Errorf("err = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Log("slow refusal; KDF should not have run")
	}
}

// A profile that's allowed but different from the one in use still fails, because
// the slot authenticates its parameters.
func TestSwappedProfileFails(t *testing.T) {
	e, v := newEnv(t)
	v.Close()
	data, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	off := len(format.Magic) + format.IDSize + 8 + 1 + 1 + format.IDSize + kdf.SaltSize
	copy(data[off:], []byte{0, 4, 0, 0}) // 256 MiB, the standard profile.
	if err := os.WriteFile(e.path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(e.path, WithPassphrase([]byte(testPass), nil), Options{StateDir: e.stateDir}); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("err = %v", err)
	}
}

func TestSymlinkAndPermissionRefused(t *testing.T) {
	e, v := newEnv(t)
	v.Close()
	link := filepath.Join(e.dir, "link")
	if err := os.Symlink(e.path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, WithPassphrase([]byte(testPass), nil), Options{StateDir: e.stateDir}); !errors.Is(err, fsutil.ErrUnsafeFile) {
		t.Errorf("symlink: %v", err)
	}
	if err := os.Chmod(e.path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(e.path, WithPassphrase([]byte(testPass), nil), Options{StateDir: e.stateDir}); !errors.Is(err, fsutil.ErrUnsafeFile) {
		t.Errorf("world-writable: %v", err)
	}
}

func TestRollbackAndFork(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "one")
	old, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	put(t, v, "a", "two")
	cur, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()

	// An older file is refused.
	if err := os.WriteFile(e.path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.open(t, Options{}); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback: %v", err)
	}

	// The override pins that file and is audited.
	r, err := e.open(t, Options{AcceptRollback: true})
	if err != nil {
		t.Fatal(err)
	}
	if get(t, r, "a") != "one" {
		t.Error("wrong file")
	}
	entries, err := r.ReadAudit()
	if err != nil {
		t.Fatal(err)
	}
	if !hasEvent(entries, audit.EventRollbackAccept) {
		t.Error("the override wasn't audited")
	}
	// A later write gets a generation above everything seen.
	high := r.high
	put(t, r, "a", "three")
	if r.Generation() <= high {
		t.Errorf("generation %d reuses a number at or below %d", r.Generation(), high)
	}
	r.Close()

	// The abandoned higher file now has a different history.
	if err := os.WriteFile(e.path, cur, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.open(t, Options{}); !errors.Is(err, ErrRollback) {
		t.Errorf("abandoned file: %v", err)
	}
}

func hasEvent(es []audit.Entry, t audit.EventType) bool {
	for _, e := range es {
		if e.Type == t {
			return true
		}
	}
	return false
}

// Two devices share a synced file and each has its own state.
func TestSyncConflictBetweenDevices(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "base")
	v.Close()
	devA, devB := e.stateDir, filepath.Join(e.dir, "stateB")
	base, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}

	b, err := e.open(t, Options{StateDir: devB})
	if err != nil {
		t.Fatal(err)
	}
	put(t, b, "a", "from-b")
	fromB, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()

	if err := os.WriteFile(e.path, base, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := e.open(t, Options{StateDir: devA})
	if err != nil {
		t.Fatal(err)
	}
	put(t, a, "a", "from-a")
	a.Close()

	// Sync delivers B's file to A. Both wrote from the same base, so it's a fork.
	if err := os.WriteFile(e.path, fromB, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.open(t, Options{StateDir: devA}); !errors.Is(err, ErrFork) {
		t.Fatalf("same generation: %v", err)
	}

	// Even if B wrote again, so its generation is higher, A must still notice.
	bb, err := e.open(t, Options{StateDir: devB})
	if err != nil {
		t.Fatal(err)
	}
	put(t, bb, "a", "from-b-2")
	bb.Close()
	if _, err := e.open(t, Options{StateDir: devA}); !errors.Is(err, ErrFork) {
		t.Fatalf("higher generation: %v", err)
	}

	r, err := e.open(t, Options{StateDir: devA, AcceptFork: true})
	if err != nil {
		t.Fatal(err)
	}
	if get(t, r, "a") != "from-b-2" {
		t.Error("wrong file")
	}
	entries, err := r.ReadAudit()
	if err != nil {
		t.Fatal(err)
	}
	if !hasEvent(entries, audit.EventForkAccept) {
		t.Error("the override wasn't audited")
	}
}

func TestStateTamperRefused(t *testing.T) {
	e, v := newEnv(t)
	id := v.ID()
	v.Close()
	p := filepath.Join(e.stateDir, "vaults", fmt.Sprintf("%x.state", id[:]))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, bytes.Replace(b, []byte(`"high":`), []byte(`"high":0`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.open(t, Options{}); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("err = %v", err)
	}
	if err := ResetLocalState(e.stateDir, id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.open(t, Options{}); err != nil {
		t.Errorf("after reset: %v", err)
	}
	got, err := IDFromFile(e.path)
	if err != nil || got != id {
		t.Errorf("IDFromFile: %v", err)
	}
}

// A rekeyed file syncs to a device that hasn't seen the rekey. Its state must still
// verify, because the state key survives a rekey.
func TestRekeyedFileReachesOtherDevice(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "one")
	v.Close()
	devB := filepath.Join(e.dir, "stateB")
	b, err := e.open(t, Options{StateDir: devB})
	if err != nil {
		t.Fatal(err)
	}
	b.Close()

	a, err := e.open(t, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Rekey(RekeyOptions{
		Passphrase: []byte(testPass), Profile: ProfileInteractive,
		Confirm: func(RekeyResult) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	r, err := e.open(t, Options{StateDir: devB})
	if err != nil {
		t.Fatalf("other device after rekey: %v", err)
	}
	if get(t, r, "a") != "one" {
		t.Error("wrong value")
	}
}

func TestChangedFileRefusedOnWrite(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "one")
	o, err := e.open(t, Options{})
	if err != nil {
		t.Fatal(err)
	}
	put(t, o, "a", "two")
	if err := v.Put(&Item{Name: "b", Value: secret.New([]byte("x"))}); !errors.Is(err, ErrChanged) {
		t.Errorf("stale writer: %v", err)
	}
	// A read would use a stale key if it logged, so it's refused too.
	if _, err := v.Get("a"); !errors.Is(err, ErrChanged) {
		t.Errorf("stale reader: %v", err)
	}
}

func TestParallelWritersKeepAllWrites(t *testing.T) {
	e, _ := newEnv(t)
	var wg sync.WaitGroup
	const writers = 4
	for i := range writers {
		wg.Go(func() {
			for attempt := range 50 {
				v, err := e.open(t, Options{})
				if err != nil {
					if errors.Is(err, ErrFork) || errors.Is(err, ErrRollback) {
						time.Sleep(time.Millisecond)
						continue
					}
					t.Error(err)
					return
				}
				err = v.Put(&Item{Name: fmt.Sprintf("w%d", i), Value: secret.New([]byte("x"))})
				v.Close()
				if err == nil {
					return
				}
				if !errors.Is(err, ErrChanged) && !errors.Is(err, audit.ErrTampered) {
					t.Errorf("attempt %d: %v", attempt, err)
					return
				}
				time.Sleep(time.Duration(i+1) * 3 * time.Millisecond)
			}
			t.Errorf("writer %d never succeeded", i)
		})
	}
	wg.Wait()
	r, err := e.open(t, Options{})
	if err != nil {
		t.Fatal(err)
	}
	list, err := r.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != writers {
		t.Errorf("lost writes: %v", list)
	}
	if _, err := r.VerifyAudit(); err != nil {
		t.Errorf("audit chain: %v", err)
	}
}

// Faults between write, fsync and rename leave the old file or the new file.
func TestCrashDuringWrite(t *testing.T) {
	boom := errors.New("crash")
	for _, stage := range []fsutil.Stage{fsutil.StageAfterWrite, fsutil.StageAfterSync, fsutil.StageAfterRename} {
		e, v := newEnv(t)
		put(t, v, "a", "old")
		v.Close()
		o := Options{StateDir: e.stateDir, hook: func(s fsutil.Stage) error {
			if s == stage {
				return boom
			}
			return nil
		}}
		w, err := Open(e.path, WithPassphrase([]byte(testPass), nil), o)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Put(&Item{Name: "a", Value: secret.New([]byte("new"))}); !errors.Is(err, boom) {
			t.Fatalf("%s: %v", stage, err)
		}
		w.Close()
		r, err := e.open(t, Options{})
		if err != nil {
			t.Fatalf("%s: reopen: %v", stage, err)
		}
		want := "old"
		if stage == fsutil.StageAfterRename {
			want = "new" // The file was replaced, and state simply lags behind it.
		}
		if got := get(t, r, "a"); got != want {
			t.Errorf("%s: got %s", stage, got)
		}
	}
}

func TestPassphraseChangeDoesNotRevoke(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "1")
	old, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	const next = "amber canyon whisper meadow copper"
	if err := v.ChangePassphrase([]byte(next), nil, ProfileInteractive, false); err != nil {
		t.Fatal(err)
	}
	if err := v.ChangePassphrase([]byte("short"), nil, ProfileInteractive, false); err == nil {
		t.Error("weak passphrase accepted")
	}
	put(t, v, "a", "2")
	v.Close()
	if _, err := e.open(t, Options{}); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("old passphrase on the new file: %v", err)
	}
	r, err := Open(e.path, WithPassphrase([]byte(next), nil), Options{StateDir: e.stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if get(t, r, "a") != "2" {
		t.Error("wrong value")
	}
	r.Close()

	// The documented limit: the old passphrase plus an old copy gives the same master
	// key, which also decrypts the new file. This test records that fact.
	oldHdr, _, err := format.Parse(old)
	if err != nil {
		t.Fatal(err)
	}
	s := oldHdr.Slots[0]
	key, err := kdf.PassphraseKey([]byte(testPass), nil, s.Salt[:], oldHdr.VaultID[:], s.Params)
	if err != nil {
		t.Fatal(err)
	}
	vmk, err := openSlot(key, oldHdr.VaultID, &s)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	h, n, err := format.Parse(cur)
	if err != nil {
		t.Fatal(err)
	}
	mk, err := kdf.Subkey(vmk, h.VaultID[:], kdf.LabelManifest)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cur[:n])
	if _, err := envelope.Open(mk, envelope.DomainManifest, sum[:], cur[n:n+int(h.ManifestLen)]); err != nil {
		t.Errorf("the limit stated in the docs no longer holds: %v", err)
	}
}

func TestRekeyRevokes(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "1")
	put(t, v, "a", "2")
	old, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	oldKeys := bytes.Clone(v.vmk())
	mk, err := v.AddMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := v.Tokens(nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := mgr.Issue(context.Background(), token.IssueRequest{Name: "x"})
	if err != nil {
		t.Fatal(err)
	}

	var shown RekeyResult
	const next = "amber canyon whisper meadow copper"
	err = v.Rekey(RekeyOptions{
		Passphrase: []byte(next), Profile: ProfileInteractive, ReissueMachine: 1,
		Confirm: func(r RekeyResult) error { shown = r; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if shown.RecoveryCode.IsZero() || len(shown.MachineKeys) != 1 {
		t.Fatal("new credentials weren't shown")
	}
	if get(t, v, "a") != "2" {
		t.Error("value lost")
	}
	if it, err := v.GetVersion("a", 1); err != nil || string(it.Value.Bytes()) != "1" {
		t.Errorf("history lost: %v", err)
	}
	v.Close()

	// All old credentials fail against the new file.
	for name, c := range map[string]Credential{
		"passphrase": WithPassphrase([]byte(testPass), nil),
		"recovery":   WithRecoveryCode(e.code.Bytes()),
		"machine":    WithMachineKeys(mk.Bytes()),
	} {
		if _, err := Open(e.path, c, Options{StateDir: e.stateDir}); !errors.Is(err, ErrWrongCredential) {
			t.Errorf("old %s: %v", name, err)
		}
	}
	// The old master key no longer opens the manifest.
	cur, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	h, n, err := format.Parse(cur)
	if err != nil {
		t.Fatal(err)
	}
	k, err := kdf.Subkey(oldKeys, h.VaultID[:], kdf.LabelManifest)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cur[:n])
	if _, err := envelope.Open(k, envelope.DomainManifest, sum[:], cur[n:n+int(h.ManifestLen)]); err == nil {
		t.Error("the old master key still opens the file")
	}
	_ = old

	// New credentials work, and tokens under the old verifier key don't.
	r, err := Open(e.path, WithPassphrase([]byte(next), nil), Options{StateDir: e.stateDir})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	m2, err := r.Tokens(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Verify(context.Background(), tok.Bytes()); !errors.Is(err, token.ErrInvalidToken) {
		t.Errorf("token after rekey: %v", err)
	}
	if _, err := r.VerifyAudit(); err != nil {
		t.Errorf("audit chain across a rekey: %v", err)
	}
	r2, err := Open(e.path, WithRecoveryCode(shown.RecoveryCode.Bytes()), Options{StateDir: e.stateDir})
	if err != nil {
		t.Fatalf("new recovery code: %v", err)
	}
	r2.Close()
	r3, err := Open(e.path, WithMachineKeys(shown.MachineKeys[0].Bytes()), Options{StateDir: e.stateDir})
	if err != nil {
		t.Fatalf("new machine key: %v", err)
	}
	r3.Close()
}

func TestRekeyKeepTokens(t *testing.T) {
	_, v := newEnv(t)
	mgr, err := v.Tokens(nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := mgr.Issue(context.Background(), token.IssueRequest{Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Rekey(RekeyOptions{
		Passphrase: []byte(testPass), Profile: ProfileInteractive, KeepTokens: true,
		Confirm: func(RekeyResult) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	m2, err := v.Tokens(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Verify(context.Background(), tok.Bytes()); err != nil {
		t.Errorf("token with KeepTokens: %v", err)
	}
}

// If the new credentials can't be confirmed, nothing changes.
func TestRekeyConfirmFailureChangesNothing(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "1")
	before, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("not saved")
	err = v.Rekey(RekeyOptions{Passphrase: []byte(testPass), Profile: ProfileInteractive, Confirm: func(RekeyResult) error { return stop }})
	if !errors.Is(err, stop) {
		t.Fatalf("err = %v", err)
	}
	after, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the file changed")
	}
	if get(t, v, "a") != "1" {
		t.Error("the open vault broke")
	}
	if err := v.Rekey(RekeyOptions{Passphrase: []byte(testPass)}); err == nil {
		t.Error("Rekey without Confirm accepted")
	}
}

func TestSlots(t *testing.T) {
	e, v := newEnv(t)
	if len(v.Slots()) != 2 {
		t.Fatalf("%v", v.Slots())
	}
	mk, err := v.AddMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := v.AddRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(mk.Bytes()), "goraz_mk_") || !strings.HasPrefix(string(rc.Bytes()), "GORAZ-RC-") {
		t.Error("wrong formats")
	}
	var machineID string
	for _, s := range v.Slots() {
		if s.Type == "machine" {
			machineID = s.ID
		}
	}
	if err := v.RemoveSlot(machineID); err != nil {
		t.Fatal(err)
	}
	if err := v.RemoveSlot("nope"); err == nil {
		t.Error("unknown slot removed")
	}
	if _, err := Open(e.path, WithMachineKeys(mk.Bytes()), Options{StateDir: e.stateDir}); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("removed slot: %v", err)
	}
	for _, s := range v.Slots()[1:] {
		if err := v.RemoveSlot(s.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.RemoveSlot(v.Slots()[0].ID); err == nil {
		t.Error("removed the last slot")
	}
}

func TestSlotLimit(t *testing.T) {
	_, v := newEnv(t)
	var err error
	for range format.MaxSlots {
		if _, err = v.AddMachineKey(); err != nil {
			break
		}
	}
	if err == nil {
		t.Error("slot limit not enforced")
	}
}

func TestAuditFailClosed(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "1")
	v.Close()
	r, err := e.open(t, Options{Audit: failSink{}})
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("open with a failing sink: %v, %v", r, err)
	}
	// Reads fail closed when the sink breaks after opening.
	s := &switchSink{}
	r, err = e.open(t, Options{Audit: s})
	if err != nil {
		t.Fatal(err)
	}
	s.fail = true
	if _, err := r.Get("a"); !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("read: %v", err)
	}
	if err := r.Put(&Item{Name: "b", Value: secret.New([]byte("x"))}); !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("write: %v", err)
	}
	s.fail = false
	if err := r.SetAuditRequired(false); err != nil {
		t.Fatal(err)
	}
	s.fail = true
	if get(t, r, "a") != "1" {
		t.Error("read should work with audit not required")
	}
	if r.AuditRequired() {
		t.Error("setting not stored")
	}
}

type failSink struct{}

func (failSink) Record(audit.Event) error { return errors.New("no") }

type switchSink struct {
	mu     sync.Mutex
	fail   bool
	events []audit.Event
}

func (s *switchSink) Record(e audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("no")
	}
	s.events = append(s.events, e)
	return nil
}

func TestAuditTruncationStopsReads(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "1")
	put(t, v, "b", "2")
	id := v.ID()
	device := v.device
	v.Close()
	p := filepath.Join(e.stateDir, "audit", fmt.Sprintf("%x", id[:]), device+".log")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.open(t, Options{}); !errors.Is(err, audit.ErrTruncated) {
		t.Fatalf("deleted log: %v", err)
	}
	r, err := e.open(t, Options{AcceptAuditGap: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Gap {
		t.Error("gap not recorded")
	}
}

func TestAuditRotateKeyAndHash(t *testing.T) {
	_, v := newEnv(t)
	put(t, v, "a", "1")
	h1, err := v.AuditHash("a")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RotateAuditKey(); err != nil {
		t.Fatal(err)
	}
	put(t, v, "a", "2")
	h2, err := v.AuditHash("a")
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Error("key rotation didn't change the hash")
	}
	if _, err := v.VerifyAudit(); err != nil {
		t.Errorf("chain across a key rotation: %v", err)
	}
	entries, err := v.ReadAudit()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range entries {
		if x.Object == h2 {
			found = true
		}
	}
	if !found {
		t.Error("audit hash doesn't match the log")
	}
}

// Canary: a known secret and name must never reach the log, in any encoding.
func TestAuditHasNoSecrets(t *testing.T) {
	e, v := newEnv(t)
	const value, name = "CANARYSECRETVALUE", "canaryitemname"
	put(t, v, name, value)
	get(t, v, name)
	_ = v.Delete(name)
	_ = v.Restore(name, 0)
	id := v.ID()
	files, err := filepath.Glob(filepath.Join(e.stateDir, "audit", fmt.Sprintf("%x", id[:]), "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("%v %v", files, err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- test path.
		if err != nil {
			t.Fatal(err)
		}
		assertNoCanary(t, f, b, value, name)
	}
	st, err := filepath.Glob(filepath.Join(e.stateDir, "vaults", "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range st {
		b, err := os.ReadFile(f) // #nosec G304 -- test path.
		if err != nil {
			t.Fatal(err)
		}
		assertNoCanary(t, f, b, value, name)
	}
}

func assertNoCanary(t *testing.T, where string, b []byte, canaries ...string) {
	t.Helper()
	for _, c := range canaries {
		for _, form := range encodings(c) {
			if bytes.Contains(b, []byte(form)) {
				t.Errorf("%s contains %q", where, form)
			}
		}
	}
}

func TestErrorsNeverContainValues(t *testing.T) {
	for _, err := range []error{
		ErrWrongCredential, ErrTampered, ErrRollback, ErrFork, ErrStateInvalid, ErrExpired, ErrNotFound,
		ErrExists, ErrChanged, ErrAuditUnavailable, ErrReadOnly, ErrNeedsRotation, ErrTooLarge, ErrClosed,
	} {
		if strings.Contains(err.Error(), "%") {
			t.Errorf("%v has a format verb", err)
		}
	}
}

func TestDecodeManifestRejects(t *testing.T) {
	bad := []string{
		"", "{}", "[]", "null", `{"unknown":1}`,
		`{"keys":{"state":"AA=="}}`,
	}
	for _, s := range bad {
		if _, err := decodeManifest([]byte(s)); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func FuzzDecodeManifest(f *testing.F) {
	f.Add([]byte(`{"items":[]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := decodeManifest(b)
		if err != nil {
			return
		}
		if len(m.Keys.State) != keyLength {
			t.Fatal("invalid manifest accepted")
		}
	})
}

func FuzzOpenReadOnly(f *testing.F) {
	// The golden file and key are the same in every fuzz worker process.
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		f.Fatal(err)
	}
	key, err := os.ReadFile(goldenKeyPath)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte{})
	f.Add([]byte(format.Magic))
	bad, err := filepath.Glob(filepath.Join(badDir, "*.goraz"))
	if err != nil {
		f.Fatal(err)
	}
	for _, p := range bad {
		b, err := os.ReadFile(p) // #nosec G304 -- test data.
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := openReadOnly(b, WithMachineKeys(key), Options{Audit: audit.Discard, Memory: NewMemoryState()})
		if err != nil {
			return
		}
		defer r.Close()
		for _, ver := range []uint32{0, 1, 2} {
			it, err := r.GetVersion("prod/db/password", ver)
			if err != nil {
				continue
			}
			if s := string(it.Value.Bytes()); s != "golden-value" && s != "first-value" {
				t.Fatalf("altered data returned: %q", s)
			}
		}
	})
}

// A valid sequence of writes must never leave a file that can't be opened.
func TestServiceLimitDoesNotBrickVault(t *testing.T) {
	e, v := newEnv(t)
	var err error
	for i := range maxServices + 1 {
		_, err = v.CreateService(fmt.Sprintf("s%d", i), filepath.Join(e.dir, "out"), ServiceOptions{Prefixes: []string{"x"}})
		if err != nil {
			break
		}
	}
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v", err)
	}
	v.Close()
	if _, err := e.open(t, Options{}); err != nil {
		t.Errorf("the vault can't be opened: %v", err)
	}
}

// A rollback override must not take effect if it can't be audited.
func TestOverrideNotPinnedWithoutAudit(t *testing.T) {
	e, v := newEnv(t)
	put(t, v, "a", "one")
	old, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	put(t, v, "a", "two")
	v.Close()
	if err := os.WriteFile(e.path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.open(t, Options{AcceptRollback: true, Audit: failSink{}}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if _, err := e.open(t, Options{}); !errors.Is(err, ErrRollback) {
		t.Errorf("the file became accepted with no audit entry: %v", err)
	}
}

func TestOpenServiceRefusesMainVault(t *testing.T) {
	e, v, key := machineVault(t)
	v.Close()
	data, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenService(data, WithMachineKeys(key), Options{Audit: audit.Discard}); !errors.Is(err, ErrNotServiceVault) {
		t.Errorf("err = %v", err)
	}
	if _, err := OpenService([]byte("junk"), WithMachineKeys(key), Options{Audit: audit.Discard}); !errors.Is(err, ErrNotVault) {
		t.Errorf("junk: %v", err)
	}
}

// With audit off and no sink, a read-only open must write nothing anywhere.
func TestReadOnlyWritesNoFiles(t *testing.T) {
	e, v, key := machineVault(t)
	if err := v.SetAuditRequired(false); err != nil {
		t.Fatal(err)
	}
	v.Close()
	data, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	wd := t.TempDir()
	t.Chdir(wd)
	r, err := openReadOnly(data, WithMachineKeys(key), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if get(t, r, "a") != "alpha" {
		t.Error("wrong value")
	}
	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("files written: %v", entries)
	}
}

func TestCloseWipesManifestKeys(t *testing.T) {
	e, v := newEnv(t)
	if _, err := v.CreateService("s", filepath.Join(e.dir, "out"), ServiceOptions{Prefixes: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	m := v.m
	state, machine := m.Keys.State, m.Services[0].MachineSecret
	kept := v.VerifierKeys()
	v.Close()
	if !bytes.Equal(state, make([]byte, keyLength)) || !bytes.Equal(machine, make([]byte, keyLength)) {
		t.Error("keys remain after Close")
	}
	if bytes.Equal(kept[0].Key, make([]byte, keyLength)) {
		t.Error("VerifierKeys must return copies")
	}
	cred := WithPassphrase([]byte("abc"), []byte("def"))
	cred.Wipe()
	if !bytes.Equal(cred.passphrase, make([]byte, 3)) || !bytes.Equal(cred.keyfile, make([]byte, 3)) {
		t.Error("credential not wiped")
	}
}

func TestConcurrentGuardAndCommitHasNoRace(t *testing.T) {
	_, v := newEnv(t)
	put(t, v, "a", "1")
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 20 {
			_ = v.ID()
			_, _ = v.Get("a")
		}
	})
	for range 5 {
		put(t, v, "a", "2")
	}
	wg.Wait()
}

func FuzzUnpad(f *testing.F) {
	f.Add(pad([]byte("value")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := unpad(b)
		if err != nil {
			return
		}
		if !bytes.Equal(pad(out), b) {
			t.Fatal("a non-canonical padding was accepted")
		}
	})
}
