package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testKeys() Keys {
	return Keys{Active: 1, All: map[uint32][]byte{1: bytes.Repeat([]byte{1}, 32)}}
}

func ev() Event {
	return Event{Type: EventItemRead, Outcome: OK, Actor: ActorPassphrase, Object: []byte{1, 2, 3}}
}

func newLog(t *testing.T) (*Log, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.log")
	return OpenLog(p, LogOptions{Keys: testKeys()}), p
}

func TestEventValidation(t *testing.T) {
	bad := []Event{
		{Type: "free form text", Outcome: OK, Actor: ActorSystem},
		{Type: EventItemRead, Outcome: "maybe", Actor: ActorSystem},
		{Type: EventItemRead, Outcome: OK, Actor: "bob"},
		{Type: EventItemRead, Outcome: OK, Actor: ActorSystem, Object: make([]byte, MaxObjectSize+1)},
	}
	for _, e := range bad {
		if e.Validate() == nil {
			t.Errorf("accepted %+v", e)
		}
		if Discard.Record(e) == nil {
			t.Errorf("Discard accepted %+v", e)
		}
	}
	if err := ev().Validate(); err != nil {
		t.Error(err)
	}
}

func TestEveryConstantIsKnown(t *testing.T) {
	for _, e := range []EventType{
		EventVaultCreate, EventVaultOpen, EventItemRead, EventItemWrite, EventItemDelete, EventItemDestroy,
		EventItemRestore, EventItemExport, EventSlotChange, EventRekey, EventSettingChange, EventRollbackAccept,
		EventForkAccept, EventTokenIssue, EventTokenVerify, EventTokenRevoke, EventTokenRotate, EventTokenStore, EventKeyRotate,
		EventServiceChange, EventAuditGap,
	} {
		if !knownEvents[e] {
			t.Errorf("%s isn't known", e)
		}
	}
}

func TestObjectHashHidesNames(t *testing.T) {
	k := bytes.Repeat([]byte{1}, 32)
	a := ObjectHash(k, "prod/db")
	if bytes.Contains(a, []byte("prod")) || len(a) != 32 {
		t.Error("bad hash")
	}
	if bytes.Equal(a, ObjectHash(bytes.Repeat([]byte{2}, 32), "prod/db")) {
		t.Error("key has no effect")
	}
}

func TestJSONSink(t *testing.T) {
	var b bytes.Buffer
	s := NewJSONSink(&b)
	if err := s.Record(ev()); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["event"] != "item.read" || got["object"] != "010203" {
		t.Errorf("%v", got)
	}
	if s.Record(Event{Type: "x"}) == nil {
		t.Error("invalid event accepted")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestJSONSinkFailureReturnsError(t *testing.T) {
	if NewJSONSink(failWriter{}).Record(ev()) == nil {
		t.Error("write failure hidden")
	}
}

func TestChainAppendVerify(t *testing.T) {
	l, p := newLog(t)
	for range 5 {
		if err := l.Record(ev()); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Verify(p, testKeys(), l.Head())
	if err != nil {
		t.Fatal(err)
	}
	if r.Entries != 5 || r.Head.Seq != 5 || r.Gap {
		t.Fatalf("%+v", r)
	}
	es, err := Read(p, testKeys(), Anchor{})
	if err != nil || len(es) != 5 || es[4].Type != EventItemRead {
		t.Fatalf("%v %v", es, err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
}

func TestEmptyLogVerifies(t *testing.T) {
	p := filepath.Join(t.TempDir(), "missing.log")
	if _, err := Verify(p, testKeys(), Anchor{}); err != nil {
		t.Error(err)
	}
	if _, err := Verify(p, testKeys(), Anchor{Seq: 3}); !errors.Is(err, ErrTruncated) {
		t.Errorf("deleted log: %v", err)
	}
}

func TestTamperDetection(t *testing.T) {
	l, p := newLog(t)
	for range 4 {
		if err := l.Record(ev()); err != nil {
			t.Fatal(err)
		}
	}
	orig, err := os.ReadFile(p) // #nosec G304 -- test path.
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(orig, []byte("\n"))
	lines = lines[:len(lines)-1]

	cases := map[string][]byte{
		"edited":      bytes.Replace(orig, []byte(`"outcome":"ok"`), []byte(`"outcome":"denied"`), 1),
		"middle gone": bytes.Join([][]byte{lines[0], lines[2], lines[3]}, nil),
		"first gone":  bytes.Join(lines[1:], nil),
		"reordered":   bytes.Join([][]byte{lines[1], lines[0], lines[2], lines[3]}, nil),
		"duplicated":  bytes.Join([][]byte{lines[0], lines[0], lines[1]}, nil),
		"no newline":  orig[:len(orig)-1],
		"extra field": bytes.Replace(orig, []byte(`{"seq":1`), []byte(`{"secret":"x","seq":1`), 1),
		"garbage":     []byte("hello\n"),
	}
	for name, data := range cases {
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(p, testKeys(), Anchor{}); !errors.Is(err, ErrTampered) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestTruncationDetectedAgainstAnchor(t *testing.T) {
	l, p := newLog(t)
	for range 4 {
		if err := l.Record(ev()); err != nil {
			t.Fatal(err)
		}
	}
	anchor := l.Head()
	orig, err := os.ReadFile(p) // #nosec G304 -- test path.
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(orig, []byte("\n"))
	if err := os.WriteFile(p, bytes.Join(lines[:2], nil), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(p, testKeys(), anchor); !errors.Is(err, ErrTruncated) {
		t.Errorf("err = %v", err)
	}
	// Appending must also refuse, so truncation is noticed without a manual check.
	l2 := OpenLog(p, LogOptions{Keys: testKeys(), Anchor: anchor})
	if err := l2.Record(ev()); !errors.Is(err, ErrTruncated) {
		t.Errorf("append over truncated log: %v", err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := l2.Record(ev()); !errors.Is(err, ErrTruncated) {
		t.Errorf("append over deleted log: %v", err)
	}
}

func TestWrongAnchorMAC(t *testing.T) {
	l, p := newLog(t)
	if err := l.Record(ev()); err != nil {
		t.Fatal(err)
	}
	a := l.Head()
	a.MAC = bytes.Repeat([]byte{9}, 32)
	if _, err := Verify(p, testKeys(), a); !errors.Is(err, ErrTampered) {
		t.Errorf("err = %v", err)
	}
}

func TestAcceptGap(t *testing.T) {
	l, p := newLog(t)
	for range 3 {
		if err := l.Record(ev()); err != nil {
			t.Fatal(err)
		}
	}
	anchor := l.Head()
	if err := os.WriteFile(p, []byte("destroyed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l2 := OpenLog(p, LogOptions{Keys: testKeys(), Anchor: anchor, AcceptGap: true})
	if err := l2.Record(ev()); err != nil {
		t.Fatal(err)
	}
	r, err := Verify(p, testKeys(), anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Gap || r.Entries != 2 || r.FirstSeq != anchor.Seq+1 {
		t.Fatalf("%+v", r)
	}
	matches, _ := filepath.Glob(p + ".damaged-*")
	if len(matches) != 1 {
		t.Errorf("damaged copy not kept: %v", matches)
	}
	if err := l2.Record(ev()); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(p, testKeys(), l2.Head()); err != nil {
		t.Fatal(err)
	}
}

func TestKeyRotationAndRetiredKeyForgery(t *testing.T) {
	keys := Keys{Active: 1, All: map[uint32][]byte{1: bytes.Repeat([]byte{1}, 32)}}
	p := filepath.Join(t.TempDir(), "x.log")
	l := OpenLog(p, LogOptions{Keys: keys})
	if err := l.Record(ev()); err != nil {
		t.Fatal(err)
	}
	rotated := Keys{Active: 2, All: map[uint32][]byte{1: keys.All[1], 2: bytes.Repeat([]byte{2}, 32)}}
	l.SetKeys(rotated)
	if err := l.Record(ev()); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(p, rotated, l.Head()); err != nil {
		t.Fatal(err)
	}
	// An ex-holder of key 1 appends an entry after the rotation.
	forger := OpenLog(p, LogOptions{Keys: Keys{Active: 1, All: rotated.All}, Anchor: l.Head()})
	if err := forger.Record(ev()); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(p, rotated, Anchor{}); !errors.Is(err, ErrTampered) {
		t.Errorf("retired key accepted after rotation: %v", err)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	l, p := newLog(t)
	if err := l.Record(ev()); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(p, Keys{Active: 9, All: map[uint32][]byte{9: make([]byte, 32)}}, Anchor{}); !errors.Is(err, ErrTampered) {
		t.Errorf("err = %v", err)
	}
}

func TestConcurrentAppendsKeepValidChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.log")
	var wg sync.WaitGroup
	const writers, each = 6, 10
	// Separate Log values simulate separate processes.
	for range writers {
		wg.Go(func() {
			l := OpenLog(p, LogOptions{Keys: testKeys()})
			for range each {
				if err := l.Record(ev()); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
	r, err := Verify(p, testKeys(), Anchor{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Entries != writers*each {
		t.Fatalf("entries = %d", r.Entries)
	}
}

func TestGuardBlocksAppend(t *testing.T) {
	l, p := newLog(t)
	stop := errors.New("vault changed")
	l.Guard = func() error { return stop }
	if err := l.Record(ev()); !errors.Is(err, stop) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("entry written despite the guard")
	}
}

func TestGuardRunsBeforeVerification(t *testing.T) {
	l, p := newLog(t)
	if err := l.Record(ev()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("damaged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("vault changed")
	l.Guard = func() error { return stop }
	if err := l.Record(ev()); !errors.Is(err, stop) {
		t.Errorf("err = %v", err)
	}
}

// A crash during an append must not look like tampering.
func TestTornLastLineIsRepaired(t *testing.T) {
	l, p := newLog(t)
	for range 3 {
		if err := l.Record(ev()); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- test path.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"seq":4,"ts":1`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(ev()); err != nil {
		t.Fatalf("append after a torn line: %v", err)
	}
	r, err := Verify(p, testKeys(), l.Head())
	if err != nil {
		t.Fatal(err)
	}
	if r.Entries != 4 || r.Gap {
		t.Errorf("%+v", r)
	}
}

func TestTruncationInsideALineStillCaught(t *testing.T) {
	l, p := newLog(t)
	for range 3 {
		if err := l.Record(ev()); err != nil {
			t.Fatal(err)
		}
	}
	anchor := l.Head()
	b, err := os.ReadFile(p) // #nosec G304 -- test path.
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b[:len(b)-5], 0o600); err != nil {
		t.Fatal(err)
	}
	l2 := OpenLog(p, LogOptions{Keys: testKeys(), Anchor: anchor})
	if err := l2.Record(ev()); !errors.Is(err, ErrTruncated) {
		t.Errorf("err = %v", err)
	}
}

func TestUnwritableIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	l := OpenLog(filepath.Join(dir, "x.log"), LogOptions{Keys: testKeys()})
	if err := l.Record(ev()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v", err)
	}
}

func TestLogRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "x.log")
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	l := OpenLog(p, LogOptions{Keys: testKeys()})
	if l.Record(ev()) == nil {
		t.Error("followed a symlink")
	}
}

func TestLogContainsNoNames(t *testing.T) {
	l, p := newLog(t)
	e := ev()
	e.Object = ObjectHash(bytes.Repeat([]byte{1}, 32), "prod/db/password")
	if err := l.Record(e); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p) // #nosec G304 -- test path.
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "prod") {
		t.Error("name reached the log")
	}
}

func FuzzVerifyBytes(f *testing.F) {
	l := OpenLog(filepath.Join(f.TempDir(), "x.log"), LogOptions{Keys: testKeys()})
	if err := l.Record(ev()); err != nil {
		f.Fatal(err)
	}
	b, err := os.ReadFile(l.path)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte("{}\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, _, err := verifyBytes(data, testKeys())
		if err == nil && len(data) > 0 && !bytes.HasPrefix(data, b[:len(b)-1]) && !bytes.Contains(data, []byte("mac")) {
			t.Fatalf("accepted %q (%+v)", data, r)
		}
	})
}
