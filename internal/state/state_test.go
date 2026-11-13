package state

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func h(b byte) [32]byte { return [32]byte{b} }

func l(gen uint64, b byte) Lineage {
	x := h(b)
	return Lineage{Generation: gen, SHA256: x[:]}
}

// One case per row of the table in docs/security-design.md, section 7.
func TestDecide(t *testing.T) {
	pinned := &Record{High: 5, PinnedGen: 5, PinnedHash: h(5)}
	cases := []struct {
		name    string
		rec     *Record
		gen     uint64
		hash    [32]byte
		lineage []Lineage
		want    Decision
	}{
		{"first use", nil, 9, h(9), nil, Accept},
		{"same file", pinned, 5, h(5), nil, Accept},
		{"next generation", pinned, 6, h(6), []Lineage{l(5, 5)}, Accept},
		{"jump within window", pinned, 8, h(8), []Lineage{l(5, 5), l(6, 6), l(7, 7)}, Accept},
		{"lineage disagrees", pinned, 6, h(6), []Lineage{l(5, 99)}, Fork},
		{"history replaced at a jump", pinned, 8, h(8), []Lineage{l(5, 99), l(6, 6), l(7, 7)}, Fork},
		{"beyond lineage window", pinned, 100, h(100), []Lineage{l(68, 68), l(99, 99)}, AcceptUnverified},
		{"same generation, different hash", pinned, 5, h(77), []Lineage{l(4, 4)}, Fork},
		{"older generation", pinned, 4, h(4), []Lineage{l(3, 3)}, Rollback},
		{"newer without lineage", pinned, 6, h(6), nil, Fork},
		{"gap inside the window", pinned, 8, h(8), []Lineage{l(3, 3), l(7, 7)}, Fork},
		{
			"accepted rollback stays accepted",
			&Record{High: 10, PinnedGen: 5, PinnedHash: h(5)}, 5, h(5), nil, Accept,
		},
		{
			"another older file after accepted rollback",
			&Record{High: 10, PinnedGen: 5, PinnedHash: h(5)}, 7, h(7), []Lineage{l(5, 5)}, Rollback,
		},
		// A device whose generation isn't in the lineage must see a fork, so that its
		// writes aren't lost silently.
		{
			"device left behind by an accepted rollback",
			&Record{High: 10, PinnedGen: 10, PinnedHash: h(10)}, 11, h(11), []Lineage{l(4, 4), l(5, 5)}, Fork,
		},
	}
	for _, c := range cases {
		if got := Decide(c.rec, c.gen, c.hash, c.lineage); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func stores(t *testing.T) map[string]Store {
	return map[string]Store{"file": &File{Dir: t.TempDir()}, "memory": NewMemory()}
}

func TestStorePinAndHighNeverLowers(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	id := [16]byte{9}
	for name, s := range stores(t) {
		r, err := s.Load(id, key)
		if err != nil || r != nil {
			t.Fatalf("%s: empty load: %v %v", name, r, err)
		}
		if _, err := s.Pin(id, key, 10, h(10)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Pin(id, key, 4, h(4)); err != nil {
			t.Fatal(err)
		}
		r, err = s.Load(id, key)
		if err != nil {
			t.Fatal(err)
		}
		if r.High != 10 || r.PinnedGen != 4 || r.PinnedHash != h(4) {
			t.Errorf("%s: %+v", name, r)
		}
		if err := s.Reset(id); err != nil {
			t.Fatal(err)
		}
		if r, _ := s.Load(id, key); r != nil {
			t.Errorf("%s: reset kept the record", name)
		}
		if err := s.Reset(id); err != nil {
			t.Errorf("%s: second reset: %v", name, err)
		}
	}
}

func TestFileDeviceIDIsStable(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	s := &File{Dir: t.TempDir()}
	a, err := s.Pin([16]byte{1}, key, 1, h(1))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Pin([16]byte{1}, key, 2, h(2))
	if err != nil {
		t.Fatal(err)
	}
	if a.DeviceID != b.DeviceID || a.DeviceID == ([16]byte{}) {
		t.Error("device ID changed or empty")
	}
}

func TestFileTamperDetected(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	id := [16]byte{3}
	s := &File{Dir: t.TempDir()}
	if _, err := s.Pin(id, key, 10, h(10)); err != nil {
		t.Fatal(err)
	}
	p := s.path(id)
	orig, err := os.ReadFile(p) // #nosec G304 -- test path.
	if err != nil {
		t.Fatal(err)
	}

	// Lowering the recorded generation would hide a rollback.
	lowered := bytes.Replace(orig, []byte(`"high":10`), []byte(`"high":1`), 1)
	if err := os.WriteFile(p, lowered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(id, key); !errors.Is(err, ErrInvalid) {
		t.Errorf("lowered high: %v", err)
	}
	if _, err := s.Pin(id, key, 11, h(11)); !errors.Is(err, ErrInvalid) {
		t.Errorf("pin over a tampered file: %v", err)
	}

	if err := os.WriteFile(p, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(id, bytes.Repeat([]byte{2}, 32)); !errors.Is(err, ErrInvalid) {
		t.Errorf("wrong key: %v", err)
	}
	if err := os.WriteFile(p, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(id, key); !errors.Is(err, ErrInvalid) {
		t.Errorf("garbage: %v", err)
	}
}

func TestFileRefusesSymlink(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	id := [16]byte{4}
	dir := t.TempDir()
	s := &File{Dir: dir}
	if _, err := s.Pin(id, key, 1, h(1)); err != nil {
		t.Fatal(err)
	}
	p := s.path(id)
	if err := os.Rename(p, filepath.Join(dir, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(id, key); err == nil {
		t.Error("followed a symlink")
	}
}

func TestConcurrentPinsKeepHighest(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	id := [16]byte{5}
	s := &File{Dir: t.TempDir()}
	var wg sync.WaitGroup
	for g := uint64(1); g <= 20; g++ {
		wg.Go(func() {
			if _, err := s.Pin(id, key, g, h(byte(g))); err != nil { // #nosec G115 -- small test value.
				t.Error(err)
			}
		})
	}
	wg.Wait()
	r, err := s.Load(id, key)
	if err != nil {
		t.Fatal(err)
	}
	if r.High != 20 {
		t.Errorf("high = %d", r.High)
	}
}

func FuzzParseRecord(f *testing.F) {
	key := bytes.Repeat([]byte{1}, 32)
	s := &File{Dir: f.TempDir()}
	if _, err := s.Pin([16]byte{1}, key, 3, h(3)); err != nil {
		f.Fatal(err)
	}
	good, err := os.ReadFile(s.path([16]byte{1})) // #nosec G304 -- test path.
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseRecord(b, [16]byte{1}, key)
		if err == nil && !bytes.Equal(b, good) && r.High != 3 {
			t.Fatalf("a forged record was accepted: %+v", r)
		}
	})
}

// Whatever the inputs, a file older than the highest generation seen is never
// accepted unless it is exactly the pinned file.
func FuzzDecide(f *testing.F) {
	f.Add(uint64(5), uint64(5), byte(5), uint64(6), byte(6), uint64(5), byte(5))
	f.Fuzz(func(t *testing.T, high, pinGen uint64, pinHash byte, gen uint64, hash byte, linGen uint64, linHash byte) {
		if pinGen > high {
			pinGen = high
		}
		r := &Record{High: high, PinnedGen: pinGen, PinnedHash: h(pinHash)}
		d := Decide(r, gen, h(hash), []Lineage{l(linGen, linHash)})
		if gen < high && hash != pinHash && d != Rollback {
			t.Fatalf("older file not refused: %d", d)
		}
		if gen == pinGen && hash != pinHash && gen >= high && d == Accept {
			t.Fatal("a different file at the pinned generation was accepted")
		}
	})
}
