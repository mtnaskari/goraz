package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/format"
	"github.com/mtnaskari/goraz/internal/kdf"
)

var updateBad = flag.Bool("update-bad", false, "rewrite the bad file corpus")

const badDir = "testdata/bad"

// Each bad file is a damaged copy of the golden vault. Its .expect file names the
// error it must cause, as "open: ErrX" or "get: ErrX" when the file opens but the
// item read must fail. The files also seed FuzzOpenReadOnly.
var badErrors = map[string]error{
	"ErrNotVault":        ErrNotVault,
	"ErrTampered":        ErrTampered,
	"ErrWrongCredential": ErrWrongCredential,
}

func makeBadFiles(t *testing.T, golden []byte) map[string][2]string {
	t.Helper()
	h, n, err := format.Parse(golden)
	if err != nil {
		t.Fatal(err)
	}
	slotStart := len(format.Magic) + format.IDSize + 8 + 1
	passMem := slotStart + 1 + format.IDSize + kdf.SaltSize
	var machine int
	off := slotStart
	for _, s := range h.Slots {
		if s.Type == format.SlotMachine {
			machine = off
		}
		if s.Type == format.SlotPassphrase {
			off += 147
		} else {
			off += 121
		}
	}
	flip := func(i int) []byte {
		b := bytes.Clone(golden)
		b[i] ^= 0x01
		return b
	}
	out := map[string][2]string{}
	add := func(name, expect string, data []byte) {
		out[name] = [2]string{expect, string(data)}
	}
	add("empty", "open: ErrNotVault", nil)
	add("not-a-vault", "open: ErrNotVault", []byte("this is a text file, not a vault\n"))
	v2 := bytes.Clone(golden)
	v2[6] = '2'
	add("newer-version", "open: ErrNotVault", v2)
	add("truncated-header", "open: ErrTampered", golden[:slotStart+10])
	add("truncated-body", "open: ErrTampered", golden[:len(golden)-1])
	add("trailing-byte", "open: ErrTampered", append(bytes.Clone(golden), 0))
	gen := bytes.Clone(golden)
	binary.BigEndian.PutUint64(gen[len(format.Magic)+format.IDSize:], h.Generation+1)
	add("generation-changed", "open: ErrTampered", gen)
	weak := bytes.Clone(golden)
	binary.BigEndian.PutUint32(weak[passMem:], 8)
	add("kdf-downgraded", "open: ErrTampered", weak)
	unknown := bytes.Clone(golden)
	unknown[slotStart] = 0x7f
	add("unknown-slot-type", "open: ErrTampered", unknown)
	add("machine-slot-damaged", "open: ErrWrongCredential", flip(machine+1+format.IDSize+10))
	add("vault-id-changed", "open: ErrWrongCredential", flip(len(format.Magic)))
	add("manifest-damaged", "open: ErrTampered", flip(n+int(h.ManifestLen)/2))
	add("item-damaged", "get: ErrTampered", flip(len(golden)-5))
	return out
}

func TestBadFiles(t *testing.T) {
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(goldenKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if *updateBad {
		if err := os.MkdirAll(badDir, 0o750); err != nil {
			t.Fatal(err)
		}
		for name, f := range makeBadFiles(t, golden) {
			if err := os.WriteFile(filepath.Join(badDir, name+".goraz"), []byte(f[1]), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(badDir, name+".expect"), []byte(f[0]+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	files, err := filepath.Glob(filepath.Join(badDir, "*.goraz"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	if len(files) < 13 {
		t.Fatalf("only %d bad files", len(files))
	}
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- test data.
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(strings.TrimSuffix(f, ".goraz") + ".expect") // #nosec G304 -- test data.
		if err != nil {
			t.Fatal(err)
		}
		stage, name, ok := strings.Cut(strings.TrimSpace(string(raw)), ": ")
		want, known := badErrors[name]
		if !ok || !known {
			t.Fatalf("%s: bad expectation %q", f, raw)
		}
		v, err := openReadOnly(data, WithMachineKeys(key), Options{Audit: audit.Discard})
		if stage == "open" {
			if !errors.Is(err, want) {
				t.Errorf("%s: open error %v, want %v", filepath.Base(f), err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: open failed: %v", filepath.Base(f), err)
			continue
		}
		if _, err := v.Get("prod/db/password"); !errors.Is(err, want) {
			t.Errorf("%s: get error %v, want %v", filepath.Base(f), err, want)
		}
		v.Close()
	}
}
