package format

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/mtnaskari/goraz/internal/envelope"
	"github.com/mtnaskari/goraz/internal/kdf"
)

func sample() *Header {
	h := &Header{Generation: 7, ManifestLen: envelope.Overhead + 10}
	copy(h.VaultID[:], bytes.Repeat([]byte{0xaa}, IDSize))
	p := Slot{Type: SlotPassphrase, Params: kdf.Interactive.Params, HasKeyfile: true, Blob: make([]byte, SlotBlobSize)}
	p.ID[0] = 1
	p.Salt[0] = 2
	r := Slot{Type: SlotRecovery, Blob: bytes.Repeat([]byte{3}, SlotBlobSize)}
	r.ID[0] = 4
	m := Slot{Type: SlotMachine, Blob: bytes.Repeat([]byte{5}, SlotBlobSize)}
	m.ID[0] = 6
	h.Slots = []Slot{p, r, m}
	return h
}

func file(t testing.TB, h *Header) []byte {
	t.Helper()
	b, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return append(b, make([]byte, h.ManifestLen)...)
}

func TestRoundTrip(t *testing.T) {
	h := sample()
	b := file(t, h)
	got, n, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(b)-int(h.ManifestLen) {
		t.Fatalf("header length %d", n)
	}
	if got.VaultID != h.VaultID || got.Generation != 7 || len(got.Slots) != 3 {
		t.Fatalf("mismatch: %+v", got)
	}
	re, err := got.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(re, b[:n]) {
		t.Fatal("parse and marshal are not inverse")
	}
}

func TestDocumentedSizes(t *testing.T) {
	if SlotBlobSize != 104 {
		t.Errorf("blob size %d", SlotBlobSize)
	}
	if passphraseFixed+SlotBlobSize != 147 {
		t.Errorf("passphrase slot %d", passphraseFixed+SlotBlobSize)
	}
	if otherFixed+SlotBlobSize != 121 {
		t.Errorf("other slot %d", otherFixed+SlotBlobSize)
	}
}

func TestRejections(t *testing.T) {
	base := file(t, sample())
	slotStart := len(Magic) + IDSize + 8 + 1
	mem := slotStart + 1 + IDSize + kdf.SaltSize

	mutate := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(base)) }
	cases := map[string][]byte{
		"empty":      {},
		"bad magic":  mutate(func(b []byte) []byte { b[0] = 'X'; return b }),
		"v2 magic":   mutate(func(b []byte) []byte { b[6] = '2'; return b }),
		"zero slots": mutate(func(b []byte) []byte { b[slotStart-1] = 0; return b }),
		"too many":   mutate(func(b []byte) []byte { b[slotStart-1] = MaxSlots + 1; return b }),
		"unknown slot type": mutate(func(b []byte) []byte {
			b[slotStart] = 0x09
			return b
		}),
		"weak KDF": mutate(func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[mem:], 1)
			return b
		}),
		"huge KDF": mutate(func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[mem:], 0xffffffff)
			return b
		}),
		"bad keyfile flag": mutate(func(b []byte) []byte {
			b[mem+9] = 2
			return b
		}),
		"truncated manifest": base[:len(base)-1],
		"truncated in slot":  base[:slotStart+5],
	}
	for name, b := range cases {
		if _, _, err := Parse(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestRejectsTwoPassphraseSlots(t *testing.T) {
	h := sample()
	dup := h.Slots[0]
	dup.ID[0] = 99
	h.Slots = append(h.Slots, dup)
	if _, err := h.Marshal(); err == nil {
		t.Error("Marshal accepted two passphrase slots")
	}
	// Build the same thing by hand, as an attacker would.
	good := sample()
	raw, err := good.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	prefix := len(Magic) + IDSize + 8
	raw[prefix] = 4
	tail := raw[len(raw)-4:]
	body := append(bytes.Clone(raw[:len(raw)-4]), dup.fixedBytes()...)
	body = append(body, dup.Blob...)
	body = append(body, tail...)
	body = append(body, make([]byte, good.ManifestLen)...)
	if _, _, err := Parse(body); !errors.Is(err, ErrFormat) {
		t.Errorf("Parse accepted two passphrase slots: %v", err)
	}
}

func TestRejectsDuplicateSlotID(t *testing.T) {
	h := sample()
	h.Slots[2].ID = h.Slots[1].ID
	b := file(t, h)
	if _, _, err := Parse(b); !errors.Is(err, ErrFormat) {
		t.Errorf("err = %v", err)
	}
}

func TestManifestLenBounds(t *testing.T) {
	for _, n := range []uint32{0, envelope.Overhead - 1, MaxManifestSize + 1, 0xffffffff} {
		h := sample()
		raw, err := h.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint32(raw[len(raw)-4:], n)
		raw = append(raw, make([]byte, 200)...)
		if _, _, err := Parse(raw); !errors.Is(err, ErrFormat) {
			t.Errorf("len %d: err = %v", n, err)
		}
	}
}

func TestContextBindsVaultAndFields(t *testing.T) {
	h := sample()
	s := h.Slots[0]
	a := s.Context(h.VaultID)
	other := h.VaultID
	other[0] ^= 1
	if bytes.Equal(a, s.Context(other)) {
		t.Error("context doesn't bind vault ID")
	}
	s2 := s
	s2.Params = kdf.Standard.Params
	if bytes.Equal(a, s2.Context(h.VaultID)) {
		t.Error("context doesn't bind KDF parameters")
	}
	s3 := s
	s3.HasKeyfile = false
	if bytes.Equal(a, s3.Context(h.VaultID)) {
		t.Error("context doesn't bind the key file flag")
	}
	// Context must not modify the caller's vault ID through aliasing.
	before := h.VaultID
	_ = s.Context(h.VaultID)
	if before != h.VaultID {
		t.Error("Context modified vault ID")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(file(f, sample()))
	f.Add([]byte(Magic))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, n, err := Parse(b)
		if err != nil {
			if h != nil {
				t.Fatal("header returned with an error")
			}
			return
		}
		passphrases := 0
		for _, s := range h.Slots {
			if s.Type == SlotPassphrase {
				passphrases++
				if !kdf.Allowed(s.Params) {
					t.Fatal("disallowed KDF parameters passed the parser")
				}
			}
		}
		if passphrases > 1 {
			t.Fatal("two passphrase slots passed the parser")
		}
		// Anything that parses must re-encode to the same bytes.
		re, err := h.Marshal()
		if err != nil {
			t.Fatalf("accepted header can't be written: %v", err)
		}
		if !bytes.Equal(re, b[:n]) {
			t.Fatal("non-canonical header accepted")
		}
	})
}
