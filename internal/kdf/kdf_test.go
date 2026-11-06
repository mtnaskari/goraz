package kdf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/argon2"
)

// Reference-implementation vector, as used by x/crypto's own tests. The
// x/crypto API can't express RFC 9106's secret and associated data inputs.
func TestArgon2idKnownAnswer(t *testing.T) {
	got := argon2.IDKey([]byte("password"), []byte("somesalt"), 1, 64, 1, 24)
	if hex.EncodeToString(got) != "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb" {
		t.Fatalf("got %x", got)
	}
}

func TestAllowlistIsExact(t *testing.T) {
	bad := []Params{
		{},
		{MemoryKiB: 1, Time: 1, Threads: 1},
		{MemoryKiB: 64 * 1024, Time: 2, Threads: 4},
		{MemoryKiB: 64*1024 - 1, Time: 3, Threads: 4},
		{MemoryKiB: 64 * 1024, Time: 3, Threads: 1},
		{MemoryKiB: 4 * 1024 * 1024, Time: 3, Threads: 4},
		{MemoryKiB: 0xffffffff, Time: 0xffffffff, Threads: 255},
		{MemoryKiB: 64 * 1024, Time: 0, Threads: 4},
		{MemoryKiB: 64 * 1024, Time: 3, Threads: 0},
	}
	salt := make([]byte, SaltSize)
	for _, p := range bad {
		if Allowed(p) {
			t.Errorf("%+v allowed", p)
		}
		if _, err := PassphraseKey([]byte("x"), nil, salt, salt, p); !errors.Is(err, ErrParams) {
			t.Errorf("%+v: err = %v", p, err)
		}
	}
	for _, p := range Profiles() {
		if !Allowed(p.Params) {
			t.Errorf("%s not allowed", p.Name)
		}
	}
}

func TestProfilesMatchRFC9106(t *testing.T) {
	if Interactive.Params != (Params{65536, 3, 4}) {
		t.Error("interactive no longer matches RFC 9106's second recommendation")
	}
	if Max.Params != (Params{2097152, 1, 4}) {
		t.Error("max no longer matches RFC 9106's first recommendation")
	}
	if Default != Strong {
		t.Error("default profile changed")
	}
}

func TestPassphraseKeyProperties(t *testing.T) {
	id := bytes.Repeat([]byte{1}, 16)
	salt := bytes.Repeat([]byte{2}, SaltSize)
	kf := bytes.Repeat([]byte{3}, KeyfileSize)
	p := Interactive.Params

	base, err := PassphraseKey([]byte("passphrase"), nil, salt, id, p)
	if err != nil {
		t.Fatal(err)
	}
	withFile, err := PassphraseKey([]byte("passphrase"), kf, salt, id, p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base, withFile) {
		t.Error("key file had no effect")
	}
	otherVault, err := PassphraseKey([]byte("passphrase"), nil, salt, bytes.Repeat([]byte{9}, 16), p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base, otherVault) {
		t.Error("vault ID had no effect")
	}
	// "é" as one code point and as e + combining accent must give the same key.
	a, err := PassphraseKey([]byte("café"), nil, salt, id, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PassphraseKey([]byte("café"), nil, salt, id, p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("NFC normalization missing")
	}
}

// Clearing the normalized copy must never wipe the caller's passphrase.
func TestPassphraseKeyLeavesInputIntact(t *testing.T) {
	id := make([]byte, 16)
	salt := make([]byte, SaltSize)
	in := []byte("already-normal passphrase")
	want := bytes.Clone(in)
	if _, err := PassphraseKey(in, nil, salt, id, Interactive.Params); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in, want) {
		t.Fatal("the caller's passphrase was modified")
	}
	if n := Normalize(in); &n[0] == &in[0] {
		t.Fatal("Normalize returned its input")
	}
}

func TestPassphraseKeyRejectsBadInput(t *testing.T) {
	id := make([]byte, 16)
	salt := make([]byte, SaltSize)
	p := Interactive.Params
	if _, err := PassphraseKey(nil, nil, salt, id, p); err == nil {
		t.Error("empty passphrase accepted")
	}
	if _, err := PassphraseKey(make([]byte, MaxPassphraseBytes+1), nil, salt, id, p); err == nil {
		t.Error("oversized passphrase accepted")
	}
	if _, err := PassphraseKey([]byte("x"), make([]byte, 31), salt, id, p); err == nil {
		t.Error("short key file accepted")
	}
	if _, err := PassphraseKey([]byte("x"), nil, salt[:15], id, p); err == nil {
		t.Error("short salt accepted")
	}
}

func TestHighEntropyKeysAreSeparated(t *testing.T) {
	id := bytes.Repeat([]byte{1}, 16)
	k := bytes.Repeat([]byte{2}, 32)
	a, err := RecoveryKey(k, id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MachineKey(k, id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("recovery and machine keys are not separated")
	}
	m, _ := Subkey(k, id, LabelManifest)
	i, _ := Subkey(k, id, LabelItem)
	if bytes.Equal(m, i) {
		t.Error("subkeys are not separated")
	}
	if _, err := RecoveryKey(k[:31], id); err == nil {
		t.Error("short code accepted")
	}
	if _, err := MachineKey(k[:31], id); err == nil {
		t.Error("short key accepted")
	}
}

func TestProfileByName(t *testing.T) {
	if _, err := ProfileByName("nope"); err == nil {
		t.Error("unknown profile accepted")
	}
	if p, err := ProfileByName("strong"); err != nil || p != Strong {
		t.Error("strong not found")
	}
}
