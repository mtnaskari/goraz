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

// Argon2id vectors from the reference implementation's src/test.c (P-H-C/phc-winner-argon2).
func TestArgon2idReferenceVectors(t *testing.T) {
	cases := []struct {
		t, logM, p uint32
		pass, salt string
		want       string
	}{
		{2, 16, 1, "password", "somesalt", "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"},
		{2, 18, 1, "password", "somesalt", "78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c"},
		{2, 8, 1, "password", "somesalt", "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe"},
		{2, 8, 2, "password", "somesalt", "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037"},
		{1, 16, 1, "password", "somesalt", "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98"},
		{4, 16, 1, "password", "somesalt", "9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c"},
		{2, 16, 1, "differentpassword", "somesalt", "0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde"},
		{2, 16, 1, "password", "diffsalt", "bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c"},
	}
	for _, c := range cases {
		got := argon2.IDKey([]byte(c.pass), []byte(c.salt), c.t, 1<<c.logM, uint8(c.p), 32) // #nosec G115 -- small test values.
		if hex.EncodeToString(got) != c.want {
			t.Errorf("t=%d m=2^%d p=%d %s/%s: got %x", c.t, c.logM, c.p, c.pass, c.salt, got)
		}
	}
}
