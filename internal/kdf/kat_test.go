package kdf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Frozen outputs of goraz's own derivations. A change to any of them makes every
// existing vault unreadable, so a refactor that changes one must fail here.
func TestDerivationKnownAnswers(t *testing.T) {
	id := bytes.Repeat([]byte{0x01}, 16)
	salt := bytes.Repeat([]byte{0x02}, SaltSize)
	key32 := bytes.Repeat([]byte{0x03}, 32)
	keyfile := bytes.Repeat([]byte{0x04}, KeyfileSize)

	pass, err := PassphraseKey([]byte("café passphrase"), nil, salt, id, Interactive.Params)
	if err != nil {
		t.Fatal(err)
	}
	// The decomposed form of the same text must give the same key.
	passNFD, err := PassphraseKey([]byte("café passphrase"), nil, salt, id, Interactive.Params)
	if err != nil {
		t.Fatal(err)
	}
	withFile, err := PassphraseKey([]byte("café passphrase"), keyfile, salt, id, Interactive.Params)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := RecoveryKey(key32, id)
	if err != nil {
		t.Fatal(err)
	}
	mach, err := MachineKey(key32, id)
	if err != nil {
		t.Fatal(err)
	}
	man, err := Subkey(key32, id, LabelManifest)
	if err != nil {
		t.Fatal(err)
	}
	item, err := Subkey(key32, id, LabelItem)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"passphrase", pass, "7a1520e3769d2ff6183161124b14b8357a7363f93b962bdc5f2a148d3c503176"},
		{"passphrase NFD", passNFD, "7a1520e3769d2ff6183161124b14b8357a7363f93b962bdc5f2a148d3c503176"},
		{"passphrase and key file", withFile, "90a48b4348a512c34df1d49537dedbd4d8fe178b19df87bea3a62c446e691f9c"},
		{"recovery", rec, "4e7c167f351444632c9c3cbd7c9f72d6b47d1bbfe0fad4514050387f5519afef"},
		{"machine", mach, "b80846d71731ff38dd371c2919e7935d7fba9b3a7b65a5aa07964b8c5f9fbaae"},
		{"manifest subkey", man, "487d1f2d9497702af15c695fc63df9da93f96f9687fb814b6b54c8fc902300dd"},
		{"item subkey", item, "c664aebc49c72bd78e9eb73f7da8cf43ba00e23d0545dce561e55d23fb7c1898"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(c.got); got != c.want {
			t.Errorf("%s: got %s", c.name, got)
		}
	}
}
