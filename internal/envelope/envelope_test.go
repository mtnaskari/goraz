package envelope

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 5869, appendix A, test case 1.
func TestHKDFKnownAnswer(t *testing.T) {
	ikm := unhex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := unhex(t, "000102030405060708090a0b0c")
	info := unhex(t, "f0f1f2f3f4f5f6f7f8f9")
	want := unhex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	got, err := hkdf.Key(sha256.New, ikm, salt, string(info), 42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x", got)
	}
}

// draft-irtf-cfrg-xchacha-03, appendix A.3.1.
func TestXChaChaKnownAnswer(t *testing.T) {
	key := unhex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := unhex(t, "404142434445464748494a4b4c4d4e4f5051525354555657")
	ad := unhex(t, "50515253c0c1c2c3c4c5c6c7")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	want := unhex(t, "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"+
		"731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"+
		"2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"+
		"21f9664c97637da9768812f615c68b13b52e"+"c0875924c1c7987947deafd8780acf49")
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	if got := aead.Seal(nil, nonce, pt, ad); !bytes.Equal(got, want) {
		t.Fatalf("got %x", got)
	}
}

// Golden vector for the envelope itself. If this fails, the format has changed
// and every existing vault would be unreadable.
func TestEnvelopeGoldenVector(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, KeySize)
	nonce := bytes.Repeat([]byte{0x24}, NonceSize)
	blob, err := seal(key, nonce, DomainItem, []byte("context"), []byte("plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(blob)
	const wantBlob = "2424242424242424242424242424242424242424242424244bb0326b4ecfd3bfd51ed0fa4eba9c4faaf9070192d64cb09b7816a47a54f398ac6ccd1faa51291b68977ae4a1d2ca3b7ee9f8bccfbc7a514f"
	if got != wantBlob {
		t.Fatalf("envelope format changed:\n got %s\nwant %s", got, wantBlob)
	}
}

func TestRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{1}, KeySize)
	for _, pt := range [][]byte{nil, {}, []byte("x"), bytes.Repeat([]byte("y"), 70000)} {
		blob, err := Seal(key, DomainItem, []byte("ctx"), pt)
		if err != nil {
			t.Fatal(err)
		}
		if len(blob) != len(pt)+Overhead {
			t.Fatalf("overhead: got %d", len(blob)-len(pt))
		}
		got, err := Open(key, DomainItem, []byte("ctx"), blob)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatal("round trip mismatch")
		}
	}
}

func TestSealRejectsBadKey(t *testing.T) {
	if _, err := Seal(make([]byte, 16), DomainItem, nil, nil); err == nil {
		t.Error("short key accepted")
	}
}

func TestNoncesDiffer(t *testing.T) {
	key := bytes.Repeat([]byte{1}, KeySize)
	seen := map[string]bool{}
	for range 1000 {
		blob, err := Seal(key, DomainItem, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		n := string(blob[:NonceSize])
		if seen[n] {
			t.Fatal("nonce repeated")
		}
		seen[n] = true
	}
}

func TestRejections(t *testing.T) {
	key := bytes.Repeat([]byte{1}, KeySize)
	blob, err := Seal(key, DomainItem, []byte("ctx"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{2}, KeySize)

	cases := map[string]func() ([]byte, error){
		"wrong key":      func() ([]byte, error) { return Open(other, DomainItem, []byte("ctx"), blob) },
		"wrong domain":   func() ([]byte, error) { return Open(key, DomainSlot, []byte("ctx"), blob) },
		"wrong context":  func() ([]byte, error) { return Open(key, DomainItem, []byte("ctX"), blob) },
		"short blob":     func() ([]byte, error) { return Open(key, DomainItem, []byte("ctx"), blob[:Overhead-1]) },
		"truncated":      func() ([]byte, error) { return Open(key, DomainItem, []byte("ctx"), blob[:len(blob)-1]) },
		"short key":      func() ([]byte, error) { return Open(key[:31], DomainItem, []byte("ctx"), blob) },
		"empty":          func() ([]byte, error) { return Open(key, DomainItem, []byte("ctx"), nil) },
		"appended bytes": func() ([]byte, error) { return Open(key, DomainItem, []byte("ctx"), append(bytes.Clone(blob), 0)) },
	}
	for name, f := range cases {
		pt, err := f()
		if !errors.Is(err, ErrOpen) || pt != nil {
			t.Errorf("%s: got pt=%q err=%v", name, pt, err)
		}
	}
}

func TestEveryBitFlipRejected(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	blob, err := Seal(key, DomainManifest, []byte("ctx"), []byte("tamper me"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range len(blob) * 8 {
		mutated := bytes.Clone(blob)
		mutated[i/8] ^= 1 << (i % 8)
		if pt, err := Open(key, DomainManifest, []byte("ctx"), mutated); err == nil {
			t.Fatalf("bit %d accepted, plaintext %q", i, pt)
		}
	}
}

// The commitment must reject a different key even for a ciphertext built so
// that the AEAD check alone can't be the only defence.
func TestCommitmentBindsKey(t *testing.T) {
	key := bytes.Repeat([]byte{1}, KeySize)
	other := bytes.Repeat([]byte{2}, KeySize)
	nonce := bytes.Repeat([]byte{3}, NonceSize)
	ad := associatedData(DomainItem, []byte("c"))
	_, kcomA, err := deriveKeys(key, nonce, ad)
	if err != nil {
		t.Fatal(err)
	}
	kencB, kcomB, err := deriveKeys(other, nonce, ad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(kcomA, kcomB) {
		t.Fatal("different keys produced one commitment")
	}
	// A blob with a valid AEAD under other's Kenc but key's commitment must fail
	// under both keys.
	aead, err := chacha20poly1305.NewX(kencB)
	if err != nil {
		t.Fatal(err)
	}
	blob := append(append(bytes.Clone(nonce), kcomA...), aead.Seal(nil, nonce, []byte("m"), ad)...)
	if _, err := Open(key, DomainItem, []byte("c"), blob); err == nil {
		t.Fatal("key accepted a blob whose AEAD belongs to another key")
	}
	if _, err := Open(other, DomainItem, []byte("c"), blob); err == nil {
		t.Fatal("other key accepted a blob with the wrong commitment")
	}
}

func TestContextEncodingIsInjective(t *testing.T) {
	if bytes.Equal(associatedData("ab", []byte("c")), associatedData("a", []byte("bc"))) {
		t.Fatal("domain and context can be shifted")
	}
}

func FuzzOpen(f *testing.F) {
	key := bytes.Repeat([]byte{9}, KeySize)
	// A fixed nonce keeps the seed identical in every fuzz worker process.
	valid, err := seal(key, bytes.Repeat([]byte{5}, NonceSize), DomainItem, []byte("ctx"), []byte("seed"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add(make([]byte, Overhead))
	f.Fuzz(func(t *testing.T, blob []byte) {
		pt, err := Open(key, DomainItem, []byte("ctx"), blob)
		if err != nil && pt != nil {
			t.Fatal("plaintext returned with an error")
		}
		if err == nil && !bytes.Equal(blob, valid) {
			t.Fatal("forged blob accepted")
		}
	})
}
