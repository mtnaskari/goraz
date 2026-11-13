package envelope

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// The primitives under the envelope are checked against Wycheproof, which includes
// the edge cases that broke other implementations. See testdata/wycheproof.

func loadWycheproof(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "wycheproof", name)) // #nosec G304 -- fixed test data.
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func unhexW(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWycheproofXChaCha20Poly1305(t *testing.T) {
	var f struct {
		TestGroups []struct {
			Tests []struct {
				TcID   int    `json:"tcId"`
				KeyH   string `json:"key"`
				IVH    string `json:"iv"`
				AADH   string `json:"aad"`
				MsgH   string `json:"msg"`
				CTH    string `json:"ct"`
				TagH   string `json:"tag"`
				Result string `json:"result"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	loadWycheproof(t, "xchacha20_poly1305_test.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		for _, c := range g.Tests {
			n++
			key, iv := unhexW(t, c.KeyH), unhexW(t, c.IVH)
			aad, msg := unhexW(t, c.AADH), unhexW(t, c.MsgH)
			sealed := append(unhexW(t, c.CTH), unhexW(t, c.TagH)...)
			aead, err := chacha20poly1305.NewX(key)
			if err != nil {
				if c.Result == "valid" {
					t.Errorf("case %d: %v", c.TcID, err)
				}
				continue
			}
			if len(iv) != aead.NonceSize() {
				if c.Result == "valid" {
					t.Errorf("case %d: valid case with a nonce of %d bytes", c.TcID, len(iv))
				}
				continue
			}
			pt, err := aead.Open(nil, iv, sealed, aad)
			switch c.Result {
			case "valid":
				if err != nil || hex.EncodeToString(pt) != c.MsgH {
					t.Errorf("case %d: valid case rejected", c.TcID)
				}
				if got := aead.Seal(nil, iv, msg, aad); hex.EncodeToString(got) != hex.EncodeToString(sealed) {
					t.Errorf("case %d: wrong ciphertext", c.TcID)
				}
			case "invalid":
				if err == nil {
					t.Errorf("case %d: invalid case accepted", c.TcID)
				}
			}
		}
	}
	if n < 300 {
		t.Fatalf("only %d cases loaded", n)
	}
}

func TestWycheproofHKDFSHA256(t *testing.T) {
	var f struct {
		TestGroups []struct {
			Tests []struct {
				TcID   int    `json:"tcId"`
				IKM    string `json:"ikm"`
				Salt   string `json:"salt"`
				Info   string `json:"info"`
				Size   int    `json:"size"`
				OKM    string `json:"okm"`
				Result string `json:"result"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	loadWycheproof(t, "hkdf_sha256_test.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		for _, c := range g.Tests {
			n++
			okm, err := hkdf.Key(sha256.New, unhexW(t, c.IKM), unhexW(t, c.Salt), string(unhexW(t, c.Info)), c.Size)
			switch c.Result {
			case "valid":
				if err != nil || hex.EncodeToString(okm) != c.OKM {
					t.Errorf("case %d: wrong output", c.TcID)
				}
			case "invalid":
				if err == nil {
					t.Errorf("case %d: invalid case accepted", c.TcID)
				}
			}
		}
	}
	if n < 80 {
		t.Fatalf("only %d cases loaded", n)
	}
}

func TestWycheproofHMACSHA256(t *testing.T) {
	var f struct {
		TestGroups []struct {
			TagSize int `json:"tagSize"`
			Tests   []struct {
				TcID   int    `json:"tcId"`
				Key    string `json:"key"`
				Msg    string `json:"msg"`
				Tag    string `json:"tag"`
				Result string `json:"result"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	loadWycheproof(t, "hmac_sha256_test.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		for _, c := range g.Tests {
			n++
			m := hmac.New(sha256.New, unhexW(t, c.Key))
			m.Write(unhexW(t, c.Msg))
			full := m.Sum(nil)
			tag := unhexW(t, c.Tag)
			ok := len(tag) == g.TagSize/8 && hmac.Equal(full[:len(tag)], tag)
			if (c.Result == "valid") != ok {
				t.Errorf("case %d: result %s, matched %v", c.TcID, c.Result, ok)
			}
		}
	}
	if n < 150 {
		t.Fatalf("only %d cases loaded", n)
	}
}
