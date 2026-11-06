// Package envelope implements the sealed envelope in docs/security-design.md,
// section 4. It applies the generic key-commitment transform of Albertini et
// al. (USENIX Security 2022) to XChaCha20-Poly1305, using HKDF-SHA-256.
//
// This composition has not been independently reviewed.
package envelope

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// NonceSize is the size of the random nonce.
	NonceSize = chacha20poly1305.NonceSizeX
	// CommitSize is the size of the key commitment.
	CommitSize = 32
	// KeySize is the required size of an input key.
	KeySize = 32
	// Overhead is the number of bytes a sealed blob adds to its plaintext.
	Overhead = NonceSize + CommitSize + chacha20poly1305.Overhead
)

// Domains separate the three kinds of sealed object.
const (
	DomainSlot     = "slot"
	DomainManifest = "manifest"
	DomainItem     = "item"
)

// ErrOpen is returned for every failure to open a blob. It deliberately gives
// no detail about which check failed.
var ErrOpen = errors.New("envelope: authentication failed")

// LP appends x to dst with a 4-byte big-endian length prefix.
func LP(dst, x []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(x))) // #nosec G115 -- inputs are bounded far below 4 GiB.
	return append(dst, x...)
}

func associatedData(domain string, context []byte) []byte {
	ad := make([]byte, 0, 11+8+len(domain)+len(context))
	ad = append(ad, "goraz/v1/ad"...)
	ad = LP(ad, []byte(domain))
	return LP(ad, context)
}

func deriveKeys(key, nonce, ad []byte) (kenc, kcom []byte, err error) {
	prk, err := hkdf.Extract(sha256.New, key, nonce)
	if err != nil {
		return nil, nil, err
	}
	defer clear(prk)
	h := sha256.Sum256(ad)
	kenc, err = hkdf.Expand(sha256.New, prk, "goraz/v1/enc\x00"+string(h[:]), chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, err
	}
	kcom, err = hkdf.Expand(sha256.New, prk, "goraz/v1/com\x00"+string(h[:]), CommitSize)
	if err != nil {
		clear(kenc)
		return nil, nil, err
	}
	return kenc, kcom, nil
}

// Seal encrypts plaintext under key, bound to domain and context.
func Seal(key []byte, domain string, context, plaintext []byte) ([]byte, error) {
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return seal(key, nonce[:], domain, context, plaintext)
}

// seal is the deterministic core of Seal. Only tests pass a chosen nonce.
func seal(key, nonce []byte, domain string, context, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("envelope: invalid key size")
	}
	ad := associatedData(domain, context)
	kenc, kcom, err := deriveKeys(key, nonce, ad)
	if err != nil {
		return nil, err
	}
	defer clear(kenc)
	aead, err := chacha20poly1305.NewX(kenc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, Overhead+len(plaintext))
	out = append(out, nonce...)
	out = append(out, kcom...)
	return aead.Seal(out, nonce, plaintext, ad), nil
}

// Open authenticates and decrypts a blob. It returns ErrOpen on every failure,
// and it returns no plaintext unless authentication has succeeded.
func Open(key []byte, domain string, context, blob []byte) ([]byte, error) {
	if len(key) != KeySize || len(blob) < Overhead {
		return nil, ErrOpen
	}
	nonce := blob[:NonceSize]
	commit := blob[NonceSize : NonceSize+CommitSize]
	ct := blob[NonceSize+CommitSize:]

	ad := associatedData(domain, context)
	kenc, kcom, err := deriveKeys(key, nonce, ad)
	if err != nil {
		return nil, ErrOpen
	}
	defer clear(kenc)
	if subtle.ConstantTimeCompare(kcom, commit) != 1 {
		return nil, ErrOpen
	}
	aead, err := chacha20poly1305.NewX(kenc)
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := aead.Open(nil, nonce, ct, ad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}
