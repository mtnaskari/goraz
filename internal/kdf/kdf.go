// Package kdf derives unlock keys. Argon2 parameters are accepted only when they
// exactly match a built-in profile, which defends against downgrade and memory
// exhaustion from a tampered file, and avoids the panics in x/crypto/argon2.
package kdf

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"github.com/mtnaskari/goraz/internal/envelope"
)

// SaltSize is the Argon2 salt size.
const SaltSize = 16

// KeyfileSize is the exact size of a key file.
const KeyfileSize = 32

// MaxPassphraseBytes limits passphrase length. Terminals in canonical mode may
// truncate long lines silently, so longer input is refused rather than cut.
const MaxPassphraseBytes = 512

// Params are Argon2id parameters.
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// Profile is a named, allowed parameter set.
type Profile struct {
	Name   string
	Params Params
}

// The allowed profiles. A new profile is a format change.
var (
	Interactive = Profile{"interactive", Params{64 * 1024, 3, 4}}
	Standard    = Profile{"standard", Params{256 * 1024, 3, 4}}
	Strong      = Profile{"strong", Params{1024 * 1024, 3, 4}}
	Max         = Profile{"max", Params{2 * 1024 * 1024, 1, 4}}
)

// Default is the profile for new vaults.
var Default = Strong

// Profiles returns all allowed profiles, weakest first.
func Profiles() []Profile { return []Profile{Interactive, Standard, Strong, Max} }

// ProfileByName finds a profile by name.
func ProfileByName(name string) (Profile, error) {
	for _, p := range Profiles() {
		if p.Name == name {
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("kdf: unknown profile %q", name)
}

// ErrParams is returned for parameters outside the allowlist.
var ErrParams = errors.New("kdf: parameters are not in the allowlist")

// Allowed reports whether p exactly matches a profile.
func Allowed(p Params) bool {
	for _, a := range Profiles() {
		if a.Params == p {
			return true
		}
	}
	return false
}

// Normalize returns the NFC form of a passphrase in a new slice. It always copies,
// because norm.Bytes may return its input, and the caller clears the result.
func Normalize(passphrase []byte) []byte {
	return norm.NFC.Append(make([]byte, 0, len(passphrase)), passphrase...)
}

// PassphraseKey derives a slot key from a passphrase and optional key file. The
// allowlist is checked first, so nothing unvalidated reaches Argon2.
func PassphraseKey(passphrase, keyfile, salt, vaultID []byte, p Params) ([]byte, error) {
	if !Allowed(p) {
		return nil, ErrParams
	}
	if len(salt) != SaltSize {
		return nil, errors.New("kdf: invalid salt size")
	}
	if len(passphrase) == 0 || len(passphrase) > MaxPassphraseBytes {
		return nil, errors.New("kdf: invalid passphrase length")
	}
	if len(keyfile) != 0 && len(keyfile) != KeyfileSize {
		return nil, errors.New("kdf: a key file must be exactly 32 bytes")
	}
	normal := Normalize(passphrase)
	defer clear(normal)
	a := argon2.IDKey(normal, salt, p.Time, p.MemoryKiB, p.Threads, 32)
	defer clear(a)

	ikm := envelope.LP(nil, a)
	ikm = envelope.LP(ikm, keyfile)
	defer clear(ikm)
	return hkdf.Key(sha256.New, ikm, vaultID, "goraz/v1/unlock/passphrase", 32)
}

// RecoveryKey derives a slot key from a 256-bit recovery code.
func RecoveryKey(code, vaultID []byte) ([]byte, error) {
	if len(code) != 32 {
		return nil, errors.New("kdf: invalid recovery code size")
	}
	return hkdf.Key(sha256.New, code, vaultID, "goraz/v1/unlock/recovery", 32)
}

// MachineKey derives a slot key from a 256-bit machine key.
func MachineKey(key, vaultID []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("kdf: invalid machine key size")
	}
	return hkdf.Key(sha256.New, key, vaultID, "goraz/v1/unlock/machine", 32)
}

// Subkey derives a purpose-specific key from the vault master key.
func Subkey(vmk, vaultID []byte, label string) ([]byte, error) {
	return hkdf.Key(sha256.New, vmk, vaultID, label, 32)
}

// Subkey labels.
const (
	LabelManifest = "goraz/v1/key/manifest"
	LabelItem     = "goraz/v1/key/item"
)
