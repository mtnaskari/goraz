// Package format parses and writes the v1 header. The parser treats its input as
// hostile: all lengths are bounded, unknown values are refused and trailing
// fields don't exist. See docs/security-design.md, section 5.
package format

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mtnaskari/goraz/internal/envelope"
	"github.com/mtnaskari/goraz/internal/kdf"
)

// Magic is the only version indicator in the format.
const Magic = "GORAZv1\n"

// Limits enforced before any allocation or KDF run.
const (
	MaxFileSize     = 1 << 30
	MaxManifestSize = 64 << 20
	MaxSlots        = 16
	MaxValueSize    = 1 << 20
	IDSize          = 16
	// SlotBlobSize is the sealed size of a 32-byte vault master key.
	SlotBlobSize = envelope.Overhead + 32
)

// Slot types.
const (
	SlotPassphrase byte = 0x01
	SlotRecovery   byte = 0x02
	SlotMachine    byte = 0x03
)

const (
	passphraseFixed = 1 + IDSize + kdf.SaltSize + 4 + 4 + 1 + 1
	otherFixed      = 1 + IDSize
)

// ErrFormat is returned for any malformed file. It never includes file contents.
var ErrFormat = errors.New("format: malformed vault file")

// Slot is one credential's copy of the wrapped vault master key.
type Slot struct {
	Type       byte
	ID         [IDSize]byte
	Salt       [kdf.SaltSize]byte // Passphrase slots only.
	Params     kdf.Params         // Passphrase slots only.
	HasKeyfile bool               // Passphrase slots only.
	Blob       []byte
}

// Header is the file's plaintext header.
type Header struct {
	VaultID     [IDSize]byte
	Generation  uint64
	Slots       []Slot
	ManifestLen uint32
}

func (s *Slot) fixedBytes() []byte {
	b := make([]byte, 0, passphraseFixed)
	b = append(b, s.Type)
	b = append(b, s.ID[:]...)
	if s.Type == SlotPassphrase {
		b = append(b, s.Salt[:]...)
		b = binary.BigEndian.AppendUint32(b, s.Params.MemoryKiB)
		b = binary.BigEndian.AppendUint32(b, s.Params.Time)
		b = append(b, s.Params.Threads)
		if s.HasKeyfile {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	return b
}

// Context returns the bytes a slot blob is bound to: the vault ID and all slot
// fields before the blob.
func (s *Slot) Context(vaultID [IDSize]byte) []byte {
	return append(vaultID[:len(vaultID):len(vaultID)], s.fixedBytes()...)
}

// Parse reads a header from the start of b and returns its length. It validates
// KDF parameters against the allowlist, so no later step sees an unvalidated
// value.
func Parse(b []byte) (*Header, int, error) {
	if len(b) > MaxFileSize {
		return nil, 0, ErrFormat
	}
	const fixed = len(Magic) + IDSize + 8 + 1
	if len(b) < fixed || string(b[:len(Magic)]) != Magic {
		return nil, 0, ErrFormat
	}
	h := &Header{}
	off := len(Magic)
	copy(h.VaultID[:], b[off:])
	off += IDSize
	h.Generation = binary.BigEndian.Uint64(b[off:])
	off += 8
	count := int(b[off])
	off++
	if count < 1 || count > MaxSlots {
		return nil, 0, ErrFormat
	}
	h.Slots = make([]Slot, 0, count)
	seen := make(map[[IDSize]byte]bool, count)
	passphrases := 0
	for range count {
		s, n, err := parseSlot(b[off:])
		if err != nil {
			return nil, 0, err
		}
		if seen[s.ID] {
			return nil, 0, ErrFormat
		}
		seen[s.ID] = true
		if s.Type == SlotPassphrase {
			passphrases++
			if passphrases > 1 {
				return nil, 0, ErrFormat
			}
		}
		h.Slots = append(h.Slots, s)
		off += n
	}
	if len(b) < off+4 {
		return nil, 0, ErrFormat
	}
	h.ManifestLen = binary.BigEndian.Uint32(b[off:])
	off += 4
	if h.ManifestLen < envelope.Overhead || h.ManifestLen > MaxManifestSize {
		return nil, 0, ErrFormat
	}
	if uint64(len(b)) < uint64(off)+uint64(h.ManifestLen) {
		return nil, 0, ErrFormat
	}
	return h, off, nil
}

func parseSlot(b []byte) (Slot, int, error) {
	var s Slot
	if len(b) < 1 {
		return s, 0, ErrFormat
	}
	s.Type = b[0]
	var fixed int
	switch s.Type {
	case SlotPassphrase:
		fixed = passphraseFixed
	case SlotRecovery, SlotMachine:
		fixed = otherFixed
	default:
		return s, 0, ErrFormat
	}
	total := fixed + SlotBlobSize
	if len(b) < total {
		return s, 0, ErrFormat
	}
	off := 1
	copy(s.ID[:], b[off:])
	off += IDSize
	if s.Type == SlotPassphrase {
		copy(s.Salt[:], b[off:])
		off += kdf.SaltSize
		s.Params.MemoryKiB = binary.BigEndian.Uint32(b[off:])
		off += 4
		s.Params.Time = binary.BigEndian.Uint32(b[off:])
		off += 4
		s.Params.Threads = b[off]
		off++
		if !kdf.Allowed(s.Params) {
			return s, 0, ErrFormat
		}
		switch b[off] {
		case 0:
		case 1:
			s.HasKeyfile = true
		default:
			return s, 0, ErrFormat
		}
		off++
	}
	s.Blob = append([]byte(nil), b[off:off+SlotBlobSize]...)
	return s, total, nil
}

// Marshal writes the header. It refuses a header the parser would reject.
func (h *Header) Marshal() ([]byte, error) {
	if len(h.Slots) < 1 || len(h.Slots) > MaxSlots {
		return nil, fmt.Errorf("format: %d slots is out of range", len(h.Slots))
	}
	out := make([]byte, 0, 64+len(h.Slots)*(passphraseFixed+SlotBlobSize))
	out = append(out, Magic...)
	out = append(out, h.VaultID[:]...)
	out = binary.BigEndian.AppendUint64(out, h.Generation)
	out = append(out, byte(len(h.Slots))) // #nosec G115 -- MaxSlots was checked above.
	passphrases := 0
	for i := range h.Slots {
		s := &h.Slots[i]
		if len(s.Blob) != SlotBlobSize {
			return nil, errors.New("format: invalid slot blob size")
		}
		switch s.Type {
		case SlotPassphrase:
			passphrases++
			if !kdf.Allowed(s.Params) {
				return nil, kdf.ErrParams
			}
		case SlotRecovery, SlotMachine:
		default:
			return nil, errors.New("format: unknown slot type")
		}
		out = append(out, s.fixedBytes()...)
		out = append(out, s.Blob...)
	}
	if passphrases > 1 {
		return nil, errors.New("format: more than one passphrase slot")
	}
	if h.ManifestLen < envelope.Overhead || h.ManifestLen > MaxManifestSize {
		return nil, errors.New("format: manifest size out of range")
	}
	return binary.BigEndian.AppendUint32(out, h.ManifestLen), nil
}
