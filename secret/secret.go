// Package secret provides a byte-slice wrapper that refuses to reveal its
// contents through formatting or encoding.
//
// Wiping is best effort. Go does not guarantee that copies made by the runtime
// or by other libraries are erased. See docs/security-design.md, section 10.
package secret

import (
	"crypto/subtle"
	"fmt"
	"io"
)

const redacted = "[REDACTED]"

// Secret holds sensitive bytes. The zero value is an empty secret.
//
// A Secret must not be copied by value after first use, because a copy shares
// its bytes with the original and is wiped with it.
type Secret struct {
	b []byte
}

// New returns a Secret holding a copy of b. The caller remains responsible for
// clearing b.
func New(b []byte) Secret {
	c := make([]byte, len(b))
	copy(c, b)
	return Secret{b: c}
}

// Adopt returns a Secret that takes ownership of b without copying it.
func Adopt(b []byte) Secret {
	return Secret{b: b}
}

// Bytes returns the underlying bytes, not a copy. The returned slice becomes
// all zeros after Wipe.
func (s Secret) Bytes() []byte { return s.b }

// Len returns the length of the secret.
func (s Secret) Len() int { return len(s.b) }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return len(s.b) == 0 }

// Equal compares two secrets. It does not hide their lengths.
func (s Secret) Equal(o Secret) bool {
	return subtle.ConstantTimeCompare(s.b, o.b) == 1
}

// Wipe overwrites the secret's bytes with zeros.
func (s Secret) Wipe() { clear(s.b) }

// String returns a fixed placeholder.
func (s Secret) String() string { return redacted }

// GoString returns a fixed placeholder.
func (s Secret) GoString() string { return "secret.Secret(" + redacted + ")" }

// Format prints a fixed placeholder for every verb.
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, redacted)
}

// MarshalJSON returns a fixed placeholder. A Secret can't be stored by encoding
// it as JSON.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}

// MarshalText returns a fixed placeholder.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(redacted), nil
}
