// Package tokfmt encodes and strictly parses token strings and recovery codes. It
// has no notion of validity beyond syntax. CRC32 lets scanners and typo checks
// reject a value cheaply, and it provides no security.
package tokfmt

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// Sizes of the decoded parts.
const (
	IDSize     = 16
	SecretSize = 32
	bodyChars  = 65
	checkChars = 6
)

// Token kinds.
const (
	KindService = "st"
	KindMachine = "mk"
)

// DefaultPrefix is used unless an application sets its own.
const DefaultPrefix = "goraz"

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// ErrSyntax is returned for any malformed token. It never includes the input.
var ErrSyntax = errors.New("tokfmt: malformed token")

const rawSize = IDSize + SecretSize

// ValidPrefix reports whether p matches [a-z]{2,10}.
func ValidPrefix(p string) bool { return validPrefix([]byte(p)) }

func validPrefix(p []byte) bool {
	if len(p) < 2 || len(p) > 10 {
		return false
	}
	for _, c := range p {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// encodeBase62 writes v as exactly len(dst) base62 digits. It divides a copy of v
// in place, so no secret reaches math/big or a string.
func encodeBase62(dst, v []byte) {
	var work [rawSize]byte
	n := copy(work[:], v)
	num := work[:n]
	defer clear(work[:])
	for i := len(dst) - 1; i >= 0; i-- {
		rem := 0
		for j := range num {
			cur := rem<<8 | int(num[j])
			num[j] = byte(cur / 62) // #nosec G115 -- cur < 62*256, so cur/62 < 256.
			rem = cur % 62
		}
		dst[i] = alphabet[rem]
	}
}

func digit(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'A' && c <= 'Z':
		return int(c-'A') + 10, true
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 36, true
	}
	return 0, false
}

// decodeBase62 reads base62 digits into dst as a big-endian number. It reports
// false for a bad digit or a value that doesn't fit, which makes the encoding
// canonical for a fixed width.
func decodeBase62(dst, src []byte) bool {
	clear(dst)
	for _, c := range src {
		carry, ok := digit(c)
		if !ok {
			return false
		}
		for j := len(dst) - 1; j >= 0; j-- {
			cur := int(dst[j])*62 + carry
			dst[j] = byte(cur) // #nosec G115 -- keeps the low byte by design; the rest carries.
			carry = cur >> 8
		}
		if carry != 0 {
			return false
		}
	}
	return true
}

func checksum(dst, head []byte) {
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc32.ChecksumIEEE(head))
	encodeBase62(dst, sum[:])
}

// Encode returns a token. The result holds the secret in clear, so treat it as
// sensitive and clear it when done.
func Encode(prefix, kind string, id, secret []byte) ([]byte, error) {
	if !ValidPrefix(prefix) || (kind != KindService && kind != KindMachine) {
		return nil, errors.New("tokfmt: invalid prefix or kind")
	}
	if len(id) != IDSize || len(secret) != SecretSize {
		return nil, errors.New("tokfmt: invalid part size")
	}
	var raw [rawSize]byte
	copy(raw[:], id)
	copy(raw[IDSize:], secret)
	defer clear(raw[:])

	out := make([]byte, 0, len(prefix)+4+bodyChars+checkChars)
	out = append(out, prefix...)
	out = append(out, '_')
	out = append(out, kind...)
	out = append(out, '_')
	start := len(out)
	out = out[:start+bodyChars]
	encodeBase62(out[start:], raw[:])
	head := len(out)
	out = out[:head+checkChars]
	checksum(out[head:], out[:head])
	return out, nil
}

// Parsed is a syntactically valid token.
type Parsed struct {
	Prefix string
	Kind   string
	ID     [IDSize]byte
	Secret [SecretSize]byte
}

// Parse validates a token completely before any store lookup: exact shape, exact
// alphabet, canonical encoding and checksum. It never converts the token to a
// string.
func Parse(token []byte) (*Parsed, error) {
	const maxLen = 10 + 1 + 2 + 1 + bodyChars + checkChars
	if len(token) > maxLen {
		return nil, ErrSyntax
	}
	first := bytes.IndexByte(token, '_')
	if first < 0 || len(token) < first+4 || token[first+3] != '_' {
		return nil, ErrSyntax
	}
	prefix, kind, rest := token[:first], token[first+1:first+3], token[first+4:]
	if !validPrefix(prefix) || len(rest) != bodyChars+checkChars {
		return nil, ErrSyntax
	}
	var kindName string
	switch string(kind) { // Two public bytes; this conversion doesn't allocate.
	case KindService:
		kindName = KindService
	case KindMachine:
		kindName = KindMachine
	default:
		return nil, ErrSyntax
	}
	var want [checkChars]byte
	checksum(want[:], token[:len(token)-checkChars])
	if subtle.ConstantTimeCompare(want[:], token[len(token)-checkChars:]) != 1 {
		return nil, ErrSyntax
	}
	var raw [rawSize]byte
	defer clear(raw[:])
	if !decodeBase62(raw[:], rest[:bodyChars]) {
		return nil, ErrSyntax
	}
	p := &Parsed{Prefix: string(prefix), Kind: kindName}
	copy(p.ID[:], raw[:IDSize])
	copy(p.Secret[:], raw[IDSize:])
	return p, nil
}

// Recovery codes are designed to be typed by a person.

const recoveryPrefix = "GORAZ-RC-"

var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// EncodeRecovery formats a 32-byte code with a 2-byte checksum, in groups of four.
// The result is a secret: clear it when done.
func EncodeRecovery(code []byte) ([]byte, error) {
	if len(code) != SecretSize {
		return nil, errors.New("tokfmt: invalid recovery code size")
	}
	sum := sha256.Sum256(code)
	var raw [SecretSize + 2]byte
	copy(raw[:], code)
	raw[SecretSize], raw[SecretSize+1] = sum[0], sum[1]
	defer clear(raw[:])
	enc := make([]byte, crockford.EncodedLen(len(raw)))
	defer clear(enc)
	crockford.Encode(enc, raw[:])
	out := make([]byte, 0, len(recoveryPrefix)+len(enc)+len(enc)/4)
	out = append(out, recoveryPrefix...)
	for i := 0; i < len(enc); i += 4 {
		if i > 0 {
			out = append(out, '-')
		}
		out = append(out, enc[i:min(i+4, len(enc))]...)
	}
	return out, nil
}

// ParseRecovery accepts a typed recovery code. Case is ignored, separators are
// optional, and the letters I, L and O are read as the digits they resemble.
func ParseRecovery(s []byte) ([]byte, error) {
	if len(s) > 128 {
		return nil, ErrSyntax
	}
	clean := make([]byte, 0, len(s))
	defer clear(clean)
	for _, c := range s {
		switch {
		case c == '-' || c == ' ':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		switch c {
		case 'I', 'L':
			c = '1'
		case 'O':
			c = '0'
		}
		clean = append(clean, c)
	}
	// The prefix contains letters remapped above, so compare after remapping.
	const mapped = "G0RAZRC"
	if len(clean) < len(mapped) || !bytes.Equal(clean[:len(mapped)], []byte(mapped)) { //nolint:forbidigo // public: a fixed prefix.
		return nil, ErrSyntax
	}
	body := clean[len(mapped):]
	raw := make([]byte, crockford.DecodedLen(len(body)))
	n, err := crockford.Decode(raw, body)
	if err != nil || n != SecretSize+2 {
		clear(raw)
		return nil, ErrSyntax
	}
	sum := sha256.Sum256(raw[:SecretSize])
	if subtle.ConstantTimeCompare(raw[SecretSize:n], sum[:2]) != 1 {
		clear(raw)
		return nil, ErrSyntax
	}
	return raw[:SecretSize], nil
}
