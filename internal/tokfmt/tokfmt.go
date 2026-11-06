// Package tokfmt encodes and strictly parses token strings and recovery codes. It
// has no notion of validity beyond syntax. CRC32 lets scanners and typo checks
// reject a value cheaply, and it provides no security.
package tokfmt

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"hash/crc32"
	"math/big"
	"strings"
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

var (
	base      = big.NewInt(62)
	bodyLimit = new(big.Int).Lsh(big.NewInt(1), (IDSize+SecretSize)*8)
)

// ValidPrefix reports whether p matches [a-z]{2,10}.
func ValidPrefix(p string) bool {
	if len(p) < 2 || len(p) > 10 {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 'a' || p[i] > 'z' {
			return false
		}
	}
	return true
}

func encodeFixed(v *big.Int, width int) []byte {
	out := make([]byte, width)
	n := new(big.Int).Set(v)
	mod := new(big.Int)
	for i := width - 1; i >= 0; i-- {
		n.DivMod(n, base, mod)
		out[i] = alphabet[mod.Int64()]
	}
	return out
}

func decode(s string) (*big.Int, bool) {
	v := new(big.Int)
	d := new(big.Int)
	for i := 0; i < len(s); i++ {
		c := s[i]
		var x int64
		switch {
		case c >= '0' && c <= '9':
			x = int64(c - '0')
		case c >= 'A' && c <= 'Z':
			x = int64(c-'A') + 10
		case c >= 'a' && c <= 'z':
			x = int64(c-'a') + 36
		default:
			return nil, false
		}
		v.Mul(v, base)
		d.SetInt64(x)
		v.Add(v, d)
	}
	return v, true
}

func check(s string) string {
	sum := crc32.ChecksumIEEE([]byte(s))
	return string(encodeFixed(big.NewInt(int64(sum)), checkChars))
}

// Encode returns a token string. The result holds the secret in clear, so treat
// it as sensitive.
func Encode(prefix, kind string, id, secret []byte) ([]byte, error) {
	if !ValidPrefix(prefix) || (kind != KindService && kind != KindMachine) {
		return nil, errors.New("tokfmt: invalid prefix or kind")
	}
	if len(id) != IDSize || len(secret) != SecretSize {
		return nil, errors.New("tokfmt: invalid part size")
	}
	raw := make([]byte, 0, IDSize+SecretSize)
	raw = append(raw, id...)
	raw = append(raw, secret...)
	defer clear(raw)
	body := encodeFixed(new(big.Int).SetBytes(raw), bodyChars)
	defer clear(body)
	head := prefix + "_" + kind + "_" + string(body)
	return []byte(head + check(head)), nil
}

// Parsed is a syntactically valid token.
type Parsed struct {
	Prefix string
	Kind   string
	ID     [IDSize]byte
	Secret [SecretSize]byte
}

// Parse validates a token completely before any store lookup: exact shape, exact
// alphabet, canonical encoding and checksum.
func Parse(token []byte) (*Parsed, error) {
	const maxLen = 10 + 1 + 2 + 1 + bodyChars + checkChars
	if len(token) > maxLen {
		return nil, ErrSyntax
	}
	s := string(token)
	first := strings.IndexByte(s, '_')
	if first < 0 || len(s) < first+4 || s[first+3] != '_' {
		return nil, ErrSyntax
	}
	prefix, kind := s[:first], s[first+1:first+3]
	rest := s[first+4:]
	if !ValidPrefix(prefix) || (kind != KindService && kind != KindMachine) {
		return nil, ErrSyntax
	}
	if len(rest) != bodyChars+checkChars {
		return nil, ErrSyntax
	}
	head := s[:len(s)-checkChars]
	if subtle.ConstantTimeCompare([]byte(check(head)), []byte(s[len(s)-checkChars:])) != 1 {
		return nil, ErrSyntax
	}
	v, ok := decode(rest[:bodyChars])
	if !ok || v.Cmp(bodyLimit) >= 0 {
		return nil, ErrSyntax
	}
	p := &Parsed{Prefix: prefix, Kind: kind}
	var raw [IDSize + SecretSize]byte
	v.FillBytes(raw[:])
	copy(p.ID[:], raw[:IDSize])
	copy(p.Secret[:], raw[IDSize:])
	clear(raw[:])
	return p, nil
}

// Recovery codes are designed to be typed by a person.

const recoveryPrefix = "GORAZ-RC-"

var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// EncodeRecovery formats a 32-byte code with a 2-byte checksum, in groups of four.
func EncodeRecovery(code []byte) (string, error) {
	if len(code) != SecretSize {
		return "", errors.New("tokfmt: invalid recovery code size")
	}
	sum := sha256.Sum256(code)
	raw := make([]byte, 0, SecretSize+2)
	raw = append(raw, code...)
	raw = append(raw, sum[0], sum[1])
	defer clear(raw)
	enc := crockford.EncodeToString(raw)
	var b strings.Builder
	b.WriteString(recoveryPrefix)
	for i := 0; i < len(enc); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(enc[i:min(i+4, len(enc))])
	}
	return b.String(), nil
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
	if len(clean) < len(mapped) || string(clean[:len(mapped)]) != mapped {
		return nil, ErrSyntax
	}
	raw, err := crockford.DecodeString(string(clean[len(mapped):]))
	if err != nil || len(raw) != SecretSize+2 {
		return nil, ErrSyntax
	}
	sum := sha256.Sum256(raw[:SecretSize])
	if raw[SecretSize] != sum[0] || raw[SecretSize+1] != sum[1] {
		clear(raw)
		return nil, ErrSyntax
	}
	return raw[:SecretSize], nil
}
