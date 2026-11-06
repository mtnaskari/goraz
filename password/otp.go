package password

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- Required for RFC 4226 and RFC 6238 compatibility.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mtnaskari/goraz/secret"
)

// Algorithm is an OTP hash. MD5 isn't offered.
type Algorithm string

// Algorithms.
const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

func (a Algorithm) hash() (func() hash.Hash, error) {
	switch a {
	case SHA1:
		return sha1.New, nil
	case SHA256:
		return sha256.New, nil
	case SHA512:
		return sha512.New, nil
	}
	return nil, errors.New("password: unknown OTP algorithm")
}

// HOTP computes an RFC 4226 code.
func HOTP(key []byte, counter uint64, digits int, alg Algorithm) (string, error) {
	if digits < 6 || digits > 10 {
		return "", errors.New("password: OTP digits must be between 6 and 10")
	}
	if len(key) == 0 {
		return "", errors.New("password: an OTP key is required")
	}
	h, err := alg.hash()
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(h, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := uint64(binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff)
	mod := uint64(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod), nil
}

// TOTP computes an RFC 6238 code.
func TOTP(key []byte, at time.Time, period int, digits int, alg Algorithm) (string, error) {
	if period <= 0 {
		return "", errors.New("password: an OTP period must be positive")
	}
	unix := at.Unix()
	if unix < 0 {
		return "", errors.New("password: time is before 1970")
	}
	return HOTP(key, uint64(unix)/uint64(period), digits, alg) // #nosec G115 -- both values are positive.
}

// OTPAuth is a parsed otpauth:// URI.
type OTPAuth struct {
	Type      string // "totp" or "hotp".
	Label     string
	Issuer    string
	Key       secret.Secret
	Algorithm Algorithm
	Digits    int
	Period    int
	Counter   uint64
}

// Code returns the code for the given time. An HOTP URI uses its stored counter.
func (o *OTPAuth) Code(at time.Time) (string, error) {
	if o.Type == "hotp" {
		return HOTP(o.Key.Bytes(), o.Counter, o.Digits, o.Algorithm)
	}
	return TOTP(o.Key.Bytes(), at, o.Period, o.Digits, o.Algorithm)
}

const maxOTPURI = 2048

// ErrOTPURI is returned for any malformed URI. It never includes the input,
// because the input holds a key.
var ErrOTPURI = errors.New("password: malformed otpauth URI")

// ParseOTPAuth parses an otpauth:// URI strictly. Repeated parameters are refused.
// The "image" parameter is ignored and never fetched.
func ParseOTPAuth(uri string) (*OTPAuth, error) {
	if len(uri) > maxOTPURI {
		return nil, ErrOTPURI
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" || u.Opaque != "" || u.User != nil || u.Fragment != "" {
		return nil, ErrOTPURI
	}
	if u.Host != "totp" && u.Host != "hotp" {
		return nil, ErrOTPURI
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrOTPURI
	}
	o := &OTPAuth{
		Type: u.Host, Algorithm: SHA1, Digits: 6, Period: 30,
		Label: strings.TrimPrefix(u.Path, "/"),
	}
	seenSecret, seenCounter := false, false
	for k, vs := range q {
		if len(vs) != 1 {
			return nil, ErrOTPURI
		}
		v := vs[0]
		switch k {
		case "secret":
			raw := strings.ToUpper(strings.TrimRight(v, "="))
			key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(raw)
			if err != nil || len(key) == 0 || len(key) > 128 {
				return nil, ErrOTPURI
			}
			o.Key = secret.Adopt(key)
			seenSecret = true
		case "issuer":
			o.Issuer = v
		case "algorithm":
			switch Algorithm(v) {
			case SHA1, SHA256, SHA512:
				o.Algorithm = Algorithm(v)
			default:
				return nil, ErrOTPURI
			}
		case "digits":
			n, err := strconv.Atoi(v)
			if err != nil || n < 6 || n > 10 {
				return nil, ErrOTPURI
			}
			o.Digits = n
		case "period":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 3600 {
				return nil, ErrOTPURI
			}
			o.Period = n
		case "counter":
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil, ErrOTPURI
			}
			o.Counter = n
			seenCounter = true
		case "image":
		default:
			return nil, ErrOTPURI
		}
	}
	if !seenSecret || (o.Type == "hotp" && !seenCounter) {
		return nil, ErrOTPURI
	}
	return o, nil
}
