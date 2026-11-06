// Package password generates passwords and passphrases, enforces the master
// passphrase policy, and produces one-time codes.
package password

import (
	"crypto/rand"
	_ "embed" // For the word list.
	"errors"
	"math"
	"math/big"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/mtnaskari/goraz/secret"
)

//go:embed wordlist/eff_large.txt
var effList string

// Character sets for Generate.
const (
	Lower   = "abcdefghijklmnopqrstuvwxyz"
	Upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digits  = "0123456789"
	Symbols = "!#$%&*+-=?@^_~"
	// DefaultAlphabet avoids characters that shells and URLs treat specially.
	DefaultAlphabet = Lower + Upper + Digits + "-_"
)

// DefaultLength is the default generated password length.
const DefaultLength = 24

// MinMasterLength is the minimum passphrase length, per NIST SP 800-63B-4.
const MinMasterLength = 15

// MinWords gives about 77 bits from the 7776-word list.
const MinWords = 6

// randIndex returns an unbiased integer in [0, n). crypto/rand.Int uses rejection
// sampling, so there is no modulo bias.
func randIndex(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

// Generate returns a random password drawn from alphabet.
func Generate(length int, alphabet string) (secret.Secret, error) {
	if length < 8 || length > 1024 {
		return secret.Secret{}, errors.New("password: length must be between 8 and 1024")
	}
	if len(alphabet) < 2 || !utf8.ValidString(alphabet) || strings.ContainsFunc(alphabet, func(r rune) bool { return r >= utf8.RuneSelf }) {
		return secret.Secret{}, errors.New("password: the alphabet must hold at least two ASCII characters")
	}
	seen := map[byte]bool{}
	for i := range len(alphabet) {
		if seen[alphabet[i]] {
			return secret.Secret{}, errors.New("password: the alphabet has a repeated character, which would bias the result")
		}
		seen[alphabet[i]] = true
	}
	out := make([]byte, length)
	for i := range out {
		idx, err := randIndex(len(alphabet))
		if err != nil {
			return secret.Secret{}, err
		}
		out[i] = alphabet[idx]
	}
	return secret.Adopt(out), nil
}

var words = sync.OnceValue(func() []string {
	lines := strings.Split(strings.TrimSpace(effList), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		_, w, ok := strings.Cut(strings.TrimRight(l, "\r"), "\t")
		if !ok {
			panic("password: malformed embedded word list")
		}
		out = append(out, w)
	}
	return out
})

// Passphrase returns random words from the EFF large word list.
func Passphrase(count int, separator string) (secret.Secret, error) {
	if count < MinWords || count > 64 {
		return secret.Secret{}, errors.New("password: use between 6 and 64 words")
	}
	list := words()
	var b []byte
	for i := range count {
		idx, err := randIndex(len(list))
		if err != nil {
			return secret.Secret{}, err
		}
		if i > 0 {
			b = append(b, separator...)
		}
		b = append(b, list[idx]...)
	}
	return secret.Adopt(b), nil
}

// EntropyBits estimates a generated value's entropy. It applies only to values
// that were generated uniformly, not to anything a person chose.
func EntropyBits(length, alphabetSize int) float64 {
	return float64(length) * math.Log2(float64(alphabetSize))
}

// Errors from CheckMaster.
var (
	ErrTooShort = errors.New("password: use at least 15 characters; a generated passphrase is recommended")
	ErrTooLong  = errors.New("password: use at most 512 bytes")
	ErrCommon   = errors.New("password: this passphrase is too predictable")
)

var blocklist = []string{
	"passwordpassword", "password1234567", "1234567890123456", "123456789012345",
	"qwertyuiopasdfgh", "qwertyuiopasdfg", "correcthorsebatterystaple", "correct horse battery staple",
	"thequickbrownfox", "letmeinletmein", "iloveyouiloveyou", "adminadminadmin", "administrator123",
	"goraz", "wildboar", "changeme", "abcdefghijklmnop", "abcdefghijklmno",
}

// CheckMaster applies the master passphrase policy: a minimum length, a blocklist
// and no composition rules. It doesn't estimate strength beyond that.
func CheckMaster(p []byte) error {
	if len(p) > 512 {
		return ErrTooLong
	}
	if !utf8.Valid(p) {
		return errors.New("password: a passphrase must be valid UTF-8")
	}
	if utf8.RuneCount(p) < MinMasterLength {
		return ErrTooShort
	}
	lower := strings.ToLower(string(p))
	for _, b := range blocklist {
		if strings.Contains(lower, b) && len(lower)-len(b) < 8 {
			return ErrCommon
		}
	}
	compact := strings.Map(func(r rune) rune {
		if r < utf8.RuneSelf && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
			return -1
		}
		return r
	}, lower)
	if repetitive(compact) || sequential(compact) {
		return ErrCommon
	}
	return nil
}

// repetitive reports a pattern repeated throughout, such as "abcabcabc...".
func repetitive(s string) bool {
	for period := 1; period*2 <= len(s); period++ {
		match := true
		for i := period; i < len(s); i++ {
			if s[i] != s[i-period] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func sequential(s string) bool {
	if len(s) < 2 {
		return false
	}
	up, down := true, true
	for i := 1; i < len(s); i++ {
		if int(s[i]) != int(s[i-1])+1 {
			up = false
		}
		if int(s[i]) != int(s[i-1])-1 {
			down = false
		}
	}
	return up || down
}
