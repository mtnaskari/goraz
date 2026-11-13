package password

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	s, err := Generate(32, DefaultAlphabet)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 32 {
		t.Fatal("wrong length")
	}
	for _, c := range s.Bytes() {
		if !strings.ContainsRune(DefaultAlphabet, rune(c)) {
			t.Fatalf("character %q outside the alphabet", c)
		}
	}
	for _, c := range []struct {
		n int
		a string
	}{{7, Lower}, {2000, Lower}, {16, "a"}, {16, ""}, {16, "aa"}, {16, "é€"}} {
		if _, err := Generate(c.n, c.a); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

// A chi-squared check for gross bias. It uses a fixed threshold well above the
// expected value, so a failure means something is actually wrong.
func TestGenerateIsNotBiased(t *testing.T) {
	const alpha = "abc"
	counts := map[byte]int{}
	const n = 60000
	for range n / 100 {
		s, err := Generate(100, alpha)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range s.Bytes() {
			counts[c]++
		}
	}
	expected := float64(n) / 3
	var chi float64
	for i := range 3 {
		d := float64(counts[alpha[i]]) - expected
		chi += d * d / expected
	}
	if chi > 30 {
		t.Fatalf("distribution looks biased: chi2=%f counts=%v", chi, counts)
	}
}

func TestWordList(t *testing.T) {
	sum := sha256.Sum256([]byte(effList))
	const want = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
	if hex.EncodeToString(sum[:]) != want {
		t.Fatal("the embedded word list has changed")
	}
	w := words()
	if len(w) != 7776 {
		t.Fatalf("%d words", len(w))
	}
	seen := map[string]bool{}
	for _, x := range w {
		if seen[x] || x == "" {
			t.Fatalf("bad word %q", x)
		}
		seen[x] = true
	}
}

func TestPassphrase(t *testing.T) {
	s, err := Passphrase(6, "-")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(s.Bytes()), "-"); got < 5 {
		t.Errorf("separators: %d", got)
	}
	if err := CheckMaster(s.Bytes()); err != nil {
		t.Errorf("a generated passphrase failed the policy: %v", err)
	}
	if _, err := Passphrase(5, "-"); err == nil {
		t.Error("too few words accepted")
	}
	if EntropyBits(6, 7776) < 77 {
		t.Error("expected at least 77 bits")
	}
}

func TestCheckMaster(t *testing.T) {
	bad := map[string]error{
		"short":                        ErrTooShort,
		"aaaaaaaaaaaaaaaaaaaaaa":       ErrCommon,
		"abcabcabcabcabcabcabc":        ErrCommon,
		"abcdefghijklmnopqrs":          ErrCommon,
		"987654321987654321":           ErrCommon,
		"passwordpassword":             ErrCommon,
		"PasswordPassword":             ErrCommon,
		"correct horse battery staple": ErrCommon,
		"123456789012345":              ErrCommon,
		"changeme-changeme":            ErrCommon,
	}
	for p, want := range bad {
		if err := CheckMaster([]byte(p)); !errors.Is(err, want) {
			t.Errorf("%q: err = %v", p, err)
		}
	}
	if err := CheckMaster([]byte(strings.Repeat("ab1", 200))); !errors.Is(err, ErrTooLong) {
		t.Errorf("long: %v", err)
	}
	if err := CheckMaster([]byte("\xff\xfe invalid utf8 value")); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
	// No composition rules: lowercase only, and non-Latin scripts, are fine.
	for _, p := range []string{"violet granite ocean drift", "رمز عبور طولانی و خوب من"} {
		if err := CheckMaster([]byte(p)); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
}

// RFC 4226, appendix D.
func TestHOTPVectors(t *testing.T) {
	key := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		got, err := HOTP(key, uint64(i), 6, SHA1) // #nosec G115 -- small test value.
		if err != nil {
			t.Fatal(err)
		}
		if got != w {
			t.Errorf("count %d: got %s, want %s", i, got, w)
		}
	}
}

// RFC 6238, appendix B.
func TestTOTPVectors(t *testing.T) {
	k1 := []byte("12345678901234567890")
	k256 := []byte("12345678901234567890123456789012")
	k512 := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	cases := []struct {
		sec  int64
		alg  Algorithm
		key  []byte
		want string
	}{
		{59, SHA1, k1, "94287082"},
		{59, SHA256, k256, "46119246"},
		{59, SHA512, k512, "90693936"},
		{1111111109, SHA1, k1, "07081804"},
		{1111111109, SHA256, k256, "68084774"},
		{1111111109, SHA512, k512, "25091201"},
		{1234567890, SHA1, k1, "89005924"},
		{2000000000, SHA1, k1, "69279037"},
		{20000000000, SHA1, k1, "65353130"},
		{20000000000, SHA256, k256, "77737706"},
		{20000000000, SHA512, k512, "47863826"},
	}
	for _, c := range cases {
		got, err := TOTP(c.key, time.Unix(c.sec, 0), 30, 8, c.alg)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%d %s: got %s, want %s", c.sec, c.alg, got, c.want)
		}
	}
}

func TestOTPRejectsBadParameters(t *testing.T) {
	k := []byte("k")
	if _, err := HOTP(k, 0, 5, SHA1); err == nil {
		t.Error("5 digits accepted")
	}
	if _, err := HOTP(k, 0, 6, "MD5"); err == nil {
		t.Error("MD5 accepted")
	}
	if _, err := HOTP(nil, 0, 6, SHA1); err == nil {
		t.Error("empty key accepted")
	}
	if _, err := TOTP(k, time.Unix(0, 0), 0, 6, SHA1); err == nil {
		t.Error("zero period accepted")
	}
	if _, err := TOTP(k, time.Unix(-5, 0), 30, 6, SHA1); err == nil {
		t.Error("negative time accepted")
	}
}

func TestParseOTPAuth(t *testing.T) {
	o, err := ParseOTPAuth("otpauth://totp/Acme:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Acme&digits=8&period=60&algorithm=SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if o.Type != "totp" || o.Issuer != "Acme" || o.Digits != 8 || o.Period != 60 || o.Algorithm != SHA256 || o.Label != "Acme:alice" {
		t.Errorf("%+v", o)
	}
	if string(o.Key.Bytes()) != "12345678901234567890" {
		t.Error("wrong key")
	}
	if _, err := o.Code(time.Unix(59, 0)); err != nil {
		t.Error(err)
	}

	h, err := ParseOTPAuth("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=1")
	if err != nil {
		t.Fatal(err)
	}
	if code, err := h.Code(time.Time{}); err != nil || code != "287082" {
		t.Errorf("hotp: %s %v", code, err)
	}

	bad := []string{
		"", "http://totp/x?secret=GEZA", "otpauth://steam/x?secret=GEZA", "otpauth://totp/x",
		"otpauth://totp/x?secret=", "otpauth://totp/x?secret=not!base32", "otpauth://totp/x?secret=GEZA&secret=GEZB",
		"otpauth://totp/x?secret=GEZA&digits=5", "otpauth://totp/x?secret=GEZA&digits=abc",
		"otpauth://totp/x?secret=GEZA&period=0", "otpauth://totp/x?secret=GEZA&period=99999",
		"otpauth://totp/x?secret=GEZA&algorithm=MD5", "otpauth://totp/x?secret=GEZA&unknown=1",
		"otpauth://hotp/x?secret=GEZA", "otpauth://user:pw@totp/x?secret=GEZA", "otpauth://totp/x?secret=GEZA#frag",
		"otpauth:totp/x?secret=GEZA", "otpauth://totp/x?secret=GEZA&counter=-1",
		"otpauth://totp/x?secret=" + strings.Repeat("A", 3000),
	}
	for _, u := range bad {
		if _, err := ParseOTPAuth(u); !errors.Is(err, ErrOTPURI) {
			t.Errorf("%q: err = %v", u, err)
		}
	}
}

func TestOTPErrorDoesNotLeakKey(t *testing.T) {
	_, err := ParseOTPAuth("otpauth://totp/x?secret=TOPSECRETVALUE&digits=5")
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Errorf("err = %v", err)
	}
}

func FuzzParseOTPAuth(f *testing.F) {
	f.Add("otpauth://totp/x?secret=GEZDGNBV")
	f.Add("otpauth://hotp/x?secret=GEZDGNBV&counter=1")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		o, err := ParseOTPAuth(s)
		if err != nil {
			return
		}
		if o.Key.IsZero() || o.Digits < 6 || o.Digits > 10 {
			t.Fatalf("invalid result for %q", s)
		}
		if _, err := o.Code(time.Unix(1000, 0)); err != nil {
			t.Fatalf("accepted URI can't produce a code: %v", err)
		}
	})
}
