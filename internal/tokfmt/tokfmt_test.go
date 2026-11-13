package tokfmt

import (
	"bytes"
	"math/big"
	"strings"
	"testing"
)

func parts() ([]byte, []byte) {
	return bytes.Repeat([]byte{0x11}, IDSize), bytes.Repeat([]byte{0xee}, SecretSize)
}

func TestRoundTrip(t *testing.T) {
	id, sec := parts()
	tok, err := Encode(DefaultPrefix, KindService, id, sec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(tok), "goraz_st_") {
		t.Fatalf("prefix: %s", tok)
	}
	p, err := Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.ID[:], id) || !bytes.Equal(p.Secret[:], sec) || p.Kind != KindService || p.Prefix != "goraz" {
		t.Fatalf("mismatch: %+v", p)
	}
}

func TestExtremeValues(t *testing.T) {
	for _, b := range []byte{0x00, 0xff} {
		tok, err := Encode("ab", KindMachine, bytes.Repeat([]byte{b}, IDSize), bytes.Repeat([]byte{b}, SecretSize))
		if err != nil {
			t.Fatal(err)
		}
		p, err := Parse(tok)
		if err != nil {
			t.Fatal(err)
		}
		if p.ID[0] != b || p.Secret[31] != b {
			t.Fatal("value not preserved")
		}
	}
}

func TestHostileTokens(t *testing.T) {
	id, sec := parts()
	raw, err := Encode(DefaultPrefix, KindService, id, sec)
	if err != nil {
		t.Fatal(err)
	}
	good := string(raw)
	cases := map[string]string{
		"empty":           "",
		"no separators":   strings.ReplaceAll(good, "_", ""),
		"trailing space":  good + " ",
		"leading space":   " " + good,
		"trailing nl":     good + "\n",
		"upper prefix":    "GORAZ" + good[5:],
		"unknown kind":    "goraz_xx_" + good[9:],
		"rc kind":         "goraz_rc_" + good[9:],
		"short":           good[:len(good)-1],
		"bad checksum":    good[:len(good)-1] + flip(good[len(good)-1]),
		"bad body char":   good[:12] + "!" + good[13:],
		"long prefix":     "abcdefghijk" + good[5:],
		"too long":        good + strings.Repeat("0", 200),
		"percent encoded": strings.ReplaceAll(good, "_", "%5F"),
	}
	for name, s := range cases {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func flip(c byte) string {
	if c == '0' {
		return "1"
	}
	return "0"
}

func TestNonCanonicalBodyRejected(t *testing.T) {
	// A body above 2^384 must be refused even with a correct checksum.
	head := []byte("goraz_st_" + strings.Repeat("z", bodyChars))
	var sum [checkChars]byte
	checksum(sum[:], head)
	if _, err := Parse(append(head, sum[:]...)); err == nil {
		t.Fatal("oversized body accepted")
	}
}

func TestChecksumDetectsEverySingleCharChange(t *testing.T) {
	id, sec := parts()
	raw, err := Encode(DefaultPrefix, KindService, id, sec)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		m := bytes.Clone(raw)
		m[i] = '7'
		if bytes.Equal(m, raw) {
			m[i] = '8'
		}
		if _, err := Parse(m); err == nil {
			t.Fatalf("change at %d accepted", i)
		}
	}
}

func TestEncodeRejectsBadInput(t *testing.T) {
	id, sec := parts()
	if _, err := Encode("A", KindService, id, sec); err == nil {
		t.Error("bad prefix accepted")
	}
	if _, err := Encode("goraz", "rc", id, sec); err == nil {
		t.Error("bad kind accepted")
	}
	if _, err := Encode("goraz", KindService, id[:1], sec); err == nil {
		t.Error("bad id accepted")
	}
	if _, err := Encode("goraz", KindService, id, sec[:1]); err == nil {
		t.Error("bad secret accepted")
	}
}

func TestRecoveryRoundTripAndTyping(t *testing.T) {
	code := bytes.Repeat([]byte{0x5a}, 32)
	code[0] = 0
	s, err := EncodeRecovery(code)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(s), "GORAZ-RC-") {
		t.Fatalf("prefix: %s", s)
	}
	str := string(s)
	forms := []string{
		str,
		strings.ToLower(str),
		strings.ReplaceAll(str, "-", ""),
		strings.ReplaceAll(str, "-", " "),
		strings.ReplaceAll(str, "0", "O"),
		strings.ReplaceAll(str, "1", "l"),
	}
	for _, f := range forms {
		got, err := ParseRecovery([]byte(f))
		if err != nil {
			t.Errorf("%q: %v", f, err)
			continue
		}
		if !bytes.Equal(got, code) {
			t.Errorf("%q: wrong value", f)
		}
	}
}

func TestRecoveryRejects(t *testing.T) {
	enc, err := EncodeRecovery(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := string(enc)
	i := len(s) - 1
	wrong := s[:i] + "Z"
	if s[i] == 'Z' {
		wrong = s[:i] + "Y"
	}
	for _, in := range []string{"", "GORAZ-RC-", "nope", wrong, s + "0000", strings.Repeat("A", 200)} {
		if _, err := ParseRecovery([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if _, err := EncodeRecovery(make([]byte, 31)); err == nil {
		t.Error("short code accepted")
	}
}

func FuzzParse(f *testing.F) {
	id, sec := parts()
	raw, err := Encode(DefaultPrefix, KindService, id, sec)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte("goraz_st_"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err != nil {
			return
		}
		re, err := Encode(p.Prefix, p.Kind, p.ID[:], p.Secret[:])
		if err != nil {
			t.Fatalf("accepted token can't be re-encoded: %v", err)
		}
		if !bytes.Equal(re, b) {
			t.Fatalf("non-canonical token accepted: %q", b)
		}
	})
}

func FuzzParseRecovery(f *testing.F) {
	s, err := EncodeRecovery(make([]byte, 32))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(s)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		code, err := ParseRecovery(b)
		if err == nil && len(code) != 32 {
			t.Fatal("wrong code size")
		}
	})
}

// The new arithmetic must match an independent big-integer implementation.
func TestBase62MatchesBigInt(t *testing.T) {
	for _, fill := range []byte{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff} {
		raw := bytes.Repeat([]byte{fill}, rawSize)
		raw[0] ^= 0x5a
		got := make([]byte, bodyChars)
		encodeBase62(got, raw)
		v := new(big.Int).SetBytes(raw)
		want := make([]byte, bodyChars)
		mod := new(big.Int)
		b62 := big.NewInt(62)
		for i := bodyChars - 1; i >= 0; i-- {
			v.DivMod(v, b62, mod)
			want[i] = alphabet[mod.Int64()]
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("fill %x: got %s want %s", fill, got, want)
		}
		back := make([]byte, rawSize)
		if !decodeBase62(back, got) || !bytes.Equal(back, raw) {
			t.Fatalf("fill %x: round trip failed", fill)
		}
	}
}

// A golden token freezes the format, so existing tokens keep verifying.
func TestTokenGolden(t *testing.T) {
	id := bytes.Repeat([]byte{0x11}, IDSize)
	sec := bytes.Repeat([]byte{0xee}, SecretSize)
	tok, err := Encode(DefaultPrefix, KindService, id, sec)
	if err != nil {
		t.Fatal(err)
	}
	const want = "goraz_st_0VWylGGClvhya2uxX1Da7kqyY40aauNFgHMxUcQPQosAHItGY7GqkWuR1mpFOdH262FyQXd"
	if string(tok) != want {
		t.Fatalf("token format changed: %s", tok)
	}
}

func TestRecoveryGolden(t *testing.T) {
	r, err := EncodeRecovery(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	const want = "GORAZ-RC-B9D5-MPJT-B9D5-MPJT-B9D5-MPJT-B9D5-MPJT-B9D5-MPJT-B9D5-MPJT-B9D6-1FR"
	if string(r) != want {
		t.Fatalf("recovery code format changed: %s", r)
	}
}
