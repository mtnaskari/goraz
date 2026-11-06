package secret

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestSecretNeverPrints(t *testing.T) {
	const canary = "correct-horse-canary"
	s := New([]byte(canary))
	type wrap struct {
		S Secret
		P *Secret
	}
	w := wrap{S: s, P: &s}

	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T%v"} {
		if out := fmt.Sprintf(format, s); strings.Contains(out, canary) || strings.Contains(out, "636f7272") {
			t.Errorf("format %q leaked: %s", format, out)
		}
		if out := fmt.Sprintf(format, w); strings.Contains(out, canary) {
			t.Errorf("format %q leaked through struct: %s", format, out)
		}
	}

	raw, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) || strings.Contains(string(raw), "Y29ycmVjd") {
		t.Errorf("JSON leaked: %s", raw)
	}

	var sb strings.Builder
	log.New(&sb, "", 0).Printf("%v %s", s, s)
	if strings.Contains(sb.String(), canary) {
		t.Errorf("log leaked: %s", sb.String())
	}
}

func TestNewCopiesAndWipe(t *testing.T) {
	in := []byte("value")
	s := New(in)
	in[0] = 'X'
	if string(s.Bytes()) != "value" {
		t.Fatal("New did not copy its input")
	}
	view := s.Bytes()
	s.Wipe()
	for _, b := range view {
		if b != 0 {
			t.Fatal("Wipe left data behind")
		}
	}
}

func TestEqual(t *testing.T) {
	if !New([]byte("a")).Equal(New([]byte("a"))) {
		t.Error("equal secrets compared unequal")
	}
	if New([]byte("a")).Equal(New([]byte("b"))) || New([]byte("a")).Equal(New([]byte("aa"))) {
		t.Error("different secrets compared equal")
	}
}

func TestZeroValue(t *testing.T) {
	var s Secret
	if !s.IsZero() || s.Len() != 0 {
		t.Error("zero value should be empty")
	}
	s.Wipe()
	if !Adopt(nil).IsZero() {
		t.Error("Adopt(nil) should be empty")
	}
}
