package names

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	for _, n := range []string{"a", "prod/db/password", "A.b_c-d/1", "..a", "a..", "...", strings.Repeat("x", MaxLength), strings.Repeat("a/", MaxSegments-1) + "a"} {
		if err := Validate(n); err != nil {
			t.Errorf("%q rejected", n)
		}
	}
}

// A corpus of hostile names, drawn from published bypasses in other projects.
func TestHostile(t *testing.T) {
	for _, n := range []string{
		"", "/", "/a", "a/", "a//b", ".", "..", "./a", "a/.", "../a", "a/../b", "a/..",
		"a b", " a", "a ", "a\t", "a\n", "a\x00", "a%2e%2e/b", "%2E%2E%2F", "a\\b", "..\\a",
		"café", "a\u200b", "a\u202e", "ａ", "ａ", "a:b", "a*", "a?", "a#b", "a@b", "a+b", "~a", "$a", "{{a}}",
		strings.Repeat("x", MaxLength+1), strings.Repeat("a/", MaxSegments) + "a",
	} {
		if err := Validate(n); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestHasPrefix(t *testing.T) {
	cases := []struct {
		name, prefix string
		want         bool
	}{
		{"prod/api", "prod/api", true},
		{"prod/api/x", "prod/api", true},
		{"prod/apiary", "prod/api", false},
		{"prod", "prod/api", false},
		{"Prod/api", "prod/api", false},
	}
	for _, c := range cases {
		if got := HasPrefix(c.name, c.prefix); got != c.want {
			t.Errorf("HasPrefix(%q, %q) = %v", c.name, c.prefix, got)
		}
	}
}

func TestFoldKey(t *testing.T) {
	if FoldKey("Prod/DB") != FoldKey("prod/db") {
		t.Error("case variants should collide")
	}
}

func FuzzValidate(f *testing.F) {
	for _, s := range []string{"a/b", "../x", "a//b", "a\x00", "%2e"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if Validate(s) != nil {
			return
		}
		if len(s) > MaxLength || strings.Contains(s, "//") || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
			t.Fatalf("accepted %q", s)
		}
		for seg := range strings.SplitSeq(s, "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("accepted traversal %q", s)
			}
		}
		for _, r := range s {
			if r > 127 || r <= ' ' {
				t.Fatalf("accepted character in %q", s)
			}
		}
	})
}
