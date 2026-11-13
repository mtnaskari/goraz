package projecttest

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const module = "github.com/mtnaskari/goraz"

// The public packages. A new one must be added here, so it gets these checks.
var public = []string{"audit", "password", "password/hibp", "secret", "service", "token", "vault"}

func root(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(strings.TrimSpace(string(out)))
}

func goCmd(t *testing.T, args ...string) string {
	t.Helper()
	c := exec.Command("go", args...) // #nosec G204 -- the go command with fixed arguments.
	c.Dir = root(t)
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("go %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// Dependencies are the attack surface of a secrets library, so only the standard
// library and the Go project's own golang.org/x modules are allowed.
func TestDependencies(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	out := goCmd(t, "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "./...")
	for dep := range strings.FieldsSeq(out) {
		if !strings.HasPrefix(dep, module) && !strings.HasPrefix(dep, "golang.org/x/") {
			t.Errorf("dependency outside the allowlist: %s", dep)
		}
	}
	// A production service shouldn't link code that makes network requests or runs
	// programs, so a bug elsewhere can't reach those capabilities from it.
	for _, pkg := range []string{"service", "vault", "token", "audit", "secret"} {
		for d := range strings.FieldsSeq(goCmd(t, "list", "-deps", module+"/"+pkg)) {
			switch d {
			case "net/http", "os/exec", "net", "unsafe", "reflect":
				if d == "unsafe" || d == "reflect" {
					continue // The standard library uses these internally.
				}
				t.Errorf("%s links %s", pkg, d)
			}
		}
	}
}

var internalName = regexp.MustCompile(`\b(envelope|format|fsutil|harden|kdf|names|state|tokfmt)\.[A-Z]`)

// A public API that takes or returns an internal type can't be used fully from
// outside the module.
func TestPublicAPIUsesNoInternalTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	for _, pkg := range public {
		doc := goCmd(t, "doc", "-all", "./"+pkg)
		for i, line := range strings.Split(doc, "\n") {
			if internalName.MatchString(line) {
				t.Errorf("%s, line %d of go doc: %s", pkg, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// Each public package has a package comment and a runnable example, which pkg.go.dev
// shows and go test runs.
func TestPackagesHaveExamples(t *testing.T) {
	r := root(t)
	for _, pkg := range public {
		files, err := filepath.Glob(filepath.Join(r, pkg, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range files {
			b, err := os.ReadFile(f) // #nosec G304 -- files of this module.
			if err != nil {
				t.Fatal(err)
			}
			if regexp.MustCompile(`(?m)^func Example`).Match(b) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s has no runnable example", pkg)
		}
		src, err := filepath.Glob(filepath.Join(r, pkg, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		comment := false
		for _, f := range src {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f) // #nosec G304 -- files of this module.
			if err != nil {
				t.Fatal(err)
			}
			if regexp.MustCompile(`(?m)^// Package \S+ `).Match(b) {
				comment = true
			}
		}
		if !comment {
			t.Errorf("%s has no package comment", pkg)
		}
	}
}
