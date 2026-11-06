package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/kdf"
	"github.com/mtnaskari/goraz/secret"
)

const (
	goldenPath    = "testdata/golden-v1.goraz"
	goldenKeyPath = "testdata/golden-v1.machine-key"
	goldenPass    = "golden vector passphrase, not a real secret"
)

// The golden file freezes format v1. If this test fails, the format has changed, and
// every existing vault would be unreadable. It must open forever.
func TestGoldenVaultOpens(t *testing.T) {
	if *update {
		writeGolden(t)
	}
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(goldenKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Credential{
		"machine":    WithMachineKeys(key),
		"passphrase": WithPassphrase([]byte(goldenPass), nil),
	} {
		v, err := openReadOnly(data, c, Options{Audit: audit.Discard})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		it, err := v.Get("prod/db/password")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(it.Value.Bytes()) != "golden-value" || it.Username != "golden-user" || it.Type != TypeLogin {
			t.Fatalf("%s: %+v", name, it)
		}
		old, err := v.GetVersion("prod/db/password", 1)
		if err != nil || string(old.Value.Bytes()) != "first-value" {
			t.Fatalf("%s: history: %v", name, err)
		}
		v.Close()
	}
}

func writeGolden(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "g")
	v, _, err := Create(p, CreateOptions{
		Passphrase: []byte(goldenPass), Profile: kdf.Interactive,
		Options: Options{StateDir: dir, Now: func() time.Time { return time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC) }},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Put(&Item{Name: "prod/db/password", Type: TypeLogin, Value: secret.New([]byte("first-value")), Username: "golden-user"}); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(&Item{Name: "prod/db/password", Type: TypeLogin, Value: secret.New([]byte("golden-value")), Username: "golden-user"}); err != nil {
		t.Fatal(err)
	}
	k, err := v.AddMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("testdata", 0o750); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p) // #nosec G304 -- test path.
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goldenPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goldenKeyPath, k.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
