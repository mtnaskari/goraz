package vault_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mtnaskari/goraz/secret"
	"github.com/mtnaskari/goraz/vault"
)

// Create a vault, store a secret and read it back. The recovery code is shown once,
// and it is the only way in if the passphrase is lost.
func Example() {
	dir, err := os.MkdirTemp("", "vault-example")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	opts := vault.Options{StateDir: filepath.Join(dir, "state")}

	v, recovery, err := vault.Create(filepath.Join(dir, "v.goraz"), vault.CreateOptions{
		Passphrase: []byte("violet granite ocean drift lantern"),
		Profile:    vault.ProfileInteractive, // Real vaults should keep the default, ProfileStrong.
		Options:    opts,
	})
	if err != nil {
		panic(err)
	}
	defer v.Close()
	recovery.Wipe()

	if err := v.Put(&vault.Item{Name: "prod/db/password", Value: secret.New([]byte("s3cret"))}); err != nil {
		panic(err)
	}
	it, err := v.Get("prod/db/password")
	if err != nil {
		panic(err)
	}
	defer it.Wipe()
	fmt.Println(it.Name, string(it.Value.Bytes()), it.Version)
	// Output: prod/db/password s3cret 1
}
