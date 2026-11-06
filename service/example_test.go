package service_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/kdf"
	"github.com/mtnaskari/goraz/secret"
	"github.com/mtnaskari/goraz/service"
	"github.com/mtnaskari/goraz/vault"
)

// A production service reads its API token from its own encrypted file. The first part
// runs on the operator's machine, and usually happens through the goraz command.
func Example() {
	dir, err := os.MkdirTemp("", "goraz-example")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// On the operator's machine.
	main, _, err := vault.Create(filepath.Join(dir, "main.goraz"), vault.CreateOptions{
		Passphrase: []byte("violet granite ocean drift lantern"),
		Profile:    kdf.Interactive,
		Options:    vault.Options{StateDir: filepath.Join(dir, "state")},
	})
	if err != nil {
		panic(err)
	}
	defer main.Close()
	if err := main.Put(&vault.Item{Name: "prod/api/stripe", Value: secret.New([]byte("sk_example"))}); err != nil {
		panic(err)
	}
	file := filepath.Join(dir, "api.goraz")
	key, err := main.CreateService("api", file, vault.ServiceOptions{Prefixes: []string{"prod/api"}})
	if err != nil {
		panic(err)
	}

	// In the service. A deployment would use service.KeyFile instead of StaticKeys, and
	// send the audit stream to its log system.
	c, err := service.Open(context.Background(), service.Options{
		Path:     file,
		Key:      service.StaticKeys(key.Bytes()),
		Audit:    audit.Discard,
		Interval: 30 * time.Second,
	})
	if err != nil {
		panic(err)
	}
	defer c.Close()

	v, err := c.Value("prod/api/stripe")
	if err != nil {
		panic(err)
	}
	defer v.Wipe()
	fmt.Println(string(v.Bytes()))
	// Output: sk_example
}
