package audit_test

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mtnaskari/goraz/audit"
)

// A service sends one JSON event per line to stdout, for its log system. An event
// never holds a name or a value: the object is an HMAC of the name.
func ExampleJSONSink() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	sink := audit.NewJSONSink(os.Stdout)
	err := sink.Record(audit.Event{
		Type:    audit.EventItemRead,
		Outcome: audit.OK,
		Actor:   audit.ActorMachine,
		Object:  audit.ObjectHash(key, "prod/api/stripe"),
	})
	fmt.Println(err)
}

// A chained log detects edits and removed entries.
func ExampleVerify() {
	dir, err := os.MkdirTemp("", "audit-example")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	keys := audit.Keys{Active: 1, All: map[uint32][]byte{1: make([]byte, 32)}}
	path := filepath.Join(dir, "device.log")

	log := audit.OpenLog(path, audit.LogOptions{Keys: keys})
	for range 3 {
		if err := log.Record(audit.Event{Type: audit.EventVaultOpen, Outcome: audit.OK, Actor: audit.ActorPassphrase}); err != nil {
			panic(err)
		}
	}
	r, err := audit.Verify(path, keys, log.Head())
	fmt.Println(r.Entries, err)
	// Output: 3 <nil>
}
