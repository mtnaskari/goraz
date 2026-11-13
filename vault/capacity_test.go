package vault

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/mtnaskari/goraz/internal/format"
	"github.com/mtnaskari/goraz/secret"
)

// A vault must stay correct at the sizes the documentation promises.
func TestCapacity(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	e, v := newEnv(t)
	const items = 300
	value := bytes.Repeat([]byte("v"), 4096)
	for i := range items {
		if err := v.Put(&Item{Name: fmt.Sprintf("team/service%d/token", i), Value: secret.New(value)}); err != nil {
			t.Fatal(err)
		}
	}
	big := bytes.Repeat([]byte{0xAB}, format.MaxValueSize)
	if err := v.Put(&Item{Name: "big", Value: secret.New(big)}); err != nil {
		t.Fatal(err)
	}
	v.Close()
	r, err := e.open(t, Options{})
	if err != nil {
		t.Fatal(err)
	}
	list, err := r.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != items+1 {
		t.Fatalf("%d items", len(list))
	}
	it, err := r.Get("big")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(it.Value.Bytes(), big) {
		t.Error("the largest value changed")
	}
	bad, err := r.FullCheck()
	if err != nil || len(bad) != 0 {
		t.Errorf("%v %v", bad, err)
	}
	st, err := os.Stat(e.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("file size with %d items: %d bytes", items+1, st.Size())
}

func benchVault(b *testing.B, items int) *Vault {
	b.Helper()
	_, v := newEnv(b)
	value := bytes.Repeat([]byte("v"), 256)
	for i := range items {
		if err := v.Put(&Item{Name: fmt.Sprintf("team/service%d/token", i), Value: secret.New(value)}); err != nil {
			b.Fatal(err)
		}
	}
	return v
}

func BenchmarkGet(b *testing.B) {
	v := benchVault(b, 100)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.Get("team/service50/token"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPut100Items(b *testing.B) {
	v := benchVault(b, 100)
	value := bytes.Repeat([]byte("n"), 256)
	b.ReportAllocs()
	for b.Loop() {
		if err := v.Put(&Item{Name: "team/service50/token", Value: secret.New(value)}); err != nil {
			b.Fatal(err)
		}
	}
}
