package envelope

import (
	"bytes"
	"testing"
)

func BenchmarkSeal1KiB(b *testing.B) {
	key := bytes.Repeat([]byte{1}, KeySize)
	pt := make([]byte, 1024)
	b.SetBytes(int64(len(pt)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Seal(key, DomainItem, []byte("context"), pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpen1KiB(b *testing.B) {
	key := bytes.Repeat([]byte{1}, KeySize)
	blob, err := Seal(key, DomainItem, []byte("context"), make([]byte, 1024))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(1024)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Open(key, DomainItem, []byte("context"), blob); err != nil {
			b.Fatal(err)
		}
	}
}
