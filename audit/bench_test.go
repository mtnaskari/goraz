package audit

import (
	"io"
	"testing"
)

func BenchmarkJSONSink(b *testing.B) {
	s := NewJSONSink(io.Discard)
	e := Event{Type: EventItemRead, Outcome: OK, Actor: ActorMachine, Object: make([]byte, 32)}
	b.ReportAllocs()
	for b.Loop() {
		if err := s.Record(e); err != nil {
			b.Fatal(err)
		}
	}
}
