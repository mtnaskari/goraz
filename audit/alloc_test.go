package audit

import (
	"io"
	"testing"
)

// Allocation counts are exact, unlike timings on shared CI machines, so a budget can
// gate a regression in the hot path.
func TestAllocationBudgets(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("allocation counts differ under the race detector")
	}
	s := NewJSONSink(io.Discard)
	e := Event{Type: EventItemRead, Outcome: OK, Actor: ActorMachine, Object: make([]byte, 32)}
	if n := testing.AllocsPerRun(200, func() { _ = s.Record(e) }); n > 0 {
		t.Errorf("JSONSink.Record: %.0f allocations, budget 0", n)
	}
}
