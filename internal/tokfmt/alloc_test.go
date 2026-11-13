package tokfmt

import (
	"bytes"
	"testing"
)

func TestAllocationBudgets(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("allocation counts differ under the race detector")
	}
	tok, err := Encode(DefaultPrefix, KindService, make([]byte, IDSize), bytes.Repeat([]byte{7}, SecretSize))
	if err != nil {
		t.Fatal(err)
	}
	// The result struct and its prefix string.
	if n := testing.AllocsPerRun(200, func() { _, _ = Parse(tok) }); n > 2 {
		t.Errorf("Parse: %.0f allocations, budget 2", n)
	}
}
