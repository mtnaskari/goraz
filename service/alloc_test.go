package service

import (
	"context"
	"testing"
)

func TestAllocationBudgets(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("allocation counts differ under the race detector")
	}
	c, tok := benchClientT(t)
	if n := testing.AllocsPerRun(100, func() { _, _ = c.Value("prod/api/x") }); n > 44 {
		t.Errorf("Value: %.0f allocations, budget 44", n)
	}
	v, err := c.Verifier(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if n := testing.AllocsPerRun(100, func() { _, _ = v.Verify(ctx, tok, "s") }); n > 14 {
		t.Errorf("Verify: %.0f allocations, budget 14", n)
	}
}
