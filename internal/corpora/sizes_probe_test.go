package corpora

import "testing"

// Non-assertive size log used during development review; kept as a cheap
// regression signal that every tier stays populated.
func TestGeneratedSizesAreLogged(t *testing.T) {
	g, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	t.Logf("public=%d hidden=%d sealed=%d handshake=%d plans=%+v",
		len(g.Public), len(g.Hidden), len(g.Sealed), len(g.Handshake), g.PlanCounts)
	if len(g.Public) < 40 || len(g.Hidden) < 40 || len(g.Sealed) < 40 || len(g.Handshake) < 30 {
		t.Fatalf("corpus tiers unexpectedly small: %d/%d/%d/%d",
			len(g.Public), len(g.Hidden), len(g.Sealed), len(g.Handshake))
	}
}
