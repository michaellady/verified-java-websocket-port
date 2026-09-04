package normcollide

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestPartitionCensusRefusesAnUnclassifiedShape attacks the surface-partition
// check directly. It lives out here rather than inside Build because Build
// needs a harness binary, and a deletion attack proved a check that only fires
// inside Build has no test in the default suite: disabling it left the whole
// suite green.
func TestPartitionCensusRefusesAnUnclassifiedShape(t *testing.T) {
	err := PartitionCensus([]Census{{
		Source:  "synthetic",
		KeySets: []KeySetCount{{Keys: []string{"a", "b"}, Rows: 1, Projection: ""}},
	}})
	if err == nil {
		t.Fatal("PartitionCensus accepted a response shape no projection classifies; " +
			"delete the check and this passes while the surface table rots")
	}
	if !strings.Contains(err.Error(), "surface table is incomplete") {
		t.Fatalf("wrong rejection: %v", err)
	}
	// Positive control: a classified shape must pass, or the check is just a
	// constant failure and proves nothing either.
	if err := PartitionCensus([]Census{{
		Source:  "synthetic",
		KeySets: []KeySetCount{{Keys: []string{"events"}, Rows: 1, Projection: "behaviour.ok"}},
	}}); err != nil {
		t.Fatalf("PartitionCensus rejected a classified shape: %v", err)
	}
}

// TestPublicCensusMeasuresTheShippedTranscript runs the census itself over the
// committed real-Java arm rather than reading numbers back out of the
// document. The exact values are pinned: if the corpus ever stops collapsing
// two rows into one observation, the correct response is to RESTATE the 74/74
// bound, not to relax this assertion.
func TestPublicCensusMeasuresTheShippedTranscript(t *testing.T) {
	census, err := MeasureTranscript(
		filepath.Join(repoRoot(t), PublicArmPath), ClassifyBehaviourKeys)
	if err != nil {
		t.Fatal(err)
	}
	if census.Rows != 74 {
		t.Fatalf("public arm has %d rows, expected 74", census.Rows)
	}
	if census.DistinctScoredRows != 73 {
		t.Fatalf("public arm carries %d distinct scored observations, expected 73; "+
			"the 74/74 bound is stated against 73 and must be restated, not relaxed",
			census.DistinctScoredRows)
	}
	if census.RowsSharingAnObservation != 2 || census.LargestClass != 2 {
		t.Fatalf("public arm: %d rows share an observation, largest class %d; expected 2 and 2 "+
			"(us005.pub.0039 and us005.pub.0066, probe NC-04)",
			census.RowsSharingAnObservation, census.LargestClass)
	}
	// The key-sets must partition as the surface table says: 48 ok rows and
	// 26 failure rows, and nothing else.
	shapes := map[string]int{}
	for _, keySet := range census.KeySets {
		shapes[keySet.Projection] += keySet.Rows
	}
	if shapes["behaviour.ok"] != 48 || shapes["behaviour.failure"] != 26 || len(shapes) != 2 {
		t.Fatalf("public arm partitions as %v, expected 48 behaviour.ok and 26 behaviour.failure",
			shapes)
	}
}

// TestClassifyRefusesToGuess is the guard under the partition: an unknown
// shape must return the empty string rather than being filed under whichever
// projection happens to match last.
func TestClassifyRefusesToGuess(t *testing.T) {
	if got := ClassifyBehaviourKeys([]string{"nothing", "recognisable"}); got != "" {
		t.Fatalf("ClassifyBehaviourKeys guessed %q for an unknown shape", got)
	}
	if got := ClassifyHandshakeKeys([]string{"nothing", "recognisable"}); got != "" {
		t.Fatalf("ClassifyHandshakeKeys guessed %q for an unknown shape", got)
	}
	if got := ClassifyBehaviourKeys([]string{"events", "frames", "transitions"}); got != "behaviour.ok" {
		t.Fatalf("ClassifyBehaviourKeys returned %q for an ok shape", got)
	}
}
