package benchplan

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// goldenWL01Order was derived with an independent Python hashlib
// implementation of the frozen seed rule (not with this package), so a
// drift in the Go implementation cannot re-derive its own expectation.
var goldenWL01Order = []string{
	"JAVA_FIRST", "RUST_FIRST", "JAVA_FIRST", "JAVA_FIRST", "JAVA_FIRST",
	"RUST_FIRST", "JAVA_FIRST", "JAVA_FIRST", "JAVA_FIRST", "RUST_FIRST",
	"JAVA_FIRST", "JAVA_FIRST", "RUST_FIRST", "JAVA_FIRST", "JAVA_FIRST",
	"RUST_FIRST", "RUST_FIRST", "JAVA_FIRST", "RUST_FIRST", "JAVA_FIRST",
	"JAVA_FIRST", "RUST_FIRST", "JAVA_FIRST", "JAVA_FIRST", "JAVA_FIRST",
	"RUST_FIRST", "RUST_FIRST", "JAVA_FIRST", "RUST_FIRST", "JAVA_FIRST",
	"JAVA_FIRST", "RUST_FIRST", "RUST_FIRST", "JAVA_FIRST", "JAVA_FIRST",
}

func TestSeedStringFormat(t *testing.T) {
	got := SeedString("wl-01-handshake-close")
	want := "vjwp-us008-pair-order|v1|wl-01-handshake-close"
	if got != want {
		t.Fatalf("seed string %q, want %q", got, want)
	}
}

func TestPairOrderMatchesIndependentGoldenVector(t *testing.T) {
	order, err := PairOrder("wl-01-handshake-close")
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != TotalPairs {
		t.Fatalf("order length %d, want %d", len(order), TotalPairs)
	}
	for i, entry := range order {
		if entry != goldenWL01Order[i] {
			t.Fatalf("pair %d: got %s, want %s (independent golden vector)", i, entry, goldenWL01Order[i])
		}
	}
}

func TestPairOrderConformsToWrittenSpec(t *testing.T) {
	// Re-derive the order directly from the spec text, written out
	// literally, for every workload.
	for _, workloadID := range WorkloadIDs {
		order, err := PairOrder(workloadID)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 35; i++ {
			material := "vjwp-us008-pair-order|v1|" + workloadID + "|" + fmt.Sprintf("%d", i)
			digest := sha256.Sum256([]byte(material))
			want := "JAVA_FIRST"
			if digest[0]%2 == 1 {
				want = "RUST_FIRST"
			}
			if order[i] != want {
				t.Fatalf("%s pair %d: got %s, spec derives %s", workloadID, i, order[i], want)
			}
		}
	}
}

func TestPairOrderIsDeterministicAndWorkloadDistinct(t *testing.T) {
	first, err := PairOrder("wl-02-small-text-echo")
	if err != nil {
		t.Fatal(err)
	}
	second, err := PairOrder("wl-02-small-text-echo")
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("pair order not deterministic at index %d", i)
		}
	}
	other, err := PairOrder("wl-03-fragmented-64kib-binary-echo")
	if err != nil {
		t.Fatal(err)
	}
	same := true
	for i := range first {
		if first[i] != other[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two different workloads derived identical orders; seed must incorporate the workload id")
	}
}

func TestPairOrderRejectsUnknownWorkload(t *testing.T) {
	if _, err := PairOrder("wl-99-not-preregistered"); err == nil {
		t.Fatal("expected error for unknown workload id")
	}
}
