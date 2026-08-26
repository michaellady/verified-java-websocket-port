// Package benchplan implements the US-008 benchmark preregistration:
// the executable SHA-256 pair-order specification, the frozen paired
// natural-log ratio statistics engine, the frozen power model, the
// fail-closed decision rule, and the document validator that reports
// exactly which binding fields remain unbound.
//
// NOTHING in this package measures anything. It is validated exclusively
// against synthetic fixtures labeled SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT
// and against published statistical tables. Producing, storing, or
// implying a real benchmark measurement is out of scope by design and
// remains owner-gated (HOST_BINDING_PENDING).
package benchplan

import (
	"crypto/sha256"
	"fmt"
	"strconv"
)

// Frozen pair-order specification (executable form of the preregistration
// in benchmarks/plan/workloads.json). Changing any constant here is a
// change to the preregistration and must be reflected in the plan document
// and its schema, or verification fails.
const (
	// SeedSpecVersion is the frozen seed-derivation rule identifier.
	SeedSpecVersion = "vjwp-us008-pair-order|v1"
	// WarmupPairs are excluded from analysis (pair indices 0..4).
	WarmupPairs = 5
	// MeasuredPairs enter analysis (pair indices 5..34).
	MeasuredPairs = 30
	// TotalPairs is warmup + measured.
	TotalPairs = WarmupPairs + MeasuredPairs
)

// Pair-order values.
const (
	JavaFirst = "JAVA_FIRST"
	RustFirst = "RUST_FIRST"
)

// WorkloadIDs is the frozen, ordered set of the six preregistered
// workloads. The plan document must contain exactly these, in this order.
var WorkloadIDs = []string{
	"wl-01-handshake-close",
	"wl-02-small-text-echo",
	"wl-03-fragmented-64kib-binary-echo",
	"wl-04-control-mix",
	"wl-05-cap-rejection",
	"wl-06-concurrent-pressure",
}

// SeedString returns the frozen per-workload seed string:
//
//	SeedSpecVersion + "|" + workloadID
func SeedString(workloadID string) string {
	return SeedSpecVersion + "|" + workloadID
}

// PairOrder derives the deterministic randomized Java/Rust order for all
// 35 pairs (5 warmup + 30 measured) of one workload. The frozen rule:
//
//	for pair index i in 0..34:
//	  digest = SHA-256( ASCII( SeedString(workloadID) + "|" + decimal(i) ) )
//	  order[i] = JAVA_FIRST if digest[0] is even, RUST_FIRST if odd
//
// The rule is pure: given the frozen seed string it admits no discretion,
// so the order cannot be re-rolled after results are known.
func PairOrder(workloadID string) ([]string, error) {
	if !isKnownWorkload(workloadID) {
		return nil, fmt.Errorf("unknown workload id %q", workloadID)
	}
	order := make([]string, TotalPairs)
	seed := SeedString(workloadID)
	for i := 0; i < TotalPairs; i++ {
		digest := sha256.Sum256([]byte(seed + "|" + strconv.Itoa(i)))
		if digest[0]%2 == 0 {
			order[i] = JavaFirst
		} else {
			order[i] = RustFirst
		}
	}
	return order, nil
}

func isKnownWorkload(workloadID string) bool {
	for _, known := range WorkloadIDs {
		if known == workloadID {
			return true
		}
	}
	return false
}
