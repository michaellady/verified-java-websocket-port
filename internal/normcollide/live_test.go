//go:build normcollide

// This file re-runs the whole audit against a real ws-oracle-harness binary.
// It is build-tagged because it needs that binary, which the default
// `go test ./...` must not require. Run it with:
//
//	cargo build -p ws-oracle-harness --manifest-path rust/Cargo.toml
//	WS_ORACLE_HARNESS=rust/target/debug/ws-oracle-harness \
//	  go test -tags normcollide ./internal/normcollide/
//
// Once the tag is selected this gate is NEVER skipped: a missing binary is a
// failure, not a pass, because a skipped collision audit that reports success
// is exactly the failure mode this whole package exists to attack.
package normcollide

import (
	"os"
	"path/filepath"
	"testing"
)

func liveRunner(t *testing.T) Runner {
	t.Helper()
	binary := os.Getenv("WS_ORACLE_HARNESS")
	if binary == "" {
		t.Fatal("WS_ORACLE_HARNESS must name the ws-oracle-harness binary; " +
			"this gate is never skipped once its tag is selected")
	}
	absolute, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(absolute); err != nil {
		t.Fatalf("WS_ORACLE_HARNESS: %v", err)
	}
	digest, err := FileDigest(absolute)
	if err != nil {
		t.Fatal(err)
	}
	return stableIdentityRunner{HarnessRunner{Binary: absolute, Digest: digest}}
}

// stableIdentityRunner mirrors cmd/normcollidectl: it runs the absolute
// binary but reports a path-independent identity, so the committed document
// is reproducible on any machine while the DIGEST still pins which binary
// answered.
type stableIdentityRunner struct{ inner HarnessRunner }

func (r stableIdentityRunner) Run(lines []string) ([]string, error) { return r.inner.Run(lines) }
func (r stableIdentityRunner) Identity() string                     { return "ws-oracle-harness " + r.inner.Digest }

// TestCommittedAuditMatchesAFreshRun is the drift gate. The committed document
// is never an input to the recomputation, so this cannot pass by copying it.
func TestCommittedAuditMatchesAFreshRun(t *testing.T) {
	if err := Verify(repoRoot(t), liveRunner(t)); err != nil {
		t.Fatalf("committed audit document drifted: %v", err)
	}
}

// TestEveryCatalogProbeStillHoldsAgainstTheRealHarness decides the catalog
// again from scratch and fails on any REFUTED probe. A probe that stops
// holding is a finding about the catalog, not a reason to relax it: the
// correct response is to reclassify the probe, never to drop the assertion.
func TestEveryCatalogProbeStillHoldsAgainstTheRealHarness(t *testing.T) {
	runner := liveRunner(t)
	for _, probe := range Probes() {
		result, err := Decide(runner, probe)
		if err != nil {
			t.Fatalf("%s: %v", probe.ID, err)
		}
		if result.Verdict != Confirmed {
			t.Fatalf("%s is now %s; its collision pair moved %v. The surface represents a "+
				"distinction this catalog says it erases — reclassify the probe, do not weaken it.",
				probe.ID, result.Verdict, result.CollisionPaths)
		}
		if result.WitnessKind == "pair" && len(result.WitnessPaths) == 0 {
			t.Fatalf("%s: the witness pair stopped moving, so the probe no longer shows the two "+
				"behaviours differ", probe.ID)
		}
	}
}

// TestErrorRowsReallyLackEveryObservationStream reads the recomputed keys
// rather than trusting the Projections() prose: if failure_response ever
// started emitting frames[], NC-01's whole claim would be void and this is
// what would say so.
func TestErrorRowsReallyLackEveryObservationStream(t *testing.T) {
	result, err := Decide(liveRunner(t), Probes()[0])
	if err != nil {
		t.Fatal(err)
	}
	if Probes()[0].ID != "NC-01" {
		t.Fatalf("catalog order changed; this test targets NC-01, got %s", Probes()[0].ID)
	}
	for _, keys := range [][]string{result.KeysA, result.KeysB} {
		for _, key := range keys {
			switch key {
			case "events", "frames", "transitions", "close":
				t.Fatalf("an error row now carries %q; NC-01's claim that the failure "+
					"projection erases every observation stream is no longer true", key)
			}
		}
	}
}
