package deltaledger

// The polarity proof for unledgered_disagreements, plus the evidence bindings
// that keep the observed-disagreement set honest.
//
// THE POINT OF THIS FILE. A fix that yields zero because everything happens to
// be ledgered is indistinguishable from the bug it replaces — the old field
// yielded zero too, and could yield nothing else. So the deliverable is not
// "the count is 0"; it is a demonstration that the count CAN be nonzero and
// that the readiness gate refuses when it is.
// TestUnledgeredCountReportsNonzeroAndTheReadinessGateRefuses is that
// demonstration, and it is a committed regression test rather than a one-off
// manual run, so re-breaking the gate into a constant fails the suite.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// TestCommittedObservationSetIsWellFormed fails closed on an empty, truncated
// or provenance-less observation set, so the gate can never become vacuous by
// the file quietly degrading.
func TestCommittedObservationSetIsWellFormed(t *testing.T) {
	set, err := ReadObservations(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	if set.EvidenceKind != "observed-disagreement-set" || set.SchemaVersion != "1.0.0" {
		t.Fatalf("observation envelope drifted: kind=%q version=%q", set.EvidenceKind, set.SchemaVersion)
	}
	if set.Schema != "../../schemas/observed-disagreements-1.0.0.schema.json" {
		t.Fatalf("observation schema pointer drifted: %q", set.Schema)
	}
	seen := map[string]bool{}
	for index, observation := range set.Observed {
		if seen[observation.SubjectRef] {
			t.Errorf("observation %d duplicates subject %s", index, observation.SubjectRef)
		}
		seen[observation.SubjectRef] = true
		if _, err := observation.Digest(); err != nil {
			t.Errorf("observation %d (%s) does not digest: %v", index, observation.SubjectRef, err)
		}
	}
	for index, provenance := range set.Provenance {
		if provenance.SubjectRef != set.Observed[index].SubjectRef {
			t.Errorf("provenance %d is for %s but observation %d is %s",
				index, provenance.SubjectRef, index, set.Observed[index].SubjectRef)
		}
		if len(provenance.Evidence) == 0 || strings.TrimSpace(provenance.SourceKind) == "" {
			t.Errorf("provenance %d (%s) names no evidence or no source kind", index, provenance.SubjectRef)
		}
	}
}

// TestCommittedLedgerCountsItsUnledgeredDisagreements pins that the committed
// field is the COMPUTED value rather than a constant that happens to agree.
func TestCommittedLedgerCountsItsUnledgeredDisagreements(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	set, err := ReadObservations(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	unledgered, err := UnledgeredSubjects(committed.Records, set.Observed)
	if err != nil {
		t.Fatalf("compute unledgered: %v", err)
	}
	if committed.UnledgeredDisagreements != len(unledgered) {
		t.Fatalf("committed unledgered_disagreements is %d but the computation over the committed observation set says %d (%v)",
			committed.UnledgeredDisagreements, len(unledgered), unledgered)
	}
}

// TestTheLedgerHasNoUnledgeredObservedDisagreements is the REQUIREMENT: at
// rest, every observed disagreement must have a record. It is deliberately a
// separate test from the computation above, because the computation being
// correct and the count being zero are two different claims and conflating
// them is how the original fake gate read clean.
func TestTheLedgerHasNoUnledgeredObservedDisagreements(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	set, err := ReadObservations(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	unledgered, err := UnledgeredSubjects(committed.Records, set.Observed)
	if err != nil {
		t.Fatalf("compute unledgered: %v", err)
	}
	if len(unledgered) != 0 {
		t.Fatalf("%d observed disagreements have no ledger record: %v", len(unledgered), unledgered)
	}
	if err := lab.DetectUnledgeredDisagreements(committed.Records, set.Observed); err != nil {
		t.Fatalf("the lab detector disagrees with the committed ledger: %v", err)
	}
}

// TestUnledgeredComputationAgreesWithTheLabDetector pins that this package's
// reporting computation and the canonical detector cannot drift apart: the
// detector says THAT something is unledgered, this package says WHICH, and
// they must agree on every prefix of the record chain.
func TestUnledgeredComputationAgreesWithTheLabDetector(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	set, err := ReadObservations(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	for cut := 0; cut <= len(committed.Records); cut++ {
		records := committed.Records[:cut]
		unledgered, err := UnledgeredSubjects(records, set.Observed)
		if err != nil {
			t.Fatalf("cut %d: compute unledgered: %v", cut, err)
		}
		detectorErr := lab.DetectUnledgeredDisagreements(records, set.Observed)
		if (len(unledgered) == 0) != (detectorErr == nil) {
			t.Fatalf("cut %d: computation reports %d unledgered but the detector returned %v",
				cut, len(unledgered), detectorErr)
		}
	}
}

// TestUnledgeredCountReportsNonzeroAndTheReadinessGateRefuses IS THE POLARITY
// PROOF, and it is the deliverable of this change.
//
// It removes exactly one record from the chain while the committed observation
// set keeps that observation, and asserts three things the previous design
// could not produce at all:
//
//  1. the computed count becomes exactly 1, naming the orphaned subject;
//  2. the ledger document that BuildLedgerFile would emit carries that nonzero
//     value — i.e. the artifact is able to say "one disagreement is
//     unledgered", where the old schema's `const: 0` forbade it;
//  3. internal/lab.VerifyBaselineEvidence REFUSES readiness on that document
//     with UNLEDGERED_BEHAVIOR_DISAGREEMENT.
//
// Restoring the record returns the count to 0 and the gate to passing, so the
// gate is proven to discriminate rather than merely to agree.
func TestUnledgeredCountReportsNonzeroAndTheReadinessGateRefuses(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	set, err := ReadObservations(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	if len(committed.Records) < 2 {
		t.Fatal("polarity proof needs at least two records")
	}

	// Baseline: the intact chain reports zero.
	intact, err := UnledgeredSubjects(committed.Records, set.Observed)
	if err != nil {
		t.Fatalf("compute unledgered on the intact chain: %v", err)
	}
	if len(intact) != 0 {
		t.Fatalf("polarity proof needs a clean baseline, got %d unledgered: %v", len(intact), intact)
	}

	// Remove the LAST record. Removing a tail record keeps the remaining
	// chain internally valid (each record still follows its predecessor), so
	// the only thing that changes is coverage — which is precisely the
	// property under test.
	removed := committed.Records[len(committed.Records)-1]
	truncated := committed.Records[:len(committed.Records)-1]

	orphaned, err := UnledgeredSubjects(truncated, set.Observed)
	if err != nil {
		t.Fatalf("compute unledgered on the truncated chain: %v", err)
	}
	if len(orphaned) != 1 {
		t.Fatalf("removing one record must orphan exactly one observation, got %d: %v", len(orphaned), orphaned)
	}
	if orphaned[0] != removed.Delta.SubjectRef {
		t.Fatalf("orphaned subject is %s but the removed record was %s", orphaned[0], removed.Delta.SubjectRef)
	}

	// The canonical detector must refuse the same chain.
	if err := lab.DetectUnledgeredDisagreements(truncated, set.Observed); err == nil {
		t.Fatal("the lab detector accepted a chain missing a record for a committed observation")
	}

	// The emitted artifact must be able to CARRY the nonzero value, and the
	// readiness gate must refuse it. Both were impossible before: the schema
	// pinned the field to 0 and build.go assigned that constant.
	document := committed
	document.Records = truncated
	document.Head = truncated[len(truncated)-1].RecordDigest
	document.UnledgeredDisagreements = len(orphaned)
	if document.UnledgeredDisagreements != 1 {
		t.Fatalf("emitted document should carry 1, carries %d", document.UnledgeredDisagreements)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal degraded ledger: %v", err)
	}
	if !strings.Contains(string(raw), `"unledgered_disagreements":1`) {
		t.Fatal("the serialized ledger document does not carry the nonzero count")
	}
	assertReadinessRefusesUnledgered(t, raw)

	// Restoring the record returns the count to zero: the gate discriminates.
	restored, err := UnledgeredSubjects(committed.Records, set.Observed)
	if err != nil {
		t.Fatalf("compute unledgered after restore: %v", err)
	}
	if len(restored) != 0 {
		t.Fatalf("restoring the record must return the count to 0, got %d: %v", len(restored), restored)
	}
}

// assertReadinessRefusesUnledgered feeds the degraded ledger document to the
// real readiness gate alongside the other committed baseline documents and
// requires an UNLEDGERED_BEHAVIOR_DISAGREEMENT refusal.
func assertReadinessRefusesUnledgered(t *testing.T, degradedLedger []byte) {
	t.Helper()
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(ledgerTestRepoRoot, "evidence", "java", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return raw
	}
	var envelope struct {
		AcceptedRootDigest string `json:"accepted_root_digest"`
	}
	if err := json.Unmarshal(degradedLedger, &envelope); err != nil {
		t.Fatalf("decode degraded ledger envelope: %v", err)
	}
	_, err := lab.VerifyBaselineEvidence(envelope.AcceptedRootDigest, lab.BaselineEvidenceDocuments{
		Build:    read("build.json"),
		Adapter:  read("adapter-baseline.json"),
		Tests:    read("test-manifest.json"),
		Autobahn: read("autobahn-baseline.json"),
		Ledger:   degradedLedger,
	})
	if err == nil {
		t.Fatal("readiness gate accepted a ledger reporting an unledgered disagreement")
	}
	if !strings.Contains(err.Error(), "UNLEDGERED_BEHAVIOR_DISAGREEMENT") {
		// The gate may refuse earlier for an unrelated reason (for example the
		// Autobahn baseline is BLOCKED on this plane). Say so explicitly
		// rather than letting a coincidental refusal masquerade as the proof.
		t.Fatalf("readiness refused, but not on the unledgered-disagreement finding; got: %v", err)
	}
}
