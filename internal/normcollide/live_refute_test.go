//go:build normcollide

// Live gate for the DECIDED candidates: the refutation probes and the
// CAND-UTF8 emptiness argument. Same tag, same never-skipped discipline as
// live_test.go — a missing binary is a failure, not a pass.
package normcollide

import "testing"

// TestEveryRefutationProbeStillMovesTheComparator re-decides the refutation
// catalog from scratch. A refutation that stops holding is a FINDING, not a
// reason to relax anything: it means the observation does NOT carry the
// distinction after all, which is an eighth collision.
func TestEveryRefutationProbeStillMovesTheComparator(t *testing.T) {
	runner := liveRunner(t)
	for _, probe := range Refutations() {
		result, err := Decide(runner, probe)
		if err != nil {
			t.Fatalf("%s: %v", probe.ID, err)
		}
		if err := CheckExpectation(probe, result); err != nil {
			t.Fatalf("%s: %v", probe.ID, err)
		}
		if result.Verdict != Refuted {
			t.Fatalf("%s is now %s; CheckExpectation should have caught this first", probe.ID, result.Verdict)
		}
	}
}

// TestTheTwoCatalogsAreDecidedByTheSameMachineryAndDisagreeOnlyInTheirVerdict
// runs CheckExpectation over BOTH lists. Its value is that a refutation is not
// held to a weaker standard than a collision: the same function decides both,
// and the only declared difference is which verdict is expected.
func TestBothCatalogsAreHeldToTheirOwnDeclaration(t *testing.T) {
	runner := liveRunner(t)
	if err := CheckEveryProbeDeclaresAnExpectation(Probes(), Refutations()); err != nil {
		t.Fatal(err)
	}
	for _, probe := range append(append([]Probe{}, Probes()...), Refutations()...) {
		result, err := Decide(runner, probe)
		if err != nil {
			t.Fatalf("%s: %v", probe.ID, err)
		}
		if err := CheckExpectation(probe, result); err != nil {
			t.Fatal(err)
		}
	}
}

// TestNC10ProvesTheNonMinimalLengthIsBothACCEPTEDAndOBSERVED is the specific
// reading the CAND-WIREBYTES decision rests on. Two ways it could go wrong and
// still be REFUTED are checked here by name: the extended form being REJECTED
// (which would make the movement a rejection, not a representation), and the
// movement landing anywhere except wire_bytes.
func TestNC10ProvesTheNonMinimalLengthIsBothAcceptedAndObserved(t *testing.T) {
	result := decideByID(t, Refutations(), "NC-10")
	for _, keys := range [][]string{result.KeysA, result.KeysB} {
		for _, key := range keys {
			if key == "error" {
				t.Fatalf("a collision answer is an error row (%v): ws-core has started REJECTING "+
					"the non-minimal extended length, so CAND-WIREBYTES is empty rather than "+
					"refuted and the entry must be reclassified", keys)
			}
		}
	}
	if !contains(result.CollisionPaths, "frames[0].wire_bytes") {
		t.Fatalf("the pair moved on %v but NOT on frames[0].wire_bytes; the non-minimal header "+
			"has stopped being observable and CAND-WIREBYTES is open again", result.CollisionPaths)
	}
}

// TestNC11ProvesTheChunkSplitIsObserved is CAND-CHUNKING's equivalent.
func TestNC11ProvesTheChunkSplitIsObserved(t *testing.T) {
	result := decideByID(t, Refutations(), "NC-11")
	if !contains(result.CollisionPaths, "events.length") {
		t.Fatalf("the pair moved on %v but NOT on events.length; the per-step input_chunk event "+
			"has stopped distinguishing a 4+4 split from an 8, and CAND-CHUNKING is open again",
			result.CollisionPaths)
	}
}

// TestTheUtf8CandidateIsStillEmpty runs every premise of the emptiness
// argument. If any one fails, CAND-UTF8 stops being EMPTY and becomes
// UNDECIDED again — which is a finding about the tree, and the fallback is to
// reopen the candidate, never to keep the EMPTY reading.
func TestTheUtf8CandidateIsStillEmpty(t *testing.T) {
	record, err := DecideUtf8Emptiness(repoRoot(t), liveRunner(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, premise := range record.Premises {
		if !premise.Holds {
			t.Fatalf("premise %s failed: %s. CAND-UTF8's EMPTY status rests on it, so the "+
				"candidate is UNDECIDED again and must be reopened", premise.ID, premise.Evidence)
		}
	}
	if record.Status != StatusEmpty {
		t.Fatalf("status %s with every premise holding; the status must be a function of the "+
			"premises", record.Status)
	}
	if len(record.Premises) < 4 {
		t.Fatalf("only %d premise(s) ran; the argument needs the decode site, both crate scans "+
			"and the discriminating run", len(record.Premises))
	}
}

// TestTheCommittedDocumentAgreesWithTheDecidedCandidates is the document-level
// consistency check for the new sections.
func TestTheCommittedDocumentAgreesWithItsOwnDecidedCandidates(t *testing.T) {
	document := loadCommitted(t)
	byID := map[string]Verdict{}
	for _, probe := range append(append([]ProbeDoc{}, document.Probes...), document.Refutations...) {
		byID[probe.ID] = probe.Result.Verdict
	}
	for _, candidate := range document.DecidedCandidates {
		switch candidate.DecidedBy {
		case document.Utf8Emptiness.ID:
			if candidate.Status != document.Utf8Emptiness.Status {
				t.Fatalf("%s says %s, the emptiness record says %s",
					candidate.ID, candidate.Status, document.Utf8Emptiness.Status)
			}
		default:
			verdict, present := byID[candidate.DecidedBy]
			if !present {
				t.Fatalf("%s is decided_by %s, which is in neither probe list",
					candidate.ID, candidate.DecidedBy)
			}
			if verdict == Refuted && candidate.Status != StatusRefuted {
				t.Fatalf("%s says %s but %s came back %s",
					candidate.ID, candidate.Status, candidate.DecidedBy, verdict)
			}
		}
	}
}

func decideByID(t *testing.T, probes []Probe, id string) Result {
	t.Helper()
	for _, probe := range probes {
		if probe.ID != id {
			continue
		}
		result, err := Decide(liveRunner(t), probe)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	t.Fatalf("%s is not in the catalog this test targets", id)
	return Result{}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
