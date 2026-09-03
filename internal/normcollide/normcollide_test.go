package normcollide

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up to the module root so tests can read committed evidence.
func repoRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		directory = filepath.Dir(directory)
	}
	t.Fatal("could not find the module root")
	return ""
}

// stubRunner answers from a fixed table keyed by the request line, so the
// DECIDING logic can be attacked without a Rust build. It is never used to
// produce evidence: the committed document is written from HarnessRunner only,
// and TestCommittedDocumentRecordsARealHarnessRun checks that.
type stubRunner struct {
	answers []string
	err     error
}

func (s *stubRunner) Identity() string { return "stub" }

func (s *stubRunner) Run(lines []string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	if len(s.answers) < len(lines) {
		return nil, errShort
	}
	return s.answers[:len(lines)], nil
}

type constError string

func (e constError) Error() string { return string(e) }

const errShort = constError("stub has fewer answers than requests")

func row(id, extra string) string {
	if extra == "" {
		return `{"outcome":"error","request_digest":"sha256:` + id + `","request_id":"` + id + `"}`
	}
	return `{"outcome":"error",` + extra + `,"request_digest":"sha256:` + id + `","request_id":"` + id + `"}`
}

// ---------------------------------------------------------------------------
// Catalog and surface invariants — these run in the default suite.
// ---------------------------------------------------------------------------

func TestIdentityFieldsAreExactlyThree(t *testing.T) {
	// Widening this list would weaken every collision claim in the package:
	// each extra field is one more real difference the comparison would stop
	// reporting. Pinning it makes that widening a test failure.
	want := []string{"case_id", "request_digest", "request_id"}
	got := IdentityFields()
	if len(got) != len(want) {
		t.Fatalf("identity fields: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("identity fields: got %v, want %v", got, want)
		}
	}
}

func TestEveryProbeRendersTwoDifferentRequestLines(t *testing.T) {
	for _, probe := range Probes() {
		a, err := probe.CollisionA.Line()
		if err != nil {
			t.Fatalf("%s collision A: %v", probe.ID, err)
		}
		b, err := probe.CollisionB.Line()
		if err != nil {
			t.Fatalf("%s collision B: %v", probe.ID, err)
		}
		if a == b {
			t.Fatalf("%s: the two collision seeds render the same line", probe.ID)
		}
	}
}

func TestEveryProbeCarriesAWitnessOrAWireWitness(t *testing.T) {
	for _, probe := range Probes() {
		pair := probe.WitnessA != nil && probe.WitnessB != nil
		if !pair && probe.WireWitness == "" {
			t.Fatalf("%s has neither a witness pair nor a wire witness; the claim is not falsifiable",
				probe.ID)
		}
	}
}

func TestEveryProbeNamesAnEnumeratedProjection(t *testing.T) {
	known := map[string]bool{}
	for _, projection := range Projections() {
		known[projection.ID] = true
	}
	for _, probe := range Probes() {
		if !known[probe.Projection] {
			t.Fatalf("%s names projection %q, which the surface table does not enumerate",
				probe.ID, probe.Projection)
		}
	}
}

func TestEveryCandidateIsLabelledHypothesis(t *testing.T) {
	// A candidate that lost its label would read as a finding. The whole
	// point of the list is that these were NOT decided by running anything.
	for _, candidate := range Candidates() {
		if candidate.Status != "HYPOTHESIS" {
			t.Fatalf("%s is status %q; an undecided candidate must say so",
				candidate.ID, candidate.Status)
		}
		if candidate.Why == "" {
			t.Fatalf("%s does not say why it was not decided", candidate.ID)
		}
	}
}

// TestCorpusCollisionSeedsMatchTheShippedScenarios re-reads the public corpus
// and fails if NC-04's seeds stop being the real us005.pub.0039 and
// us005.pub.0066 steps. Without this the probe could quietly become a
// synthetic pair and keep claiming it costs the headline a row.
func TestCorpusCollisionSeedsMatchTheShippedScenarios(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "corpora/public/scenarios.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"us005.pub.0039": pub0039Frame, "us005.pub.0066": pub0066Frame}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var scenario struct {
			ScenarioID string `json:"scenario_id"`
			Steps      []struct {
				Kind       string `json:"kind"`
				DataBase64 string `json:"data_base64"`
			} `json:"steps"`
		}
		if err := json.Unmarshal([]byte(line), &scenario); err != nil {
			t.Fatal(err)
		}
		expected, interesting := want[scenario.ScenarioID]
		if !interesting {
			continue
		}
		seen[scenario.ScenarioID] = true
		if len(scenario.Steps) != 1 || scenario.Steps[0].DataBase64 != expected {
			t.Fatalf("%s no longer carries the single bytes step %q that NC-04 claims: %+v",
				scenario.ScenarioID, expected, scenario.Steps)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Fatalf("%s is no longer in the public corpus; NC-04's in-corpus claim is stale", id)
		}
	}
}

// ---------------------------------------------------------------------------
// RED: each decision check must be able to fail on its own.
//
// A mutation that breaks compilation proves nothing, so these do not comment
// code out. Each feeds Decide a probe that ONLY the named check rejects and
// asserts it is rejected; delete that one check and the corresponding case
// starts passing, which is the deletion attack made permanent.
// ---------------------------------------------------------------------------

func TestDecideRejectsAProbeWhoseCollisionSeedsAreTheSameRequest(t *testing.T) {
	same := Seed{ID: "same", Steps: []map[string]any{textStep("A")}}
	_, err := Decide(&stubRunner{}, Probe{
		ID: "RED-1", CollisionA: same, CollisionB: same, WireWitness: "none",
	})
	if err == nil {
		t.Fatal("Decide accepted a probe whose two collision seeds are the identical request; " +
			"delete the lines[0] == lines[1] check and this passes")
	}
	if !strings.Contains(err.Error(), "SAME request line") {
		t.Fatalf("wrong rejection: %v", err)
	}
}

func TestDecideRejectsAnUnwitnessedProbe(t *testing.T) {
	_, err := Decide(&stubRunner{}, Probe{
		ID:         "RED-2",
		CollisionA: Seed{ID: "a", Steps: []map[string]any{textStep("A")}},
		CollisionB: Seed{ID: "b", Steps: []map[string]any{textStep("B")}},
	})
	if err == nil {
		t.Fatal("Decide accepted a probe with no witness of any kind; delete the " +
			"witness-or-wire-witness check and this passes")
	}
	if !strings.Contains(err.Error(), "not falsifiable") {
		t.Fatalf("wrong rejection: %v", err)
	}
}

func TestDecideRejectsWhenTheTwoAnswersShareEveryIdentityField(t *testing.T) {
	// Two answers that agree on request_id and request_digest are one request
	// compared with itself. Without the IdentityMoved check that reads as a
	// perfect collision.
	runner := &stubRunner{answers: []string{row("x", ""), row("x", "")}}
	_, err := Decide(runner, Probe{
		ID:          "RED-3",
		CollisionA:  Seed{ID: "a", Steps: []map[string]any{textStep("A")}},
		CollisionB:  Seed{ID: "b", Steps: []map[string]any{textStep("B")}},
		WireWitness: "the two request lines differ",
	})
	if err == nil {
		t.Fatal("Decide accepted two answers with identical identity fields as a collision; " +
			"delete the IdentityMoved check and this passes")
	}
	if !strings.Contains(err.Error(), "not two requests") {
		t.Fatalf("wrong rejection: %v", err)
	}
}

func TestDecideRejectsAWitnessPairThatMovedNothing(t *testing.T) {
	// The witness is what proves the two behaviours differ. A witness pair
	// that produces identical answers proves only that two equal things are
	// equal, and a probe resting on it would be worthless.
	runner := &stubRunner{answers: []string{
		row("a", ""), row("b", ""), // collision pair: identical but for identity
		row("wa", ""), row("wb", ""), // witness pair: ALSO identical but for identity
	}}
	witnessA := Seed{ID: "wa", Steps: []map[string]any{textStep("A")}}
	witnessB := Seed{ID: "wb", Steps: []map[string]any{textStep("B")}}
	_, err := Decide(runner, Probe{
		ID:         "RED-4",
		CollisionA: Seed{ID: "a", Steps: []map[string]any{textStep("A")}},
		CollisionB: Seed{ID: "b", Steps: []map[string]any{textStep("B")}},
		WitnessA:   &witnessA, WitnessB: &witnessB,
	})
	if err == nil {
		t.Fatal("Decide accepted a probe whose witness pair moved nothing; delete the " +
			"WitnessPaths emptiness check and this passes")
	}
	if !strings.Contains(err.Error(), "moved NOTHING") {
		t.Fatalf("wrong rejection: %v", err)
	}
}

func TestDecideRefutesWhenTheComparatorMoves(t *testing.T) {
	// The verdict must be able to come out REFUTED. If it cannot, CONFIRMED
	// means nothing. This is the same shape that really happened to NC-08 on
	// its first run.
	runner := &stubRunner{answers: []string{
		row("a", `"final_state":"open"`),
		row("b", `"final_state":"closed"`),
	}}
	result, err := Decide(runner, Probe{
		ID:          "RED-5",
		CollisionA:  Seed{ID: "a", Steps: []map[string]any{textStep("A")}},
		CollisionB:  Seed{ID: "b", Steps: []map[string]any{textStep("B")}},
		WireWitness: "the two request lines differ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != Refuted {
		t.Fatalf("verdict %s: a moving comparator must REFUTE, else CONFIRMED is unfalsifiable",
			result.Verdict)
	}
	if len(result.CollisionPaths) != 1 || result.CollisionPaths[0] != "final_state" {
		t.Fatalf("collision paths %v, want [final_state]", result.CollisionPaths)
	}
}

func TestDecideConfirmsOnlyWhenNothingBehaviouralMoves(t *testing.T) {
	// The positive control for the case above: same shape, no behavioural
	// difference, and the verdict flips to CONFIRMED. Together these two
	// prove the verdict is a function of the run and not a constant.
	runner := &stubRunner{answers: []string{
		row("a", `"final_state":"open"`),
		row("b", `"final_state":"open"`),
	}}
	result, err := Decide(runner, Probe{
		ID:          "RED-6",
		CollisionA:  Seed{ID: "a", Steps: []map[string]any{textStep("A")}},
		CollisionB:  Seed{ID: "b", Steps: []map[string]any{textStep("B")}},
		WireWitness: "the two request lines differ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != Confirmed {
		t.Fatalf("verdict %s, want CONFIRMED", result.Verdict)
	}
}

// TestBehaviouralPathsStripsIdentityAndNothingElse is the guard on the one
// place where this package removes information before comparing. If it ever
// started stripping a behavioural field, every CONFIRMED verdict would become
// unsound and no other test would notice.
func TestBehaviouralPathsStripsIdentityAndNothingElse(t *testing.T) {
	a := map[string]any{"request_id": "a", "request_digest": "da", "case_id": "ca",
		"final_state": "open", "counts": map[string]any{"frames": "1"}}
	b := map[string]any{"request_id": "b", "request_digest": "db", "case_id": "cb",
		"final_state": "closed", "counts": map[string]any{"frames": "2"}}
	paths := behaviouralPaths(a, b)
	want := map[string]bool{"counts.frames": true, "final_state": true}
	if len(paths) != len(want) {
		t.Fatalf("paths %v, want exactly %v", paths, want)
	}
	for _, path := range paths {
		if !want[path] {
			t.Fatalf("unexpected surviving path %q in %v", path, paths)
		}
	}
}

// ---------------------------------------------------------------------------
// The committed document, as a consumer.
// ---------------------------------------------------------------------------

func loadCommitted(t *testing.T) *Document {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), DocumentPath))
	if err != nil {
		t.Fatal(err)
	}
	var document Document
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return &document
}

func TestCommittedDocumentCountsMatchItsOwnProbeList(t *testing.T) {
	document := loadCommitted(t)
	confirmed, refuted := 0, 0
	// Both catalogs. probes[] is the confirmed-collision list and
	// refutations[] the deliberately-refuted one; the counts partition ALL
	// decided probes by the verdict each run produced, so counting only one
	// list would let the other drift.
	decided := append(append([]ProbeDoc{}, document.Probes...), document.Refutations...)
	for _, probe := range decided {
		switch probe.Result.Verdict {
		case Confirmed:
			confirmed++
		case Refuted:
			refuted++
		default:
			t.Fatalf("%s carries verdict %q, which is neither CONFIRMED nor REFUTED",
				probe.ID, probe.Result.Verdict)
		}
		if probe.Result.Verdict != probe.Expect {
			t.Fatalf("%s declares %q and the recorded run says %q; the document may not carry "+
				"a probe whose result disagrees with its own declaration",
				probe.ID, probe.Expect, probe.Result.Verdict)
		}
	}
	if document.RecomputedFrom.ProbeCount != len(decided) {
		t.Fatalf("probe_count %d, probes+refutations %d",
			document.RecomputedFrom.ProbeCount, len(decided))
	}
	// The candidate arithmetic must close: whatever is decided plus whatever
	// is still open has to be what the first pass named. A candidate dropped
	// rather than decided would shrink one side and leave the sum wrong.
	if got, want := document.RecomputedFrom.CandidateCount, len(document.Candidates); got != want {
		t.Fatalf("undecided_candidate_count %d, undecided_candidates %d", got, want)
	}
	if got, want := document.RecomputedFrom.DecidedCandidateCount,
		len(document.DecidedCandidates); got != want {
		t.Fatalf("decided_candidate_count %d, decided_candidates %d", got, want)
	}
	if sum := document.RecomputedFrom.CandidateCount +
		document.RecomputedFrom.DecidedCandidateCount; sum != document.RecomputedFrom.CandidateFirstPassCount {
		t.Fatalf("%d decided + %d undecided = %d, but the first pass named %d; a candidate has "+
			"gone missing rather than been decided",
			document.RecomputedFrom.DecidedCandidateCount, document.RecomputedFrom.CandidateCount,
			sum, document.RecomputedFrom.CandidateFirstPassCount)
	}
	if document.RecomputedFrom.ConfirmedCount != confirmed ||
		document.RecomputedFrom.RefutedCount != refuted {
		t.Fatalf("counts say %d/%d confirmed/refuted, the probe list says %d/%d",
			document.RecomputedFrom.ConfirmedCount, document.RecomputedFrom.RefutedCount,
			confirmed, refuted)
	}
}

func TestCommittedDocumentConfirmsNothingWithAMovingComparator(t *testing.T) {
	// The document's own consistency: a probe cannot be CONFIRMED while
	// recording behavioural paths that moved. Both catalogs are checked —
	// the refutation list is held to the same rule from the other side, a
	// REFUTED entry that moved nothing being just as incoherent.
	document := loadCommitted(t)
	for _, probe := range append(append([]ProbeDoc{}, document.Probes...), document.Refutations...) {
		if probe.Result.Verdict == Confirmed && len(probe.Result.CollisionPaths) != 0 {
			t.Fatalf("%s is CONFIRMED but its collision pair moved %v",
				probe.ID, probe.Result.CollisionPaths)
		}
		if probe.Result.Verdict == Refuted && len(probe.Result.CollisionPaths) == 0 {
			t.Fatalf("%s is REFUTED but nothing moved", probe.ID)
		}
		if probe.Result.WitnessKind == "pair" && len(probe.Result.WitnessPaths) == 0 {
			t.Fatalf("%s claims a witness pair that moved nothing", probe.ID)
		}
		if len(probe.Result.IdentityMoved) == 0 {
			t.Fatalf("%s compared two answers with identical identity fields", probe.ID)
		}
	}
}

func TestCommittedDocumentRecordsARealHarnessRun(t *testing.T) {
	// The document must attest a digested binary, not the stub. A document
	// generated from a stub would carry "stub" here and every verdict in it
	// would be fiction.
	harness := loadCommitted(t).RecomputedFrom.Harness
	if !strings.HasPrefix(harness, "ws-oracle-harness sha256:") {
		t.Fatalf("recomputed_from.harness is %q; the document must attest a digested "+
			"ws-oracle-harness binary", harness)
	}
}

func TestCommittedBoundsAgreeWithTheCommittedCensus(t *testing.T) {
	document := loadCommitted(t)
	var public, handshake *Census
	for i := range document.Census {
		if strings.HasPrefix(document.Census[i].Source, "corpora/handshake") {
			handshake = &document.Census[i]
		} else {
			public = &document.Census[i]
		}
	}
	if public == nil || handshake == nil {
		t.Fatal("the document does not carry both censuses")
	}
	if document.Bounds.PublicTotal != public.Rows ||
		document.Bounds.PublicDistinct != public.DistinctScoredRows ||
		document.Bounds.PublicShared != public.RowsSharingAnObservation {
		t.Fatalf("the 74/74 bound does not read the public census it cites")
	}
	if document.Bounds.HandshakeTotal != handshake.Rows ||
		document.Bounds.HandshakeDistinct != handshake.DistinctScoredRows ||
		document.Bounds.HandshakeShared != handshake.RowsSharingAnObservation ||
		document.Bounds.HandshakeLargest != handshake.LargestClass {
		t.Fatalf("the 49/49 bound does not read the handshake census it cites")
	}
	// The bound only means something if the corpora really are coarser than
	// their row counts. If a future corpus fixed that, this test failing is
	// the correct signal to restate the bound, not to delete the check.
	if public.DistinctScoredRows >= public.Rows {
		t.Fatal("the public corpus no longer collapses any row; restate the 74/74 bound")
	}
	if handshake.DistinctScoredRows >= handshake.Rows {
		t.Fatal("the handshake corpus no longer collapses any case; restate the 49/49 bound")
	}
}

func TestCommittedDocumentPartitionsEveryObservedShape(t *testing.T) {
	known := map[string]bool{}
	for _, projection := range loadCommitted(t).Surface {
		known[projection.ID] = true
	}
	for _, census := range loadCommitted(t).Census {
		for _, keySet := range census.KeySets {
			if !known[keySet.Projection] {
				t.Fatalf("%s carries shape %v filed under unknown projection %q",
					census.Source, keySet.Keys, keySet.Projection)
			}
		}
	}
}
