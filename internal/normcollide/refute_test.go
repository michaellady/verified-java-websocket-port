package normcollide

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Catalog shape. These run in the default suite and need no harness.
// ---------------------------------------------------------------------------

func TestEveryProbeInBothCatalogsDeclaresTheExpectationItsListImplies(t *testing.T) {
	if err := CheckEveryProbeDeclaresAnExpectation(Probes(), Refutations()); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogShapeGuardCatchesAMislabelledProbe(t *testing.T) {
	// RED control for the guard above. Without it a REFUTED-expecting probe
	// could sit in Probes() and be counted as a collision.
	err := CheckEveryProbeDeclaresAnExpectation(
		[]Probe{{ID: "RED-EXP-1", Expect: Refuted}}, nil)
	if err == nil {
		t.Fatal("a REFUTED-declaring member of Probes() was accepted; the collision count " +
			"would then include a probe that is not a collision")
	}
}

func TestCatalogShapeGuardCatchesAProbeInBothLists(t *testing.T) {
	// A probe in both lists would be decided twice and counted twice.
	err := CheckEveryProbeDeclaresAnExpectation(
		[]Probe{{ID: "NC-DUP", Expect: Confirmed}},
		[]Probe{{ID: "NC-DUP", Expect: Refuted}})
	if err == nil {
		t.Fatal("a probe id present in both catalogs was accepted; it would be counted twice")
	}
}

func TestEveryRefutationProbeRendersTwoDifferentRequestLines(t *testing.T) {
	for _, probe := range Refutations() {
		a, err := probe.CollisionA.Line()
		if err != nil {
			t.Fatal(err)
		}
		b, err := probe.CollisionB.Line()
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Fatalf("%s renders one request line twice; a refutation over one input decides "+
				"nothing", probe.ID)
		}
	}
}

func TestEveryRefutationProbeNamesTheePathItIsAbout(t *testing.T) {
	for _, probe := range Refutations() {
		if len(probe.RequiredPaths) == 0 {
			t.Fatalf("%s names no required_diff_paths; it would accept ANY movement as a "+
				"refutation of its own distinction", probe.ID)
		}
	}
}

func TestEveryRefutationProbeNamesAnEnumeratedProjection(t *testing.T) {
	known := map[string]bool{}
	for _, projection := range Projections() {
		known[projection.ID] = true
	}
	for _, probe := range Refutations() {
		if !known[probe.Projection] {
			t.Fatalf("%s names projection %q, which the surface table does not enumerate",
				probe.ID, probe.Projection)
		}
	}
}

// TestTheNonMinimalFrameDiffersFromTheMinimalOneInExactlyTheHeader is the
// guard that keeps NC-10 a measurement of the LENGTH ENCODING rather than of
// whatever else the two frames happen to differ in. If the two frames ever
// stopped sharing a mask key or a masked payload, the probe would still be
// REFUTED and would be measuring the wrong thing.
func TestTheNonMinimalFrameDiffersFromTheMinimalOneInExactlyTheHeader(t *testing.T) {
	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	minimal := maskedTextFrame([]byte("hi"), key)
	extended := nonMinimalTextFrame([]byte("hi"), key)
	if len(extended) != len(minimal)+2 {
		t.Fatalf("extended form is %d octets and minimal is %d; the 126 form must cost exactly "+
			"two more header octets", len(extended), len(minimal))
	}
	if minimal[0] != extended[0] {
		t.Fatalf("first octet differs (%02x vs %02x); the two frames must share FIN, RSV and "+
			"opcode", minimal[0], extended[0])
	}
	if extended[1] != 0x80|126 || extended[2] != 0x00 || extended[3] != 0x02 {
		t.Fatalf("extended header is %02x %02x %02x, want fe 00 02 — a masked 126 form "+
			"declaring a two-octet payload", extended[1], extended[2], extended[3])
	}
	if string(minimal[2:]) != string(extended[4:]) {
		t.Fatalf("mask key and masked payload differ (%x vs %x); the pair would then measure "+
			"more than the length encoding", minimal[2:], extended[4:])
	}
}

// TestTheChunkedPairCarriesTheSameOctets is NC-11's equivalent: the split must
// be a SPLIT, not a different frame.
func TestTheChunkedPairCarriesTheSameOctets(t *testing.T) {
	var whole, split []byte
	for _, probe := range Refutations() {
		if probe.ID != "NC-11" {
			continue
		}
		whole = stepBytes(t, probe.CollisionA.Steps)
		split = stepBytes(t, probe.CollisionB.Steps)
	}
	if len(whole) == 0 {
		t.Fatal("NC-11 is not in Refutations(); this test targets it by id")
	}
	if string(whole) != string(split) {
		t.Fatalf("the one-step octets %x and the two-step octets %x differ; the pair would then "+
			"measure a different frame rather than a different split", whole, split)
	}
	if len(probeSteps(t, "NC-11")) != 1 {
		t.Fatal("NC-11's collision A must be exactly one step")
	}
}

func stepBytes(t *testing.T, steps []map[string]any) []byte {
	t.Helper()
	var out []byte
	for _, step := range steps {
		encoded, ok := step["data_base64"].(string)
		if !ok {
			t.Fatalf("step %v is not a bytes step", step)
		}
		raw, err := decodeBase64(encoded)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw...)
	}
	return out
}

func probeSteps(t *testing.T, id string) []map[string]any {
	t.Helper()
	for _, probe := range Refutations() {
		if probe.ID == id {
			return probe.CollisionA.Steps
		}
	}
	t.Fatalf("%s is not in Refutations()", id)
	return nil
}

// ---------------------------------------------------------------------------
// CheckExpectation — one RED control per check.
//
// Each test below feeds a case that ONLY the named check rejects, so deleting
// that check makes exactly that test go green. The deletion attack is recorded
// in drafts/self-review/; these are the cases it used.
// ---------------------------------------------------------------------------

func refutedResult(paths []string, keysA, keysB []string) Result {
	return Result{ProbeID: "RED", Verdict: Refuted, CollisionPaths: paths,
		KeysA: keysA, KeysB: keysB, WitnessKind: "wire",
		IdentityMoved: []string{"request_id"}}
}

func okKeys() []string {
	return []string{"counts", "events", "final_state", "frames", "outcome",
		"protocol", "request_digest", "request_id", "version"}
}

// TestExpectationRejectsAProbeThatDeclaresNothing covers a branch that a
// deletion attack showed is NOT uniquely load-bearing: with the guard removed,
// this same probe is still rejected by the verdict-versus-expectation check
// one line below, because a blank expectation cannot equal a run's verdict.
// That is recorded rather than hidden. The unique guard for a catalog entry
// that declares nothing is CheckEveryProbeDeclaresAnExpectation, which Build
// calls before deciding anything and which attack A7 does turn red.
func TestExpectationRejectsAProbeThatDeclaresNothing(t *testing.T) {
	err := CheckExpectation(Probe{ID: "RED-E1"},
		refutedResult([]string{"frames[0].wire_bytes"}, okKeys(), okKeys()))
	if err == nil {
		t.Fatal("a probe with no declared expectation was accepted; nothing about it could " +
			"then be falsified by a run")
	}
	if !strings.Contains(err.Error(), "cannot be falsified by running it") {
		t.Fatalf("message %q does not say why a blank declaration is inadmissible", err)
	}
}

// TestExpectationRejectsAProbeThatDeclaresAVerdictThisAuditDoesNotIssue is the
// case the declaration guard is UNIQUELY responsible for, and finding it took
// two failed attacks.
//
// The first two attempts fed a bogus expectation against a real REFUTED
// result, and deleting the guard changed nothing: the verdict-comparison check
// one line below rejected it anyway, because a bogus expectation cannot equal
// a real verdict. That is a green reading with the check deleted, and it is
// not evidence. The case that IS uniquely the guard's is a bogus expectation
// matched by an equally bogus verdict, where every downstream check sails
// through: the expectation and the verdict agree, the probe is not CONFIRMED
// so it takes the refutation path, its required path did move, and neither
// answer is an error row. Without the guard this returns nil and a probe
// claiming a verdict this audit does not issue is ACCEPTED.
func TestExpectationRejectsAProbeThatDeclaresAVerdictThisAuditDoesNotIssue(t *testing.T) {
	bogus := Verdict("PROBABLY")
	result := refutedResult([]string{"frames[0].wire_bytes"}, okKeys(), okKeys())
	result.Verdict = bogus
	err := CheckExpectation(
		Probe{ID: "RED-E1b", Expect: bogus, RequiredPaths: []string{"frames[0].wire_bytes"}},
		result)
	if err == nil {
		t.Fatal("a probe declaring verdict PROBABLY, matched by a run reporting PROBABLY, was " +
			"ACCEPTED; this audit issues no such verdict and every other check passes such a " +
			"pair, so nothing else would catch it")
	}
}

// ---------------------------------------------------------------------------
// The decided-candidate status assignment.
//
// This lived inside Build until a deletion attack came back GREEN: Build needs
// a harness binary, so nothing in the default suite covered it and replacing
// the recomputation with a hardcoded EMPTY broke nothing. It is exported now,
// for the same reason and by the same precedent as PartitionCensus.
// ---------------------------------------------------------------------------

func TestStatusAssignmentReadsTheVerdictRatherThanAssumingIt(t *testing.T) {
	decided := []DecidedCandidate{
		{ID: "C-REFUTED", DecidedBy: "NC-10", WhyItWasOpen: "w", Consequence: "c"},
		{ID: "C-EMPTY", DecidedBy: Utf8PremiseCheckID, WhyItWasOpen: "w", Consequence: "c"},
	}
	emptiness := Utf8Emptiness{ID: Utf8PremiseCheckID, Status: StatusEmpty}
	got := AssignDecidedCandidateStatuses(decided,
		map[string]Verdict{"NC-10": Refuted}, emptiness)
	if got[0].Status != StatusRefuted {
		t.Fatalf("a candidate decided by a REFUTED probe got status %q", got[0].Status)
	}
	if got[1].Status != StatusEmpty {
		t.Fatalf("a candidate decided by an EMPTY premise check got status %q", got[1].Status)
	}
}

func TestStatusAssignmentFallsBackToHypothesisWhenTheEvidenceStopsHolding(t *testing.T) {
	// The two ways the evidence can stop holding, and both must REOPEN the
	// candidate rather than leave a stale closed one standing. A hardcoded
	// status would keep reporting REFUTED and EMPTY here.
	decided := []DecidedCandidate{
		{ID: "C-REFUTED", DecidedBy: "NC-10", WhyItWasOpen: "w", Consequence: "c"},
		{ID: "C-EMPTY", DecidedBy: Utf8PremiseCheckID, WhyItWasOpen: "w", Consequence: "c"},
	}
	got := AssignDecidedCandidateStatuses(decided,
		// The refutation probe came back CONFIRMED — the projection erases
		// the distinction after all.
		map[string]Verdict{"NC-10": Confirmed},
		// A premise failed, so the emptiness argument is undecided again.
		Utf8Emptiness{ID: Utf8PremiseCheckID, Status: StatusHypothesis})
	for _, candidate := range got {
		if candidate.Status != StatusHypothesis {
			t.Fatalf("%s is %q after its evidence stopped holding; a decided candidate whose "+
				"evidence fails must REOPEN, not keep its old verdict",
				candidate.ID, candidate.Status)
		}
	}
}

func TestStatusAssignmentLeavesACandidateNothingDecidedEmpty(t *testing.T) {
	// The input CheckDecidedCandidates then refuses. Together they are what
	// stops a candidate carrying a verdict no run produced.
	got := AssignDecidedCandidateStatuses(
		[]DecidedCandidate{{ID: "C-ORPHAN", DecidedBy: "NC-NOT-IN-THIS-DOCUMENT",
			WhyItWasOpen: "w", Consequence: "c"}},
		map[string]Verdict{"NC-10": Refuted},
		Utf8Emptiness{ID: Utf8PremiseCheckID, Status: StatusEmpty})
	if got[0].Status != "" {
		t.Fatalf("a candidate whose decided_by names nothing that ran got status %q; it must "+
			"come out empty so CheckDecidedCandidates can refuse it", got[0].Status)
	}
	if err := CheckDecidedCandidates(got); err == nil {
		t.Fatal("CheckDecidedCandidates accepted a candidate nothing decided")
	}
}

func TestStatusAssignmentDoesNotMutateItsInput(t *testing.T) {
	// The catalog function returns fresh values each call, but a caller that
	// held one across an assignment would otherwise see it change under them.
	decided := []DecidedCandidate{{ID: "C", DecidedBy: "NC-10", WhyItWasOpen: "w", Consequence: "c"}}
	AssignDecidedCandidateStatuses(decided, map[string]Verdict{"NC-10": Refuted},
		Utf8Emptiness{ID: Utf8PremiseCheckID, Status: StatusEmpty})
	if decided[0].Status != "" {
		t.Fatalf("the input list was mutated: %q", decided[0].Status)
	}
}

func TestExpectationRejectsAConfirmedProbeThatTheRunRefuted(t *testing.T) {
	err := CheckExpectation(
		Probe{ID: "RED-E2", Expect: Confirmed},
		refutedResult([]string{"final_state"}, okKeys(), okKeys()))
	if err == nil {
		t.Fatal("a CONFIRMED-declaring probe whose run came back REFUTED was accepted")
	}
	if !strings.Contains(err.Error(), "do not weaken it") {
		t.Fatalf("message %q does not say what to do instead of relaxing the check", err)
	}
}

func TestExpectationRejectsARefutedProbeThatTheRunConfirmed(t *testing.T) {
	// This is the interesting direction: a refutation that comes back
	// CONFIRMED is an EIGHTH collision, and the message has to say so rather
	// than reading as a broken test.
	err := CheckExpectation(
		Probe{ID: "RED-E3", Expect: Refuted, RequiredPaths: []string{"frames[0].wire_bytes"}},
		Result{ProbeID: "RED-E3", Verdict: Confirmed, WitnessKind: "wire",
			KeysA: okKeys(), KeysB: okKeys(), IdentityMoved: []string{"request_id"}})
	if err == nil {
		t.Fatal("a REFUTED-declaring probe whose pair moved NOTHING was accepted; that is an " +
			"unreported additional collision")
	}
	if !strings.Contains(err.Error(), "ADDITIONAL COLLISION") {
		t.Fatalf("message %q does not name the finding this is", err)
	}
}

func TestExpectationRejectsARefutationThatNamesNoPath(t *testing.T) {
	err := CheckExpectation(
		Probe{ID: "RED-E4", Expect: Refuted},
		refutedResult([]string{"anything"}, okKeys(), okKeys()))
	if err == nil {
		t.Fatal("a refutation with no required path was accepted; it would count ANY " +
			"difference as deciding its own candidate")
	}
}

func TestExpectationRejectsARefutationEarnedOnAnUnrelatedPath(t *testing.T) {
	// The pair moved — but on runtime-adjacent noise, not on the path the
	// candidate is about. Decide alone would call this REFUTED.
	err := CheckExpectation(
		Probe{ID: "RED-E5", Expect: Refuted, RequiredPaths: []string{"frames[0].wire_bytes"}},
		refutedResult([]string{"final_state"}, okKeys(), okKeys()))
	if err == nil {
		t.Fatal("a refutation whose pair moved only on an unrelated path was accepted; it " +
			"decides nothing about its own distinction")
	}
	if !strings.Contains(err.Error(), "frames[0].wire_bytes") {
		t.Fatalf("message %q does not name the path that failed to move", err)
	}
}

func TestExpectationRejectsARefutationWhoseInputWasRejected(t *testing.T) {
	// The trap this check exists for. An RFC-strict codec REJECTS a
	// non-minimal extended length; the pair would then differ by outcome and
	// Decide would say REFUTED, but nothing would have shown the projection
	// represents the length encoding.
	errorKeys := []string{"counts", "error", "final_state", "outcome",
		"protocol", "request_digest", "request_id", "version"}
	err := CheckExpectation(
		Probe{ID: "RED-E6", Expect: Refuted, RequiredPaths: []string{"outcome"}},
		refutedResult([]string{"outcome"}, okKeys(), errorKeys))
	if err == nil {
		t.Fatal("a refutation earned by one input being REJECTED was accepted; a rejected " +
			"input does not show the observation carries the distinction")
	}
	if !strings.Contains(err.Error(), "ERROR row") {
		t.Fatalf("message %q does not name why the pair is inadmissible", err)
	}
}

func TestExpectationRejectsAConfirmedProbeThatDemandsMovement(t *testing.T) {
	err := CheckExpectation(
		Probe{ID: "RED-E7", Expect: Confirmed, RequiredPaths: []string{"frames[0].wire_bytes"}},
		Result{ProbeID: "RED-E7", Verdict: Confirmed, WitnessKind: "wire",
			KeysA: okKeys(), KeysB: okKeys(), IdentityMoved: []string{"request_id"}})
	if err == nil {
		t.Fatal("a probe that both erases a distinction and requires movement on it was accepted")
	}
}

func TestExpectationAcceptsAWellFormedRefutation(t *testing.T) {
	// The positive control for all six above: with every condition met the
	// check passes, so the failures are a function of the case and not a
	// constant.
	if err := CheckExpectation(
		Probe{ID: "RED-E8", Expect: Refuted, RequiredPaths: []string{"frames[0].wire_bytes"}},
		refutedResult([]string{"counts.input_bytes", "frames[0].wire_bytes"},
			okKeys(), okKeys())); err != nil {
		t.Fatalf("a well-formed refutation was rejected: %v", err)
	}
}

func TestExpectationAcceptsAWellFormedCollision(t *testing.T) {
	if err := CheckExpectation(
		Probe{ID: "RED-E9", Expect: Confirmed},
		Result{ProbeID: "RED-E9", Verdict: Confirmed, WitnessKind: "wire",
			KeysA: okKeys(), KeysB: okKeys(), IdentityMoved: []string{"request_id"}}); err != nil {
		t.Fatalf("a well-formed collision was rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Decided candidates.
// ---------------------------------------------------------------------------

func TestNoCandidateWasLostBetweenTheTwoLists(t *testing.T) {
	// The first pass named five. Whatever else changed, none of them may
	// simply vanish: a candidate that was quietly DROPPED rather than
	// decided would shrink the undecided count without any run behind it.
	firstPass := map[string]bool{
		"CAND-TRANSPORT": true, "CAND-CROSSARRAY": true, "CAND-UTF8": true,
		"CAND-WIREBYTES": true, "CAND-CHUNKING": true,
	}
	seen := map[string]string{}
	for _, candidate := range Candidates() {
		seen[candidate.ID] = "undecided"
	}
	for _, candidate := range DecidedCandidates() {
		if where, duplicate := seen[candidate.ID]; duplicate {
			t.Fatalf("%s is in both the %s list and the decided list", candidate.ID, where)
		}
		seen[candidate.ID] = "decided"
	}
	for id := range firstPass {
		if _, present := seen[id]; !present {
			t.Fatalf("%s was named by the audit's first pass and is now in NEITHER list; a "+
				"candidate may be decided or stay open, but it may not disappear", id)
		}
	}
	if len(seen) != len(firstPass) {
		t.Fatalf("the two lists carry %d candidates, the first pass named %d: %v",
			len(seen), len(firstPass), seen)
	}
}

func TestTheTwoStructuralCandidatesStayedUndecided(t *testing.T) {
	// CAND-TRANSPORT needs a real peer socket and CAND-CROSSARRAY needs a
	// mutated harness. Neither is reachable from a seed in this package, and
	// a verdict for either here would have been manufactured.
	want := map[string]bool{"CAND-TRANSPORT": true, "CAND-CROSSARRAY": true}
	got := map[string]bool{}
	for _, candidate := range Candidates() {
		got[candidate.ID] = true
	}
	for id := range want {
		if !got[id] {
			t.Fatalf("%s is no longer in the undecided list; it is not decidable from a seed "+
				"in this package, so a verdict for it would be manufactured", id)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("undecided list is %v, want exactly %v", got, want)
	}
}

func TestEveryDecidedCandidatePreservesWhyItWasOpen(t *testing.T) {
	for _, candidate := range DecidedCandidates() {
		if candidate.WhyItWasOpen == "" {
			t.Fatalf("%s does not carry the first pass's reason; the record would then hide "+
				"what changed", candidate.ID)
		}
		if candidate.Consequence == "" {
			t.Fatalf("%s does not say what the decision does to the headline ceilings",
				candidate.ID)
		}
		if candidate.DecidedBy == "" {
			t.Fatalf("%s names nothing that decided it", candidate.ID)
		}
	}
}

func TestDecidedCandidatesAreRefusedWithoutARecomputedStatus(t *testing.T) {
	// RED control: DecidedCandidates() ships with an EMPTY status on every
	// entry, precisely so that Build has to fill it from a run. If that
	// filling were ever removed, this is what catches it.
	if err := CheckDecidedCandidates(DecidedCandidates()); err == nil {
		t.Fatal("the decided-candidate list was accepted with no status on any entry; a " +
			"candidate would then carry a verdict nothing computed")
	}
	filled := DecidedCandidates()
	for i := range filled {
		filled[i].Status = StatusRefuted
	}
	if err := CheckDecidedCandidates(filled); err != nil {
		t.Fatalf("a fully-populated decided list was rejected: %v", err)
	}
}

func TestDecidedCandidatesRefuseAStatusThisAuditDoesNotIssue(t *testing.T) {
	filled := DecidedCandidates()
	for i := range filled {
		filled[i].Status = "PROBABLY"
	}
	if err := CheckDecidedCandidates(filled); err == nil {
		t.Fatal("status \"PROBABLY\" was accepted; this audit issues no such verdict")
	}
}

// ---------------------------------------------------------------------------
// The UTF-8 emptiness premises. The source premises need no harness.
// ---------------------------------------------------------------------------

func TestTheStrictDecodeSitePremiseHoldsOnThisTree(t *testing.T) {
	premise, err := utf8StrictDecodeSitePremise(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if !premise.Holds {
		t.Fatalf("ws-core's text decode site is no longer the strict String::from_utf8: %s. "+
			"CAND-UTF8's EMPTY status rests on exactly this, so it is now UNDECIDED again "+
			"and must be reopened, not patched over.", premise.Evidence)
	}
	if !strings.Contains(premise.Evidence, "String::from_utf8") {
		t.Fatalf("evidence %q does not quote the decode it checked; a premise that reports "+
			"nothing it saw cannot be told from a vacuous one", premise.Evidence)
	}
}

func TestTheStrictDecodeSitePremiseFailsWhenTheSiteTurnsLossy(t *testing.T) {
	// RED control, run against a COPY of the real file with the decode
	// swapped for a lossy one. The premise must go red; if it does not, its
	// green reading on the real tree means nothing.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "rust", "ws-core", "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	real, err := os.ReadFile(filepath.Join(repoRoot(t), "rust", "ws-core", "src", "message.rs"))
	if err != nil {
		t.Fatal(err)
	}
	lossy := strings.Replace(string(real),
		"String::from_utf8(bytes).map_err(|_| Utf8DecodeError)",
		"Ok(String::from_utf8_lossy(&bytes).into_owned())", 1)
	if lossy == string(real) {
		t.Fatal("the strict decode line this control rewrites is no longer in message.rs; " +
			"the control is stale and would pass vacuously")
	}
	if err := os.WriteFile(
		filepath.Join(root, "rust", "ws-core", "src", "message.rs"), []byte(lossy), 0o644); err != nil {
		t.Fatal(err)
	}
	premise, err := utf8StrictDecodeSitePremise(root)
	if err != nil {
		t.Fatal(err)
	}
	if premise.Holds {
		t.Fatal("the premise still HELD against a from_utf8_lossy decode site; CAND-UTF8's " +
			"refutation could then rot silently, which is the one thing this check exists for")
	}
}

func TestTheStrictDecodeSitePremiseFailsWhenTheSiteIsGone(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "rust", "ws-core", "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "rust", "ws-core", "src", "message.rs"),
		[]byte("// the decode moved somewhere else\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	premise, err := utf8StrictDecodeSitePremise(root)
	if err != nil {
		t.Fatal(err)
	}
	if premise.Holds {
		t.Fatal("the premise HELD against a file with no string_utf8 at all; it would then " +
			"pass on any tree that renamed the decode away")
	}
}

func TestTheNoLossyScanHoldsOnBothCrates(t *testing.T) {
	for _, scope := range []string{"rust/ws-core/src", "rust/ws-oracle-harness/src"} {
		premise, err := utf8NoLossyDecodePremise(repoRoot(t), filepath.FromSlash(scope))
		if err != nil {
			t.Fatal(err)
		}
		if !premise.Holds {
			t.Fatalf("%s: %s", scope, premise.Evidence)
		}
		if !strings.Contains(premise.Evidence, ".rs files") {
			t.Fatalf("%s evidence %q does not report how many files it read", scope, premise.Evidence)
		}
	}
}

func TestTheNoLossyScanRefusesToPassOnAnEmptyScan(t *testing.T) {
	// The anti-vacuity guard, and the one that matters most: a scan pointed
	// at a directory with no sources finds zero markers and would otherwise
	// report the premise HOLDS on the strength of having read nothing.
	premise, err := utf8NoLossyDecodePremise(t.TempDir(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if premise.Holds {
		t.Fatal("a scan that read ZERO .rs files reported the premise holds; absence of " +
			"evidence would then be evidence of absence")
	}
	if !strings.Contains(premise.Evidence, "0 .rs files") {
		t.Fatalf("evidence %q does not say the scan was empty", premise.Evidence)
	}
}

func TestTheNoLossyScanFindsAPlantedLossyDecode(t *testing.T) {
	// RED control for the scan itself. Without this, "0 markers found" could
	// mean the pattern never matches anything.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"a.rs": "fn decode(b: Vec<u8>) -> String { String::from_utf8_lossy(&b).into_owned() }\n",
		"b.rs": "const PAD: char = char::REPLACEMENT_CHARACTER;\n",
		"c.rs": "const MARK: u32 = 0xFFFD;\n",
		"d.rs": "const PAD: char = '\\u{FFFD}';\n",
		"e.rs": "// the substitution rule is U+FFFD\n",
		"f.rs": "const LITERAL: char = '\ufffd';\n",
	} {
		if err := os.WriteFile(filepath.Join(root, "src", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	premise, err := utf8NoLossyDecodePremise(root, "src")
	if err != nil {
		t.Fatal(err)
	}
	if premise.Holds {
		t.Fatalf("the scan missed the planted lossy decodes: %s", premise.Evidence)
	}
	for _, name := range []string{"a.rs", "b.rs", "c.rs", "d.rs", "e.rs", "f.rs"} {
		if !strings.Contains(premise.Evidence, name) {
			t.Fatalf("evidence %q does not name %s; the scan found some but not all",
				premise.Evidence, name)
		}
	}
}

func TestTheDiscriminatingSeedsAreTheOnesTheArgumentNeeds(t *testing.T) {
	// The whole experiment turns on the accepted seed carrying the ENCODED
	// U+FFFD and the rejected one carrying what a lossy decoder turns INTO
	// U+FFFD. If either drifts, the run stops discriminating and would go
	// green for the wrong reason.
	accepted, rejected := Utf8Seeds()
	acceptedBytes := stepBytes(t, accepted.Steps)
	rejectedBytes := stepBytes(t, rejected.Steps)
	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	if want := maskedTextFrame([]byte{0xEF, 0xBF, 0xBD}, key); string(acceptedBytes) != string(want) {
		t.Fatalf("accepted seed carries %x, want %x — a text frame whose payload is the "+
			"three octets of U+FFFD", acceptedBytes, want)
	}
	if want := maskedTextFrame([]byte{0xFF}, key); string(rejectedBytes) != string(want) {
		t.Fatalf("rejected seed carries %x, want %x — a text frame whose payload is the lone "+
			"0xFF a lossy decode would fold onto U+FFFD", rejectedBytes, want)
	}
}
