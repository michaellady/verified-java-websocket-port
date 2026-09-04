package autobahnsuite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Probes for the survivor RESIDUE: the three site classes the round-4 sweep
// declared unswept — switch arms, conjuncts inside composite booleans, and
// (in the Rust crates) the checks this package has no reach into.
//
// Read every test here as: with the named line's arm or conjunct neutralised,
// and NO other change, this test goes RED; with the line restored the whole
// package suite is green. Both readings were taken from the process, not
// reasoned about.
//
// The neutralisation used for a conjunct is `(true || (LEAF))` under `&&` and
// `(false && (LEAF))` under `||`, with the leaf parenthesised, so a top-level
// `||` cannot survive the rewrite and no variable becomes unused.

// residueIndexFile writes a minimal wstest report index: one agent, one
// behaviour per case.
func residueIndexFile(t *testing.T, dir, name, agent string, behaviors map[string]string) string {
	t.Helper()
	entries := map[string]any{}
	for id, behavior := range behaviors {
		entries[id] = map[string]any{"behavior": behavior}
	}
	path := filepath.Join(dir, name)
	writeJSONFile(t, path, map[string]any{agent: entries})
	return path
}

// residueManifest builds a manifest over the given case identities.
func residueManifest(strict bool, ids ...string) *Manifest {
	manifest := &Manifest{ExpectedCaseCount: len(ids)}
	for index, id := range ids {
		manifest.Cases = append(manifest.Cases, CaseEntry{
			CaseID:             id,
			Family:             familyOf(id),
			SelectedOrdinal:    index + 1,
			SuiteCaseNumber:    index + 1,
			StrictPassRequired: strict,
		})
	}
	return manifest
}

// ---------------------------------------------------------------------------
// reconcile.go — Discriminate's subject switch (arms) and its per-subject
// AsExpected conjuncts.
// ---------------------------------------------------------------------------

// A ledger reaching Discriminate's switch must reconcile and must have scored
// something; both guards are already closed and are set here so they cannot
// answer in place of the site under probe.
func residueScoredLedger() *Ledger {
	return &Ledger{Reconciles: true, Selected: 4, Executed: 4, Missing: 0}
}

// TestEveryDiscriminateSubjectArmIssuesItsOwnVerdict closes reconcile.go:377
// (the subject-under-test / java-baseline arm), reconcile.go:422 (the mutant
// arm) and reconcile.go:439 (the default arm's only observable, its reason).
func TestEveryDiscriminateSubjectArmIssuesItsOwnVerdict(t *testing.T) {
	// reconcile.go:377 — the arm that reads AC3 literally for the real port
	// and for the pinned Java baseline. With it disabled both subjects fall
	// to `default` and come back "unknown subject" with AsExpected false, so
	// the strongest verdict this package can issue silently stops existing.
	for _, subject := range []Subject{SubjectUnderTest, SubjectJavaBaseline} {
		ledger := residueScoredLedger()
		ledger.Passed = 4
		ledger.StrictPassAll = true
		verdict := Discriminate(subject, ledger)
		if !verdict.AsExpected {
			t.Errorf("%s: a run that strict-passes every case must be AsExpected; got %q",
				subject, verdict.Reason)
		}
		if !strings.Contains(verdict.Reason, "AC3 requires every in-scope case to be a STRICT pass") {
			t.Errorf("%s: the verdict must state the literal AC3 bar it applied, not fall "+
				"through to the unknown-subject arm; got %q", subject, verdict.Reason)
		}
	}

	// reconcile.go:422 — the planted-mutant arm.
	mutant := residueScoredLedger()
	mutant.Failed = 1
	mutant.Passed = 3
	verdict := Discriminate(SubjectMutant, mutant)
	if !verdict.AsExpected {
		t.Errorf("a mutant broken on one case across a complete run is the expected "+
			"outcome; got %q", verdict.Reason)
	}
	if !strings.Contains(verdict.Reason, "expected the planted deviation to break at least one case") {
		t.Errorf("the mutant arm must state the mutant expectation rather than falling "+
			"through to the unknown-subject arm; got %q", verdict.Reason)
	}

	// reconcile.go:439 — the default arm. Its whole observable is the reason
	// text: AsExpected is already the zero value there, so a default that
	// says nothing is a default that is not there.
	unknown := Discriminate(Subject("a-subject-this-package-does-not-know"), residueScoredLedger())
	if unknown.AsExpected {
		t.Error("an unrecognised subject must never be AsExpected")
	}
	if unknown.Reason != "unknown subject" {
		t.Errorf("an unrecognised subject must be NAMED as unknown rather than returning a "+
			"silent zero verdict; got %q", unknown.Reason)
	}
}

// TestTheNegativeControlExpectationIsConjunctByConjunct closes the six
// conjuncts of reconcile.go:410-414. Each case below violates exactly ONE of
// them and satisfies the other five, so a probe cannot be satisfied by
// whichever conjunct happens to fire first.
func TestTheNegativeControlExpectationIsConjunctByConjunct(t *testing.T) {
	// The shape a real negative control has: nothing passed, nothing was
	// non-strict, every scoreable case came back broken, run complete.
	good := &Ledger{
		Reconciles: true, Selected: 4, Executed: 4, Missing: 0,
		Informational: 0, Passed: 0, NonStrict: 0, Failed: 4,
	}
	if verdict := Discriminate(SubjectNegativeControl, good); !verdict.AsExpected {
		t.Fatalf("the baseline shape must be AsExpected or every case below is vacuous; got %q",
			verdict.Reason)
	}
	for _, probe := range []struct {
		name   string
		line   string
		why    string
		ledger *Ledger
	}{
		{
			name: "one scored case passed", line: "reconcile.go:410 ledger.Passed == 0",
			why: "a negative control that PASSED a case has proven the wiring, not the port",
			ledger: &Ledger{Reconciles: true, Selected: 4, Executed: 4, Missing: 0,
				Passed: 1, NonStrict: 0, Failed: 4},
		},
		{
			name: "one scored case was non-strict", line: "reconcile.go:410 ledger.NonStrict == 0",
			why: "NON-STRICT is not a failure; a control that reached it is speaking protocol",
			ledger: &Ledger{Reconciles: true, Selected: 4, Executed: 4, Missing: 0,
				Passed: 0, NonStrict: 1, Failed: 4},
		},
		{
			name: "nothing was scoreable", line: "reconcile.go:411 scoreable > 0",
			why: "every case informational-by-construction means the control was never scored; " +
				"an empty scoreable set must not be a discrimination",
			ledger: &Ledger{Reconciles: true, Selected: 2, Executed: 2, Missing: 0,
				Informational: 2, Passed: 0, NonStrict: 0, Failed: 0},
		},
		{
			name: "only some scoreable cases broke", line: "reconcile.go:411 broken == scoreable",
			why: "a control that implements nothing must fail EVERY scoreable case",
			ledger: &Ledger{Reconciles: true, Selected: 4, Executed: 4, Missing: 0,
				Passed: 0, NonStrict: 0, Failed: 2},
		},
		{
			name: "the run was short of the selected set", line: "reconcile.go:414 executed == selected",
			why: "a control that died early discriminates by absence rather than by behaviour",
			ledger: &Ledger{Reconciles: true, Selected: 4, Executed: 3, Missing: 0,
				Passed: 0, NonStrict: 0, Failed: 4},
		},
		{
			name: "a case is missing", line: "reconcile.go:414 ledger.Missing == 0",
			why: "an absence of evidence for a case is not evidence that the control failed it",
			ledger: &Ledger{Reconciles: true, Selected: 4, Executed: 4, Missing: 1,
				Passed: 0, NonStrict: 0, Failed: 4},
		},
	} {
		t.Run(probe.name, func(t *testing.T) {
			verdict := Discriminate(SubjectNegativeControl, probe.ledger)
			if verdict.AsExpected {
				t.Errorf("%s must be load bearing: %s. verdict=%q",
					probe.line, probe.why, verdict.Reason)
			}
		})
	}
}

// TestTheMutantExpectationIsConjunctByConjunct closes the three conjuncts of
// reconcile.go:429-430.
func TestTheMutantExpectationIsConjunctByConjunct(t *testing.T) {
	good := &Ledger{Reconciles: true, Selected: 4, Executed: 4, Missing: 0, Passed: 3, Failed: 1}
	if verdict := Discriminate(SubjectMutant, good); !verdict.AsExpected {
		t.Fatalf("the baseline shape must be AsExpected; got %q", verdict.Reason)
	}
	for _, probe := range []struct {
		name   string
		line   string
		why    string
		ledger *Ledger
	}{
		{
			name: "nothing broke", line: "reconcile.go:429 broken > 0",
			why:    "a planted deviation that broke no case was not caught by the suite",
			ledger: &Ledger{Reconciles: true, Selected: 4, Executed: 4, Missing: 0, Passed: 4},
		},
		{
			name: "the run was short", line: "reconcile.go:430 executed == selected",
			why: "a mutant run that terminated early leaves cases unscored, and an unscored " +
				"case is not a deviation the suite detected",
			ledger: &Ledger{Reconciles: true, Selected: 4, Executed: 3, Missing: 0, Failed: 1},
		},
		{
			name: "a case is missing", line: "reconcile.go:430 ledger.Missing == 0",
			why:    "Missing is a run that did not happen, not a deviation",
			ledger: &Ledger{Reconciles: true, Selected: 4, Executed: 4, Missing: 1, Failed: 1},
		},
	} {
		t.Run(probe.name, func(t *testing.T) {
			verdict := Discriminate(SubjectMutant, probe.ledger)
			if verdict.AsExpected {
				t.Errorf("%s must be load bearing: %s. verdict=%q",
					probe.line, probe.why, verdict.Reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// baseline.go — DiscriminateAgainstBaseline's whole switch and its AsExpected
// conjuncts.
// ---------------------------------------------------------------------------

func residueAgreement() *Agreement {
	return &Agreement{
		Role: RoleClient, SubjectAgent: "rust", BaselineAgent: "java",
		Expected: 3, Agree: 3, Partitions: true,
	}
}

func residueReconciledLedger() *Ledger {
	return &Ledger{Reconciles: true, Selected: 3, Executed: 3, Passed: 3}
}

// TestDiscriminateAgainstBaselineAnswersForEachMissingInput closes
// baseline.go:303 (the whole nil arm) and each of its three conjuncts. With
// the arm gone the nil dereferences one line later and the test PANICS, which
// is a failing test; with a single conjunct gone the matching nil input
// reaches the same dereference.
func TestDiscriminateAgainstBaselineAnswersForEachMissingInput(t *testing.T) {
	for _, probe := range []struct {
		name     string
		subject  *Ledger
		baseline *Ledger
		agree    *Agreement
	}{
		{"no subject ledger", nil, residueReconciledLedger(), residueAgreement()},
		{"no baseline ledger", residueReconciledLedger(), nil, residueAgreement()},
		{"no agreement", residueReconciledLedger(), residueReconciledLedger(), nil},
	} {
		t.Run(probe.name, func(t *testing.T) {
			verdict := DiscriminateAgainstBaseline(probe.subject, probe.baseline, probe.agree)
			if verdict.AsExpected {
				t.Error("a comparison missing one of its three inputs must never be AsExpected")
			}
			if verdict.Reason != "missing ledger or agreement" {
				t.Errorf("the amended bar must REFUSE a missing input by name rather than "+
					"dereferencing it; got %q", verdict.Reason)
			}
		})
	}
}

// TestDiscriminateAgainstBaselineNamesWhichSideDidNotReconcile closes
// baseline.go:305 and baseline.go:308. The two arms are distinguished by their
// TEXT, not by a shared "an error came back", because a probe satisfied by
// either arm is satisfied by whichever fires first.
func TestDiscriminateAgainstBaselineNamesWhichSideDidNotReconcile(t *testing.T) {
	subjectBroken := residueReconciledLedger()
	subjectBroken.Reconciles = false
	verdict := DiscriminateAgainstBaseline(subjectBroken, residueReconciledLedger(), residueAgreement())
	if verdict.AsExpected {
		t.Error("a subject report that does not reconcile cannot satisfy the amended bar")
	}
	if !strings.Contains(verdict.Reason, "the subject's report does not reconcile") {
		t.Errorf("baseline.go:305 must name the SUBJECT as the side that did not reconcile; "+
			"got %q", verdict.Reason)
	}

	baselineBroken := residueReconciledLedger()
	baselineBroken.Reconciles = false
	verdict = DiscriminateAgainstBaseline(residueReconciledLedger(), baselineBroken, residueAgreement())
	if verdict.AsExpected {
		t.Error("a Java baseline that does not reconcile is nothing to agree WITH")
	}
	if !strings.Contains(verdict.Reason, "the Java baseline's report does not reconcile") {
		t.Errorf("baseline.go:308 must name the BASELINE as the side that did not reconcile, "+
			"and must not be answered by the subject's guard one arm above; got %q",
			verdict.Reason)
	}
}

// TestDiscriminateAgainstBaselineRefusesANonPartitioningComparison closes
// baseline.go:311.
func TestDiscriminateAgainstBaselineRefusesANonPartitioningComparison(t *testing.T) {
	agreement := residueAgreement()
	agreement.Partitions = false
	agreement.Identities = []string{"agree + ... = 2, expected 3"}
	verdict := DiscriminateAgainstBaseline(residueReconciledLedger(), residueReconciledLedger(), agreement)
	if verdict.AsExpected {
		t.Error("a comparison whose buckets do not add up to the manifest cannot be scored")
	}
	if !strings.Contains(verdict.Reason, "does not partition the manifest") {
		t.Errorf("baseline.go:311 must refuse a non-partitioning comparison by name; got %q",
			verdict.Reason)
	}
}

// TestDiscriminateAgainstBaselineRefusesUnobservedCases closes
// baseline.go:323.
func TestDiscriminateAgainstBaselineRefusesUnobservedCases(t *testing.T) {
	agreement := residueAgreement()
	agreement.Agree = 2
	agreement.Unobserved = 1
	verdict := DiscriminateAgainstBaseline(residueReconciledLedger(), residueReconciledLedger(), agreement)
	if verdict.AsExpected {
		t.Error("cases neither run scored cannot be counted as agreement")
	}
	if !strings.Contains(verdict.Reason, "an absence of evidence is not agreement") {
		t.Errorf("baseline.go:323 must refuse unobserved cases by name; got %q", verdict.Reason)
	}
}

// TestTheAmendedBarCountsUnregisteredDeltaAndTheAgreementSum closes the two
// conjuncts of baseline.go:330-331.
func TestTheAmendedBarCountsUnregisteredDeltaAndTheAgreementSum(t *testing.T) {
	if verdict := DiscriminateAgainstBaseline(
		residueReconciledLedger(), residueReconciledLedger(), residueAgreement(),
	); !verdict.AsExpected {
		t.Fatalf("a fully agreeing comparison must pass the amended bar; got %q", verdict.Reason)
	}

	unregistered := residueAgreement()
	unregistered.UnregisteredDelta = 1
	if verdict := DiscriminateAgainstBaseline(
		residueReconciledLedger(), residueReconciledLedger(), unregistered,
	); verdict.AsExpected {
		t.Error("baseline.go:330 must be load bearing: a divergence that no register entry " +
			"accounts for cannot be waved through by the amended bar")
	}

	short := residueAgreement()
	short.Agree = 2
	if verdict := DiscriminateAgainstBaseline(
		residueReconciledLedger(), residueReconciledLedger(), short,
	); verdict.AsExpected {
		t.Error("baseline.go:331 must be load bearing: agree + subject_stricter + " +
			"registered must ACCOUNT FOR the whole manifest, not merely leave no " +
			"unregistered residue")
	}
}

// ---------------------------------------------------------------------------
// reconcile.go — the behaviour classification switch and its neighbours.
// ---------------------------------------------------------------------------

// TestAnUnimplementedBehaviorIsSkippedNotUnclassified closes
// reconcile.go:215, and TestAnUnknownBehaviorIsUnclassifiedAndNamed closes
// reconcile.go:218 (the default). The two are separated deliberately: with
// the UNIMPLEMENTED arm disabled the case lands in `default`, which is a
// DIFFERENT published count, and a probe that only asserted "not passed"
// could not tell them apart.
func TestAnUnimplementedBehaviorIsSkippedNotUnclassified(t *testing.T) {
	dir := t.TempDir()
	index := residueIndexFile(t, dir, "index.json", "an-agent", map[string]string{
		"1.1.1": BehaviorOK,
		"1.1.2": BehaviorUnimplemented,
	})
	ledger, err := Reconcile(residueManifest(false, "1.1.1", "1.1.2"), index, "", nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if ledger.Skipped != 1 {
		t.Errorf("UNIMPLEMENTED must be counted as SKIPPED; skipped=%d unclassified=%d",
			ledger.Skipped, ledger.Unclassified)
	}
	if ledger.Unclassified != 0 {
		t.Errorf("a behaviour the suite DOES define must not be filed as unclassified; "+
			"unclassified=%d cases=%v", ledger.Unclassified, ledger.UnclassifiedCases)
	}
	if len(ledger.SkippedCases) != 1 || ledger.SkippedCases[0] != "1.1.2" {
		t.Errorf("the skipped case must be named; got %v", ledger.SkippedCases)
	}
}

func TestAnUnknownBehaviorIsUnclassifiedAndNamed(t *testing.T) {
	dir := t.TempDir()
	index := residueIndexFile(t, dir, "index.json", "an-agent", map[string]string{
		"1.1.1": BehaviorOK,
		"1.1.2": "A-BEHAVIOUR-THIS-SUITE-DOES-NOT-DEFINE",
	})
	ledger, err := Reconcile(residueManifest(false, "1.1.1", "1.1.2"), index, "", nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if ledger.Unclassified != 1 {
		t.Errorf("a behaviour outside the suite's vocabulary must be counted UNCLASSIFIED "+
			"rather than silently dropped; unclassified=%d", ledger.Unclassified)
	}
	if len(ledger.UnclassifiedCases) != 1 ||
		!strings.Contains(ledger.UnclassifiedCases[0], "A-BEHAVIOUR-THIS-SUITE-DOES-NOT-DEFINE") {
		t.Errorf("the unclassified case must carry the behaviour string it was filed under, "+
			"or a reader cannot tell what the run actually said; got %v",
			ledger.UnclassifiedCases)
	}
	if ledger.Passed+ledger.NonStrict+ledger.Informational+ledger.Failed+ledger.Skipped != 1 {
		t.Errorf("exactly one other case (1.1.1) must be classified; ledger=%+v", ledger)
	}
}

// TestTheStrictRequirementIsConsumedOnlyForCasesThatDeclareIt closes the
// `entry.StrictPassRequired` conjunct at reconcile.go:223. Neutralised, every
// non-OK case counts against the strict bar whether the manifest asked for it
// or not, and StrictPassRequired stops being a declaration.
func TestTheStrictRequirementIsConsumedOnlyForCasesThatDeclareIt(t *testing.T) {
	dir := t.TempDir()
	index := residueIndexFile(t, dir, "index.json", "an-agent", map[string]string{
		"1.1.1": BehaviorFailed,
	})
	ledger, err := Reconcile(residueManifest(false, "1.1.1"), index, "", nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if ledger.StrictRequiredNotOK != 0 {
		t.Errorf("a case the manifest does NOT declare strict-pass-required must not be "+
			"counted against the strict bar; strict_required_not_ok=%d cases=%v",
			ledger.StrictRequiredNotOK, ledger.StrictRequiredNotOKCases)
	}
	strict, err := Reconcile(residueManifest(true, "1.1.1"), index, "", nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if strict.StrictRequiredNotOK != 1 {
		t.Fatalf("the same failing case MUST count once the manifest declares it; got %d. "+
			"Without this half the probe above passes vacuously", strict.StrictRequiredNotOK)
	}
}

// TestRequireAgentAcceptsTheAgentTheIndexIsFiledUnder closes the
// `agent != options.RequireAgent` conjunct at reconcile.go:135. Neutralised,
// the gate refuses EVERY report whenever RequireAgent is set at all, which
// would make the AC4 agent binding unusable rather than strict.
func TestRequireAgentAcceptsTheAgentTheIndexIsFiledUnder(t *testing.T) {
	dir := t.TempDir()
	index := residueIndexFile(t, dir, "index.json", "the-real-agent", map[string]string{
		"1.1.1": BehaviorOK,
	})
	ledger, err := Reconcile(residueManifest(true, "1.1.1"), index, "",
		&Options{RequireAgent: "the-real-agent"})
	if err != nil {
		t.Fatalf("a report filed under exactly the required agent must be ACCEPTED, "+
			"or RequireAgent refuses everything: %v", err)
	}
	if ledger.Agent != "the-real-agent" {
		t.Errorf("the ledger must carry the agent it read; got %q", ledger.Agent)
	}
	if _, err := Reconcile(residueManifest(true, "1.1.1"), index, "",
		&Options{RequireAgent: "some-other-agent"}); err == nil {
		t.Fatal("a report filed under another agent must still be refused; without this " +
			"half the probe above passes vacuously")
	}
}

// TestAnIndexCaseOutsideTheManifestStopsReconciliation closes the
// `len(ledger.UnexpectedCases) == 0` conjunct at reconcile.go:309.
func TestAnIndexCaseOutsideTheManifestStopsReconciliation(t *testing.T) {
	dir := t.TempDir()
	index := residueIndexFile(t, dir, "index.json", "an-agent", map[string]string{
		"1.1.1": BehaviorOK,
		"9.9.9": BehaviorOK,
	})
	ledger, err := Reconcile(residueManifest(true, "1.1.1"), index, "", nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(ledger.UnexpectedCases) != 1 || ledger.UnexpectedCases[0] != "9.9.9" {
		t.Fatalf("the out-of-manifest case must be named; got %v", ledger.UnexpectedCases)
	}
	if ledger.Reconciles {
		t.Error("reconcile.go:309 must be load bearing: a report that scored a case the " +
			"manifest does not contain has not reconciled with the manifest, and every " +
			"other identity here holds")
	}
}

// TestAFilteredCaseTheIndexStillScoresBreaksTheIndexSizeIdentity closes the
// `ledger.IndexEntryCount == ledger.Executed+len(ledger.UnexpectedCases)`
// conjunct at reconcile.go:316. It is the one identity in the predicate that
// compares the counting walk against something OUTSIDE it.
func TestAFilteredCaseTheIndexStillScoresBreaksTheIndexSizeIdentity(t *testing.T) {
	dir := t.TempDir()
	index := residueIndexFile(t, dir, "index.json", "an-agent", map[string]string{
		"1.1.1": BehaviorOK,
		"1.1.2": BehaviorOK,
	})
	manifest := residueManifest(true, "1.1.1", "1.1.2")
	ledger, err := Reconcile(manifest, index, "", &Options{FilteredCases: []string{"1.1.2"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if ledger.Filtered != 1 || ledger.Executed != 1 || ledger.Missing != 0 {
		t.Fatalf("the probe needs exactly one filtered and one executed case; "+
			"filtered=%d executed=%d missing=%d", ledger.Filtered, ledger.Executed, ledger.Missing)
	}
	if len(ledger.UnexpectedCases) != 0 {
		t.Fatalf("a filtered case is still IN the manifest, so it is not unexpected; got %v",
			ledger.UnexpectedCases)
	}
	if ledger.Reconciles {
		t.Error("reconcile.go:316 must be load bearing: the report's own index holds 2 " +
			"entries while the walk executed 1 and found 0 unexpected, and that is a " +
			"contradiction between the run and the gate's own scope")
	}
}

// TestStrictPassAllRequiresReconciliationAndEveryCasePassing closes the
// `ledger.Reconciles` conjunct at reconcile.go:319 and the
// `ledger.Passed == ledger.Executed` conjunct at reconcile.go:321.
func TestStrictPassAllRequiresReconciliationAndEveryCasePassing(t *testing.T) {
	dir := t.TempDir()

	// reconcile.go:319 — a run that does not reconcile, but whose three
	// other strict-pass conjuncts all hold.
	unexpected := residueIndexFile(t, dir, "unexpected.json", "an-agent", map[string]string{
		"1.1.1": BehaviorOK,
		"9.9.9": BehaviorOK,
	})
	ledger, err := Reconcile(residueManifest(true, "1.1.1"), unexpected, "", nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if ledger.Reconciles {
		t.Fatal("this probe needs a non-reconciling ledger; it is stale")
	}
	if ledger.Executed != ledger.Selected || ledger.Passed != ledger.Executed ||
		ledger.StrictRequiredNotOK != 0 {
		t.Fatalf("the other three strict-pass conjuncts must hold or this probe is not "+
			"isolating: executed=%d selected=%d passed=%d strict_not_ok=%d",
			ledger.Executed, ledger.Selected, ledger.Passed, ledger.StrictRequiredNotOK)
	}
	if ledger.StrictPassAll {
		t.Error("reconcile.go:319 must be load bearing: a report that has not reconciled " +
			"with the manifest cannot report a strict pass over it")
	}

	// reconcile.go:321 — a case that did not pass but is not strict-required,
	// so the strict_required_not_ok conjunct cannot answer instead.
	failing := residueIndexFile(t, dir, "failing.json", "an-agent", map[string]string{
		"1.1.1": BehaviorOK,
		"1.1.2": BehaviorFailed,
	})
	loose, err := Reconcile(residueManifest(false, "1.1.1", "1.1.2"), failing, "", nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !loose.Reconciles || loose.Executed != loose.Selected || loose.StrictRequiredNotOK != 0 {
		t.Fatalf("the other three conjuncts must hold: reconciles=%t executed=%d selected=%d "+
			"strict_not_ok=%d", loose.Reconciles, loose.Executed, loose.Selected,
			loose.StrictRequiredNotOK)
	}
	if loose.StrictPassAll {
		t.Error("reconcile.go:321 must be load bearing: a run with a FAILED case is not a " +
			"strict pass over the whole selected set, whatever the manifest declared " +
			"about that case individually")
	}
}

// ---------------------------------------------------------------------------
// baseline.go — CompareToBaseline's classification switches and conjuncts.
// ---------------------------------------------------------------------------

// residueComparison runs CompareToBaseline over two synthetic indexes.
func residueComparison(
	t *testing.T,
	manifestIDs []string,
	subject, baseline map[string]string,
	register *DivergenceRegister,
) *Agreement {
	t.Helper()
	dir := t.TempDir()
	subjectPath := residueIndexFile(t, dir, "subject.json", "rust-agent", subject)
	baselinePath := residueIndexFile(t, dir, "baseline.json", "java-agent", baseline)
	agreement, err := CompareToBaseline(
		residueManifest(true, manifestIDs...), RoleClient, subjectPath, baselinePath, register)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	return agreement
}

func residueRow(t *testing.T, agreement *Agreement, caseID string) CaseAgreement {
	t.Helper()
	for _, row := range agreement.Cases {
		if row.CaseID == caseID {
			return row
		}
	}
	t.Fatalf("no row for case %s in %v", caseID, agreement.Cases)
	return CaseAgreement{}
}

// TestASubjectMissingCaseIsUnobservedJustLikeAMissingBaselineCase closes the
// `!subjectRan` conjunct at baseline.go:224. The already-closed probe for that
// arm drops a case from the BASELINE index only, so the subject half of the
// disjunction was never exercised.
func TestASubjectMissingCaseIsUnobservedJustLikeAMissingBaselineCase(t *testing.T) {
	agreement := residueComparison(t,
		[]string{"1.1.1", "1.1.2"},
		map[string]string{"1.1.1": BehaviorOK},
		map[string]string{"1.1.1": BehaviorOK, "1.1.2": BehaviorOK},
		nil)
	if agreement.Unobserved != 1 {
		t.Fatalf("a case only the BASELINE ran is unobserved; unobserved=%d", agreement.Unobserved)
	}
	row := residueRow(t, agreement, "1.1.2")
	if row.Class != AgreementUnobserved {
		t.Errorf("baseline.go:224's `!subjectRan` half must be load bearing: without it a "+
			"case the SUBJECT never ran is classified from a zero-valued entry and is "+
			"scored as though both runs had produced it; got class %q", row.Class)
	}
	if row.BaselineBehavior != BehaviorOK || row.SubjectBehavior != "" {
		t.Errorf("an unobserved row must carry whichever side DID run it and nothing else; "+
			"got subject=%q baseline=%q", row.SubjectBehavior, row.BaselineBehavior)
	}
}

// TestASubjectStricterCaseIsItsOwnClass closes baseline.go:243.
func TestASubjectStricterCaseIsItsOwnClass(t *testing.T) {
	agreement := residueComparison(t,
		[]string{"1.1.1"},
		map[string]string{"1.1.1": BehaviorOK},
		map[string]string{"1.1.1": BehaviorFailed},
		nil)
	if agreement.SubjectStricter != 1 || agreement.Differ != 0 {
		t.Errorf("baseline.go:243 must be load bearing: a case the port passes and the "+
			"pinned Java baseline fails is SUBJECT-STRICTER, which the amended bar counts "+
			"as safe; disabled, it becomes DIFFER, which the bar refuses. "+
			"subject_stricter=%d differ=%d", agreement.SubjectStricter, agreement.Differ)
	}
	if row := residueRow(t, agreement, "1.1.1"); row.Class != AgreementSubjectStricter {
		t.Errorf("the row's class must be %q; got %q", AgreementSubjectStricter, row.Class)
	}
}

// TestTwoDifferentNonOkBehaviorsAreClassifiedDiffer closes baseline.go:246,
// the inner default arm.
func TestTwoDifferentNonOkBehaviorsAreClassifiedDiffer(t *testing.T) {
	agreement := residueComparison(t,
		[]string{"1.1.1"},
		map[string]string{"1.1.1": BehaviorFailed},
		map[string]string{"1.1.1": BehaviorNonStrict},
		nil)
	if agreement.Differ != 1 {
		t.Errorf("baseline.go:246 must be load bearing: two DIFFERENT non-OK behaviours "+
			"are a divergence, and with the default arm gone the row is left unclassified "+
			"and counted nowhere; differ=%d", agreement.Differ)
	}
	if row := residueRow(t, agreement, "1.1.1"); row.Class != AgreementDiffer {
		t.Errorf("the row's class must be %q; got %q", AgreementDiffer, row.Class)
	}
	if !agreement.Partitions {
		t.Error("with no class assigned the buckets no longer add up to the manifest, so " +
			"Partitions is the second observable this arm carries")
	}
}

// TestARegisteredDifferCaseIsCountedRegistered closes the
// `row.Class == AgreementDiffer` disjunct at baseline.go:255.
func TestARegisteredDifferCaseIsCountedRegistered(t *testing.T) {
	register := &DivergenceRegister{Entries: []DivergenceEntry{{
		CaseID: "1.1.1", Role: RoleClient,
		SubjectBehavior: BehaviorFailed, BaselineBehavior: BehaviorNonStrict,
		LedgerDeltaID: "delta-1", LedgerSequence: 7,
	}}}
	agreement := residueComparison(t,
		[]string{"1.1.1"},
		map[string]string{"1.1.1": BehaviorFailed},
		map[string]string{"1.1.1": BehaviorNonStrict},
		register)
	if agreement.Differ != 1 {
		t.Fatalf("this probe needs a DIFFER row; differ=%d", agreement.Differ)
	}
	if agreement.RegisteredDelta != 1 || agreement.UnregisteredDelta != 0 {
		t.Errorf("baseline.go:255's `AgreementDiffer` half must be load bearing: without it "+
			"a DIFFER case is never looked up in the register at all, so it is neither "+
			"registered nor unregistered and the amended bar's arithmetic loses it. "+
			"registered=%d unregistered=%d", agreement.RegisteredDelta, agreement.UnregisteredDelta)
	}
	if row := residueRow(t, agreement, "1.1.1"); row.RegisterRef == "" {
		t.Error("a registered divergence must carry its register reference on the row")
	}
}

// ---------------------------------------------------------------------------
// baseline.go — the register checks.
// ---------------------------------------------------------------------------

// TestAStaleRegisterEntryOnAnAgreeingCaseIsReported closes baseline.go:674.
// VerifyRegisterIsExact documents itself as checking BOTH directions; the
// stale direction had no probe.
func TestAStaleRegisterEntryOnAnAgreeingCaseIsReported(t *testing.T) {
	agreement := &Agreement{
		Role: RoleClient, Expected: 1, Agree: 1, Partitions: true,
		Cases: []CaseAgreement{{
			CaseID: "1.1.1", Class: AgreementAgree,
			SubjectBehavior: BehaviorOK, BaselineBehavior: BehaviorOK,
		}},
	}
	register := &DivergenceRegister{Entries: []DivergenceEntry{{
		CaseID: "1.1.1", Role: RoleClient,
		SubjectBehavior: BehaviorFailed, BaselineBehavior: BehaviorOK,
	}}}
	problems := VerifyRegisterIsExact(register, agreement)
	requireProblem(t, problems, "is registered as a divergence but the runs agree on it",
		"baseline.go:674 is the STALE-ENTRY direction of a check whose own comment promises "+
			"both directions. A register entry that outlives the divergence it records is a "+
			"standing licence for a regression on that case")
}

// TestAnUnregisteredDifferCaseIsReportedByVerifyRegisterIsExact closes the
// `row.Class == AgreementDiffer` disjunct at baseline.go:661.
func TestAnUnregisteredDifferCaseIsReportedByVerifyRegisterIsExact(t *testing.T) {
	agreement := &Agreement{
		Role: RoleClient, Expected: 1, Differ: 1, Partitions: true,
		Cases: []CaseAgreement{{
			CaseID: "1.1.1", Class: AgreementDiffer,
			SubjectBehavior: BehaviorFailed, BaselineBehavior: BehaviorNonStrict,
		}},
	}
	problems := VerifyRegisterIsExact(&DivergenceRegister{}, agreement)
	requireProblem(t, problems, "diverges (subject=FAILED baseline=NON-STRICT) and no register entry accounts for it",
		"baseline.go:661's `AgreementDiffer` half must be load bearing: without it a case "+
			"where the two runs simply DISAGREE never enters the observed set, so an "+
			"unregistered DIFFER divergence is reported by nothing")
}

// TestARegisterEntryNamingAnAbsentLedgerSequenceIsReported closes
// baseline.go:630.
func TestARegisterEntryNamingAnAbsentLedgerSequenceIsReported(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.json")
	writeJSONFile(t, ledgerPath, map[string]any{"records": []any{
		map[string]any{"sequence": 1, "delta": map[string]any{
			"delta_id": "delta-1", "autobahn_refs": []any{"autobahn-client:1.1.1"},
		}},
	}})
	register := &DivergenceRegister{Entries: []DivergenceEntry{{
		CaseID: "1.1.1", Role: RoleClient, LedgerDeltaID: "delta-1", LedgerSequence: 42,
	}}}
	problems, err := VerifyRegisterAgainstLedger(register, ledgerPath)
	if err != nil {
		t.Fatalf("VerifyRegisterAgainstLedger: %v", err)
	}
	requireProblem(t, problems, "which the ledger does not contain",
		"baseline.go:630 must be load bearing: a register entry citing a ledger sequence "+
			"that does not exist is unanchored, and with the arm gone the zero-valued "+
			"record is compared instead and the entry is accepted on a delta id it never matched")
}

// TestOnlyAutobahnPrefixedRefsAreCountedAsCitations closes the
// `strings.HasPrefix(ref, autobahnRefPrefix)` conjunct at baseline.go:614.
func TestOnlyAutobahnPrefixedRefsAreCountedAsCitations(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.json")
	writeJSONFile(t, ledgerPath, map[string]any{"records": []any{
		map[string]any{"sequence": 1, "delta": map[string]any{
			"delta_id": "delta-1", "autobahn_refs": []any{"some-other-scheme:1.1.1"},
		}},
	}})
	register := &DivergenceRegister{Entries: []DivergenceEntry{{
		CaseID: "1.1.1", Role: RoleClient, LedgerDeltaID: "delta-1", LedgerSequence: 1,
	}}}
	problems, err := VerifyRegisterAgainstLedger(register, ledgerPath)
	if err != nil {
		t.Fatalf("VerifyRegisterAgainstLedger: %v", err)
	}
	requireProblem(t, problems, "does not cite this Autobahn case",
		"baseline.go:614's prefix half must be load bearing: any colon-bearing reference "+
			"would otherwise be read as an Autobahn citation, and a ledger record that "+
			"analyses something else entirely would be accepted as analysing this case")
}

// TestALedgerRefWithoutACaseIdCitesNoCase closes the `found` conjunct at
// baseline.go:614. `autobahnRefPrefix` is "autobahn-" and carries no colon, so
// a prefixed reference with no colon at all is exactly the input that
// separates the two conjuncts.
func TestALedgerRefWithoutACaseIdCitesNoCase(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.json")
	writeJSONFile(t, ledgerPath, map[string]any{"records": []any{
		map[string]any{"sequence": 1, "delta": map[string]any{
			"delta_id": "delta-1", "autobahn_refs": []any{"autobahn-with-no-case-id"},
		}},
	}})
	register := &DivergenceRegister{Entries: []DivergenceEntry{{
		CaseID: "", Role: RoleClient, LedgerDeltaID: "delta-1", LedgerSequence: 1,
	}}}
	problems, err := VerifyRegisterAgainstLedger(register, ledgerPath)
	if err != nil {
		t.Fatalf("VerifyRegisterAgainstLedger: %v", err)
	}
	requireProblem(t, problems, "does not cite this Autobahn case",
		"baseline.go:614's `found` half must be load bearing: a reference carrying the "+
			"autobahn- prefix and NO colon has no case id, and without the guard it is "+
			"indexed under the empty case id, which then answers for a register entry "+
			"that names no case")
}

// ---------------------------------------------------------------------------
// baseline.go — VerifyComparisonDocument's composite conditions.
// ---------------------------------------------------------------------------

func requireNoFinding(t *testing.T, findings []ComparisonFinding, caseID, field, why string) {
	t.Helper()
	for _, finding := range findings {
		if finding.CaseID == caseID && finding.Field == field {
			t.Errorf("unexpected finding %s/%s: %q\n%s", caseID, field, finding.Detail, why)
		}
	}
}

// TestADocumentThatOmitsAnAgentKeyIsNotAccusedOfNamingTheWrongAgent closes the
// `present` conjunct at baseline.go:449.
func TestADocumentThatOmitsAnAgentKeyIsNotAccusedOfNamingTheWrongAgent(t *testing.T) {
	forged := forgeComparison(t, func(t *testing.T, doc map[string]any) {
		t.Helper()
		agents, ok := doc["agents"].(map[string]any)
		if !ok {
			t.Fatal("the committed comparison document carries no agents map; probe is stale")
		}
		if _, present := agents["rust_client_role"]; !present {
			t.Fatal("the committed document does not name rust_client_role; probe is stale")
		}
		delete(agents, "rust_client_role")
	})
	findings := verifyForged(t, forged)
	requireNoFinding(t, findings, "", "agents.rust_client_role",
		"baseline.go:449's `present` half must be load bearing: an ABSENT agent key is "+
			"not a document naming the wrong agent, and reporting it as one turns the "+
			"lookup's zero value into an accusation")
}

// TestADocumentRowWithoutAStrictPassClaimIsNotAccusedOfContradictingOne closes
// the `ok` conjunct at baseline.go:474.
func TestADocumentRowWithoutAStrictPassClaimIsNotAccusedOfContradictingOne(t *testing.T) {
	forged := forgeComparison(t, func(t *testing.T, doc map[string]any) {
		t.Helper()
		cases, ok := doc["cases"].([]any)
		if !ok || len(cases) == 0 {
			t.Fatal("the committed comparison document carries no case rows; probe is stale")
		}
		row, ok := cases[0].(map[string]any)
		if !ok {
			t.Fatal("the first case row is not an object; probe is stale")
		}
		if _, present := row["strict_pass_required"]; !present {
			t.Fatal("the first row carries no strict_pass_required; probe is stale")
		}
		delete(row, "strict_pass_required")
	})
	findings := verifyForged(t, forged)
	for _, finding := range findings {
		if finding.Field == "strict_pass_required" {
			t.Errorf("baseline.go:474's `ok` half must be load bearing: a row that RESTATES "+
				"nothing cannot contradict the manifest, and without the type-assertion "+
				"guard the assertion's zero value (false) is compared against a manifest "+
				"that says true. got %s/%s: %q",
				finding.CaseID, finding.Field, finding.Detail)
		}
	}
}

// TestAnEmptyBehaviorOnOneSideIsNotABehaviorDifference closes the
// `rust != ""` and `java != ""` conjuncts at baseline.go:504.
func TestAnEmptyBehaviorOnOneSideIsNotABehaviorDifference(t *testing.T) {
	for _, side := range []string{"rust_client_behavior", "java_client_behavior"} {
		t.Run(side, func(t *testing.T) {
			var caseID string
			forged := forgeComparison(t, func(t *testing.T, doc map[string]any) {
				t.Helper()
				cases, ok := doc["cases"].([]any)
				if !ok || len(cases) == 0 {
					t.Fatal("no case rows; probe is stale")
				}
				row, ok := cases[0].(map[string]any)
				if !ok {
					t.Fatal("the first case row is not an object; probe is stale")
				}
				caseID, _ = row["case_id"].(string)
				if caseID == "" {
					t.Fatal("the first row carries no case_id; probe is stale")
				}
				if stated, _ := row[side].(string); stated == "" {
					t.Fatalf("%s is already empty in the committed document; probe is stale", side)
				}
				row[side] = ""
			})
			findings := verifyForged(t, forged)
			requireNoFinding(t, findings, caseID, "behavior_differences.client_role",
				"baseline.go:504's two non-empty conjuncts must be load bearing: an ABSENT "+
					"behaviour on one side is a row that states nothing, not a row that "+
					"states a difference. Without them every case the document leaves "+
					"blank is demanded in the difference summary, and the summary check "+
					"stops meaning what it says")
		})
	}
}

// ---------------------------------------------------------------------------
// suite.go — the two `seen &&` conjuncts.
// ---------------------------------------------------------------------------

// TestTwoCaseReportsAgreeingOnTheOrdinalAreAccepted closes the
// `prior.Case != report.Case` conjunct at suite.go:228.
func TestTwoCaseReportsAgreeingOnTheOrdinalAreAccepted(t *testing.T) {
	dir := t.TempDir()
	cases := filepath.Join(dir, "cases")
	if err := os.MkdirAll(cases, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// The SAME case, reported twice under two file names, agreeing on the
	// ordinal — which is what a re-emitted report looks like.
	for _, name := range []string{"a.json", "b.json"} {
		writeJSONFile(t, filepath.Join(cases, name), map[string]any{
			"id": "1.1.1", "case": 1, "agent": "an-agent", "behavior": BehaviorOK,
		})
	}
	index := residueIndexFile(t, dir, "index.json", "an-agent", map[string]string{"1.1.1": BehaviorOK})
	ledger, err := Reconcile(residueManifest(true, "1.1.1"), index, cases, nil)
	if err != nil {
		t.Fatalf("suite.go:228's `prior.Case != report.Case` half must be load bearing: two "+
			"reports for the same case that AGREE on the ordinal are consistent evidence, "+
			"and refusing them would make any duplicated report file a hard error: %v", err)
	}
	if ledger.CaseReportCount != 1 {
		t.Errorf("two files for one case id collapse to one report; got %d",
			ledger.CaseReportCount)
	}
}

// TestTwoSourcesInOneRoleThatAgreeAreAccepted closes the
// `prior != report.Case` conjunct at suite.go:294. The already-closed probe
// for that line asserts the DISAGREEING direction; neutralising the second
// conjunct makes every second source in a role a hard error, which that probe
// cannot see.
func TestTwoSourcesInOneRoleThatAgreeAreAccepted(t *testing.T) {
	base, sources := mutableTree(t)
	second := t.TempDir()
	src := filepath.Join(base, "fuzzingserver-run1")
	raw, err := os.ReadFile(filepath.Join(src, "index.json"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(second, "cases"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(second, "index.json"), raw, 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	names, err := filepath.Glob(filepath.Join(src, "cases", "*.json"))
	if err != nil || len(names) == 0 {
		t.Fatalf("glob: %v (%d names)", err, len(names))
	}
	for _, name := range names {
		writeJSONFile(t, filepath.Join(second, "cases", filepath.Base(name)),
			readJSONFile(t, name))
	}
	withSecond := append([]ReportSource(nil), sources...)
	withSecond = append(withSecond, ReportSource{
		Name:      "a-second-client-role-run-that-agrees",
		Role:      RoleClient,
		IndexPath: filepath.Join(second, "index.json"),
		CasesDir:  filepath.Join(second, "cases"),
	})
	manifest, err := BuildManifest(withSecond)
	if err != nil {
		t.Fatalf("suite.go:294's `prior != report.Case` half must be load bearing: two runs "+
			"of the same pinned configuration in the same role that AGREE on every case "+
			"number are exactly what the manifest wants, and refusing them would make a "+
			"second confirming source impossible: %v", err)
	}
	if len(manifest.Cases) != SelectedCaseCount {
		t.Errorf("the expanded manifest must still hold %d cases; got %d",
			SelectedCaseCount, len(manifest.Cases))
	}
}

// ---------------------------------------------------------------------------
// independence.go — the family classification switch.
// ---------------------------------------------------------------------------

// TestAManifestCaseInAnExcludedFamilyIsReported closes independence.go:135.
func TestAManifestCaseInAnExcludedFamilyIsReported(t *testing.T) {
	manifest := residueManifest(true, "9.1.1")
	problems := VerifyManifestIndependence(manifest, nil)
	requireProblem(t, problems, "which the frozen policy EXCLUDES",
		"independence.go:135 must be load bearing: a case from a DECLARED-NONSELECTED "+
			"family in the manifest is the frozen policy being contradicted, and it must "+
			"be reported as an exclusion rather than as a family the policy never mentioned")
}
