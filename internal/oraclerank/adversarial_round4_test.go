package oraclerank

import (
	"strings"
	"testing"
)

// The tests in this file each fail when ONE production check added by the
// round-4 adversarial pass is removed. Every one of the three attacks they
// cover regenerated the register and left
// "640 propositions adjudicated; 589 Java/Rust agreements, 39 of them
// overridden by a higher oracle" byte-identical, so none of them is visible in
// the census this gate prints. They assert the REFUSAL TEXT, not merely a
// non-nil error: a round-3 deletion attack survived because its test was going
// red for an unrelated reason.

// TestASplitArtifactGroupWithNoPathSplitIsRefused is attack O4b. Rank one and
// rank four in the handshake family are read from the SAME document -- the
// rfc_verdict and the java_observable of one entry -- so the independence probe
// declines to score them. Giving rank one a group of its own made the probe
// score the pair: its co-vote count went 18 -> 50 and the register said "18 of
// 50 independently sourced shared propositions", 32 of which were one file
// against itself.
func TestASplitArtifactGroupWithNoPathSplitIsRefused(t *testing.T) {
	f := fabricatedFamily("split-groups",
		[]RankSource{
			{Rank: RankRFC6455, RankName: RankRFC6455.String(), Strength: SourceRecordedReading,
				ArtifactGroup: "one-document-rfc-half", Paths: []string{"evidence/one-document.json"}, Note: "test"},
			{Rank: RankJavaObservation, RankName: RankJavaObservation.String(), Strength: SourceRecordedReading,
				ArtifactGroup: "one-document-java-half", Paths: []string{"evidence/one-document.json"}, Note: "test"},
		},
		Proposition{ID: "p", Question: "q", Opinions: []Opinion{
			opinion(RankRFC6455, "accept"),
			opinion(RankJavaObservation, "accept"),
		}},
	)
	_, err := CheckFamilyRules(f)
	if err == nil {
		t.Fatal("RED FAILED: two ranks reading one declared artifact were split into two groups and the family passed")
	}
	if want := "a group split no path split supports"; !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal does not name the defect (%q):\n%v", want, err)
	}
}

// TestAMergedArtifactGroupWithNoPathMergeIsRefused is attack O4a, the other
// direction. Giving rank three the group of rank one in both families it speaks
// in stopped the pair being scored at all, and the BLOCKING finding
// ORACLE-RANK-INDISTINGUISHABLE-1-3 left the register in favour of a DISCLOSURE.
func TestAMergedArtifactGroupWithNoPathMergeIsRefused(t *testing.T) {
	f := fabricatedFamily("merged-groups",
		[]RankSource{
			{Rank: RankRFC6455, RankName: RankRFC6455.String(), Strength: SourceRecordedReading,
				ArtifactGroup: "shared", Paths: []string{"evidence/reading.json"}, Note: "test"},
			{Rank: RankNeutralExpectation, RankName: RankNeutralExpectation.String(), Strength: SourceContent,
				ArtifactGroup: "shared", Paths: []string{"corpora/other.jsonl"}, Note: "test"},
		},
		Proposition{ID: "p", Question: "q", Opinions: []Opinion{
			opinion(RankRFC6455, "accept"),
			opinion(RankNeutralExpectation, "accept"),
		}},
	)
	_, err := CheckFamilyRules(f)
	if err == nil {
		t.Fatal("RED FAILED: two ranks reading different declared artifacts were merged into one group and the family passed")
	}
	if want := "a group merge no path merge supports"; !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal does not name the defect (%q):\n%v", want, err)
	}
}

// TestTheCommittedFamiliesSatisfyTheGroupPartition is the other polarity: the
// rule must hold on the tree as committed, or it is a rule nobody could keep.
func TestTheCommittedFamiliesSatisfyTheGroupPartition(t *testing.T) {
	families, err := Census(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if err := checkArtifactGroupPartition(f); err != nil {
			t.Fatalf("committed family %s: %v", f.ID, err)
		}
	}
}

// TestTheJoinAnalysisIgnoresAKeyNoCaseReaches is attack O5. Changing ONE
// mapping row the committed corpus never joins on -- server_response
// HS_OBS_FOLD, both verdicts `reject`, set to `accept` -- made the whole-table
// analysis report the join as a measurement and deleted BOTH
// ORACLE-RANK-JOIN-DEGENERATE findings, with every printed number unchanged.
// The disclosure now fires on the keys the census actually joins on.
func TestTheJoinAnalysisIgnoresAKeyNoCaseReaches(t *testing.T) {
	root := repoRoot(t)
	mapping, err := readHandshakeMapping(root)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := readHandshakeCases(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := map[[2]string]bool{}
	for _, c := range cases {
		key, err := handshakeOutcomeKey(c)
		if err != nil {
			t.Fatal(err)
		}
		joined[[2]string{c.Direction, key}] = true
	}

	planted := [2]string{"server_response", "HS_OBS_FOLD"}
	if joined[planted] {
		t.Fatalf("%v is reached by the corpus; this test needs a key that is not", planted)
	}
	entry, ok := mapping[planted]
	if !ok {
		t.Fatalf("%v is not in the committed mapping", planted)
	}
	entry.RFCVerdict, entry.JavaObservable = "accept", "accept"
	mapping[planted] = entry

	jds, err := handshakeJoinDegeneracies(mapping, joined)
	if err != nil {
		t.Fatal(err)
	}
	if len(jds) != 2 {
		t.Fatalf("got %d join analyses, want 2", len(jds))
	}
	for _, jd := range jds {
		if jd.Degenerate {
			t.Fatalf("%s vs %s: the planted counterexample did not reach the whole-table analysis, so this test is not exercising what it claims", jd.Higher, jd.Lower)
		}
		if !jd.DegenerateOverJoinedKeys {
			t.Fatalf("%s vs %s: a counterexample at a key NO case reaches was allowed to make the join a measurement:\n%s", jd.Higher, jd.Lower, jd.Statement)
		}
		if want := "DISAGREEMENT IS STRUCTURALLY IMPOSSIBLE OVER THE KEYS THIS CENSUS JOINS ON"; !strings.Contains(jd.Statement, want) {
			t.Fatalf("%s vs %s: statement does not disclose the split (%q):\n%s", jd.Higher, jd.Lower, want, jd.Statement)
		}
		if jd.JoinedKeysConsidered >= jd.KeysConsidered {
			t.Fatalf("%s vs %s: joined keys %d is not fewer than the table's %d", jd.Higher, jd.Lower, jd.JoinedKeysConsidered, jd.KeysConsidered)
		}
	}
}

// TestABindingMayNotClaimContentWhileItsFamiliesRecordLess is the rank-four
// finding. The binding said CONTENT_BOUND, which is the one value that
// suppresses both the "NOT bound to" obligation in Bindings and the
// ORACLE-RANK-BINDING disclosure in Findings, while the handshake family
// recorded its opinions as a RECORDED_READING of the Java sources and the
// public family DEDUCED them from an aggregate.
func TestABindingMayNotClaimContentWhileItsFamiliesRecordLess(t *testing.T) {
	bindings := []Binding{{
		Rank: RankJavaObservation, RankName: RankJavaObservation.String(),
		Strength: BoundToContent, Statement: "test", Artifacts: []Artifact{{Path: "x", SHA256: "y", Bytes: 1}},
	}}
	families := []Family{{ID: "fabricated", RankSources: []RankSource{
		source(RankJavaObservation, SourceRecordedReading, "reading"),
	}}}
	err := checkBindingStrengthAgainstFamilies(bindings, families)
	if err == nil {
		t.Fatal("RED FAILED: a CONTENT_BOUND rank whose only family reads it from a recorded reading was accepted")
	}
	if want := "a rank may not claim one strength while its own families record a weaker one"; !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal does not name the defect (%q):\n%v", want, err)
	}

	// The other polarity: a rank every family reads from content keeps its
	// CONTENT_BOUND, or the rule would be one nothing could satisfy.
	families[0].RankSources = []RankSource{source(RankJavaObservation, SourceContent, "content")}
	if err := checkBindingStrengthAgainstFamilies(bindings, families); err != nil {
		t.Fatalf("a rank read from content in every family was refused: %v", err)
	}
}

// TestTheCommittedRegisterDisclosesRankFour records the consequence of the
// derivation as an assertion, so a later change that quietly restores
// CONTENT_BOUND fails here rather than passing silently.
func TestTheCommittedRegisterDisclosesRankFour(t *testing.T) {
	reg, families, err := Recompute(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range reg.RankBindings {
		if b.Rank != RankJavaObservation {
			continue
		}
		if b.Strength == BoundToContent {
			t.Fatalf("rank four is %s again while the census records its handshake and public opinions as something other than %s", b.Strength, SourceContent)
		}
		if b.NotBoundTo == "" {
			t.Fatal("rank four is not CONTENT_BOUND and does not say what it is NOT bound to")
		}
	}
	for _, f := range Findings(reg, families) {
		if f.ID == "ORACLE-RANK-BINDING-4" {
			return
		}
	}
	t.Fatal("ORACLE-RANK-BINDING-4 is not in the findings; if rank four has become an observation of the Java process on every family, say so here rather than dropping the assertion")
}
