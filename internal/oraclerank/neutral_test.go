package oraclerank

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/rfcneutral"
)

// ---------------------------------------------------------------------------
// The measurement, restated as assertions on the committed tree.
// ---------------------------------------------------------------------------

// TestRankThreeIsDistinguishableFromTheObservationRanks is the result this
// branch exists to produce, asserted rather than described. It does not assert
// a number of disagreements -- pinning 18 would make the evidence unable to
// move -- but it does assert the thing the finding turns on: the probe must
// score the pair against independently sourced evidence AND find at least one
// disagreement.
func TestRankThreeIsDistinguishableFromTheObservationRanks(t *testing.T) {
	root := repoRoot(t)
	families, err := Census(root)
	if err != nil {
		t.Fatal(err)
	}
	probes := IndependenceProbe(families)

	for _, lower := range []Rank{RankJavaObservation, RankRustObservation} {
		var found bool
		for _, p := range probes {
			if p.Higher != RankNeutralExpectation || p.Lower != lower {
				continue
			}
			found = true
			if p.Verdict != ProbeDistinguished {
				t.Fatalf("%s vs %s: verdict %s (co_votes %d, disagreements %d); rank three has to be able to differ from the rank below it",
					p.Higher, p.Lower, p.Verdict, p.CoVotes, p.Disagreements)
			}
			if p.Disagreements == 0 {
				t.Fatalf("%s vs %s: DISTINGUISHED with zero disagreements", p.Higher, p.Lower)
			}
		}
		if !found {
			t.Fatalf("no probe for rank three against %s", lower)
		}
	}
}

// TestRankThreeOnThePublicTierIsNotTheCorpusExpectation is the register-level
// counterpart of the structural test in internal/rfcneutral: it asserts that
// rank three's public-tier verdicts are not simply rank four's, which they were
// before this branch, and that they are sourced from the derivation.
func TestRankThreeOnThePublicTierIsNotTheCorpusExpectation(t *testing.T) {
	root := repoRoot(t)
	families, err := Census(root)
	if err != nil {
		t.Fatal(err)
	}
	var f Family
	for _, cand := range families {
		if cand.ID == FamilyPublicState {
			f = cand
		}
	}
	if f.ID == "" {
		t.Fatal("no public-corpus family")
	}

	var group string
	for _, rs := range f.RankSources {
		if rs.Rank == RankNeutralExpectation {
			group = rs.ArtifactGroup
		}
	}
	if group == "" {
		t.Fatal("rank three declares no artifact group in the public family")
	}
	for _, rs := range f.RankSources {
		if rs.Rank == RankJavaObservation && rs.ArtifactGroup == group {
			t.Fatalf("ranks three and four share the artifact group %q in %s; they are one oracle under two names again", group, f.ID)
		}
	}

	differ := 0
	for _, p := range f.Propositions {
		three, ok3 := votedVerdict(p, RankNeutralExpectation)
		four, ok4 := votedVerdict(p, RankJavaObservation)
		if !ok3 || !ok4 {
			continue
		}
		if three != four {
			differ++
		}
	}
	if differ == 0 {
		t.Fatal("rank three agrees with rank four on every public proposition it votes on; the derivation is not doing any work")
	}

	for _, p := range f.Propositions {
		for _, o := range p.Opinions {
			if o.Rank != RankNeutralExpectation {
				continue
			}
			if !strings.Contains(o.Source, "internal/rfcneutral") {
				t.Fatalf("%s: rank three's source is %q; it must name the derivation that produced it", p.ID, o.Source)
			}
			if strings.Contains(o.Source, "expected/final_state") {
				t.Fatalf("%s: rank three still cites the corpus expectation: %q", p.ID, o.Source)
			}
		}
	}
}

// TestNeutralDerivationCoversEveryPublicScenarioOrSaysWhyNot asserts the
// coverage claim is exact: 74 decisions, every one carrying a rule from the
// table, and every abstention carrying a reason.
func TestNeutralDerivationCoversEveryPublicScenarioOrSaysWhyNot(t *testing.T) {
	ds, err := rfcneutral.Derive(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != PublicCorpusSize {
		t.Fatalf("the derivation decided %d scenarios, the tier holds %d", len(ds), PublicCorpusSize)
	}
	decided, abstained := 0, 0
	for _, d := range ds {
		r, ok := rfcneutral.LookupRule(d.RuleID)
		if !ok {
			t.Fatalf("%s cites rule %q, which is not in the table", d.ScenarioID, d.RuleID)
		}
		if d.Detail == "" {
			t.Fatalf("%s cites rule %q with no detail", d.ScenarioID, d.RuleID)
		}
		if d.Abstains {
			abstained++
			if r.Effect != "" {
				t.Fatalf("%s abstains under a deciding rule %q", d.ScenarioID, d.RuleID)
			}
			continue
		}
		decided++
		if !isReadyState(d.Verdict) {
			t.Fatalf("%s decides %q, outside the verdict space", d.ScenarioID, d.Verdict)
		}
	}
	if decided == 0 || abstained == 0 {
		t.Fatalf("derivation decided %d and abstained on %d; a derivation that never abstains is overclaiming and one that never decides is silent", decided, abstained)
	}
}

// ---------------------------------------------------------------------------
// The indistinguishability findings must still be able to fire.
// ---------------------------------------------------------------------------

// TestIndistinguishabilityFindingStillFiresWhenTheEvidenceEarnsIt takes the
// real families, replaces rank three's verdicts with rank four's -- the state
// the register was in before this branch -- and requires the BLOCKING finding
// to come back. Nothing in findings.go was changed; this proves the check was
// not disabled, only outrun by better evidence.
func TestIndistinguishabilityFindingStillFiresWhenTheEvidenceEarnsIt(t *testing.T) {
	root := repoRoot(t)
	families, err := Census(root)
	if err != nil {
		t.Fatal(err)
	}

	// Copy rank four's verdict onto rank three everywhere both speak, and
	// make rank three abstain where rank four does. This is exactly the
	// "relabelling" the finding names.
	for fi := range families {
		for pi := range families[fi].Propositions {
			p := &families[fi].Propositions[pi]
			four, ok := votedVerdict(*p, RankJavaObservation)
			for oi := range p.Opinions {
				if p.Opinions[oi].Rank != RankNeutralExpectation {
					continue
				}
				if !ok {
					p.Opinions[oi].Verdict = ""
					p.Opinions[oi].Abstains = true
					p.Opinions[oi].AbstainReason = "relabelling probe"
					continue
				}
				p.Opinions[oi].Verdict = four
				p.Opinions[oi].Abstains = false
				p.Opinions[oi].AbstainReason = ""
			}
		}
	}

	reg := Register{IndependenceProbe: IndependenceProbe(families)}
	var probed bool
	for _, p := range reg.IndependenceProbe {
		if p.Higher == RankNeutralExpectation && p.Lower == RankJavaObservation {
			probed = true
			if p.Verdict != ProbeNotDistinguished {
				t.Fatalf("relabelled rank three probes as %s with %d co-votes and %d disagreements; the probe can no longer detect a relabelling",
					p.Verdict, p.CoVotes, p.Disagreements)
			}
		}
	}
	if !probed {
		t.Fatal("no rank three vs rank four probe")
	}

	var fired bool
	for _, f := range Findings(reg, families) {
		if f.ID == "ORACLE-RANK-INDISTINGUISHABLE-3-4" {
			fired = true
			if f.Severity != "BLOCKING" {
				t.Fatalf("the finding fired at severity %q", f.Severity)
			}
		}
	}
	if !fired {
		t.Fatal("rank three relabelled as rank four and ORACLE-RANK-INDISTINGUISHABLE-3-4 did not fire")
	}
}

// TestTheOneToThreeIndistinguishabilityFindingIsInTheCommittedRegister records
// the cost of this branch as an assertion rather than a sentence in a report.
// A rank three derived from RFC 6455 is not distinguishable from rank one, which
// is a recorded reading of the same document, and the register says so.
func TestTheOneToThreeIndistinguishabilityFindingIsInTheCommittedRegister(t *testing.T) {
	reg, families, err := Recompute(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	var fired bool
	for _, f := range Findings(reg, families) {
		if f.ID == "ORACLE-RANK-INDISTINGUISHABLE-1-3" {
			fired = true
			if f.Severity != "BLOCKING" {
				t.Fatalf("severity %q", f.Severity)
			}
		}
	}
	if !fired {
		t.Fatal("ORACLE-RANK-INDISTINGUISHABLE-1-3 is not in the findings; if rank one and rank three have come apart, say so here rather than dropping the assertion")
	}
}

// ---------------------------------------------------------------------------
// The join-degeneracy measurement
// ---------------------------------------------------------------------------

// TestHandshakeJoinIsDegenerateOnTheCommittedMapping states the measured fact.
func TestHandshakeJoinIsDegenerateOnTheCommittedMapping(t *testing.T) {
	mapping, err := readHandshakeMapping(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	jds, err := handshakeJoinDegeneracies(mapping, everyMappingKey(mapping))
	if err != nil {
		t.Fatal(err)
	}
	if len(jds) != 2 {
		t.Fatalf("got %d join analyses; the key derived from rank three selects BOTH rank one and rank four", len(jds))
	}
	sawFour := false
	for _, jd := range jds {
		if !jd.Degenerate {
			t.Fatalf("%s vs %s is no longer join-degenerate: %s", jd.Higher, jd.Lower, jd.Statement)
		}
		if jd.KeysConsidered != len(mapping) {
			t.Fatalf("%s vs %s considered %d keys of %d", jd.Higher, jd.Lower, jd.KeysConsidered, len(mapping))
		}
		for v, got := range jd.ReachableVerdicts {
			for _, o := range got {
				if o != v {
					t.Fatalf("%s vs %s: verdict %q reaches %q but Degenerate is true", jd.Higher, jd.Lower, v, o)
				}
			}
		}
		if jd.Lower == RankJavaObservation {
			sawFour = true
			if jd.KeysAbstaining == 0 {
				t.Fatal("no key makes rank four abstain; the `conditional` arm has gone")
			}
		}
	}
	if !sawFour {
		t.Fatal("no analysis covers the rank three / rank four join")
	}
}

// TestJoinDegeneracyDetectsANonDegenerateJoin is the negative control. The
// measurement is worth nothing if it says DEGENERATE whatever it is handed, so
// one entry is changed to carry a java_observable that differs from its key's
// rfc_verdict and the detector must say so.
func TestJoinDegeneracyDetectsANonDegenerateJoin(t *testing.T) {
	mapping, err := readHandshakeMapping(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	key := [2]string{"client_request", "HS_METHOD_NOT_GET"}
	entry, ok := mapping[key]
	if !ok {
		t.Fatalf("%v is not in the committed mapping", key)
	}
	if entry.JavaObservable != "reject" {
		t.Fatalf("entry %v records java_observable %q; this control assumes it rejects", key, entry.JavaObservable)
	}
	entry.JavaObservable = "accept"
	mapping[key] = entry

	jds, err := handshakeJoinDegeneracies(mapping, everyMappingKey(mapping))
	if err != nil {
		t.Fatal(err)
	}
	var checked bool
	for _, jd := range jds {
		if jd.Lower != RankJavaObservation {
			continue
		}
		checked = true
		if jd.Degenerate {
			t.Fatal("a mapping that carries a reject key with java_observable=accept was still reported as join-degenerate")
		}
		if jd.DegenerateOverJoinedKeys {
			t.Fatal("the counterexample key IS joined on here, so the joined-key analysis must not report degeneracy either")
		}
		if !strings.Contains(jd.Statement, "reject->accept") {
			t.Fatalf("the statement does not name the counterexample: %s", jd.Statement)
		}
	}
	if !checked {
		t.Fatal("no analysis covers the rank three / rank four join")
	}
}

// TestJoinDegeneracyFindingIsInTheCommittedRegister asserts the disclosure
// reaches the document, with the probe's own numbers in its basis.
func TestJoinDegeneracyFindingIsInTheCommittedRegister(t *testing.T) {
	reg, families, err := Recompute(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	var f Finding
	for _, cand := range Findings(reg, families) {
		if cand.ID == "ORACLE-RANK-JOIN-DEGENERATE-3-4" {
			f = cand
		}
	}
	if f.ID == "" {
		t.Fatal("ORACLE-RANK-JOIN-DEGENERATE-3-4 is not in the findings")
	}
	if !strings.Contains(f.Statement, "STRUCTURALLY IMPOSSIBLE") {
		t.Fatalf("statement does not say what it found: %s", f.Statement)
	}
	if f.OwnerActionRequired == "" {
		t.Fatal("the finding names no action that would settle it")
	}
}

// ---------------------------------------------------------------------------
// The new override the independent rank three found
// ---------------------------------------------------------------------------

// TestRankThreeGovernsAtLeastOneOverrideAloneChecks that the derivation is not
// merely echoing rank one: at least one enrolled AC2 override must be governed
// by rank three on a proposition rank one does not speak on. That is an
// override the register could not previously see.
func TestRankThreeGovernsAtLeastOneOverrideAlone(t *testing.T) {
	reg, _, err := Recompute(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	var byRankThree []string
	for _, e := range reg.Overridden {
		if e.Governing == RankNeutralExpectation {
			byRankThree = append(byRankThree, e.PropositionID)
		}
	}
	if len(byRankThree) == 0 {
		t.Fatal("no enrolled override is governed by rank three; the independent oracle is finding nothing rank one did not already find")
	}
	t.Logf("overrides governed by rank three alone: %v", byRankThree)
}

// TestRegisterCarriesTheDerivationsShape asserts the public family's
// cross-checks record what the derivation decided, so a reader of the document
// alone can see rank three's coverage.
func TestRegisterCarriesTheDerivationsShape(t *testing.T) {
	data := mustRead(t, repoRoot(t), RegisterPath)
	var doc struct {
		Families []struct {
			ID          string   `json:"family_id"`
			CrossChecks []string `json:"cross_checks"`
		} `json:"families"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, f := range doc.Families {
		if f.ID != FamilyPublicState {
			continue
		}
		var sawShape, sawRank1 bool
		for _, c := range f.CrossChecks {
			if strings.Contains(c, "internal/rfcneutral") && strings.Contains(c, "By rule:") {
				sawShape = true
			}
			if strings.Contains(c, "two independent readings of RFC 6455 compared, not reconciled") {
				sawRank1 = true
			}
		}
		if !sawShape {
			t.Fatal("the public family records no cross-check describing the derivation's coverage by rule")
		}
		if !sawRank1 {
			t.Fatal("the public family records no comparison of the derivation against rank one's recorded reading")
		}
		return
	}
	t.Fatalf("no %s family in the committed register", FamilyPublicState)
}

// TestHollowCoVoteQualifierCountsRatherThanAsserts is the negative control on
// the sentence appended to the indistinguishability finding. It reports
// "leaving 0 co-vote(s) that could have come out either way" on the committed
// tree, and a qualifier that says 0 whatever it is handed would be worthless.
// Here it is handed a pair with one degenerate family, one single-answer family
// and one family that is neither, and must count them apart.
func TestHollowCoVoteQualifierCountsRatherThanAsserts(t *testing.T) {
	families := []Family{
		{ID: "joined", VerdictSpace: []string{"a", "b"}, JoinDegeneracy: []JoinDegeneracy{{
			Family: "joined", Higher: RankRFC6455, Lower: RankNeutralExpectation,
			Degenerate: true, DegenerateOverJoinedKeys: true,
		}}},
		{ID: "collapsed", VerdictSpace: []string{"a", "b"}},
		{ID: "informative", VerdictSpace: []string{"a", "b"}},
	}
	p := PairProbe{
		Higher: RankRFC6455, Lower: RankNeutralExpectation, CoVotes: 30,
		ByFamily: []FamilyProbe{
			{Family: "joined", Verdict: ProbeNotDistinguished, CoVotes: 10,
				Resolution: CoVoteResolution{DistinctVerdictPairs: 2}},
			{Family: "collapsed", Verdict: ProbeNotDistinguished, CoVotes: 15,
				Resolution: CoVoteResolution{DistinctVerdictPairs: 1}},
			{Family: "informative", Verdict: ProbeNotDistinguished, CoVotes: 5,
				Resolution: CoVoteResolution{DistinctVerdictPairs: 2}},
		},
	}
	got := hollowCoVoteQualifier(p, families)
	for _, want := range []string{
		"10 in joined where the census's own join makes disagreement structurally impossible",
		"15 in collapsed that carry one distinct answer between them",
		"leaving 5 co-vote(s) that could have come out either way",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("qualifier does not carry %q:\n%s", want, got)
		}
	}

	// With nothing hollow, the qualifier must say nothing at all rather than
	// appending an empty caveat to every finding.
	clean := PairProbe{
		Higher: RankRFC6455, Lower: RankNeutralExpectation, CoVotes: 5,
		ByFamily: []FamilyProbe{{Family: "informative", Verdict: ProbeNotDistinguished, CoVotes: 5,
			Resolution: CoVoteResolution{DistinctVerdictPairs: 2}}},
	}
	if q := hollowCoVoteQualifier(clean, families); q != "" {
		t.Fatalf("a pair with no hollow co-votes got a qualifier: %q", q)
	}
}

// everyMappingKey is the joined-key set these tests hand the analysis: they ask
// about the whole committed table, which is what the whole-table half of
// joinDegeneracy answers. TestTheJoinAnalysisIgnoresAKeyNoCaseReaches, in
// adversarial_round4_test.go, is the one that hands it a narrower set.
func everyMappingKey(mapping map[[2]string]handshakeMappingEntry) map[[2]string]bool {
	out := make(map[[2]string]bool, len(mapping))
	for k := range mapping {
		out[k] = true
	}
	return out
}
