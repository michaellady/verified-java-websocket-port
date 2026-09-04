package oraclerank

import (
	"errors"
	"strings"
	"testing"
)

// src is a throwaway source string. Every opinion needs one, and the tests that
// check that requirement pass "" deliberately.
const src = "test://opinion"

func opinion(r Rank, verdict string) Opinion {
	return Opinion{Rank: r, Verdict: verdict, Source: src}
}

func abstain(r Rank) Opinion {
	return Opinion{Rank: r, Abstains: true, AbstainReason: "test", Source: src}
}

func prop(opinions ...Opinion) Proposition {
	return Proposition{ID: "p", Family: "f", Question: "q", Opinions: opinions}
}

func TestRankOrderIsTheAC2Order(t *testing.T) {
	want := []Rank{RankRFC6455, RankAutobahnInScope, RankNeutralExpectation, RankJavaObservation, RankRustObservation}
	got := Ranks()
	if len(got) != len(want) {
		t.Fatalf("Ranks() returned %d ranks, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Ranks()[%d] = %s, want %s", i, got[i], want[i])
		}
		if uint8(want[i]) != uint8(i+1) {
			t.Fatalf("%s has value %d; AC2 numbers it %d", want[i], uint8(want[i]), i+1)
		}
	}
	// The order is strict and total: lower number outranks, and no rank
	// outranks itself.
	for i, a := range got {
		if a.Outranks(a) {
			t.Fatalf("%s outranks itself", a)
		}
		for j, b := range got {
			if i < j && !a.Outranks(b) {
				t.Fatalf("%s does not outrank %s", a, b)
			}
			if i < j && !b.Subordinate(a) {
				t.Fatalf("%s is not subordinate to %s", b, a)
			}
		}
	}
	if Rank(0).Valid() || Rank(6).Valid() {
		t.Fatal("a rank outside 1..5 reported itself valid")
	}
}

// TestAdjudicateFailsClosedOnMalformedPropositions is a RED test for each way a
// proposition can be malformed. Every case here must produce an error; a
// proposition that adjudicates anyway would make the outcome weaker than it
// looks.
func TestAdjudicateFailsClosedOnMalformedPropositions(t *testing.T) {
	cases := []struct {
		name string
		p    Proposition
		want string
	}{
		{"no id", Proposition{Family: "f", Opinions: []Opinion{opinion(RankRFC6455, "x")}}, "no id"},
		{"no family", Proposition{ID: "p", Opinions: []Opinion{opinion(RankRFC6455, "x")}}, "no family"},
		{"no opinions", Proposition{ID: "p", Family: "f"}, "no opinions"},
		{"rank zero", prop(opinion(Rank(0), "x")), "outside the AC2 order"},
		{"rank six", prop(opinion(Rank(6), "x")), "outside the AC2 order"},
		{"duplicate rank", prop(opinion(RankRFC6455, "x"), opinion(RankRFC6455, "y")), "one rank speaks once"},
		{"no source", prop(Opinion{Rank: RankRFC6455, Verdict: "x"}), "no source"},
		{"empty verdict", prop(Opinion{Rank: RankRFC6455, Source: src}), "empty verdict"},
		{"abstains and votes", prop(Opinion{Rank: RankRFC6455, Verdict: "x", Abstains: true, AbstainReason: "r", Source: src}), "both abstains and votes"},
		{"abstains with no reason", prop(Opinion{Rank: RankRFC6455, Abstains: true, Source: src}), "abstains with no reason"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Adjudicate(tc.p)
			if err == nil {
				t.Fatalf("Adjudicate accepted a malformed proposition (%s)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestGoverningRankIsTheStrongestThatVotesAndAbstentionPassesItDown(t *testing.T) {
	a, err := Adjudicate(prop(
		abstain(RankRFC6455),
		abstain(RankAutobahnInScope),
		opinion(RankNeutralExpectation, "reject"),
		opinion(RankJavaObservation, "accept"),
		opinion(RankRustObservation, "accept"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if a.Governing != RankNeutralExpectation {
		t.Fatalf("governing rank %s, want %s: abstention must pass governance down", a.Governing, RankNeutralExpectation)
	}
	if a.Verdict != "reject" {
		t.Fatalf("governing verdict %q, want %q", a.Verdict, "reject")
	}
	if len(a.Abstaining) != 2 {
		t.Fatalf("abstaining ranks %v, want the two that abstained", a.Abstaining)
	}
	if a.Outcome != OutcomeHigherOracleOverrides {
		t.Fatalf("outcome %s, want %s", a.Outcome, OutcomeHigherOracleOverrides)
	}
}

func TestUndeterminedWhenEveryRankAbstains(t *testing.T) {
	a, err := Adjudicate(prop(abstain(RankRFC6455), abstain(RankJavaObservation), abstain(RankRustObservation)))
	if err != nil {
		t.Fatal(err)
	}
	if a.Outcome != OutcomeUndetermined {
		t.Fatalf("outcome %s, want %s", a.Outcome, OutcomeUndetermined)
	}
	if a.Governing != 0 || a.Verdict != "" {
		t.Fatalf("an undetermined proposition reported a governing rank %s / verdict %q", a.Governing, a.Verdict)
	}
}

// TestAC2PolarityControl is the planted control pair the deliverable calls for.
// Two propositions differ ONLY in rank one's verdict. The first must fire the
// override rule and the second must not. A check that fires on both is not
// discriminating; a check that fires on neither is not evidence.
func TestAC2PolarityControl(t *testing.T) {
	agreeing := prop(
		opinion(RankRFC6455, "reject"),
		opinion(RankJavaObservation, "reject"),
		opinion(RankRustObservation, "reject"),
	)
	dissenting := prop(
		opinion(RankRFC6455, "reject"),
		opinion(RankJavaObservation, "accept"),
		opinion(RankRustObservation, "accept"),
	)

	positive, err := Adjudicate(dissenting)
	if err != nil {
		t.Fatal(err)
	}
	if !positive.JavaRustConsensus {
		t.Fatal("Java and Rust both said accept and the adjudication did not record a consensus")
	}
	if !positive.JavaRustConsensusOverridden {
		t.Fatal("RED: Java and Rust agreed on accept, rank one said reject, and the override rule did not fire")
	}
	if positive.Governing != RankRFC6455 || positive.Verdict != "reject" {
		t.Fatalf("governing %s/%q, want %s/reject", positive.Governing, positive.Verdict, RankRFC6455)
	}

	negative, err := Adjudicate(agreeing)
	if err != nil {
		t.Fatal(err)
	}
	if !negative.JavaRustConsensus {
		t.Fatal("the negative control lost its Java/Rust consensus")
	}
	if negative.JavaRustConsensusOverridden {
		t.Fatal("RED: the override rule fired where the higher oracle AGREED with Java and Rust; it does not discriminate")
	}
	if negative.Outcome != OutcomeConcordant {
		t.Fatalf("negative control outcome %s, want %s", negative.Outcome, OutcomeConcordant)
	}
}

func TestJavaRustDisagreementIsNotAConsensus(t *testing.T) {
	a, err := Adjudicate(prop(
		opinion(RankAutobahnInScope, "OK"),
		opinion(RankJavaObservation, "OK"),
		opinion(RankRustObservation, "NON-STRICT"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if a.JavaRustConsensus {
		t.Fatal("Java said OK, Rust said NON-STRICT, and the adjudication called it a consensus")
	}
	if a.JavaRustConsensusOverridden {
		t.Fatal("a non-existent consensus was reported as overridden")
	}
	if a.Outcome != OutcomeHigherOracleOverrides {
		t.Fatalf("outcome %s, want %s: rank five dissents from rank two", a.Outcome, OutcomeHigherOracleOverrides)
	}
}

// TestSubordinateAgreementCannotOutvoteAHigherOracle is AC2's final clause in
// its starkest form: three subordinate ranks agreeing unanimously still lose to
// one higher oracle. If this ever passes by counting votes, the hierarchy has
// become a poll.
func TestSubordinateAgreementCannotOutvoteAHigherOracle(t *testing.T) {
	a, err := Adjudicate(prop(
		opinion(RankAutobahnInScope, "OK"),
		opinion(RankNeutralExpectation, "NON-STRICT"),
		opinion(RankJavaObservation, "NON-STRICT"),
		opinion(RankRustObservation, "NON-STRICT"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != "OK" || a.Governing != RankAutobahnInScope {
		t.Fatalf("three subordinate ranks agreeing changed the governing verdict to %s/%q", a.Governing, a.Verdict)
	}
	if !a.JavaRustConsensusOverridden {
		t.Fatal("RED: ranks four and five agreed against rank two and the override rule did not fire")
	}
	if len(a.Dissenting) != 3 {
		t.Fatalf("dissenting ranks %v, want all three subordinates", a.Dissenting)
	}
}

func TestParityReadingRefusesExactlyWhenOverridden(t *testing.T) {
	overridden := prop(
		opinion(RankAutobahnInScope, "OK"),
		opinion(RankJavaObservation, "NON-STRICT"),
		opinion(RankRustObservation, "NON-STRICT"),
	)
	if verdict, err := ParityFromJavaRustAgreement(overridden); err == nil {
		t.Fatalf("RED: the guarded parity reading returned %q on an overridden agreement", verdict)
	} else {
		var typed *ErrConsensusOverridden
		if !errors.As(err, &typed) {
			t.Fatalf("refusal is %T, want *ErrConsensusOverridden so a caller can act on it", err)
		}
		if typed.Governing != RankAutobahnInScope {
			t.Fatalf("refusal names %s, want %s", typed.Governing, RankAutobahnInScope)
		}
		if !strings.Contains(typed.Error(), "AC2") {
			t.Fatalf("refusal text %q does not cite AC2", typed.Error())
		}
	}

	permitted := prop(
		opinion(RankAutobahnInScope, "OK"),
		opinion(RankJavaObservation, "OK"),
		opinion(RankRustObservation, "OK"),
	)
	verdict, err := ParityFromJavaRustAgreement(permitted)
	if err != nil {
		t.Fatalf("the guarded parity reading refused an unopposed agreement: %v", err)
	}
	if verdict != "OK" {
		t.Fatalf("parity verdict %q, want OK", verdict)
	}

	noAgreement := prop(
		opinion(RankJavaObservation, "OK"),
		opinion(RankRustObservation, "NON-STRICT"),
	)
	if _, err := ParityFromJavaRustAgreement(noAgreement); err == nil {
		t.Fatal("the guarded parity reading accepted a disagreement as parity")
	}

	rustSilent := prop(
		opinion(RankJavaObservation, "OK"),
		abstain(RankRustObservation),
	)
	if _, err := ParityFromJavaRustAgreement(rustSilent); err == nil {
		t.Fatal("the guarded parity reading read a one-sided observation as agreement")
	}
}

// TestOverrideRuleIgnoresSubordinateRanksBelowTheConsensus checks the boundary
// the rule turns on: a dissent BELOW rank four cannot make the Java/Rust
// consensus overridden, because AC2's clause is about HIGHER oracles only.
func TestOverrideRuleTurnsOnRankStrictlyAboveRankFour(t *testing.T) {
	// Rank four governs; rank five is the only other voice and it agrees.
	a, err := Adjudicate(prop(
		opinion(RankJavaObservation, "accept"),
		opinion(RankRustObservation, "accept"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if !a.JavaRustConsensus {
		t.Fatal("lost the consensus")
	}
	if a.JavaRustConsensusOverridden {
		t.Fatal("RED: a consensus with no higher oracle present was reported as overridden")
	}
	if a.Governing != RankJavaObservation {
		t.Fatalf("governing %s, want %s", a.Governing, RankJavaObservation)
	}
}
