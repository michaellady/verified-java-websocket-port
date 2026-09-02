package oraclerank

import (
	"strings"
	"testing"
)

// The tests here exist because a deletion attack found the production checks
// they cover were being RE-IMPLEMENTED by their tests rather than called by
// them: deleting the check in VerifyRules left the test green, because the test
// did its own iteration and its own assertion. A test that restates the
// production logic proves nothing about the gate. These call
// CheckFamilyRules -- the code the gate actually runs -- with fabricated
// families, so deleting the check makes them fail.

func fabricatedFamily(id string, sources []RankSource, props ...Proposition) Family {
	for i := range props {
		props[i].Family = id
	}
	return Family{ID: id, Question: "q", RankSources: sources, Propositions: props}
}

func source(r Rank, strength SourceStrength, group string) RankSource {
	return RankSource{Rank: r, RankName: r.String(), Strength: strength, ArtifactGroup: group, Note: "test"}
}

// TestCheckFamilyRulesRefusesAnOverrideInThePolarityControlFamily calls the
// production guard with a fabricated diff-probe family that DOES contain an
// override. The gate must refuse it: the polarity control is only a control if
// something enforces it.
func TestCheckFamilyRulesRefusesAnOverrideInThePolarityControlFamily(t *testing.T) {
	f := fabricatedFamily(FamilyDiffProbe,
		[]RankSource{
			source(RankAutobahnInScope, SourceContent, "planted-higher-oracle"),
			source(RankJavaObservation, SourceContent, "java"),
			source(RankRustObservation, SourceContent, "rust"),
		},
		Proposition{ID: "planted", Question: "q", Opinions: []Opinion{
			opinion(RankAutobahnInScope, "OK"),
			opinion(RankJavaObservation, "NON-STRICT"),
			opinion(RankRustObservation, "NON-STRICT"),
		}},
	)
	_, err := CheckFamilyRules(f)
	if err == nil {
		t.Fatal("RED FAILED: an override was planted in the polarity-control family and the gate accepted it")
	}
	if !strings.Contains(err.Error(), "firing where it must not") {
		t.Fatalf("the gate failed with %q, which does not name the polarity control", err)
	}
}

// TestCheckFamilyRulesRefusesARankThatIsDeclaredAndSilent calls the production
// guard with a family that names a rank at a real strength and never lets it
// speak. That is the "existence standing in for identity" failure this package
// was written to avoid, so the gate must refuse it.
func TestCheckFamilyRulesRefusesARankThatIsDeclaredAndSilent(t *testing.T) {
	f := fabricatedFamily("fabricated",
		[]RankSource{
			source(RankRFC6455, SourceRecordedReading, "declared-but-silent"),
			source(RankJavaObservation, SourceContent, "java"),
			source(RankRustObservation, SourceContent, "rust"),
		},
		Proposition{ID: "p", Question: "q", Opinions: []Opinion{
			abstain(RankRFC6455),
			opinion(RankJavaObservation, "accept"),
			opinion(RankRustObservation, "accept"),
		}},
	)
	_, err := CheckFamilyRules(f)
	if err == nil {
		t.Fatal("RED FAILED: rank one was declared with a real strength, never spoke, and the gate accepted it")
	}
	if !strings.Contains(err.Error(), "exists in name only") {
		t.Fatalf("the gate failed with %q, which does not name the silent rank", err)
	}
}

// TestCheckFamilyRulesRefusesARankDeclaredAbsentThatSpeaks is the same guard in
// the other direction.
func TestCheckFamilyRulesRefusesARankDeclaredAbsentThatSpeaks(t *testing.T) {
	f := fabricatedFamily("fabricated",
		[]RankSource{
			{Rank: RankRFC6455, RankName: RankRFC6455.String(), Strength: SourceAbsent, Note: "test"},
			source(RankJavaObservation, SourceContent, "java"),
			source(RankRustObservation, SourceContent, "rust"),
		},
		Proposition{ID: "p", Question: "q", Opinions: []Opinion{
			opinion(RankRFC6455, "reject"),
			opinion(RankJavaObservation, "accept"),
			opinion(RankRustObservation, "accept"),
		}},
	)
	_, err := CheckFamilyRules(f)
	if err == nil {
		t.Fatal("RED FAILED: rank one was declared ABSENT, voted anyway, and the gate accepted it")
	}
	if !strings.Contains(err.Error(), "declared ABSENT") {
		t.Fatalf("the gate failed with %q", err)
	}
}

// TestCheckFamilyRulesReportsTheOverridesItFinds is the positive half: the same
// production code must actually SEE an override in a family where a higher
// oracle is present, or the exactness check downstream has nothing to compare.
func TestCheckFamilyRulesReportsTheOverridesItFinds(t *testing.T) {
	f := fabricatedFamily("fabricated",
		[]RankSource{
			source(RankRFC6455, SourceRecordedReading, "rfc"),
			source(RankJavaObservation, SourceContent, "java"),
			source(RankRustObservation, SourceContent, "rust"),
		},
		Proposition{ID: "overridden", Question: "q", Opinions: []Opinion{
			opinion(RankRFC6455, "closed"),
			opinion(RankJavaObservation, "open"),
			opinion(RankRustObservation, "open"),
		}},
		Proposition{ID: "concordant", Question: "q", Opinions: []Opinion{
			opinion(RankRFC6455, "open"),
			opinion(RankJavaObservation, "open"),
			opinion(RankRustObservation, "open"),
		}},
	)
	found, err := CheckFamilyRules(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("the gate found %d overrides, want exactly the one planted", len(found))
	}
	entry, ok := found["overridden"]
	if !ok {
		t.Fatal("the gate did not report the overridden proposition")
	}
	if entry.Governing != RankRFC6455 || entry.GoverningVerdict != "closed" || entry.ConsensusVerdict != "open" {
		t.Fatalf("the gate reported %+v", entry)
	}
	if _, concordantWasFlagged := found["concordant"]; concordantWasFlagged {
		t.Fatal("the gate flagged a proposition where every rank agrees")
	}
}
