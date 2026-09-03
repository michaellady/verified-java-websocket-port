package oraclerank

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCommittedRegisterSatisfiesItsSchema is the green reading.
func TestCommittedRegisterSatisfiesItsSchema(t *testing.T) {
	if err := ValidateAgainstSchema(repoRoot(t)); err != nil {
		t.Fatal(err)
	}
}

// TestRedMissingSchemaFailsClosed is the F006 control. A lookup that cannot run
// must not read as a lookup that passed: with the schema deleted, validation is
// an error, not a pass.
func TestRedMissingSchemaFailsClosed(t *testing.T) {
	root := mirrorRoot(t, repoRoot(t), map[string][]byte{SchemaPath: nil})
	err := ValidateAgainstSchema(root)
	if err == nil {
		t.Fatal("the schema was deleted and validation passed; a validation that cannot run is not a validation that passed")
	}
	if !strings.Contains(err.Error(), SchemaPath) {
		t.Fatalf("the error does not name the missing schema: %v", err)
	}
}

// redRegister mutates the committed register with fn and returns a root whose
// register is the mutation. The mutation is applied to the decoded document, so
// every one of these is a well-formed JSON register that differs only in the
// field under attack.
func redRegister(t *testing.T, fn func(doc map[string]any)) string {
	t.Helper()
	root := repoRoot(t)
	var doc map[string]any
	if err := json.Unmarshal(mustRead(t, root, RegisterPath), &doc); err != nil {
		t.Fatal(err)
	}
	fn(doc)
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return mirrorRoot(t, root, map[string][]byte{RegisterPath: encoded})
}

func mustFailSchema(t *testing.T, root, wantSubstring string) {
	t.Helper()
	err := ValidateAgainstSchema(root)
	if err == nil {
		t.Fatal("the schema accepted a register it must refuse")
	}
	if wantSubstring != "" && !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("the failure does not name the field under attack (want %q): %v", wantSubstring, err)
	}
}

// Each of the following is one way the register could go quietly wrong. A
// schema that does not refuse them is a document rather than a gate.

func TestRedSchemaRefusesARankOutsideTheAC2Order(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		b := doc["rank_bindings"].([]any)[0].(map[string]any)
		b["rank"] = 6
	}), "rank_bindings")
}

func TestRedSchemaRefusesAWeakBindingThatDoesNotSayWhatItIsNotBoundTo(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		for _, raw := range doc["rank_bindings"].([]any) {
			b := raw.(map[string]any)
			if b["strength"] != "CONTENT_BOUND" {
				delete(b, "not_bound_to")
				return
			}
		}
		t.Fatal("no binding is weaker than CONTENT_BOUND; this attack has nothing to hit")
	}), "rank_bindings")
}

func TestRedSchemaRefusesADistinguishedProbeWithNoDisagreement(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		for _, raw := range doc["independence_probe"].([]any) {
			p := raw.(map[string]any)
			if p["verdict"] == "DISTINGUISHED" {
				p["disagreements"] = float64(0)
				return
			}
		}
		t.Fatal("no DISTINGUISHED probe to attack")
	}), "independence_probe")
}

func TestRedSchemaRefusesANotDistinguishedProbeThatCountsDisagreements(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		for _, raw := range doc["independence_probe"].([]any) {
			p := raw.(map[string]any)
			if p["verdict"] == "NOT_DISTINGUISHED" {
				p["disagreements"] = float64(3)
				return
			}
		}
		t.Fatal("no NOT_DISTINGUISHED probe to attack")
	}), "independence_probe")
}

func TestRedSchemaRefusesASharedDerivationProbeThatScoresDisagreements(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		for _, raw := range doc["independence_probe"].([]any) {
			p := raw.(map[string]any)
			for _, rawF := range asSlice(p["by_family"]) {
				fp := rawF.(map[string]any)
				if fp["verdict"] == "NOT_PROBEABLE_SHARED_DERIVATION" {
					fp["disagreements"] = float64(1)
					return
				}
			}
		}
		t.Fatal("no shared-derivation family probe to attack")
	}), "by_family")
}

func TestRedSchemaRefusesAnUnorderedRankPair(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		p := doc["independence_probe"].([]any)[0].(map[string]any)
		p["higher_rank"] = float64(5)
		p["higher_rank_name"] = "rank5-rust-observation"
	}), "independence_probe")
}

func TestRedSchemaRefusesAnOverrideGovernedByAnObservationRank(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		entries := doc["java_rust_agreements_overridden_by_a_higher_oracle"].([]any)
		if len(entries) == 0 {
			t.Fatal("no enrolled override to attack")
		}
		e := entries[0].(map[string]any)
		e["governing_rank"] = float64(4)
		e["governing_rank_name"] = "rank4-java-observation"
	}), "java_rust_agreements_overridden_by_a_higher_oracle")
}

func TestRedSchemaRefusesAFindingWithNoBasis(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		f := doc["findings"].([]any)[0].(map[string]any)
		f["basis"] = []any{}
	}), "findings")
}

func TestRedSchemaRefusesASeverityOutsideTheVocabulary(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		f := doc["findings"].([]any)[0].(map[string]any)
		f["severity"] = "INFORMATIONAL"
	}), "findings")
}

// TestRedSchemaRefusesAClaimAboveOBSERVED is the claim-vocabulary gate. The
// register's ceiling is OBSERVED and the schema must refuse an assurance note
// that argues it upward.
func TestRedSchemaRefusesAClaimAboveOBSERVED(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		doc["assurance_note"] = "PROVEN. Every verdict here is established by proof."
	}), "assurance_note")
}

func TestRedSchemaRefusesAFamilyWithFewerThanFiveRankSources(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		f := doc["families"].([]any)[0].(map[string]any)
		sources := f["rank_sources"].([]any)
		f["rank_sources"] = sources[:len(sources)-1]
	}), "families")
}

func TestRedSchemaRefusesASpeakingRankThatNamesNoBytes(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		for _, rawF := range doc["families"].([]any) {
			f := rawF.(map[string]any)
			for _, rawS := range f["rank_sources"].([]any) {
				s := rawS.(map[string]any)
				if s["strength"] != "ABSENT" {
					delete(s, "artifact_group")
					return
				}
			}
		}
		t.Fatal("every rank source is ABSENT; this attack has nothing to hit")
	}), "families")
}

func TestRedSchemaRefusesADroppedProbePair(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		probes := doc["independence_probe"].([]any)
		doc["independence_probe"] = probes[:len(probes)-1]
	}), "independence_probe")
}

func TestRedSchemaRefusesAnUnknownTopLevelField(t *testing.T) {
	mustFailSchema(t, redRegister(t, func(doc map[string]any) {
		doc["waivers"] = []any{"this register is not a waiver list"}
	}), "")
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}
