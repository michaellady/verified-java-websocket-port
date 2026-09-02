package oraclerank

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// RegisterPath is the committed adjudication register this package emits and
// verifies.
const RegisterPath = "evidence/oracle-hierarchy/adjudication-register.json"

// RegisterSchemaVersion and RegisterEntityType name the artifact.
const (
	RegisterSchemaVersion = "1.0.0"
	RegisterEntityType    = "OracleHierarchyAdjudicationRegister"
)

// FamilyReport is one family as the register records it.
type FamilyReport struct {
	Family
	PropositionCount int            `json:"proposition_count"`
	OutcomeCounts    map[string]int `json:"outcome_counts"`
	// VotesByRank counts, per rank, how many propositions in this family the
	// rank actually gave a verdict on. A rank with zero votes is visible
	// here rather than absent.
	VotesByRank    map[string]int `json:"votes_by_rank"`
	AbstainsByRank map[string]int `json:"abstains_by_rank"`
}

// OverrideEntry is one proposition where ranks four and five agreed and a
// higher oracle said something else. This is AC2's forbidden reading, enrolled.
type OverrideEntry struct {
	PropositionID    string `json:"proposition_id"`
	Family           string `json:"family"`
	Question         string `json:"question"`
	ConsensusVerdict string `json:"java_rust_consensus_verdict"`
	Governing        Rank   `json:"governing_rank"`
	GoverningName    string `json:"governing_rank_name"`
	GoverningVerdict string `json:"governing_verdict"`
	GoverningSource  string `json:"governing_source"`
}

// Register is the committed artifact.
type Register struct {
	SchemaVersion string `json:"schema_version"`
	EntityType    string `json:"entity_type"`
	Statement     string `json:"statement"`
	AssuranceNote string `json:"assurance_note"`

	RankBindings []Binding      `json:"rank_bindings"`
	Families     []FamilyReport `json:"families"`

	IndependenceProbe []PairProbe `json:"independence_probe"`

	// Findings are conclusions COMPUTED from the numbers in this document,
	// so a finding cannot drift away from the evidence it summarizes.
	Findings []Finding `json:"findings"`

	Accounting struct {
		Propositions              int            `json:"propositions"`
		Undetermined              int            `json:"undetermined"`
		Concordant                int            `json:"concordant"`
		HigherOracleOverrides     int            `json:"higher_oracle_overrides"`
		JavaRustConsensus         int            `json:"java_rust_consensus"`
		JavaRustConsensusOverride int            `json:"java_rust_consensus_overridden"`
		GoverningRankCounts       map[string]int `json:"governing_rank_counts"`
	} `json:"accounting"`

	// Overridden is the closed set of propositions where a Java/Rust
	// agreement is overridden by a higher oracle. The gate is exact in both
	// directions over it: an override the evidence exhibits and this list
	// omits fails, and an entry this list carries that the evidence does not
	// exhibit fails.
	Overridden []OverrideEntry `json:"java_rust_agreements_overridden_by_a_higher_oracle"`
}

// Recompute reads the committed evidence and builds the register from it. No
// committed register is an input, so a --check cannot pass by reading itself.
func Recompute(root string) (Register, []Family, error) {
	families, err := Census(root)
	if err != nil {
		return Register{}, nil, err
	}
	bindings, err := Bindings(root)
	if err != nil {
		return Register{}, nil, err
	}

	reg := Register{
		SchemaVersion: RegisterSchemaVersion,
		EntityType:    RegisterEntityType,
		Statement: "US-020 AC2 says RFC 6455 is rank one, in-scope Autobahn is rank two, independent neutral expectations are rank three, Java observation is rank four and Rust observation is rank five, and that agreement between Java and Rust cannot override a higher oracle. " +
			"Until this register that sentence had no mechanism anywhere in this tree: one prose string in internal/deltaledger/definitions_gap_closure.go, no type, no field and no check. " +
			"internal/oraclerank is the mechanism. This document is what it computes from committed evidence, and cmd/oraclerankctl --check recomputes it and refuses any difference, so it is a gate rather than a document. " +
			"The register is exact in both directions over its override list: an overridden agreement the evidence exhibits and this list omits fails, and an entry this list carries that the evidence does not exhibit fails.",
		AssuranceNote: "OBSERVED. Every verdict here is read from committed bytes; nothing here is proved, and the strength of each rank's attachment is stated per rank in rank_bindings and per family in rank_sources rather than averaged into one number. " +
			"Rank one is bound to committed HUMAN READINGS of RFC 6455 and not to the RFC text, which is pinned by digest and is not in this repository.",
		RankBindings:      bindings,
		IndependenceProbe: IndependenceProbe(families),
	}
	reg.Accounting.GoverningRankCounts = map[string]int{}

	for _, f := range families {
		fr := FamilyReport{
			Family:           f,
			PropositionCount: len(f.Propositions),
			OutcomeCounts:    map[string]int{},
			VotesByRank:      map[string]int{},
			AbstainsByRank:   map[string]int{},
		}
		for _, r := range Ranks() {
			fr.VotesByRank[r.String()] = 0
			fr.AbstainsByRank[r.String()] = 0
		}

		for _, prop := range f.Propositions {
			a, err := Adjudicate(prop)
			if err != nil {
				return Register{}, nil, err
			}
			fr.OutcomeCounts[string(a.Outcome)]++
			for _, o := range prop.Opinions {
				if o.Abstains {
					fr.AbstainsByRank[o.Rank.String()]++
				} else {
					fr.VotesByRank[o.Rank.String()]++
				}
			}

			reg.Accounting.Propositions++
			switch a.Outcome {
			case OutcomeUndetermined:
				reg.Accounting.Undetermined++
			case OutcomeConcordant:
				reg.Accounting.Concordant++
			case OutcomeHigherOracleOverrides:
				reg.Accounting.HigherOracleOverrides++
			}
			if a.Governing.Valid() {
				reg.Accounting.GoverningRankCounts[a.Governing.String()]++
			}
			if a.JavaRustConsensus {
				reg.Accounting.JavaRustConsensus++
			}
			if a.JavaRustConsensusOverridden {
				reg.Accounting.JavaRustConsensusOverride++
				reg.Overridden = append(reg.Overridden, OverrideEntry{
					PropositionID:    prop.ID,
					Family:           prop.Family,
					Question:         prop.Question,
					ConsensusVerdict: a.JavaRustConsensusVerdict,
					Governing:        a.Governing,
					GoverningName:    a.Governing.String(),
					GoverningVerdict: a.Verdict,
					GoverningSource:  sourceOf(prop, a.Governing),
				})
			}
		}
		reg.Families = append(reg.Families, fr)
	}

	sort.Slice(reg.Overridden, func(i, j int) bool {
		return reg.Overridden[i].PropositionID < reg.Overridden[j].PropositionID
	})
	reg.Findings = Findings(reg, families)
	return reg, families, nil
}

func sourceOf(p Proposition, r Rank) string {
	for _, o := range p.Opinions {
		if o.Rank == r {
			return o.Source
		}
	}
	return ""
}

// Encode renders the register as the committed bytes.
func Encode(reg Register) ([]byte, error) {
	encoded, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// Write recomputes and writes the register.
func Write(root string) ([]byte, error) {
	reg, _, err := Recompute(root)
	if err != nil {
		return nil, err
	}
	encoded, err := Encode(reg)
	if err != nil {
		return nil, err
	}
	full := filepath.Join(root, filepath.FromSlash(RegisterPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(full, encoded, 0o644); err != nil {
		return nil, err
	}
	return encoded, nil
}

// Verify recomputes the register from the evidence and refuses any difference
// from the committed bytes.
func Verify(root string) error {
	reg, _, err := Recompute(root)
	if err != nil {
		return err
	}
	want, err := Encode(reg)
	if err != nil {
		return err
	}
	got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(RegisterPath)))
	if err != nil {
		return fmt.Errorf("read %s: %w", RegisterPath, err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s does not equal its recomputation from the evidence (committed %d bytes, recomputed %d bytes)",
			RegisterPath, len(got), len(want))
	}
	return nil
}

// VerifyRules checks the adjudication rules themselves against the evidence,
// independently of whether the committed document matches. It is the half of
// the gate that would still have something to say if the register were deleted.
//
// It asserts, and fails on any one of:
//
//   - every proposition in the census adjudicates without error;
//   - the committed register's override list is EXACT in both directions
//     against the overrides the evidence exhibits;
//   - ParityFromJavaRustAgreement REFUSES on every overridden agreement (the
//     executable form of AC2's final clause) and the refusal names the
//     governing rank;
//   - the pure rank-four-against-rank-five family exhibits no override, so a
//     check that fires everywhere is distinguished from one that discriminates;
//   - no rank is declared and then silent: a rank named in a family's
//     rank_sources with a strength other than ABSENT must actually vote there.
func VerifyRules(root string) error {
	reg, families, err := Recompute(root)
	if err != nil {
		return err
	}

	exhibited := map[string]OverrideEntry{}
	for _, f := range families {
		found, err := CheckFamilyRules(f)
		if err != nil {
			return err
		}
		for id, entry := range found {
			exhibited[id] = entry
		}
	}

	if len(exhibited) != reg.Accounting.JavaRustConsensusOverride {
		return fmt.Errorf("accounting says %d overridden agreements, the evidence exhibits %d",
			reg.Accounting.JavaRustConsensusOverride, len(exhibited))
	}

	committed, err := readCommittedOverrides(root)
	if err != nil {
		return err
	}
	for id, want := range exhibited {
		got, ok := committed[id]
		if !ok {
			return fmt.Errorf("%s: the evidence exhibits an overridden Java/Rust agreement that %s does not enrol", id, RegisterPath)
		}
		if got.ConsensusVerdict != want.ConsensusVerdict || got.Governing != want.Governing || got.GoverningVerdict != want.GoverningVerdict {
			return fmt.Errorf("%s: %s enrols consensus=%q governing=%s/%q, the evidence exhibits consensus=%q governing=%s/%q",
				id, RegisterPath, got.ConsensusVerdict, got.Governing, got.GoverningVerdict,
				want.ConsensusVerdict, want.Governing, want.GoverningVerdict)
		}
	}
	for id := range committed {
		if _, ok := exhibited[id]; !ok {
			return fmt.Errorf("%s enrols %s, which the evidence does not exhibit; the register is not a waiver list", RegisterPath, id)
		}
	}
	return nil
}

func readCommittedOverrides(root string) (map[string]OverrideEntry, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(RegisterPath)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", RegisterPath, err)
	}
	var doc struct {
		Overridden []OverrideEntry `json:"java_rust_agreements_overridden_by_a_higher_oracle"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode %s: %w", RegisterPath, err)
	}
	out := make(map[string]OverrideEntry, len(doc.Overridden))
	for _, e := range doc.Overridden {
		if _, dup := out[e.PropositionID]; dup {
			return nil, fmt.Errorf("%s enrols %s twice", RegisterPath, e.PropositionID)
		}
		out[e.PropositionID] = e
	}
	return out, nil
}

// CheckFamilyRules is the per-family half of VerifyRules, extracted so it can
// be exercised against a fabricated family rather than only against the
// committed evidence. A deletion attack on the checks inside VerifyRules found
// that two of them were re-implemented by their tests instead of being called
// by them, so deleting the production check left the test green; this function
// is what those tests now call.
//
// It returns the overridden Java/Rust agreements the family exhibits.
func CheckFamilyRules(f Family) (map[string]OverrideEntry, error) {
	exhibited := map[string]OverrideEntry{}
	voted := map[Rank]int{}

	for _, prop := range f.Propositions {
		a, err := Adjudicate(prop)
		if err != nil {
			return nil, err
		}
		for _, o := range prop.Opinions {
			if !o.Abstains {
				voted[o.Rank]++
			}
		}
		if !a.JavaRustConsensusOverridden {
			continue
		}
		// The polarity control: the pure rank-four-against-rank-five family
		// has no oracle above rank four in it, so the override rule must
		// never fire there. A rule that fires everywhere is not a rule.
		if f.ID == FamilyDiffProbe {
			return nil, fmt.Errorf(
				"%s: %s is marked overridden, but no oracle above rank four speaks in this family; the override rule is firing where it must not",
				f.ID, prop.ID)
		}
		exhibited[prop.ID] = OverrideEntry{
			PropositionID:    prop.ID,
			ConsensusVerdict: a.JavaRustConsensusVerdict,
			Governing:        a.Governing,
			GoverningVerdict: a.Verdict,
		}

		// The executable form of AC2's final clause must refuse here.
		verdict, err := ParityFromJavaRustAgreement(prop)
		if err == nil {
			return nil, fmt.Errorf(
				"%s: ParityFromJavaRustAgreement returned %q on an overridden agreement; AC2's final clause is not being enforced",
				prop.ID, verdict)
		}
		var overridden *ErrConsensusOverridden
		if !errors.As(err, &overridden) {
			return nil, fmt.Errorf("%s: ParityFromJavaRustAgreement refused with %v, want an *ErrConsensusOverridden", prop.ID, err)
		}
		if overridden.Governing != a.Governing {
			return nil, fmt.Errorf("%s: refusal names %s, adjudication names %s", prop.ID, overridden.Governing, a.Governing)
		}
	}

	// No rank may be declared and then silent, and no rank declared ABSENT
	// may speak. Either would let a rank exist in name only.
	for _, rs := range f.RankSources {
		if rs.Strength == SourceAbsent {
			if voted[rs.Rank] != 0 {
				return nil, fmt.Errorf("%s: %s is declared ABSENT and voted %d times", f.ID, rs.Rank, voted[rs.Rank])
			}
			continue
		}
		if voted[rs.Rank] == 0 {
			return nil, fmt.Errorf(
				"%s: %s is declared with strength %s and never gave a verdict; a rank that is named and silent exists in name only",
				f.ID, rs.Rank, rs.Strength)
		}
	}
	return exhibited, nil
}
