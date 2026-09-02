package oraclerank

import (
	"fmt"
	"sort"
)

// Finding is a conclusion this census COMPUTES. Every field of every finding is
// derived from the numbers above it in the register, so a finding cannot drift
// away from the evidence it summarizes: if the evidence changes, the finding
// changes with it or the recomputation fails.
type Finding struct {
	ID string `json:"id"`
	// Severity is BLOCKING when the finding names something that would make
	// an existing claim in this repository wrong, and DISCLOSURE when it
	// names a limit of the mechanism itself.
	Severity  string `json:"severity"`
	Statement string `json:"statement"`
	// Basis names the computed numbers the statement rests on.
	Basis []string `json:"basis"`
	// OwnerActionRequired is the exact action that would settle the finding,
	// or empty when the finding is settled by evidence already here.
	OwnerActionRequired string `json:"owner_action_required,omitempty"`
}

// Findings derives the register's conclusions from its own computed numbers.
func Findings(reg Register, families []Family) []Finding {
	var out []Finding

	// F-1: the ranks that are not bound to what they are named after.
	for _, b := range reg.RankBindings {
		if b.Strength == BoundToContent {
			continue
		}
		out = append(out, Finding{
			ID:        fmt.Sprintf("ORACLE-RANK-BINDING-%d", uint8(b.Rank)),
			Severity:  "DISCLOSURE",
			Statement: fmt.Sprintf("%s is %s, not CONTENT_BOUND. %s", b.Rank, b.Strength, b.NotBoundTo),
			Basis: []string{
				fmt.Sprintf("rank_bindings[%s].strength = %s", b.Rank, b.Strength),
				fmt.Sprintf("rank_bindings[%s] hashes %d committed artifact(s) on every run", b.Rank, len(b.Artifacts)),
			},
			OwnerActionRequired: b.OwnerActionRequired,
		})
	}

	// F-2: the AC2 clause, decided, per governing rank.
	byGoverning := map[Rank]int{}
	byFamily := map[string]int{}
	for _, e := range reg.Overridden {
		byGoverning[e.Governing]++
		byFamily[e.Family]++
	}
	if len(reg.Overridden) > 0 {
		governingNames := make([]string, 0, len(byGoverning))
		for r, n := range byGoverning {
			governingNames = append(governingNames, fmt.Sprintf("%s on %d", r, n))
		}
		sort.Strings(governingNames)
		familyNames := make([]string, 0, len(byFamily))
		for f, n := range byFamily {
			familyNames = append(familyNames, fmt.Sprintf("%s on %d", f, n))
		}
		sort.Strings(familyNames)
		out = append(out, Finding{
			ID:       "ORACLE-RANK-AC2-OVERRIDES",
			Severity: "BLOCKING",
			Statement: fmt.Sprintf(
				"%d of the %d propositions where Java and Rust agree are OVERRIDDEN by a higher oracle. On each of them the differential result reads as agreement and AC2 forbids reading that agreement as parity. Governing: %v. By family: %v.",
				reg.Accounting.JavaRustConsensusOverride, reg.Accounting.JavaRustConsensus, governingNames, familyNames),
			Basis: []string{
				fmt.Sprintf("accounting.java_rust_consensus = %d", reg.Accounting.JavaRustConsensus),
				fmt.Sprintf("accounting.java_rust_consensus_overridden = %d", reg.Accounting.JavaRustConsensusOverride),
				"every entry is enrolled in java_rust_agreements_overridden_by_a_higher_oracle and the enrolment is exact in both directions (internal/oraclerank.VerifyRules)",
			},
			OwnerActionRequired: "adjudicate each enrolled proposition -- Java quirk to preserve, port defect to fix, or underspecified behaviour -- and record the disposition. This register states that the question is open; it does not answer it, and it is not a waiver list.",
		})
	}

	// F-3: ranks that never differ from a rank below them.
	for _, p := range reg.IndependenceProbe {
		if p.Verdict != ProbeNotDistinguished {
			continue
		}
		out = append(out, Finding{
			ID:       fmt.Sprintf("ORACLE-RANK-INDISTINGUISHABLE-%d-%d", uint8(p.Higher), uint8(p.Lower)),
			Severity: "BLOCKING",
			Statement: fmt.Sprintf(
				"%s is EMPIRICALLY INDISTINGUISHABLE from %s on this evidence: %d shared propositions where the two read different bytes, %d disagreements. AC2 gives %s authority over %s, and nothing here shows it is a separate oracle rather than a relabelling.",
				p.Higher, p.Lower, p.CoVotes, p.Disagreements, p.Higher, p.Lower),
			Basis: append([]string{
				fmt.Sprintf("independence_probe[%s vs %s].co_votes = %d, .disagreements = %d", p.Higher, p.Lower, p.CoVotes, p.Disagreements),
			}, familyBasis(p)...),
			OwnerActionRequired: fmt.Sprintf(
				"supply evidence at %s that is derived independently of %s and can disagree with it, or stop reading %s as an independent check on %s.",
				p.Higher, p.Lower, p.Higher, p.Lower),
		})
	}

	// F-4: rank pairs whose independence this census cannot measure at all.
	for _, p := range reg.IndependenceProbe {
		if p.Verdict != ProbeSharedDerivation {
			continue
		}
		out = append(out, Finding{
			ID:       fmt.Sprintf("ORACLE-RANK-UNPROBEABLE-%d-%d", uint8(p.Higher), uint8(p.Lower)),
			Severity: "DISCLOSURE",
			Statement: fmt.Sprintf(
				"Whether %s is independent of %s CANNOT BE MEASURED here: everywhere the two co-vote, their verdicts vary with the same bytes. This census neither confirms nor refutes the independence AC2's ordering assumes between them.",
				p.Higher, p.Lower),
			Basis:               familyBasis(p),
			OwnerActionRequired: fmt.Sprintf("supply a body of evidence in which %s and %s answer the same question from different bytes.", p.Higher, p.Lower),
		})
	}

	// F-5: the negative control, stated as a computed fact rather than a claim.
	for _, f := range families {
		if f.ID != FamilyDiffProbe {
			continue
		}
		out = append(out, Finding{
			ID:       "ORACLE-RANK-POLARITY-CONTROL",
			Severity: "DISCLOSURE",
			Statement: fmt.Sprintf(
				"The %d propositions of %s are a pure rank-four-against-rank-five comparison with no higher oracle present, and NONE of them is marked overridden. The override rule therefore discriminates: it does not fire wherever Java and Rust agree, only where a higher oracle disagrees with what they agreed on.",
				len(f.Propositions), f.ID),
			Basis: []string{
				fmt.Sprintf("families[%s].proposition_count = %d", f.ID, len(f.Propositions)),
				fmt.Sprintf("no entry in java_rust_agreements_overridden_by_a_higher_oracle carries family %s", f.ID),
				"internal/oraclerank.VerifyRules fails if any proposition in this family is marked overridden",
			},
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func familyBasis(p PairProbe) []string {
	var basis []string
	for _, fp := range p.ByFamily {
		basis = append(basis, fmt.Sprintf("independence_probe[%s vs %s].by_family[%s] = %s (co_votes %d, disagreements %d, groups %q vs %q)",
			p.Higher, p.Lower, fp.Family, fp.Verdict, fp.CoVotes, fp.Disagreements, fp.HigherGroup, fp.LowerGroup))
	}
	return basis
}
