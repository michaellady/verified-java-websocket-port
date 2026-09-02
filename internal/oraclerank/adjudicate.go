package oraclerank

import (
	"fmt"
	"sort"
)

// Opinion is one oracle's answer to one proposition.
//
// An oracle that has nothing to say ABSTAINS, and abstention is a distinct
// state from disagreement. Collapsing the two is how a rank comes to exist in
// name only: an oracle that never speaks looks, in an aggregate, exactly like
// an oracle that always agrees.
type Opinion struct {
	Rank Rank `json:"rank"`
	// Verdict is the oracle's answer in this proposition's verdict space.
	// It MUST be empty when Abstains and non-empty when not.
	Verdict string `json:"verdict,omitempty"`
	// Abstains records that this oracle has no answer here. The Reason is
	// required: an unexplained abstention is indistinguishable from an
	// oracle that was never wired up.
	Abstains bool `json:"abstains,omitempty"`
	// AbstainReason says why, in one line, when Abstains.
	AbstainReason string `json:"abstain_reason,omitempty"`
	// Source is the repository-relative artifact plus pointer the verdict
	// was read from. It is required for every opinion, abstaining or not.
	Source string `json:"source"`
}

// Proposition is one question several oracles answer in a shared verdict
// space. Verdict strings are only ever compared for equality, never ordered,
// so the space may be any closed set the family defines.
type Proposition struct {
	ID       string    `json:"proposition_id"`
	Family   string    `json:"family"`
	Question string    `json:"question"`
	Opinions []Opinion `json:"opinions"`
}

// Outcome is the adjudication result.
type Outcome string

const (
	// OutcomeUndetermined means no oracle at any rank gave a verdict.
	OutcomeUndetermined Outcome = "UNDETERMINED"
	// OutcomeConcordant means every non-abstaining oracle agrees.
	OutcomeConcordant Outcome = "CONCORDANT"
	// OutcomeHigherOracleOverrides means at least one subordinate rank
	// disagrees with the governing rank. The governing verdict stands.
	OutcomeHigherOracleOverrides Outcome = "HIGHER_ORACLE_OVERRIDES"
)

// Adjudication is the decided proposition.
type Adjudication struct {
	PropositionID string  `json:"proposition_id"`
	Family        string  `json:"family"`
	Outcome       Outcome `json:"outcome"`

	// Governing is the strongest rank that gave a verdict, and Verdict is
	// that rank's verdict. Both are zero when Outcome is UNDETERMINED.
	Governing Rank   `json:"governing_rank,omitempty"`
	Verdict   string `json:"governing_verdict,omitempty"`

	// Dissenting lists every subordinate rank whose verdict differs from
	// the governing verdict, strongest first.
	Dissenting []Rank `json:"dissenting_ranks,omitempty"`

	// JavaRustConsensus records that ranks four and five both gave a
	// verdict and those verdicts are equal. This is the reading the 74/74
	// public-corpus differential and the 247-case Autobahn per-case
	// comparison produce, and on its own it is a rank-four-against-rank-five
	// result, not an adjudication.
	JavaRustConsensus bool `json:"java_rust_consensus"`
	// JavaRustConsensusVerdict is the verdict the two observations share.
	JavaRustConsensusVerdict string `json:"java_rust_consensus_verdict,omitempty"`
	// JavaRustConsensusOverridden is AC2's final clause, decided. It is
	// true exactly when ranks four and five agree AND a strictly higher
	// oracle gave a different verdict. When it is true, the agreement is
	// NOT parity and may not be reported as parity.
	JavaRustConsensusOverridden bool `json:"java_rust_consensus_overridden"`

	// Abstaining lists ranks that were offered the proposition and declined,
	// strongest first. It is carried into the register so a rank that never
	// speaks is visible rather than absent.
	Abstaining []Rank `json:"abstaining_ranks,omitempty"`
}

// validate fails closed on a malformed proposition. Every one of these would
// otherwise make an adjudication quietly weaker than it looks.
func (p Proposition) validate() error {
	if p.ID == "" {
		return fmt.Errorf("proposition has no id")
	}
	if p.Family == "" {
		return fmt.Errorf("proposition %s has no family", p.ID)
	}
	if len(p.Opinions) == 0 {
		return fmt.Errorf("proposition %s has no opinions", p.ID)
	}
	seen := map[Rank]bool{}
	for i, o := range p.Opinions {
		if !o.Rank.Valid() {
			return fmt.Errorf("proposition %s opinion %d: rank %d is outside the AC2 order", p.ID, i, uint8(o.Rank))
		}
		if seen[o.Rank] {
			return fmt.Errorf("proposition %s: %s gave two opinions; one rank speaks once", p.ID, o.Rank)
		}
		seen[o.Rank] = true
		if o.Source == "" {
			return fmt.Errorf("proposition %s: %s opinion has no source", p.ID, o.Rank)
		}
		if o.Abstains {
			if o.Verdict != "" {
				return fmt.Errorf("proposition %s: %s both abstains and votes %q", p.ID, o.Rank, o.Verdict)
			}
			if o.AbstainReason == "" {
				return fmt.Errorf("proposition %s: %s abstains with no reason", p.ID, o.Rank)
			}
			continue
		}
		if o.Verdict == "" {
			return fmt.Errorf("proposition %s: %s votes with an empty verdict", p.ID, o.Rank)
		}
	}
	return nil
}

// Adjudicate applies the AC2 order to one proposition.
//
// The rule, in full:
//
//   - The governing rank is the STRONGEST rank that gave a verdict. Abstention
//     passes governance down; disagreement does not.
//   - Every subordinate rank whose verdict differs from the governing verdict
//     is overridden. The governing verdict stands regardless of how many
//     subordinate ranks disagree or how strongly they agree with each other.
//   - Agreement between rank four and rank five is recorded, and when a
//     strictly higher oracle gave a different verdict that agreement is marked
//     OVERRIDDEN. That is AC2's final clause and it is the whole point: a
//     rank-four-against-rank-five comparison cannot settle a question a higher
//     oracle has already answered differently.
func Adjudicate(p Proposition) (Adjudication, error) {
	if err := p.validate(); err != nil {
		return Adjudication{}, err
	}

	verdicts := map[Rank]string{}
	var voting, abstaining []Rank
	for _, o := range p.Opinions {
		if o.Abstains {
			abstaining = append(abstaining, o.Rank)
			continue
		}
		verdicts[o.Rank] = o.Verdict
		voting = append(voting, o.Rank)
	}
	sortRanks(voting)
	sortRanks(abstaining)

	a := Adjudication{
		PropositionID: p.ID,
		Family:        p.Family,
		Abstaining:    abstaining,
	}

	javaRank, rustRank := ObservationRanks()
	javaVerdict, javaVoted := verdicts[javaRank]
	rustVerdict, rustVoted := verdicts[rustRank]
	if javaVoted && rustVoted && javaVerdict == rustVerdict {
		a.JavaRustConsensus = true
		a.JavaRustConsensusVerdict = javaVerdict
	}

	if len(voting) == 0 {
		a.Outcome = OutcomeUndetermined
		return a, nil
	}

	// voting is sorted strongest first, so voting[0] is the governing rank.
	a.Governing = voting[0]
	a.Verdict = verdicts[a.Governing]

	for _, r := range voting[1:] {
		if verdicts[r] != a.Verdict {
			a.Dissenting = append(a.Dissenting, r)
		}
	}
	if len(a.Dissenting) > 0 {
		a.Outcome = OutcomeHigherOracleOverrides
	} else {
		a.Outcome = OutcomeConcordant
	}

	// AC2's final clause. The consensus is overridden exactly when the
	// governing rank is strictly higher than rank four and disagrees with
	// what ranks four and five agreed on.
	if a.JavaRustConsensus &&
		a.Governing.Outranks(javaRank) &&
		a.Verdict != a.JavaRustConsensusVerdict {
		a.JavaRustConsensusOverridden = true
	}

	return a, nil
}

// ErrConsensusOverridden reports an attempt to read a rank-four/rank-five
// agreement as settling a question a higher oracle answered differently.
type ErrConsensusOverridden struct {
	PropositionID    string
	ConsensusVerdict string
	Governing        Rank
	GoverningVerdict string
}

func (e *ErrConsensusOverridden) Error() string {
	return fmt.Sprintf(
		"%s: Java and Rust agree on %q but %s says %q; AC2 forbids reading that agreement as parity",
		e.PropositionID, e.ConsensusVerdict, e.Governing, e.GoverningVerdict)
}

// ParityFromJavaRustAgreement is the guarded reading of a differential result.
//
// A differential comparison produces exactly one fact: Java and Rust behaved
// the same, or they did not. Turning "the same" into "parity" is a separate
// claim, and AC2 permits it only when no higher oracle has answered the same
// question differently. Every consumer that wants to read agreement as parity
// must come through here.
//
// It returns the agreed verdict when the reading is permitted, and an
// *ErrConsensusOverridden naming the governing oracle when it is not.
func ParityFromJavaRustAgreement(p Proposition) (string, error) {
	a, err := Adjudicate(p)
	if err != nil {
		return "", err
	}
	if !a.JavaRustConsensus {
		return "", fmt.Errorf("%s: Java and Rust did not both give a verdict, or gave different ones; there is no agreement to read", p.ID)
	}
	if a.JavaRustConsensusOverridden {
		return "", &ErrConsensusOverridden{
			PropositionID:    p.ID,
			ConsensusVerdict: a.JavaRustConsensusVerdict,
			Governing:        a.Governing,
			GoverningVerdict: a.Verdict,
		}
	}
	return a.JavaRustConsensusVerdict, nil
}

func sortRanks(rs []Rank) { sort.Slice(rs, func(i, j int) bool { return rs[i] < rs[j] }) }
