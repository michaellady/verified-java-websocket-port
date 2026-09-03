package oraclerank

import (
	"fmt"
	"sort"
)

// ProbeVerdict is the outcome of asking whether one rank is empirically
// distinguishable from a rank below it.
type ProbeVerdict string

const (
	// ProbeDistinguished means the higher rank disagreed with the lower one
	// at least once, on propositions where the two ranks read different
	// bodies of evidence. The higher rank is doing work the lower one does
	// not.
	ProbeDistinguished ProbeVerdict = "DISTINGUISHED"
	// ProbeNotDistinguished means the two ranks read different bodies of
	// evidence, both spoke on at least one shared proposition, and never
	// once disagreed. The higher rank may still be right; this evidence
	// cannot show it is a separate oracle.
	ProbeNotDistinguished ProbeVerdict = "NOT_DISTINGUISHED"
	// ProbeNoCoVotes means the two ranks never both spoke on the same
	// proposition, so nothing was measured.
	ProbeNoCoVotes ProbeVerdict = "NO_CO_VOTES"
	// ProbeSharedDerivation means that everywhere the two ranks co-vote,
	// their verdicts vary with the same bytes. Agreement there is an
	// artifact of the derivation, not evidence, so this probe refuses to
	// score it. Reporting such a pair as NOT_DISTINGUISHED would be a
	// manufactured finding.
	ProbeSharedDerivation ProbeVerdict = "NOT_PROBEABLE_SHARED_DERIVATION"
)

// FamilyProbe is one rank pair measured inside one family.
type FamilyProbe struct {
	Family        string       `json:"family_id"`
	Verdict       ProbeVerdict `json:"verdict"`
	HigherGroup   string       `json:"higher_artifact_group,omitempty"`
	LowerGroup    string       `json:"lower_artifact_group,omitempty"`
	CoVotes       int          `json:"co_votes"`
	Disagreements int          `json:"disagreements"`
	Examples      []string     `json:"disagreement_examples,omitempty"`
	// Resolution says how many distinct answers those co-votes carry. It is
	// NOT part of the verdict: a pair is scored on disagreements exactly as
	// before. It is here because CoVotes counts propositions, not
	// distinguishable questions, and a reader who takes a large CoVotes for
	// a large body of evidence is reading a collision. See collision.go.
	Resolution CoVoteResolution `json:"co_vote_resolution"`
}

// PairProbe measures one ordered rank pair across the census.
type PairProbe struct {
	Higher     Rank         `json:"higher_rank"`
	HigherName string       `json:"higher_rank_name"`
	Lower      Rank         `json:"lower_rank"`
	LowerName  string       `json:"lower_rank_name"`
	Verdict    ProbeVerdict `json:"verdict"`

	CoVotes       int      `json:"co_votes"`
	Disagreements int      `json:"disagreements"`
	Examples      []string `json:"disagreement_examples,omitempty"`

	// ByFamily is the same measurement per family, kept because the two
	// neutral-expectation tiers behave differently and an overall verdict
	// would hide that.
	ByFamily []FamilyProbe `json:"by_family"`
	Note     string        `json:"note"`
}

// IndependenceProbe asks, for every ordered rank pair, whether the higher rank
// is empirically distinguishable from the lower one on this evidence.
//
// This exists because "rank three is an independent neutral expectation" is a
// claim, and a rank that never once differs from the rank below it is
// indistinguishable from a relabelling of that rank. Independence is a property
// of a PAIR: the probe scores a pair inside a family only when the two ranks'
// verdicts there vary with different bytes, which each family declares as its
// ranks' artifact groups. A pair whose opinions share a group cannot disagree,
// and scoring it would manufacture a finding rather than measure one.
func IndependenceProbe(families []Family) []PairProbe {
	group := map[string]map[Rank]string{}
	for _, f := range families {
		group[f.ID] = map[Rank]string{}
		for _, rs := range f.RankSources {
			group[f.ID][rs.Rank] = rs.ArtifactGroup
		}
	}

	var probes []PairProbe
	ranks := Ranks()
	for i, higher := range ranks {
		for _, lower := range ranks[i+1:] {
			p := PairProbe{
				Higher: higher, HigherName: higher.String(),
				Lower: lower, LowerName: lower.String(),
			}
			sawSharedDerivation := false

			for _, f := range families {
				hg, lg := group[f.ID][higher], group[f.ID][lower]
				fp := FamilyProbe{Family: f.ID, HigherGroup: hg, LowerGroup: lg}
				for _, prop := range f.Propositions {
					hv, hok := votedVerdict(prop, higher)
					lv, lok := votedVerdict(prop, lower)
					if !hok || !lok {
						continue
					}
					fp.CoVotes++
					if hv != lv {
						fp.Disagreements++
						if len(fp.Examples) < 3 {
							fp.Examples = append(fp.Examples, prop.ID)
						}
					}
				}
				if fp.CoVotes == 0 {
					continue
				}
				// Measured for every family probe that has co-votes,
				// including the ones the probe declines to score: how
				// many distinguishable answers those co-votes carry is
				// a fact about the evidence, not about the scoring.
				fp.Resolution = resolve(f, higher, lower)
				// Two ranks whose verdicts vary with the same bytes are
				// not comparable for independence, however many times
				// they co-vote.
				if hg == "" || lg == "" || hg == lg {
					fp.Verdict = ProbeSharedDerivation
					fp.Disagreements = 0
					fp.Examples = nil
					sawSharedDerivation = true
					p.ByFamily = append(p.ByFamily, fp)
					continue
				}
				if fp.Disagreements > 0 {
					fp.Verdict = ProbeDistinguished
				} else {
					fp.Verdict = ProbeNotDistinguished
				}
				p.CoVotes += fp.CoVotes
				p.Disagreements += fp.Disagreements
				for _, id := range fp.Examples {
					if len(p.Examples) < 3 {
						p.Examples = append(p.Examples, id)
					}
				}
				p.ByFamily = append(p.ByFamily, fp)
			}

			switch {
			case p.CoVotes > 0 && p.Disagreements > 0:
				p.Verdict = ProbeDistinguished
				p.Note = fmt.Sprintf("%s differed from %s on %d of %d independently sourced shared propositions%s.",
					higher, lower, p.Disagreements, p.CoVotes, familiesSuffix(p.ByFamily, ProbeDistinguished))
			case p.CoVotes > 0:
				p.Verdict = ProbeNotDistinguished
				p.Note = fmt.Sprintf("%s and %s both gave a verdict on %d independently sourced shared propositions and never differed. On this evidence %s cannot be shown to be a separate oracle from %s.",
					higher, lower, p.CoVotes, higher, lower)
			case sawSharedDerivation:
				p.Verdict = ProbeSharedDerivation
				p.Note = fmt.Sprintf("%s and %s co-vote only where their verdicts vary with the same bytes%s. Agreement there would be an artifact of the derivation, so this pair is not scored, and a claim that one is independent of the other cannot be settled by this census.",
					higher, lower, familiesSuffix(p.ByFamily, ProbeSharedDerivation))
			default:
				p.Verdict = ProbeNoCoVotes
				p.Note = fmt.Sprintf("%s and %s never both gave a verdict on the same proposition in this census.", higher, lower)
			}
			probes = append(probes, p)
		}
	}
	return probes
}

func familiesSuffix(fps []FamilyProbe, want ProbeVerdict) string {
	var names []string
	for _, fp := range fps {
		if fp.Verdict == want {
			names = append(names, fp.Family)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return fmt.Sprintf(" (%v)", names)
}

func votedVerdict(p Proposition, r Rank) (string, bool) {
	for _, o := range p.Opinions {
		if o.Rank == r {
			if o.Abstains {
				return "", false
			}
			return o.Verdict, true
		}
	}
	return "", false
}
