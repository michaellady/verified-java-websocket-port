package oraclerank

import (
	"fmt"
	"sort"
)

// This file answers a question the independence probe's verdict does not.
//
// The probe reports N co-votes and D disagreements. N is a count of
// PROPOSITIONS, not of distinguishable answers. internal/normcollide measured
// the same effect one layer down: the public differential's 74 rows carry 73
// distinct observations, and the handshake exam's 49 cases carry 26. The census
// in this package projects each of those observations onto a three-value
// verdict space, so its N collapses much further still, and a probe that
// reports "74 co-votes, 0 disagreements" can be reporting one answer repeated
// 74 times.
//
// That is a different failure from a relabelling and the register must not let
// them be read as the same thing. A pair whose co-votes exhibit exactly one
// (higher, lower) verdict pair has been asked one question N times: agreement
// there is a COLLISION of the projection, not evidence that the ranks are the
// same oracle. This file measures it and findings.go discloses it.

// VerdictPairCount is one (higher, lower) verdict pair and how often the two
// ranks produced it where both spoke.
type VerdictPairCount struct {
	Higher string `json:"higher_verdict"`
	Lower  string `json:"lower_verdict"`
	Count  int    `json:"propositions"`
}

// CoVoteResolution is the discriminating power of a scored family probe.
type CoVoteResolution struct {
	// DistinctVerdictPairs is how many distinct answers the CoVotes carry.
	// It is at most CoVotes and at most |verdict space| squared.
	DistinctVerdictPairs int `json:"distinct_verdict_pairs"`
	// Pairs is the full breakdown, most frequent first.
	Pairs []VerdictPairCount `json:"verdict_pairs"`
	// LargestClass is how many of the co-votes carry the single most common
	// answer. A pair whose LargestClass equals its CoVotes was asked one
	// question repeatedly.
	LargestClass int `json:"largest_class"`
	// VerdictSpace is how many distinct verdicts the family admits, carried
	// so the ratio is readable without the family in hand.
	VerdictSpace int `json:"family_verdict_space_size"`
}

// resolve measures the co-votes of one rank pair inside one family.
func resolve(f Family, higher, lower Rank) CoVoteResolution {
	counts := map[[2]string]int{}
	for _, p := range f.Propositions {
		hv, hok := votedVerdict(p, higher)
		lv, lok := votedVerdict(p, lower)
		if !hok || !lok {
			continue
		}
		counts[[2]string{hv, lv}]++
	}
	res := CoVoteResolution{
		DistinctVerdictPairs: len(counts),
		VerdictSpace:         len(f.VerdictSpace),
	}
	for k, n := range counts {
		res.Pairs = append(res.Pairs, VerdictPairCount{Higher: k[0], Lower: k[1], Count: n})
		if n > res.LargestClass {
			res.LargestClass = n
		}
	}
	sort.Slice(res.Pairs, func(i, j int) bool {
		if res.Pairs[i].Count != res.Pairs[j].Count {
			return res.Pairs[i].Count > res.Pairs[j].Count
		}
		if res.Pairs[i].Higher != res.Pairs[j].Higher {
			return res.Pairs[i].Higher < res.Pairs[j].Higher
		}
		return res.Pairs[i].Lower < res.Pairs[j].Lower
	})
	return res
}

// FamilyResolution is one family's own collapse, independent of any rank pair:
// how many distinct opinion tuples its propositions carry. A family of N
// propositions carrying D distinct tuples cannot exhibit more than D distinct
// adjudications, whatever N says.
type FamilyResolution struct {
	Family string `json:"family_id"`
	// Propositions is N.
	Propositions int `json:"propositions"`
	// DistinctOpinionTuples is D: the number of distinct full verdict-and-
	// abstention tuples across all five ranks.
	DistinctOpinionTuples int `json:"distinct_opinion_tuples"`
	// PropositionsSharingATuple is how many propositions are in a class of
	// size greater than one -- propositions this census cannot tell apart.
	PropositionsSharingATuple int `json:"propositions_sharing_a_tuple_with_another"`
	// LargestClass is the size of the biggest class.
	LargestClass int    `json:"largest_equivalence_class"`
	Statement    string `json:"statement"`
}

func familyResolution(f Family) FamilyResolution {
	counts := map[string]int{}
	for _, p := range f.Propositions {
		counts[opinionTuple(p)]++
	}
	fr := FamilyResolution{
		Family:                f.ID,
		Propositions:          len(f.Propositions),
		DistinctOpinionTuples: len(counts),
	}
	for _, n := range counts {
		if n > 1 {
			fr.PropositionsSharingATuple += n
		}
		if n > fr.LargestClass {
			fr.LargestClass = n
		}
	}
	fr.Statement = fmt.Sprintf(
		"%d propositions carrying %d distinct opinion tuples over a %d-value verdict space; %d of them share a tuple with another proposition and the largest class holds %d. This census cannot distinguish two propositions in the same class, so agreement inside one is a property of the projection rather than a repeated measurement.",
		fr.Propositions, fr.DistinctOpinionTuples, len(f.VerdictSpace), fr.PropositionsSharingATuple, fr.LargestClass)
	return fr
}

func opinionTuple(p Proposition) string {
	parts := make([]string, 0, len(Ranks()))
	for _, r := range Ranks() {
		v, ok := votedVerdict(p, r)
		if !ok {
			parts = append(parts, r.String()+"=abstain")
			continue
		}
		parts = append(parts, r.String()+"="+v)
	}
	out := ""
	for i, s := range parts {
		if i > 0 {
			out += ";"
		}
		out += s
	}
	return out
}

// Resolutions measures every family in the census.
func Resolutions(families []Family) []FamilyResolution {
	out := make([]FamilyResolution, 0, len(families))
	for _, f := range families {
		out = append(out, familyResolution(f))
	}
	return out
}
