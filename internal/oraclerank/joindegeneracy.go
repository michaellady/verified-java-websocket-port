package oraclerank

import (
	"fmt"
	"sort"
	"strings"
)

// JoinDegeneracy answers a question the independence probe does not ask.
//
// The probe refuses to score a rank pair whose two opinions vary with the SAME
// bytes, because agreement there is an artifact of the derivation. That test is
// on the artifact groups. It does not catch a second way agreement can be an
// artifact: the census can read the two ranks out of DIFFERENT documents and
// still make disagreement impossible, if the KEY it looks the lower rank up by
// is a function of the higher rank's verdict.
//
// That is exactly what the handshake family does. censusHandshake calls
// handshakeOutcomeKey(c), which is computed from the corpus case's own
// expected.verdict -- rank three's verdict -- and then reads rank four's
// java_observable at that key. If, for every key reachable from a rank-three
// verdict v, the mapping records java_observable in {v, "conditional"}, then
// rank four's non-abstaining verdict is ALWAYS v and the pair cannot disagree
// no matter what the corpus holds. The 32 co-votes and 0 disagreements the
// probe reports there are then not a measurement.
//
// This file computes that property from the committed mapping directly, over
// every entry rather than only the entries the corpus happens to reach, and the
// register carries the result so the reader is not left to infer it from a zero.
type JoinDegeneracy struct {
	Family     string `json:"family_id"`
	Higher     Rank   `json:"higher_rank"`
	HigherName string `json:"higher_rank_name"`
	Lower      Rank   `json:"lower_rank"`
	LowerName  string `json:"lower_rank_name"`

	// KeyDerivation says, in one sentence, what the census looks the lower
	// rank's opinion up by.
	KeyDerivation string `json:"key_derivation"`

	// Degenerate is true when no assignment of the higher rank's verdict can
	// produce a disagreement, given the committed lookup table.
	Degenerate bool `json:"disagreement_structurally_impossible"`

	// ReachableVerdicts is, per higher-rank verdict, the lower-rank verdicts
	// the join can produce. Abstentions are excluded: an abstention is not a
	// disagreement.
	ReachableVerdicts map[string][]string `json:"lower_rank_verdicts_reachable_from_each_higher_verdict"`

	// KeysConsidered is how many entries of the lookup table were examined.
	KeysConsidered int `json:"lookup_keys_considered"`
	// KeysAbstaining is how many of them make the lower rank abstain.
	KeysAbstaining int `json:"lookup_keys_that_make_the_lower_rank_abstain"`

	Statement string `json:"statement"`
}

// handshakeJoinDegeneracy computes the property over the whole committed
// mapping. It takes the mapping rather than the corpus deliberately: the
// question is what the JOIN can produce, not what these 49 cases happened to
// produce, so a corpus that grew a new case must not be able to change the
// answer.
func handshakeJoinDegeneracy(mapping map[[2]string]handshakeMappingEntry) (JoinDegeneracy, error) {
	jd := JoinDegeneracy{
		Family:            FamilyHandshake,
		Higher:            RankNeutralExpectation,
		HigherName:        RankNeutralExpectation.String(),
		Lower:             RankJavaObservation,
		LowerName:         RankJavaObservation.String(),
		KeyDerivation:     "oraclerank.handshakeOutcomeKey(c) computes the mapping key from the corpus case's own expected.verdict -- rank three's verdict: `accept` and `incomplete` map to themselves, and `reject` maps to the case's reject_code. Rank four's opinion is then read at that key. The key is therefore a function of rank three's verdict.",
		ReachableVerdicts: map[string][]string{},
	}

	// The reject codes are exactly the mapping keys that are not the two
	// self-named verdicts, so the reachable-key set is derived from the
	// committed table rather than listed here.
	reachable := map[string][]([2]string){}
	for key := range mapping {
		switch key[1] {
		case "accept", "incomplete":
			reachable[key[1]] = append(reachable[key[1]], key)
		default:
			reachable["reject"] = append(reachable["reject"], key)
		}
	}
	for _, v := range []string{"accept", "reject", "incomplete"} {
		keys := reachable[v]
		if len(keys) == 0 {
			return JoinDegeneracy{}, fmt.Errorf(
				"%s: no mapping key is reachable from the rank-three verdict %q; the join analysis would be vacuous",
				HandshakeLiveMappingPath, v)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i][0] != keys[j][0] {
				return keys[i][0] < keys[j][0]
			}
			return keys[i][1] < keys[j][1]
		})
		seen := map[string]bool{}
		var got []string
		for _, k := range keys {
			jd.KeysConsidered++
			obs := mapping[k].JavaObservable
			if obs == "conditional" {
				jd.KeysAbstaining++
				continue
			}
			if !seen[obs] {
				seen[obs] = true
				got = append(got, obs)
			}
		}
		sort.Strings(got)
		jd.ReachableVerdicts[v] = got
	}

	jd.Degenerate = true
	var counterexamples []string
	for v, got := range jd.ReachableVerdicts {
		for _, o := range got {
			if o != v {
				jd.Degenerate = false
				counterexamples = append(counterexamples, fmt.Sprintf("%s->%s", v, o))
			}
		}
	}
	sort.Strings(counterexamples)

	if jd.Degenerate {
		jd.Statement = fmt.Sprintf(
			"DISAGREEMENT IS STRUCTURALLY IMPOSSIBLE in %s between %s and %s. Over all %d keys of %s, every key reachable from a rank-three verdict v records java_observable either v or `conditional`, and rank four abstains on `conditional` (%d of the %d keys). Rank four's non-abstaining verdict is therefore always exactly rank three's, whatever the corpus holds. The co-votes the independence probe reports for this pair in this family are a property of the census's own join, not a measurement of two oracles.",
			FamilyHandshake, RankNeutralExpectation, RankJavaObservation,
			jd.KeysConsidered, HandshakeLiveMappingPath, jd.KeysAbstaining, jd.KeysConsidered)
	} else {
		jd.Statement = fmt.Sprintf(
			"Disagreement is POSSIBLE in %s between %s and %s: over the %d keys of %s the join can carry a rank-three verdict to a different rank-four verdict (%s). Agreement measured here is therefore a measurement.",
			FamilyHandshake, RankNeutralExpectation, RankJavaObservation,
			jd.KeysConsidered, HandshakeLiveMappingPath, strings.Join(counterexamples, ", "))
	}
	return jd, nil
}
