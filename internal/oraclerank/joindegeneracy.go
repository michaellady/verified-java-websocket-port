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

// handshakeJoinDegeneracies computes the property for BOTH rank pairs the
// handshake family joins on that key.
//
// The key is derived from rank three's verdict, and TWO other ranks are read at
// it: rank one from rfc_verdict and rank four from java_observable. Both pairs
// are therefore suspect, and measuring only the one this branch set out to look
// at would leave the other standing as a clean number.
func handshakeJoinDegeneracies(mapping map[[2]string]handshakeMappingEntry) ([]JoinDegeneracy, error) {
	// Rank one is HIGHER than rank three; rank three is higher than rank
	// four. In both cases the key comes from rank three, so in the first
	// pair it is the LOWER rank's verdict that selects the higher rank's
	// answer. Degeneracy does not care which side the key comes from: what
	// it establishes is that the two verdicts cannot differ.
	one, err := joinDegeneracy(mapping, RankRFC6455, RankNeutralExpectation,
		func(e handshakeMappingEntry) string { return e.RFCVerdict },
		"the mapping's rfc_verdict")
	if err != nil {
		return nil, err
	}
	four, err := joinDegeneracy(mapping, RankNeutralExpectation, RankJavaObservation,
		func(e handshakeMappingEntry) string { return e.JavaObservable },
		"the mapping's java_observable")
	if err != nil {
		return nil, err
	}
	return []JoinDegeneracy{one, four}, nil
}

// joinDegeneracy computes the property over the whole committed mapping. It
// takes the mapping rather than the corpus deliberately: the question is what
// the JOIN can produce, not what these 49 cases happened to produce, so a
// corpus that grew a new case must not be able to change the answer.
//
// read selects the field the joined rank's verdict is taken from; the OTHER
// rank of the pair is always the one whose verdict supplies the key.
func joinDegeneracy(mapping map[[2]string]handshakeMappingEntry, higher, lower Rank, read func(handshakeMappingEntry) string, field string) (JoinDegeneracy, error) {
	joined := lower
	if lower == RankNeutralExpectation {
		joined = higher
	}
	jd := JoinDegeneracy{
		Family:     FamilyHandshake,
		Higher:     higher,
		HigherName: higher.String(),
		Lower:      lower,
		LowerName:  lower.String(),
		KeyDerivation: fmt.Sprintf(
			"oraclerank.handshakeOutcomeKey(c) computes the mapping key from the corpus case's own expected.verdict -- %s's verdict: `accept` and `incomplete` map to themselves, and `reject` maps to the case's reject_code. %s's opinion is then read from %s at that key. The key is therefore a function of %s's verdict.",
			RankNeutralExpectation, joined, field, RankNeutralExpectation),
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
				"%s: no mapping key is reachable from the %s verdict %q; the join analysis would be vacuous",
				HandshakeLiveMappingPath, RankNeutralExpectation, v)
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
			obs := read(mapping[k])
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
			"DISAGREEMENT IS STRUCTURALLY IMPOSSIBLE in %s between %s and %s. Over all %d keys of %s, every key reachable from a %s verdict v records %s either v or `conditional`, and %s abstains on `conditional` (%d of the %d keys). %s's non-abstaining verdict is therefore always exactly %s's, whatever the corpus holds. The co-votes the independence probe reports for this pair in this family are a property of the census's own join, not a measurement of two oracles.",
			FamilyHandshake, higher, lower,
			jd.KeysConsidered, HandshakeLiveMappingPath, RankNeutralExpectation, field, joined,
			jd.KeysAbstaining, jd.KeysConsidered, joined, RankNeutralExpectation)
	} else {
		jd.Statement = fmt.Sprintf(
			"Disagreement is POSSIBLE in %s between %s and %s: over the %d keys of %s the join can carry a %s verdict to a different %s verdict (%s). Agreement measured here is therefore a measurement.",
			FamilyHandshake, higher, lower,
			jd.KeysConsidered, HandshakeLiveMappingPath, RankNeutralExpectation, joined, strings.Join(counterexamples, ", "))
	}
	return jd, nil
}
