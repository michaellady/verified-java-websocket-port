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
//
// IT ALSO COMPUTES IT OVER THE KEYS THE CORPUS ACTUALLY REACHES, and the
// disclosure fires on THAT. The whole-table analysis is deliberately the wider
// of the two, so that a corpus which grew a case could not create degeneracy
// where none was; but the same width was a way past this gate. Changing ONE
// mapping row that no committed case reaches -- server_response/HS_OBS_FOLD,
// rfc_verdict and java_observable both `reject`, set to `accept` -- made the
// whole-table analysis report "Disagreement is POSSIBLE ... Agreement measured
// here is therefore a measurement" for BOTH pairs, deleted both
// ORACLE-RANK-JOIN-DEGENERATE findings from the register, and left the
// surviving BLOCKING finding claiming 49 co-votes "that could have come out
// either way" when every one of the 49 was still forced. The census line was
// byte-identical, oraclerankctl --check exited 0, and (with the source table
// edited and the document re-rendered) deltaledger's live-mapping source
// binding passed too. A counterexample nothing reaches cannot turn an agreement
// this census measured into a measurement.
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

	// DegenerateOverJoinedKeys is the same property computed over ONLY the
	// keys this census's own corpus joins on. It is what the disclosure
	// fires on, because it is the question a reader of the co-vote count is
	// actually asking: could the propositions THIS census counted have come
	// out differently?
	DegenerateOverJoinedKeys bool `json:"disagreement_structurally_impossible_over_the_keys_this_census_joins_on"`
	// JoinedKeysConsidered is how many lookup keys the corpus reaches.
	JoinedKeysConsidered int `json:"lookup_keys_the_census_joins_on"`
	// ReachableVerdictsOverJoinedKeys is ReachableVerdicts restricted to
	// those keys.
	ReachableVerdictsOverJoinedKeys map[string][]string `json:"lower_rank_verdicts_reachable_over_the_keys_this_census_joins_on"`

	Statement string `json:"statement"`
}

// handshakeJoinDegeneracies computes the property for BOTH rank pairs the
// handshake family joins on that key.
//
// The key is derived from rank three's verdict, and TWO other ranks are read at
// it: rank one from rfc_verdict and rank four from java_observable. Both pairs
// are therefore suspect, and measuring only the one this branch set out to look
// at would leave the other standing as a clean number.
//
// joined is the set of mapping keys the committed corpus actually resolves to,
// supplied by the caller rather than recomputed here so that the analysis and
// the propositions cannot come from two different readings of the corpus.
func handshakeJoinDegeneracies(mapping map[[2]string]handshakeMappingEntry, joined map[[2]string]bool) ([]JoinDegeneracy, error) {
	// Rank one is HIGHER than rank three; rank three is higher than rank
	// four. In both cases the key comes from rank three, so in the first
	// pair it is the LOWER rank's verdict that selects the higher rank's
	// answer. Degeneracy does not care which side the key comes from: what
	// it establishes is that the two verdicts cannot differ.
	one, err := joinDegeneracy(mapping, joined, RankRFC6455, RankNeutralExpectation,
		func(e handshakeMappingEntry) string { return e.RFCVerdict },
		"the mapping's rfc_verdict")
	if err != nil {
		return nil, err
	}
	four, err := joinDegeneracy(mapping, joined, RankNeutralExpectation, RankJavaObservation,
		func(e handshakeMappingEntry) string { return e.JavaObservable },
		"the mapping's java_observable")
	if err != nil {
		return nil, err
	}
	return []JoinDegeneracy{one, four}, nil
}

// keyClass is the rank-three verdict a mapping key is reachable from. The
// reject codes are exactly the mapping keys that are not the two self-named
// verdicts, so the reachable-key set is derived from the committed table rather
// than listed here.
func keyClass(key [2]string) string {
	switch key[1] {
	case "accept", "incomplete":
		return key[1]
	default:
		return "reject"
	}
}

// joinReach is one pass of the analysis over a chosen set of keys.
type joinReach struct {
	verdicts       map[string][]string
	considered     int
	abstaining     int
	degenerate     bool
	counterexample []string
}

func reachOver(mapping map[[2]string]handshakeMappingEntry, keys [][2]string, read func(handshakeMappingEntry) string) joinReach {
	byClass := map[string][][2]string{}
	for _, key := range keys {
		byClass[keyClass(key)] = append(byClass[keyClass(key)], key)
	}
	r := joinReach{verdicts: map[string][]string{}, degenerate: true}
	for _, v := range []string{"accept", "reject", "incomplete"} {
		ks := byClass[v]
		sort.Slice(ks, func(i, j int) bool {
			if ks[i][0] != ks[j][0] {
				return ks[i][0] < ks[j][0]
			}
			return ks[i][1] < ks[j][1]
		})
		seen := map[string]bool{}
		var got []string
		for _, k := range ks {
			r.considered++
			obs := read(mapping[k])
			if obs == "conditional" {
				r.abstaining++
				continue
			}
			if !seen[obs] {
				seen[obs] = true
				got = append(got, obs)
			}
		}
		sort.Strings(got)
		r.verdicts[v] = got
	}
	for v, got := range r.verdicts {
		for _, o := range got {
			if o != v {
				r.degenerate = false
				r.counterexample = append(r.counterexample, fmt.Sprintf("%s->%s", v, o))
			}
		}
	}
	sort.Strings(r.counterexample)
	return r
}

// joinDegeneracy computes the property over the whole committed mapping AND
// over the keys the corpus joins on. The whole-table pass is the one that
// answers "could a corpus that grew a case ever disagree here"; the joined-key
// pass is the one that answers "could the propositions this census counted have
// disagreed", and only the second can be trusted to justify calling an
// observed agreement a measurement.
//
// read selects the field the joined rank's verdict is taken from; the OTHER
// rank of the pair is always the one whose verdict supplies the key.
func joinDegeneracy(mapping map[[2]string]handshakeMappingEntry, joined map[[2]string]bool, higher, lower Rank, read func(handshakeMappingEntry) string, field string) (JoinDegeneracy, error) {
	joinedRank := lower
	if lower == RankNeutralExpectation {
		joinedRank = higher
	}
	jd := JoinDegeneracy{
		Family:     FamilyHandshake,
		Higher:     higher,
		HigherName: higher.String(),
		Lower:      lower,
		LowerName:  lower.String(),
		KeyDerivation: fmt.Sprintf(
			"oraclerank.handshakeOutcomeKey(c) computes the mapping key from the corpus case's own expected.verdict -- %s's verdict: `accept` and `incomplete` map to themselves, and `reject` maps to the case's reject_code. %s's opinion is then read from %s at that key. The key is therefore a function of %s's verdict.",
			RankNeutralExpectation, joinedRank, field, RankNeutralExpectation),
	}

	var allKeys, joinedKeys [][2]string
	classesPresent := map[string]bool{}
	for key := range mapping {
		allKeys = append(allKeys, key)
		classesPresent[keyClass(key)] = true
		if joined[key] {
			joinedKeys = append(joinedKeys, key)
		}
	}
	for _, v := range []string{"accept", "reject", "incomplete"} {
		if !classesPresent[v] {
			return JoinDegeneracy{}, fmt.Errorf(
				"%s: no mapping key is reachable from the %s verdict %q; the join analysis would be vacuous",
				HandshakeLiveMappingPath, RankNeutralExpectation, v)
		}
	}
	if len(joinedKeys) == 0 {
		return JoinDegeneracy{}, fmt.Errorf(
			"%s: the committed corpus joins on none of the %d mapping keys; the join analysis would describe a table this census never reads",
			HandshakeLiveMappingPath, len(allKeys))
	}

	whole := reachOver(mapping, allKeys, read)
	reached := reachOver(mapping, joinedKeys, read)

	jd.ReachableVerdicts = whole.verdicts
	jd.KeysConsidered = whole.considered
	jd.KeysAbstaining = whole.abstaining
	jd.Degenerate = whole.degenerate
	jd.ReachableVerdictsOverJoinedKeys = reached.verdicts
	jd.JoinedKeysConsidered = reached.considered
	jd.DegenerateOverJoinedKeys = reached.degenerate

	switch {
	case whole.degenerate:
		jd.Statement = fmt.Sprintf(
			"DISAGREEMENT IS STRUCTURALLY IMPOSSIBLE in %s between %s and %s. Over all %d keys of %s, every key reachable from a %s verdict v records %s either v or `conditional`, and %s abstains on `conditional` (%d of the %d keys). %s's non-abstaining verdict is therefore always exactly %s's, whatever the corpus holds. The %d of those keys the committed corpus actually joins on carry the same property. The co-votes the independence probe reports for this pair in this family are a property of the census's own join, not a measurement of two oracles.",
			FamilyHandshake, higher, lower,
			jd.KeysConsidered, HandshakeLiveMappingPath, RankNeutralExpectation, field, joinedRank,
			jd.KeysAbstaining, jd.KeysConsidered, joinedRank, RankNeutralExpectation, jd.JoinedKeysConsidered)
	case reached.degenerate:
		jd.Statement = fmt.Sprintf(
			"DISAGREEMENT IS STRUCTURALLY IMPOSSIBLE OVER THE KEYS THIS CENSUS JOINS ON in %s between %s and %s. The whole %d-key table of %s does carry a counterexample (%s), but NO committed case reaches the key that carries it: over the %d keys the corpus does join on, every key reachable from a %s verdict v records %s either v or `conditional`. %s's non-abstaining verdict is therefore exactly %s's on every proposition this census counted, and the co-votes the independence probe reports for this pair in this family remain a property of the join. A counterexample no case reaches does not make an observed agreement a measurement.",
			FamilyHandshake, higher, lower,
			jd.KeysConsidered, HandshakeLiveMappingPath, strings.Join(whole.counterexample, ", "),
			jd.JoinedKeysConsidered, RankNeutralExpectation, field, joinedRank, RankNeutralExpectation)
	default:
		jd.Statement = fmt.Sprintf(
			"Disagreement is POSSIBLE in %s between %s and %s: over the %d keys of %s the corpus joins on, the join can carry a %s verdict to a different %s verdict (%s). Agreement measured here is therefore a measurement.",
			FamilyHandshake, higher, lower,
			jd.JoinedKeysConsidered, HandshakeLiveMappingPath, RankNeutralExpectation, joinedRank,
			strings.Join(reached.counterexample, ", "))
	}
	return jd, nil
}
