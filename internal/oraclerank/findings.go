package oraclerank

import (
	"fmt"
	"sort"
	"strings"
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
				"%s is EMPIRICALLY INDISTINGUISHABLE from %s on this evidence: %d shared propositions where the two read different bytes, %d disagreements. AC2 gives %s authority over %s, and nothing here shows it is a separate oracle rather than a relabelling.%s",
				p.Higher, p.Lower, p.CoVotes, p.Disagreements, p.Higher, p.Lower,
				hollowCoVoteQualifier(p, families)),
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

	// F-6a: scored pairs whose co-votes carry ONE answer. The probe counts
	// propositions; a family's projection onto a three-value verdict space
	// can make N propositions carry a single distinguishable answer, and a
	// reader who takes N for a body of evidence is reading a collision
	// rather than a measurement. This is a different fault from a
	// relabelling and it is disclosed separately so the two are not confused.
	for _, p := range reg.IndependenceProbe {
		for _, fp := range p.ByFamily {
			if fp.Verdict != ProbeNotDistinguished && fp.Verdict != ProbeDistinguished {
				continue
			}
			if fp.CoVotes < 2 || fp.Resolution.DistinctVerdictPairs != 1 {
				continue
			}
			only := fp.Resolution.Pairs[0]
			out = append(out, Finding{
				ID:       fmt.Sprintf("ORACLE-RANK-COVOTE-COLLISION-%d-%d-%s", uint8(p.Higher), uint8(p.Lower), fp.Family),
				Severity: "DISCLOSURE",
				Statement: fmt.Sprintf(
					"The %d co-votes %s and %s share in %s carry ONE distinct answer: %s said %q and %s said %q on every one of them. Those %d propositions are %d question asked %d times under this family's %d-value verdict space, so the probe's %s verdict there rests on a collision of the projection rather than on %d independent measurements. internal/normcollide measures the same collapse one layer down.",
					fp.CoVotes, p.Higher, p.Lower, fp.Family, p.Higher, only.Higher, p.Lower, only.Lower,
					fp.CoVotes, 1, fp.CoVotes, fp.Resolution.VerdictSpace, fp.Verdict, fp.CoVotes),
				Basis: []string{
					fmt.Sprintf("independence_probe[%s vs %s].by_family[%s].co_votes = %d", p.Higher, p.Lower, fp.Family, fp.CoVotes),
					fmt.Sprintf("independence_probe[%s vs %s].by_family[%s].co_vote_resolution.distinct_verdict_pairs = %d", p.Higher, p.Lower, fp.Family, fp.Resolution.DistinctVerdictPairs),
					fmt.Sprintf("independence_probe[%s vs %s].by_family[%s].co_vote_resolution.largest_class = %d", p.Higher, p.Lower, fp.Family, fp.Resolution.LargestClass),
				},
				OwnerActionRequired: fmt.Sprintf(
					"put %s and %s in front of a question in %s whose answer varies, or read the pair's co-vote count as %d rather than %d.",
					p.Higher, p.Lower, fp.Family, 1, fp.CoVotes),
			})
		}
	}

	// F-6: rank pairs the census JOINS on a key derived from the higher
	// rank's own verdict. The independence probe's group test does not catch
	// these: the two ranks are read from different documents, so the probe
	// scores the pair, but the lookup makes disagreement impossible. Every
	// co-vote such a pair contributes is a property of the join.
	for _, f := range families {
		for _, jd := range f.JoinDegeneracy {
			// Fires on the keys the census JOINS ON, not on the whole
			// lookup table: a counterexample at a key no committed case
			// reaches cannot make the co-votes this census counted into
			// a measurement, and before this line one such row deleted
			// both of these findings with every printed number intact.
			if !jd.DegenerateOverJoinedKeys {
				continue
			}
			cov, dis := familyCoVotes(reg, jd)
			out = append(out, Finding{
				ID:       fmt.Sprintf("ORACLE-RANK-JOIN-DEGENERATE-%d-%d", uint8(jd.Higher), uint8(jd.Lower)),
				Severity: "DISCLOSURE",
				Statement: fmt.Sprintf(
					"%s The independence probe scores this pair in this family because the two ranks are read from different documents, and it reports %d co-votes and %d disagreements there. Those %d co-votes carry no information about whether %s is a separate oracle from %s: %d was the only number the join could produce.",
					jd.Statement, cov, dis, cov, jd.Higher, jd.Lower, dis),
				Basis: []string{
					fmt.Sprintf("families[%s].join_degeneracy[0].disagreement_structurally_impossible_over_the_keys_this_census_joins_on = %v over %d joined keys (whole %d-key table: %v)", jd.Family, jd.DegenerateOverJoinedKeys, jd.JoinedKeysConsidered, jd.KeysConsidered, jd.Degenerate),
					fmt.Sprintf("families[%s].join_degeneracy[0].lower_rank_verdicts_reachable_from_each_higher_verdict = %v", jd.Family, jd.ReachableVerdicts),
					fmt.Sprintf("independence_probe[%s vs %s].by_family[%s] = co_votes %d, disagreements %d", jd.Higher, jd.Lower, jd.Family, cov, dis),
				},
				OwnerActionRequired: fmt.Sprintf(
					"read %s's rank-four opinions from a per-case observation of the pinned Java process rather than from a table keyed by rank three's own verdict, or state in this family's rank_sources that the pair is not comparable here.",
					jd.Family),
			})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// familyCoVotes reads the probe's own numbers for one pair inside one family,
// so the finding restates the register rather than recounting the evidence.
func familyCoVotes(reg Register, jd JoinDegeneracy) (coVotes, disagreements int) {
	for _, p := range reg.IndependenceProbe {
		if p.Higher != jd.Higher || p.Lower != jd.Lower {
			continue
		}
		for _, fp := range p.ByFamily {
			if fp.Family == jd.Family {
				return fp.CoVotes, fp.Disagreements
			}
		}
	}
	return 0, 0
}

// hollowCoVoteQualifier appends, to an indistinguishability finding, how many
// of the pair's co-votes could not have been a disagreement in the first place.
//
// It does NOT change when the finding fires or its severity. It exists because
// "N shared propositions, 0 disagreements" reads as a large body of agreement,
// and a reader must not be able to take a number for evidence when the census's
// own join forbade disagreement (join_degeneracy) or the family's projection
// collapsed the co-votes onto one answer (co_vote_resolution). Both figures are
// computed elsewhere in this document; this sentence points at them.
func hollowCoVoteQualifier(p PairProbe, families []Family) string {
	degenerate := map[string]bool{}
	for _, f := range families {
		for _, jd := range f.JoinDegeneracy {
			if jd.DegenerateOverJoinedKeys && jd.Higher == p.Higher && jd.Lower == p.Lower {
				degenerate[jd.Family] = true
			}
		}
	}

	forced, single, informative := 0, 0, 0
	var reasons []string
	for _, fp := range p.ByFamily {
		if fp.Verdict != ProbeNotDistinguished && fp.Verdict != ProbeDistinguished {
			continue
		}
		switch {
		case degenerate[fp.Family]:
			forced += fp.CoVotes
			reasons = append(reasons, fmt.Sprintf("%d in %s where the census's own join makes disagreement structurally impossible", fp.CoVotes, fp.Family))
		case fp.Resolution.DistinctVerdictPairs == 1 && fp.CoVotes > 1:
			single += fp.CoVotes
			reasons = append(reasons, fmt.Sprintf("%d in %s that carry one distinct answer between them", fp.CoVotes, fp.Family))
		default:
			informative += fp.CoVotes
		}
	}
	if forced+single == 0 {
		return ""
	}
	sort.Strings(reasons)
	return fmt.Sprintf(
		" READ THE %d WITH CARE: %s, leaving %d co-vote(s) that could have come out either way. See this document's join_degeneracy and co_vote_resolution.",
		p.CoVotes, strings.Join(reasons, ", and "), informative)
}

func familyBasis(p PairProbe) []string {
	var basis []string
	for _, fp := range p.ByFamily {
		basis = append(basis, fmt.Sprintf("independence_probe[%s vs %s].by_family[%s] = %s (co_votes %d, disagreements %d, groups %q vs %q)",
			p.Higher, p.Lower, fp.Family, fp.Verdict, fp.CoVotes, fp.Disagreements, fp.HigherGroup, fp.LowerGroup))
	}
	return basis
}
