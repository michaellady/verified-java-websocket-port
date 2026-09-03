package oraclerank

import (
	"fmt"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/rfcneutral"
)

// NeutralRuleTablePath is the committed rule table rank three's public-tier
// opinions are derived under. It is hashed into the rank-three binding so the
// register pins the exact reading of RFC 6455 that produced its verdicts.
const NeutralRuleTablePath = "internal/rfcneutral/rules.go"

// neutralDerivationCrossCheck records what the mechanical derivation decided,
// by rule, so the register carries the shape of rank three's coverage rather
// than only its verdicts. Recomputed on every run; a drift is a document
// mismatch under --check.
func neutralDerivationCrossCheck(ds []rfcneutral.Decision) string {
	byRule := map[string]int{}
	verdicts := map[string]int{}
	for _, d := range ds {
		byRule[d.RuleID]++
		if d.Abstains {
			verdicts["abstain"]++
			continue
		}
		verdicts[d.Verdict]++
	}
	rules := make([]string, 0, len(byRule))
	for id, n := range byRule {
		rules = append(rules, fmt.Sprintf("%s on %d", id, n))
	}
	sort.Strings(rules)
	return fmt.Sprintf(
		"rank three's %d public-tier opinions are derived on this run by internal/rfcneutral from RFC 6455 sections 5 and 7: %d open, %d closed, %d abstentions. By rule: %s. The derivation reads scenario_id, role, initial_state, limits and steps and nothing else -- its scenario struct has no expected field -- and internal/rfcneutral.TestDerivationIgnoresRecordedExpectation re-derives over a corpus whose every expectation has been replaced with a contradictory one and requires identical decisions.",
		len(ds), verdicts["open"], verdicts["closed"], verdicts["abstain"], strings.Join(rules, "; "))
}

// neutralAgainstRank1CrossCheck compares the mechanical derivation with rank
// one's independently recorded reading of the same clauses, and records the
// symmetric difference by name.
//
// It does NOT assert that the two agree. Asserting agreement would make rank
// three a restatement of rank one, which is the defect this work exists to
// remove one rank lower down. The comparison is recorded so the reader can see
// where two independent readings of RFC 6455 part company, and the register's
// independence probe scores the pair on the numbers rather than on this note.
func neutralAgainstRank1CrossCheck(ds []rfcneutral.Decision, entries map[string]rfcCensusEntry) string {
	enrolled := make(map[string]struct{}, len(entries))
	for id := range entries {
		enrolled[id] = struct{}{}
	}
	closedBy := map[string]struct{}{}
	var agree, differ int
	var differing []string
	for _, d := range ds {
		if !d.Abstains && d.Verdict == rfcneutral.VerdictClosed {
			closedBy[d.ScenarioID] = struct{}{}
		}
		entry, ok := entries[d.ScenarioID]
		if !ok || d.Abstains {
			continue
		}
		want, err := strictStateVerdict(entry.RFCStrictExpectation)
		if err != nil {
			continue
		}
		if want == d.Verdict {
			agree++
			continue
		}
		differ++
		differing = append(differing, fmt.Sprintf("%s (rank one %s, rank three %s)", d.ScenarioID, want, d.Verdict))
	}

	var onlyRank1, onlyRank3 []string
	for id := range enrolled {
		if _, ok := closedBy[id]; !ok {
			onlyRank1 = append(onlyRank1, id)
		}
	}
	for id := range closedBy {
		if _, ok := enrolled[id]; !ok {
			onlyRank3 = append(onlyRank3, id)
		}
	}
	sort.Strings(onlyRank1)
	sort.Strings(onlyRank3)
	sort.Strings(differing)

	return fmt.Sprintf(
		"two independent readings of RFC 6455 compared, not reconciled: rank one's committed reading in %s enrols %d scenarios as RFC-strict failures; rank three's mechanical derivation returns `closed` on %d. Where both give a verdict they agree on %d and differ on %d%s. Enrolled by rank one but not decided `closed` by rank three: %v. Decided `closed` by rank three but not enrolled by rank one: %v.",
		RFCDivergenceCensusPath, len(enrolled), len(closedBy), agree, differ, differingSuffix(differing), listOrNone(onlyRank1), listOrNone(onlyRank3))
}

func differingSuffix(differing []string) string {
	if len(differing) == 0 {
		return ""
	}
	return " (" + strings.Join(differing, ", ") + ")"
}

func listOrNone(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}
