package normcollide

import (
	"fmt"
	"sort"
	"strings"
)

// CheckExpectation compares a probe's DECLARED expectation with the verdict
// the run actually produced, and — for a probe expected to be REFUTED — adds
// the two checks that stop a refutation being earned by accident.
//
// Decide already answers "did the comparator move?". That question alone is
// not enough to decide a candidate, because there are two ways for a pair to
// move that say nothing about the candidate:
//
//  1. it moved on a path unrelated to the distinction under test;
//  2. it moved because one input was REJECTED, so the answers differ by
//     outcome rather than by the projection carrying the distinction.
//
// Both would produce Verdict == REFUTED from Decide alone. Neither is a
// decision. This function is where they are refused.
//
// Nothing here relaxes anything: a probe expected to be CONFIRMED is held to
// exactly the bar Decide already set, and this adds the requirement that it
// declare no required paths, because a probe that both erases a distinction
// and moves on it is incoherent.
func CheckExpectation(probe Probe, result Result) error {
	if probe.Expect == "" {
		return fmt.Errorf("probe %s declares no expected verdict; a catalog entry that does "+
			"not say what it claims cannot be falsified by running it", probe.ID)
	}
	if probe.Expect != Confirmed && probe.Expect != Refuted {
		return fmt.Errorf("probe %s declares expected verdict %q, which is neither %s nor %s",
			probe.ID, probe.Expect, Confirmed, Refuted)
	}
	if result.Verdict != probe.Expect {
		if probe.Expect == Refuted {
			return fmt.Errorf("probe %s expected %s but the run says %s: its pair moved NOTHING, "+
				"so the projection does NOT represent this distinction after all. That is an "+
				"ADDITIONAL COLLISION, not a broken check — reclassify it into Probes() with the "+
				"count it earns, do not relax this",
				probe.ID, Refuted, result.Verdict)
		}
		return fmt.Errorf("probe %s expected %s but the run says %s: its collision pair moved %v. "+
			"The surface represents a distinction this catalog says it erases — reclassify the "+
			"probe, do not weaken it", probe.ID, Confirmed, result.Verdict, result.CollisionPaths)
	}
	if probe.Expect == Confirmed {
		if len(probe.RequiredPaths) != 0 {
			return fmt.Errorf("probe %s is expected %s yet declares required_diff_paths %v; a "+
				"probe cannot both erase a distinction and be required to move on it",
				probe.ID, Confirmed, probe.RequiredPaths)
		}
		return nil
	}

	// From here on the probe claims REFUTED, and has to earn it.
	if len(probe.RequiredPaths) == 0 {
		return fmt.Errorf("probe %s claims %s but names no required_diff_paths; a refutation "+
			"that accepts ANY movement is not a decision about its own distinction",
			probe.ID, Refuted)
	}
	moved := map[string]bool{}
	for _, path := range result.CollisionPaths {
		moved[path] = true
	}
	var missing []string
	for _, required := range probe.RequiredPaths {
		if !moved[required] {
			missing = append(missing, required)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return fmt.Errorf("probe %s claims %s, and the comparator did move (%v) — but NOT on %v, "+
			"the path(s) this candidate is about. A refutation earned by an unrelated difference "+
			"decides nothing", probe.ID, Refuted, result.CollisionPaths, missing)
	}
	for label, keys := range map[string][]string{"A": result.KeysA, "B": result.KeysB} {
		for _, key := range keys {
			if key == "error" {
				return fmt.Errorf("probe %s claims %s, but collision answer %s is an ERROR row "+
					"(top-level keys %v). The pair then differs by OUTCOME, not by the projection "+
					"carrying the distinction — an input that was REJECTED does not show the "+
					"observation represents it", probe.ID, Refuted, label, keys)
			}
		}
	}
	return nil
}

// CheckEveryProbeDeclaresAnExpectation is the catalog-shape guard: both lists
// must declare what they claim, and the two lists must not overlap. A probe
// present in both would be counted twice by Build.
func CheckEveryProbeDeclaresAnExpectation(collisions, refutations []Probe) error {
	seen := map[string]string{}
	for _, group := range []struct {
		name   string
		probes []Probe
		expect Verdict
	}{
		{"Probes", collisions, Confirmed},
		{"Refutations", refutations, Refuted},
	} {
		for _, probe := range group.probes {
			if probe.Expect != group.expect {
				return fmt.Errorf("%s() member %s declares expected verdict %q; every member of "+
					"that list must declare %s", group.name, probe.ID, probe.Expect, group.expect)
			}
			if other, duplicate := seen[probe.ID]; duplicate {
				return fmt.Errorf("probe id %s appears in both %s() and %s(); it would be "+
					"counted twice", probe.ID, other, group.name)
			}
			seen[probe.ID] = group.name
		}
	}
	return nil
}

// describePaths renders a path list for a message, stably.
func describePaths(paths []string) string {
	if len(paths) == 0 {
		return "(nothing)"
	}
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	return strings.Join(sorted, ", ")
}
