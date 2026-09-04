package autobahnsuite

// Constraining the case manifest from OUTSIDE the runs it constrains.
//
// REVIEW 01a04961 FINDING 7, narrowed. The finding is that the manifest is
// snapshot-derived: BuildManifest expands it from the very wstest reports it
// then holds to account, so the expectation is computed by the thing under
// test. A run that fabricated a case id and dropped a real one keeps the
// count at 247 and the manifest records the fabrication as though the suite
// had defined it.
//
// WHAT THE STRONGEST FIX WOULD BE, AND WHY IT IS NOT THIS ONE. The pinned
// Autobahn suite defines its own cases in Python source, and this repository
// already knows how to parse them: internal/lab.ParsePinnedAutobahnRegistryArchive
// derives the exact case identities from the archive whose digest is pinned
// at internal/lab.PinnedAutobahnSourceArchiveDigest. That is a source truly
// outside the run. It needs the archive bytes, and in this environment the
// GitHub archive URL answers 403 through the agent proxy (recorded in
// .claude/CLOUD-ENVIRONMENT.md), so the archive is not materialised here and
// the registry cannot be parsed. Naming that is part of the finding's
// remediation, not a substitute for it: the residual gap and the exact action
// that closes it are recorded in the round record.
//
// WHAT THIS FILE DOES INSTEAD. It binds the manifest to every independent
// source that IS in the tree, so the set of things a snapshot can invent
// shrinks to "a case id of the right shape, in a selected family, in a
// manifest of exactly the right size, matching the suite configuration the
// runs were launched with". Each constraint below is sourced from something
// no wstest report can influence:
//
//   - THE SUITE'S OWN ID GRAMMAR and the frozen family policy, from
//     internal/lab, which derives them by static parsing of pinned source
//     rather than from any run.
//   - THE PINNED SELECTED-CASE COUNT, likewise from internal/lab, and
//     deliberately compared against this package's own constant so a drift
//     between the two independently sourced numbers is a failure rather
//     than a silent agreement.
//   - THE COMMITTED SUITE CONFIGURATION the runs were actually launched
//     with. A config that selects different families than the policy means
//     the reports describe a different suite selection than the manifest
//     claims, and nothing compared the two before this.
//
// None of these can tell a real 7.9.6 from an invented 7.9.7. Only the
// registry can, and the round record says so plainly.

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// caseIDGrammar is the Autobahn case-identity shape, mirroring the pattern
// internal/lab applies when it parses the pinned suite source. A manifest
// entry that is not a case identity at all cannot be one the suite defines.
var caseIDGrammar = regexp.MustCompile(`^([1-7]|9|10|12|13)\.[0-9]+(?:\.[0-9]+)*$`)

// SuiteConfig is the subset of a wstest configuration this package reads:
// which families the run was told to select and exclude.
type SuiteConfig struct {
	Path     string   `json:"path"`
	Cases    []string `json:"cases"`
	Excluded []string `json:"exclude-cases"`
}

// ReadSuiteConfig loads one committed wstest configuration.
func ReadSuiteConfig(path string) (*SuiteConfig, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied evidence path
	if err != nil {
		return nil, fmt.Errorf("read suite config %s: %w", path, err)
	}
	var config SuiteConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("parse suite config %s: %w", path, err)
	}
	config.Path = path
	return &config, nil
}

// VerifyManifestIndependence holds the manifest to the sources listed in this
// file's header. It returns one problem per violation; an empty slice means
// every independent constraint available in this tree is satisfied.
//
// `configs` are the committed wstest configurations the runs were launched
// with. Passing none is itself reported: a manifest checked against no
// configuration has one fewer binding than this tree can provide, and
// silently accepting that is how a check stops applying.
func VerifyManifestIndependence(manifest *Manifest, configs []*SuiteConfig) []string {
	var problems []string
	if manifest == nil {
		return []string{"no manifest"}
	}
	selectedFamilies, excludedFamilies := lab.AutobahnFamilies()
	selected := map[string]bool{}
	for _, family := range selectedFamilies {
		selected[family] = true
	}
	excluded := map[string]bool{}
	for _, family := range excludedFamilies {
		excluded[family] = true
	}

	// 1. The count, from a constant this package did not author.
	if lab.AutobahnSelectedCaseCount != SelectedCaseCount {
		problems = append(problems, fmt.Sprintf(
			"the two independently sourced selected-case counts disagree: internal/lab says %d, "+
				"internal/autobahnsuite says %d", lab.AutobahnSelectedCaseCount, SelectedCaseCount))
	}
	if len(manifest.Cases) != lab.AutobahnSelectedCaseCount {
		problems = append(problems, fmt.Sprintf(
			"the manifest holds %d cases but the pinned suite selects %d",
			len(manifest.Cases), lab.AutobahnSelectedCaseCount))
	}

	// 2. Every identity is shaped like a case identity and sits in a
	//    SELECTED family. A duplicate is a set that is smaller than it looks.
	seen := map[string]bool{}
	for _, entry := range manifest.Cases {
		if !caseIDGrammar.MatchString(entry.CaseID) {
			problems = append(problems, fmt.Sprintf(
				"manifest case %q is not shaped like an Autobahn case identity", entry.CaseID))
			continue
		}
		if seen[entry.CaseID] {
			problems = append(problems, fmt.Sprintf(
				"manifest case %s appears more than once", entry.CaseID))
		}
		seen[entry.CaseID] = true
		family := strings.SplitN(entry.CaseID, ".", 2)[0] + ".*"
		switch {
		case excluded[family]:
			problems = append(problems, fmt.Sprintf(
				"manifest case %s is in family %s, which the frozen policy EXCLUDES",
				entry.CaseID, family))
		case !selected[family]:
			problems = append(problems, fmt.Sprintf(
				"manifest case %s is in family %s, which the frozen policy neither selects nor "+
					"excludes", entry.CaseID, family))
		}
	}

	// 3. Every selected family is actually represented. A policy that names
	//    eight families and a manifest that covers six is a selection the
	//    runs narrowed on their own.
	present := map[string]bool{}
	for _, entry := range manifest.Cases {
		present[strings.SplitN(entry.CaseID, ".", 2)[0]+".*"] = true
	}
	for _, family := range selectedFamilies {
		if !present[family] {
			problems = append(problems, fmt.Sprintf(
				"the frozen policy selects family %s and the manifest holds no case from it", family))
		}
	}

	// 4. The manifest's own declared families and exclusions must be the
	//    frozen policy's, not a set it chose.
	if !sameSet(manifest.SelectedFamilies, selectedFamilies) {
		problems = append(problems, fmt.Sprintf(
			"the manifest declares selected families %v but the frozen policy is %v",
			manifest.SelectedFamilies, selectedFamilies))
	}
	declaredExclusions := make([]string, 0, len(manifest.NonselectedCategories))
	for _, category := range manifest.NonselectedCategories {
		declaredExclusions = append(declaredExclusions, category.Family)
	}
	if !sameSet(declaredExclusions, excludedFamilies) {
		problems = append(problems, fmt.Sprintf(
			"the manifest declares exclusions %v but the frozen policy excludes %v",
			declaredExclusions, excludedFamilies))
	}

	// 5. The configurations the runs were launched with must express the
	//    same selection. Without this the reports could describe a different
	//    suite selection than the manifest claims to hold.
	if len(configs) == 0 {
		problems = append(problems,
			"no suite configuration was supplied, so the manifest is not bound to the selection "+
				"the runs were actually launched with")
	}
	for _, config := range configs {
		if config == nil {
			continue
		}
		if !sameSet(config.Cases, selectedFamilies) {
			problems = append(problems, fmt.Sprintf(
				"suite config %s selects %v but the frozen policy selects %v",
				config.Path, config.Cases, selectedFamilies))
		}
		if !sameSet(config.Excluded, excludedFamilies) {
			problems = append(problems, fmt.Sprintf(
				"suite config %s excludes %v but the frozen policy excludes %v",
				config.Path, config.Excluded, excludedFamilies))
		}
	}
	sort.Strings(problems)
	return problems
}

func sameSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := map[string]int{}
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}
