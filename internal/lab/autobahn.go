package lab

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

var autobahnCasePattern = regexp.MustCompile(`^([1-7]|9|10|12|13)\.[0-9]+(?:\.[0-9]+)*$`)
var autobahnPythonTokenPattern = regexp.MustCompile(`\bCase([0-9]+(?:_[0-9X]+)+)\b`)

var selectedAutobahnFamilies = []string{"1.*", "2.*", "3.*", "4.*", "5.*", "6.*", "7.*", "10.*"}
var excludedAutobahnFamilies = []string{"9.*", "12.*", "13.*"}

func AutobahnFamilies() (selected, excluded []string) {
	return append([]string(nil), selectedAutobahnFamilies...), append([]string(nil), excludedAutobahnFamilies...)
}

type AutobahnRegistry struct {
	SchemaVersion        string   `json:"schema_version"`
	SourceDigest         string   `json:"source_digest"`
	CaseIDs              []string `json:"case_ids"`
	UnresolvedGenerators []string `json:"unresolved_generators"`
	sourceValidated      bool
}

type RegistryExpansion struct {
	SourceDigest string   `json:"source_digest"`
	Source       []byte   `json:"-"`
	CaseIDs      []string `json:"case_ids"`
}

// ParsePinnedAutobahnRegistry derives identities from the accepted registry
// source text without importing or executing it. Dynamic Case*_X families
// require exact, digest-bound static expansion inputs.
func ParsePinnedAutobahnRegistry(raw []byte, sourceDigest string, expansions map[string]RegistryExpansion) (AutobahnRegistry, error) {
	if len(raw) == 0 || len(raw) > maxManifestBytes || !utf8.Valid(raw) || strings.ContainsRune(string(raw), 0) || !isDigest(sourceDigest) || intake.DigestBytes(raw) != sourceDigest {
		return AutobahnRegistry{}, finding("INVALID_AUTOBAHN_REGISTRY_SOURCE", "$", "registry source must be bounded UTF-8 bytes matching its accepted digest")
	}
	tokens := autobahnPythonTokenPattern.FindAllStringSubmatch(string(raw), -1)
	if len(tokens) == 0 {
		return AutobahnRegistry{}, finding("INVALID_AUTOBAHN_REGISTRY_SOURCE", "$", "registry source contains no statically recognizable Case identifiers")
	}
	caseSet := make(map[string]struct{})
	usedExpansion := make(map[string]struct{})
	unresolved := make([]string, 0)
	for _, token := range tokens {
		name := "Case" + token[1]
		if strings.Contains(token[1], "X") {
			expansion, exists := expansions[name]
			if !exists {
				unresolved = append(unresolved, name)
				continue
			}
			if !isDigest(expansion.SourceDigest) || len(expansion.Source) == 0 || len(expansion.Source) > maxManifestBytes || !utf8.Valid(expansion.Source) || intake.DigestBytes(expansion.Source) != expansion.SourceDigest || len(expansion.CaseIDs) == 0 {
				return AutobahnRegistry{}, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions."+name, "expansion must provide bounded source bytes matching its digest and exact case identities")
			}
			prefix := strings.SplitN(token[1], "_", 2)[0] + "."
			extracted := make(map[string]struct{})
			for _, expansionToken := range autobahnPythonTokenPattern.FindAllStringSubmatch(string(expansion.Source), -1) {
				if strings.Contains(expansionToken[1], "X") {
					continue
				}
				id := strings.ReplaceAll(expansionToken[1], "_", ".")
				if autobahnCasePattern.MatchString(id) && strings.HasPrefix(id, prefix) {
					extracted[id] = struct{}{}
				}
			}
			if len(extracted) != len(expansion.CaseIDs) {
				return AutobahnRegistry{}, finding("INVALID_AUTOBAHN_EXPANSION", "$.expansions."+name, "declared expansion does not equal exact identities statically visible in its bound source")
			}
			for index, id := range expansion.CaseIDs {
				if !autobahnCasePattern.MatchString(id) || !strings.HasPrefix(id, prefix) {
					return AutobahnRegistry{}, finding("INVALID_AUTOBAHN_EXPANSION", fmt.Sprintf("$.expansions.%s.case_ids[%d]", name, index), "expanded ID is not exact or leaves its generator family")
				}
				if _, visible := extracted[id]; !visible {
					return AutobahnRegistry{}, finding("INVALID_AUTOBAHN_EXPANSION", fmt.Sprintf("$.expansions.%s.case_ids[%d]", name, index), "expanded ID is not statically visible in its digest-bound source")
				}
				caseSet[id] = struct{}{}
			}
			usedExpansion[name] = struct{}{}
			continue
		}
		id := strings.ReplaceAll(token[1], "_", ".")
		if !autobahnCasePattern.MatchString(id) {
			return AutobahnRegistry{}, finding("UNCLASSIFIED_AUTOBAHN_FAMILY", "$.registry_source", "static registry contains case outside the frozen selected/excluded families: "+id)
		}
		caseSet[id] = struct{}{}
	}
	for name := range expansions {
		if _, used := usedExpansion[name]; !used {
			return AutobahnRegistry{}, finding("UNKNOWN_AUTOBAHN_EXPANSION", "$.expansions."+name, "expansion does not bind a generator visible in pinned registry source")
		}
	}
	if len(unresolved) != 0 {
		sort.Strings(unresolved)
		unresolved = compactStrings(unresolved)
		return AutobahnRegistry{}, finding("UNRESOLVED_AUTOBAHN_GENERATOR", "$.unresolved_generators", "exact expansions required for "+strings.Join(unresolved, ","))
	}
	caseIDs := make([]string, 0, len(caseSet))
	for id := range caseSet {
		caseIDs = append(caseIDs, id)
	}
	sort.Strings(caseIDs)
	registry := AutobahnRegistry{SchemaVersion: "1.0.0", SourceDigest: sourceDigest, CaseIDs: caseIDs, UnresolvedGenerators: []string{}, sourceValidated: true}
	return registry, registry.Validate()
}

func (r AutobahnRegistry) Validate() error {
	if r.SchemaVersion != "1.0.0" || !isDigest(r.SourceDigest) || len(r.CaseIDs) == 0 || len(r.CaseIDs) > 100000 {
		return finding("INVALID_AUTOBAHN_REGISTRY", "$", "registry schema, source digest, or case count is invalid")
	}
	if len(r.UnresolvedGenerators) != 0 {
		return finding("UNRESOLVED_AUTOBAHN_GENERATOR", "$.unresolved_generators", "generated Case*_X families must be statically expanded to exact case identities")
	}
	seen := make(map[string]struct{}, len(r.CaseIDs))
	for index, id := range r.CaseIDs {
		if !autobahnCasePattern.MatchString(id) || strings.ContainsAny(id, "*Xx") {
			return finding("INVALID_AUTOBAHN_CASE_ID", fmt.Sprintf("$.case_ids[%d]", index), "case identity must be fully expanded dotted numerics in an allowed family")
		}
		if _, duplicate := seen[id]; duplicate {
			return finding("DUPLICATE_ENTRY", fmt.Sprintf("$.case_ids[%d]", index), "Autobahn case occurs more than once")
		}
		seen[id] = struct{}{}
	}
	return nil
}

type AutobahnSelection struct {
	SchemaVersion    string   `json:"schema_version"`
	RegistryDigest   string   `json:"registry_digest"`
	SelectedFamilies []string `json:"selected_families"`
	ExcludedFamilies []string `json:"excluded_families"`
	SelectedCaseIDs  []string `json:"selected_case_ids"`
	ExcludedCaseIDs  []string `json:"excluded_case_ids"`
}

func SelectAutobahnRegistry(registry AutobahnRegistry) (AutobahnSelection, error) {
	if err := registry.Validate(); err != nil {
		return AutobahnSelection{}, err
	}
	if !registry.sourceValidated {
		return AutobahnSelection{}, finding("AUTOBAHN_REGISTRY_PROVENANCE_REQUIRED", "$", "registry identities must come from static parsing of pinned source bytes")
	}
	bytes, err := intake.CanonicalJSON(registry)
	if err != nil {
		return AutobahnSelection{}, err
	}
	selection := AutobahnSelection{
		SchemaVersion: "1.0.0", RegistryDigest: intake.DigestBytes(bytes),
		SelectedFamilies: append([]string(nil), selectedAutobahnFamilies...),
		ExcludedFamilies: append([]string(nil), excludedAutobahnFamilies...),
	}
	selectedSeen := make(map[string]bool)
	excludedSeen := make(map[string]bool)
	for _, id := range registry.CaseIDs {
		family := strings.SplitN(id, ".", 2)[0] + ".*"
		if contains(selectedAutobahnFamilies, family) {
			selection.SelectedCaseIDs = append(selection.SelectedCaseIDs, id)
			selectedSeen[family] = true
		} else if contains(excludedAutobahnFamilies, family) {
			selection.ExcludedCaseIDs = append(selection.ExcludedCaseIDs, id)
			excludedSeen[family] = true
		} else {
			return AutobahnSelection{}, finding("UNCLASSIFIED_AUTOBAHN_FAMILY", "$.case_ids", "registry contains a family outside the frozen selected/excluded policy")
		}
	}
	for _, family := range selectedAutobahnFamilies {
		if !selectedSeen[family] {
			return AutobahnSelection{}, finding("MISSING_AUTOBAHN_FAMILY", "$.selected_families", "selected family "+family+" has no exact registry identities")
		}
	}
	for _, family := range excludedAutobahnFamilies {
		if !excludedSeen[family] {
			return AutobahnSelection{}, finding("MISSING_AUTOBAHN_EXCLUSION", "$.excluded_families", "excluded family "+family+" is not visibly represented")
		}
	}
	sort.Strings(selection.SelectedCaseIDs)
	sort.Strings(selection.ExcludedCaseIDs)
	return selection, nil
}

type AutobahnResult struct {
	CaseID string `json:"case_id"`
	Status string `json:"status"`
}

func ReconcileAutobahn(registry AutobahnRegistry, selection AutobahnSelection, mode string, results []AutobahnResult) error {
	derived, err := SelectAutobahnRegistry(registry)
	if err != nil {
		return err
	}
	left, err := intake.CanonicalJSON(selection)
	if err != nil {
		return err
	}
	right, err := intake.CanonicalJSON(derived)
	if err != nil {
		return err
	}
	if !bytes.Equal(left, right) {
		return finding("AUTOBAHN_SELECTION_DRIFT", "$", "selection does not exactly derive from the statically parsed registry")
	}
	if selection.SchemaVersion != "1.0.0" || !isDigest(selection.RegistryDigest) || !equalStrings(selection.SelectedFamilies, selectedAutobahnFamilies) || !equalStrings(selection.ExcludedFamilies, excludedAutobahnFamilies) {
		return finding("AUTOBAHN_SELECTION_DRIFT", "$", "selection policy differs from the frozen families")
	}
	if mode != "client" && mode != "server" {
		return finding("INVALID_AUTOBAHN_MODE", "$.mode", "mode must be client or server")
	}
	expected, err := exactSet(selection.SelectedCaseIDs, "$.selected_case_ids", 100000)
	if err != nil {
		return err
	}
	excluded, err := exactSet(selection.ExcludedCaseIDs, "$.excluded_case_ids", 100000)
	if err != nil {
		return err
	}
	for id := range expected {
		if _, conflict := excluded[id]; conflict {
			return finding("AUTOBAHN_SELECTION_DRIFT", "$.excluded_case_ids", "case is both selected and excluded")
		}
	}
	if len(results) != len(expected) {
		return finding("AUTOBAHN_RESULT_MISMATCH", "$.results", "executed result count differs from exact selected inventory")
	}
	seen := make(map[string]struct{}, len(results))
	for index, result := range results {
		if _, exists := expected[result.CaseID]; !exists || !refPattern.MatchString(result.Status) {
			return finding("AUTOBAHN_RESULT_MISMATCH", fmt.Sprintf("$.results[%d]", index), "result is unknown, excluded, or lacks an explicit status")
		}
		if _, duplicate := seen[result.CaseID]; duplicate {
			return finding("DUPLICATE_ENTRY", fmt.Sprintf("$.results[%d].case_id", index), "case has more than one result")
		}
		seen[result.CaseID] = struct{}{}
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
