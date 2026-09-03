// Package autobahnsuite builds and checks the US-019 Autobahn case
// manifest, and reconciles a wstest report against it dimension by
// dimension.
//
// The manifest is the story's fixed expectation: a STATICALLY EXPANDED,
// immutable enumeration of every selected case in the pinned suite's
// 1.*, 2.*, 3.*, 4.*, 5.*, 6.*, 7.* and 10.* families, plus 9.*, 12.* and
// 13.* recorded as DECLARED NONSELECTED CATEGORIES. A nonselected category
// is never a test skip: no case from those families is enumerated, and a run
// that reports a SKIP fails reconciliation.
//
// Nothing here judges conformance by assertion. Every number is read from
// the suite's own report bytes, and the reconciliation identities are
// checked arithmetically so a report that does not add up cannot pass.
package autobahnsuite

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Manifest schema identity.
const (
	SchemaVersion  = "1.0.0"
	ManifestEntity = "AutobahnCaseManifest"

	// SelectedCaseCount is the pinned suite's selected-case count. It
	// duplicates internal/lab.AutobahnSelectedCaseCount deliberately: the
	// two are independently sourced and any drift between them is a defect
	// worth failing on.
	SelectedCaseCount = 247

	// DispositionDeclaredNonselected marks a family that the pinned
	// configuration never selects. It is a SELECTION fact, not a test
	// outcome, and must never be recorded as a skip.
	DispositionDeclaredNonselected = "DECLARED_NONSELECTED"
)

// Autobahn's own `behavior` vocabulary, as emitted in its report index.
const (
	BehaviorOK            = "OK"
	BehaviorNonStrict     = "NON-STRICT"
	BehaviorInformational = "INFORMATIONAL"
	BehaviorFailed        = "FAILED"
	BehaviorUnimplemented = "UNIMPLEMENTED"
)

// Role names which peer the suite is testing.
type Role string

// The two Autobahn modes, named by the role the TESTEE plays.
const (
	// RoleClient is fuzzingserver mode: the suite listens and the testee is
	// a WebSocket client.
	RoleClient Role = "client"
	// RoleServer is fuzzingclient mode: the suite connects out and the
	// testee is a WebSocket server.
	RoleServer Role = "server"
)

// Subject names what a run was pointed at, which fixes what "as expected"
// means for it.
type Subject string

// The discrimination subjects AC4 requires the manifest to tell apart.
const (
	// SubjectUnderTest is the real port: it must show no failures.
	SubjectUnderTest Subject = "subject-under-test"
	// SubjectJavaBaseline is the pinned Java implementation.
	SubjectJavaBaseline Subject = "java-baseline"
	// SubjectNegativeControl is the empty/stub endpoint: it must fail.
	SubjectNegativeControl Subject = "negative-control"
	// SubjectMutant is a planted protocol mutant: it must fail somewhere.
	SubjectMutant Subject = "planted-mutant"
)

// SelectedFamilies is the pinned configuration's case selection.
var SelectedFamilies = []string{"1.*", "2.*", "3.*", "4.*", "5.*", "6.*", "7.*", "10.*"}

// NonselectedCategory records a family the pinned configuration excludes.
type NonselectedCategory struct {
	Family         string `json:"family"`
	Disposition    string `json:"disposition"`
	Rationale      string `json:"rationale"`
	NeverATestSkip bool   `json:"never_a_test_skip"`
}

// NonselectedCategories are the declared exclusions, with the reason each
// family is out of scope for this story.
var NonselectedCategories = []NonselectedCategory{
	{
		Family:      "9.*",
		Disposition: DispositionDeclaredNonselected,
		Rationale: "Limits and performance family. Excluded by the pinned configuration " +
			"because throughput measurement belongs to the benchmark story, not to " +
			"wire conformance; the exclusion is part of the frozen suite selection.",
		NeverATestSkip: true,
	},
	{
		Family:      "12.*",
		Disposition: DispositionDeclaredNonselected,
		Rationale: "WebSocket compression (permessage-deflate) family. The port " +
			"implements no extension or compression negotiation at all, so these " +
			"cases address behavior outside the ported surface.",
		NeverATestSkip: true,
	},
	{
		Family:      "13.*",
		Disposition: DispositionDeclaredNonselected,
		Rationale: "WebSocket compression parameter family, same excluded extension " +
			"surface as 12.*.",
		NeverATestSkip: true,
	},
}

// CaseEntry is one statically expanded selected case.
type CaseEntry struct {
	// CaseID is the suite's dotted case identifier, e.g. "1.1.1".
	CaseID string `json:"case_id"`
	// Family is the leading component, e.g. "1" or "10".
	Family string `json:"family"`
	// SelectedOrdinal is the suite's OWN 1-based index into the SELECTED
	// set — the value `/runCase?case=N` addresses in fuzzingserver mode. It
	// is dense over 1..ExpectedCaseCount and is read from each report's
	// `case` field, never derived from a sort of the identifiers.
	SelectedOrdinal int `json:"selected_ordinal"`
	// SuiteCaseNumber is the suite's ABSOLUTE case index over its whole
	// case set, which is what fuzzingclient mode reports. It is sparse over
	// the selected set: the two numberings agree up to 7.9.9 and then
	// diverge, because the declared-nonselected 9.* family still occupies
	// absolute positions (10.1.1 is selected ordinal 247 and absolute case
	// 301). Recording both is what stops one mode's numbering from being
	// silently used to address the other's.
	SuiteCaseNumber int `json:"suite_case_number"`
	// StrictPassRequired is true for every in-scope case.
	StrictPassRequired bool `json:"strict_pass_required"`
}

// SourceRecord attributes the manifest to the report bytes it was built from.
type SourceRecord struct {
	Name      string `json:"name"`
	Role      Role   `json:"role"`
	IndexPath string `json:"index_path"`
	CasesDir  string `json:"cases_dir"`
	CaseCount int    `json:"case_count"`
}

// Manifest is the immutable expectation US-019 AC2 requires.
type Manifest struct {
	SchemaVersion         string                `json:"schema_version"`
	EntityType            string                `json:"entity_type"`
	SelectedFamilies      []string              `json:"selected_families"`
	NonselectedCategories []NonselectedCategory `json:"nonselected_categories"`
	ExpectedCaseCount     int                   `json:"expected_case_count"`
	Cases                 []CaseEntry           `json:"cases"`
	Sources               []SourceRecord        `json:"sources"`
}

// ReportSource is one wstest report the manifest is expanded from.
type ReportSource struct {
	Name      string
	Role      Role
	IndexPath string
	CasesDir  string
}

// indexEntry is the per-case record inside a wstest report index.
type indexEntry struct {
	Behavior      string `json:"behavior"`
	BehaviorClose string `json:"behaviorClose"`
	ReportFile    string `json:"reportfile"`
}

// caseReport is the subset of a wstest per-case report this package reads.
type caseReport struct {
	ID                             string `json:"id"`
	Case                           int    `json:"case"`
	Agent                          string `json:"agent"`
	Behavior                       string `json:"behavior"`
	WasOpenHandshakeTimeout        bool   `json:"wasOpenHandshakeTimeout"`
	WasCloseHandshakeTimeout       bool   `json:"wasCloseHandshakeTimeout"`
	WasServerConnectionDropTimeout bool   `json:"wasServerConnectionDropTimeout"`
}

// readIndex loads a wstest report index, which is keyed by agent name.
func readIndex(path string) (agent string, entries map[string]indexEntry, err error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied evidence path
	if err != nil {
		return "", nil, fmt.Errorf("read index %s: %w", path, err)
	}
	var byAgent map[string]map[string]indexEntry
	if err := json.Unmarshal(raw, &byAgent); err != nil {
		return "", nil, fmt.Errorf("parse index %s: %w", path, err)
	}
	if len(byAgent) != 1 {
		return "", nil, fmt.Errorf("index %s reports %d agents, want exactly 1", path, len(byAgent))
	}
	for name, cases := range byAgent {
		return name, cases, nil
	}
	return "", nil, fmt.Errorf("index %s is empty", path)
}

// readCaseReports loads every per-case report in a directory, keyed by case
// identifier, and refuses a directory whose reports disagree with themselves.
func readCaseReports(dir string) (map[string]caseReport, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", dir, err)
	}
	reports := make(map[string]caseReport, len(names))
	for _, name := range names {
		raw, err := os.ReadFile(name) //nolint:gosec // operator-supplied evidence path
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		var report caseReport
		if err := json.Unmarshal(raw, &report); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		if report.ID == "" || report.Case < 1 {
			return nil, fmt.Errorf("%s: report has no usable id/case binding", name)
		}
		if prior, seen := reports[report.ID]; seen && prior.Case != report.Case {
			return nil, fmt.Errorf("case %s bound to both ordinal %d and %d",
				report.ID, prior.Case, report.Case)
		}
		reports[report.ID] = report
	}
	if len(reports) == 0 {
		return nil, fmt.Errorf("no case reports under %s", dir)
	}
	return reports, nil
}

func familyOf(caseID string) string {
	for index := range len(caseID) {
		if caseID[index] == '.' {
			return caseID[:index]
		}
	}
	return caseID
}

// BuildManifest statically expands the manifest from one or more wstest
// reports, requiring every source to agree on both the case set and the
// suite's own case-index binding.
//
// Sources must AGREE, never be merged: the manifest is a fixed expectation,
// so a disagreement between two runs of the same pinned configuration is a
// hard error rather than something to reconcile silently.
func BuildManifest(sources []ReportSource) (*Manifest, error) {
	if len(sources) == 0 {
		return nil, errors.New("no report sources given")
	}
	var (
		selectedOrdinals = map[string]int{}
		suiteNumbers     = map[string]int{}
		caseIDs          = map[string]bool{}
		records          = make([]SourceRecord, 0, len(sources))
	)
	for _, source := range sources {
		_, entries, err := readIndex(source.IndexPath)
		if err != nil {
			return nil, err
		}
		reports, err := readCaseReports(source.CasesDir)
		if err != nil {
			return nil, err
		}
		if len(entries) != len(reports) {
			return nil, fmt.Errorf("source %s: index lists %d cases but %d case reports exist",
				source.Name, len(entries), len(reports))
		}
		for caseID := range entries {
			report, ok := reports[caseID]
			if !ok {
				return nil, fmt.Errorf("source %s: case %s has no report", source.Name, caseID)
			}
			caseIDs[caseID] = true
			// The two modes number cases differently, so each numbering is
			// checked only against sources in its OWN role. A disagreement
			// WITHIN a role is a hard error.
			target := suiteNumbers
			label := "absolute suite case number"
			if source.Role == RoleClient {
				target = selectedOrdinals
				label = "selected ordinal"
			}
			if prior, seen := target[caseID]; seen && prior != report.Case {
				return nil, fmt.Errorf(
					"source %s disagrees on case %s %s: %d vs %d",
					source.Name, caseID, label, report.Case, prior)
			}
			target[caseID] = report.Case
		}
		records = append(records, SourceRecord{
			Name:      source.Name,
			Role:      source.Role,
			IndexPath: source.IndexPath,
			CasesDir:  source.CasesDir,
			CaseCount: len(entries),
		})
	}
	// Every source must cover the identical case set.
	for _, source := range sources {
		_, entries, err := readIndex(source.IndexPath)
		if err != nil {
			return nil, err
		}
		if len(entries) != len(caseIDs) {
			return nil, fmt.Errorf(
				"source %s covers %d cases but the union is %d: sources must agree exactly",
				source.Name, len(entries), len(caseIDs))
		}
	}
	if len(selectedOrdinals) == 0 {
		return nil, errors.New("no client-role (fuzzingserver) source: the selected-set " +
			"ordinal that /runCase addresses cannot be established")
	}
	if len(suiteNumbers) == 0 {
		return nil, errors.New("no server-role (fuzzingclient) source: the absolute suite " +
			"case number cannot be established")
	}
	cases := make([]CaseEntry, 0, len(caseIDs))
	for caseID := range caseIDs {
		ordinal, ok := selectedOrdinals[caseID]
		if !ok {
			return nil, fmt.Errorf("case %s has no selected ordinal", caseID)
		}
		suiteNumber, ok := suiteNumbers[caseID]
		if !ok {
			return nil, fmt.Errorf("case %s has no absolute suite case number", caseID)
		}
		family := familyOf(caseID)
		for _, nonselected := range NonselectedCategories {
			if family+".*" == nonselected.Family {
				return nil, fmt.Errorf("case %s belongs to declared-nonselected family %s",
					caseID, nonselected.Family)
			}
		}
		cases = append(cases, CaseEntry{
			CaseID:             caseID,
			Family:             family,
			SelectedOrdinal:    ordinal,
			SuiteCaseNumber:    suiteNumber,
			StrictPassRequired: true,
		})
	}
	sort.Slice(cases, func(left, right int) bool {
		return cases[left].SelectedOrdinal < cases[right].SelectedOrdinal
	})
	if len(cases) != SelectedCaseCount {
		return nil, fmt.Errorf("expanded %d cases, want the pinned %d",
			len(cases), SelectedCaseCount)
	}
	return &Manifest{
		SchemaVersion:         SchemaVersion,
		EntityType:            ManifestEntity,
		SelectedFamilies:      SelectedFamilies,
		NonselectedCategories: NonselectedCategories,
		ExpectedCaseCount:     len(cases),
		Cases:                 cases,
		Sources:               records,
	}, nil
}
