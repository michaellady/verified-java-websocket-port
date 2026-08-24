package lab

import (
	"fmt"
	"sort"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

type StaticTest struct {
	ID         string `json:"id"`
	ClassName  string `json:"class_name"`
	MethodName string `json:"method_name"`
	Annotation string `json:"annotation"`
}

type TestStatus string

const (
	TestPassed      TestStatus = "passed"
	TestFailed      TestStatus = "failed"
	TestSkipped     TestStatus = "skipped"
	TestFiltered    TestStatus = "filtered"
	TestTimedOut    TestStatus = "timed-out"
	TestQuarantined TestStatus = "quarantined"
)

var testStatuses = map[TestStatus]struct{}{
	TestPassed: {}, TestFailed: {}, TestSkipped: {}, TestFiltered: {}, TestTimedOut: {}, TestQuarantined: {},
}

type TestResult struct {
	ID     string     `json:"id"`
	Status TestStatus `json:"status"`
}

type TestCounts struct {
	Discovered  int `json:"discovered"`
	Executed    int `json:"executed"`
	Passed      int `json:"passed"`
	Failed      int `json:"failed"`
	Skipped     int `json:"skipped"`
	Filtered    int `json:"filtered"`
	TimedOut    int `json:"timed_out"`
	Quarantined int `json:"quarantined"`
}

type NonTestKind string

const (
	NonTestFeatureFile     NonTestKind = "feature-file"
	NonTestAutobahnUtility NonTestKind = "autobahn-utility"
)

type NonTestCandidate struct {
	Path    string      `json:"path"`
	Kind    NonTestKind `json:"kind"`
	HasMain bool        `json:"has_main"`
}

type NonTestClassification struct {
	Path          string      `json:"path"`
	Kind          NonTestKind `json:"kind"`
	CountedAsTest bool        `json:"counted_as_test"`
	Reason        string      `json:"reason"`
}

type TestInventory struct {
	SchemaVersion     string                  `json:"schema_version"`
	StaticAnnotations []StaticTest            `json:"static_annotations"`
	MavenDiscovered   []string                `json:"maven_discovered"`
	Results           []TestResult            `json:"results"`
	Counts            TestCounts              `json:"counts"`
	NonTestCandidates []NonTestCandidate      `json:"non_test_candidates"`
	NonTestClassified []NonTestClassification `json:"non_test_classifications"`
}

func DecodeTestInventory(data []byte) (TestInventory, error) {
	var inventory TestInventory
	if err := intake.DecodeStrict(data, &inventory); err != nil {
		return TestInventory{}, err
	}
	return inventory, inventory.Validate()
}

func (i TestInventory) Validate() error {
	if i.SchemaVersion != "1.0.0" || len(i.StaticAnnotations) == 0 || len(i.StaticAnnotations) > 100000 {
		return finding("INVALID_TEST_INVENTORY", "$", "schema or static annotation inventory is invalid")
	}
	static := make(map[string]struct{}, len(i.StaticAnnotations))
	for index, test := range i.StaticAnnotations {
		if !refPattern.MatchString(test.ID) || test.ClassName == "" || test.MethodName == "" || test.Annotation == "" {
			return finding("INVALID_TEST_INVENTORY", fmt.Sprintf("$.static_annotations[%d]", index), "test identity and annotation fields are required")
		}
		if _, duplicate := static[test.ID]; duplicate {
			return finding("DUPLICATE_ENTRY", fmt.Sprintf("$.static_annotations[%d].id", index), "static test occurs more than once")
		}
		static[test.ID] = struct{}{}
	}
	discovered, err := exactSet(i.MavenDiscovered, "$.maven_discovered", 100000)
	if err != nil {
		return err
	}
	if missing, extra := setDifference(static, discovered), setDifference(discovered, static); len(missing) != 0 || len(extra) != 0 {
		return finding("TEST_DISCOVERY_MISMATCH", "$.maven_discovered", fmt.Sprintf("static and Maven inventories differ; missing=%v extra=%v", missing, extra))
	}
	if len(i.Results) != len(discovered) {
		return finding("TEST_RESULT_MISMATCH", "$.results", "every discovered test must have exactly one terminal result")
	}
	seenResults := make(map[string]struct{}, len(i.Results))
	computed := TestCounts{Discovered: len(discovered)}
	for index, result := range i.Results {
		if _, exists := discovered[result.ID]; !exists {
			return finding("UNKNOWN_TEST_RESULT", fmt.Sprintf("$.results[%d].id", index), "result is not in the Maven discovery inventory")
		}
		if _, duplicate := seenResults[result.ID]; duplicate {
			return finding("DUPLICATE_ENTRY", fmt.Sprintf("$.results[%d].id", index), "test has more than one terminal result")
		}
		if _, allowed := testStatuses[result.Status]; !allowed {
			return finding("INVALID_TEST_STATUS", fmt.Sprintf("$.results[%d].status", index), "test terminal status is unknown")
		}
		seenResults[result.ID] = struct{}{}
		switch result.Status {
		case TestPassed:
			computed.Executed++
			computed.Passed++
		case TestFailed:
			computed.Executed++
			computed.Failed++
		case TestSkipped:
			computed.Executed++
			computed.Skipped++
		case TestFiltered:
			computed.Filtered++
		case TestTimedOut:
			computed.Executed++
			computed.TimedOut++
		case TestQuarantined:
			computed.Quarantined++
		}
	}
	if computed != i.Counts {
		return finding("TEST_COUNT_MISMATCH", "$.counts", fmt.Sprintf("declared counts %+v differ from recomputed %+v", i.Counts, computed))
	}
	return validateNonTests(i.NonTestCandidates, i.NonTestClassified)
}

func validateNonTests(candidates []NonTestCandidate, classified []NonTestClassification) error {
	if len(candidates) < 3 || len(candidates) != len(classified) || len(candidates) > 256 {
		return finding("NON_TEST_CLASSIFICATION_MISMATCH", "$.non_test_candidates", "all non-test candidates, including one feature and two Autobahn utilities, require classification")
	}
	candidateSet := make(map[string]NonTestCandidate, len(candidates))
	features, utilities := 0, 0
	for index, candidate := range candidates {
		if !refPattern.MatchString(candidate.Path) || candidate.Kind != NonTestFeatureFile && candidate.Kind != NonTestAutobahnUtility {
			return finding("INVALID_NON_TEST_CLASSIFICATION", fmt.Sprintf("$.non_test_candidates[%d]", index), "candidate path or kind is invalid")
		}
		if _, duplicate := candidateSet[candidate.Path]; duplicate {
			return finding("DUPLICATE_ENTRY", fmt.Sprintf("$.non_test_candidates[%d].path", index), "candidate occurs more than once")
		}
		if candidate.Kind == NonTestFeatureFile {
			features++
			if candidate.HasMain {
				return finding("INVALID_NON_TEST_CLASSIFICATION", fmt.Sprintf("$.non_test_candidates[%d]", index), "feature file cannot be an executable utility")
			}
		} else {
			utilities++
			if !candidate.HasMain {
				return finding("INVALID_NON_TEST_CLASSIFICATION", fmt.Sprintf("$.non_test_candidates[%d]", index), "Autobahn utility classification requires a main entry point")
			}
		}
		candidateSet[candidate.Path] = candidate
	}
	if features < 1 || utilities < 2 {
		return finding("NON_TEST_CLASSIFICATION_MISMATCH", "$.non_test_candidates", "retained feature file and client/server Autobahn utilities must remain visible")
	}
	seen := make(map[string]struct{}, len(classified))
	for index, classification := range classified {
		candidate, exists := candidateSet[classification.Path]
		if !exists || candidate.Kind != classification.Kind || classification.CountedAsTest || classification.Reason == "" || len(classification.Reason) > 1024 {
			return finding("NON_TEST_CLASSIFICATION_MISMATCH", fmt.Sprintf("$.non_test_classifications[%d]", index), "classification must exactly bind a candidate and exclude it from test counts with a reason")
		}
		if _, duplicate := seen[classification.Path]; duplicate {
			return finding("DUPLICATE_ENTRY", fmt.Sprintf("$.non_test_classifications[%d].path", index), "candidate is classified more than once")
		}
		seen[classification.Path] = struct{}{}
	}
	return nil
}

func setDifference(left, right map[string]struct{}) []string {
	result := make([]string, 0)
	for value := range left {
		if _, exists := right[value]; !exists {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
