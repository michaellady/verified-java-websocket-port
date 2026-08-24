package lab

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

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
	ID                 string     `json:"id"`
	Status             TestStatus `json:"status"`
	Invocations        int        `json:"invocations"`
	PassedInvocations  int        `json:"passed_invocations"`
	FailedInvocations  int        `json:"failed_invocations"`
	SkippedInvocations int        `json:"skipped_invocations"`
}

type TestCounts struct {
	StaticAnnotations  int `json:"static_annotations"`
	ConcreteClasses    int `json:"concrete_classes"`
	AggregateSuites    int `json:"aggregate_suites"`
	Discovered         int `json:"discovered"`
	Executed           int `json:"executed"`
	Passed             int `json:"passed"`
	Failed             int `json:"failed"`
	Skipped            int `json:"skipped"`
	Filtered           int `json:"filtered"`
	TimedOut           int `json:"timed_out"`
	Quarantined        int `json:"quarantined"`
	RuntimeInvocations int `json:"runtime_invocations"`
	PassedInvocations  int `json:"passed_invocations"`
	FailedInvocations  int `json:"failed_invocations"`
	SkippedInvocations int `json:"skipped_invocations"`
}

type AggregateSuite struct {
	ClassName string   `json:"class_name"`
	Members   []string `json:"members"`
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
	CanonicalSelector []string                `json:"canonical_selector"`
	AggregateSuites   []AggregateSuite        `json:"aggregate_suite_containers"`
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
	selector, err := exactSet(i.CanonicalSelector, "$.canonical_selector", 10000)
	if err != nil {
		return err
	}
	staticClasses := make(map[string]struct{})
	for _, test := range i.StaticAnnotations {
		staticClasses[test.ClassName] = struct{}{}
	}
	if missing, extra := setDifference(staticClasses, selector), setDifference(selector, staticClasses); len(missing) != 0 || len(extra) != 0 {
		return finding("TEST_SELECTOR_MISMATCH", "$.canonical_selector", fmt.Sprintf("selector must contain each concrete annotated class once; missing=%v extra=%v", missing, extra))
	}
	suiteNames := make(map[string]struct{}, len(i.AggregateSuites))
	for index, suite := range i.AggregateSuites {
		if !refPattern.MatchString(suite.ClassName) || len(suite.Members) == 0 || len(suite.Members) > 10000 {
			return finding("INVALID_AGGREGATE_SUITE", fmt.Sprintf("$.aggregate_suite_containers[%d]", index), "suite class and bounded member list are required")
		}
		if _, duplicate := suiteNames[suite.ClassName]; duplicate {
			return finding("DUPLICATE_ENTRY", fmt.Sprintf("$.aggregate_suite_containers[%d].class_name", index), "aggregate suite occurs more than once")
		}
		if _, selected := selector[suite.ClassName]; selected {
			return finding("TEST_SELECTOR_MISMATCH", fmt.Sprintf("$.aggregate_suite_containers[%d].class_name", index), "aggregate suite cannot be selected with its concrete members")
		}
		if _, err := exactSet(suite.Members, fmt.Sprintf("$.aggregate_suite_containers[%d].members", index), 10000); err != nil {
			return err
		}
		suiteNames[suite.ClassName] = struct{}{}
	}
	computed := TestCounts{StaticAnnotations: len(static), ConcreteClasses: len(selector), AggregateSuites: len(suiteNames), Discovered: len(discovered)}
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
		if result.Invocations < 0 || result.PassedInvocations < 0 || result.FailedInvocations < 0 || result.SkippedInvocations < 0 || result.PassedInvocations+result.FailedInvocations+result.SkippedInvocations != result.Invocations {
			return finding("TEST_INVOCATION_MISMATCH", fmt.Sprintf("$.results[%d]", index), "invocation totals must be nonnegative and exact")
		}
		seenResults[result.ID] = struct{}{}
		computed.RuntimeInvocations += result.Invocations
		computed.PassedInvocations += result.PassedInvocations
		computed.FailedInvocations += result.FailedInvocations
		computed.SkippedInvocations += result.SkippedInvocations
		switch result.Status {
		case TestPassed:
			if result.Invocations == 0 || result.FailedInvocations != 0 || result.SkippedInvocations != 0 {
				return finding("TEST_INVOCATION_MISMATCH", fmt.Sprintf("$.results[%d]", index), "passed identity must contain only passed invocations")
			}
			computed.Executed++
			computed.Passed++
		case TestFailed:
			if result.Invocations == 0 || result.FailedInvocations == 0 {
				return finding("TEST_INVOCATION_MISMATCH", fmt.Sprintf("$.results[%d]", index), "failed identity requires a failed invocation")
			}
			computed.Executed++
			computed.Failed++
		case TestSkipped:
			if result.Invocations == 0 || result.SkippedInvocations != result.Invocations {
				return finding("TEST_INVOCATION_MISMATCH", fmt.Sprintf("$.results[%d]", index), "skipped identity requires only skipped invocations")
			}
			computed.Executed++
			computed.Skipped++
		case TestFiltered:
			if result.Invocations != 0 {
				return finding("TEST_INVOCATION_MISMATCH", fmt.Sprintf("$.results[%d]", index), "filtered identity cannot have an invocation")
			}
			computed.Filtered++
		case TestTimedOut:
			if result.Invocations == 0 || result.FailedInvocations == 0 {
				return finding("TEST_INVOCATION_MISMATCH", fmt.Sprintf("$.results[%d]", index), "timed-out identity requires a failed invocation")
			}
			computed.Executed++
			computed.TimedOut++
		case TestQuarantined:
			if result.Invocations != 0 {
				return finding("TEST_INVOCATION_MISMATCH", fmt.Sprintf("$.results[%d]", index), "quarantined identity cannot have an invocation")
			}
			computed.Quarantined++
		}
	}
	if computed != i.Counts {
		return finding("TEST_COUNT_MISMATCH", "$.counts", fmt.Sprintf("declared counts %+v differ from recomputed %+v", i.Counts, computed))
	}
	return validateNonTests(i.NonTestCandidates, i.NonTestClassified)
}

var (
	javaPackagePattern = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*;`)
	javaImportPattern  = regexp.MustCompile(`(?m)^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*;`)
	javaTestPattern    = regexp.MustCompile(`(?s)@Test(?:\s*\([^)]*\))?\s+(?:(?:public|protected|private|static|final|synchronized)\s+)*void\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(`)
	javaSuitePattern   = regexp.MustCompile(`@RunWith\s*\(\s*Suite\.class\s*\)`)
	javaMembersPattern = regexp.MustCompile(`(?s)@Suite\.SuiteClasses\s*\(\s*\{([^}]*)\}\s*\)`)
	javaClassRef       = regexp.MustCompile(`([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\.class`)
	parameterSuffix    = regexp.MustCompile(`\[[0-9]+\]$`)
)

// DiscoverJavaTests derives the canonical one-concrete-class-once Maven
// selector directly from the accepted Java test sources. Aggregate suites are
// retained as executable discovery containers but excluded from that selector.
func DiscoverJavaTests(sourceRoot string) ([]StaticTest, []string, []AggregateSuite, error) {
	if err := requireRealDirectory(sourceRoot); err != nil {
		return nil, nil, nil, err
	}
	paths := make([]string, 0, 128)
	err := filepath.WalkDir(sourceRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return finding("UNSAFE_FILE", path, "Java test inventory cannot follow symbolic links")
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".java" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil || len(paths) == 0 || len(paths) > 10000 {
		if err == nil {
			err = finding("INVALID_TEST_INVENTORY", sourceRoot, "Java source inventory must contain 1..10000 files")
		}
		return nil, nil, nil, err
	}
	sort.Strings(paths)
	staticTests := make([]StaticTest, 0, 256)
	selectorSet := make(map[string]struct{})
	suites := make([]AggregateSuite, 0, 16)
	for _, path := range paths {
		data, readErr := readBoundedRegular(path, maxManifestBytes)
		if readErr != nil {
			return nil, nil, nil, readErr
		}
		clean := stripJavaCommentsAndLiterals(data)
		packageMatch := javaPackagePattern.FindSubmatch(clean)
		if len(packageMatch) != 2 {
			return nil, nil, nil, finding("INVALID_JAVA_TEST_SOURCE", path, "test source requires one explicit package")
		}
		className := strings.TrimSuffix(filepath.Base(path), ".java")
		fqcn := string(packageMatch[1]) + "." + className
		relative, relErr := filepath.Rel(sourceRoot, path)
		if relErr != nil || filepath.ToSlash(strings.TrimSuffix(relative, ".java")) != strings.ReplaceAll(fqcn, ".", "/") {
			return nil, nil, nil, finding("INVALID_JAVA_TEST_SOURCE", path, "package, class filename, and source path disagree")
		}
		methodMatches := javaTestPattern.FindAllSubmatch(clean, -1)
		seenMethods := make(map[string]struct{}, len(methodMatches))
		for _, match := range methodMatches {
			method := string(match[1])
			if _, duplicate := seenMethods[method]; duplicate {
				return nil, nil, nil, finding("DUPLICATE_ENTRY", path, "annotated method identity occurs more than once")
			}
			seenMethods[method] = struct{}{}
			staticTests = append(staticTests, StaticTest{ID: fqcn + "#" + method, ClassName: fqcn, MethodName: method, Annotation: "org.junit.Test"})
			selectorSet[fqcn] = struct{}{}
		}
		if !javaSuitePattern.Match(clean) {
			continue
		}
		membersMatch := javaMembersPattern.FindSubmatch(clean)
		if len(membersMatch) != 2 {
			return nil, nil, nil, finding("INVALID_AGGREGATE_SUITE", path, "Suite runner requires an explicit SuiteClasses member list")
		}
		imports := make(map[string]string)
		for _, match := range javaImportPattern.FindAllSubmatch(clean, -1) {
			imported := string(match[1])
			imports[imported[strings.LastIndex(imported, ".")+1:]] = imported
		}
		memberMatches := javaClassRef.FindAllSubmatch(membersMatch[1], -1)
		members := make([]string, 0, len(memberMatches))
		for _, match := range memberMatches {
			member := string(match[1])
			if !strings.Contains(member, ".") {
				if imported, ok := imports[member]; ok {
					member = imported
				} else {
					member = string(packageMatch[1]) + "." + member
				}
			}
			members = append(members, member)
		}
		sort.Strings(members)
		suites = append(suites, AggregateSuite{ClassName: fqcn, Members: members})
	}
	sort.Slice(staticTests, func(left, right int) bool { return staticTests[left].ID < staticTests[right].ID })
	selector := make([]string, 0, len(selectorSet))
	for className := range selectorSet {
		selector = append(selector, className)
	}
	sort.Strings(selector)
	sort.Slice(suites, func(left, right int) bool { return suites[left].ClassName < suites[right].ClassName })
	return staticTests, selector, suites, nil
}

type surefireSuite struct {
	Cases []surefireCase `xml:"testcase"`
}

type surefireCase struct {
	Name      string    `xml:"name,attr"`
	ClassName string    `xml:"classname,attr"`
	Failure   *struct{} `xml:"failure"`
	Error     *struct{} `xml:"error"`
	Skipped   *struct{} `xml:"skipped"`
}

// ReconcileSurefireReports aggregates parameterized Maven invocations back to
// their single static @Test method identities and rejects unknown or missing
// identities fail-closed.
func ReconcileSurefireReports(reportRoot string, staticTests []StaticTest, selector []string, suites []AggregateSuite, candidates []NonTestCandidate, classifications []NonTestClassification) (TestInventory, error) {
	if err := requireRealDirectory(reportRoot); err != nil {
		return TestInventory{}, err
	}
	paths, err := filepath.Glob(filepath.Join(reportRoot, "TEST-*.xml"))
	if err != nil || len(paths) == 0 || len(paths) > 10000 {
		return TestInventory{}, finding("INVALID_SUREFIRE_REPORTS", reportRoot, "Surefire report inventory must contain 1..10000 XML files")
	}
	sort.Strings(paths)
	staticByID := make(map[string]StaticTest, len(staticTests))
	for _, test := range staticTests {
		staticByID[test.ID] = test
	}
	totals := make(map[string]*TestResult, len(staticTests))
	for _, path := range paths {
		data, readErr := readBoundedRegular(path, maxManifestBytes)
		if readErr != nil {
			return TestInventory{}, readErr
		}
		var report surefireSuite
		decoder := xml.NewDecoder(strings.NewReader(string(data)))
		decoder.Strict = true
		if decodeErr := decoder.Decode(&report); decodeErr != nil {
			return TestInventory{}, finding("INVALID_SUREFIRE_REPORTS", path, decodeErr.Error())
		}
		for _, testCase := range report.Cases {
			method := parameterSuffix.ReplaceAllString(testCase.Name, "")
			id := testCase.ClassName + "#" + method
			if _, exists := staticByID[id]; !exists {
				return TestInventory{}, finding("UNKNOWN_TEST_RESULT", path, "Surefire emitted unknown static identity "+id)
			}
			result := totals[id]
			if result == nil {
				result = &TestResult{ID: id}
				totals[id] = result
			}
			result.Invocations++
			switch {
			case testCase.Failure != nil || testCase.Error != nil:
				result.FailedInvocations++
			case testCase.Skipped != nil:
				result.SkippedInvocations++
			default:
				result.PassedInvocations++
			}
		}
	}
	discovered := make([]string, 0, len(totals))
	results := make([]TestResult, 0, len(totals))
	for id, result := range totals {
		discovered = append(discovered, id)
		switch {
		case result.FailedInvocations > 0:
			result.Status = TestFailed
		case result.SkippedInvocations == result.Invocations:
			result.Status = TestSkipped
		default:
			result.Status = TestPassed
		}
		results = append(results, *result)
	}
	sort.Strings(discovered)
	sort.Slice(results, func(left, right int) bool { return results[left].ID < results[right].ID })
	inventory := TestInventory{SchemaVersion: "1.0.0", StaticAnnotations: staticTests, CanonicalSelector: selector, AggregateSuites: suites, MavenDiscovered: discovered, Results: results, NonTestCandidates: candidates, NonTestClassified: classifications}
	inventory.Counts = inventory.recomputedCounts()
	if err := inventory.Validate(); err != nil {
		return TestInventory{}, err
	}
	return inventory, nil
}

func PinnedJavaNonTests(projectRoot string) ([]NonTestCandidate, []NonTestClassification, error) {
	definitions := []struct {
		path   string
		kind   NonTestKind
		main   bool
		reason string
	}{
		{"src/test/resources/org/java_websocket/AutobahnClient.feature", NonTestFeatureFile, false, "retained Autobahn feature input has no configured Cucumber runner"},
		{"src/test/java/org/java_websocket/example/AutobahnClientTest.java", NonTestAutobahnUtility, true, "executable Autobahn client main is not a JUnit test"},
		{"src/test/java/org/java_websocket/example/AutobahnSSLServerTest.java", NonTestAutobahnUtility, true, "executable Autobahn TLS server main is not a JUnit test"},
		{"src/test/java/org/java_websocket/example/AutobahnServerTest.java", NonTestAutobahnUtility, true, "executable Autobahn server main is not a JUnit test"},
	}
	candidates := make([]NonTestCandidate, 0, len(definitions))
	classifications := make([]NonTestClassification, 0, len(definitions))
	for _, definition := range definitions {
		data, err := readBoundedRegular(filepath.Join(projectRoot, filepath.FromSlash(definition.path)), maxManifestBytes)
		if err != nil {
			return nil, nil, err
		}
		hasMain := strings.Contains(string(stripJavaCommentsAndLiterals(data)), "public static void main")
		if hasMain != definition.main {
			return nil, nil, finding("NON_TEST_CLASSIFICATION_MISMATCH", definition.path, "executable main classification differs from accepted bytes")
		}
		candidates = append(candidates, NonTestCandidate{Path: definition.path, Kind: definition.kind, HasMain: hasMain})
		classifications = append(classifications, NonTestClassification{Path: definition.path, Kind: definition.kind, CountedAsTest: false, Reason: definition.reason})
	}
	return candidates, classifications, nil
}

func (i TestInventory) recomputedCounts() TestCounts {
	counts := TestCounts{StaticAnnotations: len(i.StaticAnnotations), ConcreteClasses: len(i.CanonicalSelector), AggregateSuites: len(i.AggregateSuites), Discovered: len(i.MavenDiscovered)}
	for _, result := range i.Results {
		counts.RuntimeInvocations += result.Invocations
		counts.PassedInvocations += result.PassedInvocations
		counts.FailedInvocations += result.FailedInvocations
		counts.SkippedInvocations += result.SkippedInvocations
		switch result.Status {
		case TestPassed:
			counts.Executed++
			counts.Passed++
		case TestFailed:
			counts.Executed++
			counts.Failed++
		case TestSkipped:
			counts.Executed++
			counts.Skipped++
		case TestFiltered:
			counts.Filtered++
		case TestTimedOut:
			counts.Executed++
			counts.TimedOut++
		case TestQuarantined:
			counts.Quarantined++
		}
	}
	return counts
}

func stripJavaCommentsAndLiterals(data []byte) []byte {
	result := append([]byte(nil), data...)
	const (
		javaCode = iota
		javaLineComment
		javaBlockComment
		javaString
		javaCharacter
	)
	state, escaped := javaCode, false
	for index := 0; index < len(result); index++ {
		current := result[index]
		switch state {
		case javaCode:
			if current == '/' && index+1 < len(result) && result[index+1] == '/' {
				result[index], result[index+1], state = ' ', ' ', javaLineComment
				index++
			} else if current == '/' && index+1 < len(result) && result[index+1] == '*' {
				result[index], result[index+1], state = ' ', ' ', javaBlockComment
				index++
			} else if current == '"' {
				result[index], state, escaped = ' ', javaString, false
			} else if current == '\'' {
				result[index], state, escaped = ' ', javaCharacter, false
			}
		case javaLineComment:
			if current == '\n' {
				state = javaCode
			} else {
				result[index] = ' '
			}
		case javaBlockComment:
			if current == '*' && index+1 < len(result) && result[index+1] == '/' {
				result[index], result[index+1], state = ' ', ' ', javaCode
				index++
			} else if current != '\n' {
				result[index] = ' '
			}
		case javaString, javaCharacter:
			if current == '\n' {
				escaped = false
				continue
			}
			result[index] = ' '
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if state == javaString && current == '"' || state == javaCharacter && current == '\'' {
				state = javaCode
			}
		}
	}
	return result
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
