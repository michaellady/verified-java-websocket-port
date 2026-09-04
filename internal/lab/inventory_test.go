package lab

import (
	"os"
	"path/filepath"
	"testing"
)

func validInventory() TestInventory {
	return TestInventory{
		SchemaVersion: "1.0.0",
		StaticAnnotations: []StaticTest{
			{ID: "example.Test#one", ClassName: "example.Test", MethodName: "one", Annotation: "org.junit.jupiter.api.Test"},
			{ID: "example.Test#two", ClassName: "example.Test", MethodName: "two", Annotation: "org.junit.jupiter.api.Test"},
		},
		CanonicalSelector: []string{"example.Test"},
		AggregateSuites:   []AggregateSuite{{ClassName: "example.AllTests", Members: []string{"example.Test"}}},
		MavenDiscovered:   []string{"example.Test#one", "example.Test#two"},
		Results: []TestResult{
			{ID: "example.Test#one", Status: TestPassed, Invocations: 1, PassedInvocations: 1},
			{ID: "example.Test#two", Status: TestSkipped, Invocations: 1, SkippedInvocations: 1},
		},
		Counts: TestCounts{StaticAnnotations: 2, ConcreteClasses: 1, AggregateSuites: 1, Discovered: 2, Executed: 2, Passed: 1, Skipped: 1, RuntimeInvocations: 2, PassedInvocations: 1, SkippedInvocations: 1},
		NonTestCandidates: []NonTestCandidate{
			{Path: "src/test/resources/AutobahnClient.feature", Kind: NonTestFeatureFile},
			{Path: "src/test/java/org/java_websocket/example/AutobahnClientTest.java", Kind: NonTestAutobahnUtility, HasMain: true},
			{Path: "src/test/java/org/java_websocket/example/AutobahnServerTest.java", Kind: NonTestAutobahnUtility, HasMain: true},
		},
		NonTestClassified: []NonTestClassification{
			{Path: "src/test/resources/AutobahnClient.feature", Kind: NonTestFeatureFile, Reason: "feature has no configured Cucumber runner"},
			{Path: "src/test/java/org/java_websocket/example/AutobahnClientTest.java", Kind: NonTestAutobahnUtility, Reason: "main utility is not a JUnit test"},
			{Path: "src/test/java/org/java_websocket/example/AutobahnServerTest.java", Kind: NonTestAutobahnUtility, Reason: "main utility is not a JUnit test"},
		},
	}
}

func TestTestInventoryReconcilesEverySurface(t *testing.T) {
	inventory := validInventory()
	if err := inventory.Validate(); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*TestInventory){
		"missing-discovery": func(i *TestInventory) { i.MavenDiscovered = i.MavenDiscovered[:1] },
		"duplicate-result":  func(i *TestInventory) { i.Results[1].ID = i.Results[0].ID },
		"count-drift":       func(i *TestInventory) { i.Counts.Passed++ },
		"silent-feature":    func(i *TestInventory) { i.NonTestClassified = i.NonTestClassified[1:] },
		"utility-as-test":   func(i *TestInventory) { i.NonTestClassified[1].CountedAsTest = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := validInventory()
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("inventory mutation accepted")
			}
		})
	}
}

func TestTestInventoryExecutedCountExcludesFilteredAndQuarantined(t *testing.T) {
	inventory := validInventory()
	inventory.Results[0].Status = TestFiltered
	inventory.Results[0].Invocations = 0
	inventory.Results[0].PassedInvocations = 0
	inventory.Results[1].Status = TestQuarantined
	inventory.Results[1].Invocations = 0
	inventory.Results[1].SkippedInvocations = 0
	inventory.Counts = TestCounts{StaticAnnotations: 2, ConcreteClasses: 1, AggregateSuites: 1, Discovered: 2, Filtered: 1, Quarantined: 1}
	if err := inventory.Validate(); err != nil {
		t.Fatal(err)
	}
	_, err := DecodeTestInventory([]byte(`{"schema_version":"1.0.0","command":"mvn test"}`))
	assertFinding(t, err, "UNKNOWN_JSON_FIELD")
}

func TestDiscoverAndReconcileJavaTestsAggregatesParameterizedInvocations(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "src", "test", "java", "example")
	reports := filepath.Join(root, "target", "surefire-reports")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(reports, 0o700); err != nil {
		t.Fatal(err)
	}
	writeInventoryFixture(t, filepath.Join(source, "ExampleTest.java"), `package example;
import org.junit.Test;
public final class ExampleTest {
  // @Test public void forged() {}
  @Test(timeout = 1000)
  public void parameterized() {}
  @Test
  // a retained comment between annotation and declaration
  public void plain() {}
}`)
	writeInventoryFixture(t, filepath.Join(source, "AllTests.java"), `package example;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
@RunWith(Suite.class)
@Suite.SuiteClasses({ExampleTest.class})
public final class AllTests {}`)
	writeInventoryFixture(t, filepath.Join(reports, "TEST-example.ExampleTest.xml"), `<?xml version="1.0" encoding="UTF-8"?>
<testsuite><testcase name="parameterized[0]" classname="example.ExampleTest"/><testcase name="parameterized[1]" classname="example.ExampleTest"/><testcase name="plain" classname="example.ExampleTest"/></testsuite>`)
	staticTests, selector, suites, err := DiscoverJavaTests(filepath.Join(root, "src", "test", "java"))
	if err != nil {
		t.Fatal(err)
	}
	if len(staticTests) != 2 || len(selector) != 1 || len(suites) != 1 || suites[0].Members[0] != "example.ExampleTest" {
		t.Fatalf("unexpected discovery: static=%+v selector=%+v suites=%+v", staticTests, selector, suites)
	}
	candidates := validInventory().NonTestCandidates
	classifications := validInventory().NonTestClassified
	inventory, err := ReconcileSurefireReports(reports, staticTests, selector, suites, candidates, classifications)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Counts.StaticAnnotations != 2 || inventory.Counts.RuntimeInvocations != 3 || inventory.Counts.Passed != 2 || inventory.Results[0].Invocations != 2 {
		t.Fatalf("unexpected reconciliation: %+v results=%+v", inventory.Counts, inventory.Results)
	}
}

func writeInventoryFixture(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}
