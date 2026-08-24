package lab

import "testing"

func validInventory() TestInventory {
	return TestInventory{
		SchemaVersion: "1.0.0",
		StaticAnnotations: []StaticTest{
			{ID: "example.Test#one", ClassName: "example.Test", MethodName: "one", Annotation: "org.junit.jupiter.api.Test"},
			{ID: "example.Test#two", ClassName: "example.Test", MethodName: "two", Annotation: "org.junit.jupiter.api.Test"},
		},
		MavenDiscovered: []string{"example.Test#one", "example.Test#two"},
		Results:         []TestResult{{ID: "example.Test#one", Status: TestPassed}, {ID: "example.Test#two", Status: TestSkipped}},
		Counts:          TestCounts{Discovered: 2, Executed: 2, Passed: 1, Skipped: 1},
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
	inventory.Results[1].Status = TestQuarantined
	inventory.Counts = TestCounts{Discovered: 2, Filtered: 1, Quarantined: 1}
	if err := inventory.Validate(); err != nil {
		t.Fatal(err)
	}
	_, err := DecodeTestInventory([]byte(`{"schema_version":"1.0.0","command":"mvn test"}`))
	assertFinding(t, err, "UNKNOWN_JSON_FIELD")
}
