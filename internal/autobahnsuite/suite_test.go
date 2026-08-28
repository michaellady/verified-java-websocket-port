package autobahnsuite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("go.mod not found above the test directory")
	return ""
}

func devSources(root string) []ReportSource {
	base := filepath.Join(root, "evidence", "autobahn", "dev-aarch64-nonauthoritative")
	return []ReportSource{
		{
			Name:      "dev-aarch64-fuzzingserver-run1",
			Role:      RoleClient,
			IndexPath: filepath.Join(base, "fuzzingserver-run1", "index.json"),
			CasesDir:  filepath.Join(base, "fuzzingserver-run1", "cases"),
		},
		{
			Name:      "dev-aarch64-fuzzingclient-run1",
			Role:      RoleServer,
			IndexPath: filepath.Join(base, "fuzzingclient-run1", "index.json"),
			CasesDir:  filepath.Join(base, "fuzzingclient-run1", "cases"),
		},
	}
}

func TestBuildManifestStaticallyExpandsEverySelectedCase(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if got, want := len(manifest.Cases), SelectedCaseCount; got != want {
		t.Fatalf("expanded case count = %d, want %d", got, want)
	}
	if manifest.ExpectedCaseCount != SelectedCaseCount {
		t.Fatalf("ExpectedCaseCount = %d, want %d", manifest.ExpectedCaseCount, SelectedCaseCount)
	}

	// AC2: every selected case in 1..7 and 10 is enumerated explicitly, and
	// no case from a nonselected category leaks in.
	families := map[string]int{}
	for _, entry := range manifest.Cases {
		families[entry.Family]++
		if entry.CaseID == "" || entry.SelectedOrdinal < 1 || entry.SuiteCaseNumber < 1 {
			t.Fatalf("malformed entry %+v", entry)
		}
		if !entry.StrictPassRequired {
			t.Fatalf("case %s is in scope so strict pass is required", entry.CaseID)
		}
	}
	for _, family := range []string{"1", "2", "3", "4", "5", "6", "7", "10"} {
		if families[family] == 0 {
			t.Errorf("selected family %s.* expanded to no cases", family)
		}
	}
	for _, family := range []string{"9", "12", "13"} {
		if families[family] != 0 {
			t.Errorf("nonselected family %s.* must not appear as a case", family)
		}
	}
}

func TestNonselectedCategoriesAreDeclaredNotSkipped(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	// AC2: 9.*, 12.* and 13.* are recorded as DECLARED NONSELECTED
	// categories, never as test skips.
	want := map[string]bool{"9.*": false, "12.*": false, "13.*": false}
	for _, category := range manifest.NonselectedCategories {
		if _, ok := want[category.Family]; !ok {
			t.Errorf("unexpected nonselected category %q", category.Family)
			continue
		}
		want[category.Family] = true
		if category.Disposition != DispositionDeclaredNonselected {
			t.Errorf("%s disposition = %q, want %q",
				category.Family, category.Disposition, DispositionDeclaredNonselected)
		}
		if !category.NeverATestSkip {
			t.Errorf("%s must be marked as never a test skip", category.Family)
		}
		if category.Rationale == "" {
			t.Errorf("%s has no rationale", category.Family)
		}
	}
	for family, seen := range want {
		if !seen {
			t.Errorf("nonselected category %s missing from the manifest", family)
		}
	}
}

func TestOrdinalsComeFromTheSuiteNotFromAGuessedSort(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	byOrdinal := map[int]string{}
	for _, entry := range manifest.Cases {
		if prior, clash := byOrdinal[entry.SelectedOrdinal]; clash {
			t.Fatalf("ordinal %d claimed by both %s and %s",
				entry.SelectedOrdinal, prior, entry.CaseID)
		}
		byOrdinal[entry.SelectedOrdinal] = entry.CaseID
	}
	// The suite's own `case` field in each report binds index -> id. Ordinal
	// 1 is 1.1.1 and the ordinals form a dense 1..N range.
	if byOrdinal[1] != "1.1.1" {
		t.Errorf("ordinal 1 = %q, want 1.1.1", byOrdinal[1])
	}
	for index := 1; index <= SelectedCaseCount; index++ {
		if byOrdinal[index] == "" {
			t.Errorf("ordinal %d has no case", index)
		}
	}
	// A lexicographic sort would put 10.1.1 at position 17; the suite's own
	// numeric ordering does not. This pins that we read the suite rather
	// than inventing an order.
	if byOrdinal[17] == "10.1.1" {
		t.Errorf("ordinals look lexicographic, not the suite's own numbering")
	}
}

func TestManifestSourcesMustAgree(t *testing.T) {
	root := repoRoot(t)
	sources := devSources(root)
	// A source whose case set disagrees must be refused, not silently
	// merged: the manifest is an immutable expectation, so a disagreement
	// between runs is a hard error.
	temp := t.TempDir()
	index := map[string]map[string]map[string]any{
		"tampered": {"1.1.1": {"behavior": "OK", "reportfile": "x.json"}},
	}
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	indexPath := filepath.Join(temp, "index.json")
	if err := os.WriteFile(indexPath, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cases := filepath.Join(temp, "cases")
	if err := os.MkdirAll(cases, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	report := map[string]any{"id": "1.1.1", "case": 1, "behavior": "OK"}
	raw, err = json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cases, "x.json"), raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sources = append(sources, ReportSource{
		Name:      "tampered",
		Role:      RoleServer,
		IndexPath: indexPath,
		CasesDir:  cases,
	})
	if _, err := BuildManifest(sources); err == nil {
		t.Fatal("BuildManifest accepted disagreeing sources")
	}
}

func TestReconcileCountsEveryDimensionExactly(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	base := filepath.Join(root, "evidence", "autobahn", "dev-aarch64-nonauthoritative")
	for _, run := range []struct {
		name string
		dir  string
		// wantDropTimeouts is the MEASURED connection-drop overlay for this
		// role, pinned so drift is caught. In fuzzingserver mode the suite
		// hangs up at the end of every case, so the client-role testee never
		// waits and nothing times out. In fuzzingclient mode the suite waits
		// for the server-role testee to drop the connection; the testee is
		// waiting for the suite's EOF for the same Java-faithful reason, so
		// the suite times out and marks behaviorClose UNCLEAN. `behavior`,
		// the conformance class, is OK for every one of those cases.
		wantDropTimeouts int
	}{
		{"fuzzingserver-run1", filepath.Join(base, "fuzzingserver-run1"), 0},
		{"fuzzingclient-run1", filepath.Join(base, "fuzzingclient-run1"), 32},
	} {
		ledger, err := Reconcile(manifest, filepath.Join(run.dir, "index.json"),
			filepath.Join(run.dir, "cases"), nil)
		if err != nil {
			t.Fatalf("%s: Reconcile: %v", run.name, err)
		}
		if !ledger.Reconciles {
			t.Errorf("%s: ledger does not reconcile: %+v", run.name, ledger)
		}
		if ledger.Expected != SelectedCaseCount || ledger.Selected != SelectedCaseCount {
			t.Errorf("%s: expected/selected = %d/%d, want %d",
				run.name, ledger.Expected, ledger.Selected, SelectedCaseCount)
		}
		if ledger.Executed != SelectedCaseCount {
			t.Errorf("%s: executed = %d, want %d", run.name, ledger.Executed, SelectedCaseCount)
		}
		if ledger.Missing != 0 || ledger.Filtered != 0 || len(ledger.UnexpectedCases) != 0 {
			t.Errorf("%s: missing=%d filtered=%d unexpected=%v",
				run.name, ledger.Missing, ledger.Filtered, ledger.UnexpectedCases)
		}
		if ledger.Failed != 0 {
			t.Errorf("%s: failed = %d, want 0", run.name, ledger.Failed)
		}
		// AC2: nonselected categories are declared, so the suite must never
		// report a SKIP.
		if ledger.Skipped != 0 {
			t.Errorf("%s: skipped = %d, want 0 (nonselection is not a skip)",
				run.name, ledger.Skipped)
		}
		// A handshake-liveness timeout would be a real fault in either
		// direction and must never appear.
		if ledger.OpenHandshakeTimeouts != 0 || ledger.CloseHandshakeTimeouts != 0 {
			t.Errorf("%s: handshake timeouts open=%d close=%d, want 0/0",
				run.name, ledger.OpenHandshakeTimeouts, ledger.CloseHandshakeTimeouts)
		}
		if ledger.ConnectionDropTimeouts != run.wantDropTimeouts {
			t.Errorf("%s: connection-drop timeouts = %d, want the measured %d",
				run.name, ledger.ConnectionDropTimeouts, run.wantDropTimeouts)
		}
		if ledger.TimedOut != run.wantDropTimeouts {
			t.Errorf("%s: timedOut = %d, want %d", run.name, ledger.TimedOut, run.wantDropTimeouts)
		}
		if ledger.Unclassified != 0 {
			t.Errorf("%s: unclassified = %d, want 0", run.name, ledger.Unclassified)
		}
		// The partition identity must hold exactly.
		sum := ledger.Passed + ledger.NonStrict + ledger.Informational +
			ledger.Failed + ledger.Skipped + ledger.Unclassified
		if sum != ledger.Executed {
			t.Errorf("%s: class partition %d != executed %d", run.name, sum, ledger.Executed)
		}
	}
}

func TestStrictPassIsReportedLiterallyNotLoosened(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	base := filepath.Join(root, "evidence", "autobahn", "dev-aarch64-nonauthoritative",
		"fuzzingserver-run1")
	ledger, err := Reconcile(manifest, filepath.Join(base, "index.json"),
		filepath.Join(base, "cases"), nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// The runs carry 11 NON-STRICT and 3 INFORMATIONAL cases. `StrictPassAll`
	// means literally "every in-scope case behaved OK", so it MUST be false
	// here. Reporting it as true would be loosening the bar.
	if ledger.NonStrict == 0 {
		t.Fatal("fixture expected to contain NON-STRICT cases")
	}
	if ledger.StrictPassAll {
		t.Error("StrictPassAll must be false while NON-STRICT cases exist")
	}
	if len(ledger.NonStrictCases) != ledger.NonStrict {
		t.Errorf("NonStrictCases %d != NonStrict %d", len(ledger.NonStrictCases), ledger.NonStrict)
	}
}

func TestAStaleReportCannotSatisfyAGate(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	// AC4: a historical upstream report from a DIFFERENT agent must not be
	// accepted as this run's evidence. The E5 lane's committed index is a
	// real, well-formed Autobahn report for agent `verified-rust-ws-testee-e5`
	// — reconciling it while REQUIRING the current agent must fail closed.
	stale := filepath.Join(root, "evidence", "rust", "autobahn-e5", "index-run1.json")
	if _, err := os.Stat(stale); err != nil {
		t.Skipf("historical report unavailable: %v", err)
	}
	options := &Options{RequireAgent: "verified-rust-ws-testee-us019"}
	if _, err := Reconcile(manifest, stale, "", options); err == nil {
		t.Fatal("a stale historical report satisfied a gate requiring the current agent")
	}
}

func TestDiscriminationClassifiesControls(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	base := filepath.Join(root, "evidence", "autobahn", "dev-aarch64-nonauthoritative",
		"fuzzingserver-run1")
	ledger, err := Reconcile(manifest, filepath.Join(base, "index.json"),
		filepath.Join(base, "cases"), nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// A subject under test must show NO failures; a negative control must
	// show failures. The verdict is computed from the ledger, never asserted.
	if verdict := Discriminate(SubjectUnderTest, ledger); !verdict.AsExpected {
		t.Errorf("subject-under-test verdict: %+v", verdict)
	}
	if verdict := Discriminate(SubjectNegativeControl, ledger); verdict.AsExpected {
		t.Error("a clean run must NOT satisfy the negative-control expectation")
	}
}

func TestNegativeControlDiscriminationIsMeasuredAgainstTheRealControlRun(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	base := filepath.Join(root, "evidence", "autobahn", "dev-aarch64-nonauthoritative",
		"discrimination", "negative-control-fuzzingclient")
	if _, err := os.Stat(filepath.Join(base, "index.json")); err != nil {
		t.Skipf("negative-control run unavailable: %v", err)
	}
	ledger, err := Reconcile(manifest, filepath.Join(base, "index.json"),
		filepath.Join(base, "cases"), nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// The empty/stub control must pass NOTHING. This is the load-bearing
	// half of AC4: it proves the gate can actually catch a broken endpoint.
	if ledger.Passed != 0 || ledger.NonStrict != 0 {
		t.Errorf("negative control scored passed=%d non_strict=%d, want 0/0",
			ledger.Passed, ledger.NonStrict)
	}
	if ledger.Failed == 0 {
		t.Error("negative control produced no failures at all")
	}
	// The 3 INFORMATIONAL cases are informational by construction: the real
	// port and the inert control both report exactly them.
	if ledger.Informational != 3 {
		t.Errorf("informational = %d, want the measured 3", ledger.Informational)
	}
	if verdict := Discriminate(SubjectNegativeControl, ledger); !verdict.AsExpected {
		t.Errorf("negative-control verdict: %+v", verdict)
	}
	// And the SAME ledger must refuse to call it a healthy subject.
	if verdict := Discriminate(SubjectUnderTest, ledger); verdict.AsExpected {
		t.Error("the negative control must not satisfy the subject-under-test expectation")
	}
}
