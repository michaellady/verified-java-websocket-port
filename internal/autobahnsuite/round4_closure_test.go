package autobahnsuite

// round4_closure_test.go — self-review round 4, survivor closure.
//
// Round 3 swept every `if`-guarded check this package adds with `false &&`
// (never by deletion, because a mutation that breaks compilation proves
// nothing) and found 52 survivors, of which 7 were closed. This file attacks
// the remaining 45.
//
// The three failure modes round 3 diagnosed are all avoided here:
//
//  1. NON-ISOLATION. `TestATamperedComparisonDocumentIsRefused` asserts only
//     `len(findings) == 0`, so whichever check fires first satisfies it and
//     every other check in that function survives deletion. Every probe below
//     asserts on the FIELD and TEXT of the specific finding, never on a count.
//  2. MEASURING THE COPIER. Each group that copies committed evidence has a
//     polarity control asserting the unmutated copy is clean.
//  3. CLAIMING A BUILD BREAK AS A RED READING. Nothing here relies on a
//     mutation that fails to compile.
//
// A guard whose deletion turns a stated refusal into a nil-pointer panic IS
// discriminable: the function is exported, so a test can supply the input
// directly. Round 3 recorded that class as "input nothing produces"; the
// caller nothing produces is the test itself, and a panic fails a test.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func devIndex(root, run string) string {
	return filepath.Join(devBase(root), run, "index.json")
}

func devCases(root, run string) string {
	return filepath.Join(devBase(root), run, "cases")
}

func readJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return doc
}

func writeJSONFile(t *testing.T, path string, doc any) {
	t.Helper()
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// mutableTree copies the committed dev report tree (both roles, index plus
// every per-case report) into a temp directory and returns sources pointing
// at the copy. Nothing is synthesised: each fixture is a real Autobahn report
// until a probe rewrites one field of it.
func mutableTree(t *testing.T) (base string, sources []ReportSource) {
	t.Helper()
	root := repoRoot(t)
	base = t.TempDir()
	for _, run := range []string{"fuzzingserver-run1", "fuzzingclient-run1"} {
		src := filepath.Join(devBase(root), run)
		mustExist(t, filepath.Join(src, "index.json"))
		raw, err := os.ReadFile(filepath.Join(src, "index.json"))
		if err != nil {
			t.Fatalf("read index: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(base, run, "cases"), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(base, run, "index.json"), raw, 0o600); err != nil {
			t.Fatalf("write index: %v", err)
		}
		names, err := filepath.Glob(filepath.Join(src, "cases", "*.json"))
		if err != nil || len(names) == 0 {
			t.Fatalf("glob %s: %v (%d names)", src, err, len(names))
		}
		for _, name := range names {
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			out := filepath.Join(base, run, "cases", filepath.Base(name))
			if err := os.WriteFile(out, raw, 0o600); err != nil {
				t.Fatalf("write %s: %v", out, err)
			}
		}
	}
	return base, []ReportSource{
		{
			Name:      "copy-fuzzingserver-run1",
			Role:      RoleClient,
			IndexPath: filepath.Join(base, "fuzzingserver-run1", "index.json"),
			CasesDir:  filepath.Join(base, "fuzzingserver-run1", "cases"),
		},
		{
			Name:      "copy-fuzzingclient-run1",
			Role:      RoleServer,
			IndexPath: filepath.Join(base, "fuzzingclient-run1", "index.json"),
			CasesDir:  filepath.Join(base, "fuzzingclient-run1", "cases"),
		},
	}
}

// indexAgentAndCases returns the single agent key and its case map from a
// copied index, so a probe can rewrite one entry.
func indexAgentAndCases(t *testing.T, path string) (map[string]any, string, map[string]any) {
	t.Helper()
	doc := readJSONFile(t, path)
	if len(doc) != 1 {
		t.Fatalf("%s reports %d agents; this probe is stale", path, len(doc))
	}
	for agent, cases := range doc {
		byCase, ok := cases.(map[string]any)
		if !ok {
			t.Fatalf("%s: agent %q does not map to an object", path, agent)
		}
		return doc, agent, byCase
	}
	return nil, "", nil
}

// requireProblem fails unless one of the problem strings contains want.
// Matching the TEXT rather than the count is what isolates the check.
func requireProblem(t *testing.T, problems []string, want, why string) {
	t.Helper()
	for _, problem := range problems {
		if strings.Contains(problem, want) {
			return
		}
	}
	t.Errorf("no problem mentioning %q. %s\nproblems (%d): %v", want, why, len(problems), problems)
}

// requireErrorMentioning fails unless err is non-nil and names want. A
// different error is a different check firing, so the text is load-bearing.
func requireErrorMentioning(t *testing.T, err error, want, why string) {
	t.Helper()
	if err == nil {
		t.Errorf("expected a refusal mentioning %q, got none. %s", want, why)
		return
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("expected a refusal mentioning %q, got %q. %s", want, err.Error(), why)
	}
}

// requireFinding fails unless a finding with exactly this case/field exists
// and its detail names want.
func requireFinding(t *testing.T, findings []ComparisonFinding, caseID, field, want, why string) {
	t.Helper()
	for _, finding := range findings {
		if finding.CaseID == caseID && finding.Field == field && strings.Contains(finding.Detail, want) {
			return
		}
	}
	t.Errorf("no finding case=%q field=%q mentioning %q. %s\nfindings (%d): %v",
		caseID, field, want, why, len(findings), findings)
}

func devManifest(t *testing.T) *Manifest {
	t.Helper()
	manifest, err := BuildManifest(devSources(repoRoot(t)))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	return manifest
}

// ---------------------------------------------------------------------------
// Group 0 — polarity control for the whole file
// ---------------------------------------------------------------------------

// TestTheCopiedReportTreeStillExpandsAndReconciles is the polarity control
// for every probe that mutates a copy of the dev tree. Without it a probe
// could pass because the copy step broke the tree.
func TestTheCopiedReportTreeStillExpandsAndReconciles(t *testing.T) {
	base, sources := mutableTree(t)
	manifest, err := BuildManifest(sources)
	if err != nil {
		t.Fatalf("the unmutated copy does not expand, so every probe in this file "+
			"would be measuring the copier: %v", err)
	}
	if len(manifest.Cases) != SelectedCaseCount {
		t.Fatalf("the unmutated copy expanded %d cases, want %d",
			len(manifest.Cases), SelectedCaseCount)
	}
	ledger, err := Reconcile(manifest,
		filepath.Join(base, "fuzzingclient-run1", "index.json"),
		filepath.Join(base, "fuzzingclient-run1", "cases"), nil)
	if err != nil {
		t.Fatalf("Reconcile on the unmutated copy: %v", err)
	}
	if !ledger.Reconciles || ledger.Disagreements != 0 {
		t.Fatalf("the unmutated copy does not reconcile (reconciles=%t disagreements=%d: %v)",
			ledger.Reconciles, ledger.Disagreements, ledger.DisagreementDetail)
	}
}

// ---------------------------------------------------------------------------
// Group 1 — the guards whose deletion turns a stated refusal into a panic
//
// Round 3 filed these as "defensive nil/empty guards on inputs no caller
// supplies". Every one of these functions is EXPORTED, so the caller that
// supplies the input is the test below, and a panic fails a test. Each probe
// asserts the REFUSAL TEXT, so a different refusal (a later check firing) does
// not satisfy it.
// ---------------------------------------------------------------------------

func TestReconcileRefusesANilManifestRatherThanPanicking(t *testing.T) {
	root := repoRoot(t)
	_, err := Reconcile(nil, devIndex(root, "fuzzingclient-run1"), "", nil)
	requireErrorMentioning(t, err, "no manifest",
		"with this guard gone the very next statement takes len() of a nil manifest's "+
			"Cases and the gate crashes instead of reporting what it was given")
}

func TestReconcileAcceptsNilOptionsWithoutDereferencingThem(t *testing.T) {
	root := repoRoot(t)
	ledger, err := Reconcile(devManifest(t), devIndex(root, "fuzzingclient-run1"), "", nil)
	if err != nil {
		t.Fatalf("Reconcile with nil options: %v", err)
	}
	if ledger.Filtered != 0 {
		t.Errorf("nil options must mean no filtered cases, got %d", ledger.Filtered)
	}
}

func TestDiscriminateRefusesANilLedgerRatherThanPanicking(t *testing.T) {
	verdict := Discriminate(SubjectUnderTest, nil)
	if verdict.AsExpected {
		t.Error("a nil ledger must never satisfy an expectation")
	}
	if !strings.Contains(verdict.Reason, "no ledger") {
		t.Errorf("expected the reason to say there is no ledger, got %q; without this guard "+
			"the next statement reads Reconciles off a nil pointer", verdict.Reason)
	}
}

func TestCompareToBaselineRefusesANilManifestRatherThanPanicking(t *testing.T) {
	root := repoRoot(t)
	index := devIndex(root, "fuzzingclient-run1")
	_, err := CompareToBaseline(nil, RoleServer, index, index, nil)
	requireErrorMentioning(t, err, "no manifest",
		"the manifest is the denominator both indexes are read against; without it the "+
			"function reads Cases off a nil pointer")
}

func TestVerifyComparisonDocumentRefusesANilManifestRatherThanPanicking(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, filepath.FromSlash(ComparisonDocumentPath))
	mustExist(t, path)
	_, err := VerifyComparisonDocument(path, nil, nativeLegs(root))
	requireErrorMentioning(t, err, "no manifest",
		"every count in this function is compared against len(manifest.Cases)")
}

func TestVerifyRegisterAgainstLedgerReportsANilRegisterRatherThanPanicking(t *testing.T) {
	root := repoRoot(t)
	path := ledgerPath(root)
	mustExist(t, path)
	problems, err := VerifyRegisterAgainstLedger(nil, path)
	if err != nil {
		t.Fatalf("VerifyRegisterAgainstLedger: %v", err)
	}
	requireProblem(t, problems, "no register",
		"without this guard the range over register.Entries dereferences a nil pointer, so "+
			"a missing register crashes the gate instead of being reported as a problem")
}

func TestVerifyRegisterIsExactReportsANilAgreementRatherThanPanicking(t *testing.T) {
	problems := VerifyRegisterIsExact(&DivergenceRegister{}, nil)
	requireProblem(t, problems, "no agreement",
		"the agreement is what the register is checked AGAINST; without this guard the "+
			"range over agreement.Cases dereferences a nil pointer")
}

// TestVerifyRegisterIsExactSurvivesANilRegisterAndStillReportsTheDivergence
// isolates the `register != nil` arm, which is a different guard from the
// nil-agreement one above: with it gone, a nil register crashes the exactness
// check rather than reporting every observed divergence as unaccounted for.
func TestVerifyRegisterIsExactSurvivesANilRegisterAndStillReportsTheDivergence(t *testing.T) {
	agreement := &Agreement{
		Role: RoleServer,
		Cases: []CaseAgreement{{
			CaseID:           "5.15",
			Class:            AgreementSubjectWeaker,
			SubjectBehavior:  BehaviorNonStrict,
			BaselineBehavior: BehaviorOK,
		}},
	}
	problems := VerifyRegisterIsExact(nil, agreement)
	requireProblem(t, problems, "no register entry accounts for it",
		"a missing register must make every observed divergence unaccounted for, not crash")
}

// TestBuildManifestNamesTheEmptySourceListRatherThanFailingLater isolates
// `len(sources) == 0`. Deleting it does NOT make the function succeed — it
// makes it fail with the WRONG diagnosis ("no client-role source"), which
// sends a reader looking for a missing fuzzingserver report that was never
// asked for. The probe asserts the text, so the substitute refusal does not
// satisfy it.
func TestBuildManifestNamesTheEmptySourceListRatherThanFailingLater(t *testing.T) {
	_, err := BuildManifest(nil)
	requireErrorMentioning(t, err, "no report sources given",
		"an empty source list must be named as such; the fallback refusal blames a "+
			"missing client-role source instead")
}

func TestVerifyManifestIndependenceReportsANilManifestRatherThanPanicking(t *testing.T) {
	problems := VerifyManifestIndependence(nil, nil)
	requireProblem(t, problems, "no manifest",
		"without this guard the count comparison reads Cases off a nil pointer")
}

func TestVerifyManifestIndependenceSkipsANilConfigRatherThanDereferencingIt(t *testing.T) {
	problems := VerifyManifestIndependence(devManifest(t), []*SuiteConfig{nil})
	for _, problem := range problems {
		if strings.Contains(problem, "suite config ") {
			t.Errorf("a nil config must contribute no config problem, got %q", problem)
		}
		if strings.Contains(problem, "no suite configuration was supplied") {
			t.Errorf("one supplied (if nil) config is not the same as none, got %q", problem)
		}
	}
}

// ---------------------------------------------------------------------------
// Group 2 — in-package direct probes on the small helpers
//
// These tests live in the package under test, so they can call the unexported
// helpers directly. That makes them the most isolating probes available: no
// other check is between the input and the assertion.
// ---------------------------------------------------------------------------

// TestEntryForRefusesANilRegisterAndMatchesOnBothCaseAndRole isolates two
// checks inside entryFor: the nil-receiver guard and the case/role match.
func TestEntryForRefusesANilRegisterAndMatchesOnBothCaseAndRole(t *testing.T) {
	var absent *DivergenceRegister
	if got := absent.entryFor(RoleServer, "5.15"); got != nil {
		t.Errorf("a nil register must yield no entry, got %+v", got)
	}
	register := &DivergenceRegister{Entries: []DivergenceEntry{
		{CaseID: "5.15", Role: RoleServer, SubjectBehavior: BehaviorNonStrict, BaselineBehavior: BehaviorOK},
	}}
	if got := register.entryFor(RoleServer, "5.15"); got == nil {
		t.Error("the entry that is present was not found")
	}
	if got := register.entryFor(RoleServer, "1.1.1"); got != nil {
		t.Errorf("case 1.1.1 has no entry, but entryFor returned %+v; without the case/role "+
			"match every lookup answers with whatever entry is first, so any single "+
			"register entry would account for every divergence", got)
	}
	if got := register.entryFor(RoleClient, "5.15"); got != nil {
		t.Errorf("the only entry is filed against the SERVER role, but the CLIENT lookup "+
			"returned %+v", got)
	}
}

// TestSameSetComparesMultisetsNotJustLengths isolates the two checks in
// sameSet. The second one is the load-bearing half: two lists of the same
// length over the same values are not the same set.
func TestSameSetComparesMultisetsNotJustLengths(t *testing.T) {
	if sameSet([]string{"1.*"}, []string{"1.*", "2.*"}) {
		t.Error("lists of different length are not the same set")
	}
	if !sameSet([]string{"1.*", "2.*"}, []string{"2.*", "1.*"}) {
		t.Error("order must not matter")
	}
	if sameSet([]string{"1.*", "2.*"}, []string{"1.*", "1.*"}) {
		t.Error("{1.*,2.*} and {1.*,1.*} have the same length and are NOT the same set; " +
			"without the negative-count check a manifest could declare one family twice " +
			"and drop another, and the frozen-policy comparison would accept it")
	}
}

// TestFamilyOfCutsAtTheFirstSeparator isolates the '.' scan in familyOf.
// Without it every case identity is its own family, so the
// declared-nonselected check compares "12.1.1.*" against "12.*" and never
// matches.
func TestFamilyOfCutsAtTheFirstSeparator(t *testing.T) {
	for input, want := range map[string]string{
		"1.1.1":  "1",
		"10.1.1": "10",
		"7.9.6":  "7",
		"5.15":   "5",
	} {
		if got := familyOf(input); got != want {
			t.Errorf("familyOf(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestTheDivergenceSuffixIsEmptyWhenNothingDiverges isolates the
// early-return in divergenceSuffix. Without it the verdict reason ends in a
// dangling "; " on every clean comparison.
func TestTheDivergenceSuffixIsEmptyWhenNothingDiverges(t *testing.T) {
	if got := divergenceSuffix(&Agreement{}); got != "" {
		t.Errorf("an agreement with no divergence detail must add no suffix, got %q", got)
	}
	if got := divergenceSuffix(&Agreement{DivergenceDetail: []string{"5.15: subject=NON-STRICT"}}); got == "" {
		t.Error("a real divergence detail must be carried into the reason")
	}
}

// ---------------------------------------------------------------------------
// Group 3 — every reader must name WHICH read or parse failed
//
// Round 3 did not sweep these as a class. Each is isolating because the read
// refusal and the parse refusal of the same file carry different text:
// deleting the read check leaves a parse failure on nil bytes, and deleting
// the parse check leaves a zero-valued document and no refusal at all.
// ---------------------------------------------------------------------------

func TestEveryReaderNamesItsOwnReadAndParseFailure(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.json")
	if err := os.WriteFile(garbage, []byte("this is not json"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	missing := filepath.Join(dir, "does-not-exist.json")
	manifest := devManifest(t)

	for _, testCase := range []struct {
		name      string
		call      func(path string) error
		wantRead  string
		wantParse string
	}{
		{
			name:      "the behavior-delta ledger index",
			call:      func(path string) error { _, err := ReadLedgerIndex(path); return err },
			wantRead:  "read behavior-delta ledger",
			wantParse: "parse behavior-delta ledger",
		},
		{
			name:      "the divergence register",
			call:      func(path string) error { _, err := ReadDivergenceRegister(path); return err },
			wantRead:  "read divergence register",
			wantParse: "parse divergence register",
		},
		{
			name:      "the suite config",
			call:      func(path string) error { _, err := ReadSuiteConfig(path); return err },
			wantRead:  "read suite config",
			wantParse: "parse suite config",
		},
		{
			name: "the behavior-delta ledger read by the register verifier",
			call: func(path string) error {
				_, err := VerifyRegisterAgainstLedger(&DivergenceRegister{}, path)
				return err
			},
			wantRead:  "read behavior-delta ledger",
			wantParse: "parse behavior-delta ledger",
		},
		{
			name: "the comparison document",
			call: func(path string) error {
				_, err := VerifyComparisonDocument(path, manifest, nativeLegs(root))
				return err
			},
			wantRead:  "read comparison document",
			wantParse: "parse comparison document",
		},
		{
			name: "a wstest report index",
			call: func(path string) error {
				_, err := Reconcile(manifest, path, "", nil)
				return err
			},
			wantRead:  "read index",
			wantParse: "parse index",
		},
	} {
		t.Run(testCase.name+" (absent file)", func(t *testing.T) {
			requireErrorMentioning(t, testCase.call(missing), testCase.wantRead,
				"an unreadable input must be named as unreadable; without the read check the "+
					"bytes are nil and the reader blames the PARSE instead, which sends a "+
					"reader looking for malformed content that was never there")
		})
		t.Run(testCase.name+" (malformed file)", func(t *testing.T) {
			requireErrorMentioning(t, testCase.call(garbage), testCase.wantParse,
				"without the parse check the decode error is discarded and the reader "+
					"returns a zero-valued document as though the file said nothing")
		})
	}
}

// TestTheLedgerIndexOnlyIndexesAutobahnRefsThatNameACase isolates the two
// filters in ReadLedgerIndex's ref loop. A ledger record cites many kinds of
// reference; only `autobahn-<version>:<case>` binds a case.
func TestTheLedgerIndexOnlyIndexesAutobahnRefsThatNameACase(t *testing.T) {
	dir := t.TempDir()
	forged := filepath.Join(dir, "ledger.json")
	writeJSONFile(t, forged, map[string]any{
		"records": []any{map[string]any{
			"sequence": 1,
			"delta": map[string]any{
				"delta_id":    "DIV-TEST",
				"disposition": "ACCEPTED",
				"autobahn_refs": []any{
					"rfc6455:section-5.5.1", // not an autobahn ref at all
					"autobahn-0.8.2",        // an autobahn ref that names no case
					"autobahn-0.8.2:",       // an autobahn ref with an empty case
					"autobahn-0.8.2:5.15",   // the only one that binds a case
				},
			},
		}},
	})
	index, err := ReadLedgerIndex(forged)
	if err != nil {
		t.Fatalf("ReadLedgerIndex: %v", err)
	}
	if _, bound := index.ByCase["5.15"]; !bound {
		t.Fatalf("the well-formed ref did not bind its case; index=%v", index.ByCase)
	}
	if len(index.ByCase) != 1 {
		t.Errorf("only the well-formed autobahn ref names a case, so exactly one binding is "+
			"expected; got %d: %v. Without the prefix filter a non-Autobahn reference such as "+
			"rfc6455:section-5.5.1 is indexed as though it were an Autobahn case, and without "+
			"the empty-case filter a bare version string binds the empty case id",
			len(index.ByCase), index.ByCase)
	}
	if _, bound := index.ByCase["section-5.5.1"]; bound {
		t.Error("an rfc6455 reference was indexed as an Autobahn case")
	}
	if _, bound := index.ByCase[""]; bound {
		t.Error("an autobahn ref with no case bound the empty case id")
	}
}

// ---------------------------------------------------------------------------
// Group 4 — the reconciliation's control-flow selectors
//
// Round 3 filed these as "whole-feature control-flow selectors: disabling one
// skips a feature wholesale and no test notices". That is exactly what a probe
// is for. Each of these asserts the OBSERVABLE the feature produces.
// ---------------------------------------------------------------------------

// TestTimedOutIsReportedUnavailableRatherThanZeroWhenNoCasesDirectoryIsGiven
// isolates `casesDir == ""`. Zero and unavailable are different claims: zero
// says the run had no timeouts, unavailable says nobody looked. The ledger is
// published evidence, so the difference is the whole point of the field.
func TestTimedOutIsReportedUnavailableRatherThanZeroWhenNoCasesDirectoryIsGiven(t *testing.T) {
	root := repoRoot(t)
	ledger, err := Reconcile(devManifest(t), devIndex(root, "fuzzingclient-run1"), "", nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if ledger.TimedOut != -1 {
		t.Errorf("with no cases directory the timeout overlay cannot be read, so TimedOut must "+
			"be -1 (unavailable); got %d, which is a positive claim that the run timed out "+
			"zero times", ledger.TimedOut)
	}
}

// TestThePerCaseReportsAreActuallyReadWhenACasesDirectoryIsGiven isolates the
// selector that reads them at all.
func TestThePerCaseReportsAreActuallyReadWhenACasesDirectoryIsGiven(t *testing.T) {
	root := repoRoot(t)
	ledger, err := Reconcile(devManifest(t), devIndex(root, "fuzzingclient-run1"),
		devCases(root, "fuzzingclient-run1"), nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if ledger.CaseReportCount != SelectedCaseCount {
		t.Errorf("a cases directory was given and holds %d reports, but the ledger counted %d; "+
			"if the directory is never read every cross-source check below it is inert",
			SelectedCaseCount, ledger.CaseReportCount)
	}
	if ledger.TimedOut == -1 {
		t.Error("a cases directory was given, so the timeout overlay is available and " +
			"TimedOut must not be reported unavailable")
	}
}

// TestAFilteredCaseIsCountedFilteredAndNotMissing isolates the filter arm.
// Without it an explicitly filtered case is walked like any other and lands
// in whatever bucket the index puts it in, so the Filtered dimension — which
// the scope identity is built on — is always zero.
func TestAFilteredCaseIsCountedFilteredAndNotMissing(t *testing.T) {
	root := repoRoot(t)
	ledger, err := Reconcile(devManifest(t), devIndex(root, "fuzzingclient-run1"), "",
		&Options{FilteredCases: []string{"1.1.1"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if ledger.Filtered != 1 {
		t.Errorf("one case was explicitly filtered, so Filtered must be 1; got %d", ledger.Filtered)
	}
	if ledger.Executed != SelectedCaseCount-1 {
		t.Errorf("a filtered case must not also be executed: executed=%d, want %d",
			ledger.Executed, SelectedCaseCount-1)
	}
	if ledger.Selected != SelectedCaseCount-1 {
		t.Errorf("selected = expected - filtered must be %d, got %d",
			SelectedCaseCount-1, ledger.Selected)
	}
}

// TestTheDisagreementDetailIsCappedWhileTheCountStaysExact isolates the
// maxDetail cap, whose own comment claims both halves: that a wholly
// mismatched pair cannot produce a multi-megabyte ledger, and that the COUNT
// is always exact. Nothing checked either.
func TestTheDisagreementDetailIsCappedWhileTheCountStaysExact(t *testing.T) {
	root := repoRoot(t)
	src := devCases(root, "fuzzingclient-run1")
	dst := t.TempDir()
	names, err := filepath.Glob(filepath.Join(src, "*.json"))
	if err != nil || len(names) == 0 {
		t.Fatalf("glob %s: %v (%d names)", src, err, len(names))
	}
	// Every report refiled under another agent. Each one yields exactly one
	// disagreement, so the expected count is known exactly.
	for _, name := range names {
		doc := readJSONFile(t, name)
		doc["agent"] = "some-other-agent"
		writeJSONFile(t, filepath.Join(dst, filepath.Base(name)), doc)
	}
	ledger, err := Reconcile(devManifest(t), devIndex(root, "fuzzingclient-run1"), dst, nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if ledger.Disagreements != len(names) {
		t.Fatalf("every one of the %d reports was refiled under another agent, so the count "+
			"must be exactly %d; got %d", len(names), len(names), ledger.Disagreements)
	}
	if len(ledger.DisagreementDetail) != 20 {
		t.Errorf("the detail list must be capped at 20 while the count stays at %d; got %d "+
			"detail entries. Without the cap a wholly mismatched pair of directories writes "+
			"one line per case into published evidence",
			ledger.Disagreements, len(ledger.DisagreementDetail))
	}
}

// TestEachTimeoutFlagIsCountedOnItsOwnAxisAndOverlaid isolates the three
// per-flag counters and, separately, the overlay that unions them. Deleting a
// counter leaves the overlay right and the axis wrong; deleting the overlay
// leaves the axes right and TimedOut wrong. No single deletion satisfies every
// assertion in any subtest.
//
// The assertions are DELTAS against the unmutated report, measured here and
// not assumed: the committed dev fuzzingclient run already carries 32
// `wasServerConnectionDropTimeout` cases, so an absolute expectation of 1
// would have been measuring that fact rather than the counter. Case 1.1.1
// carries no timeout flag of any kind, which is asserted below so the probe
// cannot go quietly stale if the fixture changes.
func TestEachTimeoutFlagIsCountedOnItsOwnAxisAndOverlaid(t *testing.T) {
	root := repoRoot(t)
	clean := copyCases(t, devCases(root, "fuzzingclient-run1"), "", nil)
	before, err := Reconcile(devManifest(t), devIndex(root, "fuzzingclient-run1"), clean, nil)
	if err != nil {
		t.Fatalf("Reconcile the unmutated copy: %v", err)
	}
	for _, name := range before.TimedOutCases {
		if name == "1.1.1" {
			t.Fatal("case 1.1.1 already carries a timeout flag in the committed report; " +
				"this probe needs a case that does not, and is stale")
		}
	}
	for _, testCase := range []struct {
		flag string
		read func(*Ledger) int
		axis string
	}{
		{"wasOpenHandshakeTimeout", func(l *Ledger) int { return l.OpenHandshakeTimeouts }, "OpenHandshakeTimeouts"},
		{"wasCloseHandshakeTimeout", func(l *Ledger) int { return l.CloseHandshakeTimeouts }, "CloseHandshakeTimeouts"},
		{"wasServerConnectionDropTimeout", func(l *Ledger) int { return l.ConnectionDropTimeouts }, "ConnectionDropTimeouts"},
	} {
		t.Run(testCase.flag, func(t *testing.T) {
			dir := copyCases(t, devCases(root, "fuzzingclient-run1"), "1.1.1",
				func(doc map[string]any) { doc[testCase.flag] = true })
			after, err := Reconcile(devManifest(t), devIndex(root, "fuzzingclient-run1"), dir, nil)
			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if got, want := testCase.read(after), testCase.read(before)+1; got != want {
				t.Errorf("case 1.1.1 now reports %s, so %s must rise from %d to %d; got %d. "+
					"An uncounted timeout axis is a run that stalled and published nothing "+
					"about it", testCase.flag, testCase.axis, testCase.read(before), want, got)
			}
			if got, want := after.TimedOut, before.TimedOut+1; got != want {
				t.Errorf("one more case timed out, so the TimedOut overlay must rise from %d "+
					"to %d; got %d. Without the overlay the three axes can each be non-zero "+
					"while the published overlay says nothing timed out",
					before.TimedOut, want, got)
			}
			named := false
			for _, name := range after.TimedOutCases {
				if name == "1.1.1" {
					named = true
				}
			}
			if !named {
				t.Errorf("the newly timed-out case must be named; got %v", after.TimedOutCases)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Group 5 — the manifest expansion's refusals
//
// Round 3 filed most of these as "checks carrying a claim that no probe
// reaches". Each is reached below by rewriting ONE field of a committed
// report. Where deleting a check substitutes a DIFFERENT refusal rather than
// no refusal, the probe asserts the text, so the substitute does not satisfy
// it — a wrong diagnosis is a wrong diagnosis.
// ---------------------------------------------------------------------------

func TestAnIndexReportingMoreThanOneAgentIsRefused(t *testing.T) {
	base, _ := mutableTree(t)
	path := filepath.Join(base, "fuzzingclient-run1", "index.json")
	doc, _, byCase := indexAgentAndCases(t, path)
	doc["a-second-agents-run"] = byCase
	writeJSONFile(t, path, doc)
	_, err := Reconcile(devManifest(t), path, "", nil)
	requireErrorMentioning(t, err, "want exactly 1",
		"an index carrying two agents' runs has no single agent to attribute the report to; "+
			"without this check readIndex returns whichever the map iterates first, so the "+
			"agent a gate pins is chosen at random from run to run")
}

func TestACaseReportWithNoUsableIdOrOrdinalIsRefused(t *testing.T) {
	root := repoRoot(t)
	for _, testCase := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"the id is blank", func(doc map[string]any) { doc["id"] = "" }},
		{"the ordinal is zero", func(doc map[string]any) { doc["case"] = float64(0) }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			dir := copyCases(t, devCases(root, "fuzzingclient-run1"), "1.1.1", testCase.mutate)
			_, err := Reconcile(devManifest(t), devIndex(root, "fuzzingclient-run1"), dir, nil)
			requireErrorMentioning(t, err, "no usable id/case binding",
				"a report with no id/ordinal binding cannot be attributed to a case; without "+
					"this check it is filed under the empty case id and the case it really "+
					"describes silently loses its report")
		})
	}
}

func TestOneCaseIdBoundToTwoOrdinalsIsRefused(t *testing.T) {
	root := repoRoot(t)
	// Case 1.1.2's report relabelled as 1.1.1. Both files now claim the same
	// case at two different ordinals, which is the shape a merged pair of
	// directories takes.
	dir := copyCases(t, devCases(root, "fuzzingclient-run1"), "1.1.2",
		func(doc map[string]any) { doc["id"] = "1.1.1" })
	_, err := Reconcile(devManifest(t), devIndex(root, "fuzzingclient-run1"), dir, nil)
	requireErrorMentioning(t, err, "bound to both ordinal",
		"without this check the second report silently overwrites the first and the "+
			"directory reports 246 distinct cases as though it held 247")
}

func TestACasesDirectoryWithNoReportsIsRefused(t *testing.T) {
	root := repoRoot(t)
	_, err := Reconcile(devManifest(t), devIndex(root, "fuzzingclient-run1"), t.TempDir(), nil)
	requireErrorMentioning(t, err, "no case reports under",
		"an empty cases directory must be refused outright; without this check it is treated "+
			"as a directory that merely disagrees with the index, and the run's own "+
			"per-case evidence being absent is reported as 247 ordinary disagreements")
}

// TestASourceWhoseIndexAndReportCountsDifferIsRefusedByCount isolates the
// count comparison. Deleting it does not make the expansion succeed — it
// makes it blame a single named case instead of the count, which is a
// different and less accurate diagnosis, so the probe asserts the text.
func TestASourceWhoseIndexAndReportCountsDifferIsRefusedByCount(t *testing.T) {
	base, sources := mutableTree(t)
	victim := filepath.Join(base, "fuzzingclient-run1", "cases",
		"verified_rust_ws_testee_us019_case_1_1_1.json")
	mustExist(t, victim)
	if err := os.Remove(victim); err != nil {
		t.Fatalf("remove %s: %v", victim, err)
	}
	_, err := BuildManifest(sources)
	requireErrorMentioning(t, err, "case reports exist",
		"the index and the per-case reports are two renderings of one run; a count mismatch "+
			"is the cheapest possible evidence that one of them came from somewhere else")
}

// TestASourceWhoseIndexNamesACaseWithNoReportIsRefused isolates the per-case
// lookup. The counts are kept EQUAL so the count check above cannot fire:
// one report is relabelled to a case identity the index does not list, which
// leaves 247 reports for 247 index entries and one entry with nothing behind
// it.
func TestASourceWhoseIndexNamesACaseWithNoReportIsRefused(t *testing.T) {
	base, sources := mutableTree(t)
	victim := filepath.Join(base, "fuzzingclient-run1", "cases",
		"verified_rust_ws_testee_us019_case_1_1_1.json")
	mustExist(t, victim)
	doc := readJSONFile(t, victim)
	doc["id"] = "1.1.1-relabelled"
	writeJSONFile(t, victim, doc)
	_, err := BuildManifest(sources)
	requireErrorMentioning(t, err, "has no report",
		"without this lookup the missing report is read as a zero value, so the case is "+
			"expanded with suite case number 0 and the manifest carries an ordinal no run "+
			"ever produced")
}

// TestEverySourceMustCoverTheIdenticalCaseSet isolates the union comparison.
func TestEverySourceMustCoverTheIdenticalCaseSet(t *testing.T) {
	base, sources := mutableTree(t)
	// Drop case 1.1.1 from the CLIENT-role source completely — index entry and
	// per-case report — so that source is internally consistent at 246 while
	// the other still holds 247.
	index := filepath.Join(base, "fuzzingserver-run1", "index.json")
	doc, agent, byCase := indexAgentAndCases(t, index)
	if _, present := byCase["1.1.1"]; !present {
		t.Fatal("case 1.1.1 is not in the fuzzingserver index; this probe is stale")
	}
	delete(byCase, "1.1.1")
	doc[agent] = byCase
	writeJSONFile(t, index, doc)
	names, err := filepath.Glob(filepath.Join(base, "fuzzingserver-run1", "cases", "*case_1_1_1.json"))
	if err != nil || len(names) != 1 {
		t.Fatalf("glob for the 1.1.1 report: %v (%d names)", err, len(names))
	}
	if err := os.Remove(names[0]); err != nil {
		t.Fatalf("remove %s: %v", names[0], err)
	}
	_, err = BuildManifest(sources)
	requireErrorMentioning(t, err, "sources must agree exactly",
		"the manifest is a fixed expectation both roles must have covered; without this the "+
			"union is silently taken and a case only one role ran is expanded as though "+
			"both had")
}

func TestAManifestNeedsBothARoleThatNumbersAndARoleThatOrdinals(t *testing.T) {
	_, sources := mutableTree(t)
	var clientOnly, serverOnly []ReportSource
	for _, source := range sources {
		if source.Role == RoleClient {
			clientOnly = append(clientOnly, source)
		} else {
			serverOnly = append(serverOnly, source)
		}
	}
	if len(clientOnly) != 1 || len(serverOnly) != 1 {
		t.Fatalf("expected one source per role, got %d client and %d server",
			len(clientOnly), len(serverOnly))
	}
	_, err := BuildManifest(serverOnly)
	requireErrorMentioning(t, err, "no client-role (fuzzingserver) source",
		"the selected-set ordinal /runCase addresses comes only from a client-role run; "+
			"without it the manifest carries ordinals nothing sourced")
	_, err = BuildManifest(clientOnly)
	requireErrorMentioning(t, err, "no server-role (fuzzingclient) source",
		"the absolute suite case number comes only from a server-role run")
}

// TestACaseFromADeclaredNonselectedFamilyIsRefused isolates the
// nonselected-family check. Both sources gain a well-formed 12.1.1 record, so
// every count check still balances at 248 and only the family check can see
// it. Deleting that check substitutes the pinned-count refusal, so the probe
// asserts the text.
func TestACaseFromADeclaredNonselectedFamilyIsRefused(t *testing.T) {
	base, sources := mutableTree(t)
	const intruder = "12.1.1"
	for ordinal, run := range map[int]string{900: "fuzzingserver-run1", 901: "fuzzingclient-run1"} {
		index := filepath.Join(base, run, "index.json")
		doc, agent, byCase := indexAgentAndCases(t, index)
		byCase[intruder] = map[string]any{
			"behavior":      string(BehaviorOK),
			"behaviorClose": string(BehaviorOK),
			"reportfile":    "intruder_case_12_1_1.json",
		}
		doc[agent] = byCase
		writeJSONFile(t, index, doc)
		writeJSONFile(t, filepath.Join(base, run, "cases", "intruder_case_12_1_1.json"),
			map[string]any{
				"id": intruder, "case": ordinal, "agent": agent, "behavior": string(BehaviorOK),
			})
	}
	_, err := BuildManifest(sources)
	requireErrorMentioning(t, err, "declared-nonselected family",
		"12.* is compression, which the port implements nothing of; a case from it appearing "+
			"in the manifest means the run was launched against a different selection than "+
			"the frozen policy declares")
}

// TestTheExpandedCaseCountMustBeThePinnedCount isolates the final count.
// Both sources lose the same case, so every other check balances and only the
// pinned count can see that the suite selection moved.
func TestTheExpandedCaseCountMustBeThePinnedCount(t *testing.T) {
	base, sources := mutableTree(t)
	for _, run := range []string{"fuzzingserver-run1", "fuzzingclient-run1"} {
		index := filepath.Join(base, run, "index.json")
		doc, agent, byCase := indexAgentAndCases(t, index)
		if _, present := byCase["1.1.1"]; !present {
			t.Fatalf("case 1.1.1 is not in %s; this probe is stale", index)
		}
		delete(byCase, "1.1.1")
		doc[agent] = byCase
		writeJSONFile(t, index, doc)
		names, err := filepath.Glob(filepath.Join(base, run, "cases", "*case_1_1_1.json"))
		if err != nil || len(names) != 1 {
			t.Fatalf("glob for the 1.1.1 report in %s: %v (%d names)", run, err, len(names))
		}
		if err := os.Remove(names[0]); err != nil {
			t.Fatalf("remove %s: %v", names[0], err)
		}
	}
	_, err := BuildManifest(sources)
	requireErrorMentioning(t, err, fmt.Sprintf("want the pinned %d", SelectedCaseCount),
		"the manifest is the denominator every later count divides by; a manifest that quietly "+
			"expands 246 cases moves the denominator, which is precisely what must never happen")
}

// ---------------------------------------------------------------------------
// Group 6 — the committed comparison document, one finding at a time
//
// The tree already had `TestATamperedComparisonDocumentIsRefused`. It asserts
// only `len(findings) == 0`, so whichever check fires first satisfies it and
// every other check in VerifyComparisonDocument survives deletion. Every
// probe below asserts the exact (case, field) of the finding it is about.
// ---------------------------------------------------------------------------

// forgeComparison writes the committed comparison document with one mutation
// applied and returns the forged path.
func forgeComparison(t *testing.T, mutate func(*testing.T, map[string]any)) string {
	t.Helper()
	root := repoRoot(t)
	path := filepath.Join(root, filepath.FromSlash(ComparisonDocumentPath))
	mustExist(t, path)
	document := readJSONFile(t, path)
	mutate(t, document)
	forged := filepath.Join(t.TempDir(), "comparison.json")
	writeJSONFile(t, forged, document)
	return forged
}

func verifyForged(t *testing.T, forged string) []ComparisonFinding {
	t.Helper()
	root := repoRoot(t)
	findings, err := VerifyComparisonDocument(forged, devManifest(t), nativeLegs(root))
	if err != nil {
		t.Fatalf("VerifyComparisonDocument: %v", err)
	}
	return findings
}

// TestTheUnforgedComparisonDocumentProducesNoFinding is the polarity control
// for this group.
func TestTheUnforgedComparisonDocumentProducesNoFinding(t *testing.T) {
	findings := verifyForged(t, forgeComparison(t, func(*testing.T, map[string]any) {}))
	if len(findings) != 0 {
		t.Fatalf("the re-encoded but unmutated document already has findings, so every probe "+
			"in this group would be measuring the encoder: %v", findings)
	}
}

func TestTheDocumentsExpectedCountMustBeTheManifestsCount(t *testing.T) {
	forged := forgeComparison(t, func(t *testing.T, document map[string]any) {
		document["expected_case_count"] = float64(246)
	})
	requireFinding(t, verifyForged(t, forged), "", "expected_case_count", "the manifest holds",
		"the document's own statement of the denominator must be the manifest's; a document "+
			"that declares a different expected count is describing a different suite selection")
}

func TestTheDocumentsComparedCountMustMatchItsOwnRows(t *testing.T) {
	forged := forgeComparison(t, func(t *testing.T, document map[string]any) {
		document["compared_case_count"] = float64(246)
	})
	requireFinding(t, verifyForged(t, forged), "", "compared_case_count", "carries",
		"a document whose summary count disagrees with its own row count has had rows "+
			"added or removed after the summary was written")
}

// TestTheDocumentMustCarryARowForEveryManifestCase isolates the row-count
// check from the per-case omission finding it fires alongside. Both use the
// field name "cases"; only the row-count finding carries an EMPTY case id,
// and compared_case_count is corrected in the same forgery so that check
// cannot fire instead.
func TestTheDocumentMustCarryARowForEveryManifestCase(t *testing.T) {
	forged := forgeComparison(t, func(t *testing.T, document map[string]any) {
		rows, ok := document["cases"].([]any)
		if !ok || len(rows) == 0 {
			t.Fatal("the document carries no rows; this probe is stale")
		}
		document["cases"] = rows[1:]
		document["compared_case_count"] = float64(len(rows) - 1)
	})
	requireFinding(t, verifyForged(t, forged), "", "cases", "rows for a",
		"a document with fewer rows than the manifest has cases is not a comparison of the "+
			"manifest; without this check only the individual omissions are reported and the "+
			"document's shape is never questioned")
}

func TestAManifestCaseTheDocumentOmitsIsNamed(t *testing.T) {
	var omitted string
	forged := forgeComparison(t, func(t *testing.T, document map[string]any) {
		rows, ok := document["cases"].([]any)
		if !ok || len(rows) == 0 {
			t.Fatal("the document carries no rows; this probe is stale")
		}
		first, ok := rows[0].(map[string]any)
		if !ok {
			t.Fatal("a row is not an object; this probe is stale")
		}
		omitted, _ = first["case_id"].(string)
		if omitted == "" {
			t.Fatal("the first row has no case_id; this probe is stale")
		}
		document["cases"] = rows[1:]
		document["compared_case_count"] = float64(len(rows) - 1)
	})
	requireFinding(t, verifyForged(t, forged), omitted, "cases", "omits it",
		"the omitted case must be named; a count finding alone tells a reader that something "+
			"is missing but never which case stopped being compared")
}

func TestTheDocumentsAgentNamesMustBeTheAgentsTheIndexesAreFiledUnder(t *testing.T) {
	forged := forgeComparison(t, func(t *testing.T, document map[string]any) {
		agents, ok := document["agents"].(map[string]any)
		if !ok {
			t.Fatal("the document carries no agents map; this probe is stale")
		}
		agents["java_client_role"] = "verified-rust-ws-testee-us019"
	})
	requireFinding(t, verifyForged(t, forged), "", "agents.java_client_role", "is filed under",
		"the agent name is what says WHICH implementation produced a column; relabelling the "+
			"Java leg as the Rust one turns a cross-implementation comparison into a "+
			"comparison of a run with itself, and nothing else in the document would show it")
}

func TestARowWithNoCaseIdIsReported(t *testing.T) {
	forged := forgeComparison(t, func(t *testing.T, document map[string]any) {
		rows, ok := document["cases"].([]any)
		if !ok || len(rows) == 0 {
			t.Fatal("the document carries no rows; this probe is stale")
		}
		first, ok := rows[0].(map[string]any)
		if !ok {
			t.Fatal("a row is not an object; this probe is stale")
		}
		first["case_id"] = ""
	})
	requireFinding(t, verifyForged(t, forged), "", "case_id", "carries no case_id",
		"a row with no identity is compared against nothing; without this it is silently "+
			"dropped from the row map and only shows up as the case it should have been "+
			"going missing")
}

func TestADuplicatedCaseRowIsReported(t *testing.T) {
	var duplicated string
	forged := forgeComparison(t, func(t *testing.T, document map[string]any) {
		rows, ok := document["cases"].([]any)
		if !ok || len(rows) < 2 {
			t.Fatal("the document carries fewer than two rows; this probe is stale")
		}
		first, ok := rows[0].(map[string]any)
		if !ok {
			t.Fatal("a row is not an object; this probe is stale")
		}
		duplicated, _ = first["case_id"].(string)
		second, ok := rows[1].(map[string]any)
		if !ok {
			t.Fatal("a row is not an object; this probe is stale")
		}
		// The SECOND row relabelled as the first. The row count is unchanged,
		// so no count check can fire in place of the duplicate check.
		second["case_id"] = duplicated
	})
	requireFinding(t, verifyForged(t, forged), duplicated, "case_id", "twice",
		"two rows for one case means one of them describes a case that has quietly lost its "+
			"row; without this check the second silently overwrites the first")
}

func TestARowMayNotRestateTheManifestsStrictPassRequirement(t *testing.T) {
	var target string
	forged := forgeComparison(t, func(t *testing.T, document map[string]any) {
		rows, ok := document["cases"].([]any)
		if !ok || len(rows) == 0 {
			t.Fatal("the document carries no rows; this probe is stale")
		}
		first, ok := rows[0].(map[string]any)
		if !ok {
			t.Fatal("a row is not an object; this probe is stale")
		}
		target, _ = first["case_id"].(string)
		if required, ok := first["strict_pass_required"].(bool); !ok || !required {
			t.Fatalf("row %q does not declare strict_pass_required true; this probe is stale", target)
		}
		first["strict_pass_required"] = false
	})
	requireFinding(t, verifyForged(t, forged), target, "strict_pass_required", "manifest says",
		"the document may not relax the manifest's own requirement on a case; a row that "+
			"declares a strict-pass case optional is a licence written into the evidence")
}

// TestADifferenceMissingFromTheSummaryListIsReported isolates the
// differs-but-not-listed arm.
func TestADifferenceMissingFromTheSummaryListIsReported(t *testing.T) {
	forged := forgeComparison(t, func(t *testing.T, document map[string]any) {
		differences, ok := document["behavior_differences"].(map[string]any)
		if !ok {
			t.Fatal("the document carries no behavior_differences; this probe is stale")
		}
		listed, ok := differences["client_role"].([]any)
		if !ok || len(listed) == 0 {
			t.Fatal("the client-role difference list is already empty; this probe is stale")
		}
		differences["client_role"] = []any{}
	})
	requireFinding(t, verifyForged(t, forged), "5.15", "behavior_differences.client_role",
		"the difference list omits the case",
		"the summary list is what a reader reads instead of 247 rows; a real difference "+
			"missing from it is the summary being narrative beside the data")
}

// TestASummaryListEntryThatNamesAnAgreeingCaseIsReported isolates the
// listed-but-does-not-differ arm, which is the OTHER direction and which
// nothing reached: the existing tamper table only ever empties the list.
func TestASummaryListEntryThatNamesAnAgreeingCaseIsReported(t *testing.T) {
	forged := forgeComparison(t, func(t *testing.T, document map[string]any) {
		differences, ok := document["behavior_differences"].(map[string]any)
		if !ok {
			t.Fatal("the document carries no behavior_differences; this probe is stale")
		}
		listed, ok := differences["client_role"].([]any)
		if !ok {
			t.Fatal("the client-role difference list is not a list; this probe is stale")
		}
		differences["client_role"] = append(listed, "1.1.1(rust=OK java=OK)")
	})
	requireFinding(t, verifyForged(t, forged), "1.1.1", "behavior_differences.client_role",
		"the difference list names the case but the row states",
		"a summary that invents a difference is as wrong as one that hides a difference, and "+
			"an over-long list is how a genuine residual gets lost among noise")
}

// ---------------------------------------------------------------------------
// Group 7 — the comparison's own bookkeeping and the independence bindings
// ---------------------------------------------------------------------------

// TestAnUnobservedCaseCarriesWhicheverSideDidRunIt isolates the two
// `subjectRan` / `baselineRan` arms. A case only one run scored is
// Unobserved, and the class alone loses WHICH side was silent — which is the
// difference between "the port did not run it" and "the baseline did not".
func TestAnUnobservedCaseCarriesWhicheverSideDidRunIt(t *testing.T) {
	base, _ := mutableTree(t)
	// The baseline index loses case 1.1.1; the subject index keeps it.
	baseline := filepath.Join(base, "fuzzingclient-run1", "index.json")
	doc, agent, byCase := indexAgentAndCases(t, baseline)
	if _, present := byCase["1.1.1"]; !present {
		t.Fatal("case 1.1.1 is not in the index; this probe is stale")
	}
	delete(byCase, "1.1.1")
	doc["a-different-baseline-agent"] = byCase
	delete(doc, agent)
	writeJSONFile(t, baseline, doc)

	root := repoRoot(t)
	agreement, err := CompareToBaseline(devManifest(t), RoleServer,
		devIndex(root, "fuzzingclient-run1"), baseline, nil)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	var row CaseAgreement
	for _, candidate := range agreement.Cases {
		if candidate.CaseID == "1.1.1" {
			row = candidate
		}
	}
	if row.Class != AgreementUnobserved {
		t.Fatalf("case 1.1.1 was scored by only one run, so it must be Unobserved; got %q", row.Class)
	}
	if row.SubjectBehavior == "" {
		t.Error("the SUBJECT ran this case, so its observed behavior must be carried; without " +
			"the subjectRan arm an unobserved row reports nothing about the side that did run")
	}
	if row.BaselineBehavior != "" {
		t.Errorf("the baseline did NOT run this case, so its behavior must be empty; got %q",
			row.BaselineBehavior)
	}
	// And the mirror, so the baselineRan arm is exercised too.
	mirror, err := CompareToBaseline(devManifest(t), RoleServer,
		baseline, devIndex(root, "fuzzingclient-run1"), nil)
	if err != nil {
		t.Fatalf("CompareToBaseline (mirrored): %v", err)
	}
	for _, candidate := range mirror.Cases {
		if candidate.CaseID != "1.1.1" {
			continue
		}
		if candidate.BaselineBehavior == "" {
			t.Error("with the runs swapped the BASELINE ran this case, so its observed " +
				"behavior must be carried; without the baselineRan arm it is lost")
		}
		if candidate.SubjectBehavior != "" {
			t.Errorf("the subject did not run this case; got %q", candidate.SubjectBehavior)
		}
	}
}

// TestEverySelectedFamilyMustBeRepresentedInTheManifest isolates the
// family-representation check in VerifyManifestIndependence. Round 3 filed
// it among the checks "carrying a claim that no probe reaches"; the claim in
// its own comment is that a policy naming eight families and a manifest
// covering six is a selection the runs narrowed on their own.
func TestEverySelectedFamilyMustBeRepresentedInTheManifest(t *testing.T) {
	manifest := devManifest(t)
	narrowed := *manifest
	narrowed.Cases = nil
	dropped := 0
	for _, entry := range manifest.Cases {
		if strings.HasPrefix(entry.CaseID, "10.") {
			dropped++
			continue
		}
		narrowed.Cases = append(narrowed.Cases, entry)
	}
	if dropped == 0 {
		t.Fatal("the manifest holds no 10.* case; this probe is stale")
	}
	problems := VerifyManifestIndependence(&narrowed, nil)
	requireProblem(t, problems, "selects family 10.* and the manifest holds no case from it",
		"a family the frozen policy selects and the manifest covers nothing of is a "+
			"selection the runs narrowed on their own; the case-count check alone cannot "+
			"see it, because a manifest can be short by the right number for another reason")
}

// TestTheManifestsDeclaredFamiliesMustBeTheFrozenPolicysExactly isolates the
// multiset comparison at the call site, which is the only place a
// same-length-different-multiset declaration can be caught.
func TestTheManifestsDeclaredFamiliesMustBeTheFrozenPolicysExactly(t *testing.T) {
	manifest := devManifest(t)
	restated := *manifest
	restated.SelectedFamilies = append([]string(nil), manifest.SelectedFamilies...)
	if len(restated.SelectedFamilies) < 2 {
		t.Fatal("the policy names fewer than two families; this probe is stale")
	}
	// Same LENGTH, different SET: the last family restated as the first.
	restated.SelectedFamilies[len(restated.SelectedFamilies)-1] = restated.SelectedFamilies[0]
	problems := VerifyManifestIndependence(&restated, nil)
	requireProblem(t, problems, "declares selected families",
		"the manifest may not choose its own selection; a declaration that names one family "+
			"twice and drops another has the same length as the policy and is not the policy")
}
