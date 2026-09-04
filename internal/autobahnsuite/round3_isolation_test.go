package autobahnsuite

// round3_isolation_test.go — self-review round 3.
//
// A deletion sweep over every `if`-guarded check this branch adds to
// internal/autobahnsuite (85 sites, one `false &&` mutation at a time, the
// package suite plus internal/linkage plus cmd/autobahnsuitectl re-run after
// each) found 52 that survived deletion with nothing red. This file closes the
// ones that carry a written claim, each with a probe that isolates ONE check.
//
// Isolation is the whole difficulty and it is what round 1 got wrong twice.
// The tree already had `TestAnIndexPairedWithAnotherRunsCasesDoesNotReconcile`,
// which pairs a clean index with the negative control's case reports and
// asserts only `Disagreements != 0`. That is satisfied by whichever check
// happens to fire first, so deleting any single one of the per-case checks
// leaves it green. Each probe below changes exactly one field of one otherwise
// genuine report, and asserts on the disagreement TEXT rather than on a count,
// so that no other check can satisfy it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// devBase is the committed dev report tree these probes derive from. Nothing
// here is synthesised from scratch: every fixture is a real Autobahn report
// with a single field rewritten, so a probe cannot pass because its input was
// too unlike a real run to reach the check.
func devBase(root string) string {
	return filepath.Join(root, "evidence", "autobahn", "dev-aarch64-nonauthoritative")
}

// copyCases copies a real cases directory into a temp dir, applying mutate to
// the decoded JSON of the report named caseID. Returns the temp directory.
func copyCases(t *testing.T, srcDir, caseID string, mutate func(map[string]any)) string {
	t.Helper()
	dst := t.TempDir()
	names, err := filepath.Glob(filepath.Join(srcDir, "*.json"))
	if err != nil {
		t.Fatalf("glob %s: %v", srcDir, err)
	}
	if len(names) == 0 {
		t.Fatalf("no case reports under %s; this probe is stale", srcDir)
	}
	mutated := false
	for _, name := range names {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if id, _ := doc["id"].(string); id == caseID && mutate != nil {
			mutate(doc)
			mutated = true
			raw, err = json.Marshal(doc)
			if err != nil {
				t.Fatalf("marshal %s: %v", name, err)
			}
		}
		if err := os.WriteFile(filepath.Join(dst, filepath.Base(name)), raw, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if mutate != nil && !mutated {
		t.Fatalf("case %q is not present under %s; this probe is stale", caseID, srcDir)
	}
	return dst
}

// reconcileWithCases reconciles the real fuzzingclient index against the
// supplied cases directory.
func reconcileWithCases(t *testing.T, casesDir string) *Ledger {
	t.Helper()
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	ledger, err := Reconcile(manifest,
		filepath.Join(devBase(root), "fuzzingclient-run1", "index.json"), casesDir, nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return ledger
}

// requireDetail fails unless exactly the expected disagreement is present, and
// reports what was actually found. Matching the TEXT is what makes the probe
// isolating: a count would be satisfied by any other check firing.
func requireDetail(t *testing.T, ledger *Ledger, want string, why string) {
	t.Helper()
	for _, detail := range ledger.DisagreementDetail {
		if strings.Contains(detail, want) {
			return
		}
	}
	t.Errorf("no disagreement mentioning %q. %s\nDisagreements=%d, details: %v",
		want, why, ledger.Disagreements, ledger.DisagreementDetail)
}

// TestTheUnmutatedCasesDirectoryReconciles is the polarity control for every
// probe below. Without it a probe could "pass" because the copy step itself
// broke the tree, and every one of these tests would be measuring the copier.
func TestTheUnmutatedCasesDirectoryReconciles(t *testing.T) {
	root := repoRoot(t)
	clean := copyCases(t, filepath.Join(devBase(root), "fuzzingclient-run1", "cases"), "", nil)
	ledger := reconcileWithCases(t, clean)
	if ledger.Disagreements != 0 {
		t.Fatalf("the copied-but-unmutated cases directory already disagrees (%d: %v); "+
			"every probe in this file would then be measuring the copier, not its check",
			ledger.Disagreements, ledger.DisagreementDetail)
	}
	if !ledger.Reconciles {
		t.Fatal("the copied-but-unmutated cases directory does not reconcile")
	}
}

// TestTheIndexAndItsPerCaseReportMustAgreeOnBehavior isolates the check at
// reconcile.go's "index says behavior %q but its per-case report says %q".
// SWEPT AND SURVIVED before this probe existed: with that check deleted the
// whole package suite, internal/linkage and cmd/autobahnsuitectl stayed green.
func TestTheIndexAndItsPerCaseReportMustAgreeOnBehavior(t *testing.T) {
	root := repoRoot(t)
	dir := copyCases(t, filepath.Join(devBase(root), "fuzzingclient-run1", "cases"), "1.1.1",
		func(doc map[string]any) { doc["behavior"] = string(BehaviorFailed) })
	ledger := reconcileWithCases(t, dir)
	requireDetail(t, ledger, "index says behavior",
		"a per-case report whose behavior contradicts the index it is filed under is one of the "+
			"two renderings being from another run, which is exactly what this gate exists to catch")
	if ledger.Reconciles {
		t.Error("an index that contradicts its own case reports must not reconcile")
	}
}

// TestAPerCaseReportFiledUnderAnotherAgentIsRefused isolates the agent check.
// SWEPT AND SURVIVED before this probe existed.
func TestAPerCaseReportFiledUnderAnotherAgentIsRefused(t *testing.T) {
	root := repoRoot(t)
	dir := copyCases(t, filepath.Join(devBase(root), "fuzzingclient-run1", "cases"), "1.1.1",
		func(doc map[string]any) { doc["agent"] = "some-other-agent" })
	ledger := reconcileWithCases(t, dir)
	requireDetail(t, ledger, "filed under agent",
		"a per-case report carrying another agent's name is from another run; accepting it lets "+
			"one run's index be paired with another run's cases one case at a time")
	if ledger.Reconciles {
		t.Error("a report filed under another agent must not reconcile")
	}
}

// TestTheIndexReportfileMustNameAFileThatIsActuallyThere isolates the
// index-to-file binding. Its own comment in reconcile.go says "Without this
// the index's `reportfile` values are decorative and a stale case directory
// can be paired with a freshly relabelled index" — a claim that had no probe.
// SWEPT AND SURVIVED before this probe existed, in BOTH its arms.
func TestTheIndexReportfileMustNameAFileThatIsActuallyThere(t *testing.T) {
	root := repoRoot(t)
	src := filepath.Join(devBase(root), "fuzzingclient-run1", "cases")
	dst := t.TempDir()
	names, err := filepath.Glob(filepath.Join(src, "*.json"))
	if err != nil || len(names) == 0 {
		t.Fatalf("glob %s: %v (%d names)", src, err, len(names))
	}
	// Copy everything under a DIFFERENT filename, keeping the report contents
	// byte-identical. The reports still parse, still carry the right ids and
	// behaviors, and still satisfy every other check — only the names the
	// index points at are gone.
	renamed := 0
	for _, name := range names {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out := filepath.Join(dst, "renamed_"+filepath.Base(name))
		if err := os.WriteFile(out, raw, 0o600); err != nil {
			t.Fatalf("write %s: %v", out, err)
		}
		renamed++
	}
	if renamed == 0 {
		t.Fatal("nothing was renamed; this probe is stale")
	}
	ledger := reconcileWithCases(t, dst)
	requireDetail(t, ledger, "which is not in the scanned cases directory",
		"the index's reportfile values are the binding between the index and the case files; "+
			"if nothing checks them a stale cases directory pairs with a relabelled index")
	if ledger.Reconciles {
		t.Error("an index whose reportfile values name nothing present must not reconcile")
	}
}

// TestACaseTheIndexScoresButTheManifestDoesNotKnowIsReported isolates the
// unexpected-case arm. SWEPT AND SURVIVED before this probe existed: with
// `!inManifest[caseID]` deleted, UnexpectedCases stayed empty and nothing
// noticed.
func TestACaseTheIndexScoresButTheManifestDoesNotKnowIsReported(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	// Drop one case from the manifest. The report is untouched and genuine, so
	// the case it scores is now one the expectation does not contain — the
	// direction that catches a suite that grew a case underneath a frozen
	// manifest.
	dropped := manifest.Cases[0].CaseID
	manifest.Cases = manifest.Cases[1:]
	ledger, err := Reconcile(manifest,
		filepath.Join(devBase(root), "fuzzingclient-run1", "index.json"), "", nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	found := false
	for _, caseID := range ledger.UnexpectedCases {
		if caseID == dropped {
			found = true
		}
	}
	if !found {
		t.Errorf("case %s is scored by the index and absent from the manifest, and was not "+
			"reported as unexpected (UnexpectedCases=%v). A run that scores cases the "+
			"expectation does not contain is not the run the expectation describes",
			dropped, ledger.UnexpectedCases)
	}
}

// TestTheMissingRegisterEntryDirectionIsIsolated closes the mirror image of
// round 1's finding 4.
//
// Round 1 found that the STALE direction of VerifyRegisterIsExact was not
// discriminated, and added an isolating probe for it. The MISSING direction —
// a real divergence with no register entry accounting for it — still had none:
// the nearest test mutates the single entry's CaseID to "1.1.1", which makes
// 5.15 unregistered AND 1.1.1 stale at the same time, then asserts only that
// the problem list is non-empty. The stale arm satisfies that, so deleting the
// missing-entry arm left it green. Measured: `if false && (!registered[caseID])`
// kept the whole package suite green before this test existed.
func TestTheMissingRegisterEntryDirectionIsIsolated(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	register, err := ReadDivergenceRegister(registerPath(root))
	if err != nil {
		t.Fatalf("ReadDivergenceRegister: %v", err)
	}
	// An EMPTY register against the real runs: every observed divergence is
	// unregistered and NO entry can be stale, so only the missing-entry arm
	// can produce a problem.
	empty := &DivergenceRegister{}
	agreement, err := CompareToBaseline(manifest, RoleClient,
		nativeIndex(root, "rust/fuzzingserver-run1"),
		nativeIndex(root, "java/fuzzingserver-run1"), empty)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	if agreement.RegisteredDelta != 0 {
		t.Fatalf("this probe must isolate the MISSING direction; %d divergences are registered "+
			"against an empty register", agreement.RegisteredDelta)
	}
	problems := VerifyRegisterIsExact(empty, agreement)
	if len(problems) == 0 {
		t.Fatal("an EMPTY register against runs that do diverge produced no problem: a " +
			"divergence nothing accounts for is exactly what the register exists to forbid")
	}
	for _, problem := range problems {
		if !strings.Contains(problem, "no register entry accounts for it") {
			t.Errorf("this probe is no longer isolating; it produced %q, which is not the "+
				"missing-entry arm", problem)
		}
	}
	// Polarity: the committed register, on the same runs, produces none.
	if clean := VerifyRegisterIsExact(register, agreement); len(clean) != 0 {
		t.Errorf("the committed register must be exact for these runs; got %v", clean)
	}
}

// TestAnIndexEntryThatNamesNoReportfileIsReportedAsSuch isolates the FIRST arm
// of the index-to-file binding, which the renaming probe above does NOT reach.
//
// This is a finding against my own round-3 work, kept rather than quietly
// fixed. The renaming probe leaves every `reportfile` value non-empty, so it
// exercises only `!presentFiles[entry.ReportFile]`; measured, deleting
// `entry.ReportFile == ""` left the whole package green even with that probe
// present. The two arms are not independent — blanking a reportfile makes the
// SECOND arm true as well, so a probe that asserts on the disagreement COUNT
// cannot tell them apart, and only the message text can.
func TestAnIndexEntryThatNamesNoReportfileIsReportedAsSuch(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	indexPath := filepath.Join(devBase(root), "fuzzingclient-run1", "index.json")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	var byAgent map[string]map[string]map[string]any
	if err := json.Unmarshal(raw, &byAgent); err != nil {
		t.Fatalf("parse index: %v", err)
	}
	blanked := ""
	for _, cases := range byAgent {
		for caseID := range cases {
			if blanked == "" || caseID < blanked {
				blanked = caseID
			}
		}
		if blanked == "" {
			t.Fatal("the index has no entries; this probe is stale")
		}
		cases[blanked]["reportfile"] = ""
	}
	out := filepath.Join(t.TempDir(), "index.json")
	patched, err := json.Marshal(byAgent)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	if err := os.WriteFile(out, patched, 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	ledger, err := Reconcile(manifest, out,
		filepath.Join(devBase(root), "fuzzingclient-run1", "cases"), nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	requireDetail(t, ledger, "names no reportfile",
		"an index entry with an empty reportfile names nothing at all, which is a different "+
			"defect from naming a file that is missing, and it must be reported as itself")
}

// TestTheRegisterRoleFilterIsLoadBearing isolates `entry.Role != agreement.Role`.
// SWEPT AND SURVIVED before this probe existed: with that filter deleted, every
// test in the package stayed green, so an entry filed against the OTHER role
// was silently accepted as accounting for this role's divergence.
func TestTheRegisterRoleFilterIsLoadBearing(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	register, err := ReadDivergenceRegister(registerPath(root))
	if err != nil {
		t.Fatalf("ReadDivergenceRegister: %v", err)
	}
	// Re-file every entry against the SERVER role, then judge the CLIENT run.
	// The divergence is real and its description is exact in every respect
	// except the role it is filed under.
	misfiled := &DivergenceRegister{}
	for _, entry := range register.Entries {
		entry.Role = RoleServer
		misfiled.Entries = append(misfiled.Entries, entry)
	}
	if len(misfiled.Entries) == 0 {
		t.Fatal("the committed register has no entries; this probe is stale")
	}
	agreement, err := CompareToBaseline(manifest, RoleClient,
		nativeIndex(root, "rust/fuzzingserver-run1"),
		nativeIndex(root, "java/fuzzingserver-run1"), misfiled)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	problems := VerifyRegisterIsExact(misfiled, agreement)
	if len(problems) == 0 {
		t.Error("a register whose entries are all filed under the OTHER role accounted for this " +
			"role's divergences. The role is part of what an entry claims to have observed; " +
			"without the filter one role's registration silently licenses the other's")
	}
}
