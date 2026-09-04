package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRoot builds a repository-shaped directory whose rust/<crate>/tests holds
// the given files, so run() can be exercised end to end.
func fakeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	// The self-check reads the REAL manifest and fixtures; point the fake root
	// at them by symlinking the testdata tree into place.
	if err := os.MkdirAll(filepath.Join(root, "cmd", "fixtureguardctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(abs, filepath.Join(root, "cmd", "fixtureguardctl", "testdata")); err != nil {
		t.Fatal(err)
	}
	// Every declared production budget's anchor must exist, because the gate
	// verifies it on every run (budget.go, verifyBudgetAnchors). A fake
	// repository that omitted it would be testing a tree the real rule refuses
	// to scan; TestAnchorlessTreeIsRefused omits it on purpose.
	for _, pb := range productionBudgets {
		if _, given := files[pb.Anchor]; given {
			continue
		}
		anchorPath := filepath.Join(root, filepath.FromSlash(pb.Anchor))
		if err := os.MkdirAll(filepath.Dir(anchorPath), 0o755); err != nil {
			t.Fatal(err)
		}
		stub := "fn drive() {\n    " + pb.LoopText + " {\n    }\n}\npub enum LoopOutcome { " + pb.Outcome + " }\n"
		if err := os.WriteFile(anchorPath, []byte(stub), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func invoke(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String() + errOut.String()
}

const guardedFixture = `
use std::time::Instant;
const POLL_BUDGET: u64 = 2_000_000;
#[test]
fn stress() {
    let mut polls = 0u64;
    let mut applied = 0usize;
    while applied < 200 && polls < POLL_BUDGET {
        polls += 1;
        applied += step();
    }
}
`

const cleanFixture = `
use std::time::{Duration, Instant};
const POLL_DEADLINE: Duration = Duration::from_secs(60);
#[test]
fn stress() {
    let mut polls = 0u64;
    let mut applied = 0usize;
    let started = Instant::now();
    while applied < 200 && started.elapsed() < POLL_DEADLINE {
        polls += 1;
        applied += step();
    }
    assert_eq!(applied, 200, "no accepted command lost (polls={polls})");
}
`

// TestRunRefusesAGuardedTree is the end-to-end RED: a tree containing the
// defect must make the process exit nonzero.
func TestRunRefusesAGuardedTree(t *testing.T) {
	root := fakeRoot(t, map[string]string{"rust/ws-x/tests/stress.rs": guardedFixture})
	code, out := invoke(t, "-root", root)
	if code == 0 {
		t.Fatalf("a tree carrying a count-shaped liveness guard must fail; got exit 0\n%s", out)
	}
	if !strings.Contains(out, "VIOLATION") || !strings.Contains(out, "POLL_BUDGET") {
		t.Fatalf("the failure must name the guard it found:\n%s", out)
	}
}

// TestRunAcceptsAFixedTree is the matching GREEN.
func TestRunAcceptsAFixedTree(t *testing.T) {
	root := fakeRoot(t, map[string]string{"rust/ws-x/tests/stress.rs": cleanFixture})
	code, out := invoke(t, "-root", root)
	if code != 0 {
		t.Fatalf("a wall-clock-bounded fixture must pass; got exit %d\n%s", code, out)
	}
}

// TestRunRefusesAnEmptyScan is the theatre guard: a scan that matched nothing
// must never report PASS. Without this the walker could break silently and the
// gate would go green forever.
func TestRunRefusesAnEmptyScan(t *testing.T) {
	root := fakeRoot(t, map[string]string{"rust/README.md": "no rust sources here\n"})
	code, out := invoke(t, "-root", root)
	if code == 0 {
		t.Fatalf("a scan that saw no fixture files must fail; got exit 0\n%s", out)
	}
	if !strings.Contains(out, "looked at nothing") {
		t.Fatalf("the failure must say the scan looked at nothing:\n%s", out)
	}
}

// TestRunAlwaysRunsTheSelfcheck: the historical control is not optional. If
// the call is ever removed, this fails.
func TestRunAlwaysRunsTheSelfcheck(t *testing.T) {
	root := fakeRoot(t, map[string]string{"rust/ws-x/tests/stress.rs": cleanFixture})
	_, out := invoke(t, "-root", root)
	for _, want := range []string{
		"step=selfcheck",
		"history/F004-pre-fix-concurrency_boundary.rs",
		"history/F005-pre-fix-concurrency.rs",
		"refusals_before_the_drop",
		"POLL_BUDGET",
		"synthetic/production_budget_roles.rs",
		"shape=C counter=max_polls",
		"step=selfcheck cases=7 firing=4 silent=3 result=PASS",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the run must show the historical self-check (%q missing):\n%s", want, out)
		}
	}
}

// TestSelfcheckFailsOnADriftedManifest: if the declared rows and the observed
// rows disagree, the gate must refuse rather than reconcile.
func TestSelfcheckFailsOnADriftedManifest(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "cmd", "fixtureguardctl", "testdata")
	if err := os.MkdirAll(filepath.Join(dir, "history"), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(testdataPath("history/F005-pre-fix-concurrency.rs"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "history", "F005-pre-fix-concurrency.rs"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := polarityManifest{Cases: []polarityCase{
		{Path: "history/F005-pre-fix-concurrency.rs", Expect: []string{"69|A|polls|POLL_BUDGET|false"}},
		{Path: "history/F005-pre-fix-concurrency.rs", Expect: nil},
	}}
	blob, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "polarity.json"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if selfcheck(root, &out, &errOut) {
		t.Fatalf("a manifest that under-declares the findings must fail:\n%s%s", out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "POLARITY-FAIL") {
		t.Fatalf("the failure must be reported as a polarity failure:\n%s", errOut.String())
	}
}

// TestSelfcheckNeedsBothPolarities: an all-firing or all-silent manifest
// proves nothing, and must not be accepted as a self-check.
func TestSelfcheckNeedsBothPolarities(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "cmd", "fixtureguardctl", "testdata")
	if err := os.MkdirAll(filepath.Join(dir, "fixed"), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(testdataPath("fixed/F005-post-fix-concurrency.rs"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixed", "F005-post-fix-concurrency.rs"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := polarityManifest{Cases: []polarityCase{
		{Path: "fixed/F005-post-fix-concurrency.rs", Expect: nil},
	}}
	blob, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "polarity.json"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if selfcheck(root, &out, &errOut) {
		t.Fatalf("a self-check with only silent cases must fail:\n%s%s", out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "both polarities") {
		t.Fatalf("the failure must say why:\n%s", errOut.String())
	}
}

// TestWaiverCeilingIsEnforced: the escape hatch is countable, and the count
// has a declared ceiling. A new waiver turns the gate red until someone raises
// the ceiling in the same change, where a reviewer can see it.
func TestWaiverCeilingIsEnforced(t *testing.T) {
	waived := `
const CAP: usize = 32;
#[test]
fn subject() {
    let mut ticks = 0usize;
    loop {
        ticks += 1;
        if done() { break; }
        // FIXTURE-COUNT-GUARD-ALLOWED: the counter itself is the subject under test, so the bound is the property
        assert!(ticks < CAP, "overflowed");
    }
}
`
	root := fakeRoot(t, map[string]string{"rust/ws-x/tests/waived.rs": waived})
	code, out := invoke(t, "-root", root)
	if code == 0 {
		t.Fatalf("a waiver over the default ceiling of 0 must fail:\n%s", out)
	}
	if !strings.Contains(out, "waivers=1") || !strings.Contains(out, "ceiling is 0") {
		t.Fatalf("the failure must count the waivers and name the ceiling:\n%s", out)
	}
	code, out = invoke(t, "-root", root, "-max-waivers", "1")
	if code != 0 {
		t.Fatalf("a waiver within the declared ceiling must pass; got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "gate=fixture-liveness-guard waiver ") {
		t.Fatalf("an allowed waiver must still be printed, so it is countable:\n%s", out)
	}
}

// TestUsageErrorExitsTwo keeps the exit codes distinguishable: 2 is "you held
// it wrong", 1 is "the tree has the defect".
func TestUsageErrorExitsTwo(t *testing.T) {
	if code, _ := invoke(t, "-nonsense"); code != 2 {
		t.Fatalf("an unknown flag must exit 2, got %d", code)
	}
	if code, _ := invoke(t, "-root", ".", "stray"); code != 2 {
		t.Fatalf("a stray positional argument must exit 2, got %d", code)
	}
}

// TestThisRepositoryIsClean is the live claim, run as a test as well as in the
// gate: mainline's Rust fixtures carry no count-shaped liveness guard.
func TestThisRepositoryIsClean(t *testing.T) {
	code, out := invoke(t, "-root", "../..")
	if code != 0 {
		t.Fatalf("the repository must be clean under its own rule; got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "result=PASS") {
		t.Fatalf("expected a PASS verdict:\n%s", out)
	}
}

// A `#[cfg(test)]` whose module body this scan cannot reach is a hole in the
// scan surface, and the scan used to drop the whole file for it in silence --
// `files=` did not even move. Three ways in, all reached by attack:
// `#[cfg(test)] mod tests;` (ordinary Rust, fixture in its own file), more than
// braceSearchLimit bytes before the `{`, and a masked-away closing brace.
func TestACfgTestModuleThisScanCannotReachIsReported(t *testing.T) {
	guard := "\n    let mut polls: usize = 0;\n    loop {\n        polls += 1;\n" +
		"        assert!(polls < 4096, \"the peer never answered\");\n" +
		"        if done() { break; }\n    }\n"
	padding := strings.Repeat("    // "+strings.Repeat("x", 40)+"\n", 12)

	for name, body := range map[string]string{
		"body in another file": "pub fn f() {}\n\n#[cfg(test)]\nmod tests;\n",
		// The dangerous form of the same thing: a later brace that is NOT the
		// module's. Without the bodyless-module rule the scan silently adopts
		// `helper`'s body as the fixture region -- production code scanned as a
		// fixture, and the real fixture file still never opened -- and because
		// that region holds no loop the gate reports PASS.
		"a later brace stands in for the module": "pub fn f() {}\n\n#[cfg(test)]\n" +
			"mod tests;\n\nfn helper() { let _x = 1; }\n",
		"brace beyond the search bound": "pub fn f() {}\n\n#[cfg(test)]\n" + padding +
			"mod tests {\n    #[test]\n    fn t() {" + guard + "    }\n}\n",
		"closing brace masked away": "pub fn f() {}\n\n#[cfg(test)]\nmod tests {\n" +
			"    #[test]\n    fn t() {\n        let s = \"unterminated;\n" + guard + "    }\n}\n",
	} {
		root := fakeRoot(t, map[string]string{
			"rust/ws-x/src/lib.rs":     body,
			"rust/ws-x/tests/clean.rs": cleanFixture,
		})
		code, out := invoke(t, "-root", root)
		if code == 0 {
			t.Errorf("%s: an unreachable #[cfg(test)] body must fail the gate\n%s", name, out)
		}
		if !strings.Contains(out, "UNSCANNED") {
			t.Errorf("%s: the gate must NAME what it did not scan\n%s", name, out)
		}
	}
}

// The other polarity: an ordinary inline `#[cfg(test)] mod tests { }` is reached
// and reports nothing extra, so the new failure channel cannot fire on the shape
// every crate in this workspace actually uses.
func TestAnInlineCfgTestModuleIsScannedAndSilent(t *testing.T) {
	root := fakeRoot(t, map[string]string{
		"rust/ws-x/src/lib.rs": "pub fn f() {}\n\n#[cfg(test)]\nmod tests {\n" +
			"    #[test]\n    fn t() {\n        let deadline = now() + SECOND;\n" +
			"        while !done() && now() < deadline {}\n    }\n}\n",
		"rust/ws-x/tests/clean.rs": cleanFixture,
	})
	code, out := invoke(t, "-root", root)
	if code != 0 {
		t.Fatalf("an inline cfg(test) module must pass; got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "unscanned=0") {
		t.Fatalf("the scan must report nothing unscanned:\n%s", out)
	}
}
