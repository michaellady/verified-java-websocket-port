package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// summary renders a scan result as sorted "line|shape|counter|bound|waived"
// rows, so a test can pin EXACTLY what fired rather than a count that could
// come from anywhere in the file.
func summary(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(data)
	var regions []region
	if !isTestsTreeFile(path) && strings.Contains(src, "#[cfg(test)]") {
		regions, _ = cfgTestRegions(maskSource(src))
	}
	vs, loops := scanFile(path, src, regions)
	if loops == 0 && !mentionsAProductionBudget(src) {
		t.Fatalf("%s: no loops examined and no production budget named; the scanner found nothing to look at", path)
	}
	var rows []string
	for _, v := range vs {
		rows = append(rows, fmt.Sprintf("%d|%s|%s|%s|%t", v.Line, v.Shape, v.Counter, v.Bound, v.Waived))
	}
	sort.Strings(rows)
	return rows
}

func testdataPath(rel string) string {
	return filepath.Join("testdata", filepath.FromSlash(rel))
}

func requireRows(t *testing.T, rel string, want []string) {
	t.Helper()
	got := summary(t, testdataPath(rel))
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("%s: got %d finding(s) %v, want %d %v", rel, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: finding %d = %q, want %q (all: %v)", rel, i, got[i], want[i], got)
		}
	}
}

// TestPolarityManifestIsHonoured runs the same comparison the gate runs, so
// the historical control fails `go test` as well as `make gates`.
func TestPolarityManifestIsHonoured(t *testing.T) {
	blob, err := os.ReadFile(testdataPath("polarity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest polarityManifest
	if err := json.Unmarshal(blob, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Cases) == 0 {
		t.Fatal("the polarity manifest declares no cases")
	}
	for _, c := range manifest.Cases {
		requireRows(t, c.Path, c.Expect)
	}
}

// TestF004PreFixIsDetected pins the historical proof in test source too, so a
// reader grepping for `4096` finds the claim next to the assertion. This is
// the exact text that failed 2 runs in 5 with ws-core byte-identical to
// mainline.
func TestF004PreFixIsDetected(t *testing.T) {
	requireRows(t, "history/F004-pre-fix-concurrency_boundary.rs", []string{
		"280|B1|refusals_before_the_drop|4096|false",
	})
}

// TestF005PreFixIsDetected pins all THREE sibling loops, not just the one
// whose assertion happened to fail: F005 records that two siblings carried the
// same guard.
func TestF005PreFixIsDetected(t *testing.T) {
	requireRows(t, "history/F005-pre-fix-concurrency.rs", []string{
		"157|A|polls|POLL_BUDGET|false",
		"182|A|polls|POLL_BUDGET|false",
		"69|A|polls|POLL_BUDGET|false",
	})
}

// TestLandedFixesAreSilent is the other half of the proof. A detector that
// also condemns the fix teaches people to disable it.
func TestLandedFixesAreSilent(t *testing.T) {
	for _, rel := range []string{
		"fixed/F004-post-fix-concurrency_boundary.rs",
		"fixed/F005-post-fix-concurrency.rs",
	} {
		requireRows(t, rel, nil)
	}
}

// TestLegitimateBoundedConstantsAreSilent covers the noisy direction: a config
// value that is a count, a `for` over an exact domain, a `while` bounded by a
// dynamic length, GOAL counters incremented conditionally beside a wall clock,
// an assertion about the system under test placed after the loop, and prose
// that quotes the defect.
func TestLegitimateBoundedConstantsAreSilent(t *testing.T) {
	requireRows(t, "legit/bounded_domain_constants.rs", nil)
}

// TestSyntheticShapes covers what history does not supply, and pins the
// escape hatch: the justified waiver is recorded as waived, the one-word
// waiver is not.
func TestSyntheticShapes(t *testing.T) {
	requireRows(t, "synthetic/silent_break_and_waiver.rs", []string{
		"25|B2|polls|POLL_BUDGET|false",
		"40|B1|attempts|ATTEMPT_CAP|false",
		"51|A|polls|POLL_BUDGET|false",
		"69|B1|ticks|32|true",
		"85|B1|ticks|64|false",
	})
}

// TestGoalCounterBesideDeadlineIsNotAGuard states the hardest distinction the
// rule has to make, in isolation: `disposed < 20` and `polls < POLL_BUDGET`
// are the same SHAPE, and only the increment separates them.
func TestGoalCounterBesideDeadlineIsNotAGuard(t *testing.T) {
	goal := `
fn f() {
    let mut disposed = 0u64;
    let started = Instant::now();
    while disposed < 20 && started.elapsed() < POLL_DEADLINE {
        if step() { disposed += 1; }
    }
}`
	guard := `
fn f() {
    let mut polls = 0u64;
    while applied.len() < TOTAL && polls < POLL_BUDGET {
        polls += 1;
        step();
    }
}`
	if vs, _ := scanFile("goal.rs", goal, nil); len(vs) != 0 {
		t.Fatalf("a conditionally incremented GOAL counter must not be reported: %+v", vs)
	}
	vs, _ := scanFile("guard.rs", guard, nil)
	if len(vs) != 1 || vs[0].Counter != "polls" || vs[0].Shape != "A" {
		t.Fatalf("an unconditionally incremented iteration counter in the header must be reported, got %+v", vs)
	}
}

// TestReportingInTheMessageIsAllowed is F005's rule verbatim: a counter kept
// alongside the deadline may REPORT, never decide.
func TestReportingInTheMessageIsAllowed(t *testing.T) {
	src := `
fn f() {
    let mut polls = 0u64;
    let started = Instant::now();
    loop {
        polls += 1;
        assert!(started.elapsed() < DEADLINE, "gave up: polls={polls}, and a healthy host needs polls < 200");
        if done() { break; }
    }
}`
	if vs, _ := scanFile("report.rs", src, nil); len(vs) != 0 {
		t.Fatalf("a count named only in the failure message must not be reported: %+v", vs)
	}
}

// TestCommentsAndStringsAreNotCode: the masker is load-bearing. The file that
// was FIXED for F005 carries a doc comment quoting the guard it removed.
func TestCommentsAndStringsAreNotCode(t *testing.T) {
	src := `
fn f() {
    // The old guard read: while polls < POLL_BUDGET { polls += 1; }
    let note = "while polls < POLL_BUDGET { polls += 1; }";
    let mut polls = 0u64;
    let started = Instant::now();
    while started.elapsed() < DEADLINE {
        polls += 1;
    }
}`
	if vs, _ := scanFile("prose.rs", src, nil); len(vs) != 0 {
		t.Fatalf("prose quoting the defect must not be reported: %+v", vs)
	}
}

// TestForLoopsAreOutOfScope: an iterator bounds a `for`, so it cannot fail to
// terminate and cannot carry a liveness guard.
func TestForLoopsAreOutOfScope(t *testing.T) {
	src := `
fn f() {
    let mut seen = 0usize;
    for case in 0..247 {
        seen += 1;
        assert!(seen < 247, "exactly 247 cases");
    }
}`
	if vs, _ := scanFile("cases.rs", src, nil); len(vs) != 0 {
		t.Fatalf("a bound inside a `for` must not be reported: %+v", vs)
	}
}

// TestWaiverNeedsRealJustification: the escape hatch must cost a sentence, or
// it is silence with extra steps.
func TestWaiverNeedsRealJustification(t *testing.T) {
	body := `
fn f() {
    let mut ticks = 0usize;
    loop {
        ticks += 1;
        %s
        assert!(ticks < 32, "overflowed");
    }
}`
	short := fmt.Sprintf(body, "// FIXTURE-COUNT-GUARD-ALLOWED: ok")
	vs, _ := scanFile("short.rs", short, nil)
	if len(vs) != 1 || vs[0].Waived {
		t.Fatalf("a one-word justification must NOT waive: %+v", vs)
	}
	if !strings.Contains(vs[0].Reason, "justification") {
		t.Fatalf("the reason must say why the waiver was rejected, got %q", vs[0].Reason)
	}
	long := fmt.Sprintf(body, "// FIXTURE-COUNT-GUARD-ALLOWED: the counter itself is the subject under test here, so the bound is the property")
	vs, _ = scanFile("long.rs", long, nil)
	if len(vs) != 1 || !vs[0].Waived {
		t.Fatalf("a justified waiver must waive: %+v", vs)
	}
}

// TestCfgTestRegionsOnly: production code is not a fixture. A retry cap in
// src/ outside `#[cfg(test)]` is a design decision, not this rule's business.
func TestCfgTestRegionsOnly(t *testing.T) {
	src := `
fn production_retry() {
    let mut attempts = 0usize;
    loop {
        attempts += 1;
        if attempts >= 5 { break; }
    }
}

#[cfg(test)]
mod tests {
    fn fixture() {
        let mut polls = 0usize;
        loop {
            polls += 1;
            if polls >= 4096 { break; }
        }
    }
}
`
	regions, _ := cfgTestRegions(maskSource(src))
	if len(regions) != 1 {
		t.Fatalf("expected exactly one #[cfg(test)] region, got %d", len(regions))
	}
	vs, _ := scanFile("lib.rs", src, regions)
	if len(vs) != 1 || vs[0].Counter != "polls" {
		t.Fatalf("only the fixture loop must be reported, got %+v", vs)
	}
}

// TestScanTreeSeesSomething guards the theatre case directly: the walker must
// find fixture files and loops in this repository.
func TestScanTreeSeesSomething(t *testing.T) {
	res, err := scanTree("../..")
	if err != nil {
		t.Fatalf("scanTree: %v", err)
	}
	if res.files < 20 || res.loops < 50 {
		t.Fatalf("the walker saw files=%d loops=%d, which is too few to be a real scan of rust/", res.files, res.loops)
	}
}
