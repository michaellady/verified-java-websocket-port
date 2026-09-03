package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// TestPreconditionRefusesTheHistoricalStub is the historical claim as an exit
// code: the record `claude/div05-close-overtakes-echo` carried at 755b8c8 must
// not be able to satisfy a landing precondition.
func TestPreconditionRefusesTheHistoricalStub(t *testing.T) {
	root := repoRoot(t)
	code, out, _ := runCLI(t, "precondition", "-root", root,
		"cmd/recordguardctl/testdata/history/div05-close-overtakes-echo-STUB.md")
	if code != 1 {
		t.Fatalf("landing on the div05 stub exited %d, want 1\n%s", code, out)
	}
	for _, want := range []string{"verdict=REFUSED", "declared-status", "void-self-report", "cites-nothing"} {
		if !strings.Contains(out, want) {
			t.Errorf("refusal did not report %q; the operator cannot see WHY\n%s", want, out)
		}
	}
}

// TestPreconditionAcceptsTheRealRecords is the other half: the 552-line record
// the same branch eventually carried, and the two records F009 names as the ones
// that did land, must all pass.
func TestPreconditionAcceptsTheRealRecords(t *testing.T) {
	root := repoRoot(t)
	code, out, errOut := runCLI(t, "precondition", "-root", root,
		"cmd/recordguardctl/testdata/real/div05-close-overtakes-echo-FINAL.md",
		"drafts/self-review/adapter-residuals.md",
		"drafts/self-review/fixture-liveness-guard-detector.md")
	if code != 0 {
		t.Fatalf("finished records were refused, exit %d\n%s\n%s", code, out, errOut)
	}
	if n := strings.Count(out, "verdict=READS-FINISHED"); n != 3 {
		t.Errorf("want 3 READS-FINISHED verdicts, got %d\n%s", n, out)
	}
}

// TestAnAbsentRecordIsARefusalNotAPass is F009's defect stated directly. The
// finding is that a landing decision counted files matching a path; the
// correction is that a record which is not there cannot satisfy anything. This
// test exists because deletion attack A11 — dropping the `refused++` on an
// unreadable record — survived every other check in this package.
func TestAnAbsentRecordIsARefusalNotAPass(t *testing.T) {
	root := repoRoot(t)
	code, out, errOut := runCLI(t, "precondition", "-root", root,
		"drafts/self-review/this-record-was-never-written.md")
	if code != 1 {
		t.Fatalf("a missing record exited %d, want 1: absence passed as review\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(errOut, "verdict=REFUSED") {
		t.Errorf("the refusal of a missing record was not reported: %q", errOut)
	}
}

// TestAMixedSetIsRefusedWholesale pins the wave-4 shape exactly: three branches,
// two with real records and one with a stub, judged together. The batch must
// fail, and it must name the one that failed.
func TestAMixedSetIsRefusedWholesale(t *testing.T) {
	root := repoRoot(t)
	code, out, errOut := runCLI(t, "precondition", "-root", root,
		"drafts/self-review/adapter-residuals.md",
		"cmd/recordguardctl/testdata/history/div05-close-overtakes-echo-STUB.md",
		"drafts/self-review/normalization-collision-audit.md")
	if code != 1 {
		t.Fatalf("two real records and one stub exited %d, want 1\n%s", code, out)
	}
	if !strings.Contains(errOut, "1 of 3 named record(s)") {
		t.Errorf("the batch refusal did not say how many of how many failed: %q", errOut)
	}
	if strings.Count(out, "verdict=READS-FINISHED") != 2 {
		t.Errorf("the two real records were not reported as finished\n%s", out)
	}
}

// TestPreconditionWithNoRecordIsAUsageRefusal: invoking the landing check
// without naming a record must not be a quiet pass. That is the same defect one
// level up.
func TestPreconditionWithNoRecordIsAUsageRefusal(t *testing.T) {
	code, _, errOut := runCLI(t, "precondition", "-root", repoRoot(t))
	if code != 2 {
		t.Fatalf("naming no record exited %d, want 2", code)
	}
	if !strings.Contains(errOut, "no record named") {
		t.Errorf("usage refusal did not explain itself: %q", errOut)
	}
}

// TestGatePassesOnThisTreeAndPrintsWhatItRead. A gate that reports PASS without
// saying what it looked at is theatre.
func TestGatePassesOnThisTreeAndPrintsWhatItRead(t *testing.T) {
	root := repoRoot(t)
	code, out, errOut := runCLI(t, "gate", "-root", root)
	if code != 0 {
		t.Fatalf("gate exited %d on a clean tree\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"step=selfcheck cases=", "firing=", "silent=", "step=census records=", "result=PASS",
		"359940cd6fa37cf158ac603fe19803724bf9578f", // the div05 stub's blob, printed as provenance
	} {
		if !strings.Contains(out, want) {
			t.Errorf("gate output does not contain %q\n%s", want, out)
		}
	}
}

// TestGateDoesNotFailOnAnHonestlyUnfinishedRecord is the edge F009 names: a
// record that says IN PROGRESS while genuinely in progress is CORRECT, and this
// repository's own discipline tells agents to push exactly such a stub in their
// first few tool calls. The gate must SEE it and must not fail on it.
func TestGateDoesNotFailOnAnHonestlyUnfinishedRecord(t *testing.T) {
	root := t.TempDir()
	src := repoRoot(t)
	// A tree with the real fixtures (so the self-check can run) plus one
	// honestly-unfinished record.
	mustLink(t, filepath.Join(src, "cmd", "recordguardctl", "testdata"), filepath.Join(root, "cmd", "recordguardctl", "testdata"))
	recs := filepath.Join(root, "drafts", "self-review")
	if err := os.MkdirAll(recs, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(recs, "finished.md"), "# A finished record — the differential closed\n\nSTATUS: COMPLETE.\n\n`make -C rust gates` exit 0; observed at 4a2b9c6.\n")
	write(t, filepath.Join(recs, "in-flight.md"), "# A branch that is genuinely mid-flight\n\nSTATUS: IN PROGRESS — stub pushed early to survive container restarts.\n\nNothing verified yet.\n")

	code, out, errOut := runCLI(t, "gate", "-root", root)
	if code != 0 {
		t.Fatalf("the gate FAILED on an honestly-unfinished record, exit %d: writing the stub is not the defect, landing on it is\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "census UNFINISHED record=drafts/self-review/in-flight.md") {
		t.Errorf("the gate did not make the unfinished record visible\n%s", out)
	}
	if !strings.Contains(out, "unfinished=1 finished=1") {
		t.Errorf("census did not count 1 unfinished of 2\n%s", out)
	}
	// ...and the SAME record, named at a landing decision, is refused.
	code, _, _ = runCLI(t, "precondition", "-root", root, "drafts/self-review/in-flight.md")
	if code != 1 {
		t.Fatalf("the same record was accepted at the landing decision, exit %d, want 1", code)
	}
}

// TestTheStatusSignalReadsTheValueNotTheField pins the property the whole tool
// is named for, independent of any corpus fixture: two records differing ONLY in
// the value of the status field get opposite verdicts. Deletion attack A9
// (scanning the whole status line instead of its value) is an equivalent mutant
// under today's status pattern; this test is what would catch it if that pattern
// were ever loosened to allow words before the colon.
func TestTheStatusSignalReadsTheValueNotTheField(t *testing.T) {
	const body = "\n\n`rust/ws-core/src/close.rs` exit 0, digest 4a2b9c6, observed differential.\n"
	finished := "# a record — closed\n\nSTATUS: COMPLETE." + body
	unfinished := "# a record — closed\n\nSTATUS: IN PROGRESS." + body
	if sigs := Scan(finished); len(sigs) != 0 {
		t.Errorf("a record whose status field says COMPLETE fired: %v", Rows(sigs))
	}
	sigs := Scan(unfinished)
	if len(sigs) == 0 {
		t.Fatalf("a record whose status field says IN PROGRESS did not fire")
	}
	if sigs[0].Kind != "declared-status" {
		t.Errorf("want declared-status, got %s", sigs[0].Kind)
	}
	// The two differ ONLY in the field's value; the field itself is identical.
	if !strings.Contains(finished, "STATUS:") || !strings.Contains(unfinished, "STATUS:") {
		t.Fatal("the control no longer holds the status field constant")
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mustLink copies a directory tree (fixtures are small and read-only here).
func mustLink(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		s, d := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		if e.IsDir() {
			mustLink(t, s, d)
			continue
		}
		data, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		write(t, d, string(data))
	}
}
