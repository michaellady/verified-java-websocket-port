package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The exact bytes the fake cargo emits, split by stream. The OOM explanation
// deliberately goes to STDERR: it is the line attempt 0129 lost, and putting it
// on the other stream means a test that reads it back has also proven stderr is
// captured. The helper writes stderr before stdout, so the expected combined
// output is simply the concatenation in that order.
//
// failing_harness exists so that first_failure_description is NON-EMPTY in at
// least one fixture. Without it that field is absent everywhere, and pinning it
// would be satisfied by two absent keys -- deleting reFailed entirely would
// then leave every classification assertion green.
const (
	oomStderr  = "CBMC appears to have run out of memory.\n"
	oomStdout  = "Checking harness oom_harness...\n** 0 of 0 failed\n\nVERIFICATION:- FAILED\n"
	goodStderr = "kani: verification time 0.4s\n"
	goodStdout = "Checking harness good_harness...\n** 0 of 12 failed\n\nVERIFICATION:- SUCCESSFUL\n"
	failStderr = "kani: verification time 1.1s\n"
	failStdout = "Checking harness failing_harness...\n" +
		"Failed Checks: assertion failed: mask key must differ from the preceding frame\n" +
		"** 1 of 7 failed\n\nVERIFICATION:- FAILED\n"

	failDescription = "assertion failed: mask key must differ from the preceding frame"

	// The spec every classification test uses, and the sorted order kanirun
	// emits it in: failing_harness < good_harness < oom_harness.
	standardSpec = "good_harness=SUCCESSFUL,oom_harness=FAILED,failing_harness=FAILED"
)

func wantCombined(harness string) string {
	switch harness {
	case "oom_harness":
		return oomStderr + oomStdout
	case "good_harness":
		return goodStderr + goodStdout
	case "failing_harness":
		return failStderr + failStdout
	}
	return ""
}

// TestHelperProcess stands in for `cargo kani`. It is a Go helper process
// rather than a shell fixture (AGENTS.md rule 1). KANIRUN_FAKE selects the
// canned output; the harness name arrives after the "--harness" argument.
// It writes to BOTH streams so that a runner which captured only stdout would
// be caught rather than silently pass.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("KANIRUN_FAKE") == "" {
		return
	}
	name := ""
	for i, a := range os.Args {
		if a == "--harness" && i+1 < len(os.Args) {
			name = os.Args[i+1]
		}
	}
	switch name {
	case "oom_harness":
		// The exact shape attempt 0129 lost: a 0-of-0 FAILED verdict whose
		// explanation lived only in the discarded output.
		os.Stderr.WriteString(oomStderr)
		os.Stdout.WriteString(oomStdout)
		os.Exit(1)
	case "good_harness":
		os.Stderr.WriteString(goodStderr)
		os.Stdout.WriteString(goodStdout)
		os.Exit(0)
	case "failing_harness":
		os.Stderr.WriteString(failStderr)
		os.Stdout.WriteString(failStdout)
		os.Exit(1)
	}
	os.Exit(9)
}

// fakeCargo builds a directory containing a `cargo` executable that re-execs
// this test binary into TestHelperProcess. When KANIRUN_SENTINEL names a path,
// the shim appends to it on every invocation, so a test can prove that cargo
// was never reached.
func fakeCargo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	shim := filepath.Join(dir, "cargo")
	src := filepath.Join(dir, "shim.go")
	body := `package main

import (
	"os"
	"os/exec"
)

func main() {
	if s := os.Getenv("KANIRUN_SENTINEL"); s != "" {
		f, err := os.OpenFile(s, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			f.WriteString("ran\n")
			f.Close()
		}
	}
	c := exec.Command(` + fmt.Sprintf("%q", self) + `, append([]string{"-test.run=TestHelperProcess"}, os.Args[1:]...)...)
	c.Env = append(os.Environ(), "KANIRUN_FAKE=1")
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		os.Exit(3)
	}
}
`
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	build := exec.Command("go", "build", "-o", shim, src)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build shim: %v\n%s", err, out)
	}
	return dir
}

func buildKanirun(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "kanirun")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build kanirun: %v\n%s", err, out)
	}
	return bin
}

// runRaw runs the runner with an arbitrary harness spec and returns its stdout
// and real exit code without requiring the output to parse. extraEnv entries
// are appended verbatim and reach the fake cargo, which inherits the runner's
// environment.
func runRaw(t *testing.T, harnesses, rawDir string, extraEnv ...string) (string, int) {
	t.Helper()
	args := []string{"-harnesses", harnesses}
	if rawDir != "" {
		args = append(args, "-raw-dir", rawDir)
	}
	cmd := exec.Command(buildKanirun(t), args...)
	cmd.Env = append(os.Environ(), "PATH="+fakeCargo(t)+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.Output()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run kanirun: %v", err)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

// runKanirun runs the standard three-harness spec and parses the records.
func runKanirun(t *testing.T, rawDir string) []map[string]any {
	t.Helper()
	out, _ := runRaw(t, standardSpec, rawDir)
	var recs []map[string]any
	if e := json.Unmarshal([]byte(out), &recs); e != nil {
		t.Fatalf("parse kanirun output: %v\n%s", e, out)
	}
	if len(recs) != 3 {
		t.Fatalf("want 3 records, got %d: %s", len(recs), out)
	}
	return recs
}

func byHarness(t *testing.T, recs []map[string]any) map[string]map[string]any {
	t.Helper()
	m := map[string]map[string]any{}
	for _, r := range recs {
		name, _ := r["harness"].(string)
		if name == "" {
			t.Fatalf("record with no harness name: %v", r)
		}
		m[name] = r
	}
	return m
}

// Without -raw-dir the records must be byte-identical to the pre-change shape.
// Host-vs-sandbox comparison reads these fields, so a new key appearing when
// nobody asked for raw capture would be a behavioural change.
func TestWithoutRawDirRecordsCarryNoRawFields(t *testing.T) {
	for _, r := range runKanirun(t, "") {
		if _, ok := r["raw_log"]; ok {
			t.Errorf("%v: raw_log present without -raw-dir", r["harness"])
		}
		if _, ok := r["raw_log_sha256"]; ok {
			t.Errorf("%v: raw_log_sha256 present without -raw-dir", r["harness"])
		}
	}
}

// The point of the change: the OOM explanation attempt 0129 lost must be
// recoverable from the log. This asserts EXACT equality with the full expected
// bytes, not merely that the explanation appears somewhere -- a substring check
// accepts a truncated log, and since the digest is computed over whatever was
// written, a truncated log carries a self-consistent digest and would pass.
func TestRawDirCapturesTheCompleteCombinedOutput(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	recs := byHarness(t, runKanirun(t, dir))

	for _, name := range []string{"oom_harness", "good_harness", "failing_harness"} {
		rec := recs[name]
		if rec == nil {
			t.Fatalf("%s record missing", name)
		}
		path, _ := rec["raw_log"].(string)
		if path == "" {
			t.Fatalf("%s: raw_log not recorded; successful runs must be captured too", name)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: read raw log: %v", name, err)
		}
		want := wantCombined(name)
		if string(body) != want {
			t.Errorf("%s: raw log is not the complete combined output.\n got (%d bytes): %q\nwant (%d bytes): %q",
				name, len(body), body, len(want), want)
		}
		sum := sha256.Sum256(body)
		if got, wantSum := rec["raw_log_sha256"], hex.EncodeToString(sum[:]); got != wantSum {
			t.Errorf("%s: raw_log_sha256 = %v, want %v (digest must bind the bytes on disk)", name, got, wantSum)
		}
	}

	// Named explicitly: this is the line attempt 0129 discarded, and it
	// arrives on stderr, so reading it back also proves stderr is captured.
	oomBody, err := os.ReadFile(recs["oom_harness"]["raw_log"].(string))
	if err != nil {
		t.Fatalf("read oom log: %v", err)
	}
	if !strings.Contains(string(oomBody), "CBMC appears to have run out of memory") {
		t.Fatalf("the explanation attempt 0129 lost is still not captured; log was:\n%s", oomBody)
	}
}

// Classification must not shift when raw capture is on. Comparing the two modes
// field by field is necessary but NOT sufficient: an equal-in-both-modes shift
// would slip through, and absent keys would compare equal as two nils. So this
// also pins every classification field to its absolute expected value, and
// treats presence itself as part of the expectation -- a field expected to be
// present must be present, and one expected absent (omitempty) must be absent.
func TestRawDirDoesNotChangeClassification(t *testing.T) {
	without := byHarness(t, runKanirun(t, ""))
	with := byHarness(t, runKanirun(t, filepath.Join(t.TempDir(), "logs")))

	fields := []string{"harness", "expectation", "exit_code", "verification",
		"failed_checks", "total_checks", "outcome", "matches_expectation",
		"first_failure_description"}

	// Absolute expectations, so a shift applied equally in both modes fails.
	// A field missing from a harness's map is asserted ABSENT, which is how
	// first_failure_description must behave where no Failed Checks line exists.
	want := map[string]map[string]any{
		"good_harness": {
			"harness": "good_harness", "expectation": "SUCCESSFUL", "exit_code": float64(0),
			"verification": "SUCCESSFUL", "failed_checks": float64(0), "total_checks": float64(12),
			"outcome": "SUCCESSFUL", "matches_expectation": true,
		},
		"oom_harness": {
			"harness": "oom_harness", "expectation": "FAILED", "exit_code": float64(1),
			"verification": "FAILED", "failed_checks": float64(0), "total_checks": float64(0),
			"outcome": "FAILED", "matches_expectation": true,
		},
		"failing_harness": {
			"harness": "failing_harness", "expectation": "FAILED", "exit_code": float64(1),
			"verification": "FAILED", "failed_checks": float64(1), "total_checks": float64(7),
			"outcome": "FAILED", "matches_expectation": true,
			"first_failure_description": failDescription,
		},
	}

	for name, wantRec := range want {
		a, b := without[name], with[name]
		if a == nil || b == nil {
			t.Fatalf("%s missing: without=%v with=%v", name, a != nil, b != nil)
		}
		for _, f := range fields {
			av, aok := a[f]
			bv, bok := b[f]
			wv, expected := wantRec[f]
			if !expected {
				if aok || bok {
					t.Errorf("%s field %q should be omitted here but is present (without=%v with=%v)", name, f, aok, bok)
				}
				continue
			}
			if !aok || !bok {
				t.Errorf("%s field %q absent (without=%v with=%v); an absent key must not read as a match", name, f, aok, bok)
				continue
			}
			if av != bv {
				t.Errorf("%s field %q: without=%v with=%v", name, f, av, bv)
			}
			if av != wv {
				t.Errorf("%s field %q = %v, want %v", name, f, av, wv)
			}
		}
	}
}

// A failed log write is fatal by design: silently skipping it would recreate
// the exact evidence gap -raw-dir closes. Without this test, changing that
// error path to continue would leave the suite green.
func TestRawDirWriteFailureIsFatal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	// A directory where the log file belongs makes WriteFile fail with EISDIR,
	// which does not depend on file permissions or on who is running the test.
	if err := os.MkdirAll(filepath.Join(dir, "oom_harness.log"), 0o755); err != nil {
		t.Fatalf("seed blocking directory: %v", err)
	}
	out, code := runRaw(t, standardSpec, dir)
	if code != 3 {
		t.Errorf("exit code = %d, want 3 (a failed raw-log write must be fatal)", code)
	}
	if strings.Contains(out, "\"harness\"") {
		t.Errorf("results were emitted despite a failed log write:\n%s", out)
	}
}

// logFileName is many-to-one, so distinct harnesses can want the same file.
// The runner must refuse that up front rather than let the second run overwrite
// the first one's evidence while its record keeps the stale digest.
func TestCollidingHarnessNamesAreRefused(t *testing.T) {
	const colliding = "mod::proof=SUCCESSFUL,mod__proof=SUCCESSFUL"

	// The refusal must happen BEFORE any harness is executed: rejecting after
	// running cargo would also yield exit 2 and empty stdout, so exit code
	// alone cannot tell the two orderings apart. The fake cargo appends to the
	// sentinel on every invocation, so an empty sentinel proves it never ran.
	sentinel := filepath.Join(t.TempDir(), "cargo-invocations")
	out, code := runRaw(t, colliding, filepath.Join(t.TempDir(), "logs"), "KANIRUN_SENTINEL="+sentinel)
	if code != 2 {
		t.Errorf("exit code = %d, want 2 for harness names that collide on one log file", code)
	}
	if strings.Contains(out, "\"harness\"") {
		t.Errorf("results were emitted for a colliding spec:\n%s", out)
	}
	if b, err := os.ReadFile(sentinel); err == nil && len(b) > 0 {
		t.Errorf("cargo ran %d time(s) before the collision was refused; the check must precede execution", strings.Count(string(b), "ran"))
	}

	// The SAME colliding spec without -raw-dir writes no logs, so nothing can
	// be overwritten and the run must proceed. Substituting a non-colliding
	// spec here would make this assertion pass even if the check became
	// unconditional, which is exactly what it exists to rule out.
	sentinel2 := filepath.Join(t.TempDir(), "cargo-invocations-2")
	_, code = runRaw(t, colliding, "", "KANIRUN_SENTINEL="+sentinel2)
	if code == 2 {
		t.Errorf("exit code = 2 without -raw-dir; the collision check must be conditional on raw capture")
	}
	if b, err := os.ReadFile(sentinel2); err != nil || len(b) == 0 {
		t.Errorf("cargo never ran without -raw-dir; the colliding spec should have executed normally")
	}
}

func TestLogFileNameCannotEscapeTheDirectory(t *testing.T) {
	for _, in := range []string{"../../etc/passwd", "a/b", "..", "", "mod::harness"} {
		got := logFileName(in)
		if strings.ContainsAny(got, `/\`) || strings.Contains(got, "..") {
			t.Errorf("logFileName(%q) = %q, which can escape or traverse", in, got)
		}
	}
	if got := logFileName("real_apply_mask_exact"); got != "real_apply_mask_exact.log" {
		t.Errorf("ordinary name mangled: %q", got)
	}
}
