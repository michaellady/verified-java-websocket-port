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
const (
	oomStderr  = "CBMC appears to have run out of memory.\n"
	oomStdout  = "Checking harness oom_harness...\n** 0 of 0 failed\n\nVERIFICATION:- FAILED\n"
	goodStderr = "kani: verification time 0.4s\n"
	goodStdout = "Checking harness good_harness...\n** 0 of 12 failed\n\nVERIFICATION:- SUCCESSFUL\n"
)

func wantCombined(harness string) string {
	switch harness {
	case "oom_harness":
		return oomStderr + oomStdout
	case "good_harness":
		return goodStderr + goodStdout
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
	}
	os.Exit(9)
}

// fakeCargo builds a directory containing a `cargo` executable that re-execs
// this test binary into TestHelperProcess.
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
// and real exit code without requiring the output to parse.
func runRaw(t *testing.T, harnesses, rawDir string) (string, int) {
	t.Helper()
	args := []string{"-harnesses", harnesses}
	if rawDir != "" {
		args = append(args, "-raw-dir", rawDir)
	}
	cmd := exec.Command(buildKanirun(t), args...)
	cmd.Env = append(os.Environ(), "PATH="+fakeCargo(t)+string(os.PathListSeparator)+os.Getenv("PATH"))
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

// runKanirun runs the standard two-harness spec and parses the records.
func runKanirun(t *testing.T, rawDir string) []map[string]any {
	t.Helper()
	out, _ := runRaw(t, "good_harness=SUCCESSFUL,oom_harness=FAILED", rawDir)
	var recs []map[string]any
	if e := json.Unmarshal([]byte(out), &recs); e != nil {
		t.Fatalf("parse kanirun output: %v\n%s", e, out)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d: %s", len(recs), out)
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

	for _, name := range []string{"oom_harness", "good_harness"} {
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
// also pins every classification field to its absolute expected value.
func TestRawDirDoesNotChangeClassification(t *testing.T) {
	without := byHarness(t, runKanirun(t, ""))
	with := byHarness(t, runKanirun(t, filepath.Join(t.TempDir(), "logs")))

	fields := []string{"harness", "expectation", "exit_code", "verification",
		"failed_checks", "total_checks", "outcome", "matches_expectation"}

	// Absolute expectations, so a shift applied equally in both modes fails.
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
	}

	for name, wantRec := range want {
		a, b := without[name], with[name]
		if a == nil || b == nil {
			t.Fatalf("%s missing: without=%v with=%v", name, a != nil, b != nil)
		}
		for _, f := range fields {
			av, aok := a[f]
			bv, bok := b[f]
			if !aok || !bok {
				t.Errorf("%s field %q absent (without=%v with=%v); an absent key must not read as a match", name, f, aok, bok)
				continue
			}
			if av != bv {
				t.Errorf("%s field %q: without=%v with=%v", name, f, av, bv)
			}
			if av != wantRec[f] {
				t.Errorf("%s field %q = %v, want %v", name, f, av, wantRec[f])
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
	out, code := runRaw(t, "good_harness=SUCCESSFUL,oom_harness=FAILED", dir)
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
	out, code := runRaw(t, "mod::proof=SUCCESSFUL,mod__proof=SUCCESSFUL", filepath.Join(t.TempDir(), "logs"))
	if code != 2 {
		t.Errorf("exit code = %d, want 2 for harness names that collide on one log file", code)
	}
	if strings.Contains(out, "\"harness\"") {
		t.Errorf("results were emitted for a colliding spec:\n%s", out)
	}
	// The same spec without -raw-dir writes no logs, so it must still run.
	if _, code := runRaw(t, "good_harness=SUCCESSFUL", ""); code != 0 {
		t.Errorf("exit code = %d, want 0; the collision check must not affect runs without -raw-dir", code)
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
