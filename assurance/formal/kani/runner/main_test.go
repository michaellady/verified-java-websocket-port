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

// TestHelperProcess stands in for `cargo kani`. It is a Go helper process
// rather than a shell fixture (AGENTS.md rule 1). KANIRUN_FAKE selects the
// canned output; the harness name arrives after the "--harness" argument.
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
		fmt.Printf("Checking harness %s...\nCBMC appears to have run out of memory.\n** 0 of 0 failed\n\nVERIFICATION:- FAILED\n", name)
		os.Exit(1)
	case "good_harness":
		fmt.Printf("Checking harness %s...\n** 0 of 12 failed\n\nVERIFICATION:- SUCCESSFUL\n", name)
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

// runKanirun builds and runs the runner itself, returning its parsed records.
func runKanirun(t *testing.T, rawDir string) ([]map[string]any, string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "kanirun")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build kanirun: %v\n%s", err, out)
	}
	args := []string{"-harnesses", "good_harness=SUCCESSFUL,oom_harness=FAILED"}
	if rawDir != "" {
		args = append(args, "-raw-dir", rawDir)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "PATH="+fakeCargo(t)+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("run kanirun: %v", err)
		}
	}
	var recs []map[string]any
	if e := json.Unmarshal(out, &recs); e != nil {
		t.Fatalf("parse kanirun output: %v\n%s", e, out)
	}
	return recs, string(out)
}

// Without -raw-dir the records must be byte-identical to the pre-change shape.
// Host-vs-sandbox comparison reads these fields, so a new key appearing when
// nobody asked for raw capture would be a behavioural change.
func TestWithoutRawDirRecordsCarryNoRawFields(t *testing.T) {
	recs, raw := runKanirun(t, "")
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d: %s", len(recs), raw)
	}
	for _, r := range recs {
		if _, ok := r["raw_log"]; ok {
			t.Errorf("%v: raw_log present without -raw-dir", r["harness"])
		}
		if _, ok := r["raw_log_sha256"]; ok {
			t.Errorf("%v: raw_log_sha256 present without -raw-dir", r["harness"])
		}
	}
}

// The point of the change: the OOM explanation attempt 0129 lost must now be
// recoverable from the log, and the recorded digest must match its bytes.
func TestRawDirCapturesTheDiscardedExplanation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	recs, _ := runKanirun(t, dir)

	byName := map[string]map[string]any{}
	for _, r := range recs {
		byName[r["harness"].(string)] = r
	}
	oom := byName["oom_harness"]
	if oom == nil {
		t.Fatal("oom_harness record missing")
	}
	path, _ := oom["raw_log"].(string)
	if path == "" {
		t.Fatal("raw_log not recorded")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read raw log: %v", err)
	}
	if !strings.Contains(string(body), "CBMC appears to have run out of memory") {
		t.Fatalf("the explanation attempt 0129 lost is still not captured; log was:\n%s", body)
	}
	sum := sha256.Sum256(body)
	if got, want := oom["raw_log_sha256"], hex.EncodeToString(sum[:]); got != want {
		t.Errorf("raw_log_sha256 = %v, want %v (digest must bind the bytes on disk)", got, want)
	}
	// Every harness gets a log, not only the failing one.
	if p, _ := byName["good_harness"]["raw_log"].(string); p == "" {
		t.Error("good_harness has no raw_log; successful runs must be captured too")
	}
}

// Classification must not shift when raw capture is on. Same fake cargo, same
// outputs, so every classification field must be identical in both modes.
func TestRawDirDoesNotChangeClassification(t *testing.T) {
	without, _ := runKanirun(t, "")
	with, _ := runKanirun(t, filepath.Join(t.TempDir(), "logs"))
	if len(without) != len(with) {
		t.Fatalf("record count differs: %d vs %d", len(without), len(with))
	}
	fields := []string{"harness", "expectation", "exit_code", "verification",
		"failed_checks", "total_checks", "outcome", "matches_expectation",
		"first_failure_description"}
	for i := range without {
		for _, f := range fields {
			if without[i][f] != with[i][f] {
				t.Errorf("record %d field %q: without=%v with=%v", i, f, without[i][f], with[i][f])
			}
		}
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
