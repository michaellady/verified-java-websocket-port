package main

import (
	"os"
	"path/filepath"
	"testing"
)

// All runs pass: every exit code is read as 0, every per-run log exists,
// and the summary tallies passes == runs with no failures.
func TestAllRunsPassTallyAndLogs(t *testing.T) {
	dir := t.TempDir()
	sum, err := runRepeats(config{
		Runs:   3,
		Label:  "unit-pass",
		LogDir: dir,
		Argv:   []string{"/bin/sh", "-c", "echo stress-ok"},
	})
	if err != nil {
		t.Fatalf("runRepeats: %v", err)
	}
	if sum.Runs != 3 || sum.Passes != 3 || len(sum.Failures) != 0 {
		t.Fatalf("want 3/3 passes, no failures; got %+v", sum)
	}
	for run := 1; run <= 3; run++ {
		log := filepath.Join(dir, runLogName("unit-pass", run))
		body, err := os.ReadFile(log)
		if err != nil {
			t.Fatalf("per-run log %d missing: %v", run, err)
		}
		if string(body) != "stress-ok\n" {
			t.Fatalf("run %d log content = %q", run, body)
		}
	}
	if len(sum.ExitCodes) != 3 {
		t.Fatalf("want 3 recorded exit codes, got %v", sum.ExitCodes)
	}
	for i, code := range sum.ExitCodes {
		if code != 0 {
			t.Fatalf("run %d exit = %d, want 0", i+1, code)
		}
	}
}

// A deterministic mid-sequence failure: the tool must complete ALL runs
// (never abort at the first failure — flakes have to be captured), record
// the failing run number with its real exit code, and still tally the
// passing runs.
func TestMidSequenceFailureIsRecordedAndAllRunsComplete(t *testing.T) {
	dir := t.TempDir()
	ctr := filepath.Join(dir, "ctr")
	script := `n=$(cat "$0" 2>/dev/null || echo 0); n=$((n+1)); printf %s "$n" > "$0"; if [ "$n" -eq 2 ]; then exit 7; fi; echo pass-$n`
	sum, err := runRepeats(config{
		Runs:   3,
		Label:  "unit-flake",
		LogDir: dir,
		Argv:   []string{"/bin/sh", "-c", script, ctr},
	})
	if err != nil {
		t.Fatalf("runRepeats: %v", err)
	}
	if sum.Runs != 3 || sum.Passes != 2 {
		t.Fatalf("want runs=3 passes=2, got %+v", sum)
	}
	if len(sum.Failures) != 1 || sum.Failures[0].Run != 2 || sum.Failures[0].Exit != 7 {
		t.Fatalf("want exactly failure {run:2 exit:7}, got %+v", sum.Failures)
	}
	// The third run must have executed after the failure.
	if _, err := os.Stat(filepath.Join(dir, runLogName("unit-flake", 3))); err != nil {
		t.Fatalf("run 3 did not execute after the run-2 failure: %v", err)
	}
	want := []int{0, 7, 0}
	if len(sum.ExitCodes) != len(want) {
		t.Fatalf("exit codes = %v, want %v", sum.ExitCodes, want)
	}
	for i := range want {
		if sum.ExitCodes[i] != want[i] {
			t.Fatalf("exit codes = %v, want %v", sum.ExitCodes, want)
		}
	}
}

// The summary JSON artifact is written next to the logs and round-trips
// the tally.
func TestSummaryArtifactWritten(t *testing.T) {
	dir := t.TempDir()
	sum, err := runRepeats(config{
		Runs:   1,
		Label:  "unit-artifact",
		LogDir: dir,
		Argv:   []string{"/bin/sh", "-c", "true"},
	})
	if err != nil {
		t.Fatalf("runRepeats: %v", err)
	}
	loaded, err := loadSummary(filepath.Join(dir, summaryName("unit-artifact")))
	if err != nil {
		t.Fatalf("summary artifact: %v", err)
	}
	if loaded.Label != sum.Label || loaded.Runs != sum.Runs || loaded.Passes != sum.Passes {
		t.Fatalf("summary round-trip mismatch: wrote %+v, read %+v", sum, loaded)
	}
}
