// Command stressrepeatctl runs one test command N times, capturing every
// run's combined output to a per-run log and reading every exit code from
// the real process state (US-017 AC4: repeat counts with flake
// reconciliation for the native-thread stress suite).
//
// It NEVER aborts at the first failure: all N runs execute so that
// intermittent failures (flakes) are captured for reconciliation instead
// of truncating the record. The final exit is 0 only if every run passed.
//
// Usage:
//
//	stressrepeatctl -runs N -label darwin-arm64-debug -log-dir DIR -- cmd args...
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type config struct {
	Runs   int
	Label  string
	LogDir string
	Argv   []string
}

type failure struct {
	Run  int `json:"run"`
	Exit int `json:"exit"`
}

type summary struct {
	Label      string    `json:"label"`
	Command    []string  `json:"command"`
	Runs       int       `json:"runs"`
	Passes     int       `json:"passes"`
	Failures   []failure `json:"failures"`
	ExitCodes  []int     `json:"exit_codes"`
	StartedAt  string    `json:"started_at_utc"`
	FinishedAt string    `json:"finished_at_utc"`
}

func runLogName(label string, run int) string {
	return fmt.Sprintf("%s-run-%03d.log", label, run)
}

func summaryName(label string) string {
	return fmt.Sprintf("%s-summary.json", label)
}

func loadSummary(path string) (summary, error) {
	var s summary
	body, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(body, &s); err != nil {
		return s, fmt.Errorf("decode %s: %w", path, err)
	}
	return s, nil
}

// runRepeats executes cfg.Argv cfg.Runs times. Every run's combined
// stdout+stderr goes to its own log file; every exit code is read from
// the process state. All runs execute regardless of failures.
func runRepeats(cfg config) (summary, error) {
	if cfg.Runs < 1 {
		return summary{}, errors.New("runs must be >= 1")
	}
	if len(cfg.Argv) == 0 {
		return summary{}, errors.New("no command given")
	}
	if cfg.Label == "" {
		return summary{}, errors.New("label required")
	}
	if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
		return summary{}, err
	}
	sum := summary{
		Label:     cfg.Label,
		Command:   cfg.Argv,
		Runs:      cfg.Runs,
		Failures:  []failure{},
		ExitCodes: make([]int, 0, cfg.Runs),
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for run := 1; run <= cfg.Runs; run++ {
		logPath := filepath.Join(cfg.LogDir, runLogName(cfg.Label, run))
		logFile, err := os.Create(logPath)
		if err != nil {
			return summary{}, err
		}
		cmd := exec.Command(cfg.Argv[0], cfg.Argv[1:]...)
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		runErr := cmd.Run()
		if closeErr := logFile.Close(); closeErr != nil {
			return summary{}, closeErr
		}
		exitCode := 0
		if runErr != nil {
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				// The command could not even start: that is an
				// environment error, not a test failure tally.
				return summary{}, fmt.Errorf("run %d: %w", run, runErr)
			}
		}
		sum.ExitCodes = append(sum.ExitCodes, exitCode)
		if exitCode == 0 {
			sum.Passes++
		} else {
			sum.Failures = append(sum.Failures, failure{Run: run, Exit: exitCode})
		}
		fmt.Printf("label=%s run=%03d exit=%d\n", cfg.Label, run, exitCode)
	}
	sum.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	body, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return summary{}, err
	}
	if err := os.WriteFile(filepath.Join(cfg.LogDir, summaryName(cfg.Label)), append(body, '\n'), 0o644); err != nil {
		return summary{}, err
	}
	return sum, nil
}

func main() {
	runs := flag.Int("runs", 0, "number of repeat runs (required, >= 1)")
	label := flag.String("label", "", "platform/mode label for logs and summary (required)")
	logDir := flag.String("log-dir", "", "directory for per-run logs and the summary JSON (required)")
	flag.Parse()
	cfg := config{Runs: *runs, Label: *label, LogDir: *logDir, Argv: flag.Args()}
	sum, err := runRepeats(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stressrepeatctl: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("label=%s runs=%d passes=%d failures=%d\n", sum.Label, sum.Runs, sum.Passes, len(sum.Failures))
	if len(sum.Failures) > 0 {
		os.Exit(1)
	}
}
