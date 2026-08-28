// Command kanirun executes each Kani harness as its OWN process, reads that
// process's real exit status (never an echoed code, never a wrapper's opinion),
// and emits one JSON record per harness.
//
// It exists because the negative-control harnesses are REQUIRED to fail: a
// single `cargo kani` invocation collapses fourteen independent outcomes into
// one exit code, which is exactly the shape of reporting this lane forbids.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type result struct {
	Harness      string  `json:"harness"`
	Expectation  string  `json:"expectation"`
	ExitCode     int     `json:"exit_code"`
	Verification string  `json:"verification"`
	FailedChecks int     `json:"failed_checks"`
	TotalChecks  int     `json:"total_checks"`
	Outcome      string  `json:"outcome"`
	Matches      bool    `json:"matches_expectation"`
	FirstFailure string  `json:"first_failure_description,omitempty"`
	DurationSec  float64 `json:"duration_seconds"`
}

var (
	reSummary = regexp.MustCompile(`\*\* (\d+) of (\d+) failed`)
	reVerdict = regexp.MustCompile(`VERIFICATION:- (\w+)`)
	reFailed  = regexp.MustCompile(`(?s)Failed Checks: ([^\n]*)`)
)

func main() {
	dir := flag.String("dir", ".", "harness crate directory")
	kaniBin := flag.String("kani-bin", "", "directory containing the cargo-kani binary")
	out := flag.String("out", "", "path to write the JSON result array")
	list := flag.String("harnesses", "", "comma-separated harness=expectation pairs")
	flag.Parse()

	if *list == "" {
		fmt.Fprintln(os.Stderr, "kanirun: -harnesses is required")
		os.Exit(2)
	}

	var specs [][2]string
	for _, item := range strings.Split(*list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "kanirun: bad spec %q, want harness=expectation\n", item)
			os.Exit(2)
		}
		specs = append(specs, [2]string{parts[0], parts[1]})
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i][0] < specs[j][0] })

	results := make([]result, 0, len(specs))
	for _, spec := range specs {
		name, expect := spec[0], spec[1]
		start := time.Now()
		cmd := exec.Command("cargo", "kani", "--harness", name)
		cmd.Dir = *dir
		env := os.Environ()
		if *kaniBin != "" {
			env = append(env, "PATH="+*kaniBin+string(os.PathListSeparator)+os.Getenv("PATH"))
		}
		cmd.Env = env
		combined, err := cmd.CombinedOutput()
		elapsed := time.Since(start).Seconds()

		// Read the REAL exit status of the process, not the output text.
		exitCode := 0
		if err != nil {
			var ee *exec.ExitError
			if ok := asExitError(err, &ee); ok {
				exitCode = ee.ExitCode()
			} else {
				fmt.Fprintf(os.Stderr, "kanirun: %s: %v\n", name, err)
				os.Exit(3)
			}
		}

		text := string(combined)
		r := result{
			Harness:     name,
			Expectation: expect,
			ExitCode:    exitCode,
			DurationSec: elapsed,
		}
		if m := reVerdict.FindStringSubmatch(text); m != nil {
			r.Verification = m[1]
		}
		if m := reSummary.FindStringSubmatch(text); m != nil {
			fmt.Sscanf(m[1], "%d", &r.FailedChecks)
			fmt.Sscanf(m[2], "%d", &r.TotalChecks)
		}
		if m := reFailed.FindStringSubmatch(text); m != nil {
			line := strings.TrimSpace(strings.SplitN(m[1], "\n", 2)[0])
			if len(line) > 220 {
				line = line[:220]
			}
			r.FirstFailure = line
		}

		// The outcome is decided by the process exit status, cross-checked
		// against the printed verdict; a mismatch is reported, never smoothed.
		switch {
		case exitCode == 0 && r.Verification == "SUCCESSFUL":
			r.Outcome = "SUCCESSFUL"
		case exitCode != 0 && r.Verification == "FAILED":
			r.Outcome = "FAILED"
		case exitCode == 0:
			r.Outcome = "EXIT0_BUT_VERDICT_" + orNone(r.Verification)
		default:
			r.Outcome = fmt.Sprintf("EXIT%d_VERDICT_%s", exitCode, orNone(r.Verification))
		}
		r.Matches = r.Outcome == expect

		os.Stderr.WriteString(fmt.Sprintf("%-58s expect=%-10s got=%-10s exit=%d match=%v (%.1fs)\n",
			name, expect, r.Outcome, exitCode, r.Matches, elapsed))
		results = append(results, r)
	}

	blob, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "kanirun: %v\n", err)
		os.Exit(3)
	}
	if *out != "" {
		if err := os.WriteFile(*out, append(blob, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "kanirun: %v\n", err)
			os.Exit(3)
		}
	}
	os.Stdout.Write(append(blob, '\n'))

	mismatched := 0
	for _, r := range results {
		if !r.Matches {
			mismatched++
		}
	}
	if mismatched > 0 {
		fmt.Fprintf(os.Stderr, "kanirun: %d harness outcome(s) did not match expectation\n", mismatched)
		os.Exit(1)
	}
}

func orNone(s string) string {
	if s == "" {
		return "NONE"
	}
	return s
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}
