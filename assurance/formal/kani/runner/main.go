// Command kanirun executes each Kani harness as its OWN process, reads that
// process's real exit status (never an echoed code, never a wrapper's opinion),
// and emits one JSON record per harness.
//
// It exists because the negative-control harnesses are REQUIRED to fail: a
// single `cargo kani` invocation collapses fourteen independent outcomes into
// one exit code, which is exactly the shape of reporting this lane forbids.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

	// Raw-output provenance. Both are omitempty, so records are byte-identical
	// to the pre-raw-dir shape when -raw-dir is unset — host-vs-sandbox
	// comparison reads the classification fields above and must not see a
	// difference merely because one side captured logs.
	RawLog       string `json:"raw_log,omitempty"`
	RawLogSHA256 string `json:"raw_log_sha256,omitempty"`
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
	rawDir := flag.String("raw-dir", "", "directory to write each harness's full combined output to (<dir>/<harness>.log)")
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

	// logFileName is many-to-one: "mod::proof" and "mod__proof" both sanitize
	// to "mod__proof". Without this check the second harness would overwrite
	// the first one's log while the first one's JSON record kept naming that
	// path with its own now-replaced digest -- evidence silently swapped under
	// a record that still looks intact, which is the exact failure shape
	// -raw-dir exists to prevent. Refuse the ambiguity instead of resolving it
	// with a hash suffix: a collision here is a mistake in -harnesses worth
	// surfacing, and an unreadable filename is a poor trade for hiding it.
	// Checked only under -raw-dir, so runs without it are unaffected.
	if *rawDir != "" {
		byFile := make(map[string]string, len(specs))
		for _, spec := range specs {
			f := logFileName(spec[0])
			if prev, dup := byFile[f]; dup {
				fmt.Fprintf(os.Stderr, "kanirun: -raw-dir: harnesses %q and %q both map to %q\n", prev, spec[0], f)
				os.Exit(2)
			}
			byFile[f] = spec[0]
		}
		if err := os.MkdirAll(*rawDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "kanirun: -raw-dir: %v\n", err)
			os.Exit(3)
		}
	}

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

		r := result{
			Harness:     name,
			Expectation: expect,
			ExitCode:    exitCode,
			DurationSec: elapsed,
		}

		// Persist the FULL combined output before any parsing. Attempt 0129
		// lost Kani's "CBMC appears to have run out of memory" line this way:
		// the summary fields recorded a 0-of-0 FAILED signature while the
		// explanation was discarded, so the cause could only be attributed
		// circumstantially by reproducing the signature elsewhere. A write
		// failure here is fatal rather than skipped — silently not writing
		// the log recreates exactly that gap.
		if *rawDir != "" {
			path := filepath.Join(*rawDir, logFileName(name))
			if err := os.WriteFile(path, combined, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "kanirun: %s: raw log: %v\n", name, err)
				os.Exit(3)
			}
			sum := sha256.Sum256(combined)
			r.RawLog = path
			r.RawLogSHA256 = hex.EncodeToString(sum[:])
		}

		text := string(combined)
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

// logFileName maps a harness name to a filesystem-safe log file name. Kani
// harness names are Rust paths, so a separator is possible; anything outside
// the conservative set is replaced so a name can never escape -raw-dir or
// collide with a directory component.
func logFileName(harness string) string {
	// Dots are excluded along with separators. A name like "../x" cannot
	// traverse once its slashes are gone, but keeping the dots would leave
	// ".._x.log" on disk, which reads as suspicious and invites a future
	// reader to wonder whether it escaped. The stricter rule is free.
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, harness)
	if strings.Trim(safe, "_") == "" {
		safe = "harness"
	}
	return safe + ".log"
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
