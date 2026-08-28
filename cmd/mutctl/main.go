// Command mutctl runs the E1 deterministic implementation-mutation
// campaign over the ws_core behavioral sites (gap G6 of the US-010..016
// AC-closure dossier; the 2026-08-27 owner amendment amends BEHAVIOR
// clauses to Java-faithful but does NOT waive this evidence machinery).
//
// Mutants are enumerated from a curated, committed operator table (exact
// source literals + occurrence indices — never random), applied ONE at a
// time to a scratch copy of the rust/ workspace inside the campaign
// workdir (a mutant never touches the checked-out tree and is never
// committed), and judged by two real, exit-code-read kill judges:
//
//  1. `cargo test -p ws-core` in the scratch workspace (unit, contract,
//     seed, property, and fuzz suites);
//  2. the wired 74-case public behavior corpus: the scratch-built
//     ws-oracle-harness driven by `corporactl oracle-requests` and scored
//     by `corporactl evaluate` (a mutant that passes the tests but changes
//     the recorded transcript is KILLED_BY_CORPUS).
//
// Every external command's exit code is read verbatim and recorded; the
// pristine scratch must pass BOTH judges before any mutant runs (green
// polarity), and each kill is a red-polarity read of the judge that fired.
//
// Usage:
//
//	mutctl list -root DIR
//	mutctl run  -root DIR -protected-root DIR [-workdir DIR]
//	            [-manifest-out FILE] [-only id[,id...]]
//	            [-corpus-confirm id[,id...]]
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Mutation is one curated mutant: a single deterministic textual
// substitution at a named behavioral site.
type Mutation struct {
	ID       string `json:"id"`
	Operator string `json:"operator"`
	File     string `json:"file"` // relative to the repository root
	// Match is the exact source literal to replace; Occurrence selects the
	// 1-based occurrence within the file, so the enumeration is fully
	// deterministic even for repeated literals.
	Match      string `json:"match"`
	Occurrence int    `json:"occurrence"`
	Replace    string `json:"replace"`
	// Note documents what shipped behavior the mutant corrupts.
	Note string `json:"note"`
}

// expectedPublicCases is the size of the wired public behavior corpus; the
// pristine baseline must score exactly this many passes before any mutant
// runs.
const expectedPublicCases = 74

// Verdicts.
const (
	VerdictKilledByTests  = "KILLED_BY_TESTS"
	VerdictKilledByCorpus = "KILLED_BY_CORPUS"
	VerdictSurvivor       = "SURVIVOR"
	VerdictBuildFailed    = "BUILD_FAILED"
	// VerdictEquivalentDocumented marks a survivor whose observable
	// equivalence is proven in EquivalentAnalyses.
	VerdictEquivalentDocumented = "EQUIVALENT_DOCUMENTED"
)

// Result is one manifest row.
type Result struct {
	Mutation
	Line     int    `json:"line"`
	Verdict  string `json:"verdict"`
	KilledBy string `json:"killed_by,omitempty"`
	// FailedTests is every failing test name cargo reported (not just the
	// first), and KillDetail is the verbatim first assertion/panic message
	// raised inside a test file — the read evidence that the kill came from
	// a named oracle rather than an incidental nonzero exit.
	FailedTests []string `json:"failed_tests,omitempty"`
	KillDetail  string   `json:"kill_detail,omitempty"`
	TestExit    int      `json:"test_exit"`
	// HarnessExit is the ws-oracle-harness process exit read from its real
	// ProcessState (review round 2 finding 1); CorpusExit is corporactl
	// evaluate's. A nonzero HarnessExit can never score green.
	HarnessExit    *int    `json:"harness_exit,omitempty"`
	CorpusExit     *int    `json:"corpus_exit,omitempty"`
	CorpusPassed   *int    `json:"corpus_passed,omitempty"`
	CorpusFailed   *int    `json:"corpus_failed,omitempty"`
	RuntimeSeconds float64 `json:"runtime_seconds"`
	// EquivalentAnalysis carries the documented equivalence argument for
	// EQUIVALENT_DOCUMENTED verdicts.
	EquivalentAnalysis string `json:"equivalent_analysis,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "list":
		return runList(arguments[1:], stdout, stderr)
	case "run":
		return runCampaign(arguments[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return 2
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  mutctl list -root DIR")
	fmt.Fprintln(output, "  mutctl run -root DIR -protected-root DIR [-workdir DIR]")
	fmt.Fprintln(output, "             [-manifest-out FILE] [-only id[,id...]]")
	fmt.Fprintln(output, "             [-corpus-confirm id[,id...]]")
}

// enumerate resolves every mutation against the pristine tree, returning
// per-mutation line numbers. Every match/occurrence must resolve exactly —
// a drifted site is a hard error, not a skip.
func enumerate(root string, mutations []Mutation) (map[string]int, error) {
	lines := make(map[string]int, len(mutations))
	seen := make(map[string]bool, len(mutations))
	for _, m := range mutations {
		if seen[m.ID] {
			return nil, fmt.Errorf("duplicate mutation id %q", m.ID)
		}
		seen[m.ID] = true
		source, err := os.ReadFile(filepath.Join(root, m.File))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		offset, err := occurrenceOffset(string(source), m.Match, m.Occurrence)
		if err != nil {
			return nil, fmt.Errorf("%s (%s): %w", m.ID, m.File, err)
		}
		lines[m.ID] = 1 + strings.Count(string(source[:offset]), "\n")
		if m.Match == m.Replace {
			return nil, fmt.Errorf("%s: identity replacement", m.ID)
		}
	}
	return lines, nil
}

// occurrenceOffset finds the byte offset of the n-th (1-based) occurrence.
func occurrenceOffset(source, match string, occurrence int) (int, error) {
	if occurrence < 1 {
		occurrence = 1
	}
	at := 0
	for i := 0; i < occurrence; i++ {
		next := strings.Index(source[at:], match)
		if next < 0 {
			return 0, fmt.Errorf("occurrence %d of %q not found (found %d)", occurrence, firstLine(match), i)
		}
		at += next
		if i < occurrence-1 {
			at += len(match)
		}
	}
	return at, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + "..."
	}
	return s
}

// applyMutation writes the mutated file content, returning the pristine
// content for restoration.
func applyMutation(root string, m Mutation) ([]byte, error) {
	path := filepath.Join(root, m.File)
	pristine, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	offset, err := occurrenceOffset(string(pristine), m.Match, m.Occurrence)
	if err != nil {
		return nil, err
	}
	mutated := string(pristine[:offset]) + m.Replace + string(pristine[offset+len(m.Match):])
	if err := os.WriteFile(path, []byte(mutated), 0o644); err != nil {
		return nil, err
	}
	return pristine, nil
}

func runList(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root")
	if err := flags.Parse(arguments); err != nil || *root == "" {
		printUsage(stderr)
		return 2
	}
	mutations := CuratedMutations()
	lines, err := enumerate(*root, mutations)
	if err != nil {
		fmt.Fprintln(stderr, "list:", err)
		return 1
	}
	for _, m := range mutations {
		fmt.Fprintf(stdout, "%-34s %-24s %s:%d\n", m.ID, m.Operator, m.File, lines[m.ID])
	}
	fmt.Fprintf(stdout, "total %d mutants\n", len(mutations))
	return 0
}

// copyTree copies src into dst, skipping cargo target directories.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "target" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
}

// command runs one external command, capturing combined output and the
// verbatim exit code.
func command(dir string, stdin []byte, name string, args ...string) (int, string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err == nil {
		return 0, output.String(), nil
	}
	var exitErr *exec.ExitError
	if ok := errorsAs(err, &exitErr); ok {
		return exitErr.ExitCode(), output.String(), nil
	}
	return -1, output.String(), err
}

// errorsAs is a tiny local wrapper to keep the import list stdlib-simple.
func errorsAs(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

var failedTestPattern = regexp.MustCompile(`(?m)^test (\S+) \.\.\. FAILED$`)
var compileErrorPattern = regexp.MustCompile(`(?m)^error(\[E\d+\])?:`)

// firstFailedTest extracts the first failing test name from cargo output.
func firstFailedTest(output string) string {
	if m := failedTestPattern.FindStringSubmatch(output); m != nil {
		return m[1]
	}
	return ""
}

// allFailedTests extracts every failing test name, de-duplicated in first-seen
// order (one mutant commonly trips several suites).
func allFailedTests(output string) []string {
	var names []string
	seen := map[string]bool{}
	for _, m := range failedTestPattern.FindAllStringSubmatch(output, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		names = append(names, m[1])
	}
	return names
}

// assertionPattern captures EVERY panic location and its message line,
// wherever it was raised. Review round 2 finding 2: this pattern used to
// require `tests/` in the path, so kills delivered by in-crate #[cfg(test)]
// modules under src/ (for example
// fragment::accumulator_tests::finish_releases_the_accumulated_bytes_leaving_no_stale_retention)
// silently produced an empty kill_detail — four rows of the round-1
// manifest had that hole.
var assertionPattern = regexp.MustCompile(`panicked at ([^\n]*\.rs:\d+:\d+):\n([^\n]*)`)

// killDetail returns "<file:line:col>: <message>" for the assertion that
// killed the mutant.
//
// Preference: an integration-test frame (a `tests/` path) wins when one
// exists, because for those suites the library panic is only the raw cause
// and the test-side oracle frame carries the attributed message (case label,
// seed, oracle name). Otherwise the FIRST panic of any kind is reported —
// which is exactly the assertion for an in-crate unit test, whose file lives
// under src/ and is indistinguishable from library code by path alone.
func killDetail(output string) string {
	matches := assertionPattern.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return ""
	}
	for _, m := range matches {
		if strings.Contains(m[1], "tests/") {
			return strings.TrimSpace(m[1]) + ": " + strings.TrimSpace(m[2])
		}
	}
	return strings.TrimSpace(matches[0][1]) + ": " + strings.TrimSpace(matches[0][2])
}

type corpusReport struct {
	Executed int      `json:"executed"`
	Passed   int      `json:"passed"`
	Failed   int      `json:"failed"`
	Failures []string `json:"failures"`
}

// corpusJudgment is everything judge 2 READ from the real processes: the
// harness build exit, the harness process exit (from its ProcessState, never
// inferred from output text), the corporactl evaluate exit, and the parsed
// report. Review round 2 finding 1: the harness exit used to be discarded at
// the call site, which let a complete transcript from a nonzero harness run
// score green. It is now a first-class part of the verdict and of the
// manifest.
type corpusJudgment struct {
	HarnessBuildExit int          `json:"harness_build_exit"`
	HarnessExit      int          `json:"harness_exit"`
	EvaluateExit     int          `json:"evaluate_exit"`
	Report           corpusReport `json:"-"`
}

// corpusVerdict decides judge 2's outcome from the read exit codes alone. A
// nonzero harness exit is NEVER green: either the mutant crashed the harness
// (a real corpus kill) or the run is untrustworthy (also not a pass), and
// the two are indistinguishable from the outside, so the conservative
// reading is the only honest one.
func corpusVerdict(judgment corpusJudgment) (bool, string) {
	if judgment.HarnessExit != 0 {
		return true, fmt.Sprintf("harness exit %d (transcript not trustworthy)", judgment.HarnessExit)
	}
	if judgment.EvaluateExit != 0 {
		if len(judgment.Report.Failures) > 0 {
			return true, failureScenario(judgment.Report.Failures[0])
		}
		return true, "corpus evaluate nonzero exit"
	}
	return false, ""
}

// baselineCorpusOK gates the campaign on the PRISTINE scratch: every read
// exit must be zero and every one of the expected cases must pass, or no
// mutant runs at all.
func baselineCorpusOK(judgment corpusJudgment, expectedCases int) error {
	if judgment.HarnessBuildExit != 0 {
		return fmt.Errorf("pristine harness build exit=%d", judgment.HarnessBuildExit)
	}
	if judgment.HarnessExit != 0 {
		return fmt.Errorf("pristine harness process exit=%d", judgment.HarnessExit)
	}
	if judgment.EvaluateExit != 0 {
		return fmt.Errorf("pristine corpus evaluate exit=%d", judgment.EvaluateExit)
	}
	if judgment.Report.Passed != expectedCases || judgment.Report.Failed != 0 {
		return fmt.Errorf("pristine corpus scored %d/%d passed with %d failed (want %d/%d, 0 failed)",
			judgment.Report.Passed, judgment.Report.Executed, judgment.Report.Failed,
			expectedCases, expectedCases)
	}
	return nil
}

// validateKillDetails enforces the manifest invariant the receipt promises:
// every KILLED_BY_TESTS row carries the verbatim assertion that killed it
// (review round 2 finding 2). Returns one problem string per offending row.
func validateKillDetails(results []Result) []string {
	var problems []string
	for _, r := range results {
		if r.Verdict == VerdictKilledByTests && strings.TrimSpace(r.KillDetail) == "" {
			problems = append(problems, fmt.Sprintf(
				"%s: KILLED_BY_TESTS (killed_by=%s) with no kill_detail", r.ID, r.KilledBy))
		}
	}
	return problems
}

// failureScenario extracts the scenario id prefix of one corpus failure
// line ("us005.pub.0007: ..." -> "us005.pub.0007").
func failureScenario(failure string) string {
	if i := strings.Index(failure, ":"); i > 0 {
		return failure[:i]
	}
	if len(failure) > 80 {
		return failure[:80]
	}
	return failure
}

func parseCorpusReport(output string) (corpusReport, bool) {
	// The report is one JSON object on stdout; decode exactly one value
	// from the first brace (tolerating any trailing diagnostics).
	start := strings.Index(output, "{")
	if start < 0 {
		return corpusReport{}, false
	}
	var report corpusReport
	decoder := json.NewDecoder(strings.NewReader(output[start:]))
	if err := decoder.Decode(&report); err != nil {
		return corpusReport{}, false
	}
	return report, true
}

func runCampaign(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root")
	protectedRoot := flags.String("protected-root", "", "protected custodian root")
	workdir := flags.String("workdir", "", "campaign workdir (default: a fresh temp dir)")
	manifestOut := flags.String("manifest-out", "", "write the campaign manifest JSON here")
	only := flags.String("only", "", "comma-separated mutation ids to run")
	corpusConfirm := flags.String("corpus-confirm", "",
		"comma-separated ids whose corpus verdict is read even after a test kill (judge-2 polarity)")
	if err := flags.Parse(arguments); err != nil || *root == "" || *protectedRoot == "" {
		printUsage(stderr)
		return 2
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 1
	}
	if *workdir == "" {
		dir, err := os.MkdirTemp("", "mutctl-e1-")
		if err != nil {
			fmt.Fprintln(stderr, "run:", err)
			return 1
		}
		*workdir = dir
	}
	absWork, err := filepath.Abs(*workdir)
	if err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 1
	}
	if strings.HasPrefix(absWork+string(filepath.Separator), absRoot+string(filepath.Separator)) {
		fmt.Fprintln(stderr, "run: the workdir must live OUTSIDE the repository (mutants are never committed)")
		return 2
	}

	mutations := CuratedMutations()
	if *only != "" {
		keep := map[string]bool{}
		for _, id := range strings.Split(*only, ",") {
			keep[strings.TrimSpace(id)] = true
		}
		var filtered []Mutation
		for _, m := range mutations {
			if keep[m.ID] {
				filtered = append(filtered, m)
			}
		}
		mutations = filtered
	}
	confirm := map[string]bool{}
	if *corpusConfirm != "" {
		for _, id := range strings.Split(*corpusConfirm, ",") {
			confirm[strings.TrimSpace(id)] = true
		}
	}

	lines, err := enumerate(absRoot, mutations)
	if err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 1
	}

	// Scratch workspace: one copy of rust/, reused across mutants with
	// file-level restore (incremental builds stay warm).
	scratchRust := filepath.Join(absWork, "scratch", "rust")
	if _, err := os.Stat(scratchRust); os.IsNotExist(err) {
		fmt.Fprintln(stdout, "mutctl: copying rust/ workspace into scratch...")
		if err := copyTree(filepath.Join(absRoot, "rust"), scratchRust); err != nil {
			fmt.Fprintln(stderr, "run: scratch copy:", err)
			return 1
		}
	}

	// The 74-case public request stream, generated once from the REAL root.
	requestsPath := filepath.Join(absWork, "public-requests.jsonl")
	corporactl := filepath.Join(absWork, "corporactl")
	if exit, out, err := command(absRoot, nil, "go", "build", "-o", corporactl, "./cmd/corporactl"); err != nil || exit != 0 {
		fmt.Fprintf(stderr, "run: corporactl build exit=%d err=%v\n%s", exit, err, out)
		return 1
	}
	if exit, out, err := command(absRoot, nil, corporactl, "oracle-requests",
		"--root", absRoot, "--protected-root", *protectedRoot,
		"--tier", "public", "--out", requestsPath); err != nil || exit != 0 {
		fmt.Fprintf(stderr, "run: oracle-requests exit=%d err=%v\n%s", exit, err, out)
		return 1
	}
	requests, err := os.ReadFile(requestsPath)
	if err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 1
	}

	// GREEN polarity: the pristine scratch must pass BOTH judges.
	fmt.Fprintln(stdout, "mutctl: baseline judge 1 (cargo test -p ws-core, pristine scratch)...")
	baselineTestExit, baselineOut, err := command(scratchRust, nil, "cargo", "test", "-p", "ws-core")
	if err != nil || baselineTestExit != 0 {
		fmt.Fprintf(stderr, "run: pristine cargo test exit=%d err=%v\n%s", baselineTestExit, err, tail(baselineOut, 2000))
		return 1
	}
	fmt.Fprintln(stdout, "mutctl: baseline judge 2 (74-case public corpus, pristine scratch)...")
	baselineJudgment, err := corpusJudge(scratchRust, absRoot, *protectedRoot, corporactl, requests, filepath.Join(absWork, "baseline-transcript.jsonl"))
	if err != nil {
		fmt.Fprintf(stderr, "run: pristine corpus judge: %v (build_exit=%d harness_exit=%d evaluate_exit=%d)\n",
			err, baselineJudgment.HarnessBuildExit, baselineJudgment.HarnessExit, baselineJudgment.EvaluateExit)
		return 1
	}
	if err := baselineCorpusOK(baselineJudgment, expectedPublicCases); err != nil {
		fmt.Fprintln(stderr, "run: pristine corpus judge rejected the baseline:", err)
		return 1
	}
	baselineReport := baselineJudgment.Report
	fmt.Fprintf(stdout, "mutctl: baseline green — tests exit 0, harness exit %d, corpus %d/%d evaluate exit %d\n",
		baselineJudgment.HarnessExit, baselineReport.Passed, baselineReport.Executed,
		baselineJudgment.EvaluateExit)

	var results []Result
	for index, m := range mutations {
		started := time.Now()
		result := Result{Mutation: m, Line: lines[m.ID]}
		pristine, err := applyMutation(scratchRust, scratchRelative(m))
		if err != nil {
			fmt.Fprintf(stderr, "run: %s apply: %v\n", m.ID, err)
			return 1
		}
		testExit, testOut, err := command(scratchRust, nil, "cargo", "test", "-p", "ws-core")
		if err != nil {
			restore(scratchRust, m, pristine, stderr)
			fmt.Fprintf(stderr, "run: %s cargo test spawn: %v\n", m.ID, err)
			return 1
		}
		result.TestExit = testExit
		switch {
		case testExit != 0 && compileErrorPattern.MatchString(testOut) && firstFailedTest(testOut) == "":
			result.Verdict = VerdictBuildFailed
			result.KilledBy = "compile error (non-viable mutant)"
		case testExit != 0:
			result.Verdict = VerdictKilledByTests
			result.FailedTests = allFailedTests(testOut)
			result.KillDetail = killDetail(testOut)
			if name := firstFailedTest(testOut); name != "" {
				result.KilledBy = name
			} else if strings.Contains(testOut, "panicked at") {
				result.KilledBy = "test-run panic"
			} else {
				result.KilledBy = "cargo test nonzero exit"
			}
		}
		runCorpus := result.Verdict == "" || confirm[m.ID]
		if runCorpus {
			transcript := filepath.Join(absWork, fmt.Sprintf("transcript-%s.jsonl", m.ID))
			judgment, err := corpusJudge(scratchRust, absRoot, *protectedRoot, corporactl, requests, transcript)
			// A judge error whose harness exited nonzero is a CORPUS KILL,
			// not a campaign abort: the mutant broke the harness, which is
			// exactly what judge 2 exists to detect. Any other error is a
			// real campaign failure and still aborts.
			if err != nil && judgment.HarnessExit == 0 {
				restore(scratchRust, m, pristine, stderr)
				fmt.Fprintf(stderr, "run: %s corpus judge: %v\n", m.ID, err)
				return 1
			}
			harnessExit := judgment.HarnessExit
			evaluateExit := judgment.EvaluateExit
			result.HarnessExit = &harnessExit
			result.CorpusExit = &evaluateExit
			result.CorpusPassed = &judgment.Report.Passed
			result.CorpusFailed = &judgment.Report.Failed
			corpusKilled, corpusKilledBy := corpusVerdict(judgment)
			if result.Verdict == "" {
				if corpusKilled {
					result.Verdict = VerdictKilledByCorpus
					result.KilledBy = corpusKilledBy
				} else {
					result.Verdict = VerdictSurvivor
				}
			}
		}
		restore(scratchRust, m, pristine, stderr)
		result.RuntimeSeconds = time.Since(started).Seconds()
		results = append(results, result)
		fmt.Fprintf(stdout, "mutctl: [%d/%d] %-34s %-16s killed_by=%s test_exit=%d (%.1fs)\n",
			index+1, len(mutations), m.ID, result.Verdict, result.KilledBy, result.TestExit,
			result.RuntimeSeconds)
	}

	// Post-campaign pristine re-verification: the scratch must be green
	// again (proves the restore discipline held).
	verifyExit, _, err := command(scratchRust, nil, "cargo", "test", "-p", "ws-core")
	if err != nil || verifyExit != 0 {
		fmt.Fprintf(stderr, "run: post-campaign pristine verification failed exit=%d err=%v\n", verifyExit, err)
		return 1
	}

	analyses := EquivalentAnalyses()
	undocumentedSurvivors := 0
	for i := range results {
		if results[i].Verdict != VerdictSurvivor {
			continue
		}
		if analysis, ok := analyses[results[i].ID]; ok {
			results[i].Verdict = VerdictEquivalentDocumented
			results[i].EquivalentAnalysis = analysis
		} else {
			undocumentedSurvivors++
		}
	}
	tallies := map[string]int{}
	for _, r := range results {
		tallies[r.Verdict]++
	}
	// Manifest invariant (review round 2 finding 2): a KILLED_BY_TESTS row
	// without its verbatim killing assertion is a manifest with a hole in
	// it, not evidence. Fail the run rather than write one.
	killDetailProblems := validateKillDetails(results)
	for _, problem := range killDetailProblems {
		fmt.Fprintln(stderr, "run: manifest invariant violated:", problem)
	}
	manifest := map[string]any{
		"schema_version": "1.1.0",
		"campaign":       "e1-ws-core-mutation-campaign",
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"judges": []string{
			"cargo test -p ws-core (scratch workspace)",
			"corporactl oracle-requests | ws-oracle-harness (scratch build) | corporactl evaluate --tier public",
		},
		"judge_2_exit_discipline": "harness_build_exit, harness_exit and corpus_exit are each read from the real ProcessState; a nonzero harness_exit can never score green (corpusVerdict)",
		"baseline": map[string]any{
			"test_exit":          baselineTestExit,
			"harness_build_exit": baselineJudgment.HarnessBuildExit,
			"harness_exit":       baselineJudgment.HarnessExit,
			"corpus_exit":        baselineJudgment.EvaluateExit,
			"corpus_executed":    baselineReport.Executed,
			"corpus_passed":      baselineReport.Passed,
			"corpus_failed":      baselineReport.Failed,
		},
		"tallies":              tallies,
		"kill_detail_complete": len(killDetailProblems) == 0,
		"mutants":              results,
	}
	rendered, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 1
	}
	rendered = append(rendered, '\n')
	if *manifestOut != "" {
		if err := os.WriteFile(*manifestOut, rendered, 0o644); err != nil {
			fmt.Fprintln(stderr, "run:", err)
			return 1
		}
		fmt.Fprintf(stdout, "mutctl: manifest written to %s\n", *manifestOut)
	} else {
		fmt.Fprintf(stdout, "%s", rendered)
	}
	fmt.Fprintf(stdout, "mutctl: tallies %v kill_detail_complete=%v\n",
		tallies, len(killDetailProblems) == 0)
	if len(killDetailProblems) > 0 {
		return 4 // the manifest is incomplete: fix the extractor, re-run
	}
	if undocumentedSurvivors > 0 || tallies[VerdictBuildFailed] > 0 {
		return 3 // undocumented survivors / non-viable mutants demand follow-up
	}
	return 0
}

// scratchRelative rewrites a repo-relative rust/ path to be relative to the
// scratch rust/ copy.
func scratchRelative(m Mutation) Mutation {
	m.File = strings.TrimPrefix(m.File, "rust/")
	return m
}

func restore(scratchRust string, m Mutation, pristine []byte, stderr io.Writer) {
	path := filepath.Join(scratchRust, strings.TrimPrefix(m.File, "rust/"))
	if err := os.WriteFile(path, pristine, 0o644); err != nil {
		fmt.Fprintf(stderr, "run: FATAL restore failure for %s: %v\n", m.ID, err)
		os.Exit(1)
	}
}

// corpusJudge builds the harness in the scratch workspace, replays the
// public requests through it, and scores the transcript with corporactl.
// Every one of the three external commands' exit codes is read from its real
// ProcessState (via `command`) and returned in the judgment — none is
// inferred from output text and none is discarded.
func corpusJudge(scratchRust, root, protectedRoot, corporactl string, requests []byte, transcriptPath string) (corpusJudgment, error) {
	judgment := corpusJudgment{}
	buildExit, buildOut, err := command(scratchRust, nil, "cargo", "build", "-p", "ws-oracle-harness")
	judgment.HarnessBuildExit = buildExit
	if err != nil || buildExit != 0 {
		return judgment, fmt.Errorf("harness build exit=%d err=%v: %s", buildExit, err, tail(buildOut, 1200))
	}
	harness := filepath.Join(scratchRust, "target", "debug", "ws-oracle-harness")
	// Review round 2 finding 1: this exit code was previously discarded.
	harnessExit, transcript, err := command(scratchRust, requests, harness)
	judgment.HarnessExit = harnessExit
	if err != nil {
		judgment.HarnessExit = -1
		return judgment, fmt.Errorf("harness run: %w", err)
	}
	// The transcript is retained even when the harness exited nonzero: it is
	// evidence about the failure, not a pass certificate. corpusVerdict
	// refuses to score it green regardless of what it contains.
	if err := os.WriteFile(transcriptPath, []byte(transcript), 0o644); err != nil {
		return judgment, err
	}
	evaluateExit, out, err := command(root, nil, corporactl, "evaluate",
		"--root", root, "--protected-root", protectedRoot,
		"--tier", "public", "--transcript", transcriptPath)
	judgment.EvaluateExit = evaluateExit
	if err != nil {
		return judgment, err
	}
	report, ok := parseCorpusReport(out)
	if !ok {
		// A harness that exited nonzero routinely produces output evaluate
		// cannot score; report that as the harness failure it is rather than
		// as an unparseable-output mystery.
		if harnessExit != 0 {
			return judgment, fmt.Errorf("harness exit=%d and evaluate output unparseable: %s",
				harnessExit, tail(out, 800))
		}
		return judgment, fmt.Errorf("unparseable evaluate output: %s", tail(out, 800))
	}
	judgment.Report = report
	return judgment, nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
