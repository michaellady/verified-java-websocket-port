package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The curated table must enumerate exactly against the checked-out tree:
// every literal present at its declared occurrence, no duplicate ids, no
// identity replacements. This is the drift guard — a source refactor that
// moves a mutation site fails here, in plain `go test`, before any
// campaign runs.
func TestCuratedMutationsEnumerateAgainstTheRepo(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	mutations := CuratedMutations()
	if len(mutations) < 50 {
		t.Fatalf("curated table shrank to %d mutants", len(mutations))
	}
	lines, err := enumerate(root, mutations)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	for _, m := range mutations {
		if lines[m.ID] < 1 {
			t.Errorf("%s: no line resolved", m.ID)
		}
		if m.Note == "" {
			t.Errorf("%s: missing behavioral note", m.ID)
		}
		if !strings.HasPrefix(m.File, "rust/ws-core/src/") {
			t.Errorf("%s: mutation outside ws-core src: %s", m.ID, m.File)
		}
	}
}

func TestOccurrenceOffset(t *testing.T) {
	source := "alpha beta alpha gamma alpha"
	first, err := occurrenceOffset(source, "alpha", 1)
	if err != nil || first != 0 {
		t.Fatalf("first: %d %v", first, err)
	}
	second, err := occurrenceOffset(source, "alpha", 2)
	if err != nil || second != 11 {
		t.Fatalf("second: %d %v", second, err)
	}
	third, err := occurrenceOffset(source, "alpha", 3)
	if err != nil || third != 23 {
		t.Fatalf("third: %d %v", third, err)
	}
	if _, err := occurrenceOffset(source, "alpha", 4); err == nil {
		t.Fatal("fourth occurrence must not resolve")
	}
	if _, err := occurrenceOffset(source, "delta", 1); err == nil {
		t.Fatal("missing literal must not resolve")
	}
}

// Apply/restore round trip: the mutation lands at exactly the declared
// occurrence and the returned pristine bytes restore the file identically.
func TestApplyMutationRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "src", "demo.rs")
	original := "if a > b { x } // one\nif a > b { y } // two\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	m := Mutation{
		ID: "demo", Operator: "comparison-flip", File: "src/demo.rs",
		Match: "if a > b", Occurrence: 2, Replace: "if a >= b",
	}
	pristine, err := applyMutation(dir, m)
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "if a > b { x } // one\nif a >= b { y } // two\n"
	if string(mutated) != want {
		t.Fatalf("mutated content wrong:\n%s", mutated)
	}
	if err := os.WriteFile(path, pristine, 0o644); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != original {
		t.Fatal("restore did not reproduce the pristine bytes")
	}
}

func TestFirstFailedTest(t *testing.T) {
	output := "running 3 tests\ntest a::ok_case ... ok\ntest b::bad_case ... FAILED\ntest c ... ok\n"
	if got := firstFailedTest(output); got != "b::bad_case" {
		t.Fatalf("got %q", got)
	}
	if got := firstFailedTest("all fine"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestParseCorpusReport(t *testing.T) {
	output := "noise before\n{\n  \"executed\": 74,\n  \"failed\": 2,\n  \"passed\": 72,\n  \"failures\": [\"us005.pub.0001: close_code 1000, expected 1002\"]\n}\ntrailing diagnostics\n"
	report, ok := parseCorpusReport(output)
	if !ok {
		t.Fatal("report must parse")
	}
	if report.Executed != 74 || report.Passed != 72 || report.Failed != 2 {
		t.Fatalf("counts wrong: %+v", report)
	}
	if len(report.Failures) != 1 || failureScenario(report.Failures[0]) != "us005.pub.0001" {
		t.Fatalf("failures wrong: %+v", report.Failures)
	}
	if _, ok := parseCorpusReport("no json"); ok {
		t.Fatal("garbage must not parse")
	}
}

// --- Review round 2, finding 1 (session 01a045b0-3189) --------------------
// "cmd/mutctl/main.go:608 discards the harness process exit code,
// contradicting the claimed verbatim-exit discipline and permitting a
// complete transcript from a nonzero harness run to score green."
//
// The judge-2 verdict is now a pure function of the three READ exit codes
// plus the parsed report, so the discard is impossible to reintroduce
// silently: a nonzero harness exit can never produce a green corpus verdict,
// even when the transcript is complete and evaluate scores it 74/74.
func TestNonzeroHarnessExitCanNeverScoreGreen(t *testing.T) {
	greenReport := corpusReport{Executed: 74, Passed: 74, Failed: 0}

	// The exact hazard named in the finding: a COMPLETE, fully passing
	// transcript produced by a harness that exited nonzero.
	killed, killedBy := corpusVerdict(corpusJudgment{
		HarnessExit:  101,
		EvaluateExit: 0,
		Report:       greenReport,
	})
	if !killed {
		t.Fatal("a nonzero harness exit scored GREEN with a complete 74/74 transcript")
	}
	if !strings.Contains(killedBy, "harness exit") {
		t.Fatalf("the harness exit must be named in the verdict, got %q", killedBy)
	}

	// A negative harness exit (spawn failure / signal) is equally not green.
	if killed, _ := corpusVerdict(corpusJudgment{
		HarnessExit:  -1,
		EvaluateExit: 0,
		Report:       greenReport,
	}); !killed {
		t.Fatal("a failed harness spawn scored GREEN")
	}

	// Evaluate's own nonzero exit still kills, and names the scenario.
	killed, killedBy = corpusVerdict(corpusJudgment{
		HarnessExit:  0,
		EvaluateExit: 1,
		Report: corpusReport{
			Executed: 74, Passed: 73, Failed: 1,
			Failures: []string{"us005.pub.0021: close events 2, expected 1"},
		},
	})
	if !killed || killedBy != "us005.pub.0021" {
		t.Fatalf("evaluate kill wrong: killed=%v killedBy=%q", killed, killedBy)
	}

	// Only all-zero exits with a clean report are green.
	if killed, _ := corpusVerdict(corpusJudgment{
		HarnessExit:  0,
		EvaluateExit: 0,
		Report:       greenReport,
	}); killed {
		t.Fatal("an all-green judge run must not report a kill")
	}
}

// The baseline gate must refuse to start a campaign whose PRISTINE scratch
// produced a nonzero harness exit, whatever the transcript says.
func TestBaselineRejectsANonzeroHarnessExit(t *testing.T) {
	green := corpusJudgment{HarnessExit: 0, EvaluateExit: 0, Report: corpusReport{Executed: 74, Passed: 74}}
	if err := baselineCorpusOK(green, 74); err != nil {
		t.Fatalf("an all-green baseline must be accepted: %v", err)
	}
	dirty := green
	dirty.HarnessExit = 3
	if err := baselineCorpusOK(dirty, 74); err == nil {
		t.Fatal("a baseline whose harness exited 3 must abort the campaign")
	}
}

// --- Review round 2, finding 2 (session 01a045b0-3189) --------------------
// "cmd/mutctl/main.go:298 extracts assertions only from paths containing
// `tests/`; consequently four killed mutants -- including
// m016-stale-fragment-retained -- have no promised kill_detail in the
// committed manifest."
//
// kill_detail must be captured wherever the killing assertion lives,
// including in-crate #[cfg(test)] modules under src/.
func TestKillDetailCapturesInCrateUnitTestAssertions(t *testing.T) {
	// The verbatim shape cargo emits for the in-crate fragment unit test
	// that kills m016-stale-fragment-retained.
	unitOutput := "running 18 tests\n" +
		"test fragment::accumulator_tests::finish_releases_the_accumulated_bytes_leaving_no_stale_retention ... FAILED\n" +
		"\nthread 'fragment::accumulator_tests::finish_releases_the_accumulated_bytes_leaving_no_stale_retention' (102856416) panicked at ws-core/src/fragment.rs:104:9:\n" +
		"assertion `left == right` failed: finish must leave ZERO retained bytes; a stale buffer survived delivery\n" +
		"  left: 5\n right: 0\n"
	got := killDetail(unitOutput)
	if got == "" {
		t.Fatal("an in-crate src/ unit-test assertion produced NO kill_detail")
	}
	if !strings.Contains(got, "ws-core/src/fragment.rs:104:9") ||
		!strings.Contains(got, "a stale buffer survived delivery") {
		t.Fatalf("kill_detail lost the retention assertion: %q", got)
	}

	// Integration-test assertions keep the existing (more informative)
	// behavior: when a library-side panic and a test-side oracle panic are
	// both present, the ORACLE message wins even though the library panic
	// comes first in the output.
	layered := "thread 'family_config_boundaries' (1) panicked at ws-core/src/framing.rs:483:40:\n" +
		"range end index 55 out of range for slice of length 54\n" +
		"\nthread 'family_config_boundaries' (1) panicked at ws-core/tests/adversarial_fuzz.rs:288:13:\n" +
		"config_boundary case 21: panic caught by the fuzz oracle: range end index 55 out of range for slice of length 54\n"
	got = killDetail(layered)
	if !strings.Contains(got, "tests/adversarial_fuzz.rs:288:13") ||
		!strings.Contains(got, "panic caught by the fuzz oracle") {
		t.Fatalf("the test-side oracle assertion must win, got %q", got)
	}

	// A library-only panic with no test-side frame is still captured rather
	// than silently dropped.
	libOnly := "thread 'main' (1) panicked at ws-core/src/framing.rs:483:40:\n" +
		"range end index 7 out of range for slice of length 6\n"
	if got := killDetail(libOnly); !strings.Contains(got, "src/framing.rs:483:40") {
		t.Fatalf("a library-only panic must still be captured, got %q", got)
	}

	if got := killDetail("running 3 tests\ntest a ... ok\n"); got != "" {
		t.Fatalf("clean output must yield no kill_detail, got %q", got)
	}
}

// The manifest invariant the receipt promises: every KILLED_BY_TESTS row
// carries the verbatim assertion that killed it. Enforced at campaign time,
// so a regression in the extractor fails the run instead of quietly shipping
// a manifest with holes in it.
func TestManifestInvariantRejectsEmptyKillDetail(t *testing.T) {
	good := []Result{
		{Mutation: Mutation{ID: "a"}, Verdict: VerdictKilledByTests, KilledBy: "t", KillDetail: "src/x.rs:1:1: boom"},
		{Mutation: Mutation{ID: "b"}, Verdict: VerdictKilledByCorpus, KilledBy: "us005.pub.0001"},
		{Mutation: Mutation{ID: "c"}, Verdict: VerdictEquivalentDocumented},
	}
	if problems := validateKillDetails(good); len(problems) != 0 {
		t.Fatalf("a complete manifest must validate, got %v", problems)
	}
	holed := append([]Result{}, good...)
	holed = append(holed, Result{
		Mutation: Mutation{ID: "m016-stale-fragment-retained"},
		Verdict:  VerdictKilledByTests,
		KilledBy: "fragment::accumulator_tests::finish_releases_the_accumulated_bytes_leaving_no_stale_retention",
	})
	problems := validateKillDetails(holed)
	if len(problems) != 1 || !strings.Contains(problems[0], "m016-stale-fragment-retained") {
		t.Fatalf("a KILLED_BY_TESTS row with no kill_detail must be reported, got %v", problems)
	}
}

func TestCompileErrorPattern(t *testing.T) {
	if !compileErrorPattern.MatchString("error[E0308]: mismatched types") {
		t.Fatal("rustc error must match")
	}
	if !compileErrorPattern.MatchString("error: could not compile `ws-core`") {
		t.Fatal("cargo error must match")
	}
	if compileErrorPattern.MatchString("test errors::case ... ok") {
		t.Fatal("test names must not match")
	}
}
