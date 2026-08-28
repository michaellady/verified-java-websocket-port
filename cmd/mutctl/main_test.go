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
