package formalplan

// Tests for the US-017 exploration-record validator. Helper names are
// lane-scoped (crTest*) to avoid collisions with the other files in this
// package.
//
// Every negative case below was run against the validator BEFORE the
// corresponding check existed and observed to pass, so none of them is a
// check that reports clean because the tree happens to be fine.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	crTestRoot        = "../.."
	crTestResultsPath = "../../assurance/concurrency/results.json"
)

func crTestInputs() ConcurrencyResultsInputs {
	return ConcurrencyResultsInputs{ResultsPath: crTestResultsPath, Root: crTestRoot}
}

func crTestDecode(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(crTestResultsPath)
	if err != nil {
		t.Fatalf("read results: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	return value
}

// crTestWrite writes a mutated document to a temp file. Root stays the real
// tree so the provenance checks still resolve the files the document names.
func crTestWrite(t *testing.T, value map[string]any) ConcurrencyResultsInputs {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("encode results: %v", err)
	}
	path := filepath.Join(t.TempDir(), "results.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write results: %v", err)
	}
	return ConcurrencyResultsInputs{ResultsPath: path, Root: crTestRoot}
}

func crTestSection(t *testing.T, document map[string]any, keys ...string) map[string]any {
	t.Helper()
	current := document
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		if !ok {
			t.Fatalf("results document has no object at %s", strings.Join(keys, "."))
		}
		current = next
	}
	return current
}

func crTestCodes(findings []ModelFinding) []string {
	codes := make([]string, 0, len(findings))
	for _, finding := range findings {
		codes = append(codes, finding.Code)
	}
	return codes
}

func crTestRequireCode(t *testing.T, findings []ModelFinding, code string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code {
			return
		}
	}
	t.Fatalf("expected finding %s, got %v", code, crTestCodes(findings))
}

// TestConcurrencyResultsArtifactValidates is the acceptance-facing assertion:
// the committed US-017 exploration record agrees with the tree it claims to
// describe and does not contradict itself.
func TestConcurrencyResultsArtifactValidates(t *testing.T) {
	findings := ValidateConcurrencyResults(crTestInputs())
	if len(findings) != 0 {
		for _, finding := range findings {
			t.Errorf("%s %s: %s", finding.Code, finding.Path, finding.Detail)
		}
		t.Fatalf("%s does not validate against the tree", ConcurrencyResultsDocumentPath)
	}
}

// TestConcurrencyResultsDetectsStaleSourceProvenance is the check that would
// have caught the drift this validator was written for: the document names
// the driver blob and the harness blob it measured, and the tree moved on.
func TestConcurrencyResultsDetectsStaleSourceProvenance(t *testing.T) {
	for _, key := range []string{"source", "harness"} {
		t.Run(key, func(t *testing.T) {
			document := crTestDecode(t)
			ref := crTestSection(t, document, "target", key)
			ref["git_blob"] = "0000000000000000000000000000000000000000"
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_SOURCE_BLOB_STALE")
		})
	}
}

func TestConcurrencyResultsDetectsStalePlanDigest(t *testing.T) {
	document := crTestDecode(t)
	plan := crTestSection(t, document, "preregistered_plan")
	plan["sha256"] = "sha256:" + strings.Repeat("0", 64)
	findings := ValidateConcurrencyResults(crTestWrite(t, document))
	crTestRequireCode(t, findings, "RESULTS_PLAN_DIGEST_STALE")
}

func TestConcurrencyResultsDetectsStaleSeedDigests(t *testing.T) {
	t.Run("minimized", func(t *testing.T) {
		document := crTestDecode(t)
		retention := crTestSection(t, document, "retention")
		artifacts, ok := retention["minimized_artifacts"].([]any)
		if !ok || len(artifacts) == 0 {
			t.Fatal("results document records no minimized artifacts")
		}
		first, ok := artifacts[0].(map[string]any)
		if !ok {
			t.Fatal("minimized artifact is not an object")
		}
		first["sha256"] = "sha256:" + strings.Repeat("0", 64)
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_SEED_DIGEST_STALE")
	})
	t.Run("reproduction", func(t *testing.T) {
		document := crTestDecode(t)
		defects, ok := document["defects_found_and_fixed"].([]any)
		if !ok || len(defects) == 0 {
			t.Fatal("results document records no defects")
		}
		defect, ok := defects[0].(map[string]any)
		if !ok {
			t.Fatal("defect is not an object")
		}
		reproduction, ok := defect["minimized_reproduction"].(map[string]any)
		if !ok {
			t.Fatal("defect records no minimized reproduction")
		}
		reproduction["sha256"] = "sha256:" + strings.Repeat("0", 64)
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_SEED_DIGEST_STALE")
	})
}

func TestConcurrencyResultsDetectsMissingProvenanceFile(t *testing.T) {
	document := crTestDecode(t)
	source := crTestSection(t, document, "target", "source")
	source["path"] = "rust/ws-driver/src/this-file-does-not-exist.rs"
	findings := ValidateConcurrencyResults(crTestWrite(t, document))
	crTestRequireCode(t, findings, "RESULTS_PROVENANCE_MISSING")
}

// TestConcurrencyResultsSaysSoWhenProvenanceIsUnchecked pins the fail-loud
// degradation: without a tree root the validator reports that it did not
// check, instead of returning an empty (green-looking) finding set.
func TestConcurrencyResultsSaysSoWhenProvenanceIsUnchecked(t *testing.T) {
	findings := ValidateConcurrencyResults(ConcurrencyResultsInputs{ResultsPath: crTestResultsPath})
	crTestRequireCode(t, findings, "RESULTS_PROVENANCE_UNVERIFIED")
}

// TestConcurrencyResultsDetectsCountersThatContradictTheCitedRun is the
// re-derivation check: every counter in the document is compared against the
// verbatim line the exploration printed. Each subtest edits one counter and
// leaves the cited run alone — the exact shape of a fabricated or
// half-refreshed number.
func TestConcurrencyResultsDetectsCountersThatContradictTheCitedRun(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		section []string
		field   string
		value   any
	}{
		{"explored_schedules", []string{"execution"}, "explored_schedules", float64(11)},
		{"enumeration_branches", []string{"execution"}, "enumeration_branches", float64(315071)},
		{"executions", []string{"execution"}, "executions", float64(159841)},
		{"distinct trace digests", []string{"execution"}, "distinct_semantic_trace_digests", float64(19697)},
		{"closed_terminal_runs", []string{"execution"}, "closed_terminal_runs", float64(52925)},
		{"failure_halted_runs", []string{"execution"}, "failure_halted_runs", float64(26997)},
		{"accepted_commands", []string{"execution", "counters"}, "accepted_commands", float64(999999)},
		{"queue_full_refusals", []string{"execution", "counters"}, "queue_full_refusals", float64(59359)},
		{"applied", []string{"execution", "counters"}, "applied", float64(68145)},
		{"typed_rejections", []string{"execution", "counters"}, "typed_rejections", float64(22827)},
		{"terminal_rejections", []string{"execution", "counters"}, "terminal_rejections", float64(115235)},
		{"events_drained", []string{"execution", "counters"}, "events_drained", float64(471172)},
		{"surfaced_typed_failures", []string{"execution", "counters"}, "surfaced_typed_failures", float64(26997)},
		{"deferred_output_pending", []string{"execution", "counters"}, "deferred_output_pending", float64(27709)},
		{"deferred_command_turn", []string{"execution", "counters"}, "deferred_command_turn", float64(31398)},
		{"deferred_backpressure", []string{"execution", "counters"}, "deferred_backpressure", float64(3551)},
		{"typed_input_rejections", []string{"execution", "counters"}, "typed_input_rejections", float64(52419)},
		{"max_drain_polls_observed", []string{"execution", "counters"}, "max_drain_polls_observed", float64(12)},
		{"actor_programs", []string{"bounds"}, "actor_programs", float64(6)},
		{"actions_per_schedule", []string{"bounds"}, "actions_per_schedule", float64(13)},
		{"context_switch_bound", []string{"bounds"}, "context_switch_bound", float64(8)},
		{"preemption_budget", []string{"bounds"}, "preemption_budget", float64(4)},
		{"truncated", []string{"execution"}, "truncated", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			crTestSection(t, document, testCase.section...)[testCase.field] = testCase.value
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_COUNTER_CONTRADICTS_RUN")
		})
	}
}

// TestConcurrencyResultsRejectsAnUncitedOrUnusableRun keeps the re-derivation
// from being defeated by removing or blanking the thing it derives from.
func TestConcurrencyResultsRejectsAnUncitedOrUnusableRun(t *testing.T) {
	t.Run("no cited run at all", func(t *testing.T) {
		document := crTestDecode(t)
		delete(crTestSection(t, document, "execution"), "executed_run")
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_EXECUTED_RUN_ABSENT")
	})
	t.Run("the cited run did not pass", func(t *testing.T) {
		document := crTestDecode(t)
		crTestSection(t, document, "execution", "executed_run")["exit"] = float64(101)
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_EXECUTED_RUN_NOT_PASSING")
	})
	t.Run("the cited command is not the exploration", func(t *testing.T) {
		document := crTestDecode(t)
		crTestSection(t, document, "execution", "executed_run")["command"] = "cargo test --workspace"
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_EXECUTED_RUN_NOT_PASSING")
	})
	t.Run("the cited line is not the exploration line", func(t *testing.T) {
		document := crTestDecode(t)
		crTestSection(t, document, "execution", "executed_run")["stdout_line"] = "test result: ok. 1 passed"
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_EXECUTED_RUN_UNPARSED")
	})
	t.Run("the cited line drops a field", func(t *testing.T) {
		document := crTestDecode(t)
		run := crTestSection(t, document, "execution", "executed_run")
		line, ok := run["stdout_line"].(string)
		if !ok {
			t.Fatal("executed_run carries no stdout_line")
		}
		kept := []string{}
		for _, token := range strings.Fields(line) {
			if strings.HasPrefix(token, "terminal_rejected=") {
				continue
			}
			kept = append(kept, token)
		}
		run["stdout_line"] = strings.Join(kept, " ")
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_EXECUTED_RUN_UNPARSED")
	})
}

// TestConcurrencyResultsDetectsAccountingContradictions walks the arithmetic
// identities the document asserts about itself. Each mutation is the shape a
// half-finished refresh actually produces: one counter moved, the rest left.
func TestConcurrencyResultsDetectsAccountingContradictions(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			// The exact corruption used to prove the pre-fix gap.
			name: "explored schedules no longer equal the disposition partition",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution")["explored_schedules"] = float64(11)
			},
		},
		{
			name: "executions is not twice the schedule count",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution")["executions"] = float64(79920)
			},
		},
		{
			name: "schedules are not distinct",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution")["distinct_schedule_digests"] = float64(70000)
			},
		},
		{
			name: "surfaced failures disagree with halted runs",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution", "counters")["surfaced_typed_failures"] = float64(1)
			},
		},
		{
			name: "more distinct outcomes than runs",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution")["distinct_semantic_trace_digests"] = float64(999999)
			},
		},
		{
			name: "the run exceeds its own declared schedule ceiling",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "bounds")["schedule_count_max"] = float64(100)
			},
		},
		{
			name: "the run exceeds its own declared branch ceiling",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "bounds")["branch_count_max"] = float64(100)
			},
		},
		{
			name: "context switch bound contradicts its stated derivation",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "bounds")["context_switch_bound"] = float64(9)
			},
		},
		{
			name: "more commands disposed than accepted",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution", "counters")["accepted_commands"] = float64(10)
			},
		},
		{
			name: "a coverage counter the exploration asserts was reached is zero",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution", "counters")["deferred_backpressure"] = float64(0)
			},
		},
		{
			name: "PASS claimed over a non-exhaustive run",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution")["exhaustive_within_bound"] = false
			},
		},
		{
			name: "PASS claimed over a truncated run",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution")["truncated"] = true
			},
		},
		{
			name: "PASS claimed without a zero-violation outcome",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution")["outcome"] = "PASS"
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_ACCOUNTING_CONTRADICTION")
		})
	}
}

// TestConcurrencyResultsDetectsProseThatContradictsTheCounters covers the
// half-refresh: the number in the field moves and the sentence that quotes it
// to an acceptance reader does not.
func TestConcurrencyResultsDetectsProseThatContradictsTheCounters(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			// The second half of the corruption used to prove the gap: a
			// counter rewritten while the reconciliation sentence keeps the
			// old totals.
			name: "accepted_commands moves but the reconciliation sentence does not",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution", "counters")["accepted_commands"] = float64(999999)
			},
		},
		{
			name: "terminal_rejections moves but the reconciliation sentence does not",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution", "counters")["terminal_rejections"] = float64(115000)
			},
		},
		{
			name: "closed_terminal_runs moves but the exclusivity sentence does not",
			mutate: func(t *testing.T, document map[string]any) {
				execution := crTestSection(t, document, "execution")
				execution["closed_terminal_runs"] = float64(52925)
				execution["failure_halted_runs"] = float64(26995)
			},
		},
		{
			name: "enumeration_branches moves but the conformance sentence does not",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution")["enumeration_branches"] = float64(315071)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_PROSE_CONTRADICTS_COUNTERS")
		})
	}
}

// TestConcurrencyResultsProseScanIgnoresNonCounterTokens keeps the prose scan
// from being a nuisance check: commit prefixes and hex-adjacent digit runs are
// not integers a reader reads as a counter, and must not fire.
func TestConcurrencyResultsProseScanIgnoresNonCounterTokens(t *testing.T) {
	for _, text := range []string{
		"supersedes the 76b5350 revision",
		"blob 3dbe61bc6c6cb6c8a0b251157e3590517b283507",
		"recorded at 2026-08-27T22:04:57Z",
		"capacities 2/2/8 and 12 actions",
	} {
		if tokens := crIntegerTokens(text, 4); len(tokens) != 0 {
			t.Errorf("%q produced counter tokens %v, want none", text, tokens)
		}
	}
	if tokens := crIntegerTokens("79920 schedules and 315070 branches", 4); len(tokens) != 2 {
		t.Fatalf("expected the two real counters, got %v", tokens)
	}
}

// TestConcurrencyResultsIsTheStoryEvidenceItClaimsToBe stops the validator
// from being pointed at a document that is no longer the one US-017 rests on.
func TestConcurrencyResultsIsTheStoryEvidenceItClaimsToBe(t *testing.T) {
	raw, err := os.ReadFile(crTestResultsPath)
	if err != nil {
		t.Fatalf("read results: %v", err)
	}
	var results crResults
	if err := json.Unmarshal(raw, &results); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	if results.StoryID != "US-017" {
		t.Fatalf("story_id is %q, want US-017", results.StoryID)
	}
	if results.Target.Symbol != "ws_driver::ConnectionDriver::poll" {
		t.Fatalf("target symbol is %q, want ws_driver::ConnectionDriver::poll", results.Target.Symbol)
	}
}
