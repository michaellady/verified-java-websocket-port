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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
		{"events_drained", []string{"execution", "counters"}, "events_drained", float64(471172)},
		{"surfaced_typed_failures", []string{"execution", "counters"}, "surfaced_typed_failures", float64(26997)},
		{"deferred_output_pending", []string{"execution", "counters"}, "deferred_output_pending", float64(27709)},
		{"deferred_command_turn", []string{"execution", "counters"}, "deferred_command_turn", float64(31398)},
		{"deferred_backpressure", []string{"execution", "counters"}, "deferred_backpressure", float64(3551)},
		{"typed_input_rejections", []string{"execution", "counters"}, "typed_input_rejections", float64(52419)},
		{"max_drain_polls_observed", []string{"execution", "counters"}, "max_drain_polls_observed", float64(13)},
		{"actor_programs", []string{"bounds"}, "actor_programs", float64(6)},
		{"scenarios", []string{"bounds"}, "scenarios", float64(4)},
		{"actions_across_scenarios", []string{"bounds"}, "actions_across_scenarios", float64(20)},
		{"context_switch_bound", []string{"bounds"}, "context_switch_bound", float64(8)},
		{"preemption_budget", []string{"bounds"}, "preemption_budget", float64(4)},
		// Review 01a0487b BLOCKING 2. These four bounds were tied to nothing
		// before the exploration printed them; the capacity case is the
		// reviewer's own example, measured passing at exit 0 beforehand.
		{"command_queue_capacity", []string{"bounds"}, "command_queue_capacity", float64(7)},
		{"write_queue_capacity", []string{"bounds"}, "write_queue_capacity", float64(7)},
		{"event_queue_capacity", []string{"bounds"}, "event_queue_capacity", float64(4)},
		{"drain_budget_polls", []string{"bounds"}, "drain_budget_polls", float64(512)},
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
			if strings.HasPrefix(token, "rejected=") {
				continue
			}
			kept = append(kept, token)
		}
		run["stdout_line"] = strings.Join(kept, " ")
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_EXECUTED_RUN_UNPARSED")
	})
}

// crTestWriteRaw writes a document from raw text rather than a JSON
// round-trip, so a test can control the exact whitespace and key placement.
// The split-read fabrication below depends on both.
func crTestWriteRaw(t *testing.T, document string) ConcurrencyResultsInputs {
	t.Helper()
	var probe map[string]any
	if err := json.Unmarshal([]byte(document), &probe); err != nil {
		t.Fatalf("the fabrication must be VALID JSON or it proves nothing: %v", err)
	}
	path := filepath.Join(t.TempDir(), "results.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("write results: %v", err)
	}
	return ConcurrencyResultsInputs{ResultsPath: path, Root: crTestRoot}
}

// TestConcurrencyResultsRefusesTheSplitReadFabrication is review 01a0487b
// BLOCKING 1, encoded exactly as the reviewer described it.
//
// The attack: this validator reads execution.executed_run.stdout_line
// structurally, while the Rust half reads raw bytes. Give them a document with
// an ignored top-level `"stdout_line": "<real measurement>"` in the exact
// spelling the old Rust reader searched for, plus the real nested field written
// `"stdout_line" : "<forgery>"` with legal JSON whitespace before the colon,
// and each half validates a different value. Measured before the fix: Go exit
// 0 and Rust exit 0 on a document whose deferred_command_turn counter was
// forged from 31397 to 41397.
//
// Two validators only compose if they agree on what they are reading. The
// binding is now keyed on the bare key token, which must occur exactly once
// anywhere in the document, so the decoy is what makes it fail.
func TestConcurrencyResultsRefusesTheSplitReadFabrication(t *testing.T) {
	raw, err := os.ReadFile(crTestResultsPath)
	if err != nil {
		t.Fatalf("read results: %v", err)
	}
	document := string(raw)

	real, err := crRawStdoutLine(raw)
	if err != nil {
		t.Fatalf("the committed document must yield one run line: %v", err)
	}
	// The honest value is READ from the committed line (it moved from 31397 to
	// 31383 when claude/us017-ac2's run landed) and the forgery is that value
	// plus ten thousand, so this case follows the record instead of pinning it.
	match := regexp.MustCompile(`deferred_command_turn=([0-9]+)`).FindStringSubmatch(real)
	if match == nil {
		t.Fatalf("the committed run line no longer carries deferred_command_turn; retarget this fabrication")
	}
	honestValue, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("deferred_command_turn is not an integer: %v", err)
	}
	honest, forged := match[0], fmt.Sprintf("deferred_command_turn=%d", honestValue+10000)

	// The nested field keeps the FORGERY, written with the legal whitespace
	// the old raw reader could not see.
	fabrication := strings.Replace(document,
		`"stdout_line": "`+real+`"`,
		`"stdout_line" : "`+strings.Replace(real, honest, forged, 1)+`"`, 1)
	// The counter is forged to agree with it, so the re-derivation alone passes.
	fabrication = strings.Replace(fabrication,
		`"deferred_command_turn": 31397`, `"deferred_command_turn": 41397`, 1)
	// And the decoy carries the REAL measurement for the other reader.
	fabrication = strings.Replace(fabrication,
		`"schema_version": "1.0.0",`,
		`"schema_version": "1.0.0",`+"\n  "+`"stdout_line": "`+real+`",`, 1)
	if fabrication == document {
		t.Fatal("the fabrication did not apply; the document shape changed")
	}

	findings := ValidateConcurrencyResults(crTestWriteRaw(t, fabrication))
	crTestRequireCode(t, findings, "RESULTS_RUN_LINE_AMBIGUOUS")
}

// TestConcurrencyResultsRawAndStructuralReadersAgree pins the property the
// split-read fabrication violated, directly: the raw algorithm the Rust half
// runs and this package's structural parse must yield the same string on the
// committed document.
func TestConcurrencyResultsRawAndStructuralReadersAgree(t *testing.T) {
	raw, err := os.ReadFile(crTestResultsPath)
	if err != nil {
		t.Fatalf("read results: %v", err)
	}
	rawLine, err := crRawStdoutLine(raw)
	if err != nil {
		t.Fatalf("raw read: %v", err)
	}
	var results crResults
	if err := json.Unmarshal(raw, &results); err != nil {
		t.Fatalf("structural read: %v", err)
	}
	if results.Execution.ExecutedRun == nil {
		t.Fatal("the committed document cites no run")
	}
	if rawLine != results.Execution.ExecutedRun.StdoutLine {
		t.Fatalf("the two halves of this binding read different bytes:\n  raw:        %s\n  structural: %s",
			rawLine, results.Execution.ExecutedRun.StdoutLine)
	}
}

// TestConcurrencyResultsRawReaderToleratesLegalWhitespace keeps the raw reader
// from being defeated by valid JSON formatting rather than by a real forgery —
// the mistake the first version made.
func TestConcurrencyResultsRawReaderToleratesLegalWhitespace(t *testing.T) {
	for _, spelling := range []string{
		`{"stdout_line": "US017_EXPLORATION x=1"}`,
		`{"stdout_line" : "US017_EXPLORATION x=1"}`,
		"{\"stdout_line\"\n\t:\n\t\"US017_EXPLORATION x=1\"}",
		`{"stdout_line":"US017_EXPLORATION x=1"}`,
	} {
		value, err := crRawStdoutLine([]byte(spelling))
		if err != nil {
			t.Errorf("%s: %v", spelling, err)
			continue
		}
		if value != "US017_EXPLORATION x=1" {
			t.Errorf("%s yielded %q", spelling, value)
		}
	}
	if _, err := crRawStdoutLine([]byte(`{"a":{"stdout_line": "one"},"b":{"stdout_line": "two"}}`)); err == nil {
		t.Fatal("two stdout_line keys must be refused, not silently resolved to the first")
	}
	if _, err := crRawStdoutLine([]byte(`{"schedules": 79920}`)); err == nil {
		t.Fatal("a document with no stdout_line key must be refused")
	}
}

// TestConcurrencyResultsRefusesMisdirectedProvenance is review 01a0487b
// BLOCKING 3 — the plane's recurring "right hash of the wrong thing" class.
// Every case below carries a digest that MATCHES the file it points at; what
// is wrong is which file that is. All of them passed at exit 0 beforehand.
func TestConcurrencyResultsRefusesMisdirectedProvenance(t *testing.T) {
	t.Run("source and harness references swapped wholesale", func(t *testing.T) {
		document := crTestDecode(t)
		target := crTestSection(t, document, "target")
		source, harness := target["source"], target["harness"]
		target["source"], target["harness"] = harness, source
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_PROVENANCE_MISDIRECTED")
	})
	t.Run("plan redirected to another file with its own digest", func(t *testing.T) {
		const decoy = "assurance/evidence-model.json"
		content, err := os.ReadFile(filepath.Join(crTestRoot, decoy))
		if err != nil {
			t.Fatalf("read decoy: %v", err)
		}
		document := crTestDecode(t)
		plan := crTestSection(t, document, "preregistered_plan")
		plan["path"] = decoy
		plan["sha256"] = crSHA256(content)
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_PROVENANCE_MISDIRECTED")
		// And independently, from the plan side: the decoy is not a plan.
		crTestRequireCode(t, findings, "RESULTS_PLAN_NOT_CONFORMABLE")
	})
	t.Run("target symbol is not the explored symbol", func(t *testing.T) {
		document := crTestDecode(t)
		crTestSection(t, document, "target")["symbol"] = "ws_core::ConnectionCore::handle_eof"
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_PROVENANCE_MISDIRECTED")
	})
	t.Run("reproduction seed moved outside the pinned directory", func(t *testing.T) {
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
		reproduction["path"] = "rust/ws-driver/fuzz-seeds/us017/minimized/close-race.seed"
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_PROVENANCE_MISDIRECTED")
	})
}

// TestConcurrencyResultsChecksPlanConformanceAgainstThePlan covers the second
// half of BLOCKING 2 and 3: the conformance claim is checked against the
// plan's own declared ceilings, read from the plan, not from this document's
// prose.
func TestConcurrencyResultsChecksPlanConformanceAgainstThePlan(t *testing.T) {
	// The action ceiling now binds the LONGEST scenario rather than a single
	// actions_per_schedule bound, so its case mutates the scenario shape the
	// ceiling is derived from instead of a flat bounds field.
	t.Run("actions per schedule exceeds the plan ceiling", func(t *testing.T) {
		document := crTestDecode(t)
		shapes, ok := crTestSection(t, document, "bounds")["scenario_shapes"].([]any)
		if !ok || len(shapes) == 0 {
			t.Fatalf("bounds.scenario_shapes is not a non-empty array")
		}
		shape, ok := shapes[0].(map[string]any)
		if !ok {
			t.Fatalf("bounds.scenario_shapes[0] is not an object")
		}
		shape["actions_per_schedule"] = float64(65)
		findings := ValidateConcurrencyResults(crTestWrite(t, document))
		crTestRequireCode(t, findings, "RESULTS_PLAN_CONFORMANCE_VIOLATED")
	})
	for _, testCase := range []struct {
		name   string
		field  string
		value  any
		expect string
	}{
		{"event queue exceeds the plan ceiling", "event_queue_capacity", float64(9), "RESULTS_PLAN_CONFORMANCE_VIOLATED"},
		{"preemption budget disagrees with the plan bound", "preemption_budget", float64(2), "RESULTS_PLAN_CONFORMANCE_VIOLATED"},
		{"schedule ceiling disagrees with the plan", "schedule_count_max", float64(200000), "RESULTS_PLAN_CONFORMANCE_VIOLATED"},
		{"branch ceiling disagrees with the plan", "branch_count_max", float64(2000000), "RESULTS_PLAN_CONFORMANCE_VIOLATED"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			crTestSection(t, document, "bounds")[testCase.field] = testCase.value
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, testCase.expect)
		})
	}
}

// TestConcurrencyResultsProseReconciliationIsFieldSpecific is review 01a0487b
// BLOCKING 4. The previous check was global membership over every recorded
// number, so substituting one real counter for another passed. Each case below
// uses only numbers the document genuinely records.
func TestConcurrencyResultsProseReconciliationIsFieldSpecific(t *testing.T) {
	for _, testCase := range []struct {
		name string
		from string
		to   string
	}{
		{
			// The reviewer's own example, retargeted onto the sentence's
			// current wording: the schedule total substituted for the
			// failure total the clause is actually about.
			name: "schedule total substituted for the failure total",
			from: "surfaced failures total 90984 ==",
			to:   "surfaced failures total 92160 ==",
		},
		{
			name: "schedule total substituted for the halted total in the model sentence",
			from: "(90984 runs, exactly one surfaced failure each",
			to:   "(92160 runs, exactly one surfaced failure each",
		},
		{
			name: "a quoted counter dropped from the conformance sentence",
			from: "352598 enumeration branches (<= branch_count_max 1000000)",
			to:   "enumeration branches (<= branch_count_max 1000000)",
		},
		{
			name: "the outcome sentence quotes a different recorded number",
			from: "across all 92160 schedules in the main sweep",
			to:   "across all 37813 schedules in the main sweep",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			raw, err := os.ReadFile(crTestResultsPath)
			if err != nil {
				t.Fatalf("read results: %v", err)
			}
			document := string(raw)
			if !strings.Contains(document, testCase.from) {
				t.Fatalf("the committed document no longer contains %q; retarget this case", testCase.from)
			}
			findings := ValidateConcurrencyResults(crTestWriteRaw(t,
				strings.Replace(document, testCase.from, testCase.to, 1)))
			crTestRequireCode(t, findings, "RESULTS_PROSE_CONTRADICTS_COUNTERS")
		})
	}
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
			name: "typed_rejections moves but the reconciliation sentence does not",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution", "counters")["typed_rejections"] = float64(115000)
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

// crTestArray fetches an array from the decoded document.
func crTestArray(t *testing.T, document map[string]any, keys ...string) []any {
	t.Helper()
	current := any(document)
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("results document has no object before %s", key)
		}
		current = object[key]
	}
	array, ok := current.([]any)
	if !ok {
		t.Fatalf("results document has no array at %s", strings.Join(keys, "."))
	}
	return array
}

// TestConcurrencyResultsRefusesTheReviewersFairnessFlip is review 01a0487b
// round 2 BLOCKING, encoded as the reviewer stated it.
//
// The attack, measured against the committed binding BEFORE this check
// existed: change execution.producer_admission_fairness_claimed from false to
// true, refreeze the evidence DAG through its own sanctioned
// LINKAGE_REGENERATE=1 flow, and run both validators. `go test ./internal/...`
// exited 0 and `cargo test -p ws-driver --release --test schedule_exploration`
// exited 0. Nothing modeled the field: Go's permissive json.Unmarshal ignored
// it and Rust compares only the printed line.
//
// Claiming admission fairness is not a cosmetic edit. The preregistered plan
// declares PRODUCER_ADMISSION_FAIRNESS_ABSENT precisely because Java's
// unbounded queue provides no admission ordering; a record claiming it would
// assert a guarantee stronger than both the port and the plan.
func TestConcurrencyResultsRefusesTheReviewersFairnessFlip(t *testing.T) {
	document := crTestDecode(t)
	crTestSection(t, document, "execution")["producer_admission_fairness_claimed"] = true
	findings := ValidateConcurrencyResults(crTestWrite(t, document))
	// Both halves of the binding refuse it, and each would refuse alone:
	// the run never printed that stance, and the plan never declared it.
	crTestRequireCode(t, findings, "RESULTS_FAIRNESS_CONTRADICTS_RUN")
	crTestRequireCode(t, findings, "RESULTS_FAIRNESS_CONTRADICTS_PLAN")
}

// TestConcurrencyResultsRefusesAnInvariantTableThatIsNotTheRuns closes the
// rest of the class the reviewer named: "the entire invariants array is
// likewise unmodeled". Ten property ids and ten PASS outcomes an acceptance
// reader takes as the coverage claim, and every one of them was free text.
// Each case below was measured passing at exit 0 before the exploration
// printed the table it actually checked.
func TestConcurrencyResultsRefusesAnInvariantTableThatIsNotTheRuns(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			// A failing invariant relabeled as passing: the single edit that
			// turns a real violation into acceptance evidence.
			name: "an invariant outcome is flipped to PASS-by-assertion",
			mutate: func(t *testing.T, document map[string]any) {
				invariants := crTestArray(t, document, "invariants")
				invariants[8].(map[string]any)["outcome"] = "FAIL"
			},
		},
		{
			name: "an invariant is renamed to a property the run never checked",
			mutate: func(t *testing.T, document map[string]any) {
				invariants := crTestArray(t, document, "invariants")
				invariants[0].(map[string]any)["property_id"] = "concurrency.total-correctness"
			},
		},
		{
			name: "an invariant is dropped from the table",
			mutate: func(t *testing.T, document map[string]any) {
				invariants := crTestArray(t, document, "invariants")
				document["invariants"] = invariants[:len(invariants)-1]
			},
		},
		{
			name: "an invariant the run never checked is added",
			mutate: func(t *testing.T, document map[string]any) {
				invariants := crTestArray(t, document, "invariants")
				document["invariants"] = append(invariants,
					map[string]any{"property_id": "concurrency.linearizability", "outcome": "PASS"})
			},
		},
		{
			name: "two invariants are reordered so one stands in for another",
			mutate: func(t *testing.T, document map[string]any) {
				invariants := crTestArray(t, document, "invariants")
				invariants[0], invariants[1] = invariants[1], invariants[0]
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_INVARIANTS_CONTRADICT_RUN")
		})
	}
}

// TestConcurrencyResultsRefusesFairnessTheRunDidNotAssume. The three
// weak-fairness assumptions gate the final drain and are therefore part of
// what the PASS means. They were unmodeled decoration too.
func TestConcurrencyResultsRefusesFairnessTheRunDidNotAssume(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			name: "a stronger fairness assumption is substituted",
			mutate: func(t *testing.T, document map[string]any) {
				fairness := crTestArray(t, document, "execution", "weak_fairness")
				fairness[0] = "STRONG_OWNER_PROGRESS_ALWAYS"
			},
		},
		{
			name: "an assumption the run never made is added",
			mutate: func(t *testing.T, document map[string]any) {
				fairness := crTestArray(t, document, "execution", "weak_fairness")
				crTestSection(t, document, "execution")["weak_fairness"] =
					append(fairness, "WEAK_PRODUCER_ADMISSION_ROTATION")
			},
		},
		{
			name: "an assumption is dropped",
			mutate: func(t *testing.T, document map[string]any) {
				fairness := crTestArray(t, document, "execution", "weak_fairness")
				crTestSection(t, document, "execution")["weak_fairness"] = fairness[:2]
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_FAIRNESS_CONTRADICTS_RUN")
		})
	}
}

// TestConcurrencyResultsRefusesAnUnmodeledField is the DURABLE half of the
// round-2 fix, and the reason the fix is not a one-time patch.
//
// Modelling the fields that exist today fixes today's document. Strict
// decoding is what stops the class from reopening: a field nothing models is
// a field nothing can contradict, so a new one cannot be added silently.
func TestConcurrencyResultsRefusesAnUnmodeledField(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			name: "a new top-level claim",
			mutate: func(t *testing.T, document map[string]any) {
				document["java_equivalence_established"] = true
			},
		},
		{
			name: "a new claim nested inside execution",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution")["strong_fairness_claimed"] = true
			},
		},
		{
			name: "a new claim nested inside native_stress",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "native_stress")["platforms_covered"] = float64(2)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_UNMODELED_FIELD")
		})
	}
}

// TestConcurrencyResultsRefusesAnInflatedClaimCeiling. Every field here was
// unmodeled, so every one could be raised by one edit: an owner-attested
// bounded single-host result could declare itself independently reviewed,
// production, published, or passing on every platform.
func TestConcurrencyResultsRefusesAnInflatedClaimCeiling(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			name:   "independent review claimed over an owner attestation",
			mutate: func(t *testing.T, document map[string]any) { document["independent_review_claimed"] = true },
		},
		{
			name:   "production claimed",
			mutate: func(t *testing.T, document map[string]any) { document["production"] = true },
		},
		{
			name:   "publication claimed",
			mutate: func(t *testing.T, document map[string]any) { document["publication"] = true },
		},
		{
			name:   "the assurance posture is raised above the plan's",
			mutate: func(t *testing.T, document map[string]any) { document["assurance"] = "INDEPENDENTLY_REVIEWED" },
		},
		{
			// Measured: "PASS CORRUPTED" produced NO finding at all, because
			// every check was conditioned on state == "PASS" and simply
			// stopped applying.
			name:   "a state outside the vocabulary silently skips the PASS block",
			mutate: func(t *testing.T, document map[string]any) { document["state"] = "PASS CORRUPTED" },
		},
		{
			name: "the record renames itself to another evidence kind",
			mutate: func(t *testing.T, document map[string]any) {
				document["evidence_kind"] = "US017_FULL_STATE_SPACE_PROOF"
			},
		},
		{
			name: "the single-host stress result is widened to every host",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "native_stress")["outcome"] = "PASS"
			},
		},
		{
			name: "the claim ceiling stops naming the plan that sets it",
			mutate: func(t *testing.T, document map[string]any) {
				document["claim_scope_statement"] = "Bounded schedule exploration is systematic concurrency testing, never proof."
			},
		},
		{
			name: "the state stops being derived from the invariant table",
			mutate: func(t *testing.T, document map[string]any) {
				document["state"] = "FAIL"
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_CLAIM_CEILING_INFLATED")
		})
	}
}

// TestConcurrencyResultsRefusesNamedArtifactsThatDoNotExist. The record
// claims a stress suite and two regression tests; nothing required them to be
// real. A fix asserting its own regression coverage is the same shape as a
// counter asserting its own run.
func TestConcurrencyResultsRefusesNamedArtifactsThatDoNotExist(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			name: "the stress suite names a file that is not in the tree",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "native_stress")["suite"] =
					"rust/ws-driver/tests/two-platform-stress.rs (four producer threads)"
			},
		},
		{
			name: "a regression test names a file that is not in the tree",
			mutate: func(t *testing.T, document map[string]any) {
				defect := crTestArray(t, document, "defects_found_and_fixed")[0].(map[string]any)
				defect["regression_tests"] = []any{"rust/ws-driver/tests/nowhere.rs::covers_the_defect"}
			},
		},
		{
			// The harder half: the FILE resolves, the TEST does not.
			name: "a regression test names a function the file does not carry",
			mutate: func(t *testing.T, document map[string]any) {
				defect := crTestArray(t, document, "defects_found_and_fixed")[0].(map[string]any)
				defect["regression_tests"] = []any{
					"rust/ws-driver/tests/driver_contract.rs::this_regression_test_was_never_written"}
			},
		},
		{
			name: "a retained minimized artifact is dropped from the record",
			mutate: func(t *testing.T, document map[string]any) {
				artifacts := crTestArray(t, document, "retention", "minimized_artifacts")
				crTestSection(t, document, "retention")["minimized_artifacts"] = artifacts[:len(artifacts)-1]
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_NAMED_ARTIFACT_MISSING")
		})
	}
}

// TestConcurrencyResultsRefusesAResolvableButWrongReference is review
// 01a0487b round 3 BLOCKING 1, encoded exactly as the reviewer stated it.
//
// The round-2 fix required the named suite and every named regression test to
// RESOLVE in the tree. Resolving is not identifying, and the two checks it
// used — path existence and strings.Contains — accept any existing path and
// any string the file happens to contain. Each case below was measured passing
// against the committed binding BEFORE this check existed: the mutation was
// applied to the real tree, the evidence DAG refrozen through its own
// sanctioned LINKAGE_REGENERATE=1 flow, and both validators run.
//
//	native_stress.suite -> "go.mod"                                  Go 0, Rust 0
//	regression_tests[0] -> driver_contract.rs::test                  Go 0, Rust 0
//	regression_tests[1] -> schedule_exploration.rs::test             Go 0, Rust 0
//
// `test` is a substring of every test file ever written. That is the whole
// finding: the round-2 check asked whether the reference resolved, never
// whether it named the thing it claimed to name.
func TestConcurrencyResultsRefusesAResolvableButWrongReference(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			// The reviewer's own example. go.mod exists, so the round-2
			// existence check was satisfied by it.
			name: "the stress suite is replaced by an unrelated file that also exists",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "native_stress")["suite"] = "go.mod"
			},
		},
		{
			// The path is right and the description is wrong: the suite's own
			// PRODUCERS/COMMANDS_PER_PRODUCER constants say otherwise.
			name: "the stress suite is the right file described with the wrong numbers",
			mutate: func(t *testing.T, document map[string]any) {
				stress := crTestSection(t, document, "native_stress")
				stress["suite"] = strings.Replace(stress["suite"].(string),
					"4 producer threads x 50 commands", "8 producer threads x 50 commands", 1)
			},
		},
		{
			name: "a regression reference keeps its file and names a word the file contains",
			mutate: func(t *testing.T, document map[string]any) {
				defect := crTestArray(t, document, "defects_found_and_fixed")[0].(map[string]any)
				defect["regression_tests"] = []any{
					"rust/ws-driver/tests/driver_contract.rs::test",
					"rust/ws-driver/tests/schedule_exploration.rs::fixed_defect_regressions_replay_clean_on_the_shipped_driver",
				}
			},
		},
		{
			name: "the other regression reference does the same",
			mutate: func(t *testing.T, document map[string]any) {
				defect := crTestArray(t, document, "defects_found_and_fixed")[0].(map[string]any)
				defect["regression_tests"] = []any{
					"rust/ws-driver/tests/driver_contract.rs::eof_refused_by_event_backpressure_is_retried_until_the_core_accepts_it",
					"rust/ws-driver/tests/schedule_exploration.rs::test",
				}
			},
		},
		{
			// A real function in the file that is not a test: declaration,
			// not occurrence, is the bar.
			name: "a regression reference names a real function that is not a test",
			mutate: func(t *testing.T, document map[string]any) {
				defect := crTestArray(t, document, "defects_found_and_fixed")[0].(map[string]any)
				defect["regression_tests"] = []any{
					"rust/ws-driver/tests/concurrency.rs::stress_config",
					"rust/ws-driver/tests/schedule_exploration.rs::fixed_defect_regressions_replay_clean_on_the_shipped_driver",
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_NAMED_ARTIFACT_MISSING")
		})
	}
}

// crTestRootWithOverride builds a tree root in which exactly one file differs
// from the committed tree and everything else resolves through it by symlink.
// It is how the round-4 cases below attack the SOURCE the record names without
// mutating the repository: each doctored suite or test file was first applied
// to the real tree, measured passing, and then reproduced here.
func crTestRootWithOverride(t *testing.T, rel, content string) string {
	t.Helper()
	root := t.TempDir()
	segments := strings.Split(rel, "/")
	source, mirror := crTestRoot, root
	for depth, segment := range segments {
		entries, err := os.ReadDir(source)
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}
		for _, entry := range entries {
			if entry.Name() == segment {
				continue
			}
			absolute, err := filepath.Abs(filepath.Join(source, entry.Name()))
			if err != nil {
				t.Fatalf("resolve %s: %v", entry.Name(), err)
			}
			if err := os.Symlink(absolute, filepath.Join(mirror, entry.Name())); err != nil {
				t.Fatalf("link %s: %v", entry.Name(), err)
			}
		}
		if depth == len(segments)-1 {
			if err := os.WriteFile(filepath.Join(mirror, segment), []byte(content), 0o600); err != nil {
				t.Fatalf("write override: %v", err)
			}
			break
		}
		source = filepath.Join(source, segment)
		mirror = filepath.Join(mirror, segment)
		if err := os.Mkdir(mirror, 0o750); err != nil {
			t.Fatalf("mirror %s: %v", segment, err)
		}
	}
	return root
}

func crTestReadTreeFile(t *testing.T, rel string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(crTestRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(content)
}

// TestConcurrencyResultsRefusesAStressSuiteThatOnlyMentionsThreads is review
// 01a0487b round 4 BLOCKING 1.
//
// Round 3 replaced "the suite path exists" with
// `strings.Contains(source, "thread::spawn")` and the record's numbers with
// "the suite declares these constants". Both are substrings standing in for a
// parse, which is the same defect one level down. Each case below was applied
// to the REAL tree and measured passing at exit 0 before the structural reader
// existed:
//
//	both real spawn calls deleted, the words left in a comment      Go 0
//	both real spawn calls deleted, the words left in a string        Go 0
//	PRODUCERS = 4 and COMMANDS_PER_PRODUCER = 50 still declared,
//	  the loops rewritten to `for _ in 0..1`                         Go 0
//
// The last one is the sharpest: the suite recorded as "4 producer threads x 50
// commands" ran one thread issuing one command, and the description was still
// "re-derived from the suite's own constants".
func TestConcurrencyResultsRefusesAStressSuiteThatOnlyMentionsThreads(t *testing.T) {
	suite := crTestReadTreeFile(t, "rust/ws-driver/tests/concurrency.rs")
	for _, testCase := range []struct {
		name    string
		doctor  func(string) string
		because string
	}{
		{
			name: "the spawn survives only in a comment",
			doctor: func(source string) string {
				source = strings.ReplaceAll(source,
					"producers.push(thread::spawn(move || {", "producers.push(run_inline(move || {")
				return strings.Replace(source, "use std::thread;",
					"use std::thread;\n// this suite no longer calls thread::spawn", 1)
			},
			because: "a comment is not a call",
		},
		{
			name: "the spawn survives only in a string literal",
			doctor: func(source string) string {
				return strings.ReplaceAll(source, "producers.push(thread::spawn(move || {",
					"let _label = \"thread::spawn(\";\n        producers.push(run_inline(move || {")
			},
			because: "a string literal is not a call",
		},
		{
			name: "the constants are declared and the loops use literals",
			doctor: func(source string) string {
				source = strings.Replace(source, "const TOTAL: usize = PRODUCERS * COMMANDS_PER_PRODUCER;",
					"const TOTAL: usize = 1;", 1)
				source = strings.ReplaceAll(source, "for producer in 0..PRODUCERS {", "for producer in 0..1 {")
				source = strings.ReplaceAll(source, "for _ in 0..PRODUCERS {", "for _ in 0..1 {")
				return strings.ReplaceAll(source, "for index in 0..COMMANDS_PER_PRODUCER {", "for index in 0..1 {")
			},
			because: "a constant that bounds no loop makes the record's numbers a coincidence",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			doctored := testCase.doctor(suite)
			if doctored == suite {
				t.Fatalf("the doctoring changed nothing, so this case attacks the committed suite unmodified")
			}
			root := crTestRootWithOverride(t, "rust/ws-driver/tests/concurrency.rs", doctored)
			findings := ValidateConcurrencyResults(ConcurrencyResultsInputs{
				ResultsPath: crTestResultsPath, Root: root})
			crTestRequireCode(t, findings, "RESULTS_NAMED_ARTIFACT_MISSING")
		})
	}
}

// TestConcurrencyResultsReadsRustStructurallyNotTextually pins the reader the
// case above depends on. crStressSuiteShape must read the COMMITTED suite as
// both spawning and constant-driven, or the test above would be passing
// because the reader refuses everything.
func TestConcurrencyResultsReadsRustStructurallyNotTextually(t *testing.T) {
	committed := crStripRustNoise(crTestReadTreeFile(t, "rust/ws-driver/tests/concurrency.rs"))
	if spawns, driven := crStressSuiteShape(committed); !spawns || !driven {
		t.Fatalf("the committed native-thread stress suite reads as spawns=%v driven=%v; the reader is refusing "+
			"the real thing and every refusal it produces is meaningless", spawns, driven)
	}
	for _, testCase := range []struct {
		name           string
		source         string
		spawns, driven bool
	}{
		{
			name: "a spawn outside any test function is not this suite's evidence",
			source: "use std::thread;\nfn helper() {\n    thread::spawn(|| {});\n}\n" +
				"const PRODUCERS: usize = 4;\nconst COMMANDS_PER_PRODUCER: usize = 50;\n",
		},
		{
			name: "a spawn in a doc comment is not a spawn",
			source: "const PRODUCERS: usize = 4;\nconst COMMANDS_PER_PRODUCER: usize = 50;\n" +
				"/// thread::spawn(\n#[test]\nfn stress() {\n    let _ = 1;\n}\n",
		},
		{
			name: "the loops must be bounded by the constants",
			source: "const PRODUCERS: usize = 4;\nconst COMMANDS_PER_PRODUCER: usize = 50;\n" +
				"#[test]\nfn stress() {\n    for _ in 0..1 {\n        thread::spawn(move || {\n" +
				"            for _ in 0..1 {}\n        });\n    }\n}\n",
			spawns: true,
		},
		{
			name: "the inner loop must be inside the spawned closure",
			source: "const PRODUCERS: usize = 4;\nconst COMMANDS_PER_PRODUCER: usize = 50;\n" +
				"#[test]\nfn stress() {\n    for _ in 0..PRODUCERS {\n        thread::spawn(move || {});\n" +
				"        for _ in 0..COMMANDS_PER_PRODUCER {}\n    }\n}\n",
			spawns: true,
		},
		{
			name: "the real shape is accepted",
			source: "const PRODUCERS: usize = 4;\nconst COMMANDS_PER_PRODUCER: usize = 50;\n" +
				"#[test]\nfn stress() {\n    for producer in 0..PRODUCERS {\n" +
				"        handles.push(thread::spawn(move || {\n            for index in 0..COMMANDS_PER_PRODUCER {\n" +
				"                let _ = (producer, index);\n            }\n        }));\n    }\n}\n",
			spawns: true,
			driven: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			spawns, driven := crStressSuiteShape(crStripRustNoise(testCase.source))
			if spawns != testCase.spawns || driven != testCase.driven {
				t.Fatalf("read spawns=%v driven=%v, expected spawns=%v driven=%v",
					spawns, driven, testCase.spawns, testCase.driven)
			}
		})
	}
}

// TestConcurrencyResultsRefusesARegressionThatIsNotARunnableTest is review
// 01a0487b round 4 BLOCKING 2.
//
// Round 3 required a "test DECLARATION" and implemented it as a name prefix on
// the Go side and an attribute containing the letters "test" on the Rust side.
// Measured on the real tree before the fix, both at exit 0:
//
//	`#[test]` above the named regression test changed to `#[cfg(test)]`   Go 0
//	a regression reference pointed at `func Testish() {}` in a .go file   Go 0
//
// Neither function is ever RUN by its test runner. `cfg(test)` is a
// compilation condition, and `go test` runs neither a lower-case-suffixed name
// nor a function without a `*testing.T` nor anything outside a `_test.go`
// file.
func TestConcurrencyResultsRefusesARegressionThatIsNotARunnableTest(t *testing.T) {
	contract := crTestReadTreeFile(t, "rust/ws-driver/tests/driver_contract.rs")
	named := "fn eof_refused_by_event_backpressure_is_retried_until_the_core_accepts_it()"
	for _, testCase := range []struct {
		name      string
		attribute string
	}{
		{name: "the test attribute becomes a cfg condition", attribute: "#[cfg(test)]"},
		{name: "the test attribute becomes an unrelated attribute", attribute: "#[allow(dead_code)]"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			doctored := strings.Replace(contract, "#[test]\n"+named, testCase.attribute+"\n"+named, 1)
			if doctored == contract {
				t.Fatalf("the doctoring changed nothing")
			}
			root := crTestRootWithOverride(t, "rust/ws-driver/tests/driver_contract.rs", doctored)
			findings := ValidateConcurrencyResults(ConcurrencyResultsInputs{
				ResultsPath: crTestResultsPath, Root: root})
			crTestRequireCode(t, findings, "RESULTS_NAMED_ARTIFACT_MISSING")
		})
	}
}

// TestConcurrencyResultsParsesTestDeclarations pins both halves of the
// predicate, in both directions: the real declarations in this tree must be
// accepted, or every refusal above is vacuous.
func TestConcurrencyResultsParsesTestDeclarations(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		file     string
		source   string
		declared string
		want     bool
	}{
		{
			name: "rust: an attributed test is a test", file: "x.rs", declared: "stress",
			source: "#[test]\nfn stress() {}\n", want: true,
		},
		{
			name: "rust: a namespaced test attribute is still a test", file: "x.rs", declared: "stress",
			source: "#[tokio::test]\nfn stress() {}\n", want: true,
		},
		{
			name: "rust: doc comments and other attributes do not break the link", file: "x.rs", declared: "stress",
			source: "/// doc\n#[test]\n#[should_panic]\nfn stress() {}\n", want: true,
		},
		{
			name: "rust: cfg(test) is a compilation condition, not a test", file: "x.rs", declared: "helper",
			source: "#[cfg(test)]\nfn helper() {}\n",
		},
		{
			name: "rust: an unattributed fn is not a test", file: "x.rs", declared: "helper",
			source: "fn helper() {}\n",
		},
		{
			name: "rust: a test attribute on the previous item does not carry", file: "x.rs", declared: "helper",
			source: "#[test]\nfn stress() {}\n\nfn helper() {}\n",
		},
		{
			name: "rust: a libtest test takes no arguments", file: "x.rs", declared: "helper",
			source: "#[test]\nfn helper(input: u32) {}\n",
		},
		{
			name: "rust: the name in a comment is not a declaration", file: "x.rs", declared: "stress",
			source: "// #[test]\n// fn stress() {}\n",
		},
		{
			name: "go: the real signature is a test", file: "a_test.go", declared: "TestX",
			source: "package a\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n", want: true,
		},
		{
			name: "go: a lower-case suffix is not a test go test would run", file: "a_test.go", declared: "Testish",
			source: "package a\n\nfunc Testish() {}\n",
		},
		{
			name: "go: a Test name without a *testing.T is not a test", file: "a_test.go", declared: "TestX",
			source: "package a\n\nfunc TestX() {}\n",
		},
		{
			name: "go: a Test name that returns something is not a test", file: "a_test.go", declared: "TestX",
			source: "package a\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) error { return nil }\n",
		},
		{
			name: "go: a method is not a test", file: "a_test.go", declared: "TestX",
			source: "package a\n\nimport \"testing\"\n\ntype S struct{}\n\nfunc (S) TestX(t *testing.T) {}\n",
		},
		{
			name: "go: nothing outside a _test.go file is run", file: "a.go", declared: "TestX",
			source: "package a\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := crDeclaresTest(testCase.file, testCase.source, testCase.declared); got != testCase.want {
				t.Fatalf("crDeclaresTest(%s, %s) = %v, want %v",
					testCase.file, testCase.declared, got, testCase.want)
			}
		})
	}
	// And the two references the record actually makes must still resolve, in
	// the committed tree, through the same predicate.
	for _, reference := range []struct{ file, name string }{
		{"rust/ws-driver/tests/driver_contract.rs",
			"eof_refused_by_event_backpressure_is_retried_until_the_core_accepts_it"},
		{"rust/ws-driver/tests/schedule_exploration.rs",
			"fixed_defect_regressions_replay_clean_on_the_shipped_driver"},
	} {
		if !crDeclaresTest(reference.file, crTestReadTreeFile(t, reference.file), reference.name) {
			t.Fatalf("%s::%s is a real committed test and the predicate refuses it", reference.file, reference.name)
		}
	}
}

// TestConcurrencyResultsRefusesAWrongRetentionOrdinal closes the finding this
// lane deferred for three review rounds.
//
// The six `retention.minimized_artifacts[*].found_index` values could no
// longer be DELETED after round 3, but any wrong ordinal was still accepted:
// the retention run printed the ordinal (US017_RETENTION found_index=) and
// nothing in the tree recorded it, so the document's copy rested on nothing.
// The retention test now writes `found_index=` into the seed body it
// re-derives from a real minimization run and byte-compares, so a wrong
// ordinal in the document contradicts the seed and a doctored seed contradicts
// its digest.
func TestConcurrencyResultsRefusesAWrongRetentionOrdinal(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		artifact int
		ordinal  float64
	}{
		{name: "another artifact's real ordinal", artifact: 0, ordinal: 17},
		{name: "the ordinal of the one fault found late, zeroed", artifact: 3, ordinal: 0},
		{name: "an adjacent ordinal", artifact: 3, ordinal: 18},
		{name: "a plausible small integer", artifact: 5, ordinal: 3},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			artifacts := crTestArray(t, document, "retention", "minimized_artifacts")
			entry, ok := artifacts[testCase.artifact].(map[string]any)
			if !ok {
				t.Fatalf("minimized_artifacts[%d] is not an object", testCase.artifact)
			}
			if entry["found_index"] == testCase.ordinal {
				t.Fatalf("minimized_artifacts[%d] already records found_index %v, so this substitutes nothing",
					testCase.artifact, testCase.ordinal)
			}
			entry["found_index"] = testCase.ordinal
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_SEED_CONTENT_CONTRADICTED")
		})
	}
}

// TestConcurrencyResultsRefusesAMechanismThatOmitsARecordedField keeps the
// retention mechanism sentence derived from the seeds rather than pinned to a
// phrase list. When the retention test started writing found_index, the
// sentence that enumerates what the artifact records had to grow with it.
func TestConcurrencyResultsRefusesAMechanismThatOmitsARecordedField(t *testing.T) {
	document := crTestDecode(t)
	retention := crTestSection(t, document, "retention")
	mechanism, ok := retention["mechanism"].(string)
	if !ok {
		t.Fatalf("retention.mechanism is not a string")
	}
	shortened := strings.Replace(mechanism,
		", and the found index at which the exploration first hit the fault", "", 1)
	if shortened == mechanism {
		t.Fatalf("retention.mechanism no longer names the found index, so this case attacks nothing")
	}
	retention["mechanism"] = shortened
	findings := ValidateConcurrencyResults(crTestWrite(t, document))
	crTestRequireCode(t, findings, "RESULTS_SEED_CONTENT_CONTRADICTED")
}

// TestConcurrencyResultsRefusesTheReviewersFiveDeletions is review 01a0487b
// round 3 BLOCKING 2, encoded as the reviewer stated it.
//
// Each field below was DELETED from the real tree's document, the evidence DAG
// refrozen through LINKAGE_REGENERATE=1, and both validators run:
// `go test ./... -count=1` exit 0 and `cargo test -p ws-driver --release
// --test schedule_exploration` exit 0, five times out of five. Absence decodes
// to the zero value, and for every one of these the zero value is `false` —
// the value that agrees with the preregistered plan, with the cited run and
// with every other check in the validator.
//
// The whole class is asserted by
// TestConcurrencyResultsEveryModeledKeyIsRequired, which walks all 197
// removable positions. These five are kept separately because they are the
// ones the reviewer measured, and a class assertion that quietly stopped
// covering the named instance would be the same mistake again.
func TestConcurrencyResultsRefusesTheReviewersFiveDeletions(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		section []string
		key     string
	}{
		{name: "truncated", section: []string{"execution"}, key: "truncated"},
		{name: "producer_admission_fairness_claimed", section: []string{"execution"}, key: "producer_admission_fairness_claimed"},
		{name: "independent_review_claimed", key: "independent_review_claimed"},
		{name: "production", key: "production"},
		{name: "publication", key: "publication"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			target := document
			if len(testCase.section) > 0 {
				target = crTestSection(t, document, testCase.section...)
			}
			if _, present := target[testCase.key]; !present {
				t.Fatalf("%s is not in the committed document, so this deletion test proves nothing", testCase.key)
			}
			delete(target, testCase.key)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_MODELED_FIELD_OMITTED")
		})
	}
}

// TestConcurrencyResultsRefusesADroppedDefectOrDisclosure covers the rest of
// the omission class the reviewer's five were a sample of. Measured before
// this round: a whole defect record, either regression reference, and five of
// the six limitations could each be removed with no finding at all.
func TestConcurrencyResultsRefusesADroppedDefectOrDisclosure(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
		code   string
	}{
		{
			name: "a whole defect record is dropped from the roll",
			mutate: func(t *testing.T, document map[string]any) {
				document["defects_found_and_fixed"] = crTestArray(t, document, "defects_found_and_fixed")[:1]
			},
			code: "RESULTS_DEFECT_ROLL_INCOMPLETE",
		},
		{
			name: "the harness defect loses the note its kind requires",
			mutate: func(t *testing.T, document map[string]any) {
				defect := crTestArray(t, document, "defects_found_and_fixed")[1].(map[string]any)
				delete(defect, "note")
			},
			code: "RESULTS_DEFECT_ROLL_INCOMPLETE",
		},
		{
			name: "one of the two regression references is dropped",
			mutate: func(t *testing.T, document map[string]any) {
				defect := crTestArray(t, document, "defects_found_and_fixed")[0].(map[string]any)
				defect["regression_tests"] = []any{
					"rust/ws-driver/tests/schedule_exploration.rs::fixed_defect_regressions_replay_clean_on_the_shipped_driver"}
			},
			code: "RESULTS_DEFECT_ROLL_INCOMPLETE",
		},
		{
			name: "the no-race-detector disclosure is deleted",
			mutate: func(t *testing.T, document map[string]any) {
				limitations := crTestArray(t, document, "limitations")
				kept := []any{}
				for _, limitation := range limitations {
					if !strings.Contains(limitation.(string), "TSAN") {
						kept = append(kept, limitation)
					}
				}
				document["limitations"] = kept
			},
			code: "RESULTS_CLAIM_CEILING_INFLATED",
		},
		{
			// Located by its CONTENT, not by its index. This case used to
			// overwrite the last limitation, which happened to be the
			// no-live-Java one; the clean-route coverage ceiling is now
			// appended after it, so an index-addressed case silently stopped
			// testing what it names and started deleting the ceiling instead.
			name: "the no-live-Java disclosure is softened away",
			mutate: func(t *testing.T, document map[string]any) {
				limitations := crTestArray(t, document, "limitations")
				softened := false
				for index, limitation := range limitations {
					if strings.Contains(limitation.(string), "no live Java executed") {
						limitations[index] = "some Java context was considered"
						softened = true
						break
					}
				}
				if !softened {
					t.Fatal("no limitation discloses that no live Java was executed")
				}
				document["limitations"] = limitations
			},
			code: "RESULTS_CLAIM_CEILING_INFLATED",
		},
		{
			name: "the claim-scope statement is truncated past its non-substitution clause",
			mutate: func(t *testing.T, document map[string]any) {
				statement := document["claim_scope_statement"].(string)
				document["claim_scope_statement"] = statement[:len(statement)/2]
			},
			code: "RESULTS_CLAIM_CEILING_INFLATED",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, testCase.code)
		})
	}
}

// TestConcurrencyResultsRefusesATimestampFromTheFuture. Measured: shifting
// either instant to 2030 passed both validators, because the only check was
// that it parsed.
func TestConcurrencyResultsRefusesATimestampFromTheFuture(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		section []string
		key     string
	}{
		{name: "recorded_at", key: "recorded_at"},
		{name: "executed_at", section: []string{"execution", "executed_run"}, key: "executed_at"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			target := document
			if len(testCase.section) > 0 {
				target = crTestSection(t, document, testCase.section...)
			}
			target[testCase.key] = "2030-08-27T22:04:57Z"
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_TIMESTAMP_MALFORMED")
		})
	}
}

// TestConcurrencyResultsRefusesNarrativeThatContradictsItsOwnNumbers. Prose
// that enumerates a structure the record also counts is checkable, and was
// not being checked.
func TestConcurrencyResultsRefusesNarrativeThatContradictsItsOwnNumbers(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			name: "the program shape describes fewer actor programs than the bounds count",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "bounds")["program_shape"] =
					"producer A [send_text, send_binary]; producer B [send_ping, send_close]"
			},
		},
		{
			name: "a minimized artifact claims a shrink its schedule does not show",
			mutate: func(t *testing.T, document map[string]any) {
				artifact := crTestArray(t, document, "retention", "minimized_artifacts")[0].(map[string]any)
				artifact["shrink"] = "12 -> 4"
			},
		},
		{
			name: "a minimized artifact is retained for a property the record does not check",
			mutate: func(t *testing.T, document map[string]any) {
				artifact := crTestArray(t, document, "retention", "minimized_artifacts")[0].(map[string]any)
				artifact["property"] = "linearizability"
			},
		},
		{
			name: "a defect reproduction shrinks from a schedule length that does not exist",
			mutate: func(t *testing.T, document map[string]any) {
				defect := crTestArray(t, document, "defects_found_and_fixed")[0].(map[string]any)
				reproduction := defect["minimized_reproduction"].(map[string]any)
				reproduction["shrink"] = "64 -> 3 actions by the deterministic 1-minimal shrinker"
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

// TestConcurrencyResultsRefusesABlankedDescription keeps the descriptive
// fields from being emptied rather than corrected.
func TestConcurrencyResultsRefusesABlankedDescription(t *testing.T) {
	document := crTestDecode(t)
	document["adapter_model"] = ""
	findings := ValidateConcurrencyResults(crTestWrite(t, document))
	crTestRequireCode(t, findings, "RESULTS_DESCRIPTION_ABSENT")
}

func TestConcurrencyResultsRefusesAMalformedTimestamp(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			name:   "recorded_at is not an instant",
			mutate: func(t *testing.T, document map[string]any) { document["recorded_at"] = "yesterday" },
		},
		{
			name: "the cited run's executed_at is not UTC",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, document, "execution", "executed_run")["executed_at"] = "2026-08-28T13:42:29+02:00"
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_TIMESTAMP_MALFORMED")
		})
	}
}

// TestConcurrencyResultsRefusesAnUnrecognisedRunField is the run-line mirror
// of strict JSON decoding: a field in the cited line that this validator
// re-derives nothing from is a number a reader would trust and no check
// covers.
func TestConcurrencyResultsRefusesAnUnrecognisedRunField(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		suffix string
	}{
		{"a field this validator does not model", " platforms_covered=2"},
		{"a duplicated field", " schedules=11"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			run := crTestSection(t, document, "execution", "executed_run")
			line, ok := run["stdout_line"].(string)
			if !ok {
				t.Fatal("executed_run carries no stdout_line")
			}
			run["stdout_line"] = line + testCase.suffix
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_EXECUTED_RUN_UNPARSED")
		})
	}
}

// ---------------------------------------------------------------------------
// The post-failure landing review's two findings
// ---------------------------------------------------------------------------

// crTestRevisionHistory returns the decoded revision_history array, so a case
// can mutate one paragraph without re-deriving the path each time.
func crTestRevisionHistory(t *testing.T, document map[string]any) []any {
	t.Helper()
	history, ok := document["revision_history"].([]any)
	if !ok || len(history) < 2 {
		t.Fatal("results document carries no revision_history with at least two paragraphs")
	}
	return history
}

func crTestRevisionEntry(t *testing.T, document map[string]any, index int) map[string]any {
	t.Helper()
	history := crTestRevisionHistory(t, document)
	if index < 0 {
		index += len(history)
	}
	entry, ok := history[index].(map[string]any)
	if !ok {
		t.Fatalf("revision_history[%d] is not an object", index)
	}
	return entry
}

// TestConcurrencyResultsRefusesARevisionHistoryThatIsNotOne is finding 2 of
// drafts/self-review/post-failure-landing-review.md, turned into checks.
//
// THE FINDING. `revision_note` was one undifferentiated string, and the only
// rule any validator applied to it was that it not be empty. At the
// post-failure landing it therefore asserted, in the present tense, "79,920
// schedules ... 56,777/23,143 closed/halted" while the document beside it
// recorded 81,180 / 49 / 81,131, and no check could say so. Four rounds of the
// leaf enumeration listed the field INERT.
//
// EACH CASE BELOW WAS RUN AGAINST THE VALIDATOR WITH crValidateRevisionHistory
// UNREGISTERED AND OBSERVED TO PASS AT ZERO FINDINGS, so none of them is a
// case that reports clean because the document happens to be fine. The
// deletion was of the CALL, not of the function, so the package still compiled
// and the reading is a real one - see
// drafts/self-review/concurrency-coverage-disclosure.md.
func TestConcurrencyResultsRefusesARevisionHistoryThatIsNotOne(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			// THE EXACT SHAPE OF FINDING 2: the current paragraph quotes the
			// counters of a predecessor. This is the edit that produced the
			// finding, and before this field existed nothing in the tree
			// disagreed with it.
			name: "the current paragraph quotes superseded counters",
			mutate: func(t *testing.T, document map[string]any) {
				entry := crTestRevisionEntry(t, document, -1)
				entry["counters_quoted"] = map[string]any{
					"schedules": float64(79920), "closed_terminal_runs": float64(56777),
					"failure_halted_runs": float64(23143),
				}
			},
		},
		{
			// The masquerade in the other direction: a block wearing a
			// history label while quoting today's reading is not history.
			name: "a superseded paragraph quotes the current counters",
			mutate: func(t *testing.T, document map[string]any) {
				current := crTestRevisionEntry(t, document, -1)
				crTestRevisionEntry(t, document, 0)["counters_quoted"] = current["counters_quoted"]
			},
		},
		{
			name: "the counters quoted are not an exploration reading",
			mutate: func(t *testing.T, document map[string]any) {
				counters, ok := crTestRevisionEntry(t, document, 0)["counters_quoted"].(map[string]any)
				if !ok {
					t.Fatal("revision_history[0] carries no counters_quoted object")
				}
				counters["closed_terminal_runs"] = counters["closed_terminal_runs"].(float64) + 1
			},
		},
		{
			name: "the history does not chain",
			mutate: func(t *testing.T, document map[string]any) {
				crTestRevisionEntry(t, document, 0)["superseded_by"] = crTestRevisionEntry(t, document, -1)["revision"]
			},
		},
		{
			name: "two paragraphs claim to describe the document",
			mutate: func(t *testing.T, document map[string]any) {
				crTestRevisionEntry(t, document, 0)["status"] = "CURRENT"
			},
		},
		{
			name: "no paragraph describes the document",
			mutate: func(t *testing.T, document map[string]any) {
				crTestRevisionEntry(t, document, -1)["status"] = "SUPERSEDED"
			},
		},
		{
			// The paragraph is cut short. A containment or non-empty rule
			// accepts this; the closing stamp does not.
			name: "a paragraph is truncated",
			mutate: func(t *testing.T, document map[string]any) {
				entry := crTestRevisionEntry(t, document, 0)
				note, ok := entry["note"].(string)
				if !ok {
					t.Fatal("revision_history[0] carries no note")
				}
				entry["note"] = note[:len(note)/2]
			},
		},
		{
			// A neighbour's paragraph moved into this entry. Both are real
			// prose from this same document, which is what makes it the
			// plausible forgery rather than an obviously wrong one.
			name: "a paragraph is swapped for its neighbour's",
			mutate: func(t *testing.T, document map[string]any) {
				first, second := crTestRevisionEntry(t, document, 0), crTestRevisionEntry(t, document, 1)
				first["note"] = second["note"]
			},
		},
		{
			name: "a paragraph has no quotable identity",
			mutate: func(t *testing.T, document map[string]any) {
				crTestRevisionEntry(t, document, 0)["revision"] = "ROUND 2"
			},
		},
		{
			name: "the whole history is dropped",
			mutate: func(t *testing.T, document map[string]any) {
				document["revision_history"] = []any{}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_REVISION_HISTORY_UNSOUND")
		})
	}
}

// TestConcurrencyResultsDerivesScenarioProseFromTheHarness is the other half
// of the revision_note class: prose that reads as a justification and rests on
// nothing. bounds.scenario_shapes[*].models and .why_explored say what a
// scenario stands for and why it is explored - the sentences that make a
// scenario a real adapter shape rather than one chosen to make a gate green -
// and until this branch they were attested.
//
// Run with crValidateScenarioProse unregistered: every case passed at zero
// findings.
func TestConcurrencyResultsDerivesScenarioProseFromTheHarness(t *testing.T) {
	shapeAt := func(t *testing.T, document map[string]any, index int) map[string]any {
		t.Helper()
		shapes, ok := crTestSection(t, document, "bounds")["scenario_shapes"].([]any)
		if !ok || len(shapes) < 2 {
			t.Fatal("bounds carries no scenario_shapes array with at least two entries")
		}
		shape, ok := shapes[index].(map[string]any)
		if !ok {
			t.Fatalf("bounds.scenario_shapes[%d] is not an object", index)
		}
		return shape
	}
	for _, testCase := range []struct {
		name   string
		code   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			// The softening the enumeration lists as a live candidate: half a
			// justification still reads as a justification, and a containment
			// check accepts it.
			name: "the justification is truncated",
			code: "RESULTS_SCENARIO_PROSE_CONTRADICTED",
			mutate: func(t *testing.T, document map[string]any) {
				shape := shapeAt(t, document, 0)
				text, ok := shape["why_explored"].(string)
				if !ok {
					t.Fatal("scenario_shapes[0] carries no why_explored")
				}
				shape["why_explored"] = text[:len(text)/2]
			},
		},
		{
			name: "a neighbour scenario's prose is used",
			code: "RESULTS_SCENARIO_PROSE_CONTRADICTED",
			mutate: func(t *testing.T, document map[string]any) {
				shapeAt(t, document, 0)["models"] = shapeAt(t, document, 1)["models"]
			},
		},
		{
			name: "a number inside the justification is moved",
			code: "RESULTS_SCENARIO_PROSE_CONTRADICTED",
			mutate: func(t *testing.T, document map[string]any) {
				shape := shapeAt(t, document, 1)
				text, ok := shape["why_explored"].(string)
				if !ok {
					t.Fatal("scenario_shapes[1] carries no why_explored")
				}
				shape["why_explored"] = strings.Replace(text, "1260", "1261", 1)
			},
		},
		{
			// A scenario the harness's SCENARIOS table does not bind: its
			// prose derives from nothing, which must be refused rather than
			// skipped.
			name: "the scenario is not one the harness enumerates",
			code: "RESULTS_SCENARIO_PROSE_UNDERIVED",
			mutate: func(t *testing.T, document map[string]any) {
				shapeAt(t, document, 0)["name"] = "clean-finish-inbound-pong"
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, testCase.code)
		})
	}
}

// TestConcurrencyResultsRefusesACleanRouteReadingThatIsImpossible is finding 1
// of the same review, on the accounting side. The review's whole point is that
// a RUN count is not a coverage reading, so the coverage readings are recorded
// beside it - and a recorded number is only as good as the relations it has to
// satisfy.
//
// Run with the clean-route block of crValidateAccounting deleted: every case
// passed at zero findings.
func TestConcurrencyResultsRefusesACleanRouteReadingThatIsImpossible(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		field string
		value float64
	}{
		{"more distinct clean traces than clean runs", "distinct_clean_terminal_digests", 2000},
		{"clean runs that carry no trace at all", "distinct_clean_terminal_digests", 0},
		{"clean runs belonging to no scenario", "clean_terminal_scenarios", 0},
		{"a clean terminal reached in more scenarios than exist", "clean_terminal_scenarios", 9},
		{"more halted terminals than halted runs", "halted_terminals", 99999},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			crTestSection(t, document, "execution")[testCase.field] = testCase.value
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_ACCOUNTING_CONTRADICTION")
		})
	}
}

// TestConcurrencyResultsRefusesADroppedCleanRouteCeiling is the finding-1
// disclosure itself. The review checked all twelve limitations and none
// mentioned the collapse; the thirteenth states it, so it must not be
// removable, renameable or quietly re-numbered.
//
// Run with the limitations.clean_route_ceiling expectation deleted from
// crValidateQuotedCounters: every case passed at zero findings.
func TestConcurrencyResultsRefusesADroppedCleanRouteCeiling(t *testing.T) {
	locate := func(t *testing.T, document map[string]any) ([]any, int) {
		t.Helper()
		limitations, ok := document["limitations"].([]any)
		if !ok {
			t.Fatal("results document carries no limitations array")
		}
		for index, entry := range limitations {
			if text, ok := entry.(string); ok && strings.HasPrefix(strings.TrimSpace(text), "CLEAN-ROUTE COVERAGE CEILING:") {
				return limitations, index
			}
		}
		t.Fatal("no limitation states the clean-route coverage ceiling")
		return nil, -1
	}
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			name: "the ceiling is deleted outright",
			mutate: func(t *testing.T, document map[string]any) {
				limitations, index := locate(t, document)
				document["limitations"] = append(append([]any{}, limitations[:index]...), limitations[index+1:]...)
			},
		},
		{
			name: "the ceiling loses the heading that makes it findable",
			mutate: func(t *testing.T, document map[string]any) {
				limitations, index := locate(t, document)
				limitations[index] = "COVERAGE NOTE: " + limitations[index].(string)
			},
		},
		{
			name: "the ceiling understates the halted remainder",
			mutate: func(t *testing.T, document map[string]any) {
				limitations, index := locate(t, document)
				limitations[index] = strings.Replace(limitations[index].(string), "90984", "9084", 1)
			},
		},
		// The truncation case is NOT here. It belongs to
		// TestConcurrencyResultsRefusesACeilingThatForbidsNothing, because
		// cutting this limitation in half leaves every counter it must quote
		// intact: the quoted-counter expectation says nothing about it, and
		// discovering that is what produced crValidateCleanRouteCeiling.
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_PROSE_CONTRADICTS_COUNTERS")
		})
	}
}

// crTestRewriteCeiling locates the clean-route ceiling limitation and
// rewrites it through the supplied function.
func crTestRewriteCeiling(t *testing.T, document map[string]any, rewrite func(string) string) {
	t.Helper()
	limitations, ok := document["limitations"].([]any)
	if !ok {
		t.Fatal("results document carries no limitations array")
	}
	for index, entry := range limitations {
		text, ok := entry.(string)
		if !ok || !strings.HasPrefix(strings.TrimSpace(text), "CLEAN-ROUTE COVERAGE CEILING:") {
			continue
		}
		replacement := rewrite(text)
		if replacement == "" {
			document["limitations"] = append(append([]any{}, limitations[:index]...), limitations[index+1:]...)
			return
		}
		limitations[index] = replacement
		return
	}
	t.Fatal("no limitation states the clean-route coverage ceiling")
}

// TestConcurrencyResultsRefusesACeilingThatForbidsNothing is a finding this
// branch made against ITSELF, and it is the reason this check exists.
//
// With only the quoted-counter expectation in force, cutting the ceiling
// limitation in half was accepted at zero findings: every counter it must
// quote occurs in the first 863 of its 1726 characters, so the truncation
// removed what the ceiling forbids, why it cannot be widened, and the pointer
// to the reading it replaced, and no check said anything. That is the
// softening the leaf enumeration lists as a live candidate, landing on the one
// limitation whose whole purpose is to stop a coverage claim being
// strengthened.
//
// Every case below was run with crValidateCleanRouteCeiling unregistered and
// observed to pass at zero findings.
func TestConcurrencyResultsRefusesACeilingThatForbidsNothing(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		rewrite func(string) string
	}{
		{
			// The reading that produced this test.
			name:    "the ceiling is cut in half, keeping every counter",
			rewrite: func(text string) string { return text[:len(text)/2] },
		},
		{
			name: "the prohibition is dropped",
			rewrite: func(text string) string {
				return strings.Replace(text, "WHAT THIS CEILING FORBIDS:", "AS AN ASIDE,", 1)
			},
		},
		{
			name: "the bound is asserted without a reason",
			rewrite: func(text string) string {
				return strings.Replace(text, "WHY IT IS NOT WIDER:", "SEPARATELY,", 1)
			},
		},
		{
			// The pointer at the superseded reading is aimed at a paragraph
			// this document does not carry.
			name: "the reading it replaced is filed under an identity that does not exist",
			rewrite: func(text string) string {
				return strings.Replace(text, "post-failure-landing-2026-09-02", "post-failure-landing-2026-08-30", 1)
			},
		},
		{
			// A reading cannot have been superseded by itself.
			name: "the reading it replaced is filed under the current paragraph",
			rewrite: func(text string) string {
				return strings.Replace(text, "post-failure-landing-2026-09-02", "clean-finish-breadth-2026-09-02", 1)
			},
		},
		{
			name:    "the ceiling is removed from the record",
			rewrite: func(string) string { return "" },
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			crTestRewriteCeiling(t, document, testCase.rewrite)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_CLEAN_ROUTE_CEILING_UNSOUND")
		})
	}
}

// TestConcurrencyResultsRefusesACeilingPointingAtALiveParagraph closes the
// remaining direction: the ceiling names a paragraph that exists but has not
// been superseded. Marking that paragraph CURRENT is not possible without
// breaking revision_history's own rules, so the case is built the other way -
// the named paragraph's status is what changes, and the ceiling's pointer
// stops resolving to history.
func TestConcurrencyResultsRefusesACeilingPointingAtALiveParagraph(t *testing.T) {
	document := crTestDecode(t)
	entry := crTestRevisionEntry(t, document, -2)
	entry["status"] = "PROVISIONAL"
	findings := ValidateConcurrencyResults(crTestWrite(t, document))
	crTestRequireCode(t, findings, "RESULTS_CLEAN_ROUTE_CEILING_UNSOUND")
	crTestRequireCode(t, findings, "RESULTS_REVISION_HISTORY_UNSOUND")
}

// TestConcurrencyResultsRefusesAHistoryWithItsBeginningRemoved is the omission
// gap the whole-document walk found in the field this branch ADDED.
//
// TestConcurrencyResultsEveryModeledKeyIsRequired reported "deleting
// revision_history[0] produces no finding". It was right: the forward chain is
// relative, so a shortened array still chains, still carries exactly one
// CURRENT paragraph at its end, and still agrees with the record's counters.
// The oldest paragraph could simply be dropped. Substitution could never have
// found this - an absent element is not a wrong value - which is why the
// omission walk is a separate axis, and it found the hole in the field added
// to close a disclosure gap.
func TestConcurrencyResultsRefusesAHistoryWithItsBeginningRemoved(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
	}{
		{
			// Verbatim the walk's reading.
			name: "the oldest paragraph is deleted",
			mutate: func(t *testing.T, document map[string]any) {
				document["revision_history"] = crTestRevisionHistory(t, document)[1:]
			},
		},
		{
			name: "the two oldest paragraphs are deleted",
			mutate: func(t *testing.T, document map[string]any) {
				document["revision_history"] = crTestRevisionHistory(t, document)[2:]
			},
		},
		{
			// Deletion's quieter cousin: the oldest paragraph stays but stops
			// being the paragraph the record began at, stamps and all. Nothing
			// points BACK at the head, so every other rule still holds.
			name: "the oldest paragraph is re-identified",
			mutate: func(t *testing.T, document map[string]any) {
				first := crTestRevisionEntry(t, document, 0)
				was, ok := first["revision"].(string)
				if !ok {
					t.Fatal("revision_history[0] carries no revision identity")
				}
				renamed := "recut-" + was
				first["note"] = strings.ReplaceAll(first["note"].(string), was, renamed)
				first["revision"] = renamed
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := crTestDecode(t)
			testCase.mutate(t, document)
			findings := ValidateConcurrencyResults(crTestWrite(t, document))
			crTestRequireCode(t, findings, "RESULTS_REVISION_HISTORY_UNSOUND")
		})
	}
}
