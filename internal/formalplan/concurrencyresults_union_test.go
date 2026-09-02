package formalplan

// The landing-union round (round 5 of the evidence-validation lane, executed
// by the goal loop on 2026-09-02 while forward-merging claude/us017-ac2's
// record and validator into this branch).
//
// Two validators for one document met here: us017-ac2's bindings validator
// (blobs, plan digest, minimized reproductions, retention seeds, with a
// document-enumerated polarity test) and this lane's run-citation validator.
// The union kept both and extended the run-citation model to every field the
// landed record carried. Each extension below was first measured INERT — the
// leaf enumeration (CR_LEAF_ENUM=print) read 91 inert leaves of 308 on the
// merged document before any of these checks existed, including every
// fatal-termination sweep magnitude — and is now a permanent refusal.
//
// Every case is a mutation of the committed document applied to a temp copy
// with the real tree as root; the expected finding is the one the validator
// emits for that mutation and nothing weaker.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func unionDefect(t *testing.T, document map[string]any, index int) map[string]any {
	t.Helper()
	defect, ok := crTestArray(t, document, "defects_found_and_fixed")[index].(map[string]any)
	if !ok {
		t.Fatalf("defects_found_and_fixed[%d] is not an object", index)
	}
	return defect
}

func unionReproduction(t *testing.T, document map[string]any, index int) map[string]any {
	t.Helper()
	reproduction, ok := unionDefect(t, document, index)["minimized_reproduction"].(map[string]any)
	if !ok {
		t.Fatalf("defects_found_and_fixed[%d] has no minimized_reproduction object", index)
	}
	return reproduction
}

func unionArtifact(t *testing.T, document map[string]any, index int) map[string]any {
	t.Helper()
	artifact, ok := crTestArray(t, document, "retention", "minimized_artifacts")[index].(map[string]any)
	if !ok {
		t.Fatalf("retention.minimized_artifacts[%d] is not an object", index)
	}
	return artifact
}

func unionSweep(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	return crTestSection(t, document, "execution", "fatal_termination_sweep")
}

func unionSweepLines(t *testing.T, document map[string]any) []any {
	t.Helper()
	return crTestArray(t, document, "execution", "fatal_termination_sweep", "executed_run", "sweep_stdout_lines")
}

func unionReplace(t *testing.T, text, before, after string) string {
	t.Helper()
	if !strings.Contains(text, before) {
		t.Fatalf("the committed text no longer contains %q; this probe is stale", before)
	}
	return strings.Replace(text, before, after, 1)
}

func unionString(t *testing.T, document map[string]any, keys ...string) string {
	t.Helper()
	section := document
	for _, key := range keys[:len(keys)-1] {
		section = crTestSection(t, section, key)
	}
	text, ok := section[keys[len(keys)-1]].(string)
	if !ok {
		t.Fatalf("%s is not a string", strings.Join(keys, "."))
	}
	return text
}

func unionSetString(t *testing.T, document map[string]any, value string, keys ...string) {
	t.Helper()
	section := document
	for _, key := range keys[:len(keys)-1] {
		section = crTestSection(t, section, key)
	}
	section[keys[len(keys)-1]] = value
}

// TestConcurrencyResultsUnionRefusesEachNewInertLeaf is the round's table:
// one mutation per binding the union added, each refused with the finding
// the binding was written to produce.
func TestConcurrencyResultsUnionRefusesEachNewInertLeaf(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, document map[string]any)
		code   string
	}{
		// --- max_actions: required exactly where the pinned seed carries it ---
		{
			name: "the tightened action budget is dropped from the reproduction whose seed carries it",
			mutate: func(t *testing.T, document map[string]any) {
				delete(unionReproduction(t, document, 4), "max_actions")
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "the tightened action budget disagrees with the seed",
			mutate: func(t *testing.T, document map[string]any) {
				unionReproduction(t, document, 4)["max_actions"] = float64(2)
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "an action budget is claimed for a reproduction whose seed has none",
			mutate: func(t *testing.T, document map[string]any) {
				unionReproduction(t, document, 0)["max_actions"] = float64(1)
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "an action budget that admits no action",
			mutate: func(t *testing.T, document map[string]any) {
				unionReproduction(t, document, 4)["max_actions"] = float64(0)
			},
			code: "RESULTS_PLAN_CONFORMANCE_VIOLATED",
		},
		{
			name: "an action budget above the preregistered ceiling",
			mutate: func(t *testing.T, document map[string]any) {
				unionReproduction(t, document, 4)["max_actions"] = float64(99999)
			},
			code: "RESULTS_PLAN_CONFORMANCE_VIOLATED",
		},
		// --- added_by: required exactly where the fault has no adopted seed ---
		{
			name: "the seventh fault loses its origin",
			mutate: func(t *testing.T, document map[string]any) {
				delete(unionArtifact(t, document, 6), "added_by")
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "an adopted fault claims a local origin",
			mutate: func(t *testing.T, document map[string]any) {
				unionArtifact(t, document, 0)["added_by"] = unionArtifact(t, document, 6)["added_by"]
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "the origin names another story",
			mutate: func(t *testing.T, document map[string]any) {
				unionArtifact(t, document, 6)["added_by"] = "US-18 story review BLOCKING-2 fix"
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "the origin names no review",
			mutate: func(t *testing.T, document map[string]any) {
				unionArtifact(t, document, 6)["added_by"] = "US-017 landing session"
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		// --- the ten-entry defect roll and each defect's shape ---
		{
			name: "the last review-found defect is dropped from the roll",
			mutate: func(t *testing.T, document map[string]any) {
				defects := crTestArray(t, document, "defects_found_and_fixed")
				document["defects_found_and_fixed"] = defects[:len(defects)-1]
			},
			code: "RESULTS_DEFECT_ROLL_INCOMPLETE",
		},
		{
			name: "two defects trade places",
			mutate: func(t *testing.T, document map[string]any) {
				defects := crTestArray(t, document, "defects_found_and_fixed")
				defects[2], defects[3] = defects[3], defects[2]
			},
			code: "RESULTS_DEFECT_ROLL_INCOMPLETE",
		},
		{
			name: "a test-side defect loses the note that says the implementation is unchanged",
			mutate: func(t *testing.T, document map[string]any) {
				delete(unionDefect(t, document, 7), "note")
			},
			code: "RESULTS_DEFECT_ROLL_INCOMPLETE",
		},
		{
			name: "a driver defect gains a note its kind excludes",
			mutate: func(t *testing.T, document map[string]any) {
				unionDefect(t, document, 2)["note"] = "test-side only"
			},
			code: "RESULTS_DEFECT_ROLL_INCOMPLETE",
		},
		{
			name: "the socket-level reproduction narrative is dropped from the defect that has one",
			mutate: func(t *testing.T, document map[string]any) {
				delete(unionDefect(t, document, 9), "reproduction")
			},
			code: "RESULTS_DEFECT_ROLL_INCOMPLETE",
		},
		// --- the seed a reproduction cites must be THIS defect's ---
		{
			name: "a defect cites the counterexample pinned for a different defect",
			mutate: func(t *testing.T, document map[string]any) {
				other := unionReproduction(t, document, 0)
				mine := unionReproduction(t, document, 4)
				for _, key := range []string{"path", "sha256", "schedule", "event_queue_capacity"} {
					mine[key] = other[key]
				}
				delete(mine, "max_actions")
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		// --- RED readings resolve into the body of a test the defect names ---
		{
			name: "a review-found defect borrows its neighbour's RED reading",
			mutate: func(t *testing.T, document map[string]any) {
				unionDefect(t, document, 5)["red_evidence"] = unionDefect(t, document, 6)["red_evidence"]
			},
			code: "RESULTS_RED_READING_UNBOUND",
		},
		{
			name: "a RED reading that quotes nothing and attests nothing",
			mutate: func(t *testing.T, document map[string]any) {
				unionDefect(t, document, 6)["red_evidence"] = "the three tests went red on the old adapter and were looked at"
			},
			code: "RESULTS_RED_READING_UNBOUND",
		},
		{
			name: "a RED reading cut in half keeps its quote but not its closing",
			mutate: func(t *testing.T, document map[string]any) {
				defect := unionDefect(t, document, 3)
				text := defect["red_evidence"].(string)
				defect["red_evidence"] = text[:len(text)/2]
			},
			code: "RESULTS_RED_READING_UNBOUND",
		},
		// --- the fatal-termination sweep is re-derived from the lines it cites ---
		{
			name: "a per-budget halted count moves in the cited line",
			mutate: func(t *testing.T, document map[string]any) {
				lines := unionSweepLines(t, document)
				lines[1] = unionReplace(t, lines[1].(string), "halted_runs=58616", "halted_runs=58617")
			},
			code: "RESULTS_COUNTER_CONTRADICTS_RUN",
		},
		{
			name: "a per-budget drop count moves in the block",
			mutate: func(t *testing.T, document map[string]any) {
				crTestSection(t, unionSweep(t, document), "per_budget_fatal_path_drop_runs")["1"] = float64(23073)
			},
			code: "RESULTS_COUNTER_CONTRADICTS_RUN",
		},
		{
			name: "the drop-run total moves by one",
			mutate: func(t *testing.T, document map[string]any) {
				unionSweep(t, document)["fatal_path_drop_runs_total"] = float64(56190)
			},
			code: "RESULTS_COUNTER_CONTRADICTS_RUN",
		},
		{
			name: "the dropped-bytes total moves by one",
			mutate: func(t *testing.T, document map[string]any) {
				unionSweep(t, document)["fatal_path_dropped_bytes_total"] = float64(198038)
			},
			code: "RESULTS_COUNTER_CONTRADICTS_RUN",
		},
		{
			name: "the action budgets are reordered",
			mutate: func(t *testing.T, document map[string]any) {
				unionSweep(t, document)["action_budgets"] = []any{float64(0), float64(1), float64(3), float64(2)}
			},
			code: "RESULTS_COUNTER_CONTRADICTS_RUN",
		},
		{
			name: "one cited sweep line is dropped",
			mutate: func(t *testing.T, document map[string]any) {
				lines := unionSweepLines(t, document)
				crTestSection(t, unionSweep(t, document), "executed_run")["sweep_stdout_lines"] = append(lines[:2:2], lines[3:]...)
			},
			code: "RESULTS_EXECUTED_RUN_UNPARSED",
		},
		{
			name: "the total line's per-budget list disagrees with its own lines",
			mutate: func(t *testing.T, document map[string]any) {
				lines := unionSweepLines(t, document)
				lines[4] = unionReplace(t, lines[4].(string), "(1, 23072)", "(1, 23073)")
			},
			code: "RESULTS_COUNTER_CONTRADICTS_RUN",
		},
		{
			name: "the sweep cites no run at all",
			mutate: func(t *testing.T, document map[string]any) {
				delete(unionSweep(t, document), "executed_run")
			},
			code: "RESULTS_EXECUTED_RUN_ABSENT",
		},
		{
			name: "a cited sweep line carries a field nothing re-derives",
			mutate: func(t *testing.T, document map[string]any) {
				lines := unionSweepLines(t, document)
				lines[0] = lines[0].(string) + " extra=1"
			},
			code: "RESULTS_EXECUTED_RUN_UNPARSED",
		},
		{
			name: "the sweep ran a different enumeration",
			mutate: func(t *testing.T, document map[string]any) {
				lines := unionSweepLines(t, document)
				lines[0] = unionReplace(t, lines[0].(string), "schedules=79920", "schedules=79921")
			},
			code: "RESULTS_COUNTER_CONTRADICTS_RUN",
		},
		{
			name: "a budget disappears from one per-budget map",
			mutate: func(t *testing.T, document map[string]any) {
				delete(crTestSection(t, unionSweep(t, document), "per_budget_clean_path_drop_runs"), "3")
			},
			code: "RESULTS_COUNTER_CONTRADICTS_RUN",
		},
		// --- fields that NAME seeds agree with the seeds ---
		{
			name: "a polarity control restates a schedule its seed does not carry",
			mutate: func(t *testing.T, document map[string]any) {
				controls := crTestArray(t, document, "retention", "polarity_controls")
				controls[1] = unionReplace(t, controls[1].(string),
					"schedule enqueue-close-b,inbound-close,shutdown", "schedule enqueue-close-b,shutdown")
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "the rerunnable control is dropped from the list",
			mutate: func(t *testing.T, document map[string]any) {
				controls := crTestArray(t, document, "retention", "polarity_controls")
				crTestSection(t, document, "retention")["polarity_controls"] = controls[:1]
			},
			code: "RESULTS_NAMED_ARTIFACT_MISSING",
		},
		{
			name: "a pinned regression seed is dropped from the list",
			mutate: func(t *testing.T, document map[string]any) {
				regressions := crTestArray(t, document, "retention", "real_defect_regressions")
				crTestSection(t, document, "retention")["real_defect_regressions"] = regressions[:1]
			},
			code: "RESULTS_NAMED_ARTIFACT_MISSING",
		},
		{
			name: "a regression entry quotes a digest prefix that is not the seed's",
			mutate: func(t *testing.T, document map[string]any) {
				regressions := crTestArray(t, document, "retention", "real_defect_regressions")
				regressions[1] = unionReplace(t, regressions[1].(string), "sha256 66df0cdd", "sha256 66df0cde")
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "a regression entry quotes a budget that is not the seed's",
			mutate: func(t *testing.T, document map[string]any) {
				regressions := crTestArray(t, document, "retention", "real_defect_regressions")
				regressions[1] = unionReplace(t, regressions[1].(string), "max_actions=1", "max_actions=2")
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "the seed-format note misquotes the unreachable budget",
			mutate: func(t *testing.T, document map[string]any) {
				unionSetString(t, document,
					unionReplace(t, unionString(t, document, "retention", "seed_format_note"), "1024", "1025"),
					"retention", "seed_format_note")
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "the sweep's why misquotes the unreachable budget",
			mutate: func(t *testing.T, document map[string]any) {
				sweep := unionSweep(t, document)
				sweep["why"] = strings.ReplaceAll(sweep["why"].(string), "1024", "512")
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "the polarity read names a control test the harness does not declare",
			mutate: func(t *testing.T, document map[string]any) {
				sweep := unionSweep(t, document)
				sweep["harness_polarity_read"] = unionReplace(t, sweep["harness_polarity_read"].(string),
					"round_two_fatal_halt_accounting_control_replays_both_polarities", "round_two_control")
			},
			code: "RESULTS_NAMED_ARTIFACT_MISSING",
		},
		{
			name: "the mechanism sentence stops naming the found index the seeds record",
			mutate: func(t *testing.T, document map[string]any) {
				unionSetString(t, document,
					unionReplace(t, unionString(t, document, "retention", "mechanism"),
						", and the found index at which the exploration first hit the fault", ""),
					"retention", "mechanism")
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		// --- prose that quotes numbers quotes the record's ---
		{
			name: "the drift limitation misquotes the toolchain pin",
			mutate: func(t *testing.T, document map[string]any) {
				limitations := crTestArray(t, document, "limitations")
				limitations[11] = unionReplace(t, limitations[11].(string), "pinned at 1.95.0", "pinned at 1.94.0")
			},
			code: "RESULTS_SEED_CONTENT_CONTRADICTED",
		},
		{
			name: "the frame-count limitation moves the counter it opens with",
			mutate: func(t *testing.T, document map[string]any) {
				limitations := crTestArray(t, document, "limitations")
				limitations[6] = unionReplace(t, limitations[6].(string), "is 1 across all 79920", "is 2 across all 79920")
			},
			code: "RESULTS_CLAIM_CEILING_INFLATED",
		},
		{
			name: "the coverage paragraph moves a dropped-write count",
			mutate: func(t *testing.T, document map[string]any) {
				unionSetString(t, document,
					unionReplace(t, unionString(t, document, "execution", "new_disposition_coverage"), "37,813", "37,814"),
					"execution", "new_disposition_coverage")
			},
			code: "RESULTS_PROSE_CONTRADICTS_COUNTERS",
		},
		{
			name: "the outcome sentence's sweep total moves",
			mutate: func(t *testing.T, document map[string]any) {
				unionSetString(t, document,
					unionReplace(t, unionString(t, document, "execution", "outcome"),
						"across all 79920 schedules at each", "across all 79921 schedules at each"),
					"execution", "outcome")
			},
			code: "RESULTS_PROSE_CONTRADICTS_COUNTERS",
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

// unionRoot builds a tree rooted in a temp directory in which every path the
// two validators read resolves to the real tree through symlinks, except
// assurance/concurrency/results.json, which is the mutated document. This is
// what lets ValidateConcurrencyResultsAll — the union entry point, which takes
// a root and reads the canonical document path — run over a forgery.
func unionRoot(t *testing.T, document map[string]any) string {
	t.Helper()
	real, err := filepath.Abs(crTestRoot)
	if err != nil {
		t.Fatalf("resolve the tree root: %v", err)
	}
	root := t.TempDir()
	link := func(relative string) {
		target := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", relative, err)
		}
		if err := os.Symlink(filepath.Join(real, relative), target); err != nil {
			t.Fatalf("link %s: %v", relative, err)
		}
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		t.Fatalf("read the tree root: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() == "assurance" || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		link(entry.Name())
	}
	assurance, err := os.ReadDir(filepath.Join(real, "assurance"))
	if err != nil {
		t.Fatalf("read assurance/: %v", err)
	}
	for _, entry := range assurance {
		if entry.Name() == "concurrency" {
			continue
		}
		link(filepath.Join("assurance", entry.Name()))
	}
	concurrency, err := os.ReadDir(filepath.Join(real, "assurance", "concurrency"))
	if err != nil {
		t.Fatalf("read assurance/concurrency/: %v", err)
	}
	for _, entry := range concurrency {
		if entry.Name() == "results.json" {
			continue
		}
		link(filepath.Join("assurance", "concurrency", entry.Name()))
	}
	inputs := crTestWrite(t, document)
	raw, err := os.ReadFile(inputs.ResultsPath)
	if err != nil {
		t.Fatalf("read the mutated document: %v", err)
	}
	target := filepath.Join(root, filepath.FromSlash(ConcurrencyResultsDocumentPath))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir for the document: %v", err)
	}
	if err := os.WriteFile(target, raw, 0o600); err != nil {
		t.Fatalf("write the mutated document: %v", err)
	}
	return root
}

// TestConcurrencyResultsUnionComposesBothValidators replays one attack from
// each review history through the union entry point, and asserts the clean
// document passes it: the composition is what the landing claims, so it is
// measured rather than described.
func TestConcurrencyResultsUnionComposesBothValidators(t *testing.T) {
	t.Run("the committed document passes the union", func(t *testing.T) {
		findings := crBlocking(ValidateConcurrencyResultsAll(crTestRoot))
		if len(findings) != 0 {
			t.Fatalf("the committed document does not pass the union: %v", crTestCodes(findings))
		}
	})
	t.Run("the reviewer's fairness flip (evidence-validation round 2)", func(t *testing.T) {
		document := crTestDecode(t)
		crTestSection(t, document, "execution")["producer_admission_fairness_claimed"] = true
		findings := ValidateConcurrencyResultsAll(unionRoot(t, document))
		crTestRequireCode(t, findings, "RESULTS_FAIRNESS_CONTRADICTS_RUN")
	})
	t.Run("a stale retention seed digest is refused by BOTH halves (us017-ac2 round 3)", func(t *testing.T) {
		document := crTestDecode(t)
		artifact := unionArtifact(t, document, 0)
		artifact["sha256"] = crFlipLastHex(artifact["sha256"].(string))
		findings := ValidateConcurrencyResultsAll(unionRoot(t, document))
		crTestRequireCode(t, findings, "RESULTS_SEED_DIGEST_STALE")
		crTestRequireCode(t, findings, "RESULTS_ARTIFACT_DIGEST_STALE")
	})
	t.Run("a stale harness blob is refused by BOTH halves (evidence-validation round 1, us017-ac2 round 3)", func(t *testing.T) {
		document := crTestDecode(t)
		harness := crTestSection(t, document, "target", "harness")
		harness["git_blob"] = crFlipLastHex(harness["git_blob"].(string))
		findings := ValidateConcurrencyResultsAll(unionRoot(t, document))
		crTestRequireCode(t, findings, "RESULTS_SOURCE_BLOB_STALE")
		crTestRequireCode(t, findings, "RESULTS_TARGET_BLOB_STALE")
	})
	t.Run("a stale regression-seed digest is refused by BOTH halves", func(t *testing.T) {
		document := crTestDecode(t)
		reproduction := unionReproduction(t, document, 4)
		reproduction["sha256"] = crFlipLastHex(reproduction["sha256"].(string))
		findings := ValidateConcurrencyResultsAll(unionRoot(t, document))
		crTestRequireCode(t, findings, "RESULTS_SEED_DIGEST_STALE")
		crTestRequireCode(t, findings, "RESULTS_ARTIFACT_DIGEST_STALE")
	})
}

// TestConcurrencyResultsSweepLinesAreReadTheSameWayTwice holds the raw sweep
// reader to the same contract the exploration line's raw reader carries
// (evidence-validation round 1 BLOCKING 1): one bare key, any legal
// whitespace, no escapes, and a refusal for everything else.
func TestConcurrencyResultsSweepLinesAreReadTheSameWayTwice(t *testing.T) {
	want := []string{"US017_FATAL_SWEEP budget=0 schedules=1", "US017_FATAL_SWEEP_TOTAL budgets=[0]"}
	for _, layout := range []string{
		`{"sweep_stdout_lines": ["US017_FATAL_SWEEP budget=0 schedules=1", "US017_FATAL_SWEEP_TOTAL budgets=[0]"]}`,
		"{\"sweep_stdout_lines\"\n\t:\n\t[\n\t\"US017_FATAL_SWEEP budget=0 schedules=1\"\n\t,\n\t\"US017_FATAL_SWEEP_TOTAL budgets=[0]\"\n\t]}",
		`{"sweep_stdout_lines":["US017_FATAL_SWEEP budget=0 schedules=1","US017_FATAL_SWEEP_TOTAL budgets=[0]"]}`,
	} {
		lines, err := crRawSweepLines([]byte(layout))
		if err != nil {
			t.Fatalf("legal layout %q refused: %v", layout, err)
		}
		if !crSameStrings(lines, want) {
			t.Fatalf("legal layout %q read as %q", layout, lines)
		}
	}
	for name, layout := range map[string]string{
		"two keys":       `{"sweep_stdout_lines": ["a"], "x": {"sweep_stdout_lines": ["b"]}}`,
		"no key":         `{"stdout_line": "US017_EXPLORATION x=1"}`,
		"not an array":   `{"sweep_stdout_lines": "US017_FATAL_SWEEP budget=0"}`,
		"an escape":      `{"sweep_stdout_lines": ["US017_FATAL_SWEEP \"budget\"=0"]}`,
		"a bare element": `{"sweep_stdout_lines": [1]}`,
		"no separator":   `{"sweep_stdout_lines": ["a" "b"]}`,
	} {
		if lines, err := crRawSweepLines([]byte(layout)); err == nil {
			t.Errorf("%s: %q was read as %q instead of refused", name, layout, lines)
		}
	}
}
