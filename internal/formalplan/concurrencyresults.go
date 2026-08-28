// Validator for assurance/concurrency/results.json — the US-017 bounded
// schedule exploration record.
//
// WHY THIS EXISTS. Before this file the results document was acceptance
// evidence that nothing could contradict. It is the sole evidence node bound
// to US-017 in internal/linkage/mapping.go's storyEvidence map, it carries
// twenty-three counters a reader trusts without recomputing, and the only
// mechanical check on it was the evidence-DAG sha256 — a byte pin whose
// sanctioned LINKAGE_REGENERATE=1 flow re-freezes any contents at all. A
// measured corruption confirmed the gap: with explored_schedules rewritten
// from 79920 to 11 and accepted_commands from 221353 to 999999, `go test
// ./...` exited 0 and `make -C rust gates` exited 0 once the DAG pin was
// regenerated.
//
// WHAT THIS BINDS. Three classes the document cannot otherwise refute:
//
//  1. PROVENANCE. The document names the exact bytes it was measured
//     against — the driver source blob, the exploration harness blob, the
//     preregistered plan digest, the minimized-seed digests. Those names are
//     checked against the committed tree, so the record cannot keep claiming
//     a run over source that has since changed. This is the drift the
//     document actually suffered: at dc07516 all three of its top-level
//     provenance anchors named blobs from commit 7ea4780 that the tree no
//     longer contains, and nothing reported it.
//
//  2. THE CITED RUN. Every counter, bound and aggregate is re-derived from
//     execution.executed_run.stdout_line — the verbatim line the exploration
//     prints. A counter cannot be edited, fabricated, or half-refreshed
//     without contradicting the run the document itself cites.
//
//  3. INTERNAL ACCOUNTING. Every arithmetic identity the document asserts
//     about itself is recomputed, and the prose that quotes counters back to
//     the reader must quote the counters that are actually recorded.
//
// WHERE THE OTHER HALF LIVES. This validator proves the counters match the
// cited line; it cannot prove the line came from a real run. That is proven at
// the run itself: rust/ws-driver/tests/schedule_exploration.rs formats the
// same line from its own measured totals and compares it byte-for-byte with
// the string recorded here. Neither half is sufficient alone, and each runs
// where the other cannot — this one in a plain `go test ./...` with no Rust
// toolchain, that one only when the exploration actually executes.
package formalplan

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ConcurrencyResultsDocumentPath is the repository-relative home of the
// exploration record.
const ConcurrencyResultsDocumentPath = "assurance/concurrency/results.json"

// crMinimizedSeedDir is where retention.minimized_artifacts entries live.
// The entries carry a seed name and a digest but not a path; the exploration
// harness pins them at <dir>/<seed>.seed (see the retention test in
// rust/ws-driver/tests/schedule_exploration.rs). Naming the convention here
// rather than trusting it keeps the digests checkable.
const crMinimizedSeedDir = "rust/ws-driver/fuzz-seeds/us017/minimized"

// ConcurrencyResultsInputs names the document and the tree its provenance
// claims resolve against. When Root is empty the provenance half degrades to
// advisory findings rather than passing silently — the same fail-loud-or-say-
// so shape the plan validator uses for its receipt root.
type ConcurrencyResultsInputs struct {
	ResultsPath string
	Root        string
}

type crBlobRef struct {
	Path    string `json:"path"`
	GitBlob string `json:"git_blob"`
}

type crTarget struct {
	Symbol  string    `json:"symbol"`
	Source  crBlobRef `json:"source"`
	Harness crBlobRef `json:"harness"`
}

type crPreregisteredPlan struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Conformance string `json:"conformance"`
}

type crBounds struct {
	ActorPrograms      int `json:"actor_programs"`
	ActionsPerSchedule int `json:"actions_per_schedule"`
	ContextSwitchBound int `json:"context_switch_bound"`
	PreemptionBudget   int `json:"preemption_budget"`
	CommandQueue       int `json:"command_queue_capacity"`
	WriteQueue         int `json:"write_queue_capacity"`
	EventQueue         int `json:"event_queue_capacity"`
	ScheduleCountMax   int `json:"schedule_count_max"`
	BranchCountMax     int `json:"branch_count_max"`
	DrainBudgetPolls   int `json:"drain_budget_polls"`
}

type crCounters struct {
	AcceptedCommands      int    `json:"accepted_commands"`
	QueueFullRefusals     int    `json:"queue_full_refusals"`
	Applied               int    `json:"applied"`
	TypedRejections       int    `json:"typed_rejections"`
	TerminalRejections    int    `json:"terminal_rejections"`
	Reconciliation        string `json:"reconciliation"`
	EventsDrained         int    `json:"events_drained"`
	SurfacedTypedFailures int    `json:"surfaced_typed_failures"`
	DeferredOutputPending int    `json:"deferred_output_pending"`
	DeferredCommandTurn   int    `json:"deferred_command_turn"`
	DeferredBackpressure  int    `json:"deferred_backpressure"`
	TypedInputRejections  int    `json:"typed_input_rejections"`
	MaxDrainPollsObserved int    `json:"max_drain_polls_observed"`
}

// crExecutedRun records the run the counters were transcribed from. The
// stdout_line is the single line the exploration prints; binding to it is
// what makes the counters re-derivable rather than asserted. The Rust side
// (rust/ws-driver/tests/schedule_exploration.rs) proves the line is what a
// real run emits; crValidateExecutedRun below proves every counter field in
// this document is what that line says.
type crExecutedRun struct {
	Command    string `json:"command"`
	Exit       *int   `json:"exit"`
	StdoutLine string `json:"stdout_line"`
}

type crExecution struct {
	ExploredSchedules       int            `json:"explored_schedules"`
	ExhaustiveWithinBound   bool           `json:"exhaustive_within_bound"`
	Truncated               bool           `json:"truncated"`
	EnumerationBranches     int            `json:"enumeration_branches"`
	DistinctScheduleDigests int            `json:"distinct_schedule_digests"`
	Executions              int            `json:"executions"`
	DistinctTraceDigests    int            `json:"distinct_semantic_trace_digests"`
	ClosedTerminalRuns      int            `json:"closed_terminal_runs"`
	FailureHaltedRuns       int            `json:"failure_halted_runs"`
	TerminalExclusivity     string         `json:"terminal_disposition_exclusivity"`
	Counters                crCounters     `json:"counters"`
	ExecutedRun             *crExecutedRun `json:"executed_run"`
	Outcome                 string         `json:"outcome"`
}

type crMinimizedArtifact struct {
	Seed     string `json:"seed"`
	Property string `json:"property"`
	SHA256   string `json:"sha256"`
}

type crRetention struct {
	MinimizedArtifacts []crMinimizedArtifact `json:"minimized_artifacts"`
}

type crReproduction struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type crDefect struct {
	DefectID     string          `json:"defect_id"`
	Reproduction *crReproduction `json:"minimized_reproduction"`
}

type crResults struct {
	SchemaVersion     string              `json:"schema_version"`
	EvidenceKind      string              `json:"evidence_kind"`
	StoryID           string              `json:"story_id"`
	State             string              `json:"state"`
	Target            crTarget            `json:"target"`
	PreregisteredPlan crPreregisteredPlan `json:"preregistered_plan"`
	Bounds            crBounds            `json:"bounds"`
	Execution         crExecution         `json:"execution"`
	TerminalModel     string              `json:"terminal_disposition_model"`
	Retention         crRetention         `json:"retention"`
	DefectsFoundFixed []crDefect          `json:"defects_found_and_fixed"`
}

// ValidateConcurrencyResults reports every way the committed exploration
// record contradicts the tree it claims to describe or contradicts itself.
// An empty slice means the record is consistent — it does NOT mean the
// counters were re-measured; that is the Rust binding's job.
func ValidateConcurrencyResults(inputs ConcurrencyResultsInputs) []ModelFinding {
	var findings []ModelFinding

	raw, err := os.ReadFile(inputs.ResultsPath)
	if err != nil {
		return append(findings, mpFinding("RESULTS_FILE_UNREADABLE", inputs.ResultsPath, err.Error()))
	}
	if len(raw) > mpMaxArtifactBytes {
		return append(findings, mpFinding("RESULTS_FILE_UNREADABLE", inputs.ResultsPath, "results exceed the bounded size"))
	}
	var results crResults
	if err := json.Unmarshal(raw, &results); err != nil {
		return append(findings, mpFinding("RESULTS_FILE_UNREADABLE", inputs.ResultsPath, err.Error()))
	}

	findings = append(findings, crValidateProvenance(results, inputs)...)
	findings = append(findings, crValidateExecutedRun(results, inputs.ResultsPath)...)
	findings = append(findings, crValidateAccounting(results, inputs.ResultsPath)...)
	findings = append(findings, crValidateQuotedCounters(results, inputs.ResultsPath)...)
	return findings
}

// crRunFieldToCounter maps each key of the exploration's printed line to the
// document field that must carry it. The printed vocabulary and the document
// vocabulary differ (the run says `rejected`, the document says
// `typed_rejections`); writing the mapping out is what makes the rename
// auditable instead of a silent re-label.
var crRunFieldToCounter = map[string]string{
	"programs":                "bounds.actor_programs",
	"actions_total":           "bounds.actions_per_schedule",
	"context_switch_bound":    "bounds.context_switch_bound",
	"preemption_budget":       "bounds.preemption_budget",
	"schedules":               "execution.explored_schedules",
	"branches":                "execution.enumeration_branches",
	"executions":              "execution.executions",
	"distinct_trace_digests":  "execution.distinct_semantic_trace_digests",
	"closed_terminal_runs":    "execution.closed_terminal_runs",
	"failure_halted_runs":     "execution.failure_halted_runs",
	"accepted":                "execution.counters.accepted_commands",
	"refused_full":            "execution.counters.queue_full_refusals",
	"applied":                 "execution.counters.applied",
	"rejected":                "execution.counters.typed_rejections",
	"terminal_rejected":       "execution.counters.terminal_rejections",
	"events":                  "execution.counters.events_drained",
	"failures":                "execution.counters.surfaced_typed_failures",
	"deferred_output_pending": "execution.counters.deferred_output_pending",
	"deferred_command_turn":   "execution.counters.deferred_command_turn",
	"deferred_backpressure":   "execution.counters.deferred_backpressure",
	"rejected_inputs":         "execution.counters.typed_input_rejections",
	"max_drain_polls":         "execution.counters.max_drain_polls_observed",
}

// crDocumentCounters flattens the document's numeric claims under the names
// crRunFieldToCounter targets.
func crDocumentCounters(results crResults) map[string]int {
	counters := results.Execution.Counters
	return map[string]int{
		"bounds.actor_programs":                       results.Bounds.ActorPrograms,
		"bounds.actions_per_schedule":                 results.Bounds.ActionsPerSchedule,
		"bounds.context_switch_bound":                 results.Bounds.ContextSwitchBound,
		"bounds.preemption_budget":                    results.Bounds.PreemptionBudget,
		"execution.explored_schedules":                results.Execution.ExploredSchedules,
		"execution.enumeration_branches":              results.Execution.EnumerationBranches,
		"execution.executions":                        results.Execution.Executions,
		"execution.distinct_semantic_trace_digests":   results.Execution.DistinctTraceDigests,
		"execution.closed_terminal_runs":              results.Execution.ClosedTerminalRuns,
		"execution.failure_halted_runs":               results.Execution.FailureHaltedRuns,
		"execution.counters.accepted_commands":        counters.AcceptedCommands,
		"execution.counters.queue_full_refusals":      counters.QueueFullRefusals,
		"execution.counters.applied":                  counters.Applied,
		"execution.counters.typed_rejections":         counters.TypedRejections,
		"execution.counters.terminal_rejections":      counters.TerminalRejections,
		"execution.counters.events_drained":           counters.EventsDrained,
		"execution.counters.surfaced_typed_failures":  counters.SurfacedTypedFailures,
		"execution.counters.deferred_output_pending":  counters.DeferredOutputPending,
		"execution.counters.deferred_command_turn":    counters.DeferredCommandTurn,
		"execution.counters.deferred_backpressure":    counters.DeferredBackpressure,
		"execution.counters.typed_input_rejections":   counters.TypedInputRejections,
		"execution.counters.max_drain_polls_observed": counters.MaxDrainPollsObserved,
	}
}

// crValidateExecutedRun re-derives every counter in the document from the
// verbatim line the exploration printed, so a counter cannot be edited,
// fabricated, or half-refreshed without contradicting the run it cites.
//
// The line's authenticity is the other half of the binding and is proven at
// the run: rust/ws-driver/tests/schedule_exploration.rs formats this same line
// from its own measured totals and compares it byte-for-byte with the string
// recorded here.
func crValidateExecutedRun(results crResults, path string) []ModelFinding {
	var findings []ModelFinding
	run := results.Execution.ExecutedRun
	if run == nil {
		return append(findings, mpFinding("RESULTS_EXECUTED_RUN_ABSENT", path,
			"execution.executed_run is absent: the counters cite no run, so nothing can contradict them"))
	}
	if run.Exit == nil || *run.Exit != 0 {
		findings = append(findings, mpFinding("RESULTS_EXECUTED_RUN_NOT_PASSING", path,
			"execution.executed_run.exit is not 0, so the counters were transcribed from a run that did not pass"))
	}
	if !strings.Contains(run.Command, "schedule_exploration") {
		findings = append(findings, mpFinding("RESULTS_EXECUTED_RUN_NOT_PASSING", path, fmt.Sprintf(
			"execution.executed_run.command %q does not name the schedule_exploration harness", run.Command)))
	}

	fields := map[string]int{}
	tokens := strings.Fields(strings.TrimSpace(run.StdoutLine))
	if len(tokens) == 0 || tokens[0] != "US017_EXPLORATION" {
		return append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path,
			"execution.executed_run.stdout_line is not the US017_EXPLORATION line the exploration prints"))
	}
	for _, token := range tokens[1:] {
		key, value, found := strings.Cut(token, "=")
		if !found {
			return append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path, fmt.Sprintf(
				"execution.executed_run.stdout_line carries the non key=value token %q", token)))
		}
		if key == "truncated" {
			if (value == "true") != results.Execution.Truncated {
				findings = append(findings, mpFinding("RESULTS_COUNTER_CONTRADICTS_RUN", path, fmt.Sprintf(
					"the cited run reports truncated=%s but execution.truncated is %t", value, results.Execution.Truncated)))
			}
			continue
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path, fmt.Sprintf(
				"execution.executed_run.stdout_line field %s carries the non-integer value %q", key, value)))
		}
		fields[key] = parsed
	}

	documented := crDocumentCounters(results)
	names := make([]string, 0, len(crRunFieldToCounter))
	for name := range crRunFieldToCounter {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, runField := range names {
		target := crRunFieldToCounter[runField]
		measured, present := fields[runField]
		if !present {
			findings = append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path, fmt.Sprintf(
				"the cited run line has no %s field, so %s is unbacked", runField, target)))
			continue
		}
		if recorded := documented[target]; recorded != measured {
			findings = append(findings, mpFinding("RESULTS_COUNTER_CONTRADICTS_RUN", path, fmt.Sprintf(
				"%s records %d but the cited run printed %s=%d", target, recorded, runField, measured)))
		}
	}
	return findings
}

// crGitBlobID computes the git object id of a blob without shelling out to
// git: sha1("blob " + len + "\x00" + content). Reading the id straight from
// the bytes keeps the check usable in a plain `go test` with no git process
// and no new dependency.
func crGitBlobID(content []byte) string {
	hasher := sha1.New()
	fmt.Fprintf(hasher, "blob %d", len(content))
	hasher.Write([]byte{0})
	hasher.Write(content)
	return hex.EncodeToString(hasher.Sum(nil))
}

func crSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func crValidateProvenance(results crResults, inputs ConcurrencyResultsInputs) []ModelFinding {
	var findings []ModelFinding
	if inputs.Root == "" {
		return append(findings, mpAdvisory("RESULTS_PROVENANCE_UNVERIFIED", inputs.ResultsPath,
			"no tree root supplied: the recorded source blobs, plan digest and seed digests were NOT checked against the tree"))
	}

	read := func(rel string) ([]byte, *ModelFinding) {
		if rel == "" {
			finding := mpFinding("RESULTS_PROVENANCE_INCOMPLETE", inputs.ResultsPath, "a provenance entry names no path")
			return nil, &finding
		}
		content, err := os.ReadFile(filepath.Join(inputs.Root, filepath.FromSlash(rel)))
		if err != nil {
			finding := mpFinding("RESULTS_PROVENANCE_MISSING", rel, err.Error())
			return nil, &finding
		}
		return content, nil
	}

	// The two git blobs: the driver under exploration and the harness that
	// produced the counters. A drift here means the record describes a run
	// over source the tree no longer holds.
	for label, ref := range map[string]crBlobRef{
		"target.source":  results.Target.Source,
		"target.harness": results.Target.Harness,
	} {
		content, finding := read(ref.Path)
		if finding != nil {
			findings = append(findings, *finding)
			continue
		}
		actual := crGitBlobID(content)
		if actual != ref.GitBlob {
			findings = append(findings, mpFinding("RESULTS_SOURCE_BLOB_STALE", ref.Path, fmt.Sprintf(
				"%s records git_blob %s but the committed file hashes to %s; the exploration counters describe a tree that no longer exists — re-run the exploration and refresh %s",
				label, ref.GitBlob, actual, ConcurrencyResultsDocumentPath)))
		}
	}

	// The preregistered plan. The claim "the exploration stays inside the
	// plan bounds" is only meaningful against a named plan document.
	if content, finding := read(results.PreregisteredPlan.Path); finding != nil {
		findings = append(findings, *finding)
	} else if actual := crSHA256(content); actual != results.PreregisteredPlan.SHA256 {
		findings = append(findings, mpFinding("RESULTS_PLAN_DIGEST_STALE", results.PreregisteredPlan.Path, fmt.Sprintf(
			"preregistered_plan.sha256 records %s but the committed plan hashes to %s; the conformance claim names a document that is not in the tree",
			results.PreregisteredPlan.SHA256, actual)))
	}

	// The pinned minimized seeds and the pinned defect reproduction.
	for _, artifact := range results.Retention.MinimizedArtifacts {
		rel := crMinimizedSeedDir + "/" + artifact.Seed + ".seed"
		content, finding := read(rel)
		if finding != nil {
			findings = append(findings, *finding)
			continue
		}
		if actual := crSHA256(content); actual != artifact.SHA256 {
			findings = append(findings, mpFinding("RESULTS_SEED_DIGEST_STALE", rel, fmt.Sprintf(
				"minimized artifact %s records %s but the pinned seed hashes to %s", artifact.Seed, artifact.SHA256, actual)))
		}
	}
	for _, defect := range results.DefectsFoundFixed {
		if defect.Reproduction == nil {
			continue
		}
		content, finding := read(defect.Reproduction.Path)
		if finding != nil {
			findings = append(findings, *finding)
			continue
		}
		if actual := crSHA256(content); actual != defect.Reproduction.SHA256 {
			findings = append(findings, mpFinding("RESULTS_SEED_DIGEST_STALE", defect.Reproduction.Path, fmt.Sprintf(
				"defect %s records reproduction digest %s but the pinned seed hashes to %s", defect.DefectID, defect.Reproduction.SHA256, actual)))
		}
	}
	return findings
}

func crValidateAccounting(results crResults, path string) []ModelFinding {
	var findings []ModelFinding
	execution := results.Execution
	counters := execution.Counters
	contradiction := func(detail string) {
		findings = append(findings, mpFinding("RESULTS_ACCOUNTING_CONTRADICTION", path, detail))
	}

	// The disposition partition the document asserts in prose and relies on
	// for its whole classification: every schedule is clean-terminal or
	// failure-halted, never both, never neither.
	if sum := execution.ClosedTerminalRuns + execution.FailureHaltedRuns; sum != execution.ExploredSchedules {
		contradiction(fmt.Sprintf("closed_terminal_runs %d + failure_halted_runs %d = %d, but explored_schedules is %d",
			execution.ClosedTerminalRuns, execution.FailureHaltedRuns, sum, execution.ExploredSchedules))
	}
	// Replay determinism means every schedule ran twice.
	if execution.Executions != 2*execution.ExploredSchedules {
		contradiction(fmt.Sprintf("executions %d is not twice explored_schedules %d, yet the document claims every schedule was executed twice for replay equality",
			execution.Executions, execution.ExploredSchedules))
	}
	// Enumeration produced distinct schedules; the exploration asserts it.
	if execution.DistinctScheduleDigests != execution.ExploredSchedules {
		contradiction(fmt.Sprintf("distinct_schedule_digests %d != explored_schedules %d, so the schedules were not distinct",
			execution.DistinctScheduleDigests, execution.ExploredSchedules))
	}
	// Exactly one surfaced failure per halted run.
	if counters.SurfacedTypedFailures != execution.FailureHaltedRuns {
		contradiction(fmt.Sprintf("surfaced_typed_failures %d != failure_halted_runs %d, contradicting the one-failure-per-halt claim",
			counters.SurfacedTypedFailures, execution.FailureHaltedRuns))
	}
	// Outcomes cannot be more numerous than runs.
	if execution.DistinctTraceDigests > execution.ExploredSchedules {
		contradiction(fmt.Sprintf("distinct_semantic_trace_digests %d exceeds explored_schedules %d",
			execution.DistinctTraceDigests, execution.ExploredSchedules))
	}
	// Declared bounds are ceilings, and the conformance claim rests on them.
	if execution.ExploredSchedules > results.Bounds.ScheduleCountMax {
		contradiction(fmt.Sprintf("explored_schedules %d exceeds the declared schedule_count_max %d",
			execution.ExploredSchedules, results.Bounds.ScheduleCountMax))
	}
	if execution.EnumerationBranches > results.Bounds.BranchCountMax {
		contradiction(fmt.Sprintf("enumeration_branches %d exceeds the declared branch_count_max %d",
			execution.EnumerationBranches, results.Bounds.BranchCountMax))
	}
	// The document states this derivation in its own bounds section.
	if want := (results.Bounds.ActorPrograms - 1) + results.Bounds.PreemptionBudget; results.Bounds.ContextSwitchBound != want {
		contradiction(fmt.Sprintf("context_switch_bound %d does not match its stated derivation (actor_programs %d - 1) + preemption_budget %d = %d",
			results.Bounds.ContextSwitchBound, results.Bounds.ActorPrograms, results.Bounds.PreemptionBudget, want))
	}
	// Commands cannot be disposed more often than they were accepted.
	disposed := counters.Applied + counters.TypedRejections + counters.TerminalRejections
	if disposed > counters.AcceptedCommands {
		contradiction(fmt.Sprintf("applied %d + typed_rejections %d + terminal_rejections %d = %d disposed, which exceeds accepted_commands %d",
			counters.Applied, counters.TypedRejections, counters.TerminalRejections, disposed, counters.AcceptedCommands))
	}

	// Coverage honesty: the exploration test asserts each of these was
	// actually reached. A zero here would mean the schedule space never
	// exercised the behaviour the document claims coverage of.
	for name, value := range map[string]int{
		"explored_schedules":      execution.ExploredSchedules,
		"closed_terminal_runs":    execution.ClosedTerminalRuns,
		"failure_halted_runs":     execution.FailureHaltedRuns,
		"accepted_commands":       counters.AcceptedCommands,
		"queue_full_refusals":     counters.QueueFullRefusals,
		"applied":                 counters.Applied,
		"events_drained":          counters.EventsDrained,
		"deferred_output_pending": counters.DeferredOutputPending,
		"deferred_command_turn":   counters.DeferredCommandTurn,
		"deferred_backpressure":   counters.DeferredBackpressure,
		"typed_input_rejections":  counters.TypedInputRejections,
	} {
		if value <= 0 {
			contradiction(fmt.Sprintf("%s is %d: the exploration asserts this behaviour was reached, so a zero here means the record does not describe the run it claims", name, value))
		}
	}

	// A PASS with a truncated or non-exhaustive run would be an inflated claim.
	if results.State == "PASS" {
		if !execution.ExhaustiveWithinBound {
			contradiction("state is PASS but exhaustive_within_bound is false")
		}
		if execution.Truncated {
			contradiction("state is PASS but the run is marked truncated")
		}
		if !strings.Contains(execution.Outcome, "zero invariant violations") {
			contradiction(fmt.Sprintf("state is PASS but execution.outcome does not claim zero invariant violations: %q", execution.Outcome))
		}
	}
	return findings
}

// crQuotedProseFields are the four fields that quote counters back to a
// reader in prose. They are the ones an acceptance reader believes without
// recomputing, and the ones that silently keep the old number when a counter
// is updated. Scanning is deliberately limited to these four: a document-wide
// integer scan would fold in schedule strings, commit ids and dates.
func crQuotedProseFields(results crResults) map[string]string {
	return map[string]string{
		"preregistered_plan.conformance":             results.PreregisteredPlan.Conformance,
		"execution.terminal_disposition_exclusivity": results.Execution.TerminalExclusivity,
		"execution.counters.reconciliation":          results.Execution.Counters.Reconciliation,
		"terminal_disposition_model":                 results.TerminalModel,
	}
}

// crIntegerTokens returns every standalone decimal integer of at least
// minDigits digits — the numbers a reader reads as a counter.
//
// Two exclusions keep it from producing tokens that are not counters:
//   - adjacency to another alphanumeric, so commit prefixes like 76b5350 and
//     hex digests produce nothing;
//   - digit-separator-digit context, so a date or timestamp like
//     2026-08-27T22:04:57Z produces nothing. Only a separator with a digit on
//     its far side counts; a sentence-ending "79920." still yields 79920.
func crIntegerTokens(text string, minDigits int) []int {
	var out []int
	runes := []rune(text)
	isWord := func(r rune) bool {
		return r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
	}
	isDigit := func(index int) bool {
		return index >= 0 && index < len(runes) && runes[index] >= '0' && runes[index] <= '9'
	}
	isSeparator := func(r rune) bool { return r == '-' || r == ':' || r == '/' }
	for i := 0; i < len(runes); {
		if runes[i] < '0' || runes[i] > '9' {
			i++
			continue
		}
		start := i
		for i < len(runes) && runes[i] >= '0' && runes[i] <= '9' {
			i++
		}
		if start > 0 && isWord(runes[start-1]) {
			continue
		}
		if i < len(runes) && isWord(runes[i]) {
			continue
		}
		if start > 0 && isSeparator(runes[start-1]) && isDigit(start-2) {
			continue
		}
		if i < len(runes) && isSeparator(runes[i]) && isDigit(i+1) {
			continue
		}
		if i-start < minDigits {
			continue
		}
		value, err := strconv.Atoi(string(runes[start:i]))
		if err != nil {
			continue
		}
		out = append(out, value)
	}
	return out
}

// crValidateQuotedCounters requires every large number the document quotes
// at a reader to be a number the document actually records, or one of the two
// values its own reconciliation identity derives. This is what turns the
// prose from decoration into a checked claim: update a counter without
// updating the sentence that cites it and this fires.
//
// The threshold is four digits. Below that the prose legitimately carries
// bounds and small cardinalities ("2 producer tasks", "1 owner", "12 actions",
// capacities "2/2/8") that are not counters, and the accounting checks above
// already bind the ones that matter.
func crValidateQuotedCounters(results crResults, path string) []ModelFinding {
	var findings []ModelFinding
	execution := results.Execution
	counters := execution.Counters
	disposed := counters.Applied + counters.TypedRejections + counters.TerminalRejections

	recorded := map[int]bool{}
	for _, value := range []int{
		results.Bounds.ScheduleCountMax, results.Bounds.BranchCountMax, results.Bounds.DrainBudgetPolls,
		execution.ExploredSchedules, execution.EnumerationBranches, execution.DistinctScheduleDigests,
		execution.Executions, execution.DistinctTraceDigests,
		execution.ClosedTerminalRuns, execution.FailureHaltedRuns,
		counters.AcceptedCommands, counters.QueueFullRefusals, counters.Applied,
		counters.TypedRejections, counters.TerminalRejections, counters.EventsDrained,
		counters.SurfacedTypedFailures, counters.DeferredOutputPending, counters.DeferredCommandTurn,
		counters.DeferredBackpressure, counters.TypedInputRejections, counters.MaxDrainPollsObserved,
		// The two values the reconciliation identity derives rather than records.
		disposed, counters.AcceptedCommands - disposed,
	} {
		recorded[value] = true
	}

	fields := crQuotedProseFields(results)
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range crIntegerTokens(fields[name], 4) {
			if !recorded[value] {
				findings = append(findings, mpFinding("RESULTS_PROSE_CONTRADICTS_COUNTERS", path, fmt.Sprintf(
					"%s quotes %d, which is not a counter this document records nor a value its reconciliation identity derives; the prose and the counters disagree",
					name, value)))
			}
		}
	}
	return findings
}
