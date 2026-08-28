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
// WHAT THIS BINDS. Four classes the document cannot otherwise refute:
//
//  1. PROVENANCE, IDENTITY BEFORE DIGEST. The document names the bytes it was
//     measured against — the driver source blob, the exploration harness blob,
//     the preregistered plan digest, the minimized-seed digests — and every
//     one is checked against the committed tree. Each reference must ALSO name
//     the artifact it claims to be: a digest proves the bytes at a path, never
//     that the path is the one that matters. This is the drift the document
//     actually suffered (at dc07516 all three anchors named blobs from commit
//     7ea4780 that the tree no longer contains) and the attack review 01a0487b
//     found (swapping the source and harness references, or redirecting the
//     plan to another file carrying its own digest, both passed).
//
//  2. THE CITED RUN. Every counter and bound is re-derived from
//     execution.executed_run.stdout_line — the verbatim line the exploration
//     prints — including the queue capacities and drain budget, which review
//     01a0487b found were declared bounds tied to nothing.
//
//  3. INTERNAL ACCOUNTING. Every arithmetic identity the document asserts
//     about itself is recomputed, and the run must have stayed inside the
//     ceilings the preregistered plan declares, read from the plan rather than
//     taken from the document's own prose.
//
//  4. QUOTED COUNTERS. Each prose sentence must quote exactly the counters it
//     is about, in order. Membership is not reconciliation: before review
//     01a0487b this accepted any recorded number in any sentence, so the
//     schedule total could stand in for the terminal total.
//
//  5. EVERY OTHER FIELD, AND THE DOCUMENT'S SHAPE ITSELF. Review 01a0487b
//     round 2. Classes 1-4 bound the fields they touched and left their
//     neighbours inert: measured, 102 of this document's 162 JSON leaves
//     produced NO finding when replaced with a different value, because
//     permissive json.Unmarshal silently ignores what the structs do not
//     model. The reviewer's example was
//     execution.producer_admission_fairness_claimed — false to true, DAG
//     re-frozen, both validators exit 0 — but the whole invariants array, the
//     native-stress block, the limitations and the claim-scope fields sat in
//     the same position. So: the invariant table, the weak-fairness
//     assumptions and the producer-admission stance are re-derived from the
//     cited run like the counters; claim ceilings are pinned or cross-checked
//     against the preregistered plan; the named stress suite and every claimed
//     regression test must resolve in the tree; retained counterexamples are
//     compared against the pinned seed CONTENTS, not only their digests; and
//     the shrink records, minimized schedules and program-shape sentence are
//     reconciled against the bounds they describe.
//
//     The document is also decoded with DisallowUnknownFields. That is the
//     durable half: modelling the fields that exist today fixes today's
//     document, but a field nothing models is a field nothing can contradict,
//     so a new one must not be addable in silence. Adding a field here means
//     deciding what makes it load-bearing.
//
//     What remains free is prose with no number, verdict, identity or scope
//     claim in it, plus the six retention found_index ordinals, which the
//     retention run prints but this document does not record. 35 of 162 leaves
//     after the fix, named in the lane receipt rather than implied.
//
// WHERE THE OTHER HALF LIVES, AND HOW THEY ARE MADE TO COMPOSE. This validator
// proves the counters match the cited line; it cannot prove the line came from
// a real run. That is proven at the run: rust/ws-driver/tests/
// schedule_exploration.rs formats the same line from its own measured totals
// and compares it byte-for-byte with the string recorded here.
//
// Two validators only compose if they agree on what they are reading, and the
// first version of this pair did not — one searched raw bytes for an exact
// spelling, the other read the structurally nested field, and a single legal
// JSON document could feed them different values. crRawStdoutLine now runs the
// Rust half's exact algorithm here and asserts it agrees with the structural
// parse, so the agreement is checked rather than assumed.
package formalplan

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
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

// The canonical identities this record must describe.
//
// Review 01a0487b BLOCKING 3: without these the provenance check proved only
// that the bytes at some path matched some digest, never that the path was the
// one that matters — the plane's recurring "right hash of the wrong thing"
// class. Measured before the fix: swapping the source and harness references
// wholesale, and redirecting the plan to assurance/evidence-model.json with
// that file's own digest, both passed at exit 0.
const (
	crCanonicalSourcePath      = "rust/ws-driver/src/lib.rs"
	crCanonicalHarnessPath     = "rust/ws-driver/tests/schedule_exploration.rs"
	crCanonicalPlanPath        = "assurance/concurrency/plan.json"
	crCanonicalTargetSymbol    = "ws_driver::ConnectionDriver::poll"
	crCanonicalReproductionDir = "rust/ws-driver/fuzz-seeds/us017/regressions"
)

// crStdoutLineKey is the bare key token whose single string value binds this
// document to a run. See crRawStdoutLine.
const crStdoutLineKey = `"stdout_line"`

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
	ActorPrograms                int    `json:"actor_programs"`
	ProgramShape                 string `json:"program_shape"`
	ActionsPerSchedule           int    `json:"actions_per_schedule"`
	ContextSwitchBound           int    `json:"context_switch_bound"`
	ContextSwitchBoundDerivation string `json:"context_switch_bound_derivation"`
	PreemptionBudget             int    `json:"preemption_budget"`
	CommandQueue                 int    `json:"command_queue_capacity"`
	WriteQueue                   int    `json:"write_queue_capacity"`
	EventQueue                   int    `json:"event_queue_capacity"`
	ScheduleCountMax             int    `json:"schedule_count_max"`
	BranchCountMax               int    `json:"branch_count_max"`
	DrainBudgetPolls             int    `json:"drain_budget_polls"`
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
	Command         string `json:"command"`
	Exit            *int   `json:"exit"`
	ExitProvenance  string `json:"exit_provenance"`
	ExecutedAt      string `json:"executed_at"`
	ExecutedAgainst string `json:"executed_against"`
	StdoutLine      string `json:"stdout_line"`
	Binding         string `json:"binding"`
}

type crExecution struct {
	ExploredSchedules       int            `json:"explored_schedules"`
	ExhaustiveWithinBound   bool           `json:"exhaustive_within_bound"`
	Truncated               bool           `json:"truncated"`
	EnumerationBranches     int            `json:"enumeration_branches"`
	DistinctScheduleDigests int            `json:"distinct_schedule_digests"`
	Executions              int            `json:"executions"`
	ReplayDeterminism       string         `json:"replay_determinism"`
	DistinctTraceDigests    int            `json:"distinct_semantic_trace_digests"`
	ClosedTerminalRuns      int            `json:"closed_terminal_runs"`
	FailureHaltedRuns       int            `json:"failure_halted_runs"`
	TerminalExclusivity     string         `json:"terminal_disposition_exclusivity"`
	Counters                crCounters     `json:"counters"`
	WeakFairness            []string       `json:"weak_fairness"`
	ProducerAdmissionClaim  bool           `json:"producer_admission_fairness_claimed"`
	ExecutedRun             *crExecutedRun `json:"executed_run"`
	Outcome                 string         `json:"outcome"`
}

// crInvariant is one entry of the document's `invariants` array. Review
// 01a0487b round 2 BLOCKING: the whole array was unmodeled, so its ten PASS
// outcomes were decoration. It is now re-derived from the cited run.
type crInvariant struct {
	PropertyID string `json:"property_id"`
	Outcome    string `json:"outcome"`
}

type crMinimizedArtifact struct {
	Seed       string `json:"seed"`
	Property   string `json:"property"`
	FoundIndex int    `json:"found_index"`
	Shrink     string `json:"shrink"`
	Schedule   string `json:"schedule"`
	SHA256     string `json:"sha256"`
}

type crRetention struct {
	Mechanism          string                `json:"mechanism"`
	RealFailurePath    string                `json:"real_failure_path"`
	Demonstration      string                `json:"demonstration"`
	Regeneration       string                `json:"regeneration"`
	MinimizedArtifacts []crMinimizedArtifact `json:"minimized_artifacts"`
	PinnedUnchanged    string                `json:"pinned_artifacts_unchanged_by_review_round"`
	Outcome            string                `json:"outcome"`
}

type crReproduction struct {
	Path               string `json:"path"`
	SHA256             string `json:"sha256"`
	Schedule           string `json:"schedule"`
	Shrink             string `json:"shrink"`
	EventQueueCapacity int    `json:"event_queue_capacity"`
}

type crDefect struct {
	DefectID        string          `json:"defect_id"`
	FoundBy         string          `json:"found_by"`
	Description     string          `json:"description"`
	Reproduction    *crReproduction `json:"minimized_reproduction"`
	Fix             string          `json:"fix"`
	RegressionTests []string        `json:"regression_tests"`
	RedEvidence     string          `json:"red_evidence"`
	Note            string          `json:"note"`
}

type crNativeStress struct {
	Platform string `json:"platform"`
	Rustc    string `json:"rustc"`
	Target   string `json:"target"`
	Suite    string `json:"suite"`
	Executed string `json:"executed"`
	Outcome  string `json:"outcome"`
}

type crResults struct {
	SchemaVersion        string              `json:"schema_version"`
	EvidenceKind         string              `json:"evidence_kind"`
	StoryID              string              `json:"story_id"`
	State                string              `json:"state"`
	ClaimScope           string              `json:"claim_scope"`
	ClaimScopeStatement  string              `json:"claim_scope_statement"`
	RecordedAt           string              `json:"recorded_at"`
	RecordedAtProvenance string              `json:"recorded_at_provenance"`
	RevisionNote         string              `json:"revision_note"`
	Target               crTarget            `json:"target"`
	PreregisteredPlan    crPreregisteredPlan `json:"preregistered_plan"`
	Bounds               crBounds            `json:"bounds"`
	AdapterModel         string              `json:"adapter_model"`
	Execution            crExecution         `json:"execution"`
	Invariants           []crInvariant       `json:"invariants"`
	TerminalModel        string              `json:"terminal_disposition_model"`
	DefectsFoundFixed    []crDefect          `json:"defects_found_and_fixed"`
	Retention            crRetention         `json:"retention"`
	NativeStress         crNativeStress      `json:"native_stress"`
	Limitations          []string            `json:"limitations"`
	Assurance            string              `json:"assurance"`
	IndependentReview    bool                `json:"independent_review_claimed"`
	Production           bool                `json:"production"`
	Publication          bool                `json:"publication"`
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
	// The composition check reads RAW BYTES and runs before the structural
	// decode, so a decode failure can never mask it. Both refusals are real
	// and each catches what the other cannot: strict decoding refuses a field
	// no validator models, and this refuses a document whose two readers
	// would land on different values.
	rawLine, rawLineErr := crRawStdoutLine(raw)
	if rawLineErr != nil {
		findings = append(findings, mpFinding("RESULTS_RUN_LINE_AMBIGUOUS", inputs.ResultsPath, fmt.Sprintf(
			"the run line cannot be read unambiguously from the raw bytes, so the Rust half of this binding may read a different value: %v", rawLineErr)))
	}

	results, decodeFinding := crDecodeStrictly(raw, inputs.ResultsPath)
	if decodeFinding != nil {
		return append(findings, *decodeFinding)
	}

	findings = append(findings, crValidateProvenance(results, inputs)...)
	findings = append(findings, crValidateExecutedRun(results, rawLine, rawLineErr, inputs.ResultsPath)...)
	findings = append(findings, crValidateAccounting(results, inputs.ResultsPath)...)
	findings = append(findings, crValidateQuotedCounters(results, inputs.ResultsPath)...)
	findings = append(findings, crValidateClaimCeiling(results, inputs.ResultsPath)...)
	findings = append(findings, crValidateNarrative(results, inputs.ResultsPath)...)
	findings = append(findings, crValidateNamedArtifacts(results, inputs)...)
	return findings
}

// crDecodeStrictly decodes the record with DisallowUnknownFields.
//
// WHY STRICT. Review 01a0487b round 2 BLOCKING. Permissive json.Unmarshal
// silently ignores every field the struct does not model, and 108 of this
// document's 162 leaves were exactly that: inert decoration an acceptance
// reader trusts and no validator could contradict. The reviewer's measured
// example was execution.producer_admission_fairness_claimed — flipped from
// false to true, both validators still exited 0 — but the entire invariants
// array, the whole native_stress block, every limitation and every claim-scope
// field were in the same position.
//
// Modelling the fields that exist today fixes today's document. Strict
// decoding is what makes it durable: a NEW field cannot be added to the record
// without being modeled here first, so decoration cannot creep back in one key
// at a time. Every field below therefore has a check somewhere in this file;
// adding a field means deciding what makes it load-bearing.
func crDecodeStrictly(raw []byte, path string) (crResults, *ModelFinding) {
	var results crResults
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&results); err != nil {
		code := "RESULTS_FILE_UNREADABLE"
		detail := err.Error()
		if strings.Contains(detail, "unknown field") {
			code = "RESULTS_UNMODELED_FIELD"
			detail = fmt.Sprintf(
				"%s: an unmodeled field is decoration no validator can contradict. Model it in "+
					"internal/formalplan/concurrencyresults.go and give it a check, or remove it.", detail)
		}
		finding := mpFinding(code, path, detail)
		return results, &finding
	}
	// A second document after the first is not the record.
	if decoder.More() {
		finding := mpFinding("RESULTS_FILE_UNREADABLE", path,
			"trailing content follows the record: the file holds more than one JSON document")
		return results, &finding
	}
	return results, nil
}

// crRawStdoutLine extracts the one stdout_line string from the RAW document
// bytes using the same algorithm as the Rust half
// (rust/ws-driver/tests/schedule_exploration.rs::committed_stdout_line), so
// the two halves can be checked to be reading identical bytes.
//
// WHY A SECOND READER EXISTS IN A FILE THAT ALREADY HAS encoding/json.
// Review 01a0487b BLOCKING 1. The Rust half cannot use encoding/json and, in a
// zero-dependency workspace, cannot get a JSON parser at all — so it reads raw
// bytes. Two validators only compose if they agree on what they are reading.
// The previous version did not: the Rust reader searched for the exact bytes
// `"stdout_line": "` while this file read the structurally nested field, so a
// document carrying an ignored top-level decoy in that exact spelling plus a
// nested `"stdout_line" : "<forgery>"` — legal JSON whitespace — split them.
// Both halves passed on forged counters; measured, both exits 0.
//
// The rule that closes it: the BARE key token must occur exactly once anywhere
// in the document. There is then exactly one such string and every reader must
// land on it, whatever its parsing strategy. crValidateExecutedRun asserts this
// raw result equals the structural parse, so agreement is checked rather than
// assumed.
func crRawStdoutLine(raw []byte) (string, error) {
	document := string(raw)
	if occurrences := strings.Count(document, crStdoutLineKey); occurrences != 1 {
		return "", fmt.Errorf(
			"the document must carry exactly one %s key anywhere in it, found %d; more than one means two readers could land on different values",
			crStdoutLineKey, occurrences)
	}
	rest := document[strings.Index(document, crStdoutLineKey)+len(crStdoutLineKey):]
	rest = strings.TrimLeft(rest, " \t\r\n")
	if !strings.HasPrefix(rest, ":") {
		return "", fmt.Errorf("the %s key is not followed by a colon", crStdoutLineKey)
	}
	rest = strings.TrimLeft(rest[1:], " \t\r\n")
	if !strings.HasPrefix(rest, `"`) {
		return "", fmt.Errorf("the %s value is not a string literal", crStdoutLineKey)
	}
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "", fmt.Errorf("the %s literal is unterminated", crStdoutLineKey)
	}
	value := rest[:end]
	if strings.Contains(value, `\`) {
		return "", fmt.Errorf("the %s value contains a JSON escape, which this reader does not unescape", crStdoutLineKey)
	}
	return value, nil
}

// crRunFieldToCounter maps each key of the exploration's printed line to the
// document field that must carry it. The printed vocabulary and the document
// vocabulary differ (the run says `rejected`, the document says
// `typed_rejections`); writing the mapping out is what makes the rename
// auditable instead of a silent re-label.
var crRunFieldToCounter = map[string]string{
	"programs":             "bounds.actor_programs",
	"actions_total":        "bounds.actions_per_schedule",
	"context_switch_bound": "bounds.context_switch_bound",
	"preemption_budget":    "bounds.preemption_budget",
	// Review 01a0487b BLOCKING 2: these four were declared bounds the document
	// presents as part of the run, tied to neither the measured line nor the
	// plan. Measured before the fix: changing command_queue_capacity from 2 to
	// 7 and editing the small-number prose passed both validators at exit 0.
	// The exploration holds all four as constants, so it now prints them and
	// they are re-derived like every other number.
	"command_queue_capacity":  "bounds.command_queue_capacity",
	"write_queue_capacity":    "bounds.write_queue_capacity",
	"event_queue_capacity":    "bounds.event_queue_capacity",
	"drain_budget_polls":      "bounds.drain_budget_polls",
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

// The run line's non-numeric fields.
//
// Review 01a0487b round 2 BLOCKING. `producer_admission_fairness_claimed` and
// the entire `invariants` array were modeled by neither validator — the Go
// half did not decode them and the Rust half compares only the printed line —
// so flipping the fairness claim from false to true survived both at exit 0
// after a routine DAG refreeze. The exploration now prints all three, so they
// are re-derived from the measured run exactly like the counters are.
const (
	crRunTruncated         = "truncated"
	crRunInvariants        = "invariants"
	crRunWeakFairness      = "weak_fairness"
	crRunProducerAdmission = "producer_admission_fairness"

	// The two spellings the run may print for its producer-admission stance.
	// "absent" is the plan's PRODUCER_ADMISSION_FAIRNESS_ABSENT position.
	crProducerAdmissionAbsent  = "absent"
	crProducerAdmissionClaimed = "claimed"

	// The namespace the record prefixes every invariant property id with.
	crInvariantNamespace = "concurrency."
)

// crRunLineFields is every field the cited run line may carry. A field
// outside this set is refused: the line must contain only values this
// validator re-derives a document claim from.
var crRunLineFields = func() map[string]struct{} {
	fields := map[string]struct{}{
		crRunTruncated:         {},
		crRunInvariants:        {},
		crRunWeakFairness:      {},
		crRunProducerAdmission: {},
	}
	for name := range crRunFieldToCounter {
		fields[name] = struct{}{}
	}
	return fields
}()

// crValidateRunLists re-derives the document's three list-or-stance claims
// from the cited run: the invariant table, the weak-fairness assumptions, and
// the producer-admission stance.
//
// Sequence equality, not membership. The same lesson as BLOCKING 4: accepting
// "the right set in any order" would let close-convergence's PASS stand in for
// failure-halt-exclusivity's, and accepting a subset would let an invariant be
// dropped from the table while the record still reads as ten-for-ten.
func crValidateRunLists(results crResults, raws map[string]string, path string) []ModelFinding {
	var findings []ModelFinding

	if measured, present := raws[crRunInvariants]; !present {
		findings = append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path,
			"the cited run line has no invariants field, so the invariants table is unbacked"))
	} else {
		recorded := make([]string, 0, len(results.Invariants))
		for _, invariant := range results.Invariants {
			recorded = append(recorded, invariant.PropertyID+":"+invariant.Outcome)
		}
		if joined := strings.Join(recorded, ","); joined != measured {
			findings = append(findings, mpFinding("RESULTS_INVARIANTS_CONTRADICT_RUN", path, fmt.Sprintf(
				"the invariants table is not the one the cited run checked.\n  recorded: %s\n  run:      %s",
				joined, measured)))
		}
	}

	if measured, present := raws[crRunWeakFairness]; !present {
		findings = append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path,
			"the cited run line has no weak_fairness field, so execution.weak_fairness is unbacked"))
	} else if joined := strings.Join(results.Execution.WeakFairness, ","); joined != measured {
		findings = append(findings, mpFinding("RESULTS_FAIRNESS_CONTRADICTS_RUN", path, fmt.Sprintf(
			"execution.weak_fairness records the assumptions %q but the cited run applied %q; a fairness "+
				"assumption the run did not make is an unfounded strengthening of the result",
			joined, measured)))
	}

	measured, present := raws[crRunProducerAdmission]
	switch {
	case !present:
		findings = append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path,
			"the cited run line has no producer_admission_fairness field, so "+
				"execution.producer_admission_fairness_claimed is unbacked"))
	case measured != crProducerAdmissionAbsent && measured != crProducerAdmissionClaimed:
		findings = append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path, fmt.Sprintf(
			"the cited run reports producer_admission_fairness=%q, which is neither %q nor %q",
			measured, crProducerAdmissionAbsent, crProducerAdmissionClaimed)))
	case results.Execution.ProducerAdmissionClaim != (measured == crProducerAdmissionClaimed):
		findings = append(findings, mpFinding("RESULTS_FAIRNESS_CONTRADICTS_RUN", path, fmt.Sprintf(
			"execution.producer_admission_fairness_claimed is %t but the cited run reports "+
				"producer_admission_fairness=%s; claiming admission fairness the exploration never assumed "+
				"would strengthen the result over both the port design and the preregistered plan",
			results.Execution.ProducerAdmissionClaim, measured)))
	}
	return findings
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
		"bounds.command_queue_capacity":               results.Bounds.CommandQueue,
		"bounds.write_queue_capacity":                 results.Bounds.WriteQueue,
		"bounds.event_queue_capacity":                 results.Bounds.EventQueue,
		"bounds.drain_budget_polls":                   results.Bounds.DrainBudgetPolls,
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
func crValidateExecutedRun(results crResults, rawLine string, rawLineErr error, path string) []ModelFinding {
	var findings []ModelFinding
	run := results.Execution.ExecutedRun
	if run == nil {
		return append(findings, mpFinding("RESULTS_EXECUTED_RUN_ABSENT", path,
			"execution.executed_run is absent: the counters cite no run, so nothing can contradict them"))
	}

	// The composition check: the bytes the Rust half will read must be the
	// bytes this half is reading. Anything else and the two validators are
	// not one binding, they are two binding different documents. The
	// unreadable case is reported by the caller, which reads the raw bytes
	// before this document is decoded at all.
	if rawLineErr == nil && rawLine != run.StdoutLine {
		findings = append(findings, mpFinding("RESULTS_RUN_LINE_AMBIGUOUS", path, fmt.Sprintf(
			"the raw document yields a different run line than the structurally parsed execution.executed_run.stdout_line, so the two halves of this binding would validate different values.\n  raw:        %s\n  structural: %s",
			rawLine, run.StdoutLine)))
	}
	if run.Exit == nil || *run.Exit != 0 {
		findings = append(findings, mpFinding("RESULTS_EXECUTED_RUN_NOT_PASSING", path,
			"execution.executed_run.exit is not 0, so the counters were transcribed from a run that did not pass"))
	}
	if !strings.Contains(run.Command, "schedule_exploration") {
		findings = append(findings, mpFinding("RESULTS_EXECUTED_RUN_NOT_PASSING", path, fmt.Sprintf(
			"execution.executed_run.command %q does not name the schedule_exploration harness", run.Command)))
	}

	raws := map[string]string{}
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
		// Strictness in both directions, mirroring DisallowUnknownFields on
		// the JSON side: an unrecognised run field is a field this validator
		// does not re-derive anything from, so it must not be silently
		// tolerated in the line the record cites.
		if _, known := crRunLineFields[key]; !known {
			return append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path, fmt.Sprintf(
				"execution.executed_run.stdout_line carries the unrecognised field %q; every field of the "+
					"cited line must be one this validator re-derives a document claim from", key)))
		}
		if _, duplicate := raws[key]; duplicate {
			return append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path, fmt.Sprintf(
				"execution.executed_run.stdout_line carries the field %q twice, so a reader could take either value", key)))
		}
		raws[key] = value
	}

	fields := map[string]int{}
	for key, value := range raws {
		if _, numeric := crRunFieldToCounter[key]; !numeric {
			continue
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path, fmt.Sprintf(
				"execution.executed_run.stdout_line field %s carries the non-integer value %q", key, value)))
		}
		fields[key] = parsed
	}
	if value, present := raws[crRunTruncated]; present {
		if (value == "true") != results.Execution.Truncated {
			findings = append(findings, mpFinding("RESULTS_COUNTER_CONTRADICTS_RUN", path, fmt.Sprintf(
				"the cited run reports truncated=%s but execution.truncated is %t", value, results.Execution.Truncated)))
		}
	} else {
		findings = append(findings, mpFinding("RESULTS_EXECUTED_RUN_UNPARSED", path,
			"the cited run line has no truncated field, so execution.truncated is unbacked"))
	}
	findings = append(findings, crValidateRunLists(results, raws, path)...)

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

	// IDENTITY BEFORE DIGEST. A digest proves the bytes at a path; it proves
	// nothing about the path being the one that matters. Review 01a0487b
	// BLOCKING 3 — the plane's recurring "right hash of the wrong thing"
	// class. Measured before this check existed: swapping the source and
	// harness references wholesale passed at exit 0, and so did redirecting
	// the plan to assurance/evidence-model.json carrying that file's own
	// digest. Each reference must name the artifact it claims to be.
	for label, pair := range map[string][2]string{
		"target.source.path":      {results.Target.Source.Path, crCanonicalSourcePath},
		"target.harness.path":     {results.Target.Harness.Path, crCanonicalHarnessPath},
		"preregistered_plan.path": {results.PreregisteredPlan.Path, crCanonicalPlanPath},
		"target.symbol":           {results.Target.Symbol, crCanonicalTargetSymbol},
	} {
		if pair[0] != pair[1] {
			findings = append(findings, mpFinding("RESULTS_PROVENANCE_MISDIRECTED", inputs.ResultsPath, fmt.Sprintf(
				"%s names %q but this record is only evidence about %q; a matching digest on the wrong artifact is not provenance",
				label, pair[0], pair[1])))
		}
	}
	for _, defect := range results.DefectsFoundFixed {
		if defect.Reproduction == nil {
			continue
		}
		if !strings.HasPrefix(defect.Reproduction.Path, crCanonicalReproductionDir+"/") {
			findings = append(findings, mpFinding("RESULTS_PROVENANCE_MISDIRECTED", inputs.ResultsPath, fmt.Sprintf(
				"defect %s cites a reproduction at %q, outside the pinned regression seed directory %s",
				defect.DefectID, defect.Reproduction.Path, crCanonicalReproductionDir)))
		}
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
	// plan bounds" is only meaningful against a named plan document — and
	// only checkable if the plan is READ rather than merely hashed, which is
	// the second half of the BLOCKING 3 fix.
	if content, finding := read(results.PreregisteredPlan.Path); finding != nil {
		findings = append(findings, *finding)
	} else {
		if actual := crSHA256(content); actual != results.PreregisteredPlan.SHA256 {
			findings = append(findings, mpFinding("RESULTS_PLAN_DIGEST_STALE", results.PreregisteredPlan.Path, fmt.Sprintf(
				"preregistered_plan.sha256 records %s but the committed plan hashes to %s; the conformance claim names a document that is not in the tree",
				results.PreregisteredPlan.SHA256, actual)))
		}
		findings = append(findings, crValidatePlanConformance(results, content, inputs.ResultsPath)...)
	}

	// The pinned minimized seeds and the pinned defect reproduction.
	//
	// The digest proves the record names the bytes that are there. What the
	// seed CONTENTS prove is stronger and was not being used: each seed is
	// re-derived by the Rust retention test from a real minimization run and
	// byte-compared, so the property, the minimized schedule and the queue
	// capacity it carries are measured values. The record restates all three
	// in its own words; before this they were transcriptions nothing checked.
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
		seed := crParseSeed(content)
		findings = append(findings, crCompareToSeed(rel, fmt.Sprintf("minimized artifact %s", artifact.Seed),
			map[string]string{
				"id":                   "minimized-" + artifact.Seed,
				"property":             artifact.Property,
				"schedule":             artifact.Schedule,
				"event_queue_capacity": strconv.Itoa(results.Bounds.EventQueue),
			}, seed)...)
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
		seed := crParseSeed(content)
		findings = append(findings, crCompareToSeed(defect.Reproduction.Path, fmt.Sprintf("defect %s", defect.DefectID),
			map[string]string{
				"id":                   defect.DefectID,
				"schedule":             defect.Reproduction.Schedule,
				"event_queue_capacity": strconv.Itoa(defect.Reproduction.EventQueueCapacity),
			}, seed)...)
	}
	return findings
}

// crParseSeed reads the key=value seed artifact format the exploration writes
// (see render_seed in rust/ws-driver/tests/schedule_exploration.rs).
func crParseSeed(content []byte) map[string]string {
	seed := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found {
			seed[key] = value
		}
	}
	return seed
}

// crCompareToSeed holds the record's restatement of a retained counterexample
// against the counterexample itself.
func crCompareToSeed(path, label string, expected, seed map[string]string) []ModelFinding {
	var findings []ModelFinding
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		actual, present := seed[key]
		if !present {
			findings = append(findings, mpFinding("RESULTS_SEED_CONTENT_CONTRADICTED", path, fmt.Sprintf(
				"%s: the pinned seed carries no %s field, so the record's value for it rests on nothing", label, key)))
			continue
		}
		if actual != expected[key] {
			findings = append(findings, mpFinding("RESULTS_SEED_CONTENT_CONTRADICTED", path, fmt.Sprintf(
				"%s restates %s as %q but the pinned counterexample says %q; the seed is re-derived from a real "+
					"minimization run, so the record is describing a counterexample it does not have",
				label, key, expected[key], actual)))
		}
	}
	return findings
}

// crPlanBounds is the subset of the preregistered plan the results document's
// conformance and claim-ceiling claims actually rest on: its bounds, its
// assurance posture, and its declared fairness stances.
type crPlanBounds struct {
	Bounds struct {
		ProducerTasksMax      int `json:"producer_tasks_max"`
		CommandQueueCapacity  int `json:"command_queue_capacity"`
		WriteQueueCapacity    int `json:"write_queue_capacity"`
		EventQueueCapacity    int `json:"event_queue_capacity"`
		MaxActionsPerSchedule int `json:"max_actions_per_schedule"`
		PreemptionBound       int `json:"preemption_bound"`
		ScheduleCountMax      int `json:"schedule_count_max"`
		BranchCountMax        int `json:"branch_count_max"`
	} `json:"bounds"`
	Assurance struct {
		OwnerAttestation         string `json:"owner_attestation"`
		IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	} `json:"assurance"`
	Fairness []struct {
		FairnessID string `json:"fairness_id"`
		Kind       string `json:"kind"`
	} `json:"fairness"`
}

// crPlanProducerAdmissionID is the plan's declared stance on admission
// ordering among competing producers. Its `kind` is what the results
// document's producer_admission_fairness_claimed must agree with.
const crPlanProducerAdmissionID = "PRODUCER_ADMISSION_FAIRNESS_ABSENT"

// crValidateFairnessAgainstPlan is the cross-artifact half of the fairness
// binding. crValidateRunLists proves the record's stance is the one the
// exploration ran with; this proves it is also the one the preregistered plan
// declared, so the two cannot drift apart silently. Either alone would let a
// stance be strengthened by editing the other side.
func crValidateFairnessAgainstPlan(results crResults, plan crPlanBounds, path string) []ModelFinding {
	var findings []ModelFinding
	declaredAbsent := false
	weakFairnessCount := 0
	for _, entry := range plan.Fairness {
		if entry.Kind == "weak_fairness" {
			weakFairnessCount++
		}
		if entry.FairnessID == crPlanProducerAdmissionID {
			declaredAbsent = entry.Kind == "absent"
		}
	}
	if !declaredAbsent {
		findings = append(findings, mpFinding("RESULTS_FAIRNESS_CONTRADICTS_PLAN", path, fmt.Sprintf(
			"the preregistered plan does not declare %s with kind \"absent\", so this record's "+
				"producer-admission stance rests on nothing", crPlanProducerAdmissionID)))
	} else if results.Execution.ProducerAdmissionClaim {
		findings = append(findings, mpFinding("RESULTS_FAIRNESS_CONTRADICTS_PLAN", path, fmt.Sprintf(
			"execution.producer_admission_fairness_claimed is true but the preregistered plan declares "+
				"%s: the plan's stance is that no producer is guaranteed admission ahead of another, and "+
				"claiming that fairness here would strengthen the result over the plan it cites",
			crPlanProducerAdmissionID)))
	}
	if weakFairnessCount != len(results.Execution.WeakFairness) {
		findings = append(findings, mpFinding("RESULTS_FAIRNESS_CONTRADICTS_PLAN", path, fmt.Sprintf(
			"execution.weak_fairness records %d assumptions but the preregistered plan declares %d entries "+
				"of kind weak_fairness", len(results.Execution.WeakFairness), weakFairnessCount)))
	}
	if plan.Assurance.OwnerAttestation != "" && results.Assurance != plan.Assurance.OwnerAttestation {
		findings = append(findings, mpFinding("RESULTS_CLAIM_CEILING_INFLATED", path, fmt.Sprintf(
			"assurance is %q but the preregistered plan attests %q", results.Assurance, plan.Assurance.OwnerAttestation)))
	}
	if results.IndependentReview != plan.Assurance.IndependentReviewClaimed {
		findings = append(findings, mpFinding("RESULTS_CLAIM_CEILING_INFLATED", path, fmt.Sprintf(
			"independent_review_claimed is %t but the preregistered plan declares %t",
			results.IndependentReview, plan.Assurance.IndependentReviewClaimed)))
	}
	return findings
}

// crValidatePlanConformance turns the conformance SENTENCE into a checked
// claim by comparing the results document's declared bounds against the plan's
// declared ceilings, field by field.
//
// Two review findings meet here. BLOCKING 2: the queue capacities and the
// drain budget were bounds nothing constrained, so a capacity could be edited
// freely. BLOCKING 3: hashing the plan proved bytes, not that the document at
// that path was a concurrency plan at all — a redirected path with a matching
// digest passed. Requiring the named document to parse as a plan and to carry
// ceilings this run fits inside closes both from the plan side, while
// crRunFieldToCounter closes the capacities from the measured-run side.
func crValidatePlanConformance(results crResults, planContent []byte, path string) []ModelFinding {
	var findings []ModelFinding
	var plan crPlanBounds
	if err := json.Unmarshal(planContent, &plan); err != nil {
		return append(findings, mpFinding("RESULTS_PLAN_NOT_CONFORMABLE", path, fmt.Sprintf(
			"the preregistered plan does not parse as a concurrency plan, so the conformance claim cannot be checked: %v", err)))
	}
	if plan.Bounds.ScheduleCountMax == 0 && plan.Bounds.BranchCountMax == 0 && plan.Bounds.MaxActionsPerSchedule == 0 {
		return append(findings, mpFinding("RESULTS_PLAN_NOT_CONFORMABLE", path,
			"the preregistered plan declares no bounds section, so it is not the concurrency plan this record claims conformance to"))
	}
	ceiling := func(name string, actual, max int) {
		if actual > max {
			findings = append(findings, mpFinding("RESULTS_PLAN_CONFORMANCE_VIOLATED", path, fmt.Sprintf(
				"bounds.%s is %d but the preregistered plan caps it at %d, so the run did not stay inside the plan it cites",
				name, actual, max)))
		}
	}
	ceiling("actor_programs", results.Bounds.ActorPrograms, plan.Bounds.ProducerTasksMax+2)
	ceiling("command_queue_capacity", results.Bounds.CommandQueue, plan.Bounds.CommandQueueCapacity)
	ceiling("write_queue_capacity", results.Bounds.WriteQueue, plan.Bounds.WriteQueueCapacity)
	ceiling("event_queue_capacity", results.Bounds.EventQueue, plan.Bounds.EventQueueCapacity)
	ceiling("actions_per_schedule", results.Bounds.ActionsPerSchedule, plan.Bounds.MaxActionsPerSchedule)
	if results.Bounds.PreemptionBudget != plan.Bounds.PreemptionBound {
		findings = append(findings, mpFinding("RESULTS_PLAN_CONFORMANCE_VIOLATED", path, fmt.Sprintf(
			"bounds.preemption_budget is %d but the plan's preemption_bound is %d, and the conformance sentence claims they are equal",
			results.Bounds.PreemptionBudget, plan.Bounds.PreemptionBound)))
	}
	for _, pair := range []struct {
		name           string
		actual, wanted int
	}{
		{"schedule_count_max", results.Bounds.ScheduleCountMax, plan.Bounds.ScheduleCountMax},
		{"branch_count_max", results.Bounds.BranchCountMax, plan.Bounds.BranchCountMax},
	} {
		if pair.actual != pair.wanted {
			findings = append(findings, mpFinding("RESULTS_PLAN_CONFORMANCE_VIOLATED", path, fmt.Sprintf(
				"bounds.%s is %d but the preregistered plan declares %d", pair.name, pair.actual, pair.wanted)))
		}
	}
	for _, defect := range results.DefectsFoundFixed {
		if defect.Reproduction == nil {
			continue
		}
		if defect.Reproduction.EventQueueCapacity > plan.Bounds.EventQueueCapacity {
			findings = append(findings, mpFinding("RESULTS_PLAN_CONFORMANCE_VIOLATED", path, fmt.Sprintf(
				"defect %s reproduces at event_queue_capacity %d but the preregistered plan caps it at %d",
				defect.DefectID, defect.Reproduction.EventQueueCapacity, plan.Bounds.EventQueueCapacity)))
		}
	}
	findings = append(findings, crValidateFairnessAgainstPlan(results, plan, path)...)
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

// crValidateQuotedCounters requires each prose sentence that quotes counters
// at a reader to quote EXACTLY the counters that sentence is about, in order.
//
// Review 01a0487b BLOCKING 4 replaced what this used to be. The previous
// version checked global membership — any recorded number was accepted in any
// checked sentence — so substituting the schedule total 79920 for the terminal
// total 52924 in the exclusivity sentence passed at exit 0, measured. Global
// membership is not reconciliation; it only catches a number that appears
// nowhere in the document, which is the least likely half-refresh.
//
// Each sentence now declares the exact ordered sequence of counters it is
// required to quote, derived from the fields. A wrong-but-recorded number, a
// dropped number, an extra number and a reordering all fail.
//
// The threshold is four digits. Below that the prose legitimately carries
// bounds and small cardinalities ("2 producer tasks", "1 owner", "12 actions")
// that are not counters; those are bound instead by crRunFieldToCounter, which
// re-derives every one of them from the measured run.
func crValidateQuotedCounters(results crResults, path string) []ModelFinding {
	var findings []ModelFinding
	execution := results.Execution
	counters := execution.Counters
	disposed := counters.Applied + counters.TypedRejections + counters.TerminalRejections

	// Each entry: the field, and the counters that sentence must quote, in the
	// order it quotes them. Keeping the expected sequence next to the sentence
	// is what makes this reconciliation rather than membership.
	expectations := []struct {
		name     string
		text     string
		expected []int
	}{
		{
			// "... 79920 schedules (<= schedule_count_max 100000), 315070
			//  enumeration branches (<= branch_count_max 1000000)"
			name: "preregistered_plan.conformance",
			text: results.PreregisteredPlan.Conformance,
			expected: []int{
				execution.ExploredSchedules, results.Bounds.ScheduleCountMax,
				execution.EnumerationBranches, results.Bounds.BranchCountMax,
			},
		},
		{
			// "terminals total 52924 == closed_terminal_runs ...; surfaced
			//  failures total 26996 == failure_halted_runs ...; 52924 + 26996
			//  == 79920"
			name: "execution.terminal_disposition_exclusivity",
			text: execution.TerminalExclusivity,
			expected: []int{
				execution.ClosedTerminalRuns, execution.FailureHaltedRuns,
				execution.ClosedTerminalRuns, execution.FailureHaltedRuns,
				execution.ExploredSchedules,
			},
		},
		{
			// "aggregate disposed 206204 of 221353 accepted; the 15149
			//  remainder ..." — the two derived values and the recorded one.
			name: "execution.counters.reconciliation",
			text: counters.Reconciliation,
			expected: []int{
				disposed, counters.AcceptedCommands, counters.AcceptedCommands - disposed,
			},
		},
		{
			// "... (52924 runs, exactly one Terminal each ...), or the halt at
			//  the first surfaced fatal Failure (26996 runs, ...)"
			name:     "terminal_disposition_model",
			text:     results.TerminalModel,
			expected: []int{execution.ClosedTerminalRuns, execution.FailureHaltedRuns},
		},
		{
			// BLOCKING 4 also noted this field was omitted entirely, and it
			// independently quotes the schedule count:
			// "PASS - zero invariant violations across all 79920 schedules"
			name:     "execution.outcome",
			text:     execution.Outcome,
			expected: []int{execution.ExploredSchedules},
		},
	}

	for _, expectation := range expectations {
		quoted := crIntegerTokens(expectation.text, 4)
		if len(quoted) != len(expectation.expected) {
			findings = append(findings, mpFinding("RESULTS_PROSE_CONTRADICTS_COUNTERS", path, fmt.Sprintf(
				"%s quotes %d counters %v but must quote exactly %d %v; the sentence and the counters disagree",
				expectation.name, len(quoted), quoted, len(expectation.expected), expectation.expected)))
			continue
		}
		for index, value := range quoted {
			if value != expectation.expected[index] {
				findings = append(findings, mpFinding("RESULTS_PROSE_CONTRADICTS_COUNTERS", path, fmt.Sprintf(
					"%s quotes %d at position %d where the counters require %d; a number that is recorded elsewhere in the document is still the wrong number here",
					expectation.name, value, index+1, expectation.expected[index])))
			}
		}
	}
	return findings
}

// The claim ceilings this record is not allowed to exceed. Each is a value an
// edit could inflate silently before strict decoding modeled it: a renamed
// evidence_kind lets the record masquerade as a different artifact, a state
// outside the closed vocabulary skips the PASS block below entirely (a
// measured hole: "PASS CORRUPTED" produced no finding at all), and
// production/publication/independent_review turn an owner-attested bounded
// result into a claim nobody made.
const (
	crRequiredSchemaVersion = "1.0.0"
	crRequiredEvidenceKind  = "US017_DRIVER_BOUNDED_SCHEDULE_AND_NATIVE_STRESS_RESULTS"
	crRequiredStoryID       = "US-017"
	crStatePass             = "PASS"
	crStateFail             = "FAIL"
	crInvariantPass         = "PASS"
	crInvariantFail         = "FAIL"

	// The native-thread stress ran on one host. Its outcome label carries
	// that scope, and widening the label is the cheapest possible inflation
	// of a two-platform claim the story explicitly leaves open.
	crRequiredNativeStressOutcome = "PASS_CURRENT_HOST_ONLY"

	// The bounded scope this record is written under, and the retention
	// verdict. Both are labels an acceptance reader takes at face value.
	crRequiredClaimScope       = "BOUNDED_SYSTEMATIC_AND_CURRENT_HOST_STRESS_TESTING"
	crRequiredRetentionOutcome = "PASS_ALL_NAMED_FAULTS_KILLED_AND_MINIMIZED"
)

// crValidateClaimCeiling refuses a record that claims more assurance than it
// has. Review 01a0487b round 2 BLOCKING: every field below was unmodeled, so
// each was decoration — measured, corrupting any one of them produced no
// finding from either validator.
func crValidateClaimCeiling(results crResults, path string) []ModelFinding {
	var findings []ModelFinding
	inflated := func(detail string) {
		findings = append(findings, mpFinding("RESULTS_CLAIM_CEILING_INFLATED", path, detail))
	}

	for _, pinned := range []struct{ field, actual, required string }{
		{"schema_version", results.SchemaVersion, crRequiredSchemaVersion},
		{"evidence_kind", results.EvidenceKind, crRequiredEvidenceKind},
		{"story_id", results.StoryID, crRequiredStoryID},
		{"claim_scope", results.ClaimScope, crRequiredClaimScope},
		{"retention.outcome", results.Retention.Outcome, crRequiredRetentionOutcome},
	} {
		if pinned.actual != pinned.required {
			inflated(fmt.Sprintf("%s is %q but this record is only evidence of kind %q",
				pinned.field, pinned.actual, pinned.required))
		}
	}

	// The state vocabulary is closed, and the state is DERIVED: the record
	// passes exactly when every invariant it lists passed.
	if results.State != crStatePass && results.State != crStateFail {
		inflated(fmt.Sprintf(
			"state is %q, which is neither %q nor %q; a state outside the vocabulary silently skips every "+
				"check conditioned on PASS", results.State, crStatePass, crStateFail))
	}
	if len(results.Invariants) == 0 {
		inflated("the record lists no invariants, so its state rests on nothing")
	}
	allPassed := true
	for _, invariant := range results.Invariants {
		if invariant.Outcome != crInvariantPass && invariant.Outcome != crInvariantFail {
			inflated(fmt.Sprintf("invariant %s records outcome %q, which is neither %q nor %q",
				invariant.PropertyID, invariant.Outcome, crInvariantPass, crInvariantFail))
		}
		if !strings.HasPrefix(invariant.PropertyID, crInvariantNamespace) {
			inflated(fmt.Sprintf("invariant property id %q is outside the %q namespace this record's "+
				"invariants live in", invariant.PropertyID, crInvariantNamespace))
		}
		if invariant.Outcome != crInvariantPass {
			allPassed = false
		}
	}
	if len(results.Invariants) > 0 && (results.State == crStatePass) != allPassed {
		inflated(fmt.Sprintf(
			"state is %q but %d of the %d listed invariants passed; the state must be derived from the "+
				"invariant table, not asserted alongside it",
			results.State, crCountPassing(results.Invariants), len(results.Invariants)))
	}

	// An owner-attested bounded record cannot also be a production or
	// publication claim.
	if results.Production {
		inflated("production is true, but this record is bounded owner-attested evidence and no reviewed production claim exists for it")
	}
	if results.Publication {
		inflated("publication is true, but this record is bounded owner-attested evidence and no reviewed publication claim exists for it")
	}
	if results.IndependentReview && strings.Contains(results.Assurance, "NOT_INDEPENDENT") {
		inflated(fmt.Sprintf("independent_review_claimed is true but assurance is %q", results.Assurance))
	}

	// The claim ceiling must name the document that sets it. A claim-scope
	// statement that cites no plan is a ceiling nobody can check.
	if !strings.Contains(results.ClaimScopeStatement, crCanonicalPlanPath) {
		inflated(fmt.Sprintf(
			"claim_scope_statement does not cite %s, so the ceiling it describes is not anchored to the "+
				"preregistered plan", crCanonicalPlanPath))
	}

	if results.NativeStress.Outcome != crRequiredNativeStressOutcome {
		inflated(fmt.Sprintf(
			"native_stress.outcome is %q but the stress suite ran on one host only and must say so (%q)",
			results.NativeStress.Outcome, crRequiredNativeStressOutcome))
	}
	// The platform, the target triple and the limitation that discloses the
	// single-host scope all describe the SAME host. Any one of them could be
	// rewritten alone before this.
	platform := strings.ToLower(strings.TrimSpace(strings.Split(results.NativeStress.Platform, "(")[0]))
	triple := strings.ToLower(results.NativeStress.Target)
	for _, word := range strings.Fields(platform) {
		normalized := word
		if normalized == "arm64" {
			normalized = "aarch64"
		}
		if !strings.Contains(triple, normalized) {
			inflated(fmt.Sprintf(
				"native_stress.target %q does not name the %q the platform records; the triple and the platform "+
					"must describe the same host", results.NativeStress.Target, word))
		}
	}
	if platform != "" {
		disclosed := false
		for _, limitation := range results.Limitations {
			if strings.Contains(strings.ToLower(limitation), platform) {
				disclosed = true
				break
			}
		}
		if !disclosed {
			inflated(fmt.Sprintf(
				"no limitation discloses that the native-thread stress ran on %q only, though native_stress "+
					"records exactly that platform", strings.TrimSpace(platform)))
		}
	}
	return findings
}

func crCountPassing(invariants []crInvariant) int {
	passing := 0
	for _, invariant := range invariants {
		if invariant.Outcome == crInvariantPass {
			passing++
		}
	}
	return passing
}

// crShrinkPattern reads the "<from> -> <to>" shrink record every minimized
// artifact and defect reproduction carries.
var crShrinkPattern = regexp.MustCompile(`([0-9]+)\s*->\s*([0-9]+)`)

// crValidateNarrative turns the record's descriptive fields from free text
// into claims with something behind them.
//
// Not every sentence can be re-derived from a run, and pretending otherwise
// would be the same mistake in the other direction. What every one of them CAN
// be held to is: present, and — where the sentence states a structure the
// record also states numerically — consistent with that number. The
// program-shape sentence, the shrink records and the minimized schedules all
// enumerate things the bounds and the invariant table already count.
func crValidateNarrative(results crResults, path string) []ModelFinding {
	var findings []ModelFinding
	contradiction := func(detail string) {
		findings = append(findings, mpFinding("RESULTS_ACCOUNTING_CONTRADICTION", path, detail))
	}
	empty := func(field string) {
		findings = append(findings, mpFinding("RESULTS_DESCRIPTION_ABSENT", path, fmt.Sprintf(
			"%s is empty: the record states this claim to a reader and must not leave it blank", field)))
	}

	for _, described := range []struct{ field, text string }{
		{"claim_scope", results.ClaimScope},
		{"claim_scope_statement", results.ClaimScopeStatement},
		{"recorded_at_provenance", results.RecordedAtProvenance},
		{"revision_note", results.RevisionNote},
		{"adapter_model", results.AdapterModel},
		{"assurance", results.Assurance},
		{"bounds.program_shape", results.Bounds.ProgramShape},
		{"bounds.context_switch_bound_derivation", results.Bounds.ContextSwitchBoundDerivation},
		{"preregistered_plan.conformance", results.PreregisteredPlan.Conformance},
		{"execution.replay_determinism", results.Execution.ReplayDeterminism},
		{"execution.terminal_disposition_exclusivity", results.Execution.TerminalExclusivity},
		{"execution.counters.reconciliation", results.Execution.Counters.Reconciliation},
		{"execution.outcome", results.Execution.Outcome},
		{"terminal_disposition_model", results.TerminalModel},
		{"retention.mechanism", results.Retention.Mechanism},
		{"retention.real_failure_path", results.Retention.RealFailurePath},
		{"retention.demonstration", results.Retention.Demonstration},
		{"retention.regeneration", results.Retention.Regeneration},
		{"retention.pinned_artifacts_unchanged_by_review_round", results.Retention.PinnedUnchanged},
		{"retention.outcome", results.Retention.Outcome},
		{"native_stress.platform", results.NativeStress.Platform},
		{"native_stress.rustc", results.NativeStress.Rustc},
		{"native_stress.target", results.NativeStress.Target},
		{"native_stress.suite", results.NativeStress.Suite},
		{"native_stress.executed", results.NativeStress.Executed},
	} {
		if strings.TrimSpace(described.text) == "" {
			empty(described.field)
		}
	}
	if run := results.Execution.ExecutedRun; run != nil {
		for _, described := range []struct{ field, text string }{
			{"execution.executed_run.exit_provenance", run.ExitProvenance},
			{"execution.executed_run.executed_against", run.ExecutedAgainst},
			{"execution.executed_run.binding", run.Binding},
		} {
			if strings.TrimSpace(described.text) == "" {
				empty(described.field)
			}
		}
		if _, err := time.Parse(time.RFC3339, run.ExecutedAt); err != nil || !strings.HasSuffix(run.ExecutedAt, "Z") {
			findings = append(findings, mpFinding("RESULTS_TIMESTAMP_MALFORMED", path, fmt.Sprintf(
				"execution.executed_run.executed_at %q is not a UTC RFC3339 instant", run.ExecutedAt)))
		}
	}
	if _, err := time.Parse(time.RFC3339, results.RecordedAt); err != nil || !strings.HasSuffix(results.RecordedAt, "Z") {
		findings = append(findings, mpFinding("RESULTS_TIMESTAMP_MALFORMED", path, fmt.Sprintf(
			"recorded_at %q is not a UTC RFC3339 instant", results.RecordedAt)))
	}
	if len(results.Limitations) == 0 {
		empty("limitations")
	}
	for index, limitation := range results.Limitations {
		if strings.TrimSpace(limitation) == "" {
			empty(fmt.Sprintf("limitations[%d]", index))
		}
	}

	// The program-shape sentence enumerates the actor programs and their
	// actions; bounds.actor_programs and bounds.actions_per_schedule count
	// the same two things, and both are re-derived from the cited run.
	programs, actions := crProgramShapeShape(results.Bounds.ProgramShape)
	if programs != results.Bounds.ActorPrograms {
		contradiction(fmt.Sprintf(
			"bounds.program_shape describes %d actor programs but bounds.actor_programs is %d",
			programs, results.Bounds.ActorPrograms))
	}
	if actions != results.Bounds.ActionsPerSchedule {
		contradiction(fmt.Sprintf(
			"bounds.program_shape lists %d actions across its programs but bounds.actions_per_schedule is %d",
			actions, results.Bounds.ActionsPerSchedule))
	}

	// Every minimized artifact names an invariant the record actually lists,
	// shrinks from the full schedule length, and carries a schedule whose
	// length is the one the shrink claims.
	invariants := map[string]struct{}{}
	for _, invariant := range results.Invariants {
		invariants[strings.TrimPrefix(invariant.PropertyID, crInvariantNamespace)] = struct{}{}
	}
	seen := map[string]struct{}{}
	for _, artifact := range results.Retention.MinimizedArtifacts {
		if _, listed := invariants[artifact.Property]; !listed {
			contradiction(fmt.Sprintf(
				"minimized artifact %s is retained for property %q, which is not one of the invariants this "+
					"record checks", artifact.Seed, artifact.Property))
		}
		if _, duplicate := seen[artifact.Seed]; duplicate {
			contradiction(fmt.Sprintf("minimized artifact %s is listed twice", artifact.Seed))
		}
		seen[artifact.Seed] = struct{}{}
		if artifact.FoundIndex < 0 {
			contradiction(fmt.Sprintf("minimized artifact %s records a negative found_index", artifact.Seed))
		}
		findings = append(findings, crValidateShrink(
			fmt.Sprintf("minimized artifact %s", artifact.Seed),
			artifact.Shrink, artifact.Schedule, results.Bounds.ActionsPerSchedule, path)...)
	}

	defects := map[string]struct{}{}
	if len(results.DefectsFoundFixed) == 0 {
		empty("defects_found_and_fixed")
	}
	for _, defect := range results.DefectsFoundFixed {
		for _, described := range []struct{ field, text string }{
			{"defect_id", defect.DefectID},
			{"found_by", defect.FoundBy},
			{"description", defect.Description},
			{"fix", defect.Fix},
		} {
			if strings.TrimSpace(described.text) == "" {
				empty(fmt.Sprintf("defects_found_and_fixed[%s].%s", defect.DefectID, described.field))
			}
		}
		if _, duplicate := defects[defect.DefectID]; duplicate {
			contradiction(fmt.Sprintf("defect id %q is recorded twice", defect.DefectID))
		}
		defects[defect.DefectID] = struct{}{}
		if defect.Reproduction != nil {
			findings = append(findings, crValidateShrink(
				fmt.Sprintf("defect %s", defect.DefectID),
				defect.Reproduction.Shrink, defect.Reproduction.Schedule,
				results.Bounds.ActionsPerSchedule, path)...)
			if strings.TrimSpace(defect.RedEvidence) == "" {
				empty(fmt.Sprintf("defects_found_and_fixed[%s].red_evidence", defect.DefectID))
			}
			if len(defect.RegressionTests) == 0 {
				empty(fmt.Sprintf("defects_found_and_fixed[%s].regression_tests", defect.DefectID))
			}
		}
	}
	return findings
}

// crValidateShrink checks a "<from> -> <to>" record against the schedule it
// describes: shrinking starts from a full schedule, ends no longer than it
// started, and the minimized schedule really carries that many actions. A
// shrink claim nothing counts is the same decoration class as an invariant
// table nothing derives.
func crValidateShrink(label, shrink, schedule string, fullLength int, path string) []ModelFinding {
	var findings []ModelFinding
	contradiction := func(detail string) {
		findings = append(findings, mpFinding("RESULTS_ACCOUNTING_CONTRADICTION", path, detail))
	}
	match := crShrinkPattern.FindStringSubmatch(shrink)
	if match == nil {
		contradiction(fmt.Sprintf("%s records the shrink %q, which does not state a <from> -> <to> length", label, shrink))
		return findings
	}
	from, _ := strconv.Atoi(match[1])
	to, _ := strconv.Atoi(match[2])
	if from != fullLength {
		contradiction(fmt.Sprintf(
			"%s shrinks from %d actions but every schedule in this exploration is %d actions long",
			label, from, fullLength))
	}
	if to < 1 || to > from {
		contradiction(fmt.Sprintf("%s shrinks %d -> %d, which is not a shrink to a non-empty schedule", label, from, to))
	}
	actions := 0
	for _, action := range strings.Split(schedule, ",") {
		if strings.TrimSpace(action) != "" {
			actions++
		}
	}
	if actions != to {
		contradiction(fmt.Sprintf(
			"%s claims a %d-action minimized schedule but records %d actions (%q)", label, to, actions, schedule))
	}
	return findings
}

// crProgramShapeShape counts the actor programs and the total actions the
// program-shape sentence enumerates. Programs are separated by ";" and each
// names its actions inside brackets.
func crProgramShapeShape(shape string) (programs, actions int) {
	for _, segment := range strings.Split(shape, ";") {
		if strings.TrimSpace(segment) == "" {
			continue
		}
		programs++
		open := strings.Index(segment, "[")
		closed := strings.LastIndex(segment, "]")
		if open < 0 || closed < open {
			continue
		}
		for _, action := range strings.Split(segment[open+1:closed], ",") {
			if strings.TrimSpace(action) != "" {
				actions++
			}
		}
	}
	return programs, actions
}

// crValidateNamedArtifacts resolves the files this record names in prose but
// never pinned by digest: the native stress suite, and the regression tests
// each fixed defect claims now cover it.
//
// A record can claim a regression test exists; before this it did not have to
// be true. The named test file must exist in the tree AND carry the named test
// function, which is the difference between "a path that resolves" and "the
// test that was claimed".
func crValidateNamedArtifacts(results crResults, inputs ConcurrencyResultsInputs) []ModelFinding {
	var findings []ModelFinding
	if inputs.Root == "" {
		return append(findings, mpAdvisory("RESULTS_NAMED_ARTIFACT_UNVERIFIED", inputs.ResultsPath,
			"no tree root supplied: the named stress suite and regression tests were NOT resolved against the tree"))
	}
	missing := func(detail string) {
		findings = append(findings, mpFinding("RESULTS_NAMED_ARTIFACT_MISSING", inputs.ResultsPath, detail))
	}
	read := func(rel string) ([]byte, bool) {
		content, err := os.ReadFile(filepath.Join(inputs.Root, filepath.FromSlash(rel)))
		return content, err == nil
	}

	// native_stress.suite opens with the repository-relative path of the
	// suite it describes.
	if fields := strings.Fields(results.NativeStress.Suite); len(fields) > 0 {
		suite := strings.TrimSuffix(fields[0], ":")
		if _, ok := read(suite); !ok {
			missing(fmt.Sprintf(
				"native_stress.suite names %q, which is not in the tree: the stress result describes a suite "+
					"that does not exist here", suite))
		}
	}

	for _, defect := range results.DefectsFoundFixed {
		for _, reference := range defect.RegressionTests {
			file, name, found := strings.Cut(reference, "::")
			if !found {
				missing(fmt.Sprintf(
					"defect %s names the regression test %q, which does not spell out <file>::<test>",
					defect.DefectID, reference))
				continue
			}
			content, ok := read(file)
			if !ok {
				missing(fmt.Sprintf(
					"defect %s claims regression coverage in %q, which is not in the tree",
					defect.DefectID, file))
				continue
			}
			if !strings.Contains(string(content), name) {
				missing(fmt.Sprintf(
					"defect %s claims regression coverage by %s in %s, but that file carries no such test; "+
						"a claimed regression test that does not exist is the fix asserting its own coverage",
					defect.DefectID, name, file))
			}
		}
	}

	// The pinned minimized corpus and the record must agree on WHICH faults
	// were retained. A dropped entry would quietly shrink the demonstrated
	// fault set while the record still reads as complete.
	entries, err := os.ReadDir(filepath.Join(inputs.Root, filepath.FromSlash(crMinimizedSeedDir)))
	if err != nil {
		missing(fmt.Sprintf("the pinned minimized seed directory %s is unreadable: %v", crMinimizedSeedDir, err))
		return findings
	}
	pinned := map[string]struct{}{}
	for _, entry := range entries {
		if name := entry.Name(); strings.HasSuffix(name, ".seed") {
			pinned[strings.TrimSuffix(name, ".seed")] = struct{}{}
		}
	}
	recorded := map[string]struct{}{}
	for _, artifact := range results.Retention.MinimizedArtifacts {
		recorded[artifact.Seed] = struct{}{}
	}
	for seed := range pinned {
		if _, listed := recorded[seed]; !listed {
			missing(fmt.Sprintf(
				"%s/%s.seed is pinned in the tree but retention.minimized_artifacts does not record it, so the "+
					"record understates the retained fault set", crMinimizedSeedDir, seed))
		}
	}
	return findings
}
