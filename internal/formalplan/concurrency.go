// Lane B (US-006): validator for assurance/concurrency/plan.json. Schema
// validation (Draft 2020-12) plus semantic rules: full 33-seam census with
// resolvable quarantined-Java citations, required action and race families,
// single-owner bounds, declared producer-fairness absence, seeded defects
// bound to the connection model's checked properties, and a reality-checked
// binding to the behavior-delta ledger.
package formalplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ConcurrencyPlanInputs names every artifact the plan validator reads.
// QuarantineJavaRoot points at the quarantined org/java_websocket package
// root; when empty or absent, citation resolution degrades to an advisory
// finding instead of a silent pass.
type ConcurrencyPlanInputs struct {
	PlanPath           string
	SchemaPath         string
	TLAPath            string
	CfgPath            string
	LedgerPath         string
	QuarantineJavaRoot string
}

// cpExpectedSeamIDs is the complete census: 8 lock/monitor seams, 1 volatile,
// 7 plain shared fields, 5 queues, 3 atomics, 2 latches, 7 thread boundaries.
var cpExpectedSeamIDs = []string{
	"L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8",
	"V1",
	"R1", "R2", "R3", "R4", "R5", "R6", "R7",
	"Q1", "Q2", "Q3", "Q4", "Q5",
	"A1", "A2", "A3",
	"C1", "C2",
	"T1", "T2", "T3", "T4", "T5", "T6", "T7",
}

var cpRequiredActionIDs = []string{
	"action.command_enqueue.send_text",
	"action.command_enqueue.send_binary",
	"action.command_enqueue.ping",
	"action.command_enqueue.close",
	"action.inbound_frame",
	"action.inbound_close",
	"action.inbound_eof",
	"action.outbound_flush",
	"action.shutdown",
	"action.callback_delivery",
	"action.backpressure_reject",
}

var cpRequiredRaceIDs = []string{
	"race.send_vs_close",
	"race.reset_vs_decode",
	"race.timer_vs_worker",
}

type cpAssurance struct {
	Label                    string `json:"label"`
	ClaimScope               string `json:"claim_scope"`
	ClaimScopeStatement      string `json:"claim_scope_statement"`
	OwnerAttestation         string `json:"owner_attestation"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
}

type cpUS005Evidence struct {
	Path                   string `json:"path"`
	Status                 string `json:"status"`
	CloseCodeMutantSummary string `json:"close_code_mutant_summary"`
}

type cpProvenance struct {
	PinnedJavaCommit string          `json:"pinned_java_commit"`
	QuarantineTree   string          `json:"quarantine_tree"`
	JavaPackageRoot  string          `json:"java_package_root"`
	CensusMethod     string          `json:"census_method"`
	US005Calibration cpUS005Evidence `json:"us005_calibration"`
	RelatedModel     string          `json:"related_model"`
}

type cpSeam struct {
	SeamID         string   `json:"seam_id"`
	Kind           string   `json:"kind"`
	Name           string   `json:"name"`
	Citations      []string `json:"citations"`
	Classification string   `json:"classification"`
	Note           string   `json:"note"`
	RustMapping    string   `json:"rust_mapping"`
}

type cpCensus struct {
	Total       int      `json:"total"`
	InPortScope int      `json:"in_port_scope"`
	Seams       []cpSeam `json:"seams"`
}

type cpAction struct {
	ActionID                  string   `json:"action_id"`
	Actor                     string   `json:"actor"`
	JavaSeams                 []string `json:"java_seams"`
	JavaCitations             []string `json:"java_citations"`
	Preconditions             []string `json:"preconditions"`
	Effects                   []string `json:"effects"`
	ObservableOutcomes        []string `json:"observable_outcomes"`
	MaxOccurrencesPerSchedule int      `json:"max_occurrences_per_schedule"`
}

type cpBounds struct {
	ProducerTasksMax          int `json:"producer_tasks_max"`
	OwnerTasksPerConnection   int `json:"owner_tasks_per_connection"`
	FlusherTasksPerConnection int `json:"flusher_tasks_per_connection"`
	TimerTasksMax             int `json:"timer_tasks_max"`
	Connections               int `json:"connections"`
	CommandQueueCapacity      int `json:"command_queue_capacity"`
	WriteQueueCapacity        int `json:"write_queue_capacity"`
	EventQueueCapacity        int `json:"event_queue_capacity"`
	MaxInflightInboundBytes   int `json:"max_inflight_inbound_bytes"`
	FlushBatchMaxBuffers      int `json:"flush_batch_max_buffers"`
	MaxActionsPerSchedule     int `json:"max_actions_per_schedule"`
	PreemptionBound           int `json:"preemption_bound"`
	ScheduleCountMax          int `json:"schedule_count_max"`
	BranchCountMax            int `json:"branch_count_max"`
}

type cpFairness struct {
	FairnessID    string   `json:"fairness_id"`
	Kind          string   `json:"kind"`
	Subject       string   `json:"subject"`
	Rationale     string   `json:"rationale"`
	JavaCitations []string `json:"java_citations"`
}

type cpRace struct {
	RaceID                    string   `json:"race_id"`
	JavaSeams                 []string `json:"java_seams"`
	JavaCitations             []string `json:"java_citations"`
	RacyJavaBehavior          string   `json:"racy_java_behavior"`
	WhyNotCorpusEncodable     string   `json:"why_not_corpus_encodable"`
	DeterministicRustSemantic string   `json:"deterministic_rust_semantics"`
	DivergenceIDs             []string `json:"divergence_ids"`
}

type cpPlannedDelta struct {
	DivergenceID      string   `json:"divergence_id"`
	SubjectRefPlanned string   `json:"subject_ref_planned"`
	JavaRefPlanned    string   `json:"java_ref_planned"`
	RFCRefsPlanned    []string `json:"rfc_refs_planned"`
	JavaCitations     []string `json:"java_citations"`
	JavaBehavior      string   `json:"java_behavior"`
	PortBehavior      string   `json:"port_behavior"`
	DispositionPlan   string   `json:"disposition_planned"`
	Rationale         string   `json:"rationale"`
}

type cpLedgerBinding struct {
	LedgerPath          string           `json:"ledger_path"`
	ObservedStatus      string           `json:"observed_status"`
	ObservedHead        string           `json:"observed_head"`
	ObservedRecordCount int              `json:"observed_record_count"`
	AppendState         string           `json:"append_state"`
	AppendBlocker       string           `json:"append_blocker"`
	PlannedDeltas       []cpPlannedDelta `json:"planned_deltas"`
}

type cpDefect struct {
	DefectID       string `json:"defect_id"`
	Mutation       string `json:"mutation"`
	TargetProperty string `json:"target_property"`
	ExpectedResult string `json:"expected_result"`
	ExecutionState string `json:"execution_state"`
}

type cpNativeThreadSide struct {
	ClaimKind       string `json:"claim_kind"`
	CannotEstablish string `json:"cannot_establish"`
	Statement       string `json:"statement"`
}

type cpNativeThread struct {
	LoomStyleBoundedExploration cpNativeThreadSide `json:"loom_style_bounded_exploration"`
	NativeThreadStress          cpNativeThreadSide `json:"native_thread_stress"`
}

type cpProbe struct {
	Command  string `json:"command"`
	Observed string `json:"observed"`
}

type cpPlannedRun struct {
	Staging     string `json:"staging"`
	Command     string `json:"command"`
	Environment string `json:"environment"`
}

type cpRunSummary struct {
	StatesGenerated int    `json:"states_generated"`
	DistinctStates  int    `json:"distinct_states"`
	Result          string `json:"result"`
}

type cpModelCheck struct {
	Tool       string        `json:"tool"`
	Available  bool          `json:"available"`
	State      string        `json:"state"`
	Probes     []cpProbe     `json:"probes"`
	PlannedRun cpPlannedRun  `json:"planned_run"`
	RunSummary *cpRunSummary `json:"run_summary,omitempty"`
}

type cpPlan struct {
	Schema               string          `json:"$schema"`
	SchemaVersion        string          `json:"schema_version"`
	EvidenceKind         string          `json:"evidence_kind"`
	Story                string          `json:"story"`
	Assurance            cpAssurance     `json:"assurance"`
	Provenance           cpProvenance    `json:"provenance"`
	SeamCensus           cpCensus        `json:"seam_census"`
	Actions              []cpAction      `json:"actions"`
	Bounds               cpBounds        `json:"bounds"`
	Fairness             []cpFairness    `json:"fairness"`
	Races                []cpRace        `json:"races_not_corpus_encodable"`
	BehaviorDeltaLedger  cpLedgerBinding `json:"behavior_delta_ledger"`
	SeededDefects        []cpDefect      `json:"seeded_defects"`
	NativeThreadEvidence cpNativeThread  `json:"native_thread_evidence"`
	ModelCheck           cpModelCheck    `json:"model_check"`
	Production           bool            `json:"production"`
	Publication          bool            `json:"publication"`
}

type cpLedgerFile struct {
	Status  string `json:"status"`
	Head    string `json:"head"`
	Records []any  `json:"records"`
}

// ValidateConcurrencyPlan validates the concurrency plan document against its
// schema and the semantic rules, cross-checking the connection model's TLC
// configuration and the behavior-delta ledger's actual on-disk state.
func ValidateConcurrencyPlan(inputs ConcurrencyPlanInputs) []ModelFinding {
	var findings []ModelFinding

	raw, err := os.ReadFile(inputs.PlanPath)
	if err != nil {
		return append(findings, mpFinding("PLAN_FILE_UNREADABLE", inputs.PlanPath, err.Error()))
	}
	if len(raw) > mpMaxArtifactBytes {
		return append(findings, mpFinding("PLAN_FILE_UNREADABLE", inputs.PlanPath, "plan exceeds the bounded size"))
	}

	schemaFindings := cpValidateSchema(inputs.SchemaPath, raw, inputs.PlanPath)
	findings = append(findings, schemaFindings...)
	if len(schemaFindings) > 0 {
		return findings
	}

	var plan cpPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return append(findings, mpFinding("PLAN_FILE_UNREADABLE", inputs.PlanPath, err.Error()))
	}

	findings = append(findings, cpValidateCensus(plan.SeamCensus)...)
	findings = append(findings, cpValidateActions(plan)...)
	findings = append(findings, cpValidateBounds(plan.Bounds)...)
	findings = append(findings, cpValidateFairness(plan.Fairness)...)
	findings = append(findings, cpValidateRaces(plan)...)
	findings = append(findings, cpValidateLedgerBinding(plan.BehaviorDeltaLedger, inputs.LedgerPath)...)
	findings = append(findings, cpValidateSeededDefects(plan, inputs.CfgPath)...)
	findings = append(findings, cpValidateModelCheck(plan.ModelCheck)...)
	findings = append(findings, cpValidateCitations(plan, inputs.QuarantineJavaRoot)...)
	return findings
}

func cpValidateSchema(schemaPath string, raw []byte, planPath string) []ModelFinding {
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		return []ModelFinding{mpFinding("PLAN_SCHEMA_UNREADABLE", schemaPath, err.Error())}
	}
	schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		return []ModelFinding{mpFinding("PLAN_SCHEMA_UNREADABLE", schemaPath, err.Error())}
	}
	compiler := jsonschema.NewCompiler()
	resource := "https://verified-java-websocket-port.invalid/concurrency-plan-1.0.0.schema.json"
	if err := compiler.AddResource(resource, schemaValue); err != nil {
		return []ModelFinding{mpFinding("PLAN_SCHEMA_UNREADABLE", schemaPath, err.Error())}
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		return []ModelFinding{mpFinding("PLAN_SCHEMA_UNREADABLE", schemaPath, err.Error())}
	}
	planValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return []ModelFinding{mpFinding("PLAN_FILE_UNREADABLE", planPath, err.Error())}
	}
	if err := schema.Validate(planValue); err != nil {
		return []ModelFinding{mpFinding("PLAN_SCHEMA_INVALID", planPath, err.Error())}
	}
	return nil
}

func cpValidateCensus(census cpCensus) []ModelFinding {
	var findings []ModelFinding
	seen := map[string]bool{}
	inPortScope := 0
	for _, seam := range census.Seams {
		if seen[seam.SeamID] {
			findings = append(findings, mpFinding("PLAN_SEAM_CENSUS_INCOMPLETE", seam.SeamID,
				"seam id appears more than once"))
		}
		seen[seam.SeamID] = true
		if seam.Classification != "out_of_port_scope" {
			inPortScope++
		}
	}
	var missing []string
	for _, id := range cpExpectedSeamIDs {
		if !seen[id] {
			missing = append(missing, id)
		}
		delete(seen, id)
	}
	var unknown []string
	for id := range seen {
		unknown = append(unknown, id)
	}
	sort.Strings(unknown)
	if len(missing) > 0 {
		findings = append(findings, mpFinding("PLAN_SEAM_CENSUS_INCOMPLETE", "seam_census.seams",
			"census is missing seams: "+strings.Join(missing, ", ")))
	}
	if len(unknown) > 0 {
		findings = append(findings, mpFinding("PLAN_SEAM_CENSUS_INCOMPLETE", "seam_census.seams",
			"census contains unknown seam ids: "+strings.Join(unknown, ", ")))
	}
	if census.Total != len(cpExpectedSeamIDs) {
		findings = append(findings, mpFinding("PLAN_SEAM_CENSUS_INCOMPLETE", "seam_census.total",
			fmt.Sprintf("declared total %d does not match the %d-seam census", census.Total, len(cpExpectedSeamIDs))))
	}
	if len(census.Seams) != len(cpExpectedSeamIDs) {
		findings = append(findings, mpFinding("PLAN_SEAM_CENSUS_INCOMPLETE", "seam_census.seams",
			fmt.Sprintf("census has %d entries, expected %d", len(census.Seams), len(cpExpectedSeamIDs))))
	}
	if len(missing) == 0 && len(unknown) == 0 && census.InPortScope != inPortScope {
		findings = append(findings, mpFinding("PLAN_SEAM_CENSUS_INCOMPLETE", "seam_census.in_port_scope",
			fmt.Sprintf("declared in_port_scope %d does not match the %d seams not classified out_of_port_scope", census.InPortScope, inPortScope)))
	}
	return findings
}

func cpValidateActions(plan cpPlan) []ModelFinding {
	var findings []ModelFinding
	censusIDs := map[string]bool{}
	for _, seam := range plan.SeamCensus.Seams {
		censusIDs[seam.SeamID] = true
	}
	present := map[string]bool{}
	for _, action := range plan.Actions {
		present[action.ActionID] = true
		for _, seamID := range action.JavaSeams {
			if !censusIDs[seamID] {
				findings = append(findings, mpFinding("PLAN_ACTION_SEAM_UNKNOWN", action.ActionID,
					"action references seam "+seamID+" that is not in the census"))
			}
		}
		if len(action.ObservableOutcomes) == 0 {
			findings = append(findings, mpFinding("PLAN_ACTION_OUTCOMES_MISSING", action.ActionID,
				"action declares no typed observable outcomes"))
		}
	}
	for _, required := range cpRequiredActionIDs {
		if !present[required] {
			findings = append(findings, mpFinding("PLAN_ACTION_FAMILY_MISSING", "actions",
				"required action "+required+" is missing"))
		}
	}
	return findings
}

func cpValidateBounds(bounds cpBounds) []ModelFinding {
	var findings []ModelFinding
	if bounds.OwnerTasksPerConnection != 1 {
		findings = append(findings, mpFinding("PLAN_BOUNDS_INCONSISTENT", "bounds.owner_tasks_per_connection",
			fmt.Sprintf("the single-owner design requires exactly one owner task per connection, got %d", bounds.OwnerTasksPerConnection)))
	}
	if bounds.PreemptionBound >= bounds.ScheduleCountMax {
		findings = append(findings, mpFinding("PLAN_BOUNDS_INCONSISTENT", "bounds.preemption_bound",
			fmt.Sprintf("preemption bound %d must be far below the schedule budget %d", bounds.PreemptionBound, bounds.ScheduleCountMax)))
	}
	if bounds.ScheduleCountMax > bounds.BranchCountMax {
		findings = append(findings, mpFinding("PLAN_BOUNDS_INCONSISTENT", "bounds.schedule_count_max",
			"schedule budget exceeds the branch budget"))
	}
	return findings
}

func cpValidateFairness(entries []cpFairness) []ModelFinding {
	var findings []ModelFinding
	absentDeclared := false
	for _, entry := range entries {
		if entry.FairnessID == "PRODUCER_ADMISSION_FAIRNESS_ABSENT" {
			absentDeclared = true
			if entry.Kind != "absent" || strings.TrimSpace(entry.Rationale) == "" {
				findings = append(findings, mpFinding("PLAN_FAIRNESS_ABSENCE_UNDECLARED", entry.FairnessID,
					"producer-admission fairness absence must be kind=absent with a rationale"))
			}
		}
	}
	if !absentDeclared {
		findings = append(findings, mpFinding("PLAN_FAIRNESS_ABSENCE_UNDECLARED", "fairness",
			"the deliberate absence of producer-admission fairness must be declared, not implied"))
	}
	return findings
}

func cpValidateRaces(plan cpPlan) []ModelFinding {
	var findings []ModelFinding
	censusIDs := map[string]bool{}
	for _, seam := range plan.SeamCensus.Seams {
		censusIDs[seam.SeamID] = true
	}
	divergenceIDs := map[string]bool{}
	for _, delta := range plan.BehaviorDeltaLedger.PlannedDeltas {
		divergenceIDs[delta.DivergenceID] = true
	}
	present := map[string]bool{}
	for _, race := range plan.Races {
		present[race.RaceID] = true
		for _, seamID := range race.JavaSeams {
			if !censusIDs[seamID] {
				findings = append(findings, mpFinding("PLAN_ACTION_SEAM_UNKNOWN", race.RaceID,
					"race references seam "+seamID+" that is not in the census"))
			}
		}
		for _, divergenceID := range race.DivergenceIDs {
			if !divergenceIDs[divergenceID] {
				findings = append(findings, mpFinding("PLAN_DIVERGENCE_UNKNOWN", race.RaceID,
					"race references divergence "+divergenceID+" that the ledger binding does not plan"))
			}
		}
	}
	for _, required := range cpRequiredRaceIDs {
		if !present[required] {
			findings = append(findings, mpFinding("PLAN_RACE_FAMILY_MISSING", "races_not_corpus_encodable",
				"required race entry "+required+" is missing"))
		}
	}
	return findings
}

func cpValidateLedgerBinding(binding cpLedgerBinding, ledgerPath string) []ModelFinding {
	var findings []ModelFinding
	raw, err := os.ReadFile(ledgerPath)
	if err != nil {
		return append(findings, mpFinding("PLAN_LEDGER_UNREADABLE", ledgerPath, err.Error()))
	}
	var ledger cpLedgerFile
	if err := json.Unmarshal(raw, &ledger); err != nil {
		return append(findings, mpFinding("PLAN_LEDGER_UNREADABLE", ledgerPath, err.Error()))
	}
	if binding.ObservedStatus != ledger.Status {
		findings = append(findings, mpFinding("PLAN_LEDGER_BINDING_MISMATCH", "behavior_delta_ledger.observed_status",
			fmt.Sprintf("plan records ledger status %q but the ledger says %q", binding.ObservedStatus, ledger.Status)))
	}
	if binding.ObservedHead != ledger.Head {
		findings = append(findings, mpFinding("PLAN_LEDGER_BINDING_MISMATCH", "behavior_delta_ledger.observed_head",
			fmt.Sprintf("plan records ledger head %q but the ledger says %q", binding.ObservedHead, ledger.Head)))
	}
	if binding.ObservedRecordCount != len(ledger.Records) {
		findings = append(findings, mpFinding("PLAN_LEDGER_BINDING_MISMATCH", "behavior_delta_ledger.observed_record_count",
			fmt.Sprintf("plan records %d ledger records but the ledger has %d", binding.ObservedRecordCount, len(ledger.Records))))
	}
	if ledger.Status == "BLOCKED_PENDING_BASELINE" && binding.AppendState != "APPEND_BLOCKED_PENDING_BASELINE" {
		findings = append(findings, mpFinding("PLAN_LEDGER_BINDING_MISMATCH", "behavior_delta_ledger.append_state",
			"the ledger is blocked pending its baseline; the plan must record the append as blocked rather than performed"))
	}
	return findings
}

func cpValidateSeededDefects(plan cpPlan, cfgPath string) []ModelFinding {
	var findings []ModelFinding
	cfgText, failure := mpReadText(cfgPath)
	if failure != nil {
		return append(findings, *failure)
	}
	cfg, cfgFindings := mpParseCfg(cfgText)
	findings = append(findings, cfgFindings...)
	declared := map[string]bool{}
	for _, name := range append(append([]string{}, cfg.Invariants...), cfg.Properties...) {
		declared[name] = true
	}
	covered := map[string]bool{}
	for _, defect := range plan.SeededDefects {
		if !declared[defect.TargetProperty] {
			findings = append(findings, mpFinding("PLAN_SEEDED_DEFECT_UNBOUND", defect.DefectID,
				"seeded defect targets "+defect.TargetProperty+" which the TLC configuration does not check"))
			continue
		}
		covered[defect.TargetProperty] = true
		if !plan.ModelCheck.Available && defect.ExecutionState != "MODEL_CHECK_PENDING_TOOL" {
			findings = append(findings, mpFinding("PLAN_MODEL_CHECK_INCONSISTENT", defect.DefectID,
				"seeded defect claims an execution state beyond the unavailable model checker"))
		}
	}
	var uncovered []string
	for name := range declared {
		if !covered[name] {
			uncovered = append(uncovered, name)
		}
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		findings = append(findings, mpFinding("PLAN_PROPERTY_UNFALSIFIED", "seeded_defects",
			"checked properties without a seeded falsifying mutation: "+strings.Join(uncovered, ", ")))
	}
	return findings
}

func cpValidateModelCheck(check cpModelCheck) []ModelFinding {
	var findings []ModelFinding
	switch check.State {
	case "MODEL_CHECK_PENDING_TOOL":
		if check.Available {
			findings = append(findings, mpFinding("PLAN_MODEL_CHECK_INCONSISTENT", "model_check.state",
				"state is pending-tool but the tool is recorded as available"))
		}
		if len(check.Probes) == 0 {
			findings = append(findings, mpFinding("PLAN_MODEL_CHECK_INCONSISTENT", "model_check.probes",
				"a pending-tool record must carry the availability probes actually run"))
		}
	case "EXECUTED":
		if !check.Available {
			findings = append(findings, mpFinding("PLAN_MODEL_CHECK_INCONSISTENT", "model_check.state",
				"state is executed but the tool is recorded as unavailable"))
		}
		if check.RunSummary == nil || check.RunSummary.StatesGenerated < 1 {
			findings = append(findings, mpFinding("PLAN_MODEL_CHECK_INCONSISTENT", "model_check.run_summary",
				"an executed record must carry the real run summary (states generated, result)"))
		}
	default:
		findings = append(findings, mpFinding("PLAN_MODEL_CHECK_INCONSISTENT", "model_check.state",
			"unknown model-check state "+check.State))
	}
	return findings
}

func cpValidateCitations(plan cpPlan, quarantineJavaRoot string) []ModelFinding {
	var findings []ModelFinding
	type cited struct {
		location string
		citation string
	}
	var all []cited
	for _, seam := range plan.SeamCensus.Seams {
		for _, citation := range seam.Citations {
			all = append(all, cited{"seam_census." + seam.SeamID, citation})
		}
	}
	for _, action := range plan.Actions {
		for _, citation := range action.JavaCitations {
			all = append(all, cited{action.ActionID, citation})
		}
	}
	for _, entry := range plan.Fairness {
		for _, citation := range entry.JavaCitations {
			all = append(all, cited{entry.FairnessID, citation})
		}
	}
	for _, race := range plan.Races {
		for _, citation := range race.JavaCitations {
			all = append(all, cited{race.RaceID, citation})
		}
	}
	for _, delta := range plan.BehaviorDeltaLedger.PlannedDeltas {
		for _, citation := range delta.JavaCitations {
			all = append(all, cited{delta.DivergenceID, citation})
		}
	}
	quarantinePresent := quarantineJavaRoot != "" && mpDirectoryExists(quarantineJavaRoot)
	for _, entry := range all {
		if _, _, err := mpParseCitation(entry.citation); err != nil {
			findings = append(findings, mpFinding("PLAN_CITATION_MALFORMED", entry.location, err.Error()))
			continue
		}
		if quarantinePresent {
			if err := mpResolveCitation(quarantineJavaRoot, entry.citation); err != nil {
				findings = append(findings, mpFinding("PLAN_CITATION_UNRESOLVED", entry.location, err.Error()))
			}
		}
	}
	if !quarantinePresent {
		findings = append(findings, mpAdvisory("PLAN_CITATION_UNVERIFIED", "plan",
			"quarantined Java tree unavailable; plan citations were format-checked only"))
	}
	return findings
}
