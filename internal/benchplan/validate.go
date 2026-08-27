package benchplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Blocker classes reported by document verification.
const (
	// BlockerSchemaInvalid: a benchmark document violates its schema.
	BlockerSchemaInvalid = "SCHEMA_INVALID"
	// BlockerPlanInconsistent: the plan disagrees with the frozen
	// executable spec (seed rule, derived orders, statistics constants,
	// thresholds).
	BlockerPlanInconsistent = "PLAN_INCONSISTENT"
	// BlockerPowerModelInvalid: a named alternative is not detectable
	// under the frozen power model.
	BlockerPowerModelInvalid = "POWER_MODEL_INVALID"
	// BlockerHostBindingPending: the single remaining owner-gated gap —
	// confirmation-host fields and measurement/analyzer tool identities
	// that only the owner can bind.
	BlockerHostBindingPending = "HOST_BINDING_PENDING"
	// BlockerMeterTampered: an environment document's declared role or
	// required_binding_fields disagrees with the canonical per-role
	// list frozen in this package — the completion meter is code+schema
	// truth, never document truth (review fix round 2).
	BlockerMeterTampered = "METER_TAMPERED"
)

// OwnerIdentity is the frozen owner identity exactly as recorded in
// every owner decision record in the workspace protected root
// ("owner": "mikelady", e.g. us008-owner-attestation-2026-08-27.json).
// An independent attestation's attestor can never be this identity:
// a self-attestation is owner-only by definition (re-review round 1,
// session 01a04165).
const OwnerIdentity = "mikelady"

// Attestation assurance labels. The owner-only label is the honest
// posture of every real document today; the independent label exists
// only as the paired-state requirement for a future genuine
// independent attestation.
const (
	AssuranceOwnerNotIndependent   = "OWNER_ATTESTED_NOT_INDEPENDENT"
	AssuranceIndependentlyAttested = "INDEPENDENTLY_ATTESTED"
)

// EnvironmentRoleByDocument is the filename-to-role contract: each
// environment document must declare exactly this role.
var EnvironmentRoleByDocument = map[string]string{
	"benchmarks/environments/primary-macos.json": "primary",
	"benchmarks/environments/confirmation.json":  "confirmation",
}

// CanonicalBindingFields is the canonical, frozen required-binding-field
// list per environment role. The validator meters THESE fields and fails
// with METER_TAMPERED if a document declares any other list, so a
// document cannot shrink its own completion meter.
var CanonicalBindingFields = map[string][]string{
	"primary": {
		"host_identity.os_product_version",
		"host_identity.os_build_version",
		"host_identity.hardware_model_identifier",
		"host_identity.cpu_brand",
		"host_identity.cpu_logical_cores",
		"host_identity.cpu_performance_cores",
		"host_identity.cpu_efficiency_cores",
		"host_identity.memory_total_bytes",
		"host_identity.power_source_state",
		"host_identity.low_power_mode_state",
		"host_identity.thermal_pressure_state",
		"host_identity.background_process_census",
		"host_identity.clock_sync_state",
		"tool_identities.java_runtime",
		"tool_identities.rust_toolchain",
		"tool_identities.java_executable_digest",
		"tool_identities.rust_executable_digest",
		"tool_identities.load_driver",
		"tool_identities.measurement_tools",
		"tool_identities.analyzer",
	},
	"confirmation": {
		"host_identity.instance_type",
		"host_identity.instance_id",
		"host_identity.observed_architecture",
		"host_identity.allocation_evidence",
		"host_identity.region",
		"host_identity.availability_zone",
		"host_identity.ami_id",
		"host_identity.ami_name",
		"host_identity.os_identity",
		"host_identity.kernel_identity",
		"host_identity.cpu_model",
		"host_identity.cpu_frequency_policy",
		"host_identity.memory_total_bytes",
		"host_identity.numa_topology",
		"host_identity.clocksource",
		"tool_identities.java_runtime",
		"tool_identities.rust_toolchain",
		"tool_identities.java_executable_digest",
		"tool_identities.rust_executable_digest",
		"tool_identities.load_driver",
		"tool_identities.measurement_tools",
		"tool_identities.analyzer",
		"tool_identities.runner",
	},
}

// BenchmarkDocuments maps each benchmark document (repo-relative) to its
// schema in schemas/.
var BenchmarkDocuments = map[string]string{
	"benchmarks/plan/workloads.json":             "benchmark-plan-1.0.0.schema.json",
	"benchmarks/environments/primary-macos.json": "benchmark-environment-1.0.0.schema.json",
	"benchmarks/environments/confirmation.json":  "benchmark-environment-1.0.0.schema.json",
}

// UnboundField is one required binding field that has not bound yet.
type UnboundField struct {
	Document string
	Path     string
	Status   string
}

// Report is the verification result: every failure list plus the
// machine-checkable completion meter for US-008's remaining gap.
type Report struct {
	SchemaFailures        map[string][]string
	PlanFailures          []string
	PowerFailures         []string
	UnboundFields         []UnboundField
	RuntimeSnapshotFields []UnboundField
	// MeterFailures are canonical-meter integrity violations: a wrong
	// declared role or a required_binding_fields list that differs from
	// the canonical per-role list (METER_TAMPERED).
	MeterFailures []string
	// PlanAttestationState is the plan's machine-readable attestation
	// state (UNATTESTED until the owner's independent attestation).
	PlanAttestationState string
	// EnvironmentBindingStatus maps each environment document to its
	// declared binding_status (UNBOUND/BOUND).
	EnvironmentBindingStatus map[string]string
	BlockerClasses           []string
}

// attestationRecord is the digest-binding record an attested plan must
// carry: it binds the attestation to the exact frozen plan bytes plus
// the owner decision record and the honest assurance labels. The three
// independent_* fields exist ONLY in the INDEPENDENTLY_ATTESTED record
// variant (re-review round 1, session 01a04165): they are the
// independent-specific evidence an owner-only record structurally
// cannot provide, so a relabeled owner record can never satisfy the
// independent state.
type attestationRecord struct {
	PlanContentSHA256        string `json:"plan_content_sha256"`
	FrozenPlanGitCommit      string `json:"frozen_plan_git_commit"`
	FrozenPlanPath           string `json:"frozen_plan_path"`
	DigestScope              string `json:"digest_scope"`
	DecisionRecord           string `json:"decision_record"`
	AttestedAt               string `json:"attested_at"`
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	// Independent-variant evidence (empty in every owner-only record;
	// the schema's ownerAttestationRecord forbids them outright).
	IndependentAttestorIdentity        string `json:"independent_attestor_identity"`
	IndependentAttestationRecordSHA256 string `json:"independent_attestation_record_sha256"`
	IndependentAttestedAt              string `json:"independent_attested_at"`
}

// planDocument is the subset of the plan the validator cross-checks
// against the frozen executable spec.
type planDocument struct {
	Schema                   string             `json:"schema"`
	Status                   string             `json:"status"`
	AttestationState         string             `json:"attestation_state"`
	AttestationRecord        *attestationRecord `json:"attestation_record"`
	Assurance                string             `json:"assurance"`
	IndependentReviewClaimed bool               `json:"independent_review_claimed"`
	SharedDefinitions        struct {
		MaskSpecVersion string `json:"mask_spec_version"`
	} `json:"shared_definitions"`
	Workloads []struct {
		ID               string   `json:"id"`
		DerivedPairOrder []string `json:"derived_pair_order"`
	} `json:"workloads"`
	PairingAndOrdering struct {
		WarmupPairsExcluded int      `json:"warmup_pairs_excluded"`
		MeasuredPairs       int      `json:"measured_pairs"`
		TotalPairs          int      `json:"total_pairs"`
		SeedSpecVersion     string   `json:"seed_spec_version"`
		Forbidden           []string `json:"forbidden"`
	} `json:"pairing_and_ordering"`
	Statistics struct {
		ConfidenceLevel  float64 `json:"confidence_level"`
		DegreesOfFreedom int     `json:"degrees_of_freedom"`
		PowerModel       struct {
			Alpha             float64 `json:"alpha"`
			PowerMin          float64 `json:"power_min"`
			MaxLogRatioSD     float64 `json:"max_log_ratio_sd"`
			NamedAlternatives struct {
				Memory struct {
					LogRatio float64 `json:"log_ratio"`
				} `json:"memory"`
				NonRegression struct {
					LogRatio float64 `json:"log_ratio"`
				} `json:"non_regression"`
			} `json:"named_alternatives"`
		} `json:"power_model"`
		ReferenceDriftProcedure struct {
			ReferenceWorkload  string `json:"reference_workload"`
			ReferenceRunsTotal int    `json:"reference_runs_total"`
			SubsequentRuns     int    `json:"subsequent_runs"`
			EnvelopePercent    int    `json:"envelope_percent"`
		} `json:"reference_drift_procedure"`
	} `json:"statistics"`
	CIThresholds map[string]json.RawMessage `json:"ci_thresholds"`
	Binding      struct {
		RequiredSampleBindings []string `json:"required_sample_bindings"`
	} `json:"binding"`
}

type environmentDocument struct {
	Schema                string                      `json:"schema"`
	Role                  string                      `json:"role"`
	BindingStatus         string                      `json:"binding_status"`
	HostIdentity          map[string]environmentField `json:"host_identity"`
	RunPolicy             map[string]environmentField `json:"run_policy"`
	ToolIdentities        map[string]environmentField `json:"tool_identities"`
	RequiredBindingFields []string                    `json:"required_binding_fields"`
}

type environmentField struct {
	Status string          `json:"status"`
	Value  json.RawMessage `json:"value"`
}

// Verify validates every benchmark document against its schema, checks
// the plan against the frozen executable spec, verifies the power
// model, and walks each environment's required_binding_fields to build
// the completion meter. When everything driver-completable is complete,
// the only reported blocker class is HOST_BINDING_PENDING.
func Verify(root string) (Report, error) {
	report := Report{SchemaFailures: map[string][]string{}}

	for document, schemaName := range BenchmarkDocuments {
		failures, err := validateAgainstSchema(root, document, schemaName)
		if err != nil {
			return report, err
		}
		if len(failures) > 0 {
			report.SchemaFailures[document] = failures
		}
	}

	planFailures, attestationState, err := verifyPlanAgainstSpec(root)
	if err != nil {
		return report, err
	}
	report.PlanFailures = planFailures
	report.PlanAttestationState = attestationState

	powerFailures, err := VerifyPowerModel(MaxLogRatioSD)
	if err != nil {
		return report, err
	}
	report.PowerFailures = powerFailures

	report.EnvironmentBindingStatus = map[string]string{}
	for _, document := range []string{
		"benchmarks/environments/primary-macos.json",
		"benchmarks/environments/confirmation.json",
	} {
		meter, err := environmentCompletionMeter(root, document, EnvironmentRoleByDocument[document])
		if err != nil {
			return report, err
		}
		report.UnboundFields = append(report.UnboundFields, meter.unbound...)
		report.RuntimeSnapshotFields = append(report.RuntimeSnapshotFields, meter.snapshots...)
		report.MeterFailures = append(report.MeterFailures, meter.failures...)
		report.EnvironmentBindingStatus[document] = meter.bindingStatus
		// A document may not claim BOUND while any of its required
		// binding fields is still pending (fail-closed consistency).
		if meter.bindingStatus == "BOUND" && len(meter.unbound) > 0 {
			report.PlanFailures = append(report.PlanFailures, fmt.Sprintf(
				"%s declares binding_status BOUND while %d required binding field(s) are still unbound", document, len(meter.unbound)))
		}
	}

	if len(report.SchemaFailures) > 0 {
		report.BlockerClasses = append(report.BlockerClasses, BlockerSchemaInvalid)
	}
	if len(report.PlanFailures) > 0 {
		report.BlockerClasses = append(report.BlockerClasses, BlockerPlanInconsistent)
	}
	if len(report.PowerFailures) > 0 {
		report.BlockerClasses = append(report.BlockerClasses, BlockerPowerModelInvalid)
	}
	if len(report.MeterFailures) > 0 {
		report.BlockerClasses = append(report.BlockerClasses, BlockerMeterTampered)
	}
	// The owner-gated gap is host/tool binding AND its attestation:
	// syntactically complete field values with UNBOUND/UNATTESTED
	// status must never read as bound (review fix I5). OWNER_ATTESTED
	// (the owner-only attestation of 2026-08-27) still counts as
	// attestation pending here — the exit-0 gate requires an
	// INDEPENDENT attestation and is never loosened by an owner-only
	// one.
	attestationPending := report.PlanAttestationState != "INDEPENDENTLY_ATTESTED"
	for _, bindingStatus := range report.EnvironmentBindingStatus {
		if bindingStatus != "BOUND" {
			attestationPending = true
		}
	}
	if len(report.UnboundFields) > 0 || attestationPending {
		report.BlockerClasses = append(report.BlockerClasses, BlockerHostBindingPending)
	}
	return report, nil
}

// HostBindingIsOnlyBlocker reports whether the verification found the
// expected steady state: every driver-completable element is complete
// and the single remaining blocker class is the owner-gated host/tool
// binding.
func (r Report) HostBindingIsOnlyBlocker() bool {
	return len(r.BlockerClasses) == 1 && r.BlockerClasses[0] == BlockerHostBindingPending
}

// FullyBound reports whether no blocker remains at all: every binding
// field bound, both environments' binding_status BOUND, and the plan
// independently attested. It cannot be true before the owner binds the
// confirmation host and tool identities and attests the plan.
func (r Report) FullyBound() bool {
	return len(r.BlockerClasses) == 0
}

func verifyPlanAgainstSpec(root string) ([]string, string, error) {
	content, err := os.ReadFile(filepath.Join(root, "benchmarks", "plan", "workloads.json"))
	if err != nil {
		return nil, "", err
	}
	var plan planDocument
	if err := json.Unmarshal(content, &plan); err != nil {
		return nil, "", fmt.Errorf("plan parse: %w", err)
	}
	var failures []string
	fail := func(format string, args ...any) {
		failures = append(failures, fmt.Sprintf(format, args...))
	}

	// Paired attestation states (never loosened): UNATTESTED forbids the
	// digest-binding record, every attested state requires it, and only
	// INDEPENDENTLY_ATTESTED can ever satisfy the exit-0 gate.
	// OWNER_ATTESTED is the honest owner-only intermediate: the owner
	// froze and attested the plan under the
	// OWNER_ATTESTED_NOT_INDEPENDENT labeling, and no independent
	// attestation exists or is claimed. INDEPENDENTLY_ATTESTED demands
	// independent-specific evidence (a distinct attestor identity,
	// record-level independent_review_claimed true, the attestor record
	// digest and date) that an owner-only record structurally cannot
	// provide — a state/status relabel alone must always fail (re-review
	// round 1, session 01a04165).
	switch plan.AttestationState {
	case "UNATTESTED":
		if !strings.HasPrefix(plan.Status, "PREREGISTERED_BY_DRIVER_UNATTESTED") {
			fail("attestation_state UNATTESTED but status %q does not declare it", plan.Status)
		}
		if plan.AttestationRecord != nil {
			fail("attestation_state UNATTESTED must not carry an attestation_record")
		}
		verifyOwnerAssuranceLabels(plan, fail)
	case "OWNER_ATTESTED":
		if !strings.HasPrefix(plan.Status, "PREREGISTERED_OWNER_ATTESTED") {
			fail("attestation_state OWNER_ATTESTED but status %q does not declare it", plan.Status)
		}
		verifyOwnerAssuranceLabels(plan, fail)
		verifyOwnerAttestationRecord(plan.AttestationRecord, fail)
	case "INDEPENDENTLY_ATTESTED":
		if !strings.HasPrefix(plan.Status, "PREREGISTERED_INDEPENDENTLY_ATTESTED") {
			fail("attestation_state INDEPENDENTLY_ATTESTED but status %q does not declare it", plan.Status)
		}
		if plan.Assurance != AssuranceIndependentlyAttested {
			fail("attestation_state INDEPENDENTLY_ATTESTED but document assurance %q is not %q", plan.Assurance, AssuranceIndependentlyAttested)
		}
		if !plan.IndependentReviewClaimed {
			fail("attestation_state INDEPENDENTLY_ATTESTED but the document does not claim an independent review (independent_review_claimed false)")
		}
		verifyIndependentAttestationRecord(plan.AttestationRecord, fail)
	default:
		fail("attestation_state %q is not a preregistered state", plan.AttestationState)
	}
	if plan.SharedDefinitions.MaskSpecVersion != MaskSpecVersion {
		fail("mask spec version %q disagrees with the frozen spec %q", plan.SharedDefinitions.MaskSpecVersion, MaskSpecVersion)
	}
	drift := plan.Statistics.ReferenceDriftProcedure
	if drift.ReferenceWorkload != ReferenceWorkloadID || drift.ReferenceRunsTotal != ReferenceRunsTotal ||
		drift.SubsequentRuns != ReferenceSubsequentRuns || drift.EnvelopePercent != ReferenceDriftEnvelopePercent {
		fail("reference drift procedure %s/%d/%d/%d%% disagrees with the frozen spec %s/%d/%d/%d%%",
			drift.ReferenceWorkload, drift.ReferenceRunsTotal, drift.SubsequentRuns, drift.EnvelopePercent,
			ReferenceWorkloadID, ReferenceRunsTotal, ReferenceSubsequentRuns, ReferenceDriftEnvelopePercent)
	}

	ordering := plan.PairingAndOrdering
	if ordering.WarmupPairsExcluded != WarmupPairs || ordering.MeasuredPairs != MeasuredPairs || ordering.TotalPairs != TotalPairs {
		fail("pair counts %d/%d/%d disagree with the frozen spec %d/%d/%d",
			ordering.WarmupPairsExcluded, ordering.MeasuredPairs, ordering.TotalPairs, WarmupPairs, MeasuredPairs, TotalPairs)
	}
	if ordering.SeedSpecVersion != SeedSpecVersion {
		fail("seed spec version %q disagrees with the frozen spec %q", ordering.SeedSpecVersion, SeedSpecVersion)
	}
	if len(plan.Workloads) != len(WorkloadIDs) {
		fail("plan has %d workloads, frozen spec requires %d", len(plan.Workloads), len(WorkloadIDs))
	} else {
		for i, workload := range plan.Workloads {
			if workload.ID != WorkloadIDs[i] {
				fail("workload %d is %q, frozen spec requires %q", i, workload.ID, WorkloadIDs[i])
				continue
			}
			derived, err := PairOrder(workload.ID)
			if err != nil {
				return nil, "", err
			}
			if len(workload.DerivedPairOrder) != TotalPairs {
				fail("%s derived_pair_order has %d entries, spec requires %d", workload.ID, len(workload.DerivedPairOrder), TotalPairs)
				continue
			}
			for j, entry := range workload.DerivedPairOrder {
				if entry != derived[j] {
					fail("%s derived_pair_order[%d] is %s, the SHA-256 rule derives %s", workload.ID, j, entry, derived[j])
					break
				}
			}
		}
	}

	statistics := plan.Statistics
	if statistics.ConfidenceLevel != ConfidenceLevel || statistics.DegreesOfFreedom != DegreesOfFreedom {
		fail("statistics %g/%d disagree with the frozen 0.95 confidence, 29 df", statistics.ConfidenceLevel, statistics.DegreesOfFreedom)
	}
	power := statistics.PowerModel
	if power.Alpha != PowerAlpha || power.PowerMin != PowerMinimum || power.MaxLogRatioSD != MaxLogRatioSD {
		fail("power model %g/%g/%g disagrees with the frozen alpha %g, power %g, max SD %g",
			power.Alpha, power.PowerMin, power.MaxLogRatioSD, PowerAlpha, PowerMinimum, MaxLogRatioSD)
	}
	if math.Abs(power.NamedAlternatives.Memory.LogRatio-MemoryAlternativeLogRatio) > 1e-9 {
		fail("memory alternative %g disagrees with the frozen ln(0.8)", power.NamedAlternatives.Memory.LogRatio)
	}
	if math.Abs(power.NamedAlternatives.NonRegression.LogRatio-NonRegressionAlternativeLogRatio) > 1e-9 {
		fail("non-regression alternative %g disagrees with the frozen ln(1.1)", power.NamedAlternatives.NonRegression.LogRatio)
	}

	for _, metric := range MetricNames {
		raw, present := plan.CIThresholds[metric]
		if !present {
			fail("ci_thresholds is missing metric %s", metric)
			continue
		}
		var declared struct {
			Bound string  `json:"bound"`
			Value float64 `json:"value"`
		}
		if err := json.Unmarshal(raw, &declared); err != nil {
			fail("ci_thresholds.%s is malformed: %v", metric, err)
			continue
		}
		frozen := MetricThresholds[metric]
		if declared.Bound != string(frozen.Bound) || declared.Value != frozen.Value {
			fail("ci_thresholds.%s is %s/%g, frozen spec requires %s/%g", metric, declared.Bound, declared.Value, frozen.Bound, frozen.Value)
		}
	}

	if len(plan.Binding.RequiredSampleBindings) != len(RequiredSampleBindings) {
		fail("required_sample_bindings has %d entries, frozen spec requires %d", len(plan.Binding.RequiredSampleBindings), len(RequiredSampleBindings))
	} else {
		for i, name := range plan.Binding.RequiredSampleBindings {
			if name != RequiredSampleBindings[i] {
				fail("required_sample_bindings[%d] is %q, frozen spec requires %q", i, name, RequiredSampleBindings[i])
			}
		}
	}
	return failures, plan.AttestationState, nil
}

// verifyOwnerAssuranceLabels checks the document-level assurance
// pairing for the owner-only states (UNATTESTED and OWNER_ATTESTED):
// the honest owner-only labels, with no independent review claimed.
func verifyOwnerAssuranceLabels(plan planDocument, fail func(string, ...any)) {
	if plan.Assurance != AssuranceOwnerNotIndependent {
		fail("attestation_state %s but document assurance %q is not %q", plan.AttestationState, plan.Assurance, AssuranceOwnerNotIndependent)
	}
	if plan.IndependentReviewClaimed {
		fail("attestation_state %s must not claim an independent review (independent_review_claimed must be false)", plan.AttestationState)
	}
}

// verifyAttestationRecordCommon cross-checks the digest-binding core
// every attested record must carry (mirroring the schema, defense in
// depth): a lowercase 64-hex SHA-256 of the exact frozen plan bytes,
// the frozen commit and path, the decision record, and the captured
// attestation timestamp. The validator cannot recompute the digest (the
// frozen bytes are the plan content at the attested commit, which this
// record itself postdates); the recorded digest is regression-pinned by
// full equality in the package tests.
func verifyAttestationRecordCommon(record *attestationRecord, fail func(string, ...any)) {
	if !isLowercaseHex(record.PlanContentSHA256, 64) {
		fail("attestation_record.plan_content_sha256 %q is not a lowercase 64-hex SHA-256", record.PlanContentSHA256)
	}
	if len(record.FrozenPlanGitCommit) < 7 || !isLowercaseHex(record.FrozenPlanGitCommit, len(record.FrozenPlanGitCommit)) {
		fail("attestation_record.frozen_plan_git_commit %q is not a git commit hash", record.FrozenPlanGitCommit)
	}
	if record.FrozenPlanPath != "benchmarks/plan/workloads.json" {
		fail("attestation_record.frozen_plan_path %q must be the plan document itself", record.FrozenPlanPath)
	}
	if record.DigestScope == "" {
		fail("attestation_record.digest_scope must state exactly which bytes were digested")
	}
	if record.DecisionRecord == "" {
		fail("attestation_record.decision_record must reference the owner decision record")
	}
	if record.AttestedAt == "" {
		fail("attestation_record.attested_at must carry the decision record's captured timestamp")
	}
}

// verifyOwnerAttestationRecord cross-checks the OWNER_ATTESTED record
// variant: the digest-binding core plus the honest owner-only labels,
// and structurally NO independent-variant evidence — an owner record
// carrying independent fields is a mislabeled record, never progress.
func verifyOwnerAttestationRecord(record *attestationRecord, fail func(string, ...any)) {
	if record == nil {
		fail("an attested plan must carry the digest-binding attestation_record")
		return
	}
	verifyAttestationRecordCommon(record, fail)
	if record.Assurance != AssuranceOwnerNotIndependent {
		fail("attestation_record.assurance %q disagrees with the OWNER_ATTESTED_NOT_INDEPENDENT labeling (a genuinely independent attestation is a recorded preregistration change carrying independent evidence, never a label edit)", record.Assurance)
	}
	if record.IndependentReviewClaimed {
		fail("attestation_record.independent_review_claimed must stay false in an owner-only record: no independent review exists or is claimed")
	}
	if record.IndependentAttestorIdentity != "" || record.IndependentAttestationRecordSHA256 != "" || record.IndependentAttestedAt != "" {
		fail("an OWNER_ATTESTED record must not carry independent-variant evidence fields (independent_attestor_identity / independent_attestation_record_sha256 / independent_attested_at)")
	}
}

// verifyIndependentAttestationRecord cross-checks the
// INDEPENDENTLY_ATTESTED record variant (re-review round 1, session
// 01a04165): the digest-binding core plus independent-specific evidence
// an owner-only record structurally cannot provide — a non-empty
// attestor identity that is NOT the owner, record-level
// independent_review_claimed true with the state-consistent assurance
// label, and the attestor record digest and date. A relabeled owner
// record fails every one of these with a typed finding.
func verifyIndependentAttestationRecord(record *attestationRecord, fail func(string, ...any)) {
	if record == nil {
		fail("an attested plan must carry the digest-binding attestation_record")
		return
	}
	verifyAttestationRecordCommon(record, fail)
	if record.Assurance != AssuranceIndependentlyAttested {
		fail("attestation_record.assurance %q is not %q: an owner-only record relabeled to INDEPENDENTLY_ATTESTED can never satisfy the independent state", record.Assurance, AssuranceIndependentlyAttested)
	}
	if !record.IndependentReviewClaimed {
		fail("attestation_record.independent_review_claimed must be true at the record level for INDEPENDENTLY_ATTESTED: an owner-only record (which claims none) can never satisfy the independent state")
	}
	attestor := strings.TrimSpace(record.IndependentAttestorIdentity)
	if attestor == "" {
		fail("attestation_record.independent_attestor_identity is missing: INDEPENDENTLY_ATTESTED requires independent evidence an owner-only record cannot provide")
	} else if strings.EqualFold(attestor, OwnerIdentity) {
		fail("attestation_record.independent_attestor_identity %q equals the owner identity %q: a self-attestation is owner-only by definition and can never be the independent attestation", record.IndependentAttestorIdentity, OwnerIdentity)
	}
	if !isLowercaseHex(record.IndependentAttestationRecordSHA256, 64) {
		fail("attestation_record.independent_attestation_record_sha256 %q is not a lowercase 64-hex SHA-256 of the independent attestor's record", record.IndependentAttestationRecordSHA256)
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", record.IndependentAttestedAt); err != nil {
		fail("attestation_record.independent_attested_at %q is not a UTC timestamp of the independent attestation", record.IndependentAttestedAt)
	}
}

// isLowercaseHex reports whether s is exactly length lowercase-hex
// characters.
func isLowercaseHex(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// meterResult is one environment document's completion-meter outcome.
type meterResult struct {
	unbound       []UnboundField
	snapshots     []UnboundField
	failures      []string
	bindingStatus string
}

// environmentCompletionMeter meters the CANONICAL per-role field list —
// never the document's own list — and reports METER_TAMPERED failures
// when the document's declared role or required_binding_fields disagree
// with the canon (review fix round 2: a document cannot shrink its own
// completion meter).
func environmentCompletionMeter(root, document, expectedRole string) (meterResult, error) {
	var meter meterResult
	canonical, known := CanonicalBindingFields[expectedRole]
	if !known {
		return meter, fmt.Errorf("%s: no canonical binding-field list for role %q", document, expectedRole)
	}
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(document)))
	if err != nil {
		return meter, err
	}
	var environment environmentDocument
	if err := json.Unmarshal(content, &environment); err != nil {
		return meter, fmt.Errorf("%s parse: %w", document, err)
	}
	meter.bindingStatus = environment.BindingStatus

	if environment.Role != expectedRole {
		meter.failures = append(meter.failures, fmt.Sprintf(
			"%s declares role %q but the filename contract requires %q", document, environment.Role, expectedRole))
	}
	if len(environment.RequiredBindingFields) != len(canonical) {
		meter.failures = append(meter.failures, fmt.Sprintf(
			"%s declares %d required binding fields; the canonical %s list has %d (the meter is code+schema truth, not document truth)",
			document, len(environment.RequiredBindingFields), expectedRole, len(canonical)))
	} else {
		for i, path := range environment.RequiredBindingFields {
			if path != canonical[i] {
				meter.failures = append(meter.failures, fmt.Sprintf(
					"%s required_binding_fields[%d] is %q, the canonical %s list requires %q", document, i, path, expectedRole, canonical[i]))
			}
		}
	}

	sections := map[string]map[string]environmentField{
		"host_identity":   environment.HostIdentity,
		"run_policy":      environment.RunPolicy,
		"tool_identities": environment.ToolIdentities,
	}
	for _, path := range canonical {
		section, field, found := strings.Cut(path, ".")
		records := sections[section]
		if !found || records == nil {
			meter.failures = append(meter.failures, fmt.Sprintf(
				"%s: canonical binding field %q references a missing section", document, path))
			continue
		}
		record, present := records[field]
		if !present {
			meter.failures = append(meter.failures, fmt.Sprintf(
				"%s: canonical binding field %q has no field record", document, path))
			continue
		}
		switch record.Status {
		case "OWNER_DECISION_PENDING", "NOT_MEASURED":
			meter.unbound = append(meter.unbound, UnboundField{Document: document, Path: path, Status: record.Status})
		case "PENDING_FREEZE_AT_MEASUREMENT":
			meter.snapshots = append(meter.snapshots, UnboundField{Document: document, Path: path, Status: record.Status})
		case "OBSERVED", "PRD_VERBATIM", "PREREGISTERED_BY_DRIVER", "BOUND":
			// Complete to the current honest extent.
		default:
			meter.failures = append(meter.failures, fmt.Sprintf(
				"%s: field %q has unknown status %q", document, path, record.Status))
		}
	}
	sort.Slice(meter.unbound, func(i, j int) bool { return meter.unbound[i].Path < meter.unbound[j].Path })
	sort.Slice(meter.snapshots, func(i, j int) bool { return meter.snapshots[i].Path < meter.snapshots[j].Path })
	return meter, nil
}

// validateAgainstSchema validates one document against a schema in
// schemas/ and returns the flattened failure messages.
func validateAgainstSchema(root, document, schemaName string) ([]string, error) {
	schemaContent, err := os.ReadFile(filepath.Join(root, "schemas", schemaName))
	if err != nil {
		return nil, err
	}
	schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaContent))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	resourceURL := "https://verified-java-websocket-port.invalid/" + schemaName
	if err := compiler.AddResource(resourceURL, schemaValue); err != nil {
		return nil, err
	}
	schema, err := compiler.Compile(resourceURL)
	if err != nil {
		return nil, err
	}
	documentContent, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(document)))
	if err != nil {
		return nil, err
	}
	documentValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(documentContent))
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(documentValue); err != nil {
		if validationError, ok := err.(*jsonschema.ValidationError); ok {
			return flattenSchemaError(validationError), nil
		}
		return []string{err.Error()}, nil
	}
	return nil, nil
}

// ValidateSampleSetDocument validates one raw sample-set document (for
// example an engine-validation fixture) against the canonical raw-pair
// schema.
func ValidateSampleSetDocument(root, path string) ([]string, error) {
	return validateAgainstSchema(root, path, "benchmark-raw-sample-1.0.0.schema.json")
}

func flattenSchemaError(err *jsonschema.ValidationError) []string {
	var messages []string
	var walk func(node *jsonschema.ValidationError)
	walk = func(node *jsonschema.ValidationError) {
		if node == nil {
			return
		}
		if len(node.Causes) == 0 {
			messages = append(messages, node.Error())
			return
		}
		for _, cause := range node.Causes {
			walk(cause)
		}
	}
	walk(err)
	sort.Strings(messages)
	return messages
}
