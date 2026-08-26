package benchplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

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

// EnvironmentRoleByDocument is the filename-to-role contract: each
// environment document must declare exactly this role.
var EnvironmentRoleByDocument = map[string]string{
	"benchmarks/environments/primary-macos.json": "primary",
	"benchmarks/environments/confirmation.json":  "confirmation",
}

// EnvironmentIdentityByDocument is the stable document identity carried by
// every evidence receipt. It prevents a valid receipt for one environment
// from being substituted into the other role or document.
var EnvironmentIdentityByDocument = map[string]string{
	"benchmarks/environments/primary-macos.json": "primary-macos",
	"benchmarks/environments/confirmation.json":  "confirmation-linux-x86_64",
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

const (
	// PlanFreezeOwnerAttested is a valid, frozen preregistration. It is
	// deliberately not an independent-attestation claim; owner attestation is
	// the accepted US-008 assurance scope.
	PlanFreezeOwnerAttested = "OWNER_ATTESTED_NOT_INDEPENDENT"
	// canonicalWorkloadsProjectionDigest binds every field of all six workload
	// definitions, not merely their IDs and pair orders. The projection is the
	// SHA-256 of encoding/json's canonical object-key ordering for the workloads
	// array in benchmarks/plan/workloads.json.
	canonicalWorkloadsProjectionDigest = "sha256:8b15ef3dd3b92e1e404ae21cc2970d6b5c6608962d376c46868772f517e6991f"
)

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
	// PlanFreezeState is the plan's machine-readable preregistration freeze
	// state. It is independent of sample readiness.
	PlanFreezeState string
	// EnvironmentBindingStatus maps each environment document to its
	// declared binding_status (UNBOUND/BOUND).
	EnvironmentBindingStatus map[string]string
	BlockerClasses           []string
}

// planDocument is the subset of the plan the validator cross-checks
// against the frozen executable spec.
type planDocument struct {
	Schema            string `json:"schema"`
	Status            string `json:"status"`
	FreezeState       string `json:"freeze_state"`
	SharedDefinitions struct {
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
	EnvironmentID         string                      `json:"environment_id"`
	Role                  string                      `json:"role"`
	BindingStatus         string                      `json:"binding_status"`
	HostIdentity          map[string]environmentField `json:"host_identity"`
	RunPolicy             map[string]environmentField `json:"run_policy"`
	ToolIdentities        map[string]environmentField `json:"tool_identities"`
	RequiredBindingFields []string                    `json:"required_binding_fields"`
}

type environmentField struct {
	Status            string                    `json:"status"`
	Value             json.RawMessage           `json:"value"`
	ObservedByCommand string                    `json:"observed_by_command"`
	ObservedAt        string                    `json:"observed_at"`
	EvidenceDigest    string                    `json:"evidence_digest"`
	EvidenceReceipt   *evidenceReceiptReference `json:"evidence_receipt"`
}

// Verify validates every benchmark document against its schema, checks
// the plan against the frozen executable spec, verifies the power
// model, and walks each environment's required_binding_fields to build
// the completion meter. When everything driver-completable is complete,
// the only reported blocker class is HOST_BINDING_PENDING.
func Verify(root string) (Report, error) {
	return verify(root, false)
}

func verify(root string, allowTestOnlyReceipts bool) (Report, error) {
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

	planFailures, freezeState, err := verifyPlanAgainstSpec(root)
	if err != nil {
		return report, err
	}
	report.PlanFailures = planFailures
	report.PlanFreezeState = freezeState

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
		meter, err := environmentCompletionMeter(root, document, EnvironmentRoleByDocument[document], allowTestOnlyReceipts)
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
	// A valid owner-attested freeze completes the story-level preregistration.
	// Sample readiness is separate and remains blocked until both environments
	// are BOUND and every canonical field is semantically complete.
	bindingPending := false
	for _, bindingStatus := range report.EnvironmentBindingStatus {
		if bindingStatus != "BOUND" {
			bindingPending = true
		}
	}
	if len(report.UnboundFields) > 0 || bindingPending {
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

// FullyBound reports whether no blocker remains at all: the owner-attested
// preregistration is valid and every sample-readiness binding is complete.
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

	if plan.FreezeState != PlanFreezeOwnerAttested {
		fail("freeze_state %q is not the accepted owner-attested preregistration state", plan.FreezeState)
	}
	if !strings.HasPrefix(plan.Status, "PREREGISTERED_OWNER_ATTESTED_NOT_INDEPENDENT") {
		fail("freeze_state %s but status %q does not declare the owner-attested, non-independent scope", PlanFreezeOwnerAttested, plan.Status)
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
	var rawPlan struct {
		Workloads json.RawMessage `json:"workloads"`
	}
	if err := json.Unmarshal(content, &rawPlan); err != nil {
		return nil, "", fmt.Errorf("plan workload projection parse: %w", err)
	}
	var workloadProjection any
	if err := json.Unmarshal(rawPlan.Workloads, &workloadProjection); err != nil {
		return nil, "", fmt.Errorf("plan workload projection decode: %w", err)
	}
	canonicalProjection, err := json.Marshal(workloadProjection)
	if err != nil {
		return nil, "", fmt.Errorf("plan workload projection canonicalization: %w", err)
	}
	projectionDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(canonicalProjection))
	if projectionDigest != canonicalWorkloadsProjectionDigest {
		fail("workloads canonical projection digest %s disagrees with frozen %s (parameters/generators/input/output/rates/counts/durations/concurrency/pair rules are immutable)", projectionDigest, canonicalWorkloadsProjectionDigest)
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
	return failures, plan.FreezeState, nil
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
func environmentCompletionMeter(root, document, expectedRole string, allowTestOnlyReceipts bool) (meterResult, error) {
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
	if expectedID := EnvironmentIdentityByDocument[document]; environment.EnvironmentID != expectedID {
		meter.failures = append(meter.failures, fmt.Sprintf(
			"%s declares environment_id %q but the filename contract requires %q", document, environment.EnvironmentID, expectedID))
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
	validated := map[string]bool{}
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
			if failures := validateBindingField(root, document, environment.EnvironmentID, expectedRole, path, record, allowTestOnlyReceipts); len(failures) > 0 {
				for _, failure := range failures {
					meter.failures = append(meter.failures, fmt.Sprintf("%s: field %q %s", document, path, failure))
				}
			}
			validated[path] = true
		default:
			meter.failures = append(meter.failures, fmt.Sprintf(
				"%s: field %q has unknown status %q", document, path, record.Status))
		}
	}
	// Every BOUND host/tool identity must carry evidence, including
	// supplemental pipeline pins that are not sample-readiness fields.
	for _, sectionName := range []string{"host_identity", "tool_identities"} {
		fields := sections[sectionName]
		names := make([]string, 0, len(fields))
		for name := range fields {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			path := sectionName + "." + name
			record := fields[name]
			if record.Status != "BOUND" || validated[path] {
				continue
			}
			for _, failure := range validateBindingField(root, document, environment.EnvironmentID, expectedRole, path, record, allowTestOnlyReceipts) {
				meter.failures = append(meter.failures, fmt.Sprintf("%s: field %q %s", document, path, failure))
			}
		}
	}
	sort.Slice(meter.unbound, func(i, j int) bool { return meter.unbound[i].Path < meter.unbound[j].Path })
	sort.Slice(meter.snapshots, func(i, j int) bool { return meter.snapshots[i].Path < meter.snapshots[j].Path })
	return meter, nil
}

var (
	instanceIDPattern       = regexp.MustCompile(`^i-[0-9a-f]{17}$`)
	availabilityZonePattern = regexp.MustCompile(`^us-east-1[a-z]$`)
	clocksourcePattern      = regexp.MustCompile(`^[a-z0-9_-]+$`)
)

type toolIdentityEvidence struct {
	Kind       string `json:"kind"`
	Identity   string `json:"identity"`
	Platform   string `json:"platform"`
	Digest     string `json:"digest"`
	Provenance string `json:"provenance"`
}

func validateBindingField(root, document, environmentID, role, path string, field environmentField, allowTestOnlyReceipts bool) []string {
	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }
	if len(field.Value) == 0 || bytes.Equal(bytes.TrimSpace(field.Value), []byte("null")) {
		fail("has status %s without a value", field.Status)
		return failures
	}
	if field.Status == "BOUND" {
		var receiptFailures []string
		_, receiptFailures = validateBindingReceipt(root, document, environmentID, role, path, field, allowTestOnlyReceipts)
		failures = append(failures, receiptFailures...)
		if !validDigest(field.EvidenceDigest) {
			fail("BOUND identity requires a nonzero sha256 evidence_digest")
		}
	}

	var value any
	if err := json.Unmarshal(field.Value, &value); err != nil {
		fail("has malformed value: %v", err)
		return failures
	}
	stringValue, _ := value.(string)
	if field.Status == "BOUND" && containsPlaceholderIdentity(value) {
		fail("contains an obvious placeholder identity")
	}
	positiveInteger := func() bool {
		number, ok := value.(float64)
		return ok && number > 0 && number == math.Trunc(number)
	}

	if strings.HasPrefix(path, "tool_identities.") {
		name := strings.TrimPrefix(path, "tool_identities.")
		if field.Status != "BOUND" {
			return failures
		}
		if ownerAttestedReceiptFields[role+"|"+path] {
			if strings.TrimSpace(stringValue) == "" {
				fail("owner-attested pipeline identity must be a nonempty string")
			}
			return failures
		}
		if name == "java_executable_digest" || name == "rust_executable_digest" {
			if !validDigest(stringValue) {
				fail("must be a nonzero sha256 executable digest")
			}
			return failures
		}
		var evidence toolIdentityEvidence
		if err := json.Unmarshal(field.Value, &evidence); err != nil || evidence.Kind != name || strings.TrimSpace(evidence.Identity) == "" || !validDigest(evidence.Digest) || strings.TrimSpace(evidence.Provenance) == "" {
			fail("must be an object whose kind matches the field, with nonempty identity/provenance and a nonzero sha256 digest")
		}
		expectedPlatform := "aarch64-apple-darwin"
		if role == "confirmation" {
			expectedPlatform = "x86_64-unknown-linux-gnu"
		}
		if evidence.Platform != expectedPlatform {
			fail("tool platform %q must equal the %s environment platform %q", evidence.Platform, role, expectedPlatform)
		}
		return failures
	}

	if role == "primary" {
		switch path {
		case "host_identity.cpu_logical_cores", "host_identity.cpu_performance_cores", "host_identity.cpu_efficiency_cores", "host_identity.memory_total_bytes":
			if !positiveInteger() {
				fail("must be a positive integer")
			}
		default:
			if stringValue == "" {
				fail("must be a nonempty string")
			}
		}
		if field.Status == "BOUND" && (strings.TrimSpace(field.ObservedByCommand) == "" || strings.TrimSpace(field.ObservedAt) == "") {
			fail("BOUND primary identity requires observed_by_command and observed_at")
		}
		return failures
	}

	switch path {
	case "host_identity.instance_type":
		if stringValue != "c7i.xlarge" {
			fail("must equal the frozen Tier-1 class c7i.xlarge")
		}
	case "host_identity.instance_id":
		if !instanceIDPattern.MatchString(stringValue) {
			fail("must be a concrete EC2 instance id")
		}
	case "host_identity.observed_architecture":
		if stringValue != "x86_64" {
			fail("must equal x86_64")
		}
	case "host_identity.allocation_evidence":
		var evidence struct {
			Method        string `json:"method"`
			ObservedValue string `json:"observed_value"`
			ObservedAtUTC string `json:"observed_at_utc"`
		}
		if err := json.Unmarshal(field.Value, &evidence); err != nil || evidence.Method == "" || evidence.ObservedValue == "" || evidence.ObservedAtUTC == "" {
			fail("must record method, observed_value, and observed_at_utc")
		}
	case "host_identity.region":
		if stringValue != "us-east-1" {
			fail("must equal the frozen region us-east-1")
		}
	case "host_identity.availability_zone":
		if !availabilityZonePattern.MatchString(stringValue) {
			fail("must be an us-east-1 availability zone")
		}
	case "host_identity.ami_id":
		if stringValue != "ami-02b3d83d84b07786d" {
			fail("must equal the frozen AMI ami-02b3d83d84b07786d")
		}
	case "host_identity.ami_name":
		if stringValue != "al2023-ami-2023.12.20260817.0-kernel-6.1-x86_64" {
			fail("must equal the frozen AMI name")
		}
	case "host_identity.memory_total_bytes":
		if !positiveInteger() {
			fail("must be a positive integer byte count")
		}
	case "host_identity.clocksource":
		if !clocksourcePattern.MatchString(stringValue) {
			fail("must be a concrete clocksource identifier")
		}
	default:
		if stringValue == "" {
			fail("must be a nonempty typed identity string")
		}
	}
	return failures
}

func validDigest(value string) bool {
	return digestPattern.MatchString(value) && value != zeroDigest
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

// ValidateEvidenceBundleDocument validates a future complete bundle manifest.
func ValidateEvidenceBundleDocument(root, path string) ([]string, error) {
	return validateAgainstSchema(root, path, "benchmark-evidence-bundle-1.0.0.schema.json")
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
