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
	// PlanAttestationState is the plan's machine-readable attestation
	// state (UNATTESTED until the owner's independent attestation).
	PlanAttestationState string
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
	AttestationState  string `json:"attestation_state"`
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
		unbound, snapshots, bindingStatus, err := environmentCompletionMeter(root, document)
		if err != nil {
			return report, err
		}
		report.UnboundFields = append(report.UnboundFields, unbound...)
		report.RuntimeSnapshotFields = append(report.RuntimeSnapshotFields, snapshots...)
		report.EnvironmentBindingStatus[document] = bindingStatus
		// A document may not claim BOUND while any of its required
		// binding fields is still pending (fail-closed consistency).
		if bindingStatus == "BOUND" && len(unbound) > 0 {
			report.PlanFailures = append(report.PlanFailures, fmt.Sprintf(
				"%s declares binding_status BOUND while %d required binding field(s) are still unbound", document, len(unbound)))
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
	// The owner-gated gap is host/tool binding AND its attestation:
	// syntactically complete field values with UNBOUND/UNATTESTED
	// status must never read as bound (review fix I5).
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

	switch plan.AttestationState {
	case "UNATTESTED":
		if !strings.HasPrefix(plan.Status, "PREREGISTERED_BY_DRIVER_UNATTESTED") {
			fail("attestation_state UNATTESTED but status %q does not declare it", plan.Status)
		}
	case "INDEPENDENTLY_ATTESTED":
		if !strings.HasPrefix(plan.Status, "PREREGISTERED_INDEPENDENTLY_ATTESTED") {
			fail("attestation_state INDEPENDENTLY_ATTESTED but status %q does not declare it", plan.Status)
		}
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

func environmentCompletionMeter(root, document string) (unbound, snapshots []UnboundField, bindingStatus string, err error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(document)))
	if err != nil {
		return nil, nil, "", err
	}
	var environment environmentDocument
	if err := json.Unmarshal(content, &environment); err != nil {
		return nil, nil, "", fmt.Errorf("%s parse: %w", document, err)
	}
	sections := map[string]map[string]environmentField{
		"host_identity":   environment.HostIdentity,
		"run_policy":      environment.RunPolicy,
		"tool_identities": environment.ToolIdentities,
	}
	for _, path := range environment.RequiredBindingFields {
		section, field, found := strings.Cut(path, ".")
		records := sections[section]
		if !found || records == nil {
			return nil, nil, "", fmt.Errorf("%s: required binding field %q references an unknown section", document, path)
		}
		record, present := records[field]
		if !present {
			return nil, nil, "", fmt.Errorf("%s: required binding field %q has no field record", document, path)
		}
		switch record.Status {
		case "OWNER_DECISION_PENDING", "NOT_MEASURED":
			unbound = append(unbound, UnboundField{Document: document, Path: path, Status: record.Status})
		case "PENDING_FREEZE_AT_MEASUREMENT":
			snapshots = append(snapshots, UnboundField{Document: document, Path: path, Status: record.Status})
		case "OBSERVED", "PRD_VERBATIM", "PREREGISTERED_BY_DRIVER", "BOUND":
			// Complete to the current honest extent.
		default:
			return nil, nil, "", fmt.Errorf("%s: field %q has unknown status %q", document, path, record.Status)
		}
	}
	sort.Slice(unbound, func(i, j int) bool { return unbound[i].Path < unbound[j].Path })
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].Path < snapshots[j].Path })
	return unbound, snapshots, environment.BindingStatus, nil
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
