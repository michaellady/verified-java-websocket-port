package benchplan

import (
	"errors"
	"os"
)

const ResourceEnvelopeDecisionSchema = "vjwp-benchmark-resource-envelope-decision/1.0.0"

const (
	MechanicsPassOwnerRelaxed       = "PASS_OWNER_RELAXED_MECHANICS"
	MechanicsBlocked                = "BLOCKED"
	MeasurementInconclusiveBlocked  = "INCONCLUSIVE_BLOCKED"
	HostNotBound                    = "NOT_BOUND"
	IndependentRecomputeNotExecuted = "NOT_EXECUTED"
	RawAbsent                       = "ABSENT"
	RawPresentPartial               = "PRESENT_PARTIAL"
	RawPresentComplete              = "PRESENT_COMPLETE"
	RawPresentInvalid               = "PRESENT_INVALID"
	ReasonRawAbsent                 = "RAW_ABSENT"
	ReasonRawPartial                = "RAW_PRESENT_PARTIAL"
	ReasonRawInvalid                = "RAW_PRESENT_INVALID"
	ReasonHostNotBound              = "HOST_NOT_BOUND"
)

type MeasurementDecision string

const (
	MeasurementThresholdMet    MeasurementDecision = "THRESHOLD_MET"
	MeasurementThresholdNotMet MeasurementDecision = "THRESHOLD_NOT_MET"
	MeasurementInconclusive    MeasurementDecision = "INCONCLUSIVE"
)

type ValidationState string

const (
	ValidationValid   ValidationState = "VALID"
	ValidationBlocked ValidationState = "BLOCKED"
)

type EnvelopeEndpointDecision struct {
	Metric      string              `json:"metric"`
	Decision    MeasurementDecision `json:"decision"`
	Validation  ValidationState     `json:"validation"`
	ReasonCodes []string            `json:"reason_codes"`
}

type HostWorkloadDecision struct {
	EnvironmentRole   string                     `json:"environment_role"`
	WorkloadID        string                     `json:"workload_id"`
	Decision          MeasurementDecision        `json:"decision"`
	Validation        ValidationState            `json:"validation"`
	EndpointDecisions []EnvelopeEndpointDecision `json:"endpoint_decisions"`
	ReasonCodes       []string                   `json:"reason_codes"`
}

type ResourceEnvelopeDecision struct {
	Schema                   string                 `json:"schema"`
	MechanicsStatus          string                 `json:"mechanics_status"`
	MeasurementAcceptance    string                 `json:"measurement_acceptance"`
	PerformanceClaimed       bool                   `json:"performance_claimed"`
	PrimaryHost              string                 `json:"primary_host"`
	ConfirmationHost         string                 `json:"confirmation_host"`
	SamplesAuthorized        bool                   `json:"samples_authorized"`
	RawState                 map[string]string      `json:"raw_state"`
	Workloads                []HostWorkloadDecision `json:"workloads"`
	IndependentRecompute     string                 `json:"independent_recompute"`
	Assurance                string                 `json:"assurance"`
	IndependentReviewClaimed bool                   `json:"independent_review_claimed"`
	Blockers                 []string               `json:"blockers"`
	Nonclaims                []string               `json:"nonclaims"`
}

var resourceEnvelopeBlockers = []string{
	"PRIMARY_NATIVE_HOST_NOT_BOUND",
	"CONFIRMATION_LINUX_HOST_NOT_BOUND",
	"SAMPLES_NOT_AUTHORIZED_OR_COLLECTED",
	"DUAL_HOST_30_PAIR_EVIDENCE_NOT_EXECUTED",
	"RESOURCE_THRESHOLDS_NOT_DECIDED",
	"FD_AND_JAVA_GC_OBSERVATIONS_NOT_COLLECTED",
	"INDEPENDENT_ANALYZER_REBUILD_NOT_EXECUTED",
	"PROVENANCE_DISTINCT_RECOMPUTATION_NOT_EXECUTED",
	"PERFORMANCE_TUNING_AND_AFFECTED_GATE_RERUNS_NOT_EXECUTED",
}

var resourceEnvelopeNonclaims = []string{
	"no memory, CPU, startup, latency, allocation, throughput, or power result",
	"no clean measured environment or dual-host confirmation",
	"no independent review or provenance-distinct recomputation",
	"no publication, signing, production readiness, or cutover readiness",
}

func newResourceEnvelopeDecision() ResourceEnvelopeDecision {
	decision := ResourceEnvelopeDecision{
		Schema:                   ResourceEnvelopeDecisionSchema,
		MechanicsStatus:          MechanicsBlocked,
		MeasurementAcceptance:    MeasurementInconclusiveBlocked,
		PerformanceClaimed:       false,
		PrimaryHost:              HostNotBound,
		ConfirmationHost:         HostNotBound,
		SamplesAuthorized:        false,
		RawState:                 map[string]string{},
		IndependentRecompute:     IndependentRecomputeNotExecuted,
		Assurance:                PlanFreezeOwnerAttested,
		IndependentReviewClaimed: false,
		Blockers:                 append([]string(nil), resourceEnvelopeBlockers...),
		Nonclaims:                append([]string(nil), resourceEnvelopeNonclaims...),
	}
	for _, role := range []string{EnvironmentRolePrimary, EnvironmentRoleConfirmation} {
		for _, workloadID := range WorkloadIDs {
			workload := HostWorkloadDecision{
				EnvironmentRole: role,
				WorkloadID:      workloadID,
				Decision:        MeasurementInconclusive,
				Validation:      ValidationBlocked,
				ReasonCodes:     []string{ReasonRawAbsent},
			}
			for _, metric := range MetricNames {
				workload.EndpointDecisions = append(workload.EndpointDecisions, EnvelopeEndpointDecision{
					Metric:      metric,
					Decision:    MeasurementInconclusive,
					Validation:  ValidationBlocked,
					ReasonCodes: []string{ReasonRawAbsent},
				})
			}
			decision.Workloads = append(decision.Workloads, workload)
		}
	}
	return decision
}

// DecideResourceEnvelope enumerates the complete frozen campaign before it
// inspects raw evidence. It never measures, binds a host, or authorizes a
// sample; current absent evidence therefore remains a typed blocked decision.
func DecideResourceEnvelope(root string) (ResourceEnvelopeDecision, error) {
	return decideResourceEnvelopeWithExpected(root, nil)
}

func decideResourceEnvelopeWithExpected(root string, expected *BindingClosure) (ResourceEnvelopeDecision, error) {
	decision := newResourceEnvelopeDecision()
	report, err := Verify(root)
	if err != nil {
		return decision, err
	}
	if report.HostBindingIsOnlyBlocker() || report.FullyBound() {
		decision.MechanicsStatus = MechanicsPassOwnerRelaxed
	}
	repository, err := openSecureLedgerRepository(root, false)
	if err != nil {
		return decision, err
	}
	defer repository.close()
	for _, role := range []string{EnvironmentRolePrimary, EnvironmentRoleConfirmation} {
		document := "benchmarks/environments/primary-macos.json"
		if role == EnvironmentRoleConfirmation {
			document = "benchmarks/environments/confirmation.json"
		}
		state, err := classifyRawLedger(repository, role, expected, report.EnvironmentBindingStatus[document] == "BOUND")
		if err != nil {
			return decision, err
		}
		decision.RawState[role] = state
		switch state {
		case RawPresentPartial:
			setRoleRawReason(&decision, role, ReasonRawPartial)
		case RawPresentComplete:
			setRoleRawReason(&decision, role, ReasonHostNotBound)
		case RawPresentInvalid:
			setRoleRawReason(&decision, role, ReasonRawInvalid)
		}
	}
	return decision, nil
}

func classifyRawLedger(repository *secureLedgerRepository, role string, expected *BindingClosure, hostBound bool) (string, error) {
	if repository.raw == nil {
		return RawAbsent, nil
	}
	filename, err := ledgerFilename(role)
	if err != nil {
		return "", err
	}
	info, err := repository.raw.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return RawAbsent, nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return RawPresentInvalid, nil
	}
	if expected == nil {
		return RawPresentInvalid, nil
	}
	file, err := openHeldRegular(repository.raw, filename, os.O_RDONLY, 0)
	if err != nil {
		return RawPresentInvalid, nil
	}
	receipt, err := verifyHeldRawLedger(file, role, *expected)
	closeErr := file.Close()
	if err != nil {
		return RawPresentInvalid, nil
	}
	if closeErr != nil {
		return "", closeErr
	}
	if receipt.State == RawPresentPartial {
		if !hostBound && receipt.RecordCount > 1 {
			return RawPresentInvalid, nil
		}
		return RawPresentPartial, nil
	}
	if !hostBound {
		return RawPresentInvalid, nil
	}
	// A future bound-host phase must also supply an independently derived
	// closure before measurement acceptance. Mechanics never treats raw bytes
	// as their own bound identity source.
	return RawPresentInvalid, nil
}

func setRoleRawReason(decision *ResourceEnvelopeDecision, role, reason string) {
	for i := range decision.Workloads {
		if decision.Workloads[i].EnvironmentRole != role {
			continue
		}
		decision.Workloads[i].ReasonCodes = []string{reason}
		for j := range decision.Workloads[i].EndpointDecisions {
			decision.Workloads[i].EndpointDecisions[j].ReasonCodes = []string{reason}
		}
	}
}
