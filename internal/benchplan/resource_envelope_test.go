package benchplan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResourceEnvelopeEnumeratesCompleteAbsentMatrix(t *testing.T) {
	decision, err := DecideResourceEnvelope(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.MechanicsStatus != MechanicsPassOwnerRelaxed || decision.MeasurementAcceptance != MeasurementInconclusiveBlocked {
		t.Fatalf("statuses = %q/%q", decision.MechanicsStatus, decision.MeasurementAcceptance)
	}
	if decision.PrimaryHost != HostNotBound || decision.ConfirmationHost != HostNotBound || decision.SamplesAuthorized || decision.PerformanceClaimed {
		t.Fatalf("claim boundary widened: %+v", decision)
	}
	if decision.RawState[EnvironmentRolePrimary] != RawAbsent || decision.RawState[EnvironmentRoleConfirmation] != RawAbsent {
		t.Fatalf("raw states = %#v", decision.RawState)
	}
	if len(decision.Workloads) != 2*len(WorkloadIDs) {
		t.Fatalf("workloads = %d, want %d", len(decision.Workloads), 2*len(WorkloadIDs))
	}
	endpointCount := 0
	for i, workload := range decision.Workloads {
		wantRole := EnvironmentRolePrimary
		workloadIndex := i
		if i >= len(WorkloadIDs) {
			wantRole = EnvironmentRoleConfirmation
			workloadIndex -= len(WorkloadIDs)
		}
		wantWorkload := WorkloadIDs[workloadIndex]
		if workload.EnvironmentRole != wantRole || workload.WorkloadID != wantWorkload {
			t.Fatalf("workload %d identity = %s/%s, want %s/%s", i, workload.EnvironmentRole, workload.WorkloadID, wantRole, wantWorkload)
		}
		if workload.Decision != MeasurementInconclusive || workload.Validation != ValidationBlocked || len(workload.ReasonCodes) != 1 || workload.ReasonCodes[0] != ReasonRawAbsent {
			t.Fatalf("workload %d absent outcome = %+v", i, workload)
		}
		if len(workload.EndpointDecisions) != len(MetricNames) {
			t.Fatalf("workload %d endpoints = %d", i, len(workload.EndpointDecisions))
		}
		for j, endpoint := range workload.EndpointDecisions {
			if endpoint.Metric != MetricNames[j] || endpoint.Decision != MeasurementInconclusive || endpoint.Validation != ValidationBlocked || len(endpoint.ReasonCodes) != 1 || endpoint.ReasonCodes[0] != ReasonRawAbsent {
				t.Fatalf("workload %d endpoint %d = %+v", i, j, endpoint)
			}
			endpointCount++
		}
	}
	if endpointCount != 120 {
		t.Fatalf("endpoint count = %d, want 120", endpointCount)
	}
	root := copyBenchmarkTree(t)
	writeJSON(t, filepath.Join(root, "decision.json"), decision)
	failures, err := validateAgainstSchema(root, "decision.json", "benchmark-resource-envelope-decision-1.0.0.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 0 {
		t.Fatalf("resource-envelope decision schema failures: %v", failures)
	}
}

func TestResourceEnvelopeDistinguishesEmptyPartialAndUnboundCompleteRaw(t *testing.T) {
	root := copyBenchmarkTree(t)
	rawDirectory := filepath.Join(root, "benchmarks", "raw")
	if err := os.MkdirAll(rawDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(rawDirectory, "primary.jsonl")
	if err := os.WriteFile(primary, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	decision, err := DecideResourceEnvelope(root)
	if err != nil {
		t.Fatal(err)
	}
	if decision.RawState[EnvironmentRolePrimary] != RawPresentInvalid || decision.RawState[EnvironmentRoleConfirmation] != RawAbsent {
		t.Fatalf("empty/absent raw states = %#v", decision.RawState)
	}

	if err := os.Remove(primary); err != nil {
		t.Fatal(err)
	}
	appendClosure(t, primary, EnvironmentRolePrimary, syntheticLedgerClosure(t))
	decision, err = DecideResourceEnvelope(root)
	if err != nil {
		t.Fatal(err)
	}
	if decision.RawState[EnvironmentRolePrimary] != RawPresentPartial {
		t.Fatalf("partial raw state = %q", decision.RawState[EnvironmentRolePrimary])
	}
	for _, workload := range decision.Workloads[:len(WorkloadIDs)] {
		if len(workload.ReasonCodes) != 1 || workload.ReasonCodes[0] != ReasonRawPartial {
			t.Fatalf("partial workload reason = %+v", workload)
		}
	}

	if err := os.Remove(primary); err != nil {
		t.Fatal(err)
	}
	appendCompletePrimaryLedger(t, primary, nil)
	decision, err = DecideResourceEnvelope(root)
	if err != nil {
		t.Fatal(err)
	}
	if decision.RawState[EnvironmentRolePrimary] != RawPresentInvalid {
		t.Fatalf("sample-bearing ledger on NOT_BOUND host state = %q, want %q", decision.RawState[EnvironmentRolePrimary], RawPresentInvalid)
	}
	if decision.MeasurementAcceptance != MeasurementInconclusiveBlocked || decision.PerformanceClaimed {
		t.Fatalf("unbound complete ledger widened claim: %+v", decision)
	}
}
