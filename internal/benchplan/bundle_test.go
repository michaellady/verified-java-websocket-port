package benchplan

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceBundleManifestSchema(t *testing.T) {
	root := copyBenchmarkTree(t)
	bundle, _, _ := completeSyntheticBundle(t)
	path := filepath.Join(root, "bundle.json")
	writeJSON(t, path, bundle)
	failures, err := ValidateEvidenceBundleDocument(root, "bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 0 {
		t.Fatalf("complete bundle manifest failed schema: %v", failures)
	}
	bundle.ProvenanceLabel = LabelSynthetic
	writeJSON(t, path, bundle)
	failures, err = ValidateEvidenceBundleDocument(root, "bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) == 0 {
		t.Fatal("future evidence bundle schema must reject synthetic provenance")
	}
}

func completeSyntheticBundle(t *testing.T) (EvidenceBundle, map[string][]byte, BoundIdentities) {
	t.Helper()
	bundle := EvidenceBundle{Schema: EvidenceBundleSchema, ProvenanceLabel: LabelMeasured, EnvironmentRole: EnvironmentRolePrimary}
	records := map[string][]byte{}
	bound := syntheticClosure()
	for _, workload := range WorkloadIDs {
		order, err := PairOrder(workload)
		if err != nil {
			t.Fatal(err)
		}
		for _, metric := range MetricNames {
			java, rust := 2.0, 1.0
			if metric == "throughput" {
				java, rust = 1.0, 2.0
			}
			set := SampleSet{
				Schema:          "vjwp-benchmark-raw-sample/1.0.0",
				ProvenanceLabel: LabelMeasured,
				EnvironmentRole: EnvironmentRolePrimary,
				WorkloadID:      workload,
				Metric:          metric,
				Order:           order,
				WarmupPairs:     make([]Pair, WarmupPairs),
				MeasuredPairs:   make([]Pair, MeasuredPairs),
				Bindings:        map[string]string{},
			}
			for name, digest := range bound {
				set.Bindings[name] = digest
			}
			observations := cleanObservations()
			set.RunValidity = &observations
			for i := range set.WarmupPairs {
				set.WarmupPairs[i] = Pair{Java: java, Rust: rust}
			}
			for i := range set.MeasuredPairs {
				set.MeasuredPairs[i] = Pair{Java: java, Rust: rust}
			}
			raw, err := json.Marshal(set)
			if err != nil {
				t.Fatal(err)
			}
			digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
			if _, duplicate := records[digest]; duplicate {
				t.Fatalf("test construction produced duplicate digest %s", digest)
			}
			records[digest] = raw
			bundle.Endpoints = append(bundle.Endpoints, EvidenceEndpoint{WorkloadID: workload, Metric: metric, RawRecordDigest: digest})
		}
	}
	return bundle, records, bound
}

func TestCompleteEvidenceBundleDecidesAllSixtyEndpoints(t *testing.T) {
	bundle, records, bound := completeSyntheticBundle(t)
	decision := DecideEvidenceBundle(bundle, records, bound)
	if decision.Outcome != OutcomeThresholdMet {
		t.Fatalf("outcome %s: %v", decision.Outcome, decision.Reasons)
	}
	if len(decision.EndpointDecisions) != len(WorkloadIDs)*len(MetricNames) {
		t.Fatalf("got %d endpoint decisions, want 60", len(decision.EndpointDecisions))
	}
}

func TestEvidenceBundleRejectsDuplicateExtraMissingAndUnboundRawRecords(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*EvidenceBundle, map[string][]byte)
		want   string
	}{
		{"missing endpoint", func(bundle *EvidenceBundle, _ map[string][]byte) { bundle.Endpoints = bundle.Endpoints[1:] }, "missing 1 endpoint"},
		{"duplicate endpoint", func(bundle *EvidenceBundle, _ map[string][]byte) { bundle.Endpoints[1] = bundle.Endpoints[0] }, "duplicate endpoint"},
		{"extra endpoint", func(bundle *EvidenceBundle, _ map[string][]byte) { bundle.Endpoints[0].Metric = "post_hoc_metric" }, "extra endpoint"},
		{"missing raw record", func(bundle *EvidenceBundle, records map[string][]byte) {
			delete(records, bundle.Endpoints[0].RawRecordDigest)
		}, "is missing"},
		{"digest mismatch", func(bundle *EvidenceBundle, records map[string][]byte) {
			records[bundle.Endpoints[0].RawRecordDigest] = []byte(`{}`)
		}, "raw bytes digest"},
		{"extra raw record", func(_ *EvidenceBundle, records map[string][]byte) {
			records[syntheticDigest("extra-record")] = []byte(`{}`)
		}, "unmanifested raw record"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			bundle, records, bound := completeSyntheticBundle(t)
			testCase.mutate(&bundle, records)
			decision := DecideEvidenceBundle(bundle, records, bound)
			if decision.Outcome != OutcomeBlocked || !strings.Contains(strings.Join(decision.Reasons, "\n"), testCase.want) {
				t.Fatalf("outcome %s reasons %v, want BLOCKED containing %q", decision.Outcome, decision.Reasons, testCase.want)
			}
		})
	}
}
