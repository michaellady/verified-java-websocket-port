package benchplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

const EvidenceBundleSchema = "vjwp-benchmark-evidence-bundle/1.0.0"

type EvidenceEndpoint struct {
	WorkloadID      string `json:"workload_id"`
	Metric          string `json:"metric"`
	RawRecordDigest string `json:"raw_record_digest"`
}

type EvidenceBundle struct {
	Schema          string             `json:"schema"`
	ProvenanceLabel string             `json:"provenance_label"`
	EnvironmentRole string             `json:"environment_role"`
	Endpoints       []EvidenceEndpoint `json:"endpoints"`
}

type BundleDecision struct {
	Outcome           Outcome
	Reasons           []string
	EndpointDecisions map[string]Decision
}

// DecideEvidenceBundle verifies a complete future evidence bundle and then
// aggregates its endpoint decisions. Exactly one endpoint must exist for each
// frozen workload x metric pair. Every manifest digest must bind the exact raw
// record bytes supplied under the same digest; missing, duplicate, extra, or
// content-mismatched records block the bundle before statistics are considered.
func DecideEvidenceBundle(bundle EvidenceBundle, rawRecords map[string][]byte, bound BoundIdentities) BundleDecision {
	decision := BundleDecision{EndpointDecisions: map[string]Decision{}}
	block := func(format string, args ...any) {
		decision.Outcome = OutcomeBlocked
		decision.Reasons = append(decision.Reasons, fmt.Sprintf(format, args...))
	}
	if bundle.Schema != EvidenceBundleSchema {
		block("bundle schema %q is not %q", bundle.Schema, EvidenceBundleSchema)
		return decision
	}
	if bundle.ProvenanceLabel != LabelMeasured {
		block("complete evidence bundle provenance must be %s, got %q", LabelMeasured, bundle.ProvenanceLabel)
		return decision
	}
	if bundle.EnvironmentRole != EnvironmentRolePrimary && bundle.EnvironmentRole != EnvironmentRoleConfirmation {
		block("bundle environment role %q is not preregistered", bundle.EnvironmentRole)
		return decision
	}

	expected := map[string]bool{}
	for _, workload := range WorkloadIDs {
		for _, metric := range MetricNames {
			expected[endpointKey(workload, metric)] = true
		}
	}
	seenEndpoints := map[string]bool{}
	seenDigests := map[string]bool{}
	for _, endpoint := range bundle.Endpoints {
		key := endpointKey(endpoint.WorkloadID, endpoint.Metric)
		if !expected[key] {
			block("extra endpoint %s", key)
			continue
		}
		if seenEndpoints[key] {
			block("duplicate endpoint %s", key)
			continue
		}
		seenEndpoints[key] = true
		if !validDigest(endpoint.RawRecordDigest) {
			block("endpoint %s has invalid raw_record_digest %q", key, endpoint.RawRecordDigest)
			continue
		}
		if seenDigests[endpoint.RawRecordDigest] {
			block("raw record digest %s is bound by more than one endpoint", endpoint.RawRecordDigest)
			continue
		}
		seenDigests[endpoint.RawRecordDigest] = true
		raw, present := rawRecords[endpoint.RawRecordDigest]
		if !present {
			block("endpoint %s raw record %s is missing", key, endpoint.RawRecordDigest)
			continue
		}
		actualDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
		if actualDigest != endpoint.RawRecordDigest {
			block("endpoint %s raw bytes digest to %s, not manifest binding %s", key, actualDigest, endpoint.RawRecordDigest)
			continue
		}
		var sample SampleSet
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&sample); err != nil {
			block("endpoint %s raw record decode failed: %v", key, err)
			continue
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			block("endpoint %s raw record contains trailing JSON", key)
			continue
		}
		if sample.WorkloadID != endpoint.WorkloadID || sample.Metric != endpoint.Metric {
			block("endpoint %s manifest identity disagrees with raw record %s", key, endpointKey(sample.WorkloadID, sample.Metric))
			continue
		}
		if sample.Schema != "vjwp-benchmark-raw-sample/1.0.0" {
			block("endpoint %s raw record schema %q is not canonical", key, sample.Schema)
			continue
		}
		if sample.ProvenanceLabel != LabelMeasured || sample.EnvironmentRole != bundle.EnvironmentRole {
			block("endpoint %s raw record provenance/role %s/%s disagrees with bundle %s/%s", key, sample.ProvenanceLabel, sample.EnvironmentRole, bundle.ProvenanceLabel, bundle.EnvironmentRole)
			continue
		}
		decision.EndpointDecisions[key] = DecideEndpoint(sample, bound)
	}

	var missing []string
	for key := range expected {
		if !seenEndpoints[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		block("bundle is missing %d endpoint(s): %v", len(missing), missing)
	}
	var extraDigests []string
	for digest := range rawRecords {
		if !seenDigests[digest] {
			extraDigests = append(extraDigests, digest)
		}
	}
	sort.Strings(extraDigests)
	for _, digest := range extraDigests {
		block("unmanifested raw record %s is extra", digest)
	}
	if decision.Outcome == OutcomeBlocked {
		return decision
	}

	decision.Outcome = OutcomeThresholdMet
	for _, workload := range WorkloadIDs {
		for _, metric := range MetricNames {
			key := endpointKey(workload, metric)
			endpointDecision := decision.EndpointDecisions[key]
			switch endpointDecision.Outcome {
			case OutcomeBlocked:
				decision.Outcome = OutcomeBlocked
				decision.Reasons = append(decision.Reasons, fmt.Sprintf("%s: %v", key, endpointDecision.Reasons))
			case OutcomeInconclusive:
				if decision.Outcome != OutcomeBlocked {
					decision.Outcome = OutcomeInconclusive
				}
				decision.Reasons = append(decision.Reasons, fmt.Sprintf("%s: %v", key, endpointDecision.Reasons))
			case OutcomeThresholdNotMet:
				if decision.Outcome == OutcomeThresholdMet {
					decision.Outcome = OutcomeThresholdNotMet
				}
				decision.Reasons = append(decision.Reasons, fmt.Sprintf("%s: threshold not met", key))
			}
		}
	}
	return decision
}

func endpointKey(workload, metric string) string {
	return workload + "x" + metric
}
