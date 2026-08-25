package securitygate

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

const (
	acceptedJavaRoot   = "sha256:5713245496362ece061c769bc4ee8eb909bfcc6d7d319bc3fc9b750f6e0a4ad8"
	originalPlan       = "sha256:53a10ae09a728b63471e5298be777c5e86a5b2f525b43ce247787df9e2139173"
	originalReceipt    = "sha256:ca942585442eb4be74a62533fa2b44a985970612ce6f69d5c13df8ede83c6cff"
	remediationPlan    = "sha256:a94500dee3959f14941a749e04fe53b4679dd84041449e45a22572fb296a56f5"
	remediationReceipt = "sha256:ebb5157aa8ba6c7998dfce303acfbd5c4af166a8d377441e0709b481c26e44b2"
)

type autobahnClosure struct {
	OriginalReceiptDigests             []string
	RemediationReceiptDigests          []string
	ConsumedRemediationAttemptsPerMode int
	FurtherRerunsAuthorized            bool
}

type retainedAutobahnClosure struct {
	Status           string              `json:"status"`
	Client           retainedAutobahnRun `json:"client"`
	Server           retainedAutobahnRun `json:"server"`
	RerunDisposition struct {
		Authorized       int    `json:"authorized_remediation_attempts_per_mode"`
		Consumed         int    `json:"consumed_remediation_attempts_per_mode"`
		OriginalRetained bool   `json:"original_receipt_retained"`
		Further          bool   `json:"further_reruns_authorized"`
		Disposition      string `json:"disposition"`
	} `json:"rerun_disposition"`
}

type retainedAutobahnRun struct {
	AttemptCount int                       `json:"attempt_count"`
	Attempts     []retainedAutobahnAttempt `json:"attempts"`
}

type retainedAutobahnAttempt struct {
	Sequence       int    `json:"sequence"`
	Classification string `json:"classification"`
	PlanDigest     string `json:"plan_digest"`
	ReceiptDigest  string `json:"receipt_digest"`
	ReceiptBytes   int    `json:"receipt_bytes"`
	Executed       bool   `json:"executed"`
	Completed      bool   `json:"completed"`
	CompletedCount int    `json:"completed_count"`
	ResultCount    int    `json:"result_count"`
}

func validateAutobahnClosure(snapshot map[string][]byte) (autobahnClosure, error) {
	documents := lab.BaselineEvidenceDocuments{
		Build:    snapshot[baselineEvidencePaths[0]],
		Adapter:  snapshot[baselineEvidencePaths[1]],
		Tests:    snapshot[baselineEvidencePaths[2]],
		Autobahn: snapshot[baselineEvidencePaths[3]],
		Ledger:   snapshot[baselineEvidencePaths[4]],
	}
	readiness, err := lab.VerifyBaselineEvidence(acceptedJavaRoot, documents)
	if err != nil {
		return autobahnClosure{}, fmt.Errorf("CANONICAL_EVIDENCE_MUTATION/REVOKE: retained baseline adapter rejected the one-read snapshot: %w", err)
	}
	if readiness.Status != "BLOCKED" {
		return autobahnClosure{}, errors.New("CANONICAL_EVIDENCE_MUTATION/REVOKE: retained baseline readiness changed")
	}
	var retained retainedAutobahnClosure
	if err := json.Unmarshal(documents.Autobahn, &retained); err != nil {
		return autobahnClosure{}, fmt.Errorf("CANONICAL_EVIDENCE_MUTATION/REVOKE: %w", err)
	}
	if retained.Status != "BLOCKED" || retained.RerunDisposition.Authorized != 1 || retained.RerunDisposition.Consumed != 1 || !retained.RerunDisposition.OriginalRetained || retained.RerunDisposition.Further || retained.RerunDisposition.Disposition != "NO_FURTHER_RERUNS_AUTHORIZED" {
		return autobahnClosure{}, errors.New("CANONICAL_EVIDENCE_MUTATION/REVOKE: no-rerun disposition changed")
	}
	for mode, run := range map[string]retainedAutobahnRun{"client": retained.Client, "server": retained.Server} {
		if run.AttemptCount != 2 || len(run.Attempts) != 2 {
			return autobahnClosure{}, fmt.Errorf("CANONICAL_EVIDENCE_MUTATION/REVOKE: %s attempt count changed", mode)
		}
		want := []struct {
			sequence             int
			class, plan, receipt string
		}{
			{1, "ORIGINAL_AUTHORITATIVE", originalPlan, originalReceipt},
			{2, "OWNER_AUTHORIZED_REMEDIATION", remediationPlan, remediationReceipt},
		}
		for index, attempt := range run.Attempts {
			expected := want[index]
			if attempt.Sequence != expected.sequence || attempt.Classification != expected.class || attempt.PlanDigest != expected.plan || attempt.ReceiptDigest != expected.receipt || attempt.ReceiptBytes <= 0 || attempt.Executed || attempt.Completed || attempt.CompletedCount != 0 || attempt.ResultCount != 0 {
				return autobahnClosure{}, fmt.Errorf("CANONICAL_EVIDENCE_MUTATION/REVOKE: %s attempt %d identity/disposition changed", mode, index+1)
			}
		}
	}
	return autobahnClosure{
		OriginalReceiptDigests:             []string{retained.Client.Attempts[0].ReceiptDigest, retained.Server.Attempts[0].ReceiptDigest},
		RemediationReceiptDigests:          []string{retained.Client.Attempts[1].ReceiptDigest, retained.Server.Attempts[1].ReceiptDigest},
		ConsumedRemediationAttemptsPerMode: retained.RerunDisposition.Consumed,
		FurtherRerunsAuthorized:            retained.RerunDisposition.Further,
	}, nil
}
