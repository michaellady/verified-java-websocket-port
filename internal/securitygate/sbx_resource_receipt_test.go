package securitygate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSupervisorObservationRejectsMissingRegressionAndDigestDrift(t *testing.T) {
	request := testSbxExecutionRequest(t)
	profile, err := loadSbxExecutionProfile(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	receipt := testSbxReceipt(t, request)
	if err := validateSbxExecutionReceipt(profile, request, receipt); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name string
		edit func(*SbxExecutionReceipt)
	}{
		{"preflight-missing", func(r *SbxExecutionReceipt) { r.SupervisorObservation.CapabilityPreflight.CgroupKill = "" }},
		{"counter-regression", func(r *SbxExecutionReceipt) {
			r.SupervisorObservation.CgroupFinal.CPUUsageUsec = r.SupervisorObservation.CgroupInitial.CPUUsageUsec - 1
		}},
		{"supervisor-digest-drift", func(r *SbxExecutionReceipt) { r.SupervisorObservation.SupervisorDigestReopened = digestOf("drift") }},
		{"cleanup-procs-not-empty", func(r *SbxExecutionReceipt) { r.SupervisorObservation.Cleanup.CgroupProcsReopened = "4242" }},
		{"fd-semantics-overclaim", func(r *SbxExecutionReceipt) { r.SupervisorObservation.Identity.FDSemantics = "aggregate tree hard cap" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			bad := receipt
			mutation.edit(&bad)
			if err := validateSbxExecutionReceipt(profile, request, bad); err == nil {
				t.Fatal("invalid supervisor observation accepted")
			}
		})
	}
}

func TestSupervisorReceiptStrictDecodeRejectsWorkloadBooleanEvidence(t *testing.T) {
	request := testSbxExecutionRequest(t)
	receipt := testSbxReceipt(t, request)
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"termination":"EXITED"`), []byte(`"termination":"EXITED","supervisor_limits_applied":true`), 1)
	if _, err := DecodeSbxExecutionReceipt(raw); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("boolean evidence decode err=%v", err)
	}
}

func TestRunControlledCanaryRemainsUnconditionallyProtected(t *testing.T) {
	request := testSbxExecutionRequest(t)
	if _, err := RunControlledCanary(t.Context(), CanaryRequest{RootPath: repoRoot(t), Execution: request}); err == nil || !strings.Contains(err.Error(), "PROTECTED_CALLER_REQUIRED/BLOCK") {
		t.Fatalf("candidate obtained launcher authority: %v", err)
	}
}
