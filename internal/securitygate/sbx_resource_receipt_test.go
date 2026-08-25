package securitygate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/santhosh-tekuri/jsonschema/v6"
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

func TestProtectedRawProjectionRoundTripsStrictDecoderAndSchema(t *testing.T) {
	request := testSbxExecutionRequest(t)
	profile, err := loadSbxExecutionProfile(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	projected := testSbxReceipt(t, request)
	raw, err := intake.CanonicalJSON(projected)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSbxExecutionReceipt(raw)
	if err != nil || validateSbxExecutionReceipt(profile, request, decoded) != nil {
		t.Fatalf("protected projection round-trip: decode=%v validate=%v", err, validateSbxExecutionReceipt(profile, request, decoded))
	}
	schemaBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "schemas/sbx-execution-receipt-1.0.0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaResource any
	if err := json.Unmarshal(schemaBytes, &schemaResource); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("sbx-receipt", schemaResource); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("sbx-receipt")
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil || schema.Validate(value) != nil {
		t.Fatalf("projection schema: unmarshal=%v schema=%v", err, schema.Validate(value))
	}
	drift := projected
	drift.SupervisorObservation.CompleteMountInfoDigest = digestOf("drift")
	if err := validateSbxExecutionReceipt(profile, request, drift); err == nil {
		t.Fatal("protected projection field drift accepted")
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
