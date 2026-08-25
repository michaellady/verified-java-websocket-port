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

func TestProtectedPublicProjectionGoldenRoundTrip(t *testing.T) {
	projection := testProtectedPublicProjection()
	canonical, err := intake.CanonicalJSON(projection)
	if err != nil {
		t.Fatal(err)
	}
	envelope := ProtectedPublicProjectionEnvelope{Projection: projection, CanonicalDigest: intake.DigestBytes(canonical)}
	raw, err := intake.CanonicalJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeProtectedPublicProjection(raw); err != nil {
		t.Fatal(err)
	}
	schemaBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "schemas/sbx-public-projection-1.0.0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaResource any
	if err := json.Unmarshal(schemaBytes, &schemaResource); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("sbx-public-projection", schemaResource); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("sbx-public-projection")
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil || schema.Validate(value) != nil {
		t.Fatalf("public projection schema: unmarshal=%v schema=%v", err, schema.Validate(value))
	}
	drift := envelope
	drift.CanonicalDigest = digestOf("drift")
	driftBytes, _ := json.Marshal(drift)
	if _, err := DecodeProtectedPublicProjection(driftBytes); err == nil {
		t.Fatal("aggregate public projection digest drift accepted")
	}
}

func testProtectedPublicProjection() ProtectedPublicProjection {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	const tree = "89abcdef0123456789abcdef0123456789abcdef"
	plan := protectedFixedPlan()
	observations := make([]ProtectedDescriptorObservation, 0, len(plan))
	for _, id := range plan {
		request := SbxExecutionRequest{CanaryID: id, SupervisorDigest: digestOf("supervisor")}
		observation := testSupervisorObservation(request)
		switch id {
		case "FD_BOUND":
			observation.Termination, observation.ParentExitCode, observation.Peaks.PerProcessOpenFDs = "PARENT_OBSERVED_NONZERO_EXIT", sbxIntPointer(23), 252
		case "CPU_BOUND":
			observation.Termination, observation.ParentExitCode = "CPU_LIMIT_EXCEEDED", nil
			observation.CgroupFinal.CPUUsageUsec = observation.CgroupInitial.CPUUsageUsec + 58000000
		case "MEMORY_BOUND":
			observation.Termination, observation.ParentExitCode = "MEMORY_LIMIT_EXCEEDED", nil
			observation.CgroupFinal.MemoryEventsMax++
		case "OUTPUT_BOUND":
			observation.Termination, observation.ParentExitCode, observation.Peaks.OutputBytes = "OUTPUT_LIMIT_EXCEEDED", nil, 8388609
		case "PID_BOUND":
			observation.Termination, observation.ParentExitCode = "PARENT_OBSERVED_NONZERO_EXIT", sbxIntPointer(23)
			observation.CgroupFinal.PIDsEventsMax++
		case "WALL_BOUND":
			observation.Termination, observation.ParentExitCode, observation.WallDurationNanos = "WALL_LIMIT_EXCEEDED", nil, 119000000000
		case "WORKSPACE_BOUND":
			observation.Termination, observation.ParentExitCode, observation.Peaks.WorkspaceBytes = "PARENT_OBSERVED_NONZERO_EXIT", sbxIntPointer(23), 67108864-(2<<20)
		case "BENIGN_OPERATION":
			observation.Artifact = SupervisorArtifactObservation{ToolPath: "/usr/local/go/bin/go", ToolVersion: "go version go1.25.5 linux/arm64", Target: "./cmd/resource-envelope-artifact", SourceCommit: commit, NamespacePath: "/run/us007-output/resource-envelope-artifact", CapturePath: "/tmp/us007-resource-envelope-artifact", CaptureChannel: "SUPERVISOR_OWNED_PIPE_REOPENED", WorkloadDigest: digestOf("artifact"), ParentDigest: digestOf("artifact"), Bytes: 8}
		}
		observations = append(observations, protectedObservationFromCandidate(id, commit, tree, observation))
	}
	return ProtectedPublicProjection{
		SchemaVersion: "1.0.0",
		Request:       ProtectedProjectionRequest{AttemptID: "us007-sbx-output-live-0012", TargetCommit: commit, SourceTree: tree, FixedPlanDigest: protectedFixedPlanDigest(), ProfileDigest: digestOf("profile"), PolicyDigest: digestOf("policy"), AcceptedRootDigest: digestOf("accepted"), InventoryRootDigest: digestOf("inventory"), InputRoot: "/Users/mikelady/hq/workspace/worktrees/verified-java-websocket-port/us007-resource-supervisor", OutputRoot: "/Users/mikelady/hq/workspace/orchestrator/verified-java-websocket-port/protected/us007-sbx-output-live-0012", PrivilegedExecArgvDigest: protectedPrivilegedExecDigest()},
		Runtime:       ProtectedProjectionRuntime{CLIPath: "/opt/homebrew/Caskroom/sbx/0.39.0/bin/sbx", CLIBinaryDigest: "sha256:f2a9e83f41a1cc20292d1f0e40974c495065f59a933aaec98f0619c286ddbeaf", CLIVersionOutputDigest: digestOf("version"), CLIVersion: "v0.39.0", CLICommit: "def8cb0523a77e757bdd6ef52b459fe374f3783e", DaemonStatusDigest: digestOf("daemon"), DaemonVersion: "v0.39.0", DaemonCommit: "def8cb0523a77e757bdd6ef52b459fe374f3783e", Template: "docker.io/docker/sandbox-templates:shell@sha256:1e642f7fadebcbff3d8de67114e9b42a5971ba9b4287ebffa1d05662f5a0f5ec", SandboxName: "us007-resource-envelope-0012", PrivilegeLifecycle: "trusted supervisor uses privilege only for cgroup and mount setup; stage-2 drops identity and capabilities before workload"},
		StartedAt:     "2026-08-25T12:00:00Z", FinishedAt: "2026-08-25T12:00:01Z",
		Artifact:               ProtectedProjectionArtifact{Digest: digestOf("artifact"), Bytes: 8, Path: "/Users/mikelady/hq/workspace/orchestrator/verified-java-websocket-port/protected/us007-sbx-output-live-0012/resource-envelope-artifact"},
		Output:                 ProtectedProjectionOutput{SupervisorReceiptsDigest: digestOf("receipts"), InspectDigest: digestOf("inspect"), PolicyListDigest: digestOf("policy-list"), ExamplePolicyCheckDigest: digestOf("example"), ProviderPolicyCheckDigest: digestOf("provider")},
		Cleanup:                ProtectedProjectionCleanup{RemoveDigest: digestOf("remove"), AbsenceDigest: digestOf("absence"), SandboxAbsent: true},
		DescriptorObservations: observations, Assurance: AssuranceOwnerOnly,
	}
}

func protectedObservationFromCandidate(id, commit, tree string, value SupervisorObservation) ProtectedDescriptorObservation {
	toProtected := func(c SupervisorCgroupObservation) ProtectedCgroupReadback {
		return ProtectedCgroupReadback{MemoryMax: c.MemoryMaxBytes, MemorySwapMax: c.MemorySwapMax, MemoryOOM: c.MemoryOOMGroup, PIDsMax: c.PIDsMax, CPU: ProtectedCPUCounters{UsageUsec: c.CPUUsageUsec, UserUsec: c.CPUUserUsec, SystemUsec: c.CPUSystemUsec}, MemoryEvents: ProtectedMemoryEvents{Max: c.MemoryEventsMax, OOM: c.MemoryEventsOOM, OOMKill: c.MemoryEventsKill}, MemoryCurrent: c.MemoryCurrent, MemoryPeak: c.MemoryPeak, PIDsCurrent: c.PIDsCurrent, PIDsEventsMax: c.PIDsEventsMax}
	}
	return ProtectedDescriptorObservation{SchemaVersion: "1.0.0", DescriptorID: id, DescriptorDigest: value.DescriptorDigest, SupervisorDigest: value.SupervisorDigestReopened, SupervisorDigestReopened: value.SupervisorDigestReopened, RuntimeIdentity: value.RuntimeIdentity, SBXIdentity: value.SBXIdentity, SourceCommit: commit, SourceTree: tree, Preflight: value.CapabilityPreflight, Envelope: exactProtectedEnvelope(), Mechanics: value.EnforcementMechanics, CgroupInitial: toProtected(value.CgroupInitial), CgroupFinal: toProtected(value.CgroupFinal), RLimits: value.RLimits, Identity: value.Identity, Mounts: value.Mounts, RootMountInfo: value.RootMountInfo, SourceMountInfo: value.SourceMountInfo, CompleteMountInfo: value.CompleteMountInfo, CompleteMountInfoDigest: value.CompleteMountInfoDigest, Peaks: value.Peaks, StdoutDigest: value.StdoutDigest, StderrDigest: value.StderrDigest, Termination: value.Termination, ParentWaitStatus: value.ParentWaitStatus, ExitCode: value.ParentExitCode, Signal: value.ParentSignal, WallDurationNanos: value.WallDurationNanos, Cleanup: value.Cleanup, Artifact: value.Artifact, Assurance: AssuranceOwnerOnly}
}
