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
		{"preflight-missing", func(r *SbxExecutionReceipt) { r.SupervisorObservation.CapabilityPreflight.UIDIsolation = "" }},
		{"preflight-cpu-overclaim", func(r *SbxExecutionReceipt) {
			r.SupervisorObservation.CapabilityPreflight.OuterCPU = "runtime.NumCPU=8"
		}},
		{"preflight-cgroup-overclaim", func(r *SbxExecutionReceipt) {
			r.SupervisorObservation.CapabilityPreflight.InnerCgroup = "read-write cgroup-v2 memory.max=536870912 cpu.max=100000 100000"
		}},
		{"aggregate-under-rusage", func(r *SbxExecutionReceipt) {
			r.SupervisorObservation.Peaks.CPUUsageUsec = r.SupervisorObservation.Rusage.CPUUsageUsec - 1
		}},
		{"supervisor-digest-drift", func(r *SbxExecutionReceipt) { r.SupervisorObservation.SupervisorDigestReopened = digestOf("drift") }},
		{"cleanup-procs-not-empty", func(r *SbxExecutionReceipt) { r.SupervisorObservation.Cleanup.UIDProcesses = "4242" }},
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

func TestPIDDescriptorRequiresRetainedNProcLimit(t *testing.T) {
	request := testSbxExecutionRequest(t)
	request.CanaryID = "PID_BOUND"
	receipt := testSbxReceipt(t, request)
	receipt.SupervisorObservation.Termination = "PARENT_OBSERVED_NONZERO_EXIT"
	receipt.SupervisorObservation.ParentExitCode = sbxIntPointer(23)
	profile, err := loadSbxExecutionProfile(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSbxExecutionReceipt(profile, request, receipt); err != nil {
		t.Fatal(err)
	}
	receipt.SupervisorObservation.RLimits.NProcCur = uint64(profile.SupervisorLimits.PIDs - 1)
	if err := validateSbxExecutionReceipt(profile, request, receipt); err == nil {
		t.Fatal("drifted RLIMIT_NPROC accepted")
	}
}

func TestMountinfoForbiddenBindRootFieldIsUnescapedAndRejected(t *testing.T) {
	realistic := testCandidateMountInfo() + "\n8 1 0:8 /protected/owner /safe ro,relatime - ext4 /dev/disk1 ro"
	if err := validateSBXNoForbiddenMounts(realistic, "/candidate/source"); err == nil {
		t.Fatal("forbidden bind root field accepted")
	}
	escaped := testCandidateMountInfo() + "\n8 1 0:8 /protected\\040owner /safe ro,relatime - ext4 /dev/disk1 ro"
	if err := validateSBXNoForbiddenMounts(escaped, "/candidate/source"); err == nil {
		t.Fatal("escaped forbidden bind root field accepted")
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
	projectionObject := value.(map[string]any)["projection"].(map[string]any)
	firstObservation := projectionObject["descriptor_observations"].([]any)[0].(map[string]any)
	preflight := firstObservation["capability_preflight"].(map[string]any)
	preflight["candidate_claim"] = true
	if err := schema.Validate(value); err == nil {
		t.Fatal("public projection schema accepted an unknown nested preflight field")
	}
	delete(preflight, "candidate_claim")
	preflight["outer_cpu"] = "runtime.NumCPU=8"
	if err := schema.Validate(value); err == nil {
		t.Fatal("public projection schema accepted false outer CPU evidence")
	}
	drift := envelope
	drift.CanonicalDigest = digestOf("drift")
	driftBytes, _ := json.Marshal(drift)
	if _, err := DecodeProtectedPublicProjection(driftBytes); err == nil {
		t.Fatal("aggregate public projection digest drift accepted")
	}
	for _, mutation := range []struct {
		name string
		edit func(*ProtectedPublicProjection)
	}{
		{"profile", func(value *ProtectedPublicProjection) { value.Request.ProfileDigest = digestOf("other-profile") }},
		{"policy-list", func(value *ProtectedPublicProjection) { value.Request.PolicyDigest = digestOf("other-policy") }},
		{"accepted-tree", func(value *ProtectedPublicProjection) { value.Request.AcceptedRootDigest = digestOf("other-accepted") }},
		{"inventory-tree", func(value *ProtectedPublicProjection) {
			value.Request.InventoryRootDigest = digestOf("other-inventory")
		}},
		{"runtime-supervisor", func(value *ProtectedPublicProjection) { value.Runtime.SupervisorDigest = digestOf("other-supervisor") }},
		{"descriptor-supervisor", func(value *ProtectedPublicProjection) {
			value.DescriptorObservations[0].SupervisorDigest = digestOf("other-supervisor")
		}},
	} {
		t.Run("binding-"+mutation.name, func(t *testing.T) {
			bad := projection
			bad.DescriptorObservations = append([]ProtectedDescriptorObservation(nil), projection.DescriptorObservations...)
			mutation.edit(&bad)
			canonical, err := intake.CanonicalJSON(bad)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := intake.CanonicalJSON(ProtectedPublicProjectionEnvelope{Projection: bad, CanonicalDigest: intake.DigestBytes(canonical)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeProtectedPublicProjection(raw); err == nil {
				t.Fatal("internally re-digested projection with drifted provenance binding accepted")
			}
		})
	}
}

func testProtectedPublicProjection() ProtectedPublicProjection {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	const tree = "89abcdef0123456789abcdef0123456789abcdef"
	plan := protectedFixedPlan()
	profileBytes, _ := json.Marshal(exactProtectedEnvelope())
	inputRoot := "/Users/mikelady/hq/workspace/orchestrator/verified-java-websocket-port/protected/us007-source-clone-" + commit
	outputRoot := "/Users/mikelady/hq/workspace/orchestrator/verified-java-websocket-port/protected/us007-sbx-output-live-0018"
	observations := make([]ProtectedDescriptorObservation, 0, len(plan))
	for _, id := range plan {
		request := SbxExecutionRequest{CanaryID: id, SupervisorDigest: digestOf("supervisor"), InputRoot: inputRoot}
		observation := testSupervisorObservation(request)
		switch id {
		case "FD_BOUND":
			observation.Termination, observation.ParentExitCode, observation.Peaks.OpenFiles = "FD_LIMIT_EXCEEDED", nil, observation.EnforcementMechanics.AggregateOpenFiles+1
		case "CPU_BOUND":
			observation.Termination, observation.ParentExitCode = "CPU_LIMIT_EXCEEDED", nil
			observation.Peaks.CPUUsageUsec = observation.EnforcementMechanics.CPUCorroborationUsec
		case "MEMORY_BOUND":
			observation.Termination, observation.ParentExitCode = "MEMORY_LIMIT_EXCEEDED", nil
			observation.Peaks.MemoryBytes = observation.EnforcementMechanics.MemoryKillBytes + 1
		case "OUTPUT_BOUND":
			observation.Termination, observation.ParentExitCode, observation.Peaks.OutputBytes = "OUTPUT_LIMIT_EXCEEDED", nil, 8388609
		case "PID_BOUND":
			observation.Termination, observation.ParentExitCode = "PARENT_OBSERVED_NONZERO_EXIT", sbxIntPointer(23)
		case "WALL_BOUND":
			observation.Termination, observation.ParentExitCode, observation.WallDurationNanos = "WALL_LIMIT_EXCEEDED", nil, observation.EnforcementMechanics.WallKillThresholdNS
		case "WORKSPACE_BOUND":
			observation.Termination, observation.ParentExitCode, observation.Peaks.WorkspaceBytes = "PARENT_OBSERVED_NONZERO_EXIT", sbxIntPointer(23), int64(exactProtectedEnvelope().WorkspaceBytes)-(2<<20)
		case "BENIGN_OPERATION":
			observation.Artifact = SupervisorArtifactObservation{ToolPath: "/usr/bin/go", ToolVersion: "go version go1.26.0 linux/arm64", Target: "security/fixtures/resource-envelope-canary.go", SourceCommit: commit, NamespacePath: "/run/us007-benign/output/resource-envelope-canary.o", CapturePath: "/tmp/us007-resource-envelope-artifact", CaptureChannel: "SUPERVISOR_OWNED_PIPE_REOPENED", WorkloadDigest: digestOf("artifact"), ParentDigest: digestOf("artifact"), Bytes: 8}
		}
		observations = append(observations, protectedObservationFromCandidate(id, commit, tree, observation))
	}
	return ProtectedPublicProjection{
		SchemaVersion: "1.0.0",
		Request:       ProtectedProjectionRequest{AttemptID: "us007-sbx-output-live-0018", TargetCommit: commit, SourceTree: tree, FixedPlanDigest: protectedFixedPlanDigest(), ProfileDigest: intake.DigestBytes(profileBytes), PolicyDigest: digestOf("policy-list"), AcceptedRootDigest: intake.DigestBytes([]byte("accepted-git-tree:" + tree)), InventoryRootDigest: intake.DigestBytes([]byte("inventory-git-tree:" + tree)), InputRoot: inputRoot, OutputRoot: outputRoot, PrivilegedExecArgvDigest: protectedPrivilegedExecDigest()},
		Runtime:       ProtectedProjectionRuntime{CLIPath: "/opt/homebrew/Caskroom/sbx/0.39.0/bin/sbx", CLIBinaryDigest: "sha256:f2a9e83f41a1cc20292d1f0e40974c495065f59a933aaec98f0619c286ddbeaf", CLIVersionOutputDigest: digestOf("version"), CLIVersion: "v0.39.0", CLICommit: "def8cb0523a77e757bdd6ef52b459fe374f3783e", DaemonStatusDigest: digestOf("daemon"), DaemonVersion: "v0.39.0", DaemonCommit: "def8cb0523a77e757bdd6ef52b459fe374f3783e", Template: "docker.io/docker/sandbox-templates:shell@sha256:1e642f7fadebcbff3d8de67114e9b42a5971ba9b4287ebffa1d05662f5a0f5ec", SandboxName: "us007-resource-envelope-0018", SupervisorDigest: digestOf("supervisor"), PrivilegeLifecycle: "sbx exec privilege is fixed to the trusted supervisor; stage-2 drops UID/GID/capabilities, sets no_new_privs/seccomp, and is reopened before workload release"},
		StartedAt:     "2026-08-25T12:00:00Z", FinishedAt: "2026-08-25T12:00:01Z",
		Artifact:               ProtectedProjectionArtifact{Digest: digestOf("artifact"), Bytes: 8, Path: outputRoot + "/resource-envelope-artifact"},
		Output:                 ProtectedProjectionOutput{SupervisorReceiptsDigest: digestOf("receipts"), InspectDigest: digestOf("inspect"), PolicyListDigest: digestOf("policy-list"), ExamplePolicyCheckDigest: digestOf("example"), ProviderPolicyCheckDigest: digestOf("provider")},
		Cleanup:                ProtectedProjectionCleanup{RemoveDigest: digestOf("remove"), AbsenceDigest: digestOf("absence"), SandboxAbsent: true},
		DescriptorObservations: observations, Assurance: AssuranceOwnerOnly,
	}
}

func protectedObservationFromCandidate(id, commit, tree string, value SupervisorObservation) ProtectedDescriptorObservation {
	value.DescriptorID = id
	value.SourceCommit = commit
	value.SourceTree = tree
	return value
}
