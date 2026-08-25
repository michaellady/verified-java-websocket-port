package securitygate

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func TestSbxExecutionRequestBindsExactProtectedProfile(t *testing.T) {
	request := testSbxExecutionRequest(t)
	if request.SchemaVersion != "1.0.0" || request.Company != requiredCompany || request.Project != requiredProject || request.Laboratory != requiredLaboratory {
		t.Fatalf("scope=%#v", request)
	}
	if request.ProfileDigest == "" || request.SandboxPolicyDigest == "" || request.InputRoot != repoRoot(t) || request.InputRoot == request.OutputRoot {
		t.Fatalf("root/profile binding=%#v", request)
	}
	wantCreate := []string{
		"/opt/homebrew/Caskroom/sbx/0.39.0/bin/sbx", "create", "--clone", "--cpus", "2", "--memory", "2g", "--deny-network", "**",
		"--name", "us007-clean-exit", "--template", "docker.io/docker/sandbox-templates:shell@sha256:1e642f7fadebcbff3d8de67114e9b42a5971ba9b4287ebffa1d05662f5a0f5ec",
		"shell", repoRoot(t),
	}
	if !slices.Equal(request.CreateCommand, wantCreate) {
		t.Fatalf("create command=%q want=%q", request.CreateCommand, wantCreate)
	}
	if !slices.Equal(request.RemoveCommand, []string{wantCreate[0], "rm", "--force", request.SandboxName}) ||
		!slices.Equal(request.AbsenceCommand, []string{wantCreate[0], "ls", "--json"}) {
		t.Fatalf("cleanup commands=%q / %q", request.RemoveCommand, request.AbsenceCommand)
	}
	profile, err := loadSbxExecutionProfile(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if profile.SupervisorLimits != (resources{WallSeconds: 120, CPUSeconds: 60, MemoryBytes: 536870912, PIDs: 64, OpenFiles: 256, OutputBytes: 8388608, WorkspaceBytes: 67108864, CacheBytes: 67108864, DiskBytes: 134217728, Inodes: 8192}) {
		t.Fatalf("supervisor limits widened from retained sandbox policy: %#v", profile.SupervisorLimits)
	}
	for _, forbidden := range []string{"--env", "--env-file", "--kit", "--publish", "--static-mcp", "--privileged"} {
		if slices.Contains(request.CreateCommand, forbidden) {
			t.Fatalf("create command imports forbidden capability %s", forbidden)
		}
	}
	if request.Assurance != AssuranceOwnerOnly || request.IndependentReviewClaimed || request.Production || request.Signing || request.Publication {
		t.Fatalf("assurance widened: %#v", request)
	}
}

func TestRunControlledCanaryRequiresProtectedCallerBeforeAdapter(t *testing.T) {
	request := testSbxExecutionRequest(t)
	_, err := RunControlledCanary(context.Background(), CanaryRequest{
		RootPath: repoRoot(t), Execution: request,
	})
	finding, ok := err.(*SandboxAdapterFinding)
	if !ok || finding.Code != "PROTECTED_CALLER_REQUIRED" || finding.Disposition != "BLOCK" {
		t.Fatalf("err=%T %v", err, err)
	}
}

func TestCandidateCanValidateReceiptShapeButNeverAuthorizeLaunch(t *testing.T) {
	request := testSbxExecutionRequest(t)
	profile, err := loadSbxExecutionProfile(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSbxExecutionReceipt(profile, request, testSbxReceipt(t, request)); err != nil {
		t.Fatalf("valid structural receipt: %v", err)
	}
	if _, err := RunControlledCanary(context.Background(), CanaryRequest{RootPath: repoRoot(t), Execution: request}); err == nil || !strings.Contains(err.Error(), "PROTECTED_CALLER_REQUIRED/BLOCK") {
		t.Fatalf("candidate launch unexpectedly authorized: %v", err)
	}

	mutations := []struct {
		name string
		code string
		edit func(*SbxExecutionReceipt)
	}{
		{"cli", "SBX_RUNTIME_MISMATCH", func(r *SbxExecutionReceipt) { r.CLIVersion = "v0.40.0" }},
		{"template", "SBX_TEMPLATE_MISMATCH", func(r *SbxExecutionReceipt) { r.TemplateManifestDigest = digestOf("other-template") }},
		{"network", "NETWORK_POLICY_VIOLATION", func(r *SbxExecutionReceipt) { r.NetworkPolicyState = "allow" }},
		{"environment", "SECRET_ACCESS_DENIED", func(r *SbxExecutionReceipt) { r.EnvironmentImportCount = 1 }},
		{"platform-control-secret", "SANDBOX_CAPABILITY_MISMATCH", func(r *SbxExecutionReceipt) { r.PlatformControlSecretCount = 0 }},
		{"clone-bridge", "SANDBOX_CAPABILITY_MISMATCH", func(r *SbxExecutionReceipt) { r.CloneGitBridgePortCount = 0 }},
		{"docker-socket", "FORBIDDEN_MOUNT_EXPOSED", func(r *SbxExecutionReceipt) { r.HostDockerSocketMounted = true }},
		{"skills", "FORBIDDEN_CAPABILITY_OBSERVED", func(r *SbxExecutionReceipt) { r.SharedSkillsEnabled = true }},
		{"mcp", "FORBIDDEN_CAPABILITY_OBSERVED", func(r *SbxExecutionReceipt) { r.LocalMCPEnabled = true }},
		{"canary-inventory", "SANDBOX_RECEIPT_INVALID", func(r *SbxExecutionReceipt) { r.CanaryObservationCount = 0 }},
		{"artifact", "ARTIFACT_CAPTURE_INCOMPLETE", func(r *SbxExecutionReceipt) { r.ArtifactManifestDigest = "" }},
		{"source", "SOURCE_MUTATION_DETECTED", func(r *SbxExecutionReceipt) { r.SourceAfterDigest = digestOf("changed") }},
		{"remove", "SANDBOX_CLEANUP_INCOMPLETE", func(r *SbxExecutionReceipt) { r.SandboxPresentAfterRemoval = true }},
		{"assurance", "ASSURANCE_CEILING_EXCEEDED", func(r *SbxExecutionReceipt) { r.IndependentReviewClaimed = true }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			bad := testSbxReceipt(t, request)
			mutation.edit(&bad)
			err := validateSbxExecutionReceipt(profile, request, bad)
			finding, ok := err.(*SandboxAdapterFinding)
			if !ok || finding.Code != mutation.code {
				t.Fatalf("err=%T %v want=%s", err, err, mutation.code)
			}
		})
	}
}

func TestSbxCandidatePreflightNeverAuthorizes(t *testing.T) {
	request := testSbxExecutionRequest(t)
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	record, err := BuildAndSignSbxLaunchAuthorization(repoRoot(t), SbxLaunchSigningRequest{
		Execution: request, IssuedAt: testSbxNow().Add(-time.Minute), ExpiresAt: testSbxNow().Add(time.Hour),
		RoleSnapshotDigest: digestOf("candidate-roles"), RevocationSnapshotDigest: digestOf("candidate-revocations"),
		Nonces: []string{"candidate-qualification-nonce-0001", "candidate-promotion-nonce-0002"},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := intake.CanonicalJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	err = PreflightSbxLaunchCandidate(repoRoot(t), request, data, testSbxNow())
	finding, ok := err.(*SandboxAdapterFinding)
	if !ok || finding.Code != "PROTECTED_CALLER_REQUIRED" || finding.Disposition != "BLOCK" {
		t.Fatalf("err=%T %v", err, err)
	}
	if _, err := DecodeSbxLaunchAuthorizationRecord(append(data[:len(data)-1], []byte(`,"candidate_authority":true}`)...)); err == nil {
		t.Fatal("unknown candidate authority field was accepted")
	}
}

func testSbxExecutionRequest(t *testing.T) SbxExecutionRequest {
	t.Helper()
	request, err := BuildSbxExecutionRequest(repoRoot(t), SbxExecutionParameters{
		AttemptID: "us007-attempt-0001", SandboxName: "us007-clean-exit", CanaryID: "CLEAN_EXIT",
		PlanDigest: digestOf("plan"), AcceptedRootDigest: digestOf("accepted"), InventoryRootDigest: digestOf("inventory"),
		PromotionRecordDigest: digestOf("promotion"), SecurityctlDigest: digestOf("securityctl"), SupervisorDigest: digestOf("supervisor"),
		InputRoot: repoRoot(t), OutputRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testSbxReceipt(t *testing.T, request SbxExecutionRequest) SbxExecutionReceipt {
	t.Helper()
	profile, err := loadSbxExecutionProfile(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := SbxExecutionRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	exitCode, removeExit := 0, 0
	return SbxExecutionReceipt{
		SchemaVersion: "1.0.0", RequestDigest: requestDigest, AttemptID: request.AttemptID,
		SandboxName: request.SandboxName, CanaryID: request.CanaryID,
		ProfileDigest: request.ProfileDigest, SandboxPolicyDigest: request.SandboxPolicyDigest,
		CLIVersion: profile.Runtime.CLIVersion, CLICommit: profile.Runtime.CLICommit, CLIBinaryDigest: profile.Runtime.CLIBinaryDigest,
		DaemonVersion: profile.Runtime.DaemonVersion, Agent: profile.Runtime.Agent,
		TemplateReference: profile.Runtime.TemplateReference, TemplateIndexDigest: profile.Runtime.TemplateIndexDigest,
		TemplatePlatform: profile.Runtime.TemplatePlatform, TemplateManifestDigest: profile.Runtime.TemplateManifestDigest,
		WorkspaceMode: profile.Isolation.WorkspaceMode, CloneSourceReadOnly: true,
		CPUCount: profile.Isolation.CPUs, MemoryBytes: profile.Isolation.MemoryBytes, CompiledSupervisorEnvelope: profile.SupervisorLimits,
		SupervisorObservation: testSupervisorObservation(request),
		NetworkPolicyDigest:   profile.Isolation.NetworkPolicy.CanonicalDigest,
		NetworkPolicyState:    "ACTIVE_DENY_ALL", InputRoot: request.InputRoot, OutputRoot: request.OutputRoot,
		PlatformControlSecretCount: 1, MCPGatewayInfrastructure: true, CloneGitBridgePortCount: 1,
		AcceptedRootDigest: request.AcceptedRootDigest, InventoryRootDigest: request.InventoryRootDigest,
		SourceBeforeDigest: digestOf("source-tree"), SourceAfterDigest: digestOf("source-tree"), OutputRootDigest: digestOf("output-root"),
		CanaryObservationCount: 1, ArtifactManifestDigest: digestOf("artifacts"), ExitCode: &exitCode, TerminationReason: "EXITED",
		StartedAt: "2026-08-25T08:00:00Z", FinishedAt: "2026-08-25T08:00:01Z",
		RemovalStartedAt: "2026-08-25T08:00:01Z", RemovalFinishedAt: "2026-08-25T08:00:02Z",
		RemoveInvoked: true, RemoveExitCode: &removeExit, CleanupComplete: true,
		Assurance: AssuranceOwnerOnly,
	}
}

func testSupervisorObservation(request SbxExecutionRequest) SupervisorObservation {
	descriptorDigest, _, err := sbxDescriptorContract(request.CanaryID)
	if err != nil {
		panic(err)
	}
	initial := SupervisorCgroupObservation{
		MemoryMaxBytes: 536870912, MemorySwapMax: 0, MemoryOOMGroup: 1, PIDsMax: 56,
		CPUUsageUsec: 1, CPUUserUsec: 1,
	}
	return SupervisorObservation{
		DescriptorDigest: descriptorDigest, SupervisorDigestReopened: request.SupervisorDigest,
		RuntimeIdentity: "linux/arm64", SBXIdentity: "docker-sbx-v0.39.0/linux/arm64",
		SourceCommit: "0123456789abcdef0123456789abcdef01234567", SourceTree: "89abcdef0123456789abcdef0123456789abcdef",
		CapabilityPreflight: SupervisorCapabilityPreflight{
			CAPSysAdmin: "CapEff bit 21 observed", CgroupV2: "cgroup2 mount observed",
			Controllers: "cpu memory pids observed", CgroupKill: "cgroup.kill reopened",
			MountTmpfs:        "private mount namespace and tmpfs available",
			Stage2Containment: "pid reopened in cgroup.procs before release",
		},
		EnforcementMechanics: SupervisorEnforcementMechanics{RLimitFSizeBytes: 134217728, CPUKillThresholdUsec: 58000000, WallKillThresholdNS: 119000000000, CgroupPIDsMax: 56},
		CgroupInitial:        initial, CgroupFinal: initial,
		RLimits: SupervisorRLimitObservation{
			CPUCur: 60, CPUMax: 60, ASCur: 536870912, ASMax: 536870912,
			NProcCur: 64, NProcMax: 64, NOFileCur: 256, NOFileMax: 256,
			FSizeCur: 134217728, FSizeMax: 134217728,
		},
		Identity: SupervisorIdentityObservation{
			UID: 65534, GID: 65534, CapEff: "0000000000000000", NoNewPrivs: 1, Seccomp: 2, OpenFDs: 3,
			FDSemantics: "per-process RLIMIT_NOFILE; aggregate tree FD count observed but not separately hard-capped",
		},
		Mounts: []SupervisorMountObservation{
			{Name: "workspace", MountInfo: "tmpfs rw", FSType: 0x01021994, BytesTotal: 67108864, BytesFree: 67108864, InodesTotal: 4096, InodesFree: 4096},
			{Name: "cache", MountInfo: "tmpfs rw", FSType: 0x01021994, BytesTotal: 33554432, BytesFree: 33554432, InodesTotal: 2048, InodesFree: 2048},
			{Name: "output", MountInfo: "tmpfs rw", FSType: 0x01021994, BytesTotal: 16777216, BytesFree: 16777216, InodesTotal: 1024, InodesFree: 1024},
			{Name: "general", MountInfo: "tmpfs rw", FSType: 0x01021994, BytesTotal: 16777216, BytesFree: 16777216, InodesTotal: 1024, InodesFree: 1024},
		},
		RootMountInfo: "1 0 0:1 / / ro - rootfs rootfs ro", SourceMountInfo: "2 1 0:2 / /run/sandbox/source ro - ext4 source ro",
		CompleteMountInfo: testCandidateMountInfo(), CompleteMountInfoDigest: intake.DigestBytes([]byte(testCandidateMountInfo())),
		StdoutDigest: digestOf("stdout"), StderrDigest: digestOf("stderr"), Termination: "EXITED", ParentWaitStatus: "exit status 0", ParentExitCode: sbxIntPointer(0), WallDurationNanos: int64(time.Second),
		Cleanup: SupervisorCleanupObservation{
			ProcessGroupKill: "ALREADY_ABSENT_ESRCH", CgroupKill: "WRITE_SUCCEEDED", ChildWait: "REAP_SUCCEEDED",
			CgroupEventsReopened: "populated 0\nfrozen 0", CgroupProcsReopened: "<empty>", NamespaceMounts: "PROCESS_MOUNT_NAMESPACE_REAPED",
			FDClosure: "OWNED_FDS_CLOSED", CgroupRemoval: "REMOVE_SUCCEEDED",
		},
		Assurance: AssuranceOwnerOnly,
	}
}

func testCandidateMountInfo() string {
	return strings.Join([]string{
		"1 0 0:1 / / ro - rootfs rootfs ro", "2 1 0:2 / /run/sandbox/source ro - ext4 source ro",
		"3 1 0:3 / /run/us007-workspace rw - tmpfs tmpfs rw", "4 1 0:4 / /run/us007-cache rw - tmpfs tmpfs rw",
		"5 1 0:5 / /run/us007-output rw - tmpfs tmpfs rw", "6 1 0:6 / /run/us007-general rw - tmpfs tmpfs rw",
	}, "\n")
}

func sbxIntPointer(value int) *int { return &value }

func digestOf(value string) string { return intake.DigestBytes([]byte(value)) }

func testSbxNow() time.Time { return time.Date(2026, 8, 25, 8, 0, 0, 0, time.UTC) }

func TestSbxRequestRejectsNonCanonicalOutputAndAutobahn(t *testing.T) {
	base := SbxExecutionParameters{
		AttemptID: "us007-attempt-0001", SandboxName: "us007-clean-exit", CanaryID: "CLEAN_EXIT",
		PlanDigest: digestOf("plan"), AcceptedRootDigest: digestOf("accepted"), InventoryRootDigest: digestOf("inventory"),
		PromotionRecordDigest: digestOf("promotion"), SecurityctlDigest: digestOf("securityctl"), SupervisorDigest: digestOf("supervisor"),
		InputRoot: repoRoot(t), OutputRoot: t.TempDir(),
	}
	bad := base
	bad.OutputRoot = "/"
	if _, err := BuildSbxExecutionRequest(repoRoot(t), bad); err == nil || !strings.Contains(err.Error(), "ROOT_CONFINEMENT_FAILED") {
		t.Fatalf("broad output root err=%v", err)
	}
	bad = base
	bad.CanaryID = "AUTOBAHN_CLIENT"
	if _, err := BuildSbxExecutionRequest(repoRoot(t), bad); err == nil || !strings.Contains(err.Error(), "AUTOBAHN_RERUN_FORBIDDEN") {
		t.Fatalf("Autobahn request err=%v", err)
	}
}

func TestUS007ExternalSbxPublicProjectionIsExactAndBounded(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "evidence", "sbx-validation.json"))
	if err != nil {
		t.Fatal(err)
	}
	if digest := intake.DigestBytes(data); digest != "sha256:930b9073555f24d4013773f3f81e7bc354442ded9795812e2888907c4853b6b7" {
		t.Fatalf("external sbx public projection digest=%s", digest)
	}
	var projection struct {
		Story                    string `json:"story"`
		TargetCommit             string `json:"target_commit"`
		NetworkPolicy            string `json:"network_policy"`
		PlatformControlSecrets   int    `json:"platform_control_secrets"`
		CloneGitBridgePorts      int    `json:"clone_git_bridge_ports"`
		RegisteredMCPServers     int    `json:"registered_mcp_servers"`
		UserSecretImports        int    `json:"user_secret_imports"`
		UserPublishedPorts       int    `json:"user_published_ports"`
		SandboxRemoved           bool   `json:"sandbox_removed"`
		SandboxAbsentAfterRemove bool   `json:"sandbox_absent_after_remove"`
		AutobahnReruns           int    `json:"autobahn_reruns"`
		Assurance                string `json:"assurance"`
		IndependentReviewClaimed bool   `json:"independent_review_claimed"`
		Production               bool   `json:"production"`
		Signing                  bool   `json:"signing"`
		Publication              bool   `json:"publication"`
		Canaries                 []struct {
			ID       string `json:"id"`
			Passed   bool   `json:"passed"`
			ExitCode int    `json:"exit_code"`
		} `json:"canaries"`
	}
	if err := json.Unmarshal(data, &projection); err != nil {
		t.Fatal(err)
	}
	if projection.Story != "US-007" || projection.TargetCommit != "f1860a4bd0420c8073aec8980cfcf3d118e1ea5a" || projection.NetworkPolicy != "ACTIVE_DENY_ALL" ||
		projection.PlatformControlSecrets != 1 || projection.CloneGitBridgePorts != 1 || projection.RegisteredMCPServers != 0 || projection.UserSecretImports != 0 || projection.UserPublishedPorts != 0 ||
		!projection.SandboxRemoved || !projection.SandboxAbsentAfterRemove || projection.AutobahnReruns != 0 || projection.Assurance != AssuranceOwnerOnly || projection.IndependentReviewClaimed || projection.Production || projection.Signing || projection.Publication || len(projection.Canaries) != 15 {
		t.Fatalf("external sbx projection widened or incomplete: %#v", projection)
	}
	seenPID := false
	for _, canary := range projection.Canaries {
		if !canary.Passed {
			t.Fatalf("external sbx canary failed: %#v", canary)
		}
		if canary.ID == "PID_BOUND" {
			seenPID = canary.ExitCode != 0
		}
	}
	if !seenPID {
		t.Fatal("process bomb did not retain its typed nonzero termination")
	}
}
