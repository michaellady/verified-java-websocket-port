package securitygate

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
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
	launcher := &recordingSbxLauncher{receipt: testSbxReceipt(t, request)}
	_, err := RunControlledCanary(context.Background(), CanaryRequest{
		RootPath: repoRoot(t), Execution: request,
	})
	finding, ok := err.(*SandboxAdapterFinding)
	if !ok || finding.Code != "PROTECTED_CALLER_REQUIRED" || finding.Disposition != "BLOCK" {
		t.Fatalf("err=%T %v", err, err)
	}
	if launcher.calls != 0 {
		t.Fatalf("unprotected adapter called %d times", launcher.calls)
	}
}

func TestRunControlledCanaryAcceptsOnlyExactProtectedReceipt(t *testing.T) {
	request := testSbxExecutionRequest(t)
	record, validation := testProtectedSbxAuthorization(t, request)
	launcher := &recordingSbxLauncher{receipt: testSbxReceipt(t, request)}
	receipt, err := RunControlledCanary(context.Background(), CanaryRequest{
		RootPath: repoRoot(t), Execution: request,
		Protected: &ProtectedCanaryInvocation{Authorization: record, Validation: validation, Launcher: launcher, Now: testSbxNow()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if launcher.calls != 1 || receipt.CanaryObservationCount != 1 || !receipt.CleanupComplete {
		t.Fatalf("launcher calls=%d receipt=%#v", launcher.calls, receipt)
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
			launcher := &recordingSbxLauncher{receipt: bad}
			_, err := RunControlledCanary(context.Background(), CanaryRequest{
				RootPath: repoRoot(t), Execution: request,
				Protected: &ProtectedCanaryInvocation{Authorization: record, Validation: validation, Launcher: launcher, Now: testSbxNow()},
			})
			finding, ok := err.(*SandboxAdapterFinding)
			if !ok || finding.Code != mutation.code {
				t.Fatalf("err=%T %v want=%s", err, err, mutation.code)
			}
		})
	}
}

func TestSbxCandidatePreflightNeverAuthorizes(t *testing.T) {
	request := testSbxExecutionRequest(t)
	record, _ := testProtectedSbxAuthorization(t, request)
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

type recordingSbxLauncher struct {
	calls   int
	receipt SbxExecutionReceipt
	err     error
}

func (launcher *recordingSbxLauncher) LaunchProtectedSbx(_ context.Context, _ SbxExecutionRequest) (SbxExecutionReceipt, error) {
	launcher.calls++
	return launcher.receipt, launcher.err
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

func testProtectedSbxAuthorization(t *testing.T, request SbxExecutionRequest) (SbxLaunchAuthorizationRecord, intake.ScopedOwnerValidation) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	record, err := BuildAndSignSbxLaunchAuthorization(repoRoot(t), SbxLaunchSigningRequest{
		Execution: request, IssuedAt: testSbxNow().Add(-time.Minute), ExpiresAt: testSbxNow().Add(time.Hour),
		RoleSnapshotDigest: digestOf("roles"), RevocationSnapshotDigest: digestOf("revocations"),
		Nonces: []string{"sbx-qualification-nonce-0001", "sbx-promotion-nonce-0002"},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	authority := intake.TrustedAuthority{
		AuthorityMode: intake.SingleOwnerAuthorityMode, OwnerActorID: intake.RequiredOwnerActor,
		Identities: map[string]intake.Identity{intake.RequiredOwnerActor: {
			ActorID: intake.RequiredOwnerActor, AuthorityMode: intake.SingleOwnerAuthorityMode,
			AllowedRoles: []string{"port-implementer", "release-attestor"}, KeyID: executablePromotionKeyID,
			PublicKey: hex.EncodeToString(publicKey),
		}},
		Snapshots: map[string]intake.Snapshot{intake.RequiredOwnerActor: {
			RoleDigest: record.Statements[0].RoleSnapshotDigest, RevocationDigest: record.Statements[0].RevocationSnapshotDigest,
		}},
		Ledger: intake.FileLedger{Directory: filepath.Join(t.TempDir(), "protected-ledger")},
	}
	validation, err := intake.VerifyScopedOwnerStatements(record.Subject, record.Statements, authority, SbxLaunchOwnerRequirements(), testSbxNow())
	if err != nil {
		t.Fatal(err)
	}
	return record, validation
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
		CPUCount: profile.Isolation.CPUs, MemoryBytes: profile.Isolation.MemoryBytes, SupervisorLimits: profile.SupervisorLimits,
		SupervisorLimitsApplied: true, NetworkPolicyDigest: profile.Isolation.NetworkPolicy.CanonicalDigest,
		NetworkPolicyState: "ACTIVE_DENY_ALL", InputRoot: request.InputRoot, OutputRoot: request.OutputRoot,
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
