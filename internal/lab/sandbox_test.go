package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func TestControlledCanaryRequestIsClosedAndRequiresAuthenticatedPromotions(t *testing.T) {
	request := ControlledCanaryRequest{
		CanaryID: "CLEAN_EXIT", PolicyDigest: intake.DigestBytes([]byte("sandbox-policy")),
		Resources: validSandboxPlan(t, SandboxMavenBuild).Resources,
	}
	planDigest, err := ControlledCanaryPlanDigest(request)
	if runtime.GOOS != "darwin" {
		assertFinding(t, err, "PLATFORM_EXECUTOR_UNSUPPORTED")
		request.PlanDigest = intake.DigestBytes([]byte("unavailable-platform-plan"))
		assertClosedCanaryRequestEncoding(t, request)
		if _, executeErr := ExecuteControlledCanary(request); executeErr == nil {
			t.Fatal("unsupported platform accepted controlled canary execution")
		} else {
			assertFinding(t, executeErr, "PLATFORM_EXECUTOR_UNSUPPORTED")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	request.PlanDigest = planDigest
	assertClosedCanaryRequestEncoding(t, request)
	if _, err := ExecuteControlledCanary(request); err == nil {
		t.Fatal("unpromoted self executable was allowed to run")
	} else {
		assertFinding(t, err, "UNPROMOTED_EXECUTABLE")
	}

	tests := []struct {
		name   string
		mutate func(*ControlledCanaryRequest)
	}{
		{"canary", func(r *ControlledCanaryRequest) { r.CanaryID = "CALLER_SELECTED" }},
		{"policy", func(r *ControlledCanaryRequest) { r.PolicyDigest = "candidate-policy" }},
		{"plan", func(r *ControlledCanaryRequest) { r.PlanDigest = intake.DigestBytes([]byte("different-plan")) }},
		{"resources", func(r *ControlledCanaryRequest) { r.Resources.WallTimeSeconds = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := request
			test.mutate(&mutated)
			if _, err := ExecuteControlledCanary(mutated); err == nil {
				t.Fatal("open or malformed controlled-canary request was accepted")
			}
		})
	}
}

func assertClosedCanaryRequestEncoding(t *testing.T, request ControlledCanaryRequest) {
	t.Helper()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"path", "argument", "environment", "operation", "secret", "signing", "publication"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("closed request exposed caller-controlled %s: %s", forbidden, encoded)
		}
	}
}

func validSandboxPlan(t *testing.T, operation SandboxOperation) SandboxPlan {
	t.Helper()
	base := t.TempDir()
	offline := operation != SandboxMavenAcquire
	network := NetworkPolicy{Mode: "deny-all", AuditRequired: true}
	if operation == SandboxMavenAcquire {
		network = NetworkPolicy{Mode: "maven-central-only", AllowedEndpoints: []string{"https://repo.maven.apache.org:443"}, AuditRequired: true}
	}
	if operation == SandboxMavenTest {
		network = NetworkPolicy{Mode: "loopback-only", AllowedEndpoints: []string{"127.0.0.1:*"}, AuditRequired: true}
	}
	if operation == SandboxAutobahnClient || operation == SandboxAutobahnServer {
		network = NetworkPolicy{Mode: "local-autobahn", AllowedEndpoints: []string{"127.0.0.1:9001"}, AuditRequired: true}
	}
	plan := SandboxPlan{
		SchemaVersion: "1.0.0", PlanID: "plan-0000000000000001", Operation: operation,
		AcceptedRootDigest: intake.DigestBytes([]byte("root")), ExecutableObjectID: operationExecutable[operation],
		SourceDirectory: filepath.Join(base, "source"), ToolDirectory: filepath.Join(base, "tools"), WorkspaceDirectory: filepath.Join(base, "workspace"),
		CacheDirectory: filepath.Join(base, "cache"), OutputDirectory: filepath.Join(base, "output"),
		Resources: ResourceLimits{WallTimeSeconds: 60, CPUTimeSeconds: 30, MemoryBytes: 128 << 20, MaxProcesses: 16, MaxOpenFiles: 128, MaxOutputBytes: 1 << 20, MaxWorkspaceBytes: 64 << 20},
		Cache:     CachePolicy{Isolated: true, Mode: "disposable", ClosureManifest: intake.DigestBytes([]byte("cache")), OfflineAuthoritative: offline},
		Source:    SourcePolicy{ReadOnly: true, NoFollowLinks: true, AcceptedRootOnly: true, ProductionUnmodified: true},
		Network:   network, Secrets: "none",
	}
	environment, err := SanitizedEnvironment(plan.ToolDirectory, plan.WorkspaceDirectory, plan.CacheDirectory)
	if err != nil {
		t.Fatal(err)
	}
	plan.Environment = environment
	if operation == SandboxMavenAcquire {
		plan.Cache.ClosureManifest = GenesisLedgerHead
	}
	return plan
}

func TestCanonicalMavenSelectorAndOwnerAttestedOverlayAreExact(t *testing.T) {
	selector := strings.Split(canonicalMavenTestSelector, ",")
	set, err := exactSet(selector, "$.selector", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 62 {
		t.Fatalf("canonical selector contains %d classes, want 62", len(set))
	}
	for index := 1; index < len(selector); index++ {
		if selector[index-1] >= selector[index] {
			t.Fatalf("canonical selector is not strictly sorted at %d", index)
		}
	}
	overlay, err := os.ReadFile(filepath.Join("..", "..", "evidence", "java", mavenTestSecurityOverlayName))
	if err != nil {
		t.Fatal(err)
	}
	if string(overlay) != mavenTestSecurityOverlay || intake.DigestBytes(overlay) != mavenTestSecurityOverlayDigest {
		t.Fatal("committed owner-attested overlay differs from its compiled exact pin")
	}
	value, ok := javaSecurityProperty(overlay, "jdk.tls.disabledAlgorithms")
	if !ok || normalizeSecurityList(value) != overlaidTLSDisabledAlgorithms || strings.Contains(normalizeSecurityList(value), "TLS_RSA_*") {
		t.Fatal("overlay did not remove exactly the TLS_RSA_* token")
	}
}

func TestSandboxOperationsAreClosedAndMavenAcquisitionIsSeparate(t *testing.T) {
	for _, operation := range []SandboxOperation{SandboxMavenAcquire, SandboxMavenBuild, SandboxMavenTest, SandboxJavaOracle, SandboxAutobahnClient, SandboxAutobahnServer} {
		plan := validSandboxPlan(t, operation)
		if err := plan.Validate(); err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
	}
	plan := validSandboxPlan(t, SandboxMavenBuild)
	plan.Network = NetworkPolicy{Mode: "maven-central-only", AllowedEndpoints: []string{"https://repo.maven.apache.org:443"}, AuditRequired: true}
	assertFinding(t, plan.Validate(), "NETWORK_POLICY_VIOLATION")
	plan = validSandboxPlan(t, SandboxMavenAcquire)
	plan.Network.AllowedEndpoints[0] = "https://attacker.invalid:443"
	assertFinding(t, plan.Validate(), "NETWORK_POLICY_VIOLATION")
}

func TestSandboxPlanRejectsAmbientAuthorityAndArbitraryCommands(t *testing.T) {
	tests := map[string]func(*SandboxPlan){
		"operation":  func(p *SandboxPlan) { p.Operation = SandboxOperation("shell") },
		"executable": func(p *SandboxPlan) { p.ExecutableObjectID = "candidate-tool" },
		"secret":     func(p *SandboxPlan) { p.Secrets = "AWS_TOKEN" },
		"environment": func(p *SandboxPlan) {
			p.Environment = append(p.Environment, EnvironmentVariable{Name: "TOKEN", Value: "x"})
		},
		"environment-value": func(p *SandboxPlan) { p.Environment[0].Value = "/tmp/attacker-home" },
		"source-write":      func(p *SandboxPlan) { p.Source.ReadOnly = false },
		"tool-overlap":      func(p *SandboxPlan) { p.ToolDirectory = filepath.Join(p.SourceDirectory, "tools") },
		"overlap":           func(p *SandboxPlan) { p.OutputDirectory = filepath.Join(p.WorkspaceDirectory, "output") },
		"resource":          func(p *SandboxPlan) { p.Resources.WallTimeSeconds = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := validSandboxPlan(t, SandboxMavenTest)
			mutate(&plan)
			if err := plan.Validate(); err == nil {
				t.Fatal("hostile plan accepted")
			}
		})
	}
}

func TestSandboxSpecAndReceiptBindExactPlan(t *testing.T) {
	plan := validSandboxPlan(t, SandboxMavenTest)
	executable := intake.Object{ID: operationExecutable[SandboxMavenTest], Bytes: []byte("maven distribution")}
	executable.Digest = intake.DigestBytes(executable.Bytes)
	rootDigestInput := executable.ID + "=" + executable.Digest + "\n"
	root := &AcceptedRoot{
		manifest: AcceptedManifest{SchemaVersion: "1.0.0", RootDigest: intake.DigestBytes([]byte(rootDigestInput))},
		objects:  []intake.Object{executable},
	}
	plan.AcceptedRootDigest = root.manifest.RootDigest
	spec, err := BuildExecutionSpec(plan, root)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Arguments[0] != "--offline" || spec.Profile == "" {
		t.Fatalf("unsafe spec: %+v", spec)
	}
	joinedArguments := strings.Join(spec.Arguments, "\n")
	if !strings.Contains(joinedArguments, "-Dtest="+canonicalMavenTestSelector) || !strings.Contains(joinedArguments, "-Djava.security.properties="+filepath.Join(plan.OutputDirectory, mavenTestSecurityOverlayName)) {
		t.Fatalf("test spec omitted its canonical selector or isolated security overlay: %+v", spec.Arguments)
	}
	planDigest, _ := plan.Digest()
	environment, _ := intake.CanonicalJSON(plan.Environment)
	now := time.Unix(1_700_000_000, 0).UTC()
	receipt := SandboxReceipt{
		SchemaVersion: "1.0.0", PlanDigest: planDigest, StartedAt: now, FinishedAt: now.Add(time.Second), ExitCode: 0,
		ObservedMaxMemory: 1, ObservedOutputBytes: 1, EnvironmentDigest: intake.DigestBytes(environment),
		SourceBeforeDigest: intake.DigestBytes([]byte("source")), SourceAfterDigest: intake.DigestBytes([]byte("source")), CacheManifestDigest: plan.Cache.ClosureManifest,
		EnforcementCanaries: completeCanaries(),
	}
	receipt.ObservedEndpoints = append(receipt.ObservedEndpoints, plan.Network.AllowedEndpoints...)
	receipt.ObservedTCBExecutables = expectedTCBExecutables(plan)
	bindTestPolicyReceipt(&receipt, plan)
	if err := receipt.Validate(plan); err != nil {
		t.Fatal(err)
	}
	receipt.ObservedTCBExecutables[0].Digest = intake.DigestBytes([]byte("hostile-shell"))
	assertFinding(t, receipt.Validate(plan), "TCB_EXECUTABLE_MISMATCH")
	receipt.ObservedTCBExecutables = expectedTCBExecutables(plan)
	receipt.ObservedEndpoints = []string{"attacker.invalid:443"}
	assertFinding(t, receipt.Validate(plan), "NETWORK_POLICY_VIOLATION")
	receipt.ObservedEndpoints = nil
	receipt.IndependentReview = true
	assertFinding(t, receipt.Validate(plan), "TEST_POLICY_BINDING_MISMATCH")
	receipt.IndependentReview = false
	receipt.ObservedCPUSeconds = plan.Resources.CPUTimeSeconds + 1
	assertFinding(t, receipt.Validate(plan), "RESOURCE_LIMIT_EXCEEDED")
}

func TestSandboxReceiptRequiresEveryEnforcementCanary(t *testing.T) {
	plan := validSandboxPlan(t, SandboxMavenTest)
	planDigest, _ := plan.Digest()
	environment, _ := intake.CanonicalJSON(plan.Environment)
	now := time.Unix(1_700_000_000, 0).UTC()
	receipt := SandboxReceipt{
		SchemaVersion: "1.0.0", PlanDigest: planDigest, StartedAt: now, FinishedAt: now.Add(time.Second), ExitCode: 0,
		ObservedMaxMemory: 1, ObservedOutputBytes: 1, EnvironmentDigest: intake.DigestBytes(environment),
		SourceBeforeDigest: intake.DigestBytes([]byte("source")), SourceAfterDigest: intake.DigestBytes([]byte("source")), CacheManifestDigest: plan.Cache.ClosureManifest,
		EnforcementCanaries: completeCanaries(),
	}
	receipt.ObservedEndpoints = append(receipt.ObservedEndpoints, plan.Network.AllowedEndpoints...)
	receipt.ObservedTCBExecutables = expectedTCBExecutables(plan)
	bindTestPolicyReceipt(&receipt, plan)
	receipt.EnforcementCanaries.MemoryLimitEnforced = false
	assertFinding(t, receipt.Validate(plan), "SANDBOX_CANARY_INCOMPLETE")
}

func bindTestPolicyReceipt(receipt *SandboxReceipt, plan SandboxPlan) {
	if plan.Operation != SandboxMavenTest {
		return
	}
	receipt.JavaSecurityDigest = promotedJavaSecurityDigest
	receipt.TestSecurityDigest = mavenTestSecurityOverlayDigest
	receipt.TestInventoryDigest = intake.DigestBytes([]byte("inventory"))
	receipt.Assurance = ownerAttestedNotIndependent
	receipt.IndependentReview = false
}

func expectedTCBExecutables(plan SandboxPlan) []TCBExecutable {
	if plan.Operation != SandboxMavenTest {
		return []TCBExecutable{}
	}
	return []TCBExecutable{
		{Path: "/bin/sh", Digest: darwinMavenTestShellDigest, Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT"},
		{Path: "/bin/bash", Digest: darwinMavenTestBashDigest, Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT"},
	}
}

func completeCanaries() SandboxEnforcementCanaries {
	return SandboxEnforcementCanaries{
		SanitizedEnvironment: true, UserHomeDenied: true, SourceWriteDenied: true, DisjointWritesOnly: true,
		WallTimeEnforced: true, OutputLimitEnforced: true, WorkspaceLimitEnforced: true,
		ProcessLimitEnforced: true, CPULimitEnforced: true, MemoryLimitEnforced: true,
		OpenFileLimitEnforced: true, NetworkPolicyEnforced: true,
	}
}

func TestStrictSandboxDecodersRejectUnknownFields(t *testing.T) {
	_, err := DecodeSandboxPlan([]byte(`{"schema_version":"1.0.0","command":"sh"}`))
	assertFinding(t, err, "UNKNOWN_JSON_FIELD")
	plan := validSandboxPlan(t, SandboxMavenTest)
	_, err = DecodeSandboxReceipt([]byte(`{"schema_version":"1.0.0","argv":["sh"]}`), plan)
	assertFinding(t, err, "UNKNOWN_JSON_FIELD")
}
