package lab

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

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
	if spec.Arguments[len(spec.Arguments)-2] != "-DargLine=-Djava.net.preferIPv4Stack=true" {
		t.Fatalf("test spec omitted the IPv4-only child JVM network identity: %+v", spec.Arguments)
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
	if err := receipt.Validate(plan); err != nil {
		t.Fatal(err)
	}
	receipt.ObservedTCBExecutables[0].Digest = intake.DigestBytes([]byte("hostile-shell"))
	assertFinding(t, receipt.Validate(plan), "TCB_EXECUTABLE_MISMATCH")
	receipt.ObservedTCBExecutables = expectedTCBExecutables(plan)
	receipt.ObservedEndpoints = []string{"attacker.invalid:443"}
	assertFinding(t, receipt.Validate(plan), "NETWORK_POLICY_VIOLATION")
	receipt.ObservedEndpoints = nil
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
	receipt.EnforcementCanaries.MemoryLimitEnforced = false
	assertFinding(t, receipt.Validate(plan), "SANDBOX_CANARY_INCOMPLETE")
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
