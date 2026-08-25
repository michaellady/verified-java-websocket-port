package securitygate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func TestUS007RegenerateEvidence(t *testing.T) {
	if os.Getenv("US007_REGENERATE") != "1" {
		t.Skip("set US007_REGENERATE=1 to rewrite canonical US-007 evidence")
	}
	root := repoRoot(t)
	read := func(path string) []byte {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var catalog fixtureCatalog
	if err := intake.DecodeStrict(read("security/fixtures/cases.json"), &catalog); err != nil {
		t.Fatal(err)
	}
	snapshot := &policySnapshot{catalog: catalog, bytes: map[string][]byte{}, digests: map[string]string{}, registry: map[string]string{}}
	if err := intake.DecodeStrict(read(policyPaths[0]), &snapshot.ingestion); err != nil {
		t.Fatal(err)
	}
	if err := intake.DecodeStrict(read(policyPaths[1]), &snapshot.sandbox); err != nil {
		t.Fatal(err)
	}
	if err := intake.DecodeStrict(read(policyPaths[2]), &snapshot.release); err != nil {
		t.Fatal(err)
	}
	for _, entries := range [][]registryEntry{snapshot.ingestion.FindingRegistry, snapshot.sandbox.FindingRegistry, snapshot.release.FindingRegistry} {
		for _, entry := range entries {
			snapshot.registry[entry.Code] = entry.Disposition
		}
	}
	for _, path := range policyPaths {
		snapshot.bytes[path] = read(path)
		snapshot.digests[path] = intake.DigestBytes(snapshot.bytes[path])
	}
	for _, path := range baselineEvidencePaths {
		snapshot.bytes[path] = read(path)
		snapshot.digests[path] = intake.DigestBytes(snapshot.bytes[path])
	}
	closure, err := validateAutobahnClosure(snapshot.bytes)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.autobahn = closure
	evidence := validationEvidence{SchemaVersion: policyVersion, Story: "US-007", Company: requiredCompany, Project: requiredProject, PolicyDigests: map[string]string{}, SchemaDigests: map[string]string{}, FixtureCatalogDigest: intake.DigestBytes(read("security/fixtures/cases.json")), AutobahnBaselineDigest: intake.DigestBytes(read("evidence/java/autobahn-baseline.json")), OriginalReceiptDigests: closure.OriginalReceiptDigests, RemediationReceiptDigests: closure.RemediationReceiptDigests, ConsumedRemediationAttemptsPerMode: closure.ConsumedRemediationAttemptsPerMode, FurtherRerunsAuthorized: closure.FurtherRerunsAuthorized, RerunsPerformedByUS007: 0, FixtureResults: []fixtureResult{}, MechanicsState: "BLOCKED_SANDBOX_ENFORCEMENT_UNAVAILABLE", Assurance: AssuranceOwnerOnly, IndependentReviewClaimed: false, Production: false, Signing: false, Publication: false, SandboxMechanics: Finding{Code: "SANDBOX_ENFORCEMENT_UNAVAILABLE", Disposition: "BLOCK", Path: "$.platform_enforcement", Message: "required namespace/profile, resource, mount, network, and cleanup enforcement is not proven; no host-process fallback was used"}, LifecycleIntegration: Finding{Code: "LIFECYCLE_INTEGRATION_UNAVAILABLE", Disposition: "BLOCK", Path: "$.assurance.lifecycle", Message: "the frozen US-004 regeneration adapter has no authorized US-007 security-evidence node seam; assurance artifacts were not hand-edited"}, Runtime: runtimeMetadata{Provider: "OpenAI", RequestedModel: "gpt-5.6-sol", RequestedReasoningEffort: "xhigh", TaskSessionPath: "/root/us007_implementation", ActualDeploymentIdentifier: "not_exposed", RuntimeSessionUUID: "not_exposed"}}
	for _, path := range policyPaths {
		evidence.PolicyDigests[path] = intake.DigestBytes(read(path))
	}
	for _, path := range schemaPaths {
		evidence.SchemaDigests[path] = intake.DigestBytes(read(path))
	}
	for _, item := range catalog.Cases {
		observation, err := evaluateFixture(snapshot, item)
		if err != nil {
			t.Fatalf("evaluate fixture %s: %v", item.ID, err)
		}
		evidence.FixtureResults = append(evidence.FixtureResults, fixtureResult{ID: item.ID, Component: observation.Component, State: observation.State, InputDigest: observation.InputDigest, OutputDigest: observation.OutputDigest, ExpectedCode: item.ExpectedCode, ActualCode: observation.Code, ExpectedDisposition: item.ExpectedDisposition, ActualDisposition: observation.Disposition, CLIExit: observation.Exit, Matched: observation.Code == item.ExpectedCode && observation.Disposition == item.ExpectedDisposition})
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(root, "evidence/security-validation.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
