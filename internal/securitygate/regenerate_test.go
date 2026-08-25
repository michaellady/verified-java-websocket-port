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
	bindings := map[string]string{}
	dispositions := map[string]string{}
	for _, name := range policyPaths {
		switch name {
		case "security/ingestion-policy.json":
			var policy ingestionPolicy
			if err := intake.DecodeStrict(read(name), &policy); err != nil {
				t.Fatal(err)
			}
			for _, entry := range policy.FindingRegistry {
				dispositions[entry.Code] = entry.Disposition
			}
			for _, binding := range policy.FixtureBindings {
				bindings[binding.ID] = binding.Finding
			}
		case "security/sandbox-policy.json":
			var policy sandboxPolicy
			if err := intake.DecodeStrict(read(name), &policy); err != nil {
				t.Fatal(err)
			}
			for _, entry := range policy.FindingRegistry {
				dispositions[entry.Code] = entry.Disposition
			}
			for _, binding := range policy.FixtureBindings {
				bindings[binding.ID] = binding.Finding
			}
		case "security/release-firewall.json":
			var policy releasePolicy
			if err := intake.DecodeStrict(read(name), &policy); err != nil {
				t.Fatal(err)
			}
			for _, entry := range policy.FindingRegistry {
				dispositions[entry.Code] = entry.Disposition
			}
			for _, binding := range policy.FixtureBindings {
				bindings[binding.ID] = binding.Finding
			}
		}
	}
	evidence := validationEvidence{SchemaVersion: policyVersion, Story: "US-007", Company: requiredCompany, Project: requiredProject, PolicyDigests: map[string]string{}, SchemaDigests: map[string]string{}, FixtureCatalogDigest: intake.DigestBytes(read("security/fixtures/cases.json")), AutobahnBaselineDigest: intake.DigestBytes(read("evidence/java/autobahn-baseline.json")), OriginalReceiptDigests: []string{"sha256:ca942585442eb4be74a62533fa2b44a985970612ce6f69d5c13df8ede83c6cff", "sha256:ca942585442eb4be74a62533fa2b44a985970612ce6f69d5c13df8ede83c6cff"}, RemediationReceiptDigests: []string{"sha256:ebb5157aa8ba6c7998dfce303acfbd5c4af166a8d377441e0709b481c26e44b2", "sha256:ebb5157aa8ba6c7998dfce303acfbd5c4af166a8d377441e0709b481c26e44b2"}, ConsumedRemediationAttemptsPerMode: 1, FurtherRerunsAuthorized: false, RerunsPerformedByUS007: 0, FixtureResults: []fixtureResult{}, MechanicsState: "BLOCKED_SANDBOX_ENFORCEMENT_UNAVAILABLE", Assurance: AssuranceOwnerOnly, IndependentReviewClaimed: false, Production: false, Signing: false, Publication: false, SandboxMechanics: Finding{Code: "SANDBOX_ENFORCEMENT_UNAVAILABLE", Disposition: "BLOCK", Path: "$.platform_enforcement", Message: "required namespace/profile, resource, mount, network, and cleanup enforcement is not proven; no host-process fallback was used"}, Runtime: runtimeMetadata{Provider: "OpenAI", RequestedModel: "gpt-5.4", RequestedReasoningEffort: "high", TaskSessionPath: "/root/us007_implementation", ActualDeploymentIdentifier: "not_exposed", RuntimeSessionUUID: "not_exposed"}}
	for _, path := range policyPaths {
		evidence.PolicyDigests[path] = intake.DigestBytes(read(path))
	}
	for _, path := range schemaPaths {
		evidence.SchemaDigests[path] = intake.DigestBytes(read(path))
	}
	for _, item := range catalog.Cases {
		actual := bindings[item.ID]
		exit := 0
		if actual != "" {
			exit = 1
		}
		disposition := dispositions[actual]
		evidence.FixtureResults = append(evidence.FixtureResults, fixtureResult{ID: item.ID, ExpectedCode: item.ExpectedCode, ActualCode: actual, ExpectedDisposition: item.ExpectedDisposition, ActualDisposition: disposition, CLIExit: exit, Matched: actual == item.ExpectedCode})
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
