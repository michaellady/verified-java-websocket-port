package securitygate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// These tests are acceptance specifications for controls that cannot be
// established by looking up an expected finding in the fixture catalog. Every
// input below is inert project-owned text or synthetic receipt data.

func TestUS007Acceptance_InventoryBlocksEveryHostileMetadataClass(t *testing.T) {
	cases := []struct {
		name string
		path string
		data string
	}{
		{
			name: "jvm-dependency",
			path: "pom.xml",
			data: `<project><dependencies><dependency><groupId>example.invalid</groupId><artifactId>inert</artifactId><version>1</version></dependency></dependencies></project>`,
		},
		{
			name: "maven-extension",
			path: ".mvn/extensions.xml",
			data: `<extensions><extension><groupId>example.invalid</groupId><artifactId>inert</artifactId><version>1</version></extension></extensions>`,
		},
		{
			name: "rust-dependency",
			path: "Cargo.lock",
			data: `version = 3

[[package]]
name = "inert"
version = "0.0.0"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
`,
		},
		{
			name: "cargo-runner",
			path: ".cargo/config.toml",
			data: `[target.'cfg(all())']
runner = "inert-runner"
`,
		},
		{
			name: "container-layer",
			path: "container-layer.json",
			data: `{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := t.TempDir()
			target := filepath.Join(candidate, filepath.FromSlash(tc.path))
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}

			verdict, err := Ingest(context.Background(), Request{
				RootPath:          repoRoot(t),
				Operation:         OperationIngest,
				fixtureSourcePath: candidate,
				StorePath:         t.TempDir(),
			})
			if err != nil {
				t.Fatalf("ingest inert %s metadata: %v", tc.name, err)
			}
			if verdict.QuarantineRoot != "" {
				t.Fatalf("%s metadata was promoted before executable promotion: %#v", tc.name, verdict)
			}
			if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "UNPROMOTED_EXECUTABLE" || verdict.Findings[0].Disposition != "QUARANTINE" {
				t.Fatalf("%s findings = %#v, want UNPROMOTED_EXECUTABLE/QUARANTINE", tc.name, verdict.Findings)
			}
		})
	}
}

func TestUS007Acceptance_PromotedManifestBindsTenantProvenance(t *testing.T) {
	candidate := t.TempDir()
	if err := os.WriteFile(filepath.Join(candidate, "safe.txt"), []byte("inert public input"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	verdict, err := Ingest(context.Background(), Request{
		RootPath:          repoRoot(t),
		Operation:         OperationIngest,
		fixtureSourcePath: candidate,
		StorePath:         store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.QuarantineRoot == "" || len(verdict.Findings) != 0 {
		t.Fatalf("benign ingest did not promote: %#v", verdict)
	}
	accepted, err := lab.LoadAcceptedRoot(store, verdict.QuarantineRoot)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, ok := accepted.Object("candidate-manifest")
	if !ok {
		t.Fatal("candidate-manifest is absent from accepted quarantine root")
	}
	var manifest struct {
		Files []struct {
			Path       string `json:"path"`
			Provenance string `json:"provenance"`
		} `json:"files"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 1 {
		t.Fatalf("manifest files = %#v", manifest.Files)
	}
	provenance := manifest.Files[0].Provenance
	for _, required := range []string{requiredCompany, requiredProject, "sha256:"} {
		if !strings.Contains(provenance, required) {
			t.Fatalf("provenance %q for %s omits required tenant/project/digest binding %q", provenance, manifest.Files[0].Path, required)
		}
	}
}

func TestUS007Acceptance_SandboxReceiptRequiresExactEnforcementProof(t *testing.T) {
	root := copySecurityInputs(t)
	snapshot, err := loadPolicies(root)
	if err != nil {
		t.Fatal(err)
	}
	basePlan, baseReceipt := inertSandboxPair(snapshot, "CLEAN_EXIT")
	snapshot.root.Close()

	tests := []struct {
		name        string
		wantCode    string
		wantDispose string
		mutate      func(*sandboxPlan, *securitySandboxReceipt)
	}{
		{
			name:        "closed-canary-id",
			wantCode:    "SANDBOX_RECEIPT_INVALID",
			wantDispose: "QUARANTINE",
			mutate: func(plan *sandboxPlan, receipt *securitySandboxReceipt) {
				plan.CanaryID = "CANDIDATE_SELECTED_COMMAND"
				receipt.CanaryID = plan.CanaryID
			},
		},
		{
			name:        "exact-resource-envelope",
			wantCode:    "SANDBOX_CAPABILITY_MISMATCH",
			wantDispose: "QUARANTINE",
			mutate: func(plan *sandboxPlan, _ *securitySandboxReceipt) {
				plan.Resources.MemoryBytes++
			},
		},
		{
			name:        "termination-is-present",
			wantCode:    "SANDBOX_RECEIPT_INVALID",
			wantDispose: "QUARANTINE",
			mutate: func(_ *sandboxPlan, receipt *securitySandboxReceipt) {
				receipt.TerminationReason = ""
			},
		},
		{
			name:        "complete-platform-observation",
			wantCode:    "SANDBOX_RECEIPT_INVALID",
			wantDispose: "QUARANTINE",
			mutate: func(_ *sandboxPlan, receipt *securitySandboxReceipt) {
				receipt.PlatformIdentity = ""
			},
		},
		{
			name:        "limit-canary-has-exact-termination",
			wantCode:    "RESOURCE_TERMINATION_MISSING",
			wantDispose: "QUARANTINE",
			mutate: func(plan *sandboxPlan, receipt *securitySandboxReceipt) {
				plan.CanaryID = "CPU_BOUND"
				receipt.CanaryID = plan.CanaryID
				receipt.TerminationReason = "EXITED"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := basePlan
			plan.Capabilities = append([]string{}, basePlan.Capabilities...)
			plan.PromotionReceipts = append([]string{}, basePlan.PromotionReceipts...)
			receipt := baseReceipt
			receipt.PromotionReceipts = append([]string{}, baseReceipt.PromotionReceipts...)
			receipt.EnvironmentNames = append([]string{}, baseReceipt.EnvironmentNames...)
			receipt.NamespaceIDs = cloneStringMap(baseReceipt.NamespaceIDs)
			receipt.NetworkAttemptsByClass = cloneIntMap(baseReceipt.NetworkAttemptsByClass)
			observed := *baseReceipt.ObservedResources
			receipt.ObservedResources = &observed
			tc.mutate(&plan, &receipt)
			plan.PlanDigest, err = sandboxPlanDigest(plan)
			if err != nil {
				t.Fatal(err)
			}
			receipt.PlanDigest = plan.PlanDigest
			writeJSON(t, filepath.Join(root, "acceptance-plan.json"), plan)
			writeJSON(t, filepath.Join(root, "acceptance-receipt.json"), receipt)

			verdict, err := VerifySandbox(context.Background(), Request{
				RootPath:    root,
				Operation:   OperationVerifySandbox,
				PlanPath:    "acceptance-plan.json",
				ReceiptPath: "acceptance-receipt.json",
			})
			if err != nil {
				t.Fatalf("verify synthetic receipt: %v", err)
			}
			if len(verdict.Findings) != 1 || verdict.Findings[0].Code != tc.wantCode || verdict.Findings[0].Disposition != tc.wantDispose {
				t.Fatalf("findings = %#v, want %s/%s", verdict.Findings, tc.wantCode, tc.wantDispose)
			}
		})
	}
}

func TestUS007Acceptance_ProjectionRequiresExactQuarantineRoot(t *testing.T) {
	verdict, err := Project(context.Background(), Request{
		RootPath:  repoRoot(t),
		Operation: OperationProject,
		FixtureID: "good-safe-projection",
		StorePath: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.ProjectionRoot != "" {
		t.Fatalf("projection was created without a candidate quarantine root: %#v", verdict)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "PROMOTION_BINDING_MISMATCH" || verdict.Findings[0].Disposition != "QUARANTINE" {
		t.Fatalf("findings = %#v, want PROMOTION_BINDING_MISMATCH/QUARANTINE", verdict.Findings)
	}
}

func TestUS007Acceptance_ReleaseFixtureExpectedFindingCannotGenerateActualFinding(t *testing.T) {
	root := copySecurityInputs(t)
	catalogPath := filepath.Join(root, "security", "fixtures", "cases.json")
	catalogBytes, err := os.ReadFile(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	var catalog fixtureCatalog
	if err := intake.DecodeStrict(catalogBytes, &catalog); err != nil {
		t.Fatal(err)
	}
	found := false
	for index := range catalog.Cases {
		if catalog.Cases[index].ID == "credential-leak" {
			catalog.Cases[index].Input = "inert safe public text"
			found = true
			break
		}
	}
	if !found {
		t.Fatal("credential-leak fixture is absent")
	}
	catalogBytes, err = json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogPath, catalogBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	evidencePath := filepath.Join(root, "evidence", "security-validation.json")
	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	var evidence validationEvidence
	if err := intake.DecodeStrict(evidenceBytes, &evidence); err != nil {
		t.Fatal(err)
	}
	evidence.FixtureCatalogDigest = intake.DigestBytes(catalogBytes)
	writeJSON(t, evidencePath, evidence)

	store, candidateRoot := acceptedProjectionFixture(t, "public/readme.txt", []byte("inert safe public text"), "PUBLIC", true)
	verdict, err := Project(context.Background(), Request{
		RootPath:      root,
		Operation:     OperationProject,
		CandidateRoot: candidateRoot,
		FixtureID:     "credential-leak",
		StorePath:     store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "INVALID_SECURITY_POLICY" || verdict.Findings[0].Disposition != "BLOCK" {
		t.Fatalf("findings = %#v, want INVALID_SECURITY_POLICY/BLOCK for fixture input/expectation mismatch", verdict.Findings)
	}
}
