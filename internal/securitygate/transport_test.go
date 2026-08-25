package securitygate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

func TestUS007Acceptance_BenignIngestPromotesOneReadCAS(t *testing.T) {
	candidate := t.TempDir()
	if err := os.WriteFile(filepath.Join(candidate, "one.txt"), []byte("same inert bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "two.txt"), []byte("same inert bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	verdict, err := Ingest(context.Background(), Request{RootPath: repoRoot(t), Operation: OperationIngest, fixtureSourcePath: candidate, StorePath: store})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.State != "PASS_SYNTHETIC_NON_CLAIM" || verdict.QuarantineRoot == "" || len(verdict.Findings) != 0 {
		t.Fatalf("verdict=%#v", verdict)
	}
	accepted, err := lab.LoadAcceptedRoot(store, verdict.QuarantineRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted.Objects()) != 2 {
		t.Fatalf("objects=%d, want one blob plus manifest", len(accepted.Objects()))
	}
	replay, err := Ingest(context.Background(), Request{RootPath: repoRoot(t), Operation: OperationIngest, fixtureSourcePath: candidate, StorePath: store})
	if err != nil || replay.QuarantineRoot != verdict.QuarantineRoot {
		t.Fatalf("idempotent replay=%#v err=%v", replay, err)
	}
}

func TestUS007Acceptance_IngestDeniesInventoryAndOverlap(t *testing.T) {
	candidate := t.TempDir()
	if err := os.WriteFile(filepath.Join(candidate, "pom.xml"), []byte("<project><plugin>inert</plugin></project>"), 0o600); err != nil {
		t.Fatal(err)
	}
	verdict, err := Ingest(context.Background(), Request{RootPath: repoRoot(t), Operation: OperationIngest, fixtureSourcePath: candidate, StorePath: t.TempDir()})
	if err != nil || len(verdict.Findings) != 1 || verdict.Findings[0].Code != "UNPROMOTED_EXECUTABLE" {
		t.Fatalf("verdict=%#v err=%v", verdict, err)
	}
	if err := os.Mkdir(filepath.Join(candidate, "store"), 0o700); err != nil {
		t.Fatal(err)
	}
	overlap, err := Ingest(context.Background(), Request{RootPath: repoRoot(t), Operation: OperationIngest, fixtureSourcePath: candidate, StorePath: filepath.Join(candidate, "store")})
	if err != nil || len(overlap.Findings) != 1 || overlap.Findings[0].Code != "ROOT_CONFINEMENT_FAILED" {
		t.Fatalf("overlap=%#v err=%v", overlap, err)
	}
}

func TestUS007Acceptance_ArchiveAdaptersNeverExtract(t *testing.T) {
	policy := ingestionPolicy{Quotas: quotaPolicy{MaxArchiveEntries: 4, MaxFileBytes: 1024, MaxExpandedBytes: 2048, MaxArchiveDepth: 4}}
	var zipBytes bytes.Buffer
	zw := zip.NewWriter(&zipBytes)
	member, err := zw.Create("safe.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write([]byte("inert")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if media, finding := inspectArchive("safe.zip", zipBytes.Bytes(), policy); media != "ZIP" || finding != nil {
		t.Fatalf("media=%s finding=%#v", media, finding)
	}
	var tarBytes bytes.Buffer
	tw := tar.NewWriter(&tarBytes)
	if err := tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o600, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, finding := inspectArchive("bad.tar", tarBytes.Bytes(), policy); finding == nil || finding.Code != "PATH_TRAVERSAL" {
		t.Fatalf("finding=%#v", finding)
	}
	if media, finding := inspectArchive("plain.txt", []byte("plain"), policy); media != "REGULAR" || finding != nil {
		t.Fatalf("media=%s finding=%#v", media, finding)
	}
}

func TestUS007Acceptance_PathAndInventoryClassifiers(t *testing.T) {
	policy := pathPolicy{MaxDepth: 2, MaxComponent: 8, MaxPath: 16}
	cases := []struct{ name, code string }{{"/abs", "ABSOLUTE_PATH"}, {"a\\b", "PATH_TRAVERSAL"}, {"../x", "PATH_TRAVERSAL"}, {"a/b/c", "PATH_TRAVERSAL"}, {"toolonggg", "PATH_TRAVERSAL"}, {"e\u0301.txt", "NONCANONICAL_PATH"}, {"ok.txt", ""}}
	for _, tc := range cases {
		if code, _ := validateCandidatePath(tc.name, policy); code != tc.code {
			t.Fatalf("%q code=%q want=%q", tc.name, code, tc.code)
		}
	}
	classCases := []struct{ name, data, want string }{{"build.rs", "", "CARGO_BUILD_SCRIPT"}, {"Cargo.toml", "proc-macro = true", "RUST_PROC_MACRO"}, {"jdt-config.json", "{}", "JDT_LS_IMPORT"}, {"autobahn.txt", "", "AUTOBAHN_SCRIPT"}, {"container.json", "{\"Entrypoint\":[]}", "CONTAINER_ENTRYPOINT"}, {"readme.md", "", ""}}
	for _, tc := range classCases {
		if got := classifyExecutable(tc.name, []byte(tc.data), 0o600); got != tc.want {
			t.Fatalf("%s class=%q want=%q", tc.name, got, tc.want)
		}
	}
	if got := classifyExecutable("fixed-canary", nil, 0o700); got != "ARCHIVE_DECLARED_EXECUTABLE" {
		t.Fatalf("executable class=%q", got)
	}
}

func TestUS007Acceptance_SandboxReceiptClosure(t *testing.T) {
	snapshot, err := loadPolicies(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.root.Close()
	plan, receipt := inertSandboxPair(snapshot, "CLEAN_EXIT")
	if finding := validateSandboxReceipt(snapshot, plan, receipt); finding != nil {
		t.Fatalf("good receipt=%#v", finding)
	}
	tests := []struct {
		want   string
		mutate func(*sandboxPlan, *securitySandboxReceipt)
	}{
		{"SANDBOX_RECEIPT_INVALID", func(_ *sandboxPlan, r *securitySandboxReceipt) { r.PlanDigest = "wrong" }},
		{"SANDBOX_RECEIPT_INVALID", func(p *sandboxPlan, _ *securitySandboxReceipt) { p.Capabilities = nil }},
		{"SECRET_ACCESS_DENIED", func(_ *sandboxPlan, r *securitySandboxReceipt) { r.SecretValueCount = 1 }},
		{"NETWORK_POLICY_VIOLATION", func(_ *sandboxPlan, r *securitySandboxReceipt) { r.AllowedEndpointCount = 1 }},
		{"ARTIFACT_CAPTURE_INCOMPLETE", func(_ *sandboxPlan, r *securitySandboxReceipt) { r.ArtifactCaptureComplete = false }},
		{"SOURCE_MUTATION_DETECTED", func(_ *sandboxPlan, r *securitySandboxReceipt) { r.SourceAfterDigest = "changed" }},
		{"CACHE_CLOSURE_MISMATCH", func(_ *sandboxPlan, r *securitySandboxReceipt) { r.CacheAfterDigest = "changed" }},
		{"SANDBOX_CLEANUP_INCOMPLETE", func(_ *sandboxPlan, r *securitySandboxReceipt) { r.LivePIDsAfter = 1 }},
		{"ASSURANCE_CEILING_EXCEEDED", func(_ *sandboxPlan, r *securitySandboxReceipt) { r.IndependentReviewClaimed = true }},
	}
	for _, tc := range tests {
		p := plan
		p.Capabilities = append([]string(nil), plan.Capabilities...)
		p.PromotionReceipts = append([]string(nil), plan.PromotionReceipts...)
		r := receipt
		r.PromotionReceipts = append([]string(nil), receipt.PromotionReceipts...)
		tc.mutate(&p, &r)
		finding := validateSandboxReceipt(snapshot, p, r)
		if finding == nil || finding.Code != tc.want {
			t.Fatalf("finding=%#v want=%s", finding, tc.want)
		}
	}
}

func TestUS007Acceptance_VerifySandboxAndProjectSeams(t *testing.T) {
	root := copySecurityInputs(t)
	snapshot, err := loadPolicies(root)
	if err != nil {
		t.Fatal(err)
	}
	plan, receipt := inertSandboxPair(snapshot, "CLEAN_EXIT")
	snapshot.root.Close()
	writeJSON(t, filepath.Join(root, "plan.json"), plan)
	writeJSON(t, filepath.Join(root, "receipt.json"), receipt)
	verdict, err := VerifySandbox(context.Background(), Request{RootPath: root, Operation: OperationVerifySandbox, PlanPath: "plan.json", ReceiptPath: "receipt.json"})
	if err != nil || len(verdict.Findings) != 1 || verdict.Findings[0].Code != "SANDBOX_ENFORCEMENT_UNAVAILABLE" {
		t.Fatalf("sandbox verdict=%#v err=%v", verdict, err)
	}
	goodStore, goodRoot := acceptedProjectionFixture(t, "public/readme.txt", []byte("inert safe public bytes"), "PUBLIC", true)
	good, err := Project(context.Background(), Request{RootPath: root, Operation: OperationProject, CandidateRoot: goodRoot, StorePath: goodStore, FixtureID: "good-safe-projection"})
	if err != nil || good.State != "PASS_SYNTHETIC_NON_CLAIM" || good.ProjectionRoot == "" {
		t.Fatalf("good projection=%#v err=%v", good, err)
	}
	badStore, badRoot := acceptedProjectionFixture(t, "public/readme.txt", []byte("SYNTHETIC_TOKEN_VALUE"), "PUBLIC", true)
	bad, err := Project(context.Background(), Request{RootPath: root, Operation: OperationProject, CandidateRoot: badRoot, StorePath: badStore, FixtureID: "credential-leak"})
	if err != nil || len(bad.Findings) != 1 || bad.Findings[0].Code != "CREDENTIAL_DISCLOSURE" {
		t.Fatalf("bad projection=%#v err=%v", bad, err)
	}
	realStore, realRoot := acceptedProjectionFixture(t, "public/readme.txt", []byte("inert safe public bytes"), "PUBLIC", true)
	real, err := Project(context.Background(), Request{RootPath: root, Operation: OperationProject, CandidateRoot: realRoot, StorePath: realStore})
	if err != nil || len(real.Findings) != 1 || real.Findings[0].Code != "PROTECTED_CLASSIFIER_UNAVAILABLE" {
		t.Fatalf("real projection=%#v err=%v", real, err)
	}
}

func TestUS007Acceptance_RetainedEvidenceMutationClosure(t *testing.T) {
	snapshot, err := loadPolicies(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.root.Close()
	original := snapshot.evidence
	tests := []struct {
		want   string
		mutate func(*validationEvidence)
	}{
		{"ASSURANCE_CEILING_EXCEEDED", func(e *validationEvidence) { e.IndependentReviewClaimed = true }},
		{"POLICY_DIGEST_MISMATCH", func(e *validationEvidence) {
			e.PolicyDigests = cloneMap(e.PolicyDigests)
			e.PolicyDigests[policyPaths[0]] = "sha256:" + strings.Repeat("0", 64)
		}},
		{"POLICY_DIGEST_MISMATCH", func(e *validationEvidence) {
			e.SchemaDigests = cloneMap(e.SchemaDigests)
			e.SchemaDigests[schemaPaths[0]] = "sha256:" + strings.Repeat("0", 64)
		}},
		{"POLICY_DIGEST_MISMATCH", func(e *validationEvidence) { e.FixtureCatalogDigest = "sha256:" + strings.Repeat("0", 64) }},
		{"CANONICAL_EVIDENCE_MUTATION", func(e *validationEvidence) { e.RerunsPerformedByUS007 = 1 }},
		{"SANDBOX_RECEIPT_INVALID", func(e *validationEvidence) { e.SandboxMechanics.Code = "" }},
		{"INVALID_SECURITY_POLICY", func(e *validationEvidence) { e.LifecycleIntegration.EvidenceNodeID = "" }},
		{"INVALID_SECURITY_POLICY", func(e *validationEvidence) { e.FixtureResults = nil }},
		{"INVALID_SECURITY_POLICY", func(e *validationEvidence) {
			e.FixtureResults = append([]fixtureResult{}, e.FixtureResults...)
			e.FixtureResults[0].ActualCode = "wrong"
		}},
	}
	for _, tc := range tests {
		snapshot.evidence = original
		tc.mutate(&snapshot.evidence)
		findings := verifyRetainedEvidence(snapshot)
		if len(findings) != 1 || findings[0].Code != tc.want {
			t.Fatalf("findings=%#v want=%s", findings, tc.want)
		}
	}
	snapshot.evidence = original
}

func TestUS007Acceptance_StrictPolicyDocuments(t *testing.T) {
	root := copySecurityInputs(t)
	policyPath := filepath.Join(root, "security", "sandbox-policy.json")
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(data, []byte("{\n"), []byte("{\n  \"unknown\": true,\n"), 1)
	if err := os.WriteFile(policyPath, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPolicies(root); err == nil || !strings.Contains(err.Error(), "INVALID_SECURITY_POLICY/BLOCK") {
		t.Fatalf("unknown field err=%v", err)
	}
	root = copySecurityInputs(t)
	policyPath = filepath.Join(root, "security", "ingestion-policy.json")
	data, err = os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(data, []byte("\"schema_version\": \"1.0.0\","), []byte("\"schema_version\": \"1.0.0\",\n  \"schema_version\": \"1.0.0\","), 1)
	if err := os.WriteFile(policyPath, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPolicies(root); err == nil || !strings.Contains(err.Error(), "INVALID_SECURITY_POLICY/BLOCK") {
		t.Fatalf("duplicate field err=%v", err)
	}
}

func copySecurityInputs(t *testing.T) string {
	t.Helper()
	source := repoRoot(t)
	root := t.TempDir()
	paths := append(append([]string{}, policyPaths...), schemaPaths...)
	paths = append(paths, "security/fixtures/cases.json", "evidence/security-validation.json")
	paths = append(paths, baselineEvidencePaths...)
	for _, name := range paths {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
func cloneMap(source map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneStringMap(source map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneIntMap(source map[string]int) map[string]int {
	result := map[string]int{}
	for key, value := range source {
		result[key] = value
	}
	return result
}
