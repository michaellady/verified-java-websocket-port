package assurance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

func TestVerifyCanonicalLifecycle(t *testing.T) {
	root := repoRoot(t)
	verdict, err := Verify(context.Background(), Request{
		RootPath:      root,
		LifecyclePath: "assurance/lifecycle.json",
		Mode:          ModeVerify,
	})
	if err != nil {
		t.Fatalf("verify canonical lifecycle: %v", err)
	}
	if verdict.State != "BLOCKED" {
		t.Fatalf("state = %q, want BLOCKED", verdict.State)
	}
	assertFinding(t, verdict.Findings, "INVALID_ATTESTATION", vendorprotocol.Block)
	if len(verdict.Findings) != 2 {
		t.Fatalf("canonical lifecycle produced unexpected findings: %+v", verdict.Findings)
	}
	if verdict.Assurance != assuranceCeiling {
		t.Fatalf("assurance = %q, want %q", verdict.Assurance, assuranceCeiling)
	}
	if verdict.IndependentReviewClaimed {
		t.Fatal("canonical lifecycle must not claim independent review")
	}
	if verdict.SnapshotRoot == "" || verdict.PublicEvidenceRoot == "" {
		t.Fatalf("roots missing from verdict: %+v", verdict)
	}
}

func TestVerifyCanonicalLifecycleIntegratesSecurityValidation(t *testing.T) {
	bundle := readLifecycleBundle(t, repoRoot(t), lifecyclePathDefault)

	foundNode := false
	for _, node := range bundle.Nodes {
		if node.ID != "evidence-security-validation" {
			continue
		}
		foundNode = true
		if node.Kind != "evidence" || node.Classification != "PUBLIC_DERIVED" {
			t.Fatalf("security validation node = %+v, want evidence/PUBLIC_DERIVED", node)
		}
	}
	if !foundNode {
		t.Fatal("canonical lifecycle is missing evidence-security-validation")
	}

	foundEdge := false
	for _, edge := range bundle.Edges {
		if edge.From == bundle.RootNodeID && edge.To == "evidence-security-validation" && edge.Kind == "supports" {
			foundEdge = true
		}
	}
	if !foundEdge {
		t.Fatal("security validation evidence is not directly reachable from the lifecycle root")
	}

	verifyStage := mustStage(t, bundle, "verify")
	foundInput := false
	for _, input := range verifyStage.Inputs {
		if input == "evidence-security-validation" {
			foundInput = true
		}
	}
	if !foundInput {
		t.Fatal("verify stage does not bind evidence-security-validation as an input")
	}
}

func TestVerifyRejectsVendoredManifestDrift(t *testing.T) {
	root := copiedAssuranceRoot(t)
	target := filepath.Join(root, "third_party", "verified-java-to-rust-foundation", "protocol", "canonical.go")
	if err := os.WriteFile(target, []byte("drift"), 0o600); err != nil {
		t.Fatalf("drift vendored file: %v", err)
	}
	verdict, err := Verify(context.Background(), Request{
		RootPath:      root,
		LifecyclePath: "assurance/lifecycle.json",
		Mode:          ModeVerify,
	})
	if err != nil {
		t.Fatalf("verify vendored drift: %v", err)
	}
	assertFinding(t, verdict.Findings, "VENDORED_FILE_DIGEST_MISMATCH", vendorprotocol.Block)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func copiedAssuranceRoot(t *testing.T) string {
	t.Helper()
	source := repoRoot(t)
	destination := t.TempDir()
	for _, relative := range []string{
		"assurance",
		"evidence",
		"schemas",
		"third_party",
	} {
		if err := copyDir(filepath.Join(source, relative), filepath.Join(destination, relative)); err != nil {
			t.Fatalf("copy %s: %v", relative, err)
		}
	}
	return destination
}

func copyDir(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}

func assertFinding(t *testing.T, findings []vendorprotocol.Finding, code string, disposition vendorprotocol.Disposition) {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code && finding.Disposition == disposition {
			return
		}
	}
	t.Fatalf("missing finding %s/%s in %+v", code, disposition, findings)
}

type replayCaseCatalog struct {
	DispositionCoverage replayDispositionCoverage `json:"disposition_coverage"`
	Cases               []replayCase              `json:"cases"`
}

type replayCase struct {
	ID                   string                  `json:"id"`
	LifecyclePath        string                  `json:"lifecycle_path"`
	MutationManifestPath string                  `json:"mutation_manifest_path"`
	ExactFindings        bool                    `json:"exact_findings"`
	VerifyFindings       []replayCaseExpectation `json:"verify_findings"`
	ReplayFindings       []replayCaseExpectation `json:"replay_findings"`
	CLI                  replayCaseCLI           `json:"cli"`
}

type replayCaseExpectation struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
	Count       int    `json:"count"`
}

type replayCaseCLI struct {
	VerifyExitCode int `json:"verify_exit_code"`
	ReplayExitCode int `json:"replay_exit_code"`
}

type replayDispositionCoverage struct {
	CaseMapped   []replayDispositionMapping `json:"case_mapped"`
	RegistryOnly []replayDispositionCodes   `json:"registry_only"`
}

type replayDispositionMapping struct {
	Disposition string   `json:"disposition"`
	CaseIDs     []string `json:"case_ids"`
}

type replayDispositionCodes struct {
	Disposition string   `json:"disposition"`
	Codes       []string `json:"codes"`
}

func loadReplayCaseCatalog(t *testing.T) replayCaseCatalog {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "assurance", "replay", "fixtures", "cases.json"))
	if err != nil {
		t.Fatalf("read replay cases: %v", err)
	}
	var catalog replayCaseCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatalf("decode replay cases: %v", err)
	}
	return catalog
}
