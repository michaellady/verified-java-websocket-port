package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyCommandEmitsCanonicalJSON(t *testing.T) {
	repo := repoRoot(t)
	command := exec.Command(assurectlBinary(t), "verify", "--root", repo, "--lifecycle", "assurance/lifecycle.json")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify command to fail closed for canonical owner-only lifecycle, output=%s", output)
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("verify output is not canonical JSON: %v\n%s", err, output)
	}
	if result["state"] != "BLOCKED" {
		t.Fatalf("state = %v, want BLOCKED", result["state"])
	}
	findings, ok := result["findings"].([]any)
	if !ok || len(findings) != 2 {
		t.Fatalf("findings = %#v, want exactly two inherited attestation blockers", result["findings"])
	}
}

func TestReplayCommandReturnsNonZeroOnFindings(t *testing.T) {
	repo := repoRoot(t)
	command := exec.Command(assurectlBinary(t), "replay", "--root", repo, "--lifecycle", "assurance/replay/fixtures/cycle/lifecycle.json")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("expected replay command to fail, output=%s", output)
	}
	var result map[string]any
	if decodeErr := json.Unmarshal(output, &result); decodeErr != nil {
		t.Fatalf("replay output is not canonical JSON: %v\n%s", decodeErr, output)
	}
}

func TestFormalCommandsEmitIdenticalValidBlockedVerdicts(t *testing.T) {
	repo := repoRoot(t)
	binary := assurectlBinary(t)
	var outputs [][]byte
	for _, mode := range []string{"formal-preflight", "formal-replay"} {
		command := exec.Command(binary, mode, "--root", repo)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", mode, err, output)
		}
		var verdict struct {
			Valid       bool     `json:"valid"`
			State       string   `json:"state"`
			ClaimScopes []string `json:"claim_scopes"`
			Findings    []any    `json:"findings"`
		}
		if err := json.Unmarshal(output, &verdict); err != nil {
			t.Fatalf("%s output: %v\n%s", mode, err, output)
		}
		if !verdict.Valid || verdict.State != "BLOCKED" || len(verdict.Findings) != 0 {
			t.Fatalf("%s verdict = %#v", mode, verdict)
		}
		outputs = append(outputs, output)
	}
	if !bytes.Equal(outputs[0], outputs[1]) {
		t.Fatalf("formal modes differ:\n%s\n%s", outputs[0], outputs[1])
	}
}

func TestFormalCommandsFailTypedWhenRequiredArtifactMissing(t *testing.T) {
	root := formalFixtureRoot(t)
	if err := os.Remove(filepath.Join(root, "assurance/formal/connection-model.tla")); err != nil {
		t.Fatal(err)
	}
	binary := assurectlBinary(t)
	for _, mode := range []string{"formal-preflight", "formal-replay"} {
		command := exec.Command(binary, mode, "--root", root)
		output, err := command.CombinedOutput()
		if err == nil {
			t.Fatalf("%s unexpectedly succeeded: %s", mode, output)
		}
		var verdict struct {
			Valid    bool `json:"valid"`
			Findings []struct {
				Reason string `json:"reason"`
			} `json:"findings"`
		}
		if decodeErr := json.Unmarshal(output, &verdict); decodeErr != nil {
			t.Fatalf("%s output: %v\n%s", mode, decodeErr, output)
		}
		found := false
		for _, finding := range verdict.Findings {
			found = found || finding.Reason == "MISSING_REQUIRED_ARTIFACT"
		}
		if verdict.Valid || !found {
			t.Fatalf("%s verdict = %#v", mode, verdict)
		}
	}
}

func TestFormalCommandsRejectBackendAndReceiptFlags(t *testing.T) {
	for _, flagName := range []string{"--backend", "--receipt", "--argv"} {
		var stdout, stderr bytes.Buffer
		exit := run([]string{"formal-preflight", "--root", ".", flagName, "candidate"}, &stdout, &stderr, time.Time{})
		if exit != 2 {
			t.Fatalf("%s exit = %d, want usage exit 2", flagName, exit)
		}
	}
}

func assurectlBinary(t *testing.T) string {
	t.Helper()
	repo := repoRoot(t)
	binary := filepath.Join(t.TempDir(), "assurectl")
	command := exec.Command("go", "build", "-o", binary, "./cmd/assurectl")
	command.Dir = repo
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build assurectl: %v\n%s", err, output)
	}
	return binary
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func formalFixtureRoot(t *testing.T) string {
	t.Helper()
	source := repoRoot(t)
	destination := t.TempDir()
	files := []string{
		"assurance/formal/proof-targets.json",
		"assurance/formal/backend-qualification.json",
		"assurance/formal/connection-model.tla",
		"assurance/concurrency/plan.json",
		"schemas/formal-proof-targets-1.0.0.schema.json",
		"schemas/formal-backend-qualification-1.0.0.schema.json",
		"schemas/concurrency-plan-1.0.0.schema.json",
		"assurance/evidence-model.json",
		"corpora/public/manifest.json",
		"corpora/public/scenarios.jsonl",
		"evidence/corpus-calibration.json",
		"evidence/intake/compatibility-surface.json",
		"evidence/intake/cutover-contract.json",
		"evidence/intake/port-seam-dossier.json",
		"evidence/sbx-validation.json",
		"evidence/security-validation.json",
		"security/sandbox-policy.json",
		"security/sbx-template.json",
	}
	for _, relative := range files {
		data, err := os.ReadFile(filepath.Join(source, relative))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(destination, relative)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return destination
}
