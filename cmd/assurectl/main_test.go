package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
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
