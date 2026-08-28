package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

func TestFormalCommandsExerciseFrozenHostileCatalog(t *testing.T) {
	type fixtureCase struct {
		FixtureID           string   `json:"fixture_id"`
		ExpectedCode        string   `json:"expected_code"`
		ExpectedDisposition string   `json:"expected_disposition"`
		ExpectedReason      string   `json:"expected_reason"`
		ExpectedExit        int      `json:"expected_exit"`
		ExpectedState       string   `json:"expected_state"`
		ExpectedClaimScopes []string `json:"expected_claim_scopes"`
	}
	var catalog struct {
		Cases []fixtureCase `json:"cases"`
	}
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "assurance/formal/fixtures/cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatal(err)
	}
	binary := assurectlBinary(t)
	for _, fixture := range catalog.Cases {
		if fixture.ExpectedExit == 0 {
			continue
		}
		t.Run(fixture.FixtureID, func(t *testing.T) {
			root := formalFixtureRoot(t)
			mutateCLIFormalFixture(t, root, fixture.FixtureID)
			for _, mode := range []string{"formal-preflight", "formal-replay"} {
				command := exec.Command(binary, mode, "--root", root)
				output, err := command.CombinedOutput()
				if err == nil {
					t.Fatalf("%s unexpectedly succeeded: %s", mode, output)
				}
				exitError, ok := err.(*exec.ExitError)
				if !ok || exitError.ExitCode() != fixture.ExpectedExit {
					t.Fatalf("%s exit = %v, want %d", mode, err, fixture.ExpectedExit)
				}
				var verdict struct {
					State       string                                       `json:"state"`
					ClaimScopes []string                                     `json:"claim_scopes"`
					Findings    []struct{ Code, Disposition, Reason string } `json:"findings"`
				}
				if err := json.Unmarshal(output, &verdict); err != nil {
					t.Fatalf("%s: %v\n%s", mode, err, output)
				}
				found := false
				for _, finding := range verdict.Findings {
					found = found || finding.Code == fixture.ExpectedCode && finding.Disposition == fixture.ExpectedDisposition && finding.Reason == fixture.ExpectedReason
				}
				if !found || verdict.State != fixture.ExpectedState || !reflect.DeepEqual(verdict.ClaimScopes, fixture.ExpectedClaimScopes) {
					t.Fatalf("%s verdict = %#v, contract = %#v", mode, verdict, fixture)
				}
			}
		})
	}
}

func TestCandidateCommandsRejectAliasesRepeatsAndRelativeRoots(t *testing.T) {
	for _, arguments := range [][]string{
		{"candidate-verify", "--root=."},
		{"candidate-verify", "--root", ".", "--root", "."},
		{"candidate-replay", "--root", "."},
		{"candidate-replay", "--root", "/tmp", "trailing"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr, time.Time{}); code == 0 {
			t.Fatalf("invalid candidate arguments passed: %v", arguments)
		}
	}
}

func mutateCLIFormalFixture(t *testing.T, root, id string) {
	t.Helper()
	proofPath := filepath.Join(root, "assurance/formal/proof-targets.json")
	qualificationPath := filepath.Join(root, "assurance/formal/backend-qualification.json")
	switch id {
	case "disconnected-proof-copy":
		proof := readJSONObject(t, proofPath)
		proof["targets"].([]any)[0].(map[string]any)["rust_symbol"] = "proof_only::frame_header_copy"
		writeJSONObject(t, proofPath, proof)
		rebindCLIArtifact(t, qualificationPath, "proof_targets", proofPath)
	case "disconnected-symbol":
		proof := readJSONObject(t, proofPath)
		proof["targets"].([]any)[0].(map[string]any)["required_call_paths"].([]any)[0].(map[string]any)["state"] = "DISCONNECTED"
		writeJSONObject(t, proofPath, proof)
		rebindCLIArtifact(t, qualificationPath, "proof_targets", proofPath)
	case "inflated-finite-proof":
		qualification := readJSONObject(t, qualificationPath)
		cliBackend(t, qualification, "backend.finite-mask-prototype")["claim_scope"] = "PROVED_MODEL"
		writeJSONObject(t, qualificationPath, qualification)
	case "inflated-loom-proof":
		qualification := readJSONObject(t, qualificationPath)
		cliBackend(t, qualification, "backend.loom-concurrency")["claim_scope"] = "PROVED_MODEL"
		writeJSONObject(t, qualificationPath, qualification)
	case "inflated-model-production":
		proof := readJSONObject(t, proofPath)
		proof["targets"].([]any)[0].(map[string]any)["obligations"].([]any)[0].(map[string]any)["production_refinement_required"] = false
		writeJSONObject(t, proofPath, proof)
		rebindCLIArtifact(t, qualificationPath, "proof_targets", proofPath)
	case "inflated-schedule-count":
		qualification := readJSONObject(t, qualificationPath)
		bounds := cliBackend(t, qualification, "backend.loom-concurrency")["bounds"].(map[string]any)
		bounds["schedule_count"] = bounds["max_schedules"].(float64) + 1
		writeJSONObject(t, qualificationPath, qualification)
	case "known-bad-survives":
		qualification := readJSONObject(t, qualificationPath)
		cliBackend(t, qualification, "backend.finite-mask-prototype")["known_bad_canaries"].([]any)[0].(map[string]any)["observed_outcome"] = "PASS"
		writeJSONObject(t, qualificationPath, qualification)
	case "missing-digest":
		proof := readJSONObject(t, proofPath)
		delete(proof["source_basis"].([]any)[0].(map[string]any), "sha256")
		writeJSONObject(t, proofPath, proof)
		rebindCLIArtifact(t, qualificationPath, "proof_targets", proofPath)
	case "missing-required-artifact":
		qualification := readJSONObject(t, qualificationPath)
		backend := cliBackend(t, qualification, "backend.finite-mask-prototype")
		items := backend["required_artifacts"].([]any)
		filtered := []any{}
		for _, item := range items {
			if item != "TOOL_IDENTITY" {
				filtered = append(filtered, item)
			}
		}
		backend["required_artifacts"] = filtered
		writeJSONObject(t, qualificationPath, qualification)
	case "missing-target":
		qualification := readJSONObject(t, qualificationPath)
		backend := cliBackend(t, qualification, "backend.finite-mask-prototype")
		backend["obligation_ids"].([]any)[0] = "obligation.unknown"
		backend["outcomes"].([]any)[0].(map[string]any)["obligation_id"] = "obligation.unknown"
		writeJSONObject(t, qualificationPath, qualification)
	case "replay-digest-mismatch":
		qualification := readJSONObject(t, qualificationPath)
		cliBackend(t, qualification, "backend.finite-mask-prototype")["replay"].(map[string]any)["semantic_output_digest"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		writeJSONObject(t, qualificationPath, qualification)
	case "unavailable-as-skip":
		qualification := readJSONObject(t, qualificationPath)
		cliBackend(t, qualification, "backend.finite-mask-prototype")["claim_scope"] = "SKIP"
		writeJSONObject(t, qualificationPath, qualification)
	case "unavailable-as-success":
		qualification := readJSONObject(t, qualificationPath)
		backend := cliBackend(t, qualification, "backend.finite-mask-prototype")
		backend["claim_scope"] = "BOUNDED_TEST_EVIDENCE"
		outcome := backend["outcomes"].([]any)[0].(map[string]any)
		outcome["raw_outcome"], outcome["claim_scope"] = "BOUNDED_CHECK_PASSED", "BOUNDED_TEST_EVIDENCE"
		writeJSONObject(t, qualificationPath, qualification)
	case "unsupported-claimed-covered":
		qualification := readJSONObject(t, qualificationPath)
		backend := cliBackend(t, qualification, "backend.finite-mask-prototype")
		backend["unsupported_constructs"] = []any{"construct.dynamic-dispatch"}
		backend["outcomes"].([]any)[0].(map[string]any)["raw_outcome"] = "BOUNDED_CHECK_PASSED"
		writeJSONObject(t, qualificationPath, qualification)
	case "zero-obligations":
		qualification := readJSONObject(t, qualificationPath)
		backend := cliBackend(t, qualification, "backend.finite-mask-prototype")
		backend["obligation_ids"], backend["outcomes"], backend["obligation_count"] = []any{}, []any{}, float64(0)
		writeJSONObject(t, qualificationPath, qualification)
	default:
		t.Fatalf("unhandled hostile fixture %s", id)
	}
}

func readJSONObject(t *testing.T, path string) map[string]any {
	t.Helper()
	var value map[string]any
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func writeJSONObject(t *testing.T, path string, value map[string]any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func cliBackend(t *testing.T, qualification map[string]any, id string) map[string]any {
	t.Helper()
	for _, item := range qualification["backends"].([]any) {
		backend := item.(map[string]any)
		if backend["backend_id"] == id {
			return backend
		}
	}
	t.Fatalf("backend %s not found", id)
	return nil
}

func rebindCLIArtifact(t *testing.T, qualificationPath, field, artifactPath string) {
	t.Helper()
	qualification := readJSONObject(t, qualificationPath)
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	qualification[field].(map[string]any)["sha256"] = fmt.Sprintf("sha256:%x", digest)
	writeJSONObject(t, qualificationPath, qualification)
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
