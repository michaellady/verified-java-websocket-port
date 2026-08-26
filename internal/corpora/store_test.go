package corpora

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAllToTemp(t *testing.T) (string, string, *GeneratedCorpora) {
	t.Helper()
	root := t.TempDir()
	protectedRoot := t.TempDir()
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	if err := WriteAll(root, protectedRoot, testInput(), generated); err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	return root, protectedRoot, generated
}

// The four manifests land in the repo; hidden and sealed scenario bytes land
// only under the protected custodian store.
func TestWriteAllStorageSeparation(t *testing.T) {
	root, protectedRoot, _ := writeAllToTemp(t)
	for _, path := range []string{
		"corpora/public/manifest.json",
		"corpora/public/scenarios.jsonl",
		"corpora/handshake/manifest.json",
		"corpora/handshake/cases.jsonl",
		"corpora/hidden/manifest.json",
		"corpora/sealed/manifest.json",
	} {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatalf("missing repo artifact %s: %v", path, err)
		}
	}
	for _, path := range []string{
		"us005-corpora/hidden/scenarios.jsonl",
		"us005-corpora/sealed/scenarios.jsonl",
		"us005-corpora/canary-inventory.json",
		"us005-corpora/custodian/policy.json",
		"us005-corpora/custodian/ledger.json",
	} {
		if _, err := os.Stat(filepath.Join(protectedRoot, path)); err != nil {
			t.Fatalf("missing protected artifact %s: %v", path, err)
		}
	}
	// No held-out scenario bytes anywhere under the repo root.
	err := filepath.Walk(filepath.Join(root, "corpora"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if strings.Contains(path, "hidden") || strings.Contains(path, "sealed") {
			if !strings.HasSuffix(path, "manifest.json") {
				t.Fatalf("held-out tier leaked into repo: %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// Manifests carry the full derived count set and correct classifications.
func TestManifestCountsAndClassifications(t *testing.T) {
	root, _, generated := writeAllToTemp(t)
	for tier, wantSelected := range map[string]int{
		"public":    len(generated.Public),
		"handshake": len(generated.Handshake),
		"hidden":    len(generated.Hidden),
		"sealed":    len(generated.Sealed),
	} {
		raw, err := os.ReadFile(filepath.Join(root, "corpora", tier, "manifest.json"))
		if err != nil {
			t.Fatalf("read %s manifest: %v", tier, err)
		}
		var manifest map[string]any
		if err := json.Unmarshal(raw, &manifest); err != nil {
			t.Fatalf("parse %s manifest: %v", tier, err)
		}
		counts := manifest["counts"].(map[string]any)
		for _, field := range []string{"expected", "selected", "executed", "passed",
			"failed", "skipped", "filtered", "timed_out"} {
			if _, present := counts[field]; !present {
				t.Fatalf("%s manifest counts lack %s", tier, field)
			}
		}
		if int(counts["selected"].(float64)) != wantSelected {
			t.Fatalf("%s manifest selected=%v want %d", tier, counts["selected"], wantSelected)
		}
		for _, field := range []string{"executed", "passed", "failed", "skipped", "timed_out"} {
			if int(counts[field].(float64)) != 0 {
				t.Fatalf("%s manifest %s must be 0 before live calibration", tier, field)
			}
		}
		if manifest["execution_status"] != "NOT_EXECUTED_PENDING_LIVE_CALIBRATION" {
			t.Fatalf("%s manifest execution_status = %v", tier, manifest["execution_status"])
		}
		if manifest["assurance"] != "OWNER_ATTESTED_NOT_INDEPENDENT" ||
			manifest["independent_review_claimed"] != false {
			t.Fatalf("%s manifest assurance labels wrong", tier)
		}
		artifacts := manifest["artifacts"].([]any)
		if len(artifacts) == 0 {
			t.Fatalf("%s manifest has no artifacts", tier)
		}
		first := artifacts[0].(map[string]any)
		heldOut := tier == "hidden" || tier == "sealed"
		if heldOut {
			if first["stored_in_repo"] != false ||
				first["classification"] != "PROTECTED_HELD_OUT" {
				t.Fatalf("%s artifact = %v", tier, first)
			}
			if manifest["commitments"] == nil || manifest["custodian"] == nil ||
				manifest["sealing"] == nil {
				t.Fatalf("%s manifest lacks sealing mechanics", tier)
			}
		} else {
			if first["stored_in_repo"] != true || first["classification"] != "PUBLIC" {
				t.Fatalf("%s artifact = %v", tier, first)
			}
		}
	}
}

// VerifyAll must pass on a fresh write and fail closed on any tampering,
// in the repo or in the protected store.
func TestVerifyAllPassesFreshAndFailsClosedOnTamper(t *testing.T) {
	root, protectedRoot, _ := writeAllToTemp(t)
	findings, err := VerifyAll(root, protectedRoot)
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("fresh corpora must verify, findings: %v", findings)
	}

	publicPath := filepath.Join(root, "corpora/public/scenarios.jsonl")
	raw, _ := os.ReadFile(publicPath)
	tampered := strings.Replace(string(raw), `"outcome":"ok"`, `"outcome":"okay"`, 1)
	if tampered == string(raw) {
		t.Fatal("tamper probe found nothing to change")
	}
	if err := os.WriteFile(publicPath, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err = VerifyAll(root, protectedRoot)
	if err != nil {
		t.Fatalf("VerifyAll after tamper: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("public tamper must produce findings")
	}
	if err := os.WriteFile(publicPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	hiddenPath := filepath.Join(protectedRoot, "us005-corpora/hidden/scenarios.jsonl")
	rawHidden, _ := os.ReadFile(hiddenPath)
	lines := strings.Split(strings.TrimRight(string(rawHidden), "\n"), "\n")
	lines[0], lines[1] = lines[1], lines[0]
	if err := os.WriteFile(hiddenPath,
		[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err = VerifyAll(root, protectedRoot)
	if err != nil {
		t.Fatalf("VerifyAll after hidden tamper: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("hidden reorder must produce findings")
	}
	if err := os.WriteFile(hiddenPath, rawHidden, 0o644); err != nil {
		t.Fatal(err)
	}

	// A hand-edited manifest count blocks.
	manifestPath := filepath.Join(root, "corpora/public/manifest.json")
	rawManifest, _ := os.ReadFile(manifestPath)
	edited := strings.Replace(string(rawManifest), `"selected": 74`, `"selected": 75`, 1)
	if edited == string(rawManifest) {
		var manifest map[string]any
		_ = json.Unmarshal(rawManifest, &manifest)
		t.Fatalf("count tamper probe failed; counts=%v", manifest["counts"])
	}
	if err := os.WriteFile(manifestPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err = VerifyAll(root, protectedRoot)
	if err != nil {
		t.Fatalf("VerifyAll after manifest tamper: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("manifest count tamper must produce findings")
	}
}

// The commitment scheme binds each held-out line with a secret-derived salt,
// so the repo commitment proves content without revealing or allowing
// brute-force of scenario bytes.
func TestHeldOutCommitmentRootRecomputes(t *testing.T) {
	root, _, generated := writeAllToTemp(t)
	for tier, scenarios := range map[string][]Scenario{
		"hidden": generated.Hidden, "sealed": generated.Sealed} {
		raw, err := os.ReadFile(filepath.Join(root, "corpora", tier, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		var manifest map[string]any
		if err := json.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		commitments := manifest["commitments"].(map[string]any)
		recomputed, err := CommitmentRoot(testInput().Secret, tier, scenarios)
		if err != nil {
			t.Fatalf("CommitmentRoot: %v", err)
		}
		if commitments["scenario_commitment_root"] != recomputed {
			t.Fatalf("%s commitment root mismatch", tier)
		}
		if int(commitments["committed_line_count"].(float64)) != len(scenarios) {
			t.Fatalf("%s committed line count mismatch", tier)
		}
	}
}

// The canary leak scan covers every repository file, not only the corpus
// artifacts: a token planted anywhere under the root is a finding.
func TestVerifyAllCanaryScanCoversWholeRepo(t *testing.T) {
	root, protectedRoot, generated := writeAllToTemp(t)
	var anyToken string
	for _, token := range generated.CanaryTokens {
		anyToken = token
		break
	}
	planted := filepath.Join(root, "docs", "notes.md")
	if err := os.MkdirAll(filepath.Dir(planted), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planted,
		[]byte("innocuous notes containing "+anyToken+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := VerifyAll(root, protectedRoot)
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	var leak bool
	for _, finding := range findings {
		if finding.Code == "CANARY_LEAK" && strings.Contains(finding.Path, "notes.md") {
			leak = true
		}
	}
	if !leak {
		t.Fatalf("planted canary outside corpora must be found, findings: %v", findings)
	}
}

// Recording a live execution in a manifest (execution_status=LIVE_EXECUTED,
// execution_evidence, executed counts) must not trip the deterministic
// reconciliation, while any drift in the deterministic core still blocks.
func TestVerifyAllToleratesRecordedExecutionState(t *testing.T) {
	root, protectedRoot, _ := writeAllToTemp(t)
	path := filepath.Join(root, "corpora/public/manifest.json")
	manifest, err := readManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	manifest["execution_status"] = "LIVE_EXECUTED"
	manifest["execution_evidence"] = map[string]any{
		"transcript_sha256": DigestSHA256([]byte("transcript")),
		"report_sha256":     DigestSHA256([]byte("report")),
		"evaluator":         "corporactl evaluate",
	}
	counts := manifest["counts"].(map[string]any)
	selected := int(counts["selected"].(float64))
	counts["executed"] = selected
	counts["passed"] = selected
	if err := writeJSONFile(path, manifest); err != nil {
		t.Fatal(err)
	}
	findings, err := VerifyAll(root, protectedRoot)
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("recorded execution state must verify, findings: %v", findings)
	}

	// Core drift under recorded execution state still blocks.
	counts["selected"] = selected + 1
	if err := writeJSONFile(path, manifest); err != nil {
		t.Fatal(err)
	}
	findings, err = VerifyAll(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("deterministic-core drift must still block")
	}
}
