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

// Advancing the generation epoch rotates the existing hash-chained ledger
// under the same custodian lock and leaves every epoch-bearing artifact in a
// single verifiable state. Backward generation is rejected without mutation.
func TestWriteAllRotatesLedgerAndRejectsBackwardEpoch(t *testing.T) {
	root, protectedRoot, _ := writeAllToTemp(t)
	if err := SpendCustodian(protectedRoot, func(ledger *Ledger) error {
		return ledger.RecordQuery("us005.hid.0001", "same-query")
	}); err != nil {
		t.Fatal(err)
	}

	input2 := testInput()
	input2.Epoch = 2
	generated2, err := GenerateAll(input2)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteAll(root, protectedRoot, input2, generated2); err != nil {
		t.Fatalf("epoch 2 WriteAll: %v", err)
	}
	ledgerRaw, err := os.ReadFile(ProtectedLedgerPath(protectedRoot))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := LoadLedger(ledgerRaw)
	if err != nil {
		t.Fatal(err)
	}
	entries := ledger.Entries()
	if ledger.Epoch() != 2 || entries[len(entries)-1].Op != "rotation" ||
		ledger.ProbingDetected() {
		t.Fatalf("ledger was not rotated cleanly: epoch=%d last=%+v",
			ledger.Epoch(), entries[len(entries)-1])
	}
	findings, err := VerifyAll(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("rotated state must verify: %v", findings)
	}

	input1 := testInput()
	generated1, err := GenerateAll(input1)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteAll(root, protectedRoot, input1, generated1); err == nil {
		t.Fatal("backward generation must be rejected")
	}
	findings, err = VerifyAll(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("rejected backward generation must preserve epoch 2: %v", findings)
	}
}

func TestVerifyAllRejectsEpochComponentDisagreement(t *testing.T) {
	tests := map[string]struct {
		mutate func(t *testing.T, root, protectedRoot string)
		code   string
	}{
		"ledger": {
			mutate: func(t *testing.T, _, protectedRoot string) {
				raw, err := os.ReadFile(ProtectedLedgerPath(protectedRoot))
				if err != nil {
					t.Fatal(err)
				}
				ledger, err := LoadLedger(raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := ledger.Rotate(2); err != nil {
					t.Fatal(err)
				}
				rotated, err := ledger.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(ProtectedLedgerPath(protectedRoot), rotated, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			code: "LEDGER_EPOCH_MISMATCH",
		},
		"policy": {
			mutate: func(t *testing.T, _, protectedRoot string) {
				path := filepath.Join(protectedRoot, protectedPolicyFile)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				mutated := strings.Replace(string(raw), `"query_budget":200`, `"query_budget":199`, 1)
				if mutated == string(raw) {
					t.Fatal("policy mutation did not apply")
				}
				if err := os.WriteFile(path, []byte(mutated), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			code: "CUSTODIAN_POLICY_MISMATCH",
		},
		"canary": {
			mutate: func(t *testing.T, _, protectedRoot string) {
				path := filepath.Join(protectedRoot, protectedCanaryFile)
				inventory, err := readManifest(path)
				if err != nil {
					t.Fatal(err)
				}
				inventory["epoch"] = 2
				if err := writeJSONFile(path, inventory); err != nil {
					t.Fatal(err)
				}
			},
			code: "CANARY_INVENTORY_MISMATCH",
		},
		"manifest": {
			mutate: func(t *testing.T, root, _ string) {
				path := filepath.Join(root, repoCorporaDir, "sealed/manifest.json")
				manifest, err := readManifest(path)
				if err != nil {
					t.Fatal(err)
				}
				manifest["generator"].(map[string]any)["epoch"] = 2
				if err := writeJSONFile(path, manifest); err != nil {
					t.Fatal(err)
				}
			},
			code: "MANIFEST_MISMATCH",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root, protectedRoot, _ := writeAllToTemp(t)
			tc.mutate(t, root, protectedRoot)
			findings, err := VerifyAll(root, protectedRoot)
			if err != nil {
				t.Fatal(err)
			}
			if findingCodes(findings)[tc.code] == 0 {
				t.Fatalf("missing %s: %v", tc.code, findings)
			}
		})
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

// A faithfully recorded live execution (real protected artifacts, matched
// digests, consistent counters) passes VerifyAll, while drift in the
// deterministic core still blocks. Dangling digests are covered by the
// live-evidence tamper tests.
func TestVerifyAllToleratesRecordedExecutionState(t *testing.T) {
	root, protectedRoot, generated := writeAllToTemp(t)
	manifestPath, _ := recordLiveExecution(t, root, protectedRoot, generated)
	findings, err := VerifyAll(root, protectedRoot)
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("recorded execution state must verify, findings: %v", findings)
	}

	// Core drift under recorded execution state still blocks.
	manifest, err := readManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	counts := manifest["counts"].(map[string]any)
	counts["selected"] = int(counts["selected"].(float64)) + 1
	if err := writeJSONFile(manifestPath, manifest); err != nil {
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
