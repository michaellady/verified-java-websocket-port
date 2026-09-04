package corpora

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	absolute, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

// The committed public and handshake corpora must re-derive byte-for-byte
// from the committed public seed, and every repo-side manifest must
// reconcile, without any access to the protected store.
func TestCommittedPublicCorporaReDerive(t *testing.T) {
	root := repoRoot(t)
	manifest, err := readManifest(filepath.Join(root, "corpora/public/manifest.json"))
	if err != nil {
		t.Fatalf("committed public manifest: %v", err)
	}
	generator := manifest["generator"].(map[string]any)
	publicSeed := generator["public_seed"].(string)

	public, handshake, plans, err := GeneratePublic(publicSeed)
	if err != nil {
		t.Fatalf("GeneratePublic: %v", err)
	}
	publicBytes, err := scenarioLines(public)
	if err != nil {
		t.Fatal(err)
	}
	committedPublic, err := os.ReadFile(filepath.Join(root, "corpora/public/scenarios.jsonl"))
	if err != nil {
		t.Fatalf("committed public scenarios: %v", err)
	}
	if string(publicBytes) != string(committedPublic) {
		t.Fatal("committed public corpus does not re-derive from the committed seed")
	}
	handshakeBytes, err := handshakeLines(handshake)
	if err != nil {
		t.Fatal(err)
	}
	committedHandshake, err := os.ReadFile(filepath.Join(root, "corpora/handshake/cases.jsonl"))
	if err != nil {
		t.Fatalf("committed handshake cases: %v", err)
	}
	if string(handshakeBytes) != string(committedHandshake) {
		t.Fatal("committed handshake corpus does not re-derive from the committed seed")
	}

	counts := manifest["counts"].(map[string]any)
	if int(counts["selected"].(float64)) != plans["public"].Selected ||
		int(counts["expected"].(float64)) != plans["public"].Expected {
		t.Fatalf("committed public counts do not reconcile: %v vs %+v",
			counts, plans["public"])
	}
	artifact := manifest["artifacts"].([]any)[0].(map[string]any)
	if artifact["sha256"] != DigestSHA256(committedPublic) {
		t.Fatal("committed public artifact digest does not reconcile")
	}
}

// Every committed repo artifact is schema-valid, held-out tiers commit only
// manifests, and the calibration evidence keeps its live gates fail-closed:
// a gate is either pending with no result, or records PASS/FAIL with a
// transcript-digest-bearing result per the documented live-evidence contract.
func TestCommittedArtifactsAreSchemaValidAndSealed(t *testing.T) {
	root := repoRoot(t)
	findings, err := ValidateCorpusSchemas(filepath.Join(root, "schemas"), root, "")
	if err != nil {
		t.Fatalf("ValidateCorpusSchemas: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("committed artifacts must be schema-valid: %v", findings)
	}
	for _, tier := range []string{"hidden", "sealed"} {
		entries, err := os.ReadDir(filepath.Join(root, "corpora", tier))
		if err != nil {
			t.Fatalf("read %s: %v", tier, err)
		}
		for _, entry := range entries {
			if entry.Name() != "manifest.json" {
				t.Fatalf("held-out bytes leaked into the repo: corpora/%s/%s",
					tier, entry.Name())
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, "evidence/corpus-calibration.json"))
	if err != nil {
		t.Fatalf("committed calibration evidence: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for gate, entry := range document["live_gates"].(map[string]any) {
		gateMap := entry.(map[string]any)
		switch gateMap["status"] {
		case "BLOCKED_PENDING_LIVE_EXECUTION":
			if _, recorded := gateMap["result"]; recorded {
				t.Fatalf("pending live gate %s must not carry a result", gate)
			}
		case "PASS", "FAIL":
			result, isMap := gateMap["result"].(map[string]any)
			if !isMap {
				t.Fatalf("recorded live gate %s lacks a result", gate)
			}
			digests, isSlice := result["transcript_sha256s"].([]any)
			if !isSlice || len(digests) == 0 {
				t.Fatalf("recorded live gate %s lacks transcript digests", gate)
			}
			executed, executedOK := gateCounter(result, "executed")
			passed, passedOK := gateCounter(result, "passed")
			failed, failedOK := gateCounter(result, "failed")
			if !executedOK || !passedOK || !failedOK {
				t.Fatalf("recorded live gate %s carries unreadable counters", gate)
			}
			if passed+failed != executed || executed < 1 {
				t.Fatalf("recorded live gate %s counters inconsistent "+
					"(executed=%d passed=%d failed=%d)", gate, executed, passed, failed)
			}
			// Per-gate PASS semantics (round-5): identities alone admit
			// dishonest states like PASS with passed=0 failed=executed.
			if gateMap["status"] == "PASS" {
				switch gate {
				case "java_oracle_pass_rate":
					if failed != 0 || passed != executed {
						t.Fatalf("pass-rate gate PASS must have zero failures "+
							"(executed=%d passed=%d failed=%d)", executed, passed, failed)
					}
					if want, ok := behaviorSelectedTotal(document); !ok || executed != want {
						t.Fatalf("pass-rate gate PASS must cover every behavior "+
							"scenario (executed=%d selected=%d ok=%v)", executed, want, ok)
					}
				case "empty_rust_target_fails", "planted_java_rust_mutants_killed":
					if failed < 1 {
						t.Fatalf("kill gate %s PASS with zero failing executions "+
							"is vacuous", gate)
					}
				}
			}
		default:
			t.Fatalf("committed live gate %s has unsupported status %v",
				gate, gateMap["status"])
		}
	}
	if document["assurance"] != "OWNER_ATTESTED_NOT_INDEPENDENT" ||
		document["independent_review_claimed"] != false {
		t.Fatal("committed calibration assurance labels wrong")
	}
}
