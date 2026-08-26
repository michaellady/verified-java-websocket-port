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
// manifests, and the calibration evidence keeps its fail-closed live gates.
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
		if entry.(map[string]any)["status"] != "BLOCKED_PENDING_LIVE_EXECUTION" {
			t.Fatalf("committed live gate %s is not fail-closed", gate)
		}
	}
	if document["assurance"] != "OWNER_ATTESTED_NOT_INDEPENDENT" ||
		document["independent_review_claimed"] != false {
		t.Fatal("committed calibration assurance labels wrong")
	}
}
