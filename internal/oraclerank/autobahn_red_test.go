package oraclerank

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// The Autobahn evidence root is pinned in both directions by a digest manifest
// that divergencesweep.VerifyEvidenceIntegrity checks before this package reads
// a single report. That manifest catches any lone edit, which means the
// cross-checks THIS package adds on top of it -- the `expected` map being
// byte-equal between the Java and Rust legs, the INFORMATIONAL grading agreeing
// between them, and the recomputed classes matching the independently produced
// comparison document -- would never fire against a lone edit and would look
// like evidence while being unreachable.
//
// The tests here therefore plant a CONSISTENT edit: the report is changed and
// the digest manifest is repaired to match, exactly as a regeneration would
// leave it. The manifest check then passes and this package's own cross-checks
// are the only thing left to catch the change. If one of them stays green here,
// it is decoration and must be reported as such rather than shipped.

// repairManifest rewrites the digest-manifest entry for one path so a mutated
// file passes the integrity check, and returns the manifest bytes.
func repairManifest(t *testing.T, root string, mutated map[string][]byte) []byte {
	t.Helper()
	var manifest struct {
		SchemaVersion string `json:"schema_version"`
		EntityType    string `json:"entity_type"`
		Root          string `json:"root"`
		FileCount     int    `json:"file_count"`
		TotalBytes    int64  `json:"total_bytes"`
		Files         []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Bytes  int64  `json:"bytes"`
		} `json:"files"`
	}
	if err := json.Unmarshal(mustRead(t, root, AutobahnDigestManifestPath), &manifest); err != nil {
		t.Fatal(err)
	}
	repaired := 0
	for i, entry := range manifest.Files {
		content, ok := mutated[entry.Path]
		if !ok {
			continue
		}
		sum := sha256.Sum256(content)
		manifest.TotalBytes += int64(len(content)) - entry.Bytes
		manifest.Files[i].SHA256 = "sha256:" + hex.EncodeToString(sum[:])
		manifest.Files[i].Bytes = int64(len(content))
		repaired++
	}
	if repaired != len(mutated) {
		t.Fatalf("repaired %d manifest entries, want %d; a mutated path is not pinned", repaired, len(mutated))
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

// TestRedDivergedExpectedMapIsCaughtByThisPackage plants a consistent edit that
// makes the suite's own `expected` map differ between the Java and Rust legs of
// the same case. Rank two's verdict is supposed to be a property of the CASE,
// confirmed by two separately written report sets; if this passes, that
// confirmation is not being made.
func TestRedDivergedExpectedMapIsCaughtByThisPackage(t *testing.T) {
	root := repoRoot(t)
	rel := AutobahnEvidenceRoot + "/java/fuzzingclient-run1/cases/verified_java_websocket_port_1_6_0_case_6_4_1.json"

	var report map[string]any
	if err := json.Unmarshal(mustRead(t, root, rel), &report); err != nil {
		t.Fatal(err)
	}
	expected, _ := report["expected"].(map[string]any)
	if expected == nil {
		t.Fatal("case 6.4.1 java leg carries no `expected` map")
	}
	if _, ok := expected["OK"]; !ok {
		t.Fatal("case 6.4.1 declares no OK arm; this RED test needs one to remove")
	}
	// Remove the OK arm on ONE leg only. Rank two would then endorse
	// NON-STRICT here and the override would silently disappear.
	delete(expected, "OK")
	edited, err := json.MarshalIndent(report, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	manifest := repairManifest(t, root, map[string][]byte{rel: edited})
	mirror := mirrorRoot(t, root, map[string][]byte{
		rel:                        edited,
		AutobahnDigestManifestPath: manifest,
	})

	_, err = Census(mirror)
	if err == nil {
		t.Fatal("RED FAILED: the suite's `expected` map was made to differ between the two legs, the digest manifest was repaired to match, and this package accepted it. The cross-leg equality check is decoration, not evidence.")
	}
	if !strings.Contains(err.Error(), "property of the case") {
		t.Fatalf("the census failed with %q; the cross-leg `expected` check is not what caught it", err)
	}
}

// TestRedFlippedBehaviorWithARepairedManifestIsCaughtByTheComparisonDocument
// plants a consistent edit to the graded behaviour on one leg, repairing both
// the per-case report and the leg index that repeats it, plus the manifest. The
// only remaining catcher is this package's cross-check against the
// independently produced per-case comparison document.
func TestRedFlippedBehaviorWithARepairedManifestIsCaughtByTheComparisonDocument(t *testing.T) {
	root := repoRoot(t)
	caseRel := AutobahnEvidenceRoot + "/java/fuzzingclient-run1/cases/verified_java_websocket_port_1_6_0_case_6_4_1.json"
	indexRel := AutobahnEvidenceRoot + "/java/fuzzingclient-run1/index.json"

	var report map[string]any
	if err := json.Unmarshal(mustRead(t, root, caseRel), &report); err != nil {
		t.Fatal(err)
	}
	if report["behavior"] != "NON-STRICT" {
		t.Fatalf("case 6.4.1 java leg records behavior %v, this RED test expects NON-STRICT", report["behavior"])
	}
	report["behavior"] = "OK"
	editedCase, err := json.MarshalIndent(report, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	var index map[string]map[string]map[string]any
	if err := json.Unmarshal(mustRead(t, root, indexRel), &index); err != nil {
		t.Fatal(err)
	}
	patched := false
	for _, cases := range index {
		if entry, ok := cases["6.4.1"]; ok {
			entry["behavior"] = "OK"
			patched = true
		}
	}
	if !patched {
		t.Fatal("the java fuzzingclient index does not name case 6.4.1")
	}
	editedIndex, err := json.MarshalIndent(index, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	mutated := map[string][]byte{caseRel: editedCase, indexRel: editedIndex}
	manifest := repairManifest(t, root, mutated)
	overrides := map[string][]byte{AutobahnDigestManifestPath: manifest}
	for path, content := range mutated {
		overrides[path] = content
	}

	mirror := mirrorRoot(t, root, overrides)
	_, err = Census(mirror)
	if err == nil {
		t.Fatal("RED FAILED: a graded behaviour was flipped consistently across the report, the index and the manifest, and this package accepted it. The cross-check against the comparison document is decoration, not evidence.")
	}
	if !strings.Contains(err.Error(), AutobahnComparisonPath) {
		t.Fatalf("the census failed with %q; the comparison-document cross-check is not what caught it", err)
	}
}
