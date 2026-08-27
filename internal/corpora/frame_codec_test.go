package corpora

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCommittedFrameCodecProjectionReconciles(t *testing.T) {
	projection, err := LoadAndVerifyFrameCodecProjection(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.FrozenCases) != 17 {
		t.Fatalf("frozen source inventory = %d, want 17", len(projection.FrozenCases))
	}
	if len(projection.AdditiveVectors) != 10 {
		t.Fatalf("additive vector families = %d, want 10", len(projection.AdditiveVectors))
	}
	if projection.Properties.MaskGridExecutionsPerProfile != 204 ||
		projection.Fuzz.SeedCount != 20 || len(projection.RuntimeAssertions) != 5 {
		t.Fatalf("unexpected bounded execution inventory: %+v", projection.Properties)
	}
}

func TestFrameCodecProjectionRecordsStrictJavaDivergencesAndZeroLiveClaims(t *testing.T) {
	projection, err := LoadAndVerifyFrameCodecProjection(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if projection.Authority.JavaObservationMode != "SOURCE_DERIVED_NO_LIVE_EXECUTION" ||
		projection.Autobahn.ExecutedCases != 0 || projection.Autobahn.ResultCount != 0 ||
		projection.Autobahn.ResultClaimed {
		t.Fatal("projection overstated Java or Autobahn execution")
	}
	want := map[string]bool{
		"add.role.server-unmasked":  false,
		"add.role.client-masked":    false,
		"add.length.noncanonical16": false,
		"add.length.noncanonical64": false,
	}
	for _, vector := range projection.AdditiveVectors {
		if _, ok := want[vector.ID]; ok {
			if vector.Java.Observable != "accept" || !vector.Java.Divergent {
				t.Fatalf("%s did not preserve the source-derived Java leniency", vector.ID)
			}
			want[vector.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Fatalf("missing strictness vector %s", id)
		}
	}
}

func TestFrameCodecProjectionRejectsUnknownFieldsAndAssuranceInflation(t *testing.T) {
	root := copyFrameCodecFixture(t)
	path := filepath.Join(root, frameCodecProjectionPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["unexpected"] = true
	writeFrameCodecTestJSON(t, path, doc)
	if _, err := LoadAndVerifyFrameCodecProjection(root); err == nil {
		t.Fatal("unknown projection field was accepted")
	}

	root = copyFrameCodecFixture(t)
	path = filepath.Join(root, frameCodecProjectionPath)
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc = make(map[string]any)
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["assurance"].(map[string]any)["independent_review_claimed"] = true
	writeFrameCodecTestJSON(t, path, doc)
	if _, err := LoadAndVerifyFrameCodecProjection(root); err == nil {
		t.Fatal("inflated projection assurance was accepted")
	}
}

func TestFrameCodecProjectionRejectsSourceAndVectorDrift(t *testing.T) {
	root := copyFrameCodecFixture(t)
	projection, err := LoadAndVerifyFrameCodecProjection(root)
	if err != nil {
		t.Fatal(err)
	}
	projection.FrozenCases[0].Expected = "FrameFailure::ReservedBits"
	writeFrameCodecTestJSON(t, filepath.Join(root, frameCodecProjectionPath), projection)
	if _, err := LoadAndVerifyFrameCodecProjection(root); err == nil {
		t.Fatal("frozen result drift was accepted")
	}

	root = copyFrameCodecFixture(t)
	projection, err = LoadAndVerifyFrameCodecProjection(root)
	if err != nil {
		t.Fatal(err)
	}
	projection.AdditiveVectors[0].Values[0] = 2
	writeFrameCodecTestJSON(t, filepath.Join(root, frameCodecProjectionPath), projection)
	if _, err := LoadAndVerifyFrameCodecProjection(root); err == nil {
		t.Fatal("additive literal drift was accepted")
	}
}

func TestCommittedFrameCodecEvidenceBindsFinalRustAndFormalWork(t *testing.T) {
	if err := VerifyFrameCodecEvidence(repoRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func TestFrameCodecEvidenceIsClosedByFinalFormalSupport(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, frameCodecEvidencePath))
	if err != nil {
		t.Fatal(err)
	}
	var evidence frameCodecEvidence
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		t.Fatal(err)
	}
	const formalDigest = "sha256:fc6c03c9c16a4d0e80c14ab8c6d50e76cec3663ad42d5be6165f79e8dea43f0a"
	if evidence.Status != "CLOSED" || evidence.Formal.ResultSHA != formalDigest ||
		len(evidence.PendingFinalBindings) != 0 {
		t.Fatalf("evidence did not close over final formal bytes: status=%s formal=%s pending=%v",
			evidence.Status, evidence.Formal.ResultSHA, evidence.PendingFinalBindings)
	}

	var dag struct {
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
		Edges []struct {
			From string `json:"from"`
			To   string `json:"to"`
			Kind string `json:"kind"`
		} `json:"edges"`
	}
	dagRaw, err := os.ReadFile(filepath.Join(root, evidence.EvidenceDAG.Path))
	if err != nil || json.Unmarshal(dagRaw, &dag) != nil {
		t.Fatal("cannot decode final US-012 evidence DAG")
	}
	formalNode := "evidence-us012-formal-fc6c03c"
	receiptNode := "evidence-us012-receipt-closed-fc6c03c"
	seenNodes := map[string]bool{}
	for _, node := range dag.Nodes {
		seenNodes[node.ID] = true
		if node.ID == "evidence-us012-formal-pending" || node.ID == "evidence-us012-receipt-pending" {
			t.Errorf("pending DAG node survived closure: %s", node.ID)
		}
	}
	if !seenNodes[formalNode] || !seenNodes[receiptNode] {
		t.Fatalf("final digest-qualified DAG nodes missing: %v", seenNodes)
	}
	for _, edge := range dag.Edges {
		if edge.Kind == "pending" {
			t.Errorf("pending DAG edge survived closure: %+v", edge)
		}
	}
}

func TestFrameCodecEvidenceBindsFinalSharedIntakeArtifacts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), frameCodecEvidencePath))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	bindings := doc["compatibility"].(map[string]any)["shared_artifact_digests"].([]any)
	if len(bindings) != 4 {
		t.Fatalf("shared artifact bindings = %d, want 4", len(bindings))
	}
	for _, value := range bindings {
		binding := value.(map[string]any)
		if binding["sha256"] == "PENDING_FINAL_DIGEST" {
			t.Errorf("finalized shared artifact remained pending: %s", binding["path"])
		}
		if _, hasReason := binding["reason"]; hasReason {
			t.Errorf("finalized shared artifact retained pending reason: %s", binding["path"])
		}
	}
}

func TestFrameCodecEvidenceRejectsRustAutobahnAndNonclaimDrift(t *testing.T) {
	mutations := []func(map[string]any){
		func(doc map[string]any) {
			doc["rust_binding"].(map[string]any)["commit"] = "0000000000000000000000000000000000000000"
		},
		func(doc map[string]any) { doc["autobahn"].(map[string]any)["executed_cases"] = float64(1) },
		func(doc map[string]any) { doc["nonclaims"].([]any)[0] = "live Java was probably exercised" },
	}
	for index, mutate := range mutations {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), frameCodecEvidencePath))
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		mutate(doc)
		mutated, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		var evidence frameCodecEvidence
		decoder := json.NewDecoder(bytes.NewReader(mutated))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&evidence); err != nil {
			continue
		}
		if err := verifyFrameCodecEvidenceClaims(evidence); err == nil {
			t.Fatalf("evidence drift %d was accepted", index)
		}
	}
}

func copyFrameCodecFixture(t *testing.T) string {
	t.Helper()
	source := repoRoot(t)
	root := t.TempDir()
	for _, relative := range []string{
		frameCodecProjectionPath,
		"corpora/public/scenarios.jsonl",
		"corpora/public/manifest.json",
		"evidence/java/autobahn-baseline.json",
	} {
		raw, err := os.ReadFile(filepath.Join(source, relative))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func writeFrameCodecTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
