package corpora

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func schemasDir(t *testing.T) string {
	t.Helper()
	// Package tests run inside the repository; the schemas ship with it.
	absolute, err := filepath.Abs("../../schemas")
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

// Every emitted artifact validates against its strict schema, and the
// calibration document validates against its own.
func TestEmittedArtifactsValidateAgainstSchemas(t *testing.T) {
	root, protectedRoot, generated := writeAllToTemp(t)
	doc, err := BuildCalibration(root, protectedRoot, generated)
	if err != nil {
		t.Fatalf("BuildCalibration: %v", err)
	}
	if err := WriteCalibration(root, doc); err != nil {
		t.Fatal(err)
	}
	findings, err := ValidateCorpusSchemas(schemasDir(t), root, protectedRoot)
	if err != nil {
		t.Fatalf("ValidateCorpusSchemas: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("fresh artifacts must be schema-valid, findings: %v", findings)
	}
}

// Schema validation fails closed on malformed committed lines.
func TestSchemaValidationFailsClosedOnMalformedLine(t *testing.T) {
	root, protectedRoot, generated := writeAllToTemp(t)
	doc, err := BuildCalibration(root, protectedRoot, generated)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteCalibration(root, doc); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "corpora/public/scenarios.jsonl")
	raw, _ := os.ReadFile(path)
	edited := strings.Replace(string(raw), `"tier":"public"`, `"tier":"pubic"`, 1)
	if edited == string(raw) {
		t.Fatal("nothing replaced")
	}
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := ValidateCorpusSchemas(schemasDir(t), root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("schema-invalid line must produce findings")
	}
}

// While execution is pending, nonzero execution counters are schema-invalid;
// a recorded live execution requires evidence and permits them.
func TestManifestSchemaGuardsExecutionStates(t *testing.T) {
	root, protectedRoot, _ := writeAllToTemp(t)
	path := filepath.Join(root, "corpora/public/manifest.json")
	manifest, err := readManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	counts := manifest["counts"].(map[string]any)
	counts["executed"] = 1
	if err := writeJSONFile(path, manifest); err != nil {
		t.Fatal(err)
	}
	findings, err := ValidateCorpusSchemas(schemasDir(t), root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("pending status with nonzero executed count must be schema-invalid")
	}

	manifest["execution_status"] = "LIVE_EXECUTED"
	manifest["execution_evidence"] = map[string]any{
		"transcript_sha256": DigestSHA256([]byte("t")),
		"report_sha256":     DigestSHA256([]byte("r")),
		"evaluator":         "corporactl evaluate",
	}
	if err := writeJSONFile(path, manifest); err != nil {
		t.Fatal(err)
	}
	findings, err = ValidateCorpusSchemas(schemasDir(t), root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if strings.Contains(finding.Path, "public/manifest.json") {
			t.Fatalf("recorded execution state must be schema-valid: %v", finding)
		}
	}
}

// LIVE_EXECUTED with zero executed scenarios is schema-invalid.
func TestManifestSchemaRejectsEmptyLiveExecution(t *testing.T) {
	root, protectedRoot, _ := writeAllToTemp(t)
	path := filepath.Join(root, "corpora/public/manifest.json")
	manifest, err := readManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	manifest["execution_status"] = "LIVE_EXECUTED"
	manifest["execution_evidence"] = map[string]any{
		"transcript_sha256": DigestSHA256([]byte("t")),
		"report_sha256":     DigestSHA256([]byte("r")),
		"evaluator":         "corporactl evaluate",
	}
	if err := writeJSONFile(path, manifest); err != nil {
		t.Fatal(err)
	}
	findings, err := ValidateCorpusSchemas(schemasDir(t), root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	var hit bool
	for _, finding := range findings {
		if strings.Contains(finding.Path, "public/manifest.json") {
			hit = true
		}
	}
	if !hit {
		t.Fatal("LIVE_EXECUTED with executed=0 must be schema-invalid")
	}
}
