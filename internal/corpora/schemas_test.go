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
