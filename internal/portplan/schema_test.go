package portplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Each frozen document must validate against its own strict schema, and Verify must enforce that.
func TestEveryDocumentValidatesAgainstItsSchema(t *testing.T) {
	for _, document := range DocumentNames {
		failures, err := ValidateAgainstSchema(repoRoot, document)
		if err != nil {
			t.Fatalf("%s: %v", document, err)
		}
		if len(failures) != 0 {
			t.Fatalf("%s failed schema validation: %v", document, failures)
		}
	}
}

func TestSchemaViolationIsReportedByVerify(t *testing.T) {
	report := mutate(t, CutoverDocument, func(document map[string]any) {
		document["unexpected_field"] = "schemas are additionalProperties:false"
	})
	requireFinding(t, report, FindingSchemaViolation)
}

// The schema, not just the Go validator, must refuse a resolver-verified Rust identity.
func TestSchemaRefusesVerifiedRustIdentity(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "evidence", "intake")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(
		mustAbs(t, filepath.Join(repoRoot, "schemas")),
		filepath.Join(root, "schemas"),
	); err != nil {
		t.Fatalf("symlink schemas: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(repoRoot, EvidenceDirectory, MigrationMapDocument))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(content, &value); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	value["rows"].([]any)[0].(map[string]any)["rust_identity_verified"] = true
	mutated, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, MigrationMapDocument), mutated, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	failures, err := ValidateAgainstSchema(root, MigrationMapDocument)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(failures) == 0 {
		t.Fatal("the schema must refuse rust_identity_verified=true while no Rust workspace exists")
	}
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return absolute
}
