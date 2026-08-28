package provenance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestValidateCurrentHeadQualificationBindsBlobToDeclaredCommit(t *testing.T) {
	root, firstCommit, firstTree, bindings := qualificationRepositoryAllPaths(t)
	receipt := qualificationFixtureWithBindings(firstCommit, firstTree, bindings)

	summary, err := ValidateCurrentHeadQualification(root, marshalQualification(t, receipt))
	if err != nil {
		t.Fatalf("validate exact qualification: %v", err)
	}
	if summary.QualifiedCommit != firstCommit || summary.BindingCount != len(bindings) {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestValidateCurrentHeadQualificationRejectsCommitBlobMismatch(t *testing.T) {
	root, firstCommit, firstTree, bindings := qualificationRepositoryAllPaths(t)
	receipt := qualificationFixtureWithBindings(firstCommit, firstTree, bindings)
	receipt["bindings"].([]map[string]any)[0]["git_blob"] = strings.Repeat("0", 40)

	_, err := ValidateCurrentHeadQualification(root, marshalQualification(t, receipt))
	if err == nil || !strings.Contains(err.Error(), "COMMIT_BLOB_MISMATCH") {
		t.Fatalf("commit/blob mismatch was not rejected exactly: %v", err)
	}
}

func TestValidateCurrentHeadQualificationRejectsBlobContentDigestMismatch(t *testing.T) {
	root, firstCommit, firstTree, bindings := qualificationRepositoryAllPaths(t)
	receipt := qualificationFixtureWithBindings(firstCommit, firstTree, bindings)
	receipt["bindings"].([]map[string]any)[0]["sha256"] = "sha256:" + strings.Repeat("0", 64)

	_, err := ValidateCurrentHeadQualification(root, marshalQualification(t, receipt))
	if err == nil || !strings.Contains(err.Error(), "BLOB_SHA256_MISMATCH") {
		t.Fatalf("blob digest mismatch was not rejected exactly: %v", err)
	}
}

func TestValidateCurrentHeadQualificationRejectsTrailingRecord(t *testing.T) {
	root, commit, tree, bindings := qualificationRepositoryAllPaths(t)
	document := append(marshalQualification(t, qualificationFixtureWithBindings(commit, tree, bindings)), []byte(`{}`)...)
	_, err := ValidateCurrentHeadQualification(root, document)
	if err == nil || !strings.Contains(err.Error(), "QUALIFICATION_TRAILING_DATA") {
		t.Fatalf("trailing record was not rejected exactly: %v", err)
	}
}

func TestLoadCurrentHeadQualificationRejectsMissingAndStaleCoverage(t *testing.T) {
	root, commit, tree, bindings := qualificationRepositoryAllPaths(t)
	if _, err := LoadAndValidateCurrentHeadQualification(root); err == nil || !strings.Contains(err.Error(), "QUALIFICATION_MISSING") {
		t.Fatalf("missing current qualification was not rejected exactly: %v", err)
	}
	receipt := qualificationFixtureWithBindings(commit, tree, bindings)
	path := filepath.Join(root, CurrentHeadQualificationPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, marshalQualification(t, receipt), 0o644); err != nil {
		t.Fatal(err)
	}
	runQualificationGit(t, root, "add", CurrentHeadQualificationPath)
	runQualificationGit(t, root, "commit", "--quiet", "-m", "qualification receipt")
	if _, err := LoadAndValidateCurrentHeadQualification(root); err != nil {
		t.Fatalf("current receipt did not cover unchanged source: %v", err)
	}
	documentation := filepath.Join(root, "docs", "rust-workspace.md")
	if err := os.WriteFile(documentation, []byte("later documentation only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runQualificationGit(t, root, "add", "docs/rust-workspace.md")
	runQualificationGit(t, root, "commit", "--quiet", "-m", "documentation after qualification")
	if _, err := LoadAndValidateCurrentHeadQualification(root); err != nil {
		t.Fatalf("documentation-only change invalidated source qualification: %v", err)
	}

	stalePath := filepath.Join(root, "rust", "connection-core", "src", "connection.rs")
	if err := os.WriteFile(stalePath, []byte("pub fn changed_after_qualification() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runQualificationGit(t, root, "add", "rust/connection-core/src/connection.rs")
	runQualificationGit(t, root, "commit", "--quiet", "-m", "stale qualified source")
	if _, err := LoadAndValidateCurrentHeadQualification(root); err == nil || !strings.Contains(err.Error(), "CURRENT_BINDING_STALE") {
		t.Fatalf("stale current qualification was not rejected exactly: %v", err)
	}
}

func TestHistoricalBindingRejectsForgedCommitPathBlob(t *testing.T) {
	root, firstCommit, _, firstBlob, firstSHA := qualificationRepository(t)
	path := filepath.Join(root, "rust", "source.rs")
	if err := os.WriteFile(path, []byte("pub fn later() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runQualificationGit(t, root, "add", "rust/source.rs")
	runQualificationGit(t, root, "commit", "--quiet", "-m", "later source")
	laterCommit := runQualificationGit(t, root, "rev-parse", "HEAD")
	binding := HistoricalBinding{Path: "rust/source.rs", SHA256: firstSHA, GitBlob: firstBlob}
	if err := ValidateHistoricalBindings(root, firstCommit, []HistoricalBinding{binding}); err != nil {
		t.Fatalf("exact historical binding failed: %v", err)
	}
	if err := ValidateHistoricalBindings(root, laterCommit, []HistoricalBinding{binding}); err == nil || !strings.Contains(err.Error(), "COMMIT_BLOB_MISMATCH") {
		t.Fatalf("forged historical commit/path/blob chain was accepted: %v", err)
	}
}

func TestHistoricalReceiptResolutionSelectsOriginalEraNotRestoration(t *testing.T) {
	root := t.TempDir()
	runQualificationGit(t, root, "init", "--quiet")
	runQualificationGit(t, root, "config", "user.email", "qualification@example.invalid")
	runQualificationGit(t, root, "config", "user.name", "Qualification Test")
	path := filepath.Join(root, "evidence", "historical.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	original := []byte("{\"era\":\"original\"}\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	runQualificationGit(t, root, "add", "evidence/historical.json")
	runQualificationGit(t, root, "commit", "--quiet", "-m", "original receipt")
	originalCommit := runQualificationGit(t, root, "rev-parse", "HEAD")
	if err := os.WriteFile(path, []byte("{\"era\":\"false-refresh\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runQualificationGit(t, root, "add", "evidence/historical.json")
	runQualificationGit(t, root, "commit", "--quiet", "-m", "false refresh")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	runQualificationGit(t, root, "add", "evidence/historical.json")
	runQualificationGit(t, root, "commit", "--quiet", "-m", "honest restoration")

	resolved, err := ResolveHistoricalArtifactCommit(root, "evidence/historical.json", original)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != originalCommit {
		t.Fatalf("resolved historical era = %s, want original %s", resolved, originalCommit)
	}
}

func TestCurrentHeadQualificationSchemaIsClosed(t *testing.T) {
	root, commit, tree, bindings := qualificationRepositoryAllPaths(t)
	_ = root
	schemaBytes, err := os.ReadFile(filepath.Join("..", "..", "schemas", "us020-current-head-qualification-1.1.0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaResource any
	if err := json.Unmarshal(schemaBytes, &schemaResource); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("qualification", schemaResource); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("qualification")
	if err != nil {
		t.Fatal(err)
	}
	fixture := qualificationFixtureWithBindings(commit, tree, bindings)
	var value any
	if err := json.Unmarshal(marshalQualification(t, fixture), &value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("closed fixture does not validate: %v", err)
	}
	value.(map[string]any)["unreviewed_claim"] = true
	if err := schema.Validate(value); err == nil {
		t.Fatal("schema accepted an unreviewed top-level claim")
	}
}

func TestMaterializeCurrentHeadQualificationUsesGitDerivedDenominator(t *testing.T) {
	root, commit, _, bindings := qualificationRepositoryAllPaths(t)
	if err := os.MkdirAll(filepath.Join(root, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := MaterializeCurrentHeadQualification(root, CurrentHeadMaterialization{
		ValidationTime: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC),
		Rustc:          "rustc 1.95.0 (59807616e 2026-04-14)",
		Host:           "aarch64-apple-darwin",
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, CurrentHeadQualificationPath))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := ValidateCurrentHeadQualification(root, raw)
	if err != nil {
		t.Fatal(err)
	}
	if summary.QualifiedCommit != commit || summary.BindingCount != len(bindings) {
		t.Fatalf("materialized summary = %+v, want commit %s and %d bindings", summary, commit, len(bindings))
	}
	if bytes.Contains(raw, []byte("docs/rust-workspace.md")) || bytes.Contains(raw, []byte("rust/target/generated.rs")) {
		t.Fatal("documentation or build output entered the source/test denominator")
	}
}

func qualificationRepository(t *testing.T) (string, string, string, string, string) {
	t.Helper()
	root := t.TempDir()
	runQualificationGit(t, root, "init", "--quiet")
	runQualificationGit(t, root, "config", "user.email", "qualification@example.invalid")
	runQualificationGit(t, root, "config", "user.name", "Qualification Test")
	path := filepath.Join(root, "rust", "source.rs")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("pub fn qualified() {}\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	runQualificationGit(t, root, "add", "rust/source.rs")
	runQualificationGit(t, root, "commit", "--quiet", "-m", "qualified source")
	commit := runQualificationGit(t, root, "rev-parse", "HEAD")
	tree := runQualificationGit(t, root, "rev-parse", "HEAD^{tree}")
	blob := runQualificationGit(t, root, "rev-parse", "HEAD:rust/source.rs")
	digest := sha256.Sum256(content)
	return root, commit, tree, blob, "sha256:" + hex.EncodeToString(digest[:])
}

func qualificationRepositoryAllPaths(t *testing.T) (string, string, string, []map[string]any) {
	t.Helper()
	root := t.TempDir()
	runQualificationGit(t, root, "init", "--quiet")
	runQualificationGit(t, root, "config", "user.email", "qualification@example.invalid")
	runQualificationGit(t, root, "config", "user.name", "Qualification Test")
	fixturePaths := []string{
		"LICENSE", "README.md", "cmd/currentheadctl/main.go", "cmd/rustgate/main.go",
		"docs/rust-workspace.md", "internal/provenance/current_head.go", "internal/rustgate/verify.go",
		"rust/Cargo.lock", "rust/Cargo.toml", "rust/Makefile", "rust/dependency-inventory.toml",
		"rust/dependency-policy.toml", "rust/rust-toolchain.toml", "rust/connection-core/Cargo.toml",
		"rust/connection-core/src/connection.rs", "rust/connection-core/tests/connection_contract.rs",
		"rust/target/generated.rs",
	}
	for _, name := range fixturePaths {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		content := []byte("qualified " + name + "\n")
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		runQualificationGit(t, root, "add", name)
	}
	runQualificationGit(t, root, "commit", "--quiet", "-m", "qualified source tree")
	commit := runQualificationGit(t, root, "rev-parse", "HEAD")
	tree := runQualificationGit(t, root, "rev-parse", "HEAD^{tree}")
	paths, err := expectedQualificationPaths(root, commit)
	if err != nil {
		t.Fatal(err)
	}
	bindings := make([]map[string]any, 0, len(paths))
	for _, name := range paths {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		bindings = append(bindings, map[string]any{
			"path": name, "sha256": "sha256:" + hex.EncodeToString(digest[:]),
			"git_blob": runQualificationGit(t, root, "rev-parse", "HEAD:"+name),
		})
	}
	return root, commit, tree, bindings
}

func qualificationFixtureWithBindings(commit, tree string, bindings []map[string]any) map[string]any {
	return map[string]any{
		"$schema":           "../schemas/us020-current-head-qualification-1.1.0.schema.json",
		"schema_version":    "1.1.0",
		"evidence_id":       "evidence.us-020-current-head-qualification",
		"story_id":          "US-020",
		"status":            "PASS_OWNER_ATTESTED_CURRENT_HEAD_NONNETWORK",
		"assurance":         "OWNER_ATTESTED_NOT_INDEPENDENT",
		"head_at_execution": commit,
		"source_tree":       tree,
		"validation_time":   "2026-08-27T23:00:00Z",
		"toolchain": map[string]any{
			"rustc": "rustc 1.95.0 (59807616e 2026-04-14)",
			"host":  "aarch64-apple-darwin",
		},
		"bindings":          bindings,
		"commands":          qualificationCommandsFixture(),
		"predecessor_scope": []string{"US-010", "US-011", "US-012", "US-013", "US-014", "US-015", "US-016", "US-017", "US-018", "US-019"},
		"claim_scope":       "CURRENT_SOURCE_TEST_QUALIFICATION_ONLY",
		"network":           false,
		"live_java":         false,
		"docker":            false,
		"autobahn":          false,
		"nonclaims": []string{
			"historical predecessor receipts are preserved and not rewritten",
			"no predecessor result is rerun or upgraded",
			"no live Java Docker Autobahn Linux network production publication signing or independent review claim",
		},
	}
}

func qualificationCommandsFixture() []map[string]any {
	return []map[string]any{
		{"argv": []string{"cargo", "test", "--locked", "-p", "websocket-core"}, "working_directory": "rust", "exit_code": 0, "result": "PASS"},
		{"argv": []string{"cargo", "test", "--locked", "-p", "websocket-driver"}, "working_directory": "rust", "exit_code": 0, "result": "PASS"},
		{"argv": []string{"cargo", "test", "--locked", "-p", "websocket-testee", "--lib"}, "working_directory": "rust", "exit_code": 0, "result": "PASS"},
		{"argv": []string{"cargo", "test", "--locked", "-p", "websocket-testee", "--test", "process", "neutral_oracle"}, "working_directory": "rust", "exit_code": 0, "result": "PASS"},
		{"argv": []string{"cargo", "fmt", "--all", "--", "--check"}, "working_directory": "rust", "exit_code": 0, "result": "PASS"},
		{"argv": []string{"cargo", "clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"}, "working_directory": "rust", "exit_code": 0, "result": "PASS"},
		{"argv": []string{"go", "test", "./cmd/rustgate", "-count=1"}, "working_directory": ".", "exit_code": 0, "result": "PASS"},
	}
}

func marshalQualification(t *testing.T, value map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func runQualificationGit(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return strings.TrimSpace(string(output))
}
