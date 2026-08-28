package campaign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join(working, "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func loadManifest(t *testing.T, root, relative string) Manifest {
	t.Helper()
	raw, err := readRepositoryFile(root, relative, maximumDocument)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func requireFinding(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || !strings.HasPrefix(err.Error(), code+" at ") {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}

func TestVerifyCommittedUS021Evidence(t *testing.T) {
	if err := Verify(repositoryRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyAndFuzzManifestsVerifyIndependently(t *testing.T) {
	root := repositoryRoot(t)
	for _, relative := range manifestPaths[:2] {
		manifest := loadManifest(t, root, relative)
		if err := verifyManifest(root, relative, manifest); err != nil {
			t.Fatalf("%s: %v", relative, err)
		}
	}
}

func TestCampaignEvidenceRejectsHostileMutations(t *testing.T) {
	root := repositoryRoot(t)
	propertyPath := manifestPaths[0]
	property := loadManifest(t, root, propertyPath)

	tests := []struct {
		name string
		code string
		edit func(*Manifest)
	}{
		{"overclaim", "CAMPAIGN_OVERCLAIM", func(value *Manifest) { value.IndependentReviewClaimed = true }},
		{"source drift", "CAMPAIGN_SOURCE_DRIFT", func(value *Manifest) { value.Targets[0].Sources[0].SHA256 = "sha256:" + strings.Repeat("0", 64) }},
		{"corpus drift", "CAMPAIGN_CORPUS_DRIFT", func(value *Manifest) { value.Targets[0].SeedCount++ }},
		{"missing target", "CAMPAIGN_TARGET_MISMATCH", func(value *Manifest) { value.Targets = value.Targets[:len(value.Targets)-1] }},
		{"duplicate target", "CAMPAIGN_TARGET_MISMATCH", func(value *Manifest) { value.Targets[1] = value.Targets[0] }},
		{"changed command", "CAMPAIGN_TARGET_CONTRACT_MISMATCH", func(value *Manifest) { value.Targets[0].Command[0] = "changed" }},
		{"unsafe replay", "CAMPAIGN_TARGET_CONTRACT_MISMATCH", func(value *Manifest) { value.Targets[0].ReplayCommand[0] = "$cargo" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := property
			value.Targets = append([]Target(nil), property.Targets...)
			for index := range value.Targets {
				value.Targets[index].Sources = append([]Artifact(nil), property.Targets[index].Sources...)
				value.Targets[index].Command = append([]string(nil), property.Targets[index].Command...)
				value.Targets[index].ReplayCommand = append([]string(nil), property.Targets[index].ReplayCommand...)
			}
			test.edit(&value)
			requireFinding(t, verifyManifest(root, propertyPath, value), test.code)
		})
	}
}

func TestCampaignEvidenceRejectsUnavailableToolClaim(t *testing.T) {
	root := repositoryRoot(t)
	path := manifestPaths[1]
	manifest := loadManifest(t, root, path)
	manifest.ExternalTools[0].ClaimedPass = true
	requireFinding(t, verifyManifest(root, path, manifest), "EXTERNAL_TOOL_OVERCLAIM")
}

func TestRuntimeEvidenceRejectsEmulationAndFailedReceipts(t *testing.T) {
	root := repositoryRoot(t)
	path := manifestPaths[2]
	base := loadManifest(t, root, path)
	base.Status = "PASS_OWNER_RELAXED"
	base.Platforms[1].RustcVersion = rustc195
	base.Platforms[1].Debug = append([]RuntimeCommand(nil), base.Platforms[0].Debug...)
	base.Platforms[1].Release = append([]RuntimeCommand(nil), base.Platforms[0].Release...)
	base.Platforms[1].FileDescriptorCleanup = "PASS"
	base.Platforms[1].ProcessCleanup = "PASS"
	base.Platforms[1].Unresolved = 0
	base.Counts.Cases = 1448
	base.Counts.RuntimeCommands = 8
	base.Counts.Unresolved = 0

	t.Run("emulation", func(t *testing.T) {
		value := base
		value.Platforms = append([]Platform(nil), base.Platforms...)
		value.Platforms[1].ExecutionKind = "EMULATED"
		requireFinding(t, verifyManifest(root, path, value), "RUNTIME_PLATFORM_FAILED")
	})
	t.Run("failed command", func(t *testing.T) {
		value := base
		value.Platforms = append([]Platform(nil), base.Platforms...)
		value.Platforms[1].ExecutionKind = "NATIVE"
		value.Platforms[1].Debug = append([]RuntimeCommand(nil), base.Platforms[1].Debug...)
		value.Platforms[1].Debug[0].Status = "FAIL"
		requireFinding(t, verifyManifest(root, path, value), "RUNTIME_COMMAND_FAILED")
	})
}

func TestSchemaReferencesRemainLocal(t *testing.T) {
	requireFinding(t, verifySchemaReferences("schema.json", map[string]any{"$ref": "https://attacker.invalid/schema"}), "UNSAFE_CAMPAIGN_SCHEMA_REFERENCE")
}

func TestDecodeStrictRejectsUnknownAndTrailingFields(t *testing.T) {
	var manifest Manifest
	if err := decodeStrict([]byte(`{"unexpected":true}`), &manifest); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if err := decodeStrict([]byte(`{} {}`), &manifest); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}

func TestManifestShapeRejectsMissingZeroValuedAndDuplicateFields(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := readRepositoryFile(root, manifestPaths[0], maximumDocument)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := decodeJSONTree(raw)
	if err != nil {
		t.Fatal(err)
	}
	object := tree.(map[string]any)
	delete(object, "independent_review_claimed")
	if err := verifyManifestShape(object); err == nil || !strings.Contains(err.Error(), "independent_review_claimed is required") {
		t.Fatalf("missing false-valued required field was accepted: %v", err)
	}
	if _, err := decodeJSONTree([]byte(`{"kind":"property","kind":"runtime"}`)); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate JSON key was accepted: %v", err)
	}
}

func TestArtifactMustMatchWorkingTreeAndDeclaredCommit(t *testing.T) {
	root := repositoryRoot(t)
	path := "rust/websocket-testee/src/io_loop.rs"
	data, err := readRepositoryFile(root, path, maximumDocument)
	if err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{Path: path, SHA256: digest(data)}
	const preFixAnchor = "70a3cfad6b083d3ad39b76f938f64f9156412f33"
	requireFinding(t, verifyArtifact(root, preFixAnchor, artifact), "CAMPAIGN_ANCHOR_DRIFT")
}
