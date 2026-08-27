package linkage

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/michaellady/verified-java-websocket-port/internal/portplan"
)

// repoRoot walks up from the working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("no go.mod above the test directory")
		}
		directory = parent
	}
}

// TestFrozenMigrationMapStillRecordsTheHonestBlocker pins the state this
// overlay verifies against: the frozen US-003 map's 47 rows all carry
// rust_identity_verified=false with the resolver blocker active. The overlay
// never tampers with that freeze — if this test fails, someone mutated the
// frozen map instead of the linkage layer.
func TestFrozenMigrationMapStillRecordsTheHonestBlocker(t *testing.T) {
	root := repoRoot(t)
	migration, _, err := loadMigrationMap(root)
	if err != nil {
		t.Fatalf("load migration map: %v", err)
	}
	if len(migration.Rows) != 47 {
		t.Fatalf("migration map has %d rows, want 47", len(migration.Rows))
	}
	if migration.RustIdentityStatus.BlockerCode != "RUST_IDENTITIES_NOT_YET_RESOLVER_VERIFIED" {
		t.Fatalf("blocker code %q drifted", migration.RustIdentityStatus.BlockerCode)
	}
	for _, row := range migration.Rows {
		if row.RustIdentityVerified {
			t.Fatalf("frozen map row %s claims rust_identity_verified=true; the freeze was tampered", row.ID)
		}
	}
}

// TestLinkageArtifactsMatchTheTree is the closure gate: both committed
// artifacts must exist and be byte-identical to what the tree derives.
func TestLinkageArtifactsMatchTheTree(t *testing.T) {
	root := repoRoot(t)
	findings := Verify(root)
	if len(findings) != 0 {
		t.Fatalf("linkage verification findings: %v", findings)
	}
}

// TestEveryMigrationRowIsResolverVerifiedOrExcludedConfirmed asserts the
// committed verification artifact covers all 47 rows: 45 resolver-verified
// against the tree and the 2 capability-excluded rows exclusion-confirmed.
func TestEveryMigrationRowIsResolverVerifiedOrExcludedConfirmed(t *testing.T) {
	root := repoRoot(t)
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(VerificationPath)))
	if err != nil {
		t.Fatalf("the committed verification artifact is missing: %v", err)
	}
	var document VerificationDocument
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if document.Summary.RowsTotal != 47 || len(document.Rows) != 47 {
		t.Fatalf("artifact covers %d/%d rows, want 47/47", len(document.Rows), document.Summary.RowsTotal)
	}
	if document.Summary.Verified != 45 || document.Summary.ExcludedConfirmed != 2 {
		t.Fatalf("summary verified=%d excluded=%d, want 45/2",
			document.Summary.Verified, document.Summary.ExcludedConfirmed)
	}
	migration, _, err := loadMigrationMap(root)
	if err != nil {
		t.Fatalf("load migration map: %v", err)
	}
	mapRows := map[string]portplan.MigrationRow{}
	for _, row := range migration.Rows {
		mapRows[row.ID] = row
	}
	for _, row := range document.Rows {
		mapRow, exists := mapRows[row.RowID]
		if !exists {
			t.Fatalf("verification row %s matches no migration row", row.RowID)
		}
		if row.PlannedRustSemanticID != mapRow.RustSemanticID {
			t.Fatalf("row %s planned identity drifted from the map", row.RowID)
		}
		if row.Disposition == "capability_excluded" {
			if row.RustIdentityVerified || len(row.LandedSymbols) != 0 {
				t.Fatalf("excluded row %s must be unverified with no symbols", row.RowID)
			}
			continue
		}
		if !row.RustIdentityVerified || len(row.LandedSymbols) == 0 {
			t.Fatalf("row %s is not resolver-verified", row.RowID)
		}
		for _, symbol := range row.LandedSymbols {
			resolved, err := resolveSymbol(root, symbol.RustPath)
			if err != nil {
				t.Fatalf("row %s symbol %s no longer resolves: %v", row.RowID, symbol.RustPath, err)
			}
			if resolved.SHA256 != symbol.SHA256 {
				t.Fatalf("row %s symbol %s digest is stale (file changed since verification)",
					row.RowID, symbol.RustPath)
			}
		}
	}
}

// TestLinkageDagBindsStoriesSymbolsAndEvidence asserts the committed DAG
// carries the story/symbol nodes the dossier's G7 demands and that every
// binding endpoint is real.
func TestLinkageDagBindsStoriesSymbolsAndEvidence(t *testing.T) {
	root := repoRoot(t)
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(DAGPath)))
	if err != nil {
		t.Fatalf("the committed linkage DAG is missing: %v", err)
	}
	var document DAGDocument
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	nodes := map[string]DAGNode{}
	for _, node := range document.Nodes {
		if _, duplicate := nodes[node.ID]; duplicate {
			t.Fatalf("duplicate node %s", node.ID)
		}
		nodes[node.ID] = node
	}
	outgoing := map[string]map[string]int{}
	for _, edge := range document.Edges {
		if _, exists := nodes[edge.From]; !exists {
			t.Fatalf("edge from unknown node %s", edge.From)
		}
		if _, exists := nodes[edge.To]; !exists {
			t.Fatalf("edge to unknown node %s", edge.To)
		}
		if outgoing[edge.From] == nil {
			outgoing[edge.From] = map[string]int{}
		}
		outgoing[edge.From][edge.Kind]++
	}
	for story := range storyTitles {
		node, exists := nodes[story]
		if !exists || node.Kind != "story" {
			t.Fatalf("story node %s missing", story)
		}
		if outgoing[story]["evidenced_by"] == 0 {
			t.Fatalf("story %s binds no evidence", story)
		}
	}
	for _, story := range []string{"US-010", "US-011", "US-012", "US-013", "US-014", "US-015", "US-016"} {
		if outgoing[story]["owns"] == 0 {
			t.Fatalf("story %s owns no migration rows", story)
		}
	}
	targetsContent, _, err := fileDigest(root, proofTargetsPath)
	if err != nil {
		t.Fatalf("read proof targets: %v", err)
	}
	var targets proofTargetsDocument
	if err := json.Unmarshal(targetsContent, &targets); err != nil {
		t.Fatalf("unmarshal proof targets: %v", err)
	}
	if len(targets.Targets) == 0 {
		t.Fatal("proof targets are empty")
	}
	for _, target := range targets.Targets {
		node, exists := nodes[target.TargetID]
		if !exists || node.Kind != "proof_target" {
			t.Fatalf("proof-target node %s missing", target.TargetID)
		}
		if outgoing[target.TargetID]["declares"] != len(target.ProductionSymbols) {
			t.Fatalf("proof target %s declares %d symbols in the DAG, want %d",
				target.TargetID, outgoing[target.TargetID]["declares"], len(target.ProductionSymbols))
		}
		for _, planned := range target.ProductionSymbols {
			if outgoing[planned.SymbolID]["landed_as"] == 0 {
				t.Fatalf("planned symbol %s binds no landed symbol", planned.SymbolID)
			}
		}
	}
	for _, node := range document.Nodes {
		switch node.Kind {
		case "symbol":
			_, digest, err := fileDigest(root, node.File)
			if err != nil {
				t.Fatalf("symbol %s file missing: %v", node.ID, err)
			}
			if digest != node.SHA256 {
				t.Fatalf("symbol %s digest is stale", node.ID)
			}
		case "evidence":
			_, digest, err := fileDigest(root, node.Path)
			if err != nil {
				t.Fatalf("evidence %s file missing: %v", node.ID, err)
			}
			if digest != node.SHA256 {
				t.Fatalf("evidence %s digest is stale", node.ID)
			}
		}
	}
}

// TestLinkageArtifactsValidateAgainstTheirSchemas validates both committed
// artifacts against their strict schemas.
func TestLinkageArtifactsValidateAgainstTheirSchemas(t *testing.T) {
	root := repoRoot(t)
	for _, pair := range []struct {
		artifact string
		schema   string
	}{
		{VerificationPath, "schemas/rust-identity-verification-1.0.0.schema.json"},
		{DAGPath, "schemas/linkage-evidence-dag-1.0.0.schema.json"},
	} {
		schemaContent, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(pair.schema)))
		if err != nil {
			t.Fatalf("read schema %s: %v", pair.schema, err)
		}
		schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaContent))
		if err != nil {
			t.Fatalf("parse schema %s: %v", pair.schema, err)
		}
		compiler := jsonschema.NewCompiler()
		resource := "https://verified-java-websocket-port.invalid/" + filepath.Base(pair.schema)
		if err := compiler.AddResource(resource, schemaValue); err != nil {
			t.Fatalf("add schema %s: %v", pair.schema, err)
		}
		schema, err := compiler.Compile(resource)
		if err != nil {
			t.Fatalf("compile schema %s: %v", pair.schema, err)
		}
		artifactContent, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(pair.artifact)))
		if err != nil {
			t.Fatalf("the committed artifact %s is missing: %v", pair.artifact, err)
		}
		artifactValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(artifactContent))
		if err != nil {
			t.Fatalf("parse artifact %s: %v", pair.artifact, err)
		}
		if err := schema.Validate(artifactValue); err != nil {
			t.Fatalf("%s fails its schema: %v", pair.artifact, err)
		}
	}
}

// TestResolverRefusesASymbolThatDoesNotExist is the polarity check on the
// scan itself: a declaration that is not in the file must fail resolution,
// so the verification can never be vacuous.
func TestResolverRefusesASymbolThatDoesNotExist(t *testing.T) {
	root := repoRoot(t)
	pattern, err := declarationPattern("ws_core::framing::CompletelyFabricatedFrameType", "struct")
	if err != nil {
		t.Fatalf("pattern: %v", err)
	}
	content, _, err := fileDigest(root, "rust/ws-core/src/framing.rs")
	if err != nil {
		t.Fatalf("read framing.rs: %v", err)
	}
	if pattern.Match(content) {
		t.Fatal("the scan matched a declaration that does not exist")
	}
	if _, err := resolveSymbol(root, "ws_core::framing::CompletelyFabricatedFrameType"); err == nil {
		t.Fatal("resolveSymbol accepted an uncataloged symbol")
	}
}

// derivationInputPaths lists every repository file the derivation reads, so
// the tamper test can run against an isolated copy.
func derivationInputPaths(t *testing.T, root string) []string {
	t.Helper()
	paths := map[string]bool{
		migrationMapPath: true,
		proofTargetsPath: true,
	}
	for _, spec := range symbolCatalog {
		paths[spec.File] = true
	}
	for _, spec := range evidenceCatalog {
		paths[spec.Path] = true
	}
	for _, dir := range rustSourceDirs {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(dir)), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && strings.HasSuffix(path, ".rs") {
				relative, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				paths[filepath.ToSlash(relative)] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	return ordered
}

// TestTamperedCommittedArtifactIsDetected proves Verify is a real gate: in
// an isolated copy of the derivation inputs, freshly written artifacts
// verify clean, and a single tampered byte in either committed artifact
// produces a typed drift finding.
func TestTamperedCommittedArtifactIsDetected(t *testing.T) {
	root := repoRoot(t)
	isolated := t.TempDir()
	for _, relative := range derivationInputPaths(t, root) {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		target := filepath.Join(isolated, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatalf("write %s: %v", relative, err)
		}
	}
	if err := WriteArtifacts(isolated); err != nil {
		t.Fatalf("write artifacts: %v", err)
	}
	if findings := Verify(isolated); len(findings) != 0 {
		t.Fatalf("fresh artifacts must verify clean, got %v", findings)
	}
	for _, artifact := range []struct {
		path    string
		finding string
	}{
		{VerificationPath, "LINKAGE_VERIFICATION_DRIFTED"},
		{DAGPath, "LINKAGE_DAG_DRIFTED"},
	} {
		target := filepath.Join(isolated, filepath.FromSlash(artifact.path))
		pristine, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read %s: %v", artifact.path, err)
		}
		tampered := bytes.Replace(pristine, []byte("sha256:"), []byte("sha256:0"), 1)
		if bytes.Equal(tampered, pristine) {
			t.Fatalf("tamper produced no change in %s", artifact.path)
		}
		if err := os.WriteFile(target, tampered, 0o644); err != nil {
			t.Fatalf("tamper %s: %v", artifact.path, err)
		}
		findings := Verify(isolated)
		found := false
		for _, finding := range findings {
			if strings.HasPrefix(finding, artifact.finding) {
				found = true
			}
		}
		if !found {
			t.Fatalf("tampering %s produced findings %v, want %s", artifact.path, findings, artifact.finding)
		}
		if err := os.WriteFile(target, pristine, 0o644); err != nil {
			t.Fatalf("restore %s: %v", artifact.path, err)
		}
	}
}

// TestRegenerateLinkageArtifacts rewrites the canonical artifacts. Guarded
// exactly like the other sanctioned regeneration paths (US004/US006/US007):
// set LINKAGE_REGENERATE=1 to refreeze deliberately, and the regeneration
// must be byte-idempotent.
func TestRegenerateLinkageArtifacts(t *testing.T) {
	if os.Getenv("LINKAGE_REGENERATE") != "1" {
		t.Skip("set LINKAGE_REGENERATE=1 to rewrite the canonical linkage artifacts")
	}
	root := repoRoot(t)
	if err := WriteArtifacts(root); err != nil {
		t.Fatalf("first write: %v", err)
	}
	first := readBoth(t, root)
	if err := WriteArtifacts(root); err != nil {
		t.Fatalf("second write: %v", err)
	}
	second := readBoth(t, root)
	for path, before := range first {
		if !bytes.Equal(before, second[path]) {
			t.Fatalf("regeneration is not byte-idempotent for %s", path)
		}
	}
}

func readBoth(t *testing.T, root string) map[string][]byte {
	t.Helper()
	artifacts := map[string][]byte{}
	for _, path := range []string{VerificationPath, DAGPath} {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		artifacts[path] = content
	}
	return artifacts
}
