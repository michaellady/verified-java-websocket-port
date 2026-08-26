package portplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const quarantineTree = ".quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667"

// TestEndToEndIntakeReconciliationAndPlanTraceability is the story's end-to-end test: given the
// exact Java release, intake reconciliation and plan traceability must show that every in-scope
// semantic item maps to a child story and an evidence obligation, and that every excluded item
// stays explicit.
func TestEndToEndIntakeReconciliationAndPlanTraceability(t *testing.T) {
	report := verifyRepo(t)
	if !report.OK {
		t.Fatalf("intake reconciliation failed: %v", report.Findings)
	}

	inventory := loadInventory(t, repoRoot)
	migration := loadMigration(t, repoRoot)
	dossier := loadDossier(t, repoRoot)

	// Every in-scope semantic item maps to a child story and an evidence obligation.
	seamsByStory := map[string]int{}
	for _, seam := range dossier.Seams {
		seamsByStory[seam.ChildStoryID]++
	}
	storyOf := map[string]string{}
	for _, row := range migration.Rows {
		if row.ChildStoryID == "" {
			t.Fatalf("%s maps to no child story", row.JavaBinaryName)
		}
		if len(row.EvidenceIDs) == 0 || len(row.OracleIDs) == 0 {
			t.Fatalf("%s carries no evidence obligation", row.JavaBinaryName)
		}
		if seamsByStory[row.ChildStoryID] == 0 {
			t.Fatalf("%s maps to %s, which owns no seam", row.JavaBinaryName, row.ChildStoryID)
		}
		storyOf[row.JavaBinaryName] = row.ChildStoryID
	}

	// Every in-scope file contributes at least one mapped semantic item, except the package-info
	// documentation units, which declare no type at all.
	mappedFiles := map[string]bool{}
	for _, row := range migration.Rows {
		for _, file := range row.TouchedFiles {
			mappedFiles[file] = true
		}
	}
	for _, record := range inventory.Selected {
		if strings.HasSuffix(record.Path, "package-info.java") {
			if record.DeclarationCount != 0 {
				t.Fatalf("%s unexpectedly declares %d items", record.Path, record.DeclarationCount)
			}
			continue
		}
		if !mappedFiles[record.Path] {
			t.Fatalf("in-scope file %s maps to no semantic item", record.Path)
		}
	}

	// Every excluded item stays explicit.
	for _, record := range inventory.Excluded {
		if record.ReasonCode == "" || record.Reason == "" {
			t.Fatalf("excluded file %s is not explicit", record.Path)
		}
		if mappedFiles[record.Path] {
			t.Fatalf("excluded file %s leaked into the port plan", record.Path)
		}
	}

	// Every implementation story owns at least one seam, so no slice is left unplanned.
	for _, story := range dossier.ImplementationStories {
		if len(story.SeamIDs) == 0 {
			t.Fatalf("%s owns no seam", story.StoryID)
		}
	}
	t.Logf("traceable semantic items=%d across %d child stories; %d files explicitly excluded",
		report.TraceableSemanticItems, len(dossier.ImplementationStories), len(inventory.Excluded))
}

// TestDeriveReproducesCommittedEvidence re-runs the whole derivation against the digest-verified
// upstream tree and requires it to reproduce the committed documents byte for byte. It skips when
// the quarantined source is not materialized, because the archive is never committed.
func TestDeriveReproducesCommittedEvidence(t *testing.T) {
	production := filepath.Join(repoRoot, quarantineTree, "src/main/java")
	if _, err := os.Stat(production); err != nil {
		t.Skip("quarantined Java source is not materialized; re-acquire it to run this check")
	}
	oracle := filepath.Join(repoRoot, "java-semantic-oracle/build/semantic-ids.json")
	if _, err := os.Stat(oracle); err != nil {
		t.Skip("semantic identity oracle output is not present; run java-semantic-oracle first")
	}

	root := t.TempDir()
	request := DeriveRequest{
		Root:                 root,
		ProductionSourceRoot: production,
		TestSourceRoot:       filepath.Join(repoRoot, quarantineTree, "src/test/java"),
		OraclePath:           oracle,
		OracleToolPath:       filepath.Join(repoRoot, "java-semantic-oracle/src/main/java/SemanticIdOracle.java"),
		SourceArtifactID:     "java-websocket-source-archive",
		SourceSHA256:         "sha256:f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4",
		SourceVersion:        "1.6.0",
		SourceCommit:         "da3cf2a777aed862f2f5b5cf060cae7969958667",
		RFC6455SHA256:        "sha256:765775326aee0ecca9b04bde3fd1f52932d498e33e34e428bd61b8a24da0fa3b",
	}
	if err := Derive(request); err != nil {
		t.Fatalf("Derive: %v", err)
	}
	for _, document := range DocumentNames {
		derived, err := os.ReadFile(filepath.Join(root, EvidenceDirectory, document))
		if err != nil {
			t.Fatalf("read derived %s: %v", document, err)
		}
		committed, err := os.ReadFile(filepath.Join(repoRoot, EvidenceDirectory, document))
		if err != nil {
			t.Fatalf("read committed %s: %v", document, err)
		}
		if string(derived) != string(committed) {
			t.Fatalf("%s: committed evidence is not what the pipeline derives from the pinned"+
				" source; re-run portplanctl derive", document)
		}
	}
}
