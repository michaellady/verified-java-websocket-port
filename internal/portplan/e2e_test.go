package portplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const quarantineTree = QuarantineDirectory + "/" + SourceTreeDirectory

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

	// Every in-scope semantic item maps to at least one child story and evidence obligation
	// through its slice bindings.
	seamsByStory := map[string]int{}
	for _, seam := range dossier.Seams {
		seamsByStory[seam.ChildStoryID]++
	}
	for _, row := range migration.Rows {
		if len(row.PortSlices) == 0 {
			t.Fatalf("%s maps to no slice binding", row.JavaBinaryName)
		}
		for _, binding := range row.PortSlices {
			if binding.ChildStoryID == "" {
				t.Fatalf("%s binding %s has no child story", row.JavaBinaryName, binding.PortSliceID)
			}
			if len(binding.EvidenceIDs) == 0 {
				t.Fatalf("%s binding %s carries no evidence obligation",
					row.JavaBinaryName, binding.PortSliceID)
			}
			if seamsByStory[binding.ChildStoryID] == 0 {
				t.Fatalf("%s maps to %s, which owns no seam",
					row.JavaBinaryName, binding.ChildStoryID)
			}
		}
		if len(row.EvidenceIDs) == 0 || len(row.OracleIDs) == 0 {
			t.Fatalf("%s carries no row-level evidence obligation", row.JavaBinaryName)
		}
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

	// Every excluded item stays explicit and never gains a migration row. The seam dossier MAY
	// reference excluded byte-channel files as adapter context (review B2), but only under the
	// US-018 adapter seam.
	for _, record := range inventory.Excluded {
		if record.ReasonCode == "" || record.Reason == "" {
			t.Fatalf("excluded file %s is not explicit", record.Path)
		}
		if mappedFiles[record.Path] {
			t.Fatalf("excluded file %s leaked into the migration map", record.Path)
		}
	}
	for _, seam := range dossier.Seams {
		for _, file := range seam.TouchedFiles {
			if mappedFiles[file] {
				continue
			}
			if seam.ChildStoryID != "US-018" || seam.Category != "adapter_seams" {
				t.Fatalf("seam %s references non-study file %s outside the adapter context",
					seam.SurfaceID, file)
			}
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

// TestDeriveReproducesCommittedEvidence is the non-skippable qualification (review B3): it
// materializes the digest-pinned upstream source (re-acquiring it over the network when absent,
// with a typed failure when that is impossible), verifies every oracle file entry against the
// real tree inside Derive, and requires the committed documents to be reproduced byte for byte.
func TestDeriveReproducesCommittedEvidence(t *testing.T) {
	if _, err := EnsureQuarantinedSource(repoRoot); err != nil {
		t.Fatalf("source materialization failed (never skipped): %v", err)
	}

	root := t.TempDir()
	if err := Derive(reproductionRequest(root)); err != nil {
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
