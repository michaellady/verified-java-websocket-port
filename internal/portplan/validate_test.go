package portplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const repoRoot = "../.."

func verifyRepo(t *testing.T) Report {
	t.Helper()
	report, err := Verify(repoRoot)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return report
}

// mutate copies the six committed documents into a temp root, applies edit to one of them, and
// returns the verification report for the mutated tree.
func mutate(t *testing.T, name string, edit func(document map[string]any)) Report {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, "evidence", "intake")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	schemas, err := filepath.Abs(filepath.Join(repoRoot, "schemas"))
	if err != nil {
		t.Fatalf("abs schemas: %v", err)
	}
	if err := os.Symlink(schemas, filepath.Join(root, "schemas")); err != nil {
		t.Fatalf("symlink schemas: %v", err)
	}
	oracle, err := os.ReadFile(filepath.Join(repoRoot, EvidenceDirectory, OracleEvidenceDocument))
	if err != nil {
		t.Fatalf("read oracle evidence: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, OracleEvidenceDocument), oracle, 0o644); err != nil {
		t.Fatalf("write oracle evidence: %v", err)
	}
	for _, document := range DocumentNames {
		content, err := os.ReadFile(filepath.Join(repoRoot, "evidence", "intake", document))
		if err != nil {
			t.Fatalf("read %s: %v", document, err)
		}
		if document == name {
			var value map[string]any
			if err := json.Unmarshal(content, &value); err != nil {
				t.Fatalf("unmarshal %s: %v", document, err)
			}
			edit(value)
			if content, err = json.MarshalIndent(value, "", "  "); err != nil {
				t.Fatalf("marshal %s: %v", document, err)
			}
		}
		if err := os.WriteFile(filepath.Join(target, document), content, 0o644); err != nil {
			t.Fatalf("write %s: %v", document, err)
		}
	}
	report, err := Verify(root)
	if err != nil {
		t.Fatalf("Verify mutated: %v", err)
	}
	return report
}

func requireFinding(t *testing.T, report Report, code string) {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.Code == code {
			return
		}
	}
	t.Fatalf("expected finding %s, got %v", code, report.Findings)
}

func TestCommittedIntakeEvidenceVerifies(t *testing.T) {
	report := verifyRepo(t)
	if !report.OK {
		t.Fatalf("committed intake evidence must verify, findings: %v", report.Findings)
	}
}

// AC1: the manifest reconciles the real production and test trees.
func TestManifestReconcilesDerivedTreeTotals(t *testing.T) {
	report := verifyRepo(t)
	want := map[string][2]int{
		"production": {78, 12317},
		"test":       {79, 9838},
		"study":      {52, 6916},
	}
	for name, expected := range want {
		got, ok := report.Totals[name]
		if !ok {
			t.Fatalf("manifest is missing the %s tree totals", name)
		}
		if got.Files != expected[0] || got.PhysicalLines != expected[1] {
			t.Fatalf("%s totals = %d files/%d lines, want %d/%d",
				name, got.Files, got.PhysicalLines, expected[0], expected[1])
		}
	}
}

func TestManifestRejectsUnreconciledTotals(t *testing.T) {
	report := mutate(t, ManifestDocument, func(document map[string]any) {
		reconciliation := document["reconciliation"].(map[string]any)
		production := reconciliation["production_tree"].(map[string]any)
		production["physical_lines"] = float64(12318)
	})
	requireFinding(t, report, FindingTotalsNotReconciled)
}

func TestManifestRequiresEverySurfaceSectionToCarryAnObservationStatus(t *testing.T) {
	report := mutate(t, ManifestDocument, func(document map[string]any) {
		sections := document["surface_sections"].([]any)
		first := sections[0].(map[string]any)
		first["observation_status"] = "OBSERVED"
		first["evidence_ref"] = ""
	})
	requireFinding(t, report, FindingSurfaceSectionUnsupported)
}

// AC2: the study surface is exactly the named files, with every exclusion named.
func TestSurfaceInventoryIsExactlyFiftyTwoFiles(t *testing.T) {
	report := verifyRepo(t)
	if report.StudySurfaceFiles != 52 {
		t.Fatalf("study surface = %d files, want 52", report.StudySurfaceFiles)
	}
}

func TestSurfaceInventoryRejectsAnUnnamedExclusion(t *testing.T) {
	report := mutate(t, SurfaceInventoryDocument, func(document map[string]any) {
		excluded := document["excluded"].([]any)
		first := excluded[0].(map[string]any)
		first["reason_code"] = ""
	})
	requireFinding(t, report, FindingExclusionNotNamed)
}

func TestSurfaceInventoryRejectsAnUnpartitionedFile(t *testing.T) {
	report := mutate(t, SurfaceInventoryDocument, func(document map[string]any) {
		excluded := document["excluded"].([]any)
		document["excluded"] = excluded[1:]
	})
	requireFinding(t, report, FindingPartitionIncomplete)
}

// AC3: every MigrationMap row binds compiler-derived Java identity to a Rust identity plus the
// full applicability, non-equivalence, provenance, slice, and evidence bindings.
func TestMigrationRowsCarryCompilerDerivedJavaIdentity(t *testing.T) {
	report := verifyRepo(t)
	if report.MigrationRows == 0 {
		t.Fatal("migration map must not be empty")
	}
	if report.MigrationRows != report.StudySurfaceTypes {
		t.Fatalf("migration rows = %d, study-surface types = %d; every in-scope semantic item"+
			" must map to a row", report.MigrationRows, report.StudySurfaceTypes)
	}
}

func TestMigrationRowRejectsMissingSemanticBinding(t *testing.T) {
	for _, field := range []string{
		"java_semantic_id", "java_signature", "rust_semantic_id", "source_revision",
		"detection_query", "status",
	} {
		report := mutate(t, MigrationMapDocument, func(document map[string]any) {
			rows := document["rows"].([]any)
			rows[0].(map[string]any)[field] = ""
		})
		requireFinding(t, report, FindingIncompleteMigrationRow)
	}
	for _, field := range []string{
		"applicability_conditions", "known_non_equivalent_cases", "touched_files",
		"specification_ids", "oracle_ids", "vector_ids", "property_claim_ids",
		"formal_claim_ids", "evidence_ids", "port_slices",
	} {
		report := mutate(t, MigrationMapDocument, func(document map[string]any) {
			rows := document["rows"].([]any)
			rows[0].(map[string]any)[field] = []any{}
		})
		requireFinding(t, report, FindingIncompleteMigrationRow)
	}
}

// The story's central honesty constraint: static or grep lookup is explicitly weaker than
// compiler/LSP semantic identity and cannot establish a proved claim.
func TestMigrationRowRejectsGrepLookupStrength(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		rows := document["rows"].([]any)
		rows[0].(map[string]any)["java_lookup_strength"] = "grep-fallback"
	})
	requireFinding(t, report, FindingWeakLookupStrength)
}

// No row may claim a rust-analyzer- or Glancer-verified Rust identity while no Rust workspace
// exists in the repository. US-009 creates that workspace.
func TestMigrationRowCannotClaimVerifiedRustIdentityWithoutARustWorkspace(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		rows := document["rows"].([]any)
		row := rows[0].(map[string]any)
		row["rust_identity_verified"] = true
		row["status"] = "RUST_IDENTITY_RESOLVER_VERIFIED"
	})
	requireFinding(t, report, FindingUnverifiableRustIdentity)
}

func TestMigrationMapDeclaresNoRustWorkspaceExists(t *testing.T) {
	report := verifyRepo(t)
	if report.RustWorkspacePresent {
		t.Skip("a Rust workspace now exists; US-009 has landed and this guard changes shape")
	}
	if report.VerifiedRustIdentities != 0 {
		t.Fatalf("no Rust identity can be resolver-verified before US-009, got %d",
			report.VerifiedRustIdentities)
	}
}

func TestMigrationMapVerifiesOnlyImplementedUS009Identities(t *testing.T) {
	migration := loadMigration(t, repoRoot)
	want := map[string]string{
		"org.java_websocket.WebSocketImpl":    "websocket_core::ConnectionCore",
		"org.java_websocket.enums.ReadyState": "websocket_core::ConnectionState",
		"org.java_websocket.enums.Role":       "websocket_core::Role",
	}
	verified := 0
	for _, row := range migration.Rows {
		if !row.RustIdentityVerified {
			if row.Status != "PLANNED_RUST_IDENTITY_NOT_RESOLVER_VERIFIED" &&
				row.Status != "IN_SCOPE_SEMANTIC_ITEM_CAPABILITY_EXCLUDED" {
				t.Fatalf("unverified %s has dishonest status %s", row.JavaSemanticID, row.Status)
			}
			continue
		}
		verified++
		expected, ok := want[row.JavaSemanticID]
		if !ok {
			t.Fatalf("later-story identity was fabricated as verified: %s -> %s", row.JavaSemanticID, row.RustSemanticID)
		}
		if row.RustSemanticID != expected {
			t.Fatalf("%s maps to %s, want %s", row.JavaSemanticID, row.RustSemanticID, expected)
		}
		delete(want, row.JavaSemanticID)
	}
	if verified != 3 || len(want) != 0 {
		t.Fatalf("verified identities = %d and missing = %v; want exactly three US-009 identities", verified, want)
	}
}

func TestMigrationMapRejectsUnreceiptedVerifiedIdentity(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		rows := document["rows"].([]any)
		row := rows[0].(map[string]any)
		row["rust_identity_verified"] = true
		row["status"] = "RESOLVER_VERIFIED_DIRECT_IDENTITY"
	})
	requireFinding(t, report, FindingUnverifiableRustIdentity)
}

func TestMigrationMapRejectsRustAnalyzerReceiptDrift(t *testing.T) {
	tests := map[string]func(map[string]any){
		"resolver binary digest": func(receipt map[string]any) {
			receipt["resolver_binary_sha256"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"resolver command": func(receipt map[string]any) {
			receipt["command"].([]any)[0] = "unreceipted-rust-analyzer"
		},
		"resolved SCIP symbol": func(receipt map[string]any) {
			resolutions := receipt["resolutions"].([]any)
			resolutions[0].(map[string]any)["scip_symbol"] = "fabricated symbol"
		},
	}
	for name, drift := range tests {
		t.Run(name, func(t *testing.T) {
			report := mutate(t, MigrationMapDocument, func(document map[string]any) {
				status := document["rust_identity_status"].(map[string]any)
				drift(status["resolution_receipt"].(map[string]any))
			})
			requireFinding(t, report, FindingUnverifiableRustIdentity)
		})
	}
}

// AC4: no implementation story has an unresolved touched surface.
func TestSeamDossierLeavesNoImplementationStoryUnresolved(t *testing.T) {
	report := verifyRepo(t)
	if len(report.UnresolvedStories) != 0 {
		t.Fatalf("implementation stories with unresolved touched surface: %v",
			report.UnresolvedStories)
	}
	if len(report.ImplementationStories) == 0 {
		t.Fatal("seam dossier must enumerate the implementation stories")
	}
}

func TestSeamDossierRejectsAnUnresolvedTouchedSurface(t *testing.T) {
	report := mutate(t, SeamDossierDocument, func(document map[string]any) {
		seams := document["seams"].([]any)
		seams[0].(map[string]any)["touched_files"] = []any{}
	})
	requireFinding(t, report, FindingUnresolvedTouchedSurface)
}

func TestSeamDossierCoversEveryRequiredBoundaryCategory(t *testing.T) {
	report := mutate(t, SeamDossierDocument, func(document map[string]any) {
		delete(document, "buffers")
	})
	requireFinding(t, report, FindingSeamCategoryMissing)
}

// AC5: the RFC 6455 wire boundary is preserved and the named surfaces are explicitly excluded.
func TestCompatibilityAndCutoverPreserveTheWireBoundary(t *testing.T) {
	report := verifyRepo(t)
	if !report.WireBoundaryPreserved {
		t.Fatal("compatibility surface must preserve the RFC 6455 wire boundary")
	}
}

func TestCompatibilityRejectsDroppedWireBoundary(t *testing.T) {
	report := mutate(t, CompatibilityDocument, func(document map[string]any) {
		document["preserved_boundary"] = map[string]any{
			"standard": "", "normative_artifact_id": "", "normalized_command_event_behavior": false,
		}
	})
	requireFinding(t, report, FindingWireBoundaryNotPreserved)
}

func TestCutoverExcludesEveryNamedOutOfScopeSurface(t *testing.T) {
	report := verifyRepo(t)
	for _, code := range RequiredExclusions {
		if !report.DeclaredExclusions[code] {
			t.Fatalf("AC5 requires %s be explicitly excluded", code)
		}
	}
}

func TestCutoverRejectsAMissingRequiredExclusion(t *testing.T) {
	for _, code := range RequiredExclusions {
		dropped := code
		report := mutate(t, CutoverDocument, func(document map[string]any) {
			excluded := document["excluded_behaviors"].([]any)
			kept := make([]any, 0, len(excluded))
			for _, entry := range excluded {
				if entry.(map[string]any)["code"].(string) != dropped {
					kept = append(kept, entry)
				}
			}
			document["excluded_behaviors"] = kept
		})
		requireFinding(t, report, FindingRequiredExclusionMissing)
	}
}

func TestCutoverRejectsUnresolvedBehaviors(t *testing.T) {
	report := mutate(t, CutoverDocument, func(document map[string]any) {
		document["unresolved_behaviors"] = []any{"an unresolved behavior"}
	})
	requireFinding(t, report, FindingUnresolvedBehavior)
}

// E2E: every in-scope semantic item maps to a child story and an evidence obligation, and every
// excluded item stays explicit.
func TestPlanTraceabilityIsTotal(t *testing.T) {
	report := verifyRepo(t)
	if len(report.UnmappedSemanticItems) != 0 {
		t.Fatalf("semantic items with no child story or evidence obligation: %v",
			report.UnmappedSemanticItems)
	}
	if report.TraceableSemanticItems != report.StudySurfaceTypes {
		t.Fatalf("traceable items = %d, study-surface types = %d",
			report.TraceableSemanticItems, report.StudySurfaceTypes)
	}
}

func TestPlanTraceabilityRejectsARowWithoutAChildStory(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		rows := document["rows"].([]any)
		bindings := rows[0].(map[string]any)["port_slices"].([]any)
		bindings[0].(map[string]any)["child_story_id"] = "US-999"
	})
	requireFinding(t, report, FindingUnknownChildStory)
}

// Assurance posture is fixed for every document in this story.
func TestEveryDocumentCarriesTheOwnerAttestedPosture(t *testing.T) {
	report := verifyRepo(t)
	if report.DocumentsChecked != len(DocumentNames) {
		t.Fatalf("checked %d documents, want %d", report.DocumentsChecked, len(DocumentNames))
	}
}

func TestAssurancePostureCannotBeUpgraded(t *testing.T) {
	for _, document := range DocumentNames {
		report := mutate(t, document, func(value map[string]any) {
			assurance := value["assurance"].(map[string]any)
			assurance["independent_review_claimed"] = true
		})
		requireFinding(t, report, FindingAssurancePosture)
	}
}
