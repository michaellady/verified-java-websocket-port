package portplan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Verify validates the six frozen intake documents under root and reports every acceptance
// criterion that is not met. It reads only committed evidence, so it runs without the quarantined
// Java source tree; correspondence to the real tree is established by Derive.
func Verify(root string) (Report, error) {
	report := Report{
		OK:                 true,
		Totals:             map[string]TreeCount{},
		DeclaredExclusions: map[string]bool{},
	}

	var manifest IntakeManifest
	var inventory SurfaceInventory
	var migration MigrationMap
	var dossier SeamDossier
	var compatibility CompatibilitySurface
	var cutover CutoverContract

	targets := []struct {
		name  string
		value interface{}
	}{
		{ManifestDocument, &manifest},
		{SurfaceInventoryDocument, &inventory},
		{MigrationMapDocument, &migration},
		{SeamDossierDocument, &dossier},
		{CompatibilityDocument, &compatibility},
		{CutoverDocument, &cutover},
	}
	rawDocuments := map[string]map[string]interface{}{}
	for _, target := range targets {
		path := filepath.Join(root, EvidenceDirectory, target.name)
		content, err := os.ReadFile(path)
		if err != nil {
			return Report{}, fmt.Errorf("read %s: %w", target.name, err)
		}
		if err := json.Unmarshal(content, target.value); err != nil {
			report.add(FindingDocumentUnreadable, target.name, "$", err.Error())
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(content, &raw); err != nil {
			report.add(FindingDocumentUnreadable, target.name, "$", err.Error())
			continue
		}
		rawDocuments[target.name] = raw
		report.DocumentsChecked++

		failures, schemaErr := ValidateAgainstSchema(root, target.name)
		if schemaErr != nil {
			report.add(FindingSchemaViolation, target.name, "$",
				"schema unavailable: "+schemaErr.Error())
			continue
		}
		for _, failure := range failures {
			report.add(FindingSchemaViolation, target.name, "$", failure)
		}
	}

	report.checkAssurance(ManifestDocument, manifest.Assurance)
	report.checkAssurance(SurfaceInventoryDocument, inventory.Assurance)
	report.checkAssurance(MigrationMapDocument, migration.Assurance)
	report.checkAssurance(SeamDossierDocument, dossier.Assurance)
	report.checkAssurance(CompatibilityDocument, compatibility.Assurance)
	report.checkAssurance(CutoverDocument, cutover.Assurance)

	report.checkReconciliation(&manifest, &inventory)
	report.checkOracleBinding(root, &manifest)
	report.checkPromotedInputs(&manifest)
	report.checkSurfaceSections(&manifest)
	report.checkInventory(&inventory, &manifest)
	report.checkMigration(&migration, &manifest, &dossier, root)
	report.checkDossier(&dossier, rawDocuments[SeamDossierDocument])
	report.checkCompatibility(&compatibility)
	report.checkCutover(&cutover)

	report.OK = len(report.Findings) == 0
	return report, nil
}

func (report *Report) add(code, document, path, message string) {
	report.Findings = append(report.Findings, Finding{
		Code: code, Document: document, Path: path, Message: message,
	})
}

func (report *Report) checkAssurance(document string, assurance Assurance) {
	if assurance.Assurance != OwnerAttested {
		report.add(FindingAssurancePosture, document, "$.assurance.assurance",
			"assurance must remain "+OwnerAttested)
	}
	if assurance.IndependentReviewClaimed {
		report.add(FindingAssurancePosture, document, "$.assurance.independent_review_claimed",
			"this story never claims independent review")
	}
	if assurance.Production || assurance.Signing || assurance.Publication {
		report.add(FindingAssurancePosture, document, "$.assurance",
			"production, signing, and publication remain false")
	}
}

// checkReconciliation recomputes every declared total from the inventory's own per-file records,
// so the manifest cannot assert a count the primary data does not support.
func (report *Report) checkReconciliation(manifest *IntakeManifest, inventory *SurfaceInventory) {
	production := TreeCount{}
	for _, record := range append(append([]FileRecord{}, inventory.Selected...), inventory.Excluded...) {
		production.Files++
		production.PhysicalLines += record.PhysicalLines
	}
	study := TreeCount{}
	for _, record := range inventory.Selected {
		study.Files++
		study.PhysicalLines += record.PhysicalLines
	}
	test := TreeCount{}
	for _, record := range inventory.TestFiles {
		test.Files++
		test.PhysicalLines += record.PhysicalLines
	}

	report.Totals["production"] = production
	report.Totals["test"] = test
	report.Totals["study"] = study
	report.StudySurfaceFiles = study.Files
	report.StudySurfaceTypes = manifest.Reconciliation.DeclarationTotals.StudyTypes

	compare := func(name string, declared, derived TreeCount) {
		if declared != derived {
			report.add(FindingTotalsNotReconciled, ManifestDocument, "$.reconciliation."+name,
				fmt.Sprintf("declared %d files/%d lines, per-file records sum to %d/%d",
					declared.Files, declared.PhysicalLines, derived.Files, derived.PhysicalLines))
		}
	}
	compare("production_tree", manifest.Reconciliation.ProductionTree, production)
	compare("test_tree", manifest.Reconciliation.TestTree, test)
	compare("study_surface", manifest.Reconciliation.StudySurface, study)

	if manifest.Reconciliation.DeclarationTotals.CompilerErrorCount != 0 {
		report.add(FindingTotalsNotReconciled, ManifestDocument,
			"$.reconciliation.declaration_totals.compiler_error_count",
			"semantic identity requires a clean compiler run")
	}
}

func (report *Report) checkSurfaceSections(manifest *IntakeManifest) {
	if len(manifest.Sections) == 0 {
		report.add(FindingSurfaceSectionUnsupported, ManifestDocument, "$.surface_sections",
			"AC1 requires the surface sections be inventoried")
		return
	}
	for index, section := range manifest.Sections {
		path := fmt.Sprintf("$.surface_sections[%d]", index)
		switch section.ObservationStatus {
		case "OBSERVED":
			if strings.TrimSpace(section.EvidenceRef) == "" {
				report.add(FindingSurfaceSectionUnsupported, ManifestDocument, path,
					"an OBSERVED section must cite the evidence that observed it")
			}
		case "UNOBSERVABLE", "NOT_APPLICABLE":
			if strings.TrimSpace(section.BlockerCode) == "" {
				report.add(FindingSurfaceSectionUnsupported, ManifestDocument, path,
					"a non-observed section must carry a blocker code")
			}
		default:
			report.add(FindingSurfaceSectionUnsupported, ManifestDocument, path,
				"unknown observation status "+section.ObservationStatus)
		}
	}
}

func (report *Report) checkInventory(inventory *SurfaceInventory, manifest *IntakeManifest) {
	seen := map[string]bool{}
	for index, record := range inventory.Excluded {
		path := fmt.Sprintf("$.excluded[%d]", index)
		if strings.TrimSpace(record.ReasonCode) == "" || strings.TrimSpace(record.Reason) == "" {
			report.add(FindingExclusionNotNamed, SurfaceInventoryDocument, path,
				"AC2 requires every exclusion be named: "+record.Path)
		}
		seen[record.Path] = true
	}
	for _, record := range inventory.Selected {
		if seen[record.Path] {
			report.add(FindingPartitionIncomplete, SurfaceInventoryDocument, "$.selected",
				record.Path+" appears in both partitions")
		}
		seen[record.Path] = true
	}
	total := len(inventory.Selected) + len(inventory.Excluded)
	if total != manifest.Reconciliation.ProductionTree.Files {
		report.add(FindingPartitionIncomplete, SurfaceInventoryDocument, "$",
			fmt.Sprintf("partition covers %d files, production tree has %d",
				total, manifest.Reconciliation.ProductionTree.Files))
	}
	if len(seen) != total {
		report.add(FindingPartitionIncomplete, SurfaceInventoryDocument, "$",
			"partition contains duplicate paths")
	}
	// The rule recorded in the document must actually produce the recorded partition.
	all := make([]string, 0, total)
	for _, record := range inventory.Selected {
		all = append(all, record.Path)
	}
	for _, record := range inventory.Excluded {
		all = append(all, record.Path)
	}
	sort.Strings(all)
	recomputed := SelectStudySurface(all)
	if len(recomputed.Selected) != len(inventory.Selected) {
		report.add(FindingPartitionIncomplete, SurfaceInventoryDocument, "$.selected",
			fmt.Sprintf("the recorded selection rule yields %d files, the document lists %d",
				len(recomputed.Selected), len(inventory.Selected)))
	}
}

func (report *Report) checkMigration(
	migration *MigrationMap,
	manifest *IntakeManifest,
	dossier *SeamDossier,
	root string,
) {
	report.MigrationRows = len(migration.Rows)
	report.RustWorkspacePresent = rustWorkspacePresent(root)

	knownStories := map[string]bool{}
	for _, story := range dossier.ImplementationStories {
		knownStories[story.StoryID] = true
	}

	if migration.JavaIdentityMethod.Strength != "semantic" {
		report.add(FindingWeakLookupStrength, MigrationMapDocument, "$.java_identity_method.strength",
			"Java identity must be compiler-derived, not static or grep lookup")
	}
	if migration.RustIdentityStatus.WorkspacePresent != report.RustWorkspacePresent {
		report.add(FindingUnverifiableRustIdentity, MigrationMapDocument,
			"$.rust_identity_status.rust_workspace_present",
			"declared Rust workspace presence disagrees with the repository")
	}

	boundFacets := map[string]bool{}
	for index, row := range migration.Rows {
		path := fmt.Sprintf("$.rows[%d]", index)
		complete := row.ID != "" && row.JavaSemanticID != "" && row.JavaSignature != "" &&
			row.JavaBinaryName != "" && row.JavaDescriptor != "" && row.RustSemanticID != "" &&
			row.SourceRevision != "" && row.DetectionQuery != "" && row.Status != "" &&
			len(row.PortSlices) > 0 &&
			len(row.ApplicabilityConditions) > 0 && len(row.KnownNonEquivalentCases) > 0 &&
			len(row.TouchedFiles) > 0 && len(row.SpecificationIDs) > 0 &&
			len(row.ObservedBehaviorIDs) > 0 && len(row.OracleIDs) > 0 &&
			len(row.VectorIDs) > 0 && len(row.PropertyClaimIDs) > 0 &&
			len(row.FormalClaimIDs) > 0 && len(row.EvidenceIDs) > 0
		if !complete {
			report.add(FindingIncompleteMigrationRow, MigrationMapDocument, path,
				"row is missing a required semantic, provenance, slice, or evidence binding")
		}
		if row.JavaLookupStrength != "semantic" {
			report.add(FindingWeakLookupStrength, MigrationMapDocument, path+".java_lookup_strength",
				"static or grep lookup cannot establish this row's identity")
		}
		if row.RustResolver != "rust-analyzer" && row.RustResolver != "reviewed-glancer" {
			report.add(FindingIncompleteMigrationRow, MigrationMapDocument, path+".rust_resolver",
				"rust_resolver must name the planned resolver")
		}
		if row.RustIdentityVerified {
			report.VerifiedRustIdentities++
			if !report.RustWorkspacePresent {
				report.add(FindingUnverifiableRustIdentity, MigrationMapDocument,
					path+".rust_identity_verified",
					"no Rust workspace exists, so no Rust identity can be resolver-verified")
			}
		}
		bindingsSound := len(row.PortSlices) > 0
		for bindingIndex, binding := range row.PortSlices {
			bindingPath := fmt.Sprintf("%s.port_slices[%d]", path, bindingIndex)
			slice, known := sliceByID(binding.PortSliceID)
			if !known {
				report.add(FindingIncompleteMigrationRow, MigrationMapDocument,
					bindingPath+".port_slice_id",
					binding.PortSliceID+" is not a declared port slice")
				bindingsSound = false
				continue
			}
			if binding.ChildStoryID != slice.ChildStoryID {
				report.add(FindingUnknownChildStory, MigrationMapDocument,
					bindingPath+".child_story_id",
					fmt.Sprintf("%s is owned by %s, binding names %s",
						binding.PortSliceID, slice.ChildStoryID, binding.ChildStoryID))
				bindingsSound = false
			}
			if !knownStories[binding.ChildStoryID] {
				report.add(FindingUnknownChildStory, MigrationMapDocument,
					bindingPath+".child_story_id",
					binding.ChildStoryID+" is not an implementation story in the seam dossier")
				bindingsSound = false
			}
			if strings.TrimSpace(binding.TouchedBehavior) == "" {
				report.add(FindingIncompleteMigrationRow, MigrationMapDocument,
					bindingPath+".touched_behavior",
					"every slice binding must name the behavior that slice touches")
				bindingsSound = false
			}
			if len(binding.EvidenceIDs) == 0 {
				report.add(FindingIncompleteMigrationRow, MigrationMapDocument,
					bindingPath+".evidence_ids",
					"every slice binding must carry an evidence obligation")
				bindingsSound = false
			}
			boundFacets[row.JavaBinaryName+"@"+binding.PortSliceID] = true
		}
		if !complete || !bindingsSound {
			report.UnmappedSemanticItems = append(report.UnmappedSemanticItems, row.JavaSemanticID)
			continue
		}
		report.TraceableSemanticItems++
	}

	// Review B2: every implementation story's frozen behavioral surface must keep a covering
	// binding in the migration map and (for adapter files) in the dossier's touched surface,
	// regardless of what the dossier claims about itself.
	touchedByStory := map[string]map[string]bool{}
	for _, seam := range dossier.Seams {
		files := touchedByStory[seam.ChildStoryID]
		if files == nil {
			files = map[string]bool{}
			touchedByStory[seam.ChildStoryID] = files
		}
		for _, file := range seam.TouchedFiles {
			files[file] = true
		}
	}
	for _, requirement := range RequiredStoryCoverage {
		if requirement.JavaBinaryName != "" {
			if !boundFacets[requirement.JavaBinaryName+"@"+requirement.PortSliceID] {
				report.add(FindingStoryCoverageGap, MigrationMapDocument, "$.rows",
					fmt.Sprintf("%s requires %s bound to %s (%s); no covering binding exists",
						requirement.ChildStoryID, requirement.JavaBinaryName,
						requirement.PortSliceID, requirement.Reason))
			}
			continue
		}
		if !touchedByStory[requirement.ChildStoryID][requirement.TouchedFile] {
			report.add(FindingStoryCoverageGap, SeamDossierDocument, "$.seams",
				fmt.Sprintf("%s requires touched file %s (%s); no seam covers it",
					requirement.ChildStoryID, requirement.TouchedFile, requirement.Reason))
		}
	}

	if manifest.Reconciliation.DeclarationTotals.StudyTypes != len(migration.Rows) {
		report.add(FindingIncompleteMigrationRow, MigrationMapDocument, "$.rows",
			fmt.Sprintf("%d rows for %d in-scope semantic types",
				len(migration.Rows), manifest.Reconciliation.DeclarationTotals.StudyTypes))
	}
}

func (report *Report) checkDossier(dossier *SeamDossier, raw map[string]interface{}) {
	for _, category := range RequiredSeamCategories {
		value, present := raw[category]
		if !present {
			report.add(FindingSeamCategoryMissing, SeamDossierDocument, "$."+category,
				"AC4 requires the "+category+" boundary category be inventoried")
			continue
		}
		entries, ok := value.([]interface{})
		if !ok || len(entries) == 0 {
			report.add(FindingSeamCategoryMissing, SeamDossierDocument, "$."+category,
				"category must be a non-empty inventory")
		}
	}

	seamsByID := map[string]Seam{}
	for index, seam := range dossier.Seams {
		path := fmt.Sprintf("$.seams[%d]", index)
		seamsByID[seam.SurfaceID] = seam
		if len(seam.TouchedFiles) == 0 {
			report.add(FindingUnresolvedTouchedSurface, SeamDossierDocument, path+".touched_files",
				seam.SurfaceID+" has an unresolved touched surface")
		}
		if len(seam.EvidenceObligationIDs) == 0 {
			report.add(FindingUnresolvedTouchedSurface, SeamDossierDocument, path,
				seam.SurfaceID+" carries no evidence obligation")
		}
		if seam.Status != "RESOLVED" {
			report.add(FindingUnresolvedTouchedSurface, SeamDossierDocument, path+".status",
				seam.SurfaceID+" is not resolved")
		}
	}

	for _, story := range dossier.ImplementationStories {
		report.ImplementationStories = append(report.ImplementationStories, story.StoryID)
		unresolved := len(story.SeamIDs) == 0
		for _, seamID := range story.SeamIDs {
			seam, present := seamsByID[seamID]
			if !present || len(seam.TouchedFiles) == 0 || seam.Status != "RESOLVED" {
				unresolved = true
			}
		}
		if unresolved {
			report.UnresolvedStories = append(report.UnresolvedStories, story.StoryID)
			report.add(FindingUnresolvedTouchedSurface, SeamDossierDocument,
				"$.implementation_stories", story.StoryID+" has an unresolved touched surface")
		}
	}
	sort.Strings(report.ImplementationStories)
	sort.Strings(report.UnresolvedStories)
}

func (report *Report) checkCompatibility(compatibility *CompatibilitySurface) {
	boundary := compatibility.PreservedBoundary
	report.WireBoundaryPreserved = boundary.Standard == "RFC 6455" &&
		boundary.NormativeArtifactID != "" && boundary.NormativeArtifactSHA256 != "" &&
		boundary.NormalizedCommandEventBehavior && boundary.WireOctetEquivalenceRequired
	if !report.WireBoundaryPreserved {
		report.add(FindingWireBoundaryNotPreserved, CompatibilityDocument, "$.preserved_boundary",
			"AC5 requires the RFC 6455 wire boundary and normalized command/event behavior")
	}
	declared := map[string]bool{}
	for _, record := range compatibility.ExcludedSurfaces {
		declared[record.Code] = true
	}
	for _, code := range RequiredExclusions {
		if !declared[code] {
			report.add(FindingRequiredExclusionMissing, CompatibilityDocument,
				"$.excluded_surfaces", code+" must be explicitly excluded")
		}
	}
	for index, item := range compatibility.Items {
		path := fmt.Sprintf("$.items[%d]", index)
		if len(item.EvidenceObligationIDs) == 0 || item.CutoverObligationID == "" {
			report.add(FindingUnresolvedTouchedSurface, CompatibilityDocument, path,
				item.SurfaceID+" carries no evidence or cutover obligation")
		}
		if item.ObservationStatus == "OBSERVED" && item.BlockerCode != "" {
			report.add(FindingWireBoundaryNotPreserved, CompatibilityDocument, path,
				"an OBSERVED surface must not carry a blocker code")
		}
	}
}

func (report *Report) checkCutover(cutover *CutoverContract) {
	declared := map[string]bool{}
	for _, record := range cutover.ExcludedBehaviors {
		if strings.TrimSpace(record.Reason) == "" {
			report.add(FindingExclusionNotNamed, CutoverDocument, "$.excluded_behaviors",
				record.Code+" must carry a reason")
		}
		declared[record.Code] = true
	}
	for _, code := range RequiredExclusions {
		if !declared[code] {
			report.add(FindingRequiredExclusionMissing, CutoverDocument, "$.excluded_behaviors",
				code+" must be explicitly excluded")
		}
		report.DeclaredExclusions[code] = declared[code]
	}
	if len(cutover.UnresolvedBehaviors) != 0 {
		report.add(FindingUnresolvedBehavior, CutoverDocument, "$.unresolved_behaviors",
			"the cutover contract may not carry unresolved behaviors")
	}
	if len(cutover.ReadinessLadder) != len(ReadinessLadder) {
		report.add(FindingUnresolvedBehavior, CutoverDocument, "$.readiness_ladder",
			"the inherited readiness ladder must be preserved verbatim")
	} else {
		for index, step := range ReadinessLadder {
			if cutover.ReadinessLadder[index] != step {
				report.add(FindingUnresolvedBehavior, CutoverDocument, "$.readiness_ladder",
					"the inherited readiness ladder must be preserved verbatim")
				break
			}
		}
	}
	boundary := cutover.PreservedBoundary
	if boundary.Standard != "RFC 6455" || !boundary.WireOctetEquivalenceRequired {
		report.add(FindingWireBoundaryNotPreserved, CutoverDocument, "$.preserved_boundary",
			"the cutover contract must preserve the RFC 6455 wire boundary")
	}
	for index, obligation := range cutover.Obligations {
		path := fmt.Sprintf("$.obligations[%d]", index)
		if obligation.Status == "DECLARED" && len(obligation.EvidenceIDs) != 0 {
			report.add(FindingUnresolvedBehavior, CutoverDocument, path,
				"a DECLARED obligation must not cite evidence")
		}
		if obligation.Status == "SATISFIED" && len(obligation.EvidenceIDs) == 0 {
			report.add(FindingUnresolvedBehavior, CutoverDocument, path,
				"a SATISFIED obligation must cite evidence")
		}
	}
}

// checkOracleBinding binds the manifest's recorded oracle digest and derived totals to the
// committed oracle report itself, so neither can drift from the other unnoticed.
func (report *Report) checkOracleBinding(root string, manifest *IntakeManifest) {
	oraclePath := filepath.Join(root, EvidenceDirectory, OracleEvidenceDocument)
	digest, err := FileDigest(oraclePath)
	if err != nil {
		report.add(FindingOracleBindingBroken, ManifestDocument, "$.jdk.oracle_output_sha256",
			"committed oracle report unreadable: "+err.Error())
		return
	}
	if digest != manifest.JDK.OracleOutputSHA {
		report.add(FindingOracleBindingBroken, ManifestDocument, "$.jdk.oracle_output_sha256",
			fmt.Sprintf("manifest records %s, committed oracle is %s",
				manifest.JDK.OracleOutputSHA, digest))
		return
	}
	oracle, _, err := LoadOracle(oraclePath)
	if err != nil {
		report.add(FindingOracleBindingBroken, ManifestDocument, "$.jdk",
			"committed oracle report invalid: "+err.Error())
		return
	}
	reconciliation := manifest.Reconciliation
	if oracle.Totals.Files != reconciliation.ProductionTree.Files ||
		oracle.Totals.PhysicalLines != reconciliation.ProductionTree.PhysicalLines ||
		oracle.Totals.StudySurfaceFiles != reconciliation.StudySurface.Files ||
		oracle.Totals.StudySurfacePhysicalLines != reconciliation.StudySurface.PhysicalLines ||
		oracle.Totals.Declarations != reconciliation.DeclarationTotals.ProductionDeclarations {
		report.add(FindingOracleBindingBroken, ManifestDocument, "$.reconciliation",
			"manifest totals disagree with the committed oracle report")
	}
}

// checkPromotedInputs enforces the SLF4J identity binding (review B4): the manifest must record
// the compile-classpath jar as a promoted input whose digest equals the US-002-qualified digest.
func (report *Report) checkPromotedInputs(manifest *IntakeManifest) {
	for _, input := range manifest.PromotedInputs {
		if input.ArtifactID != "slf4j-api-2.0.13" {
			continue
		}
		if input.SHA256 != SLF4JAPIJarSHA256 {
			report.add(FindingPromotedInputUnbound, ManifestDocument, "$.promoted_inputs",
				fmt.Sprintf("slf4j-api-2.0.13 records %s, the US-002-qualified digest is %s",
					input.SHA256, SLF4JAPIJarSHA256))
		}
		if input.QualifiedBy != "US-002" || strings.TrimSpace(input.EnforcedBy) == "" {
			report.add(FindingPromotedInputUnbound, ManifestDocument, "$.promoted_inputs",
				"the SLF4J binding must cite its qualifying story and its enforcement point")
		}
		return
	}
	report.add(FindingPromotedInputUnbound, ManifestDocument, "$.promoted_inputs",
		"the SLF4J compile input must be recorded as a promoted input")
}

// rustWorkspacePresent reports whether a Rust workspace exists yet. US-009 creates it; until then
// no Rust identity in the migration map may claim resolver verification.
func rustWorkspacePresent(root string) bool {
	for _, candidate := range []string{"Cargo.toml", "rust/Cargo.toml", "crates/Cargo.toml"} {
		if _, err := os.Stat(filepath.Join(root, candidate)); err == nil {
			return true
		}
	}
	return false
}
