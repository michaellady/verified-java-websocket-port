package formalcoverage

import (
	"fmt"
	"sort"
	"strings"
)

// Axis ids. AC3 names the axes a US-023 formal-coverage report must expose;
// these are those axes, split where one AC3 word covers two different questions
// that must not be added together (production linkage on the Java side and on
// the Rust side are not the same fact, and counterexample sensitivity on one
// side says nothing about the other).
const (
	AxisJavaCoverage       = "java_coverage"
	AxisRustCoverage       = "rust_coverage"
	AxisPairedComparable   = "paired_comparable_coverage"
	AxisLinkageJava        = "production_linkage_java"
	AxisLinkageRust        = "production_linkage_rust"
	AxisRefinement         = "refinement_coverage"
	AxisBoundParity        = "bound_parity"
	AxisCounterexampleJava = "counterexample_sensitivity_java"
	AxisCounterexampleRust = "counterexample_sensitivity_rust"
	AxisAggregate          = "aggregate"
)

// Blocking reason codes. Every one names a specific missing thing; none is a
// catch-all, because a catch-all is how a blocking gap becomes a footnote.
const (
	BlockJavaBelowRequired   = "JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH"
	BlockRustBelowRequired   = "RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH"
	BlockRustNotExecuted     = "RUST_EVIDENCE_NOT_EXECUTED"
	BlockRefinementMissing   = "REFINEMENT_LINK_DISCONNECTED"
	BlockLinkageJavaMissing  = "JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION"
	BlockLinkageRustMissing  = "RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL"
	// These two are OBSERVATIONS ABOUT THIS TREE, and their names now say so.
	// They used to read CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE and
	// CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE, which were true of this
	// tree and false as stated: the path exists in the tree the catalog is
	// about, and the namespace names a crate that tree ships. A reason code
	// that indicts a document for a lookup performed against the wrong subject
	// is absence standing in for defect, and it is the more damaging direction
	// of the error because it blames someone else's correct work.
	BlockRustPathAbsent      = "CATALOG_RUST_SOURCE_PATH_ABSENT_FROM_THIS_PLANE"
	BlockRustNamespaceAbsent = "CATALOG_RUST_NAMESPACE_NAMES_NO_CRATE_SHIPPED_BY_THIS_PLANE"
	// This is the CAUSE the two above are symptoms of, and it blocks in its own
	// right. It is derived from the plane-correspondence record, never asserted:
	// the record must name every catalog namespace, path and symbol, and a row
	// may only reach ESTABLISHED_BY_OWNER_DECISION by producing a decision in
	// the protected store.
	BlockPlaneNotEstablished = "CATALOG_IS_ABOUT_ANOTHER_PLANE_AND_NO_CORRESPONDENCE_TO_THIS_ONE_IS_ESTABLISHED"
	BlockBoundsNotComparable = "DECLARED_BOUNDS_ARE_NOT_COMPARABLE"
	BlockCounterexampleJava  = "NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY"
	BlockCounterexampleRust  = "NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT"
	BlockCatalogSymbolDefect = "CATALOG_DECLARES_A_JAVA_SYMBOL_THAT_CANNOT_CARRY_THE_OBLIGATION"
	BlockNoProofTarget       = "OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET"
)

// AxisResult is one axis's verdict. It always publishes its MEMBERS, not only
// its numerator: a numerator alone is exactly the shape in which a blocking
// obligation disappears.
type AxisResult struct {
	Axis                string   `json:"axis"`
	Definition          string   `json:"definition"`
	IsCoverage          bool     `json:"is_coverage"`
	FeedsAggregate      bool     `json:"feeds_aggregate"`
	Weighting           string   `json:"weighting"`
	Numerator           int      `json:"numerator"`
	Denominator         int      `json:"denominator"`
	CountedObligations  []string `json:"counted_obligations"`
	BlockingObligations []string `json:"blocking_obligations"`
	Note                string   `json:"note,omitempty"`
}

// SideEvidence is one language side's evidence for one obligation.
type SideEvidence struct {
	CatalogSymbol       string   `json:"catalog_production_symbol"`
	CatalogSourcePath   string   `json:"catalog_source_path"`
	Method              string   `json:"method"`
	ExecutionState      string   `json:"execution_state"`
	ObservedStrength    string   `json:"observed_strength"`
	MeetsRequired       bool     `json:"meets_required_strength"`
	ProductionLinkage   string   `json:"production_linkage"`
	LinkageDetail       string   `json:"linkage_detail"`
	BoundsDeclared      bool     `json:"bounds_declared"`
	BoundsDescription   string   `json:"bounds_description"`
	CounterexampleState string   `json:"counterexample_sensitivity"`
	Notes               []string `json:"notes,omitempty"`
}

// ObligationReport is one row of the report, over the fixed denominator.
type ObligationReport struct {
	ObligationID     string       `json:"obligation_id"`
	Statement        string       `json:"statement"`
	SurfaceIDs       []string     `json:"surface_ids"`
	RequiredStrength string       `json:"required_strength"`
	RequiredMethods  []string     `json:"allowed_methods"`
	Java             SideEvidence `json:"java"`
	Rust             SideEvidence `json:"rust"`
	RefinementState  string       `json:"refinement_state"`
	BoundParity      string       `json:"bound_parity"`
	ProofTargetIDs   []string     `json:"proof_target_ids"`
	CorrectionID     string       `json:"catalog_correction_proposal_id,omitempty"`
	Blocking         bool         `json:"blocking"`
	BlockingReasons  []string     `json:"blocking_reasons"`
}

// BlockingGap is one blocking obligation, restated as its own row so the list
// of gaps can be read without reconstructing it from the obligation table.
type BlockingGap struct {
	ObligationID string   `json:"obligation_id"`
	Statement    string   `json:"statement"`
	Reasons      []string `json:"reasons"`
}

// Invariant is one mechanically enforced no-hiding rule.
type Invariant struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	Holds     bool   `json:"holds"`
	Detail    string `json:"detail,omitempty"`
}

// ResolverCeiling is the honest ceiling on every claim that formal evidence in
// this repository reaches shipped Rust.
type ResolverCeiling struct {
	State                          string `json:"proof_target_resolver_state"`
	PlannedResolver                string `json:"planned_resolver"`
	ResolverVerifiedAt             string `json:"resolver_verified_at"`
	PlannedProductionSymbols       int    `json:"planned_production_symbols"`
	PlannedSymbolsResolverVerified int    `json:"planned_symbols_resolver_verified"`
	MigrationBindings              int    `json:"migration_bindings"`
	MigrationBindingsVerified      int    `json:"migration_bindings_rust_identity_verified"`
	StrongestOverlayPath           string `json:"strongest_linkage_overlay"`
	StrongestOverlayMethod         string `json:"strongest_linkage_overlay_method"`
	StrongestOverlayStrength       string `json:"strongest_linkage_overlay_strength"`
	OverlayRowsTotal               int    `json:"overlay_rows_total"`
	OverlayRowsVerified            int    `json:"overlay_rows_verified"`
	ObligationsOnResolverVerified  int    `json:"obligations_bound_to_a_resolver_verified_rust_symbol"`
	Denominator                    int    `json:"denominator"`
	Statement                      string `json:"statement"`
}

// FreezeVerdict is the AC3 decision this report exists to make.
type FreezeVerdict struct {
	Verdict               string   `json:"verdict"`
	BlockingObligations   int      `json:"blocking_obligations"`
	Denominator           int      `json:"denominator"`
	Rule                  string   `json:"rule"`
	BlockingObligationIDs []string `json:"blocking_obligation_ids"`
}

// DenominatorSummary is the reconciliation, restated in the report so a reader
// of the report alone knows which denominator the numbers are over.
type DenominatorSummary struct {
	CatalogObligations        int              `json:"catalog_obligations"`
	ProofTargets              int              `json:"proof_targets"`
	ObligationsWithNoTarget   int              `json:"obligations_with_no_proof_target"`
	TargetsWithNoObligation   int              `json:"targets_named_by_no_obligation"`
	ObligationIDsWithNoTarget []string         `json:"obligation_ids_with_no_proof_target"`
	TargetIDsWithNoObligation []string         `json:"target_ids_named_by_no_obligation"`
	RustBindingRowsPathAbsent int              `json:"catalog_rust_binding_rows_whose_source_path_is_absent"`
	RustRowsMeasurableHere    int              `json:"catalog_rust_binding_rows_measurable_on_this_plane"`
	PlaneRecord               ArtifactIdentity `json:"plane_correspondence"`
	Reconciliation            ArtifactIdentity `json:"reconciliation"`
}

// Report is the canonical machine-readable US-023 AC3 formal-coverage report.
type Report struct {
	SchemaVersion   string             `json:"schema_version"`
	ReportID        string             `json:"report_id"`
	EntityType      string             `json:"entity_type"`
	StoryID         string             `json:"story_id"`
	AcceptanceRef   string             `json:"acceptance_criterion"`
	Statement       string             `json:"statement"`
	Assurance       Assurance          `json:"assurance"`
	Inputs          []ArtifactIdentity `json:"inputs"`
	Denominator     DenominatorSummary `json:"denominator"`
	Axes            []AxisResult       `json:"axes"`
	Obligations     []ObligationReport `json:"obligations"`
	BlockingGaps    []BlockingGap      `json:"blocking_gaps"`
	NoHidingRule    string             `json:"no_hiding_rule"`
	Invariants      []Invariant        `json:"no_hiding_invariants"`
	ResolverCeiling ResolverCeiling    `json:"resolver_ceiling"`
	CatalogDefects  []CatalogDefectRow `json:"catalog_denominator_defects"`
	PlaneMismatches []PlaneMismatchRow `json:"plane_mismatches"`
	Freeze          FreezeVerdict      `json:"freeze"`
	NotClaims       []string           `json:"not_claims"`
}

// CatalogDefectRow names one defect IN THE DENOMINATOR ITSELF, so that a
// reader cannot mistake a defective denominator for a merely uncovered one.
type CatalogDefectRow struct {
	ObligationID string `json:"obligation_id"`
	Side         string `json:"side"`
	DefectClass  string `json:"defect_class"`
	Detail       string `json:"detail"`
	CorrectionID string `json:"correction_proposal_id,omitempty"`
}

// PlaneMismatchRow is one catalog Rust row that does not resolve on THIS plane,
// stated as a mismatch between planes rather than as a defect in the catalog.
// The distinction is the whole point of the type: a defect is something to
// repair in the document, a mismatch is a question about which tree the
// document is being read against, and only the second one is true here.
type PlaneMismatchRow struct {
	ObligationCount         int    `json:"obligation_count"`
	CatalogSourcePath       string `json:"catalog_source_path"`
	CatalogNamespace        string `json:"catalog_namespace"`
	PathState               string `json:"path_state_on_this_plane"`
	NamespaceState          string `json:"namespace_state_on_this_plane"`
	PathCorrespondence      string `json:"path_correspondence_state"`
	NamespaceCorrespondence string `json:"namespace_correspondence_state"`
	Detail                  string `json:"detail"`
}

// DeriveReport recomputes the whole report from the artifacts on disk. It is
// the only place these numbers are produced, and it refuses to return a report
// whose no-hiding invariants do not all hold.
func DeriveReport(root string) (Report, error) {
	reconciliation, err := Reconcile(root)
	if err != nil {
		return Report{}, err
	}
	reconciliationIdentity := ArtifactIdentity{Path: ReconciliationPath}
	if encoded, marshalErr := MarshalArtifact(reconciliation); marshalErr == nil {
		reconciliationIdentity.SHA256 = Digest(encoded)
		reconciliationIdentity.GitBlob = GitBlobID(encoded)
	}

	catalogBytes, catalogIdentity, err := LoadArtifact(root, CatalogPath)
	if err != nil {
		return Report{}, err
	}
	catalog, err := DecodeCatalog(catalogBytes)
	if err != nil {
		return Report{}, err
	}
	planBytes, planIdentity, err := LoadArtifact(root, ProofTargetsPath)
	if err != nil {
		return Report{}, err
	}
	plan, err := DecodeProofTargets(planBytes)
	if err != nil {
		return Report{}, err
	}
	projectionBytes, projectionIdentity, err := LoadArtifact(root, ProjectionPath)
	if err != nil {
		return Report{}, err
	}
	projection, err := DecodeJavaProjection(projectionBytes)
	if err != nil {
		return Report{}, err
	}
	if projection.Catalog.SHA256 != catalogIdentity.SHA256 {
		return Report{}, fmt.Errorf("formalcoverage: the Java projection was derived against catalog %s, not the catalog on disk %s",
			projection.Catalog.SHA256, catalogIdentity.SHA256)
	}
	specBytes, specIdentity, err := LoadArtifact(root, BindingSpecPath)
	if err != nil {
		return Report{}, err
	}
	spec, err := DecodeBindingSpec(specBytes)
	if err != nil {
		return Report{}, err
	}
	linkageBytes, linkageIdentity, err := LoadArtifact(root, LinkagePath)
	if err != nil {
		return Report{}, err
	}
	linkage, err := DecodeLinkage(linkageBytes)
	if err != nil {
		return Report{}, err
	}
	correctionFindings, proposal, err := VerifyCorrections(root)
	if err != nil {
		return Report{}, err
	}
	if len(correctionFindings) > 0 {
		return Report{}, fmt.Errorf("formalcoverage: the catalog correction proposal does not check out (%d findings, first: %s/%s: %s)",
			len(correctionFindings), correctionFindings[0].CorrectionID, correctionFindings[0].Check, correctionFindings[0].Detail)
	}
	_, correctionIdentity, err := LoadArtifact(root, CorrectionPath)
	if err != nil {
		return Report{}, err
	}

	correctionByObligation := map[string]Correction{}
	for _, correction := range proposal.Corrections {
		correctionByObligation[correction.ObligationID] = correction
	}
	mappingByObligation := map[string]ObligationMapping{}
	for _, row := range reconciliation.Obligations {
		mappingByObligation[row.ObligationID] = row
	}
	rustCheckByPath := map[string]RustBindingCheck{}
	for _, check := range reconciliation.RustBindingCheck {
		rustCheckByPath[check.SourcePath] = check
	}

	// ---- per-obligation rows -------------------------------------------
	rows := make([]ObligationReport, 0, CatalogDenominator)
	for _, obligation := range catalog.Obligations {
		row := ObligationReport{
			ObligationID:     obligation.ObligationID,
			Statement:        obligation.Statement,
			SurfaceIDs:       append([]string(nil), obligation.SurfaceIDs...),
			RequiredStrength: obligation.RequiredStrength,
			RequiredMethods:  append([]string(nil), obligation.AllowedMethods...),
		}
		mapping := mappingByObligation[obligation.ObligationID]
		row.ProofTargetIDs = append([]string(nil), mapping.TargetIDs...)
		if correction, ok := correctionByObligation[obligation.ObligationID]; ok {
			row.CorrectionID = correction.CorrectionID
		}

		// --- Java side, quoted from internal/javabind's projection --------
		javaBinding, _ := catalog.JavaBinding(obligation.ObligationID)
		projectionRow, ok := projection.Row(obligation.ObligationID)
		if !ok {
			return Report{}, fmt.Errorf("formalcoverage: the Java projection has no row for %q", obligation.ObligationID)
		}
		observed := projectionRow.ObservedStrength
		if observed == "" {
			observed = "NONE"
		}
		javaMeets, err := MeetsRequired(observed, obligation.RequiredStrength)
		if err != nil {
			return Report{}, err
		}
		if javaMeets != projectionRow.MeetsRequired {
			return Report{}, fmt.Errorf("formalcoverage: this report derives meets_required=%t for %q on the Java side but the retained projection says %t",
				javaMeets, obligation.ObligationID, projectionRow.MeetsRequired)
		}
		scenarioIDs, scenarioLimits := spec.ScenarioLimitsFor(obligation.ObligationID)
		row.Java = SideEvidence{
			CatalogSymbol:     javaBinding.ProductionSymbol,
			CatalogSourcePath: javaBinding.SourcePath,
			Method:            "EXECUTED_OBSERVATION_OF_THE_PINNED_RUNTIME",
			ExecutionState:    "EXECUTED",
			ObservedStrength:  observed,
			MeetsRequired:     javaMeets,
			BoundsDeclared:    len(scenarioIDs) > 0,
			BoundsDescription: describeScenarioBounds(scenarioIDs, scenarioLimits),
		}
		if projectionRow.SpanSHA256 != "" {
			row.Java.ProductionLinkage = "BOUND_TO_A_DIGESTED_DECLARATION_SPAN_IN_THE_PINNED_SOURCE"
			row.Java.LinkageDetail = fmt.Sprintf("%s span %s, descriptor agreement %s, binding state %s",
				projectionRow.SourceFile, projectionRow.SpanSHA256, projectionRow.DescriptorAgreement, projectionRow.BindingState)
		} else {
			row.Java.ProductionLinkage = "NOT_BOUND"
			row.Java.LinkageDetail = fmt.Sprintf("binding state %s, reason %s", projectionRow.BindingState, projectionRow.ReasonCode)
			row.Java.Method = "NOT_OBSERVED"
			row.Java.ExecutionState = "NOT_EXECUTED"
		}
		if projectionRow.CanariesKilled > 0 {
			row.Java.CounterexampleState = "OBLIGATION_SPECIFIC_CANARY_KILLED_INSIDE_THE_BOUND_SPAN"
		} else {
			row.Java.CounterexampleState = "NONE"
		}
		if projectionRow.ReasonCode != "" {
			row.Java.Notes = append(row.Java.Notes, "unbound reason "+projectionRow.ReasonCode)
		}
		if projectionRow.BindingState == "PARTIAL" {
			row.Java.Notes = append(row.Java.Notes, fmt.Sprintf(
				"PARTIAL: %d of %d clauses satisfied; a partial binding is never folded into a coverage numerator",
				projectionRow.ClausesSatisfied, projectionRow.ClausesDeclared))
		}

		// --- Rust side, quoted from the catalog's own evidence row --------
		rustBinding, _ := catalog.RustBinding(obligation.ObligationID)
		evidence, ok := catalog.EvidenceFor(obligation.ObligationID)
		if !ok {
			return Report{}, fmt.Errorf("formalcoverage: the catalog has no evidence row for %q", obligation.ObligationID)
		}
		rustMeets, err := MeetsRequired(evidence.ObservedStrength, obligation.RequiredStrength)
		if err != nil {
			return Report{}, err
		}
		rustCheck := rustCheckByPath[rustBinding.SourcePath]
		row.Rust = SideEvidence{
			CatalogSymbol:     rustBinding.ProductionSymbol,
			CatalogSourcePath: rustBinding.SourcePath,
			Method:            evidence.Method,
			ExecutionState:    evidence.ExecutionState,
			ObservedStrength:  evidence.ObservedStrength,
			MeetsRequired:     rustMeets,
			LinkageDetail: fmt.Sprintf(
				"catalog connection state %s; declared source path %s (%s, correspondence %s); namespace root %s (%s, correspondence %s); tool %s %s",
				rustBinding.ConnectionState, rustBinding.SourcePath, rustCheck.PathState, rustCheck.PathCorrespondence,
				rustCheck.NamespaceRoot, rustCheck.NamespaceState, rustCheck.NamespaceCorrespondence,
				evidence.Tool.Name, evidence.Tool.Version),
			BoundsDeclared:    evidence.Bounds.MaxFrameBytes != nil || evidence.Bounds.MaxSteps != nil,
			BoundsDescription: describeCatalogBounds(evidence.Bounds),
		}
		// Rust production linkage is derived from two inputs, never asserted:
		// the catalog must call the binding CONNECTED, AND the proof-target plan
		// must record that a resolver actually ran. Either alone is a name.
		row.Rust.ProductionLinkage = "NOT_BOUND"
		if rustBinding.ConnectionState == "CONNECTED" && plan.RustIdentityResolution.ResolverVerifiedAt != nil {
			row.Rust.ProductionLinkage = "BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL"
		}
		row.Rust.CounterexampleState = "NONE"
		for _, sensitivity := range evidence.MutationSensitivity {
			// "Killed by a DIFFERENT subject" is not sensitivity for THIS
			// obligation. Counting it would be the purest form of the round-up
			// this report exists to prevent.
			if sensitivity.Disposition == "RETAINED_KILLED_OBLIGATION_SPECIFIC" {
				row.Rust.CounterexampleState = "OBLIGATION_SPECIFIC_MUTANT_KILLED"
			}
			row.Rust.Notes = append(row.Rust.Notes, fmt.Sprintf("mutant %s: %s", sensitivity.MutantID, sensitivity.Disposition))
		}
		row.RefinementState = evidence.Refinement.State

		// --- bound parity -------------------------------------------------
		switch {
		case row.Java.BoundsDeclared && row.Rust.BoundsDeclared:
			row.BoundParity = "BOTH_SIDES_DECLARE_BOUNDS"
		case !row.Java.BoundsDeclared && !row.Rust.BoundsDeclared:
			row.BoundParity = "NEITHER_SIDE_DECLARES_A_BOUND"
		default:
			row.BoundParity = "ONE_SIDE_DECLARES_A_BOUND_AND_THE_OTHER_DOES_NOT"
		}

		// --- blocking reasons, one per specific missing thing --------------
		if !javaMeets {
			row.BlockingReasons = append(row.BlockingReasons, BlockJavaBelowRequired)
		}
		if !rustMeets {
			row.BlockingReasons = append(row.BlockingReasons, BlockRustBelowRequired)
		}
		if evidence.ExecutionState != "EXECUTED" {
			row.BlockingReasons = append(row.BlockingReasons, BlockRustNotExecuted)
		}
		if row.RefinementState != "CONNECTED" {
			row.BlockingReasons = append(row.BlockingReasons, BlockRefinementMissing)
		}
		if row.Java.ProductionLinkage == "NOT_BOUND" {
			row.BlockingReasons = append(row.BlockingReasons, BlockLinkageJavaMissing)
		}
		if row.Rust.ProductionLinkage == "NOT_BOUND" {
			row.BlockingReasons = append(row.BlockingReasons, BlockLinkageRustMissing)
		}
		if rustCheck.PathState == RustPathAbsent {
			row.BlockingReasons = append(row.BlockingReasons, BlockRustPathAbsent)
		}
		if rustCheck.NamespaceState == RustNamespaceDisagrees {
			row.BlockingReasons = append(row.BlockingReasons, BlockRustNamespaceAbsent)
		}
		if !rustCheck.MeasurableHere {
			row.BlockingReasons = append(row.BlockingReasons, BlockPlaneNotEstablished)
		}
		if row.BoundParity != "BOTH_SIDES_DECLARE_BOUNDS" {
			row.BlockingReasons = append(row.BlockingReasons, BlockBoundsNotComparable)
		}
		if row.Java.CounterexampleState == "NONE" {
			row.BlockingReasons = append(row.BlockingReasons, BlockCounterexampleJava)
		}
		if row.Rust.CounterexampleState == "NONE" {
			row.BlockingReasons = append(row.BlockingReasons, BlockCounterexampleRust)
		}
		if _, ok := correctionByObligation[obligation.ObligationID]; ok {
			row.BlockingReasons = append(row.BlockingReasons, BlockCatalogSymbolDefect)
		}
		if mapping.State != MappingMapped {
			row.BlockingReasons = append(row.BlockingReasons, BlockNoProofTarget)
		}
		sort.Strings(row.BlockingReasons)
		row.Blocking = len(row.BlockingReasons) > 0
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ObligationID < rows[j].ObligationID })

	// ---- axes, each derived as an unweighted count of rows ---------------
	axes := []AxisResult{
		axisFrom(AxisJavaCoverage, rows, true, true,
			"Obligations whose JAVA-side evidence reaches the obligation's own required_strength. Java evidence "+
				"below that strength is not counted here and is not counted anywhere else either.",
			func(row ObligationReport) bool { return row.Java.MeetsRequired }, ""),
		axisFrom(AxisRustCoverage, rows, true, true,
			"Obligations whose RUST-side evidence reaches required_strength, read from the immutable catalog's own "+
				"evidence rows.",
			func(row ObligationReport) bool { return row.Rust.MeetsRequired }, ""),
		axisFrom(AxisPairedComparable, rows, true, true,
			"Obligations where BOTH sides reach required_strength AND their declared bounds are comparable. Pairing "+
				"is an intersection, so it can never exceed either side.",
			func(row ObligationReport) bool {
				return row.Java.MeetsRequired && row.Rust.MeetsRequired && row.BoundParity == "BOTH_SIDES_DECLARE_BOUNDS"
			}, ""),
		axisFrom(AxisLinkageJava, rows, false, false,
			"Obligations whose Java evidence is bound to one identified declaration in the digest-pinned Java source, "+
				"recorded as a byte span with its own digest.",
			func(row ObligationReport) bool { return row.Java.ProductionLinkage != "NOT_BOUND" },
			"NOT COVERAGE. Production linkage says an obligation is attached to identified shipped code; it says "+
				"nothing about the strength of the evidence at the other end of that attachment. This numerator is "+
				"non-zero while java_coverage is zero, and the two must never be conflated."),
		axisFrom(AxisLinkageRust, rows, false, false,
			"Obligations whose Rust evidence is bound to a RESOLVER-VERIFIED shipped Rust symbol.",
			func(row ObligationReport) bool { return row.Rust.ProductionLinkage != "NOT_BOUND" },
			"NOT COVERAGE, and zero. No Rust identity in this repository is resolver-verified; see resolver_ceiling."),
		axisFrom(AxisRefinement, rows, true, true,
			"Obligations with a CONNECTED refinement link between the model subject and the shipped symbol.",
			func(row ObligationReport) bool { return row.RefinementState == "CONNECTED" }, ""),
		axisFrom(AxisBoundParity, rows, false, false,
			"Obligations where both sides declare bounds, so that the two sides' results are quoted under comparable "+
				"assumptions.",
			func(row ObligationReport) bool { return row.BoundParity == "BOTH_SIDES_DECLARE_BOUNDS" },
			"NOT COVERAGE. Bound parity is a precondition for comparing two sides, not a measure of either."),
		axisFrom(AxisCounterexampleJava, rows, false, false,
			"Obligations for which at least one obligation-specific Java canary, placed inside the bound declaration's "+
				"own span, flipped a predicate that held on the baseline.",
			func(row ObligationReport) bool { return row.Java.CounterexampleState != "NONE" },
			"NOT COVERAGE. This counts attribution, not satisfaction: an obligation can be mutation-sensitive and "+
				"still PARTIAL or DISCONNECTED."),
		axisFrom(AxisCounterexampleRust, rows, false, false,
			"Obligations for which at least one OBLIGATION-SPECIFIC Rust mutant was killed. Mutants recorded as "+
				"RETAINED_KILLED_DIFFERENT_SUBJECT are deliberately NOT counted: a mutant killed by some other "+
				"obligation's evidence is not sensitivity for this one.",
			func(row ObligationReport) bool { return row.Rust.CounterexampleState != "NONE" },
			"NOT COVERAGE, and zero. All 24 catalog mutation dispositions read RETAINED_KILLED_DIFFERENT_SUBJECT."),
		axisFrom(AxisAggregate, rows, true, false,
			"Obligations satisfying EVERY coverage axis at required strength simultaneously. Derived as the "+
				"intersection of the coverage axes' member sets, never as a weighted sum of their numerators.",
			func(row ObligationReport) bool { return !row.Blocking }, ""),
	}

	// ---- blocking gaps ---------------------------------------------------
	var gaps []BlockingGap
	var blockingIDs []string
	for _, row := range rows {
		if !row.Blocking {
			continue
		}
		gaps = append(gaps, BlockingGap{ObligationID: row.ObligationID, Statement: row.Statement, Reasons: row.BlockingReasons})
		blockingIDs = append(blockingIDs, row.ObligationID)
	}

	// ---- catalog denominator defects ------------------------------------
	var defects []CatalogDefectRow
	for _, row := range rows {
		if correction, ok := correctionByObligation[row.ObligationID]; ok {
			defects = append(defects, CatalogDefectRow{
				ObligationID: row.ObligationID,
				Side:         "JAVA",
				DefectClass:  correction.Current.DefectClass,
				Detail:       correction.Current.WhyWrong,
				CorrectionID: correction.CorrectionID,
			})
		}
	}
	// The Rust rows are deliberately NOT added to the defect list. A path that
	// does not resolve here is a fact about which tree it is being resolved
	// against; filing it as a defect in the catalog is the mistake this report
	// used to make, and it indicted another plane's correct work. They get
	// their own list, with the correspondence evidence attached.
	var mismatches []PlaneMismatchRow
	for _, check := range reconciliation.RustBindingCheck {
		if check.MeasurableHere {
			continue
		}
		mismatches = append(mismatches, PlaneMismatchRow{
			ObligationCount:         check.ObligationCount,
			CatalogSourcePath:       check.SourcePath,
			CatalogNamespace:        check.NamespaceRoot,
			PathState:               check.PathState,
			NamespaceState:          check.NamespaceState,
			PathCorrespondence:      check.PathCorrespondence,
			NamespaceCorrespondence: check.NamespaceCorrespondence,
			Detail: fmt.Sprintf(
				"the catalog names %q in namespace %q; this plane ships the crate namespaces %s and does not hold that path. "+
					"%s records what is known about the two planes: path correspondence %s, namespace correspondence %s. "+
					"Neither is ESTABLISHED_BY_OWNER_DECISION, so these %d obligations are not measurable here.",
				check.SourcePath, check.NamespaceRoot, strings.Join(check.ShippedCrates, ", "),
				PlaneCorrespondencePath, check.PathCorrespondence, check.NamespaceCorrespondence, check.ObligationCount),
		})
	}
	sort.Slice(mismatches, func(i, j int) bool { return mismatches[i].CatalogSourcePath < mismatches[j].CatalogSourcePath })

	// ---- resolver ceiling ------------------------------------------------
	resolverVerifiedAt := "null"
	if plan.RustIdentityResolution.ResolverVerifiedAt != nil {
		resolverVerifiedAt = *plan.RustIdentityResolution.ResolverVerifiedAt
	}
	ceiling := ResolverCeiling{
		State:                          plan.RustIdentityResolution.State,
		PlannedResolver:                plan.RustIdentityResolution.PlannedResolver,
		ResolverVerifiedAt:             resolverVerifiedAt,
		PlannedProductionSymbols:       reconciliation.Counts.PlannedProductionSymbols,
		PlannedSymbolsResolverVerified: reconciliation.Counts.PlannedSymbolsResolverVerified,
		MigrationBindings:              reconciliation.Counts.MigrationBindings,
		MigrationBindingsVerified:      reconciliation.Counts.MigrationBindingsVerified,
		StrongestOverlayPath:           LinkagePath,
		StrongestOverlayMethod:         linkage.Resolver.Method,
		StrongestOverlayStrength:       linkage.Resolver.Strength,
		OverlayRowsTotal:               linkage.Summary.RowsTotal,
		OverlayRowsVerified:            linkage.Summary.Verified,
		Denominator:                    CatalogDenominator,
	}
	for _, axis := range axes {
		if axis.Axis == AxisLinkageRust {
			ceiling.ObligationsOnResolverVerified = axis.Numerator
		}
	}
	ceiling.Statement = fmt.Sprintf(
		"NO formal obligation in this repository binds to a resolver-verified shipped Rust symbol: %d of %d. "+
			"The proof-target plan reads %s with planned_resolver %s and resolver_verified_at %s; all %d planned "+
			"production symbols are PLANNED_PENDING_RESOLVER with resolved_symbol null, and all %d migration bindings "+
			"read rust_identity_verified=false. The strongest linkage evidence this repository holds, %s, resolves "+
			"%d of %d rows by %s and labels its own strength %q. That overlay and the plan do not contradict each "+
			"other and neither overstates itself; the ceiling is the CONJUNCTION of what they honestly say. Every "+
			"claim that formal evidence here reaches shipped Rust code therefore rests on a declaration scan, not on "+
			"semantic resolution, and no coverage percentage in this report may be read as implying otherwise.",
		ceiling.ObligationsOnResolverVerified, CatalogDenominator,
		ceiling.State, ceiling.PlannedResolver, resolverVerifiedAt,
		ceiling.PlannedProductionSymbols, ceiling.MigrationBindings,
		LinkagePath, ceiling.OverlayRowsVerified, ceiling.OverlayRowsTotal,
		linkage.Resolver.Method, linkage.Resolver.Strength)

	report := Report{
		SchemaVersion: "1.0.0",
		ReportID:      "us023-formal-coverage",
		EntityType:    "FormalCoverageReport",
		StoryID:       "US-023",
		AcceptanceRef: "US-023 AC3 — canonical machine-readable formal-coverage report over the immutable " +
			"24-obligation denominator, exposing Java coverage, Rust coverage, paired comparable coverage, " +
			"production linkage, refinement coverage, bound parity, counterexample sensitivity and every blocking gap.",
		Statement: "Formal coverage of the immutable 24-obligation catalog, derived from the artifacts this " +
			"repository actually holds. Every numerator is an unweighted count of named obligations and every axis " +
			"publishes both the obligations it counted and the obligations that block it, so no aggregate can hide a " +
			"blocking obligation. Evidence below an obligation's required strength is a BLOCK, not a discount.",
		Assurance: DefaultAssurance(),
		Inputs: []ArtifactIdentity{
			catalogIdentity, planIdentity, projectionIdentity, specIdentity, linkageIdentity,
			correctionIdentity, reconciliation.PlaneRecord, reconciliationIdentity,
		},
		Denominator: DenominatorSummary{
			CatalogObligations:        reconciliation.Counts.Obligations,
			ProofTargets:              reconciliation.Counts.ProofTargets,
			ObligationsWithNoTarget:   reconciliation.Counts.ObligationsWithNoTarget,
			TargetsWithNoObligation:   reconciliation.Counts.TargetsWithNoObligation,
			ObligationIDsWithNoTarget: unmappedObligationIDs(reconciliation),
			TargetIDsWithNoObligation: unmappedTargetIDs(reconciliation),
			RustBindingRowsPathAbsent: reconciliation.Counts.RustBindingPathsAbsent,
			RustRowsMeasurableHere:    reconciliation.Counts.RustBindingRowsMeasurableHere,
			PlaneRecord:               reconciliation.PlaneRecord,
			Reconciliation:            reconciliationIdentity,
		},
		Axes:            axes,
		Obligations:     rows,
		BlockingGaps:    gaps,
		ResolverCeiling: ceiling,
		CatalogDefects:  defects,
		PlaneMismatches: mismatches,
		NoHidingRule: "No weighted aggregate may hide a blocking obligation. Enforced three ways at once: no axis " +
			"applies any weight (every axis declares weighting NONE and is derived as a count of rows); every axis " +
			"publishes its counted and its blocking obligations by name, so a numerator can be checked against a " +
			"list rather than trusted; and the aggregate is derived as the INTERSECTION of the coverage axes' member " +
			"sets, so it is bounded above by the weakest axis and cannot be lifted by a strong one. The invariants " +
			"below are recomputed on every derivation and a violated invariant refuses the report rather than " +
			"annotating it.",
		NotClaims: []string{
			"No number in this report is a proof. Nothing here proves anything about Java-WebSocket 1.6.0 or about " +
				"the shipped Rust; the report measures what evidence exists and at what strength.",
			"Non-zero numerators on the production-linkage and counterexample-sensitivity axes are NOT coverage and " +
				"are labelled so in the artifact. Coverage is java_coverage, rust_coverage, paired_comparable_coverage, " +
				"refinement_coverage and aggregate, and all five are zero.",
			"The six Java production-linkage rows are span digests QUOTED from " +
				"evidence/java/formal-bindings/receipt.json. In the default lane those spans are provenance recorded " +
				"in that receipt, not recomputed from the pinned Java tree; only the javabinde2e lane recomputes " +
				"them. This report inherits that bound and does not close it.",
			"The denominator is defective on its JAVA side: five obligations declare Java symbols that cannot carry " +
				"them, all 24 java_bindings share one whole-archive source_sha256 so the column distinguishes no " +
				"two obligations by content, and its 15 distinct source_path values are synthesised paths that " +
				"treat a METHOD as a file and exist on NEITHER plane. That finding is plane-independent and is " +
				"listed rather than corrected here.",
			"The denominator is NOT defective on its Rust side, and an earlier version of this report said it was. " +
				"All four of its distinct Rust source paths and both of its namespaces resolve on the plane the " +
				"catalog is vendored from; they resolve here to nothing because they are about another tree. That " +
				"is a plane mismatch, published in plane_mismatches with the correspondence evidence, and it is a " +
				"question for the owner rather than a repair to the catalog.",
			"Because no plane correspondence is established, the Rust column of this report is not a measurement " +
				"of this plane's crates at all. Its zeroes are honest and they are also not about ws_core and " +
				"ws_driver; they are about a document whose subject this plane has not been shown to be.",
			"This report is owner-executed on a single host. assurance is OWNER_ATTESTED_NOT_INDEPENDENT and " +
				"independent_review_claimed is false.",
		},
	}

	report.Freeze = FreezeVerdict{
		Verdict:               "BLOCKED",
		BlockingObligations:   len(blockingIDs),
		Denominator:           CatalogDenominator,
		BlockingObligationIDs: blockingIDs,
		Rule: "US-023 AC3: evidence below the obligation's required strength blocks the freeze. The freeze is " +
			"BLOCKED while any obligation is blocking, regardless of any aggregate.",
	}
	if len(blockingIDs) == 0 {
		report.Freeze.Verdict = "NOT_BLOCKED"
	}

	invariants := enforceNoHiding(report)
	report.Invariants = invariants
	for _, invariant := range invariants {
		if !invariant.Holds {
			return Report{}, fmt.Errorf("formalcoverage: no-hiding invariant %s does not hold: %s", invariant.ID, invariant.Detail)
		}
	}
	return report, nil
}

func unmappedObligationIDs(reconciliation Reconciliation) []string {
	var ids []string
	for _, row := range reconciliation.Obligations {
		if row.State != MappingMapped {
			ids = append(ids, row.ObligationID)
		}
	}
	sort.Strings(ids)
	return ids
}

func unmappedTargetIDs(reconciliation Reconciliation) []string {
	var ids []string
	for _, row := range reconciliation.Targets {
		if row.State != MappingMapped {
			ids = append(ids, row.TargetID)
		}
	}
	sort.Strings(ids)
	return ids
}

func axisFrom(id string, rows []ObligationReport, isCoverage, feedsAggregate bool, definition string,
	counted func(ObligationReport) bool, note string) AxisResult {
	axis := AxisResult{
		Axis: id, Definition: definition, IsCoverage: isCoverage, FeedsAggregate: feedsAggregate,
		Weighting: "NONE", Denominator: CatalogDenominator, Note: note,
	}
	for _, row := range rows {
		if counted(row) {
			axis.CountedObligations = append(axis.CountedObligations, row.ObligationID)
		} else {
			axis.BlockingObligations = append(axis.BlockingObligations, row.ObligationID)
		}
	}
	axis.Numerator = len(axis.CountedObligations)
	return axis
}

func describeScenarioBounds(ids []string, limits []ScenarioLimits) string {
	if len(ids) == 0 {
		return "no executed scenario, so no bound is declared"
	}
	parts := make([]string, 0, len(ids))
	for index, id := range ids {
		limit := limits[index]
		parts = append(parts, fmt.Sprintf("%s{input<=%d,buffered<=%d,actions<=%d,frames<=%d,output<=%d}",
			id, limit.MaxInputBytes, limit.MaxBufferedBytes, limit.MaxActions, limit.MaxFrames, limit.MaxOutputBytes))
	}
	return "per-scenario execution limits, not a per-obligation bound: " + strings.Join(parts, " ")
}

func describeCatalogBounds(bounds CatalogBounds) string {
	frame, steps := "null", "null"
	if bounds.MaxFrameBytes != nil {
		frame = fmt.Sprintf("%d", *bounds.MaxFrameBytes)
	}
	if bounds.MaxSteps != nil {
		steps = fmt.Sprintf("%d", *bounds.MaxSteps)
	}
	return fmt.Sprintf("catalog-declared bounds max_frame_bytes=%s max_steps=%s", frame, steps)
}

// enforceNoHiding recomputes every no-hiding invariant from the report itself.
// Each invariant is independent on purpose: deleting one must leave the others
// still able to catch the defect it was protecting against.
func enforceNoHiding(report Report) []Invariant {
	var invariants []Invariant
	record := func(id, statement string, holds bool, detail string) {
		invariants = append(invariants, Invariant{ID: id, Statement: statement, Holds: holds, Detail: detail})
	}

	// NH1 — a numerator that is not the size of its own published member list
	// is a numerator nobody can check.
	holds, detail := true, ""
	for _, axis := range report.Axes {
		if axis.Numerator != len(axis.CountedObligations) {
			holds = false
			detail = fmt.Sprintf("axis %s reports %d but publishes %d members", axis.Axis, axis.Numerator, len(axis.CountedObligations))
			break
		}
	}
	record("NH1", "Every axis numerator equals the length of the obligation list it publishes.", holds, detail)

	// NH2 — counted and blocking must partition the fixed denominator.
	holds, detail = true, ""
	for _, axis := range report.Axes {
		seen := map[string]int{}
		for _, id := range axis.CountedObligations {
			seen[id]++
		}
		for _, id := range axis.BlockingObligations {
			seen[id]++
		}
		if len(seen) != CatalogDenominator || len(axis.CountedObligations)+len(axis.BlockingObligations) != CatalogDenominator {
			holds = false
			detail = fmt.Sprintf("axis %s partitions %d distinct ids over %d+%d entries", axis.Axis,
				len(seen), len(axis.CountedObligations), len(axis.BlockingObligations))
			break
		}
		for id, count := range seen {
			if count != 1 {
				holds = false
				detail = fmt.Sprintf("axis %s lists %s %d times", axis.Axis, id, count)
			}
		}
		if !holds {
			break
		}
	}
	record("NH2", "On every axis the counted and the blocking obligations partition the fixed denominator of 24 exactly once each.", holds, detail)

	// NH3 — stated separately from NH2 so that deleting either still catches an
	// obligation counted and blocked at the same time.
	holds, detail = true, ""
	for _, axis := range report.Axes {
		blocking := map[string]bool{}
		for _, id := range axis.BlockingObligations {
			blocking[id] = true
		}
		for _, id := range axis.CountedObligations {
			if blocking[id] {
				holds = false
				detail = fmt.Sprintf("axis %s counts %s and also blocks on it", axis.Axis, id)
			}
		}
	}
	record("NH3", "No axis counts an obligation it also reports as blocking.", holds, detail)

	// NH4 — the aggregate is an intersection, bounded above by every coverage
	// axis, and its members are a subset of every coverage axis's members.
	holds, detail = true, ""
	var aggregate AxisResult
	for _, axis := range report.Axes {
		if axis.Axis == AxisAggregate {
			aggregate = axis
		}
	}
	aggregateMembers := map[string]bool{}
	for _, id := range aggregate.CountedObligations {
		aggregateMembers[id] = true
	}
	for _, axis := range report.Axes {
		if !axis.FeedsAggregate || axis.Axis == AxisAggregate {
			continue
		}
		if aggregate.Numerator > axis.Numerator {
			holds = false
			detail = fmt.Sprintf("aggregate %d exceeds axis %s at %d", aggregate.Numerator, axis.Axis, axis.Numerator)
			break
		}
		counted := map[string]bool{}
		for _, id := range axis.CountedObligations {
			counted[id] = true
		}
		for id := range aggregateMembers {
			if !counted[id] {
				holds = false
				detail = fmt.Sprintf("aggregate counts %s which axis %s does not", id, axis.Axis)
			}
		}
		if !holds {
			break
		}
	}
	record("NH4", "The aggregate is bounded above by every coverage axis and its members are a subset of every coverage axis's members, so it is an intersection and not a weighted sum.", holds, detail)

	// NH5 — no weights anywhere.
	holds, detail = true, ""
	for _, axis := range report.Axes {
		if axis.Weighting != "NONE" {
			holds = false
			detail = fmt.Sprintf("axis %s declares weighting %q", axis.Axis, axis.Weighting)
		}
	}
	record("NH5", "No axis applies any weight; every numerator is an unweighted count of obligations.", holds, detail)

	// NH6 — the blocking list is complete and matches the rows.
	rowBlocking := map[string]bool{}
	for _, row := range report.Obligations {
		if row.Blocking {
			rowBlocking[row.ObligationID] = true
		}
	}
	holds, detail = len(report.BlockingGaps) == len(rowBlocking), ""
	if !holds {
		detail = fmt.Sprintf("%d blocking rows but %d published gaps", len(rowBlocking), len(report.BlockingGaps))
	}
	for _, gap := range report.BlockingGaps {
		if !rowBlocking[gap.ObligationID] {
			holds = false
			detail = fmt.Sprintf("gap %s is not a blocking row", gap.ObligationID)
		}
		if len(gap.Reasons) == 0 {
			holds = false
			detail = fmt.Sprintf("gap %s carries no reason", gap.ObligationID)
		}
	}
	record("NH6", "Every blocking obligation appears in blocking_gaps with at least one named reason, and blocking_gaps names nothing else.", holds, detail)

	// NH7 — sub-required evidence blocks. This is the AC3 sentence, mechanised.
	holds, detail = true, ""
	for _, row := range report.Obligations {
		if (!row.Java.MeetsRequired || !row.Rust.MeetsRequired) && !row.Blocking {
			holds = false
			detail = fmt.Sprintf("%s is below required strength on at least one side yet is not blocking", row.ObligationID)
		}
	}
	record("NH7", "Any obligation whose evidence is below its required strength on either side is blocking.", holds, detail)

	// NH8 — the freeze verdict follows the blocking list, not the aggregate.
	holds = (report.Freeze.BlockingObligations == len(rowBlocking)) &&
		((len(rowBlocking) > 0) == (report.Freeze.Verdict == "BLOCKED")) &&
		len(report.Freeze.BlockingObligationIDs) == len(rowBlocking)
	detail = ""
	if !holds {
		detail = fmt.Sprintf("verdict %s with %d blocking rows and %d listed ids",
			report.Freeze.Verdict, len(rowBlocking), len(report.Freeze.BlockingObligationIDs))
	}
	record("NH8", "The freeze verdict is BLOCKED exactly when at least one obligation blocks, and it names every blocking obligation.", holds, detail)

	// NH9 — an axis that is not coverage must not feed the aggregate, so a
	// non-zero attribution number can never lift a coverage number.
	holds, detail = true, ""
	for _, axis := range report.Axes {
		if !axis.IsCoverage && axis.FeedsAggregate {
			holds = false
			detail = fmt.Sprintf("axis %s is not coverage yet feeds the aggregate", axis.Axis)
		}
		if !axis.IsCoverage && axis.Numerator > 0 && strings.TrimSpace(axis.Note) == "" {
			holds = false
			detail = fmt.Sprintf("axis %s has a non-zero numerator and is not coverage, but says so nowhere", axis.Axis)
		}
	}
	record("NH9", "No axis that is not coverage feeds the aggregate, and any non-zero non-coverage numerator states in the artifact that it is not coverage.", holds, detail)

	// NH10 — the denominator is the fixed 24, each obligation exactly once.
	seen := map[string]int{}
	for _, row := range report.Obligations {
		seen[row.ObligationID]++
	}
	holds = len(report.Obligations) == CatalogDenominator && len(seen) == CatalogDenominator
	detail = ""
	if !holds {
		detail = fmt.Sprintf("%d rows over %d distinct obligations", len(report.Obligations), len(seen))
	}
	record("NH10", "The report holds exactly 24 rows over 24 distinct obligations.", holds, detail)

	// NH11 — the resolver ceiling cannot be claimed away. While the plan
	// records no resolver verification, the Rust production-linkage numerator
	// must be zero and no obligation may be counted as reaching shipped Rust.
	ceiling := report.ResolverCeiling
	holds, detail = true, ""
	if ceiling.ResolverVerifiedAt == "null" || ceiling.ResolverVerifiedAt == "" {
		if ceiling.PlannedSymbolsResolverVerified != 0 || ceiling.ObligationsOnResolverVerified != 0 {
			holds = false
			detail = fmt.Sprintf("resolver_verified_at is %q yet %d planned symbols and %d obligations claim resolver verification",
				ceiling.ResolverVerifiedAt, ceiling.PlannedSymbolsResolverVerified, ceiling.ObligationsOnResolverVerified)
		}
		if ceiling.MigrationBindingsVerified != 0 {
			holds = false
			detail = fmt.Sprintf("resolver_verified_at is null yet %d migration bindings read rust_identity_verified=true",
				ceiling.MigrationBindingsVerified)
		}
	}
	record("NH11", "While the proof-target plan records no resolver verification, the Rust production-linkage numerator, the resolver-verified planned-symbol count and the verified migration-binding count are all zero.", holds, detail)

	return invariants
}
