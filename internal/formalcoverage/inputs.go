package formalcoverage

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// The immutable 24-obligation catalog (vendored from the Codex plane).
//
// Only the fields this package reads are modelled, and unknown fields are
// tolerated: the catalog is owned elsewhere and must never be constrained,
// rewritten or repaired by this package.
// ---------------------------------------------------------------------------

// CatalogObligation is one obligation row.
type CatalogObligation struct {
	ObligationID          string   `json:"obligation_id"`
	SurfaceIDs            []string `json:"surface_ids"`
	Statement             string   `json:"statement"`
	NormativeRefs         []string `json:"normative_refs"`
	RequiredStrength      string   `json:"required_strength"`
	AllowedMethods        []string `json:"allowed_methods"`
	RequiredEvidenceKinds []string `json:"required_evidence_kinds"`
	RequiredMutationIDs   []string `json:"required_mutation_ids"`
}

// CatalogIdentity is a binding's content identity as the catalog states it.
type CatalogIdentity struct {
	Commit        *string `json:"commit"`
	Tree          *string `json:"tree"`
	Blob          *string `json:"blob"`
	ArchiveSHA256 *string `json:"archive_sha256"`
}

// CatalogBinding is one java_bindings or rust_bindings row.
type CatalogBinding struct {
	ObligationID        string          `json:"obligation_id"`
	Language            string          `json:"language"`
	ProductionSymbol    string          `json:"production_symbol"`
	ItemKind            string          `json:"item_kind"`
	SourcePath          string          `json:"source_path"`
	SourceSHA256        string          `json:"source_sha256"`
	Identity            CatalogIdentity `json:"identity"`
	DeclarationIdentity string          `json:"declaration_identity"`
	ReachableFromEntry  bool            `json:"reachable_from_entry"`
	ConnectionState     string          `json:"connection_state"`
	BlockerIDs          []string        `json:"blocker_ids"`
}

// CatalogCoverage is one coverage row: the catalog's own per-axis verdict.
type CatalogCoverage struct {
	ObligationID    string   `json:"obligation_id"`
	JavaStatus      string   `json:"java_status"`
	RustStatus      string   `json:"rust_status"`
	RefinementState string   `json:"refinement_status"`
	MutationStatus  string   `json:"mutation_status"`
	AggregateStatus string   `json:"aggregate_status"`
	BlockerIDs      []string `json:"blocker_ids"`
}

// CatalogBounds is the declared bound pair. Both are pointers because the
// catalog leaves them null, and a null bound is not a bound: it must be
// reportable as "undeclared", never silently read as "unbounded" or as "0".
type CatalogBounds struct {
	MaxFrameBytes *int64 `json:"max_frame_bytes"`
	MaxSteps      *int64 `json:"max_steps"`
}

// CatalogRefinement is the refinement link an evidence row declares.
type CatalogRefinement struct {
	State       string  `json:"state"`
	FromSubject string  `json:"from_subject"`
	ToSymbol    string  `json:"to_symbol"`
	ArtifactSHA *string `json:"artifact_sha256"`
}

// CatalogMutationSensitivity is one recorded mutant disposition.
type CatalogMutationSensitivity struct {
	MutantID    string `json:"mutant_id"`
	Anchor      string `json:"anchor"`
	Disposition string `json:"disposition"`
}

// CatalogTool names the tool an evidence row was produced by.
type CatalogTool struct {
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	BinarySHA256 *string `json:"binary_sha256"`
}

// CatalogEvidence is one evidence row.
type CatalogEvidence struct {
	EvidenceID          string                       `json:"evidence_id"`
	ObligationID        string                       `json:"obligation_id"`
	SubjectLanguage     string                       `json:"subject_language"`
	Method              string                       `json:"method"`
	ExecutionState      string                       `json:"execution_state"`
	ObservedStrength    string                       `json:"observed_strength"`
	Bounds              CatalogBounds                `json:"bounds"`
	Assumptions         map[string]string            `json:"assumptions"`
	TrustedBase         []string                     `json:"trusted_base"`
	Tool                CatalogTool                  `json:"tool"`
	InputSHA256s        []string                     `json:"input_sha256s"`
	OutputSHA256s       []string                     `json:"output_sha256s"`
	Refinement          CatalogRefinement            `json:"refinement"`
	Counterexample      json.RawMessage              `json:"counterexample"`
	MutationSensitivity []CatalogMutationSensitivity `json:"mutation_sensitivity"`
}

// CatalogBasis is one entry of the catalog's declared denominator basis.
type CatalogBasis struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Git    struct {
		Commit string `json:"commit"`
		Tree   string `json:"tree"`
		Blob   string `json:"blob"`
	} `json:"git"`
}

// Catalog is the read-only view this package takes of the immutable catalog.
type Catalog struct {
	CatalogID        string              `json:"catalog_id"`
	DenominatorBasis []CatalogBasis      `json:"denominator_basis"`
	Obligations      []CatalogObligation `json:"obligations"`
	JavaBindings     []CatalogBinding    `json:"java_bindings"`
	RustBindings     []CatalogBinding    `json:"rust_bindings"`
	Evidence         []CatalogEvidence   `json:"evidence"`
	Coverage         []CatalogCoverage   `json:"coverage"`
	Assurance        string              `json:"assurance"`
	IndependentClaim bool                `json:"independent_review_claimed"`
}

// DecodeCatalog reads the immutable catalog and refuses anything that is not
// the fixed 24-row denominator.
func DecodeCatalog(data []byte) (Catalog, error) {
	var catalog Catalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("formalcoverage: decode catalog: %w", err)
	}
	if catalog.CatalogID != "us023-formal-obligations" {
		return Catalog{}, fmt.Errorf("formalcoverage: catalog id is %q, not us023-formal-obligations", catalog.CatalogID)
	}
	for name, size := range map[string]int{
		"obligations":   len(catalog.Obligations),
		"java_bindings": len(catalog.JavaBindings),
		"rust_bindings": len(catalog.RustBindings),
		"evidence":      len(catalog.Evidence),
		"coverage":      len(catalog.Coverage),
	} {
		if size != CatalogDenominator {
			return Catalog{}, fmt.Errorf("formalcoverage: catalog %s holds %d rows, not the fixed denominator %d", name, size, CatalogDenominator)
		}
	}
	return catalog, nil
}

// JavaBinding, RustBinding, Coverage and Evidence look one row up by obligation.
func (c Catalog) JavaBinding(id string) (CatalogBinding, bool) {
	return findBinding(c.JavaBindings, id)
}
func (c Catalog) RustBinding(id string) (CatalogBinding, bool) {
	return findBinding(c.RustBindings, id)
}

func findBinding(rows []CatalogBinding, id string) (CatalogBinding, bool) {
	for _, row := range rows {
		if row.ObligationID == id {
			return row, true
		}
	}
	return CatalogBinding{}, false
}

// CoverageFor returns the catalog's own coverage row for one obligation.
func (c Catalog) CoverageFor(id string) (CatalogCoverage, bool) {
	for _, row := range c.Coverage {
		if row.ObligationID == id {
			return row, true
		}
	}
	return CatalogCoverage{}, false
}

// Evidence returns the catalog's own evidence row for one obligation.
func (c Catalog) EvidenceFor(id string) (CatalogEvidence, bool) {
	for _, row := range c.Evidence {
		if row.ObligationID == id {
			return row, true
		}
	}
	return CatalogEvidence{}, false
}

// Basis returns the catalog's declared basis pin for one path.
func (c Catalog) Basis(path string) (CatalogBasis, bool) {
	for _, row := range c.DenominatorBasis {
		if row.Path == path {
			return row, true
		}
	}
	return CatalogBasis{}, false
}

// ---------------------------------------------------------------------------
// The US-006 proof-target plan.
// ---------------------------------------------------------------------------

// JavaAnchor is one file:line span of pinned Java the plan cites as authority.
type JavaAnchor struct {
	AnchorID  string `json:"anchor_id"`
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	SHA256    string `json:"sha256"`
	Behavior  string `json:"behavior"`
}

// PlannedResolution is a planned production symbol's resolver state.
type PlannedResolution struct {
	State          string  `json:"state"`
	ResolvedSymbol *string `json:"resolved_symbol"`
}

// PlannedSymbol is one planned Rust production symbol with its Java authority.
type PlannedSymbol struct {
	SymbolID            string            `json:"symbol_id"`
	PlannedSymbol       string            `json:"planned_symbol"`
	NamespaceSemanticID string            `json:"namespace_rust_semantic_id"`
	JavaAuthorityMember []string          `json:"java_authority_members"`
	Resolution          PlannedResolution `json:"resolution"`
}

// MigrationBinding is one migration-map row a target pins.
type MigrationBinding struct {
	RowID                string `json:"row_id"`
	JavaSemanticID       string `json:"java_semantic_id"`
	RustSemanticID       string `json:"rust_semantic_id"`
	Excluded             bool   `json:"excluded"`
	RustIdentityVerified bool   `json:"rust_identity_verified"`
}

// ProofTarget is one of the ten targets.
type ProofTarget struct {
	TargetID          string             `json:"target_id"`
	FormalClaimID     string             `json:"formal_claim_id"`
	Title             string             `json:"title"`
	PropertyFamilies  []string           `json:"property_families"`
	PropertyClaimRefs []string           `json:"property_claim_refs"`
	JavaAuthority     []JavaAnchor       `json:"java_authority"`
	MigrationBindings []MigrationBinding `json:"migration_bindings"`
	ProductionSymbols []PlannedSymbol    `json:"production_symbols"`
}

// RustIdentityResolution is the plan's own statement of its resolver ceiling.
type RustIdentityResolution struct {
	State              string  `json:"state"`
	PlannedResolver    string  `json:"planned_resolver"`
	ResolverVerifiedAt *string `json:"resolver_verified_at"`
	Statement          string  `json:"statement"`
}

// ProofTargets is the read-only view of assurance/formal/proof-targets.json.
type ProofTargets struct {
	DocumentID string        `json:"document_id"`
	StoryID    string        `json:"story_id"`
	Targets    []ProofTarget `json:"targets"`
	Sources    struct {
		QuarantinedJavaTree struct {
			ArchiveSHA256  string `json:"archive_sha256"`
			TreeDirectory  string `json:"tree_directory"`
			SourceRevision string `json:"source_revision"`
		} `json:"quarantined_java_tree"`
	} `json:"sources"`
	RustIdentityResolution RustIdentityResolution `json:"rust_identity_resolution"`
}

// DecodeProofTargets reads the proof-target plan and refuses a plan of a
// different size for the same reason DecodeCatalog does.
func DecodeProofTargets(data []byte) (ProofTargets, error) {
	var plan ProofTargets
	if err := json.Unmarshal(data, &plan); err != nil {
		return ProofTargets{}, fmt.Errorf("formalcoverage: decode proof targets: %w", err)
	}
	if plan.DocumentID != "formal-proof-targets.us006" {
		return ProofTargets{}, fmt.Errorf("formalcoverage: proof-target document id is %q, not formal-proof-targets.us006", plan.DocumentID)
	}
	if len(plan.Targets) != ProofTargetDenominator {
		return ProofTargets{}, fmt.Errorf("formalcoverage: proof-target plan holds %d targets, not %d", len(plan.Targets), ProofTargetDenominator)
	}
	return plan, nil
}

// ---------------------------------------------------------------------------
// The Java-side coverage projection produced by internal/javabind.
// ---------------------------------------------------------------------------

// ProjectionRow is one obligation row of the Java projection.
type ProjectionRow struct {
	ObligationID        string `json:"obligation_id"`
	CatalogSymbol       string `json:"catalog_symbol"`
	BindingState        string `json:"binding_state"`
	ReasonCode          string `json:"reason_code"`
	ReasonDetail        string `json:"reason_detail"`
	SourceFile          string `json:"source_file"`
	SpanSHA256          string `json:"span_sha256"`
	DescriptorAgreement string `json:"descriptor_agreement"`
	ObservedStrength    string `json:"observed_strength"`
	RequiredStrength    string `json:"required_strength"`
	MeetsRequired       bool   `json:"meets_required_strength"`
	ClausesDeclared     int    `json:"clauses_declared"`
	ClausesSatisfied    int    `json:"clauses_satisfied"`
	CanariesKilled      int    `json:"canaries_killed"`
}

// ProjectionCounts mirrors internal/javabind's derived counts.
type ProjectionCounts struct {
	Denominator                    int `json:"denominator"`
	JavaBindingsConnected          int `json:"java_bindings_connected"`
	JavaBindingsPartial            int `json:"java_bindings_partial"`
	JavaBindingsDisconnected       int `json:"java_bindings_disconnected"`
	JavaMutationSensitive          int `json:"java_mutation_sensitive"`
	JavaBindingsAtRequiredStrength int `json:"java_bindings_at_required_strength"`
	Refinement                     int `json:"refinement"`
	Aggregate                      int `json:"aggregate"`
	ClausesDeclared                int `json:"clauses_declared"`
	ClausesSatisfied               int `json:"clauses_satisfied"`
	CanariesDeclared               int `json:"canaries_declared"`
	CanariesKilled                 int `json:"canaries_killed"`
}

// JavaProjection is the read-only view of the retained Java projection.
type JavaProjection struct {
	ProjectionID     string `json:"projection_id"`
	CatalogID        string `json:"catalog_id"`
	ObservedStrength string `json:"observed_strength"`
	RequiredStrength string `json:"required_strength"`
	Catalog          struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"catalog"`
	Counts      ProjectionCounts `json:"counts"`
	Obligations []ProjectionRow  `json:"obligations"`
}

// DecodeJavaProjection reads the retained Java projection.
func DecodeJavaProjection(data []byte) (JavaProjection, error) {
	var projection JavaProjection
	if err := json.Unmarshal(data, &projection); err != nil {
		return JavaProjection{}, fmt.Errorf("formalcoverage: decode java projection: %w", err)
	}
	if projection.ProjectionID != "java-formal-binding-coverage" {
		return JavaProjection{}, fmt.Errorf("formalcoverage: java projection id is %q", projection.ProjectionID)
	}
	if len(projection.Obligations) != CatalogDenominator {
		return JavaProjection{}, fmt.Errorf("formalcoverage: java projection holds %d rows, not %d", len(projection.Obligations), CatalogDenominator)
	}
	return projection, nil
}

// Row returns the projection row for one obligation.
func (p JavaProjection) Row(id string) (ProjectionRow, bool) {
	for _, row := range p.Obligations {
		if row.ObligationID == id {
			return row, true
		}
	}
	return ProjectionRow{}, false
}

// ---------------------------------------------------------------------------
// The Java binding spec's typed unbound reasons.
// ---------------------------------------------------------------------------

// ScenarioLimits are the declared bounds one executed scenario ran under. They
// are the only concrete bounds the Java side of this repository declares, and
// they are per SCENARIO, not per obligation — which is exactly what makes bound
// parity against the catalog's per-obligation bounds impossible rather than
// merely unequal.
type ScenarioLimits struct {
	MaxInputBytes    int64 `json:"max_input_bytes"`
	MaxBufferedBytes int64 `json:"max_buffered_bytes"`
	MaxActions       int64 `json:"max_actions"`
	MaxFrames        int64 `json:"max_frames"`
	MaxOutputBytes   int64 `json:"max_output_bytes"`
}

// BindingSpec is the read-only view of the Java binding spec. This package
// never re-derives Java bindings — it quotes internal/javabind's — but it does
// read the scenario limits each bound obligation's witnesses actually ran
// under, because those are the Java side of the bound-parity question.
type BindingSpec struct {
	SpecID    string `json:"spec_id"`
	Scenarios []struct {
		ScenarioID string         `json:"scenario_id"`
		Limits     ScenarioLimits `json:"limits"`
	} `json:"scenarios"`
	Bindings []struct {
		ObligationID string `json:"obligation_id"`
		Clauses      []struct {
			ClauseID  string `json:"clause_id"`
			Witnesses []struct {
				ScenarioID string `json:"scenario_id"`
			} `json:"witnesses"`
		} `json:"clauses"`
	} `json:"bindings"`
	Unbound []struct {
		ObligationID string `json:"obligation_id"`
		ReasonCode   string `json:"reason_code"`
		Detail       string `json:"detail"`
	} `json:"unbound"`
}

// ScenarioLimitsFor returns the distinct scenario ids one obligation's
// witnesses ran under, in id order, with each one's declared limits.
func (s BindingSpec) ScenarioLimitsFor(obligationID string) ([]string, []ScenarioLimits) {
	byID := map[string]ScenarioLimits{}
	for _, scenario := range s.Scenarios {
		byID[scenario.ScenarioID] = scenario.Limits
	}
	seen := map[string]bool{}
	var ids []string
	for _, binding := range s.Bindings {
		if binding.ObligationID != obligationID {
			continue
		}
		for _, clause := range binding.Clauses {
			for _, witness := range clause.Witnesses {
				if !seen[witness.ScenarioID] {
					seen[witness.ScenarioID] = true
					ids = append(ids, witness.ScenarioID)
				}
			}
		}
	}
	sort.Strings(ids)
	limits := make([]ScenarioLimits, 0, len(ids))
	for _, id := range ids {
		limits = append(limits, byID[id])
	}
	return ids, limits
}

// DecodeBindingSpec reads the Java binding spec.
func DecodeBindingSpec(data []byte) (BindingSpec, error) {
	var spec BindingSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return BindingSpec{}, fmt.Errorf("formalcoverage: decode binding spec: %w", err)
	}
	return spec, nil
}

// UnboundReason returns the typed reason the Java lane recorded, if any.
func (s BindingSpec) UnboundReason(id string) (string, string, bool) {
	for _, row := range s.Unbound {
		if row.ObligationID == id {
			return row.ReasonCode, row.Detail, true
		}
	}
	return "", "", false
}

// ---------------------------------------------------------------------------
// The Rust identity linkage overlay.
// ---------------------------------------------------------------------------

// LinkageEvidence is the read-only view of the strongest Rust linkage artifact
// this repository holds.
type LinkageEvidence struct {
	DocumentID string `json:"document_id"`
	Resolver   struct {
		Method    string `json:"method"`
		Strength  string `json:"strength"`
		Statement string `json:"statement"`
	} `json:"resolver"`
	Summary struct {
		RowsTotal         int `json:"rows_total"`
		Verified          int `json:"verified"`
		ExcludedConfirmed int `json:"excluded_confirmed"`
	} `json:"summary"`
	Rows []struct {
		RowID                string `json:"row_id"`
		RustIdentityVerified bool   `json:"rust_identity_verified"`
		LandedSymbols        []struct {
			RustPath string `json:"rust_path"`
			File     string `json:"file"`
			Line     int    `json:"line"`
		} `json:"landed_symbols"`
	} `json:"rows"`
}

// DecodeLinkage reads the Rust identity verification overlay.
func DecodeLinkage(data []byte) (LinkageEvidence, error) {
	var linkage LinkageEvidence
	if err := json.Unmarshal(data, &linkage); err != nil {
		return LinkageEvidence{}, fmt.Errorf("formalcoverage: decode linkage evidence: %w", err)
	}
	if linkage.DocumentID != "rust-identity-verification.e2-linkage" {
		return LinkageEvidence{}, fmt.Errorf("formalcoverage: linkage document id is %q", linkage.DocumentID)
	}
	return linkage, nil
}

// ---------------------------------------------------------------------------
// The one join key both denominators actually carry.
// ---------------------------------------------------------------------------

// JavaKey is the pinned-Java construct key `DeclaringType#memberName`. It is the
// only key the two denominators share: the catalog names Java production
// symbols in JVM-descriptor form, the proof-target plan names Java authority
// members in `package.Type#member(Params)` form, and both are anchored to the
// same digest-pinned Java-WebSocket archive. The key deliberately drops the
// parameter list, because the catalog's descriptors are known to disagree with
// the pinned source's parameter lists (see docs/java-formal-binding-design.md
// section 3.2) — joining on a field known to be wrong would produce a smaller,
// falsely confident mapping.
type JavaKey string

// CatalogJavaKey normalises one catalog production symbol to a JavaKey. A
// symbol naming a bare type yields `Type#Type`, so a type-level declaration is
// visible in the join rather than dropped from it.
func CatalogJavaKey(symbol string) JavaKey {
	head := symbol
	if index := strings.IndexByte(symbol, '('); index >= 0 {
		head = symbol[:index]
	}
	parts := strings.Split(head, ".")
	last := parts[len(parts)-1]
	if last == "" {
		return JavaKey(head)
	}
	if last[0] >= 'A' && last[0] <= 'Z' {
		return JavaKey(last + "#" + last)
	}
	if len(parts) < 2 {
		return JavaKey(last + "#" + last)
	}
	return JavaKey(parts[len(parts)-2] + "#" + last)
}

// TargetJavaKey normalises one proof-target java_authority_member to a JavaKey.
// Members carry free-text qualifiers after the signature ("… masking XOR
// loop"); those are trailing prose and are dropped, never parsed.
func TargetJavaKey(member string) JavaKey {
	member = strings.TrimSpace(member)
	hash := strings.IndexByte(member, '#')
	if hash < 0 {
		// A bare type reference, possibly with trailing prose in parentheses.
		typePart := strings.Fields(member)
		if len(typePart) == 0 {
			return ""
		}
		parts := strings.Split(typePart[0], ".")
		last := parts[len(parts)-1]
		return JavaKey(last + "#" + last)
	}
	typeName := member[:hash]
	rest := member[hash+1:]
	if index := strings.IndexByte(rest, '('); index >= 0 {
		rest = rest[:index]
	}
	rest = strings.TrimSpace(rest)
	typeParts := strings.Split(typeName, ".")
	simpleType := typeParts[len(typeParts)-1]
	if rest == "" {
		return JavaKey(simpleType + "#" + simpleType)
	}
	return JavaKey(simpleType + "#" + rest)
}
