// Package formalplan validates the US-006 formal-plan artifacts. This file is
// lane A: the proof-targets document and its claim-ID bijection against the
// semantic-id migration map, the digest-pinned quarantined Java tree, and the
// US-005 live handshake evidence. Lanes B and C add sibling files for the
// connection model, concurrency plan, and backend qualification; every
// identifier here is lane-scoped (ProofTargets* / Targets* / targets*) so the
// lanes never collide inside the shared package.
package formalplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/michaellady/verified-java-websocket-port/internal/portplan"
)

// Document locations, relative to the repository root.
const (
	ProofTargetsDocumentPath = "assurance/formal/proof-targets.json"
	ProofTargetsSchemaName   = "formal-proof-targets-1.0.0.schema.json"

	targetsMigrationMapPath = "evidence/intake/semantic-id-migration-map.json"
	targetsDeltaLedgerPath  = "evidence/java/behavior-delta-ledger.json"

	targetsHandshakeClaimID = "formal.handshake.accept-derivation"
	targetsPendingBlocker   = "RUST_IDENTITIES_NOT_YET_RESOLVER_VERIFIED"
	targetsPendingSymbol    = "PLANNED_PENDING_RESOLVER"
	targetsFutureRequired   = "FUTURE_REQUIRED"
	targetsExcludedPrefix   = "(no Rust counterpart:"
)

// Typed finding codes. One code per failure family; a catch-all code is the
// recorded Codex US-006 gap this lane must not repeat.
const (
	TargetsFindingDocumentUnreadable                  = "TARGETS_DOCUMENT_UNREADABLE"
	TargetsFindingStrictDecodeFailed                  = "TARGETS_STRICT_DECODE_FAILED"
	TargetsFindingSchemaViolation                     = "TARGETS_SCHEMA_VIOLATION"
	TargetsFindingMigrationMapUnreadable              = "MIGRATION_MAP_UNREADABLE"
	TargetsFindingMigrationMapDigestMismatch          = "MIGRATION_MAP_DIGEST_MISMATCH"
	TargetsFindingQuarantineUnavailable               = "JAVA_QUARANTINE_UNAVAILABLE"
	TargetsFindingQuarantinePinMismatch               = "QUARANTINE_PIN_MISMATCH"
	TargetsFindingClaimNotCovered                     = "CLAIM_NOT_COVERED"
	TargetsFindingClaimUnknown                        = "CLAIM_UNKNOWN"
	TargetsFindingClaimDuplicated                     = "CLAIM_DUPLICATED"
	TargetsFindingBindingRowOmitted                   = "BINDING_ROW_OMITTED"
	TargetsFindingBindingRowUnknown                   = "BINDING_ROW_UNKNOWN"
	TargetsFindingBindingRustIdentityMismatch         = "BINDING_RUST_IDENTITY_MISMATCH"
	TargetsFindingBindingJavaIdentityMismatch         = "BINDING_JAVA_IDENTITY_MISMATCH"
	TargetsFindingBindingExclusionMismatch            = "BINDING_EXCLUSION_MISMATCH"
	TargetsFindingBindingVerificationOverclaim        = "BINDING_VERIFICATION_OVERCLAIM"
	TargetsFindingJavaAnchorFileMissing               = "JAVA_ANCHOR_FILE_MISSING"
	TargetsFindingJavaAnchorDigestMismatch            = "JAVA_ANCHOR_DIGEST_MISMATCH"
	TargetsFindingJavaAnchorRangeInvalid              = "JAVA_ANCHOR_RANGE_INVALID"
	TargetsFindingSymbolNamespaceUnbound              = "SYMBOL_NAMESPACE_UNBOUND"
	TargetsFindingSymbolNamespaceExcluded             = "SYMBOL_NAMESPACE_EXCLUDED"
	TargetsFindingSymbolPrefixMismatch                = "SYMBOL_PREFIX_MISMATCH"
	TargetsFindingSymbolResolutionOverclaim           = "SYMBOL_RESOLUTION_OVERCLAIM"
	TargetsFindingResolutionStateOverclaim            = "RESOLUTION_STATE_OVERCLAIM"
	TargetsFindingInvokerRoleMissing                  = "INVOKER_ROLE_MISSING"
	TargetsFindingInvokerStateOverclaim               = "INVOKER_STATE_OVERCLAIM"
	TargetsFindingAC1FamilyMissing                    = "AC1_FAMILY_MISSING"
	TargetsFindingAC1FamilyUnbound                    = "AC1_FAMILY_UNBOUND"
	TargetsFindingHandshakeLiveEvidenceMissing        = "HANDSHAKE_LIVE_EVIDENCE_MISSING"
	TargetsFindingHandshakeLiveEvidenceDigestMismatch = "HANDSHAKE_LIVE_EVIDENCE_DIGEST_MISMATCH"
	TargetsFindingStrictnessDeltaUnledgered           = "STRICTNESS_DELTA_UNLEDGERED"
	TargetsFindingStrengtheningNoteStateInvalid       = "STRENGTHENING_NOTE_STATE_INVALID"
	TargetsFindingStrengtheningNoteUnledgered         = "STRENGTHENING_NOTE_UNLEDGERED"
)

// Strengthening-note paired states. A strengthening note records a planned
// Rust-side behavior STRONGER than shipped Java — a future ledger obligation
// for the implementing story, never a current formal claim. While PENDING it
// must cite no ledger record; once LEDGERED it must cite a real one.
const (
	targetsNotePending  = "PENDING_BEHAVIOR_DELTA_LEDGER_ENTRY"
	targetsNoteLedgered = "LEDGERED"
)

// targetsAC1Families is the closed AC1 property-family inventory: the six
// families for which the plan must name the shipped mask function and
// frame-header decoder symbols.
var targetsAC1Families = []string{
	"mask-equation-involution",
	"canonical-length-encoding-7-16-64",
	"checked-arithmetic",
	"allocation-caps",
	"control-constraints",
	"role-masking",
}

// ProofTargetsDocument is assurance/formal/proof-targets.json.
type ProofTargetsDocument struct {
	SchemaRef              string                       `json:"$schema"`
	SchemaVersion          string                       `json:"schema_version"`
	EntityType             string                       `json:"entity_type"`
	DocumentID             string                       `json:"document_id"`
	StoryID                string                       `json:"story_id"`
	Statement              string                       `json:"statement"`
	Sources                ProofTargetsSources          `json:"sources"`
	RustIdentityResolution ProofTargetsResolution       `json:"rust_identity_resolution"`
	InvocationContract     ProofTargetsInvocation       `json:"invocation_contract"`
	AC1Coverage            []ProofTargetsAC1Family      `json:"ac1_coverage"`
	Targets                []ProofTarget                `json:"targets"`
	Assurance              ProofTargetsAssuranceBanner  `json:"assurance"`
}

// ProofTargetsSources pins every input the document was frozen against.
type ProofTargetsSources struct {
	MigrationMap         ProofTargetsMapSource    `json:"migration_map"`
	QuarantinedJavaTree  ProofTargetsTreeSource   `json:"quarantined_java_tree"`
	HandshakeLiveMapping ProofTargetsMapSource    `json:"handshake_live_mapping"`
	BehaviorDeltaLedger  ProofTargetsLedgerSource `json:"behavior_delta_ledger"`
}

// ProofTargetsMapSource pins one evidence document by path and digest.
type ProofTargetsMapSource struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	MapID      string `json:"map_id"`
	MapVersion string `json:"map_version,omitempty"`
}

// ProofTargetsTreeSource pins the quarantined upstream Java tree.
type ProofTargetsTreeSource struct {
	ArchiveSHA256  string `json:"archive_sha256"`
	TreeDirectory  string `json:"tree_directory"`
	SourceRevision string `json:"source_revision"`
	SourcePinsPath string `json:"source_pins_path"`
}

// ProofTargetsLedgerSource pins the behavior-delta ledger state at freeze.
type ProofTargetsLedgerSource struct {
	Path            string `json:"path"`
	RecordsAtFreeze int    `json:"records_at_freeze"`
}

// ProofTargetsResolution is the paired pending/bound state for the whole
// document's Rust identity resolution.
type ProofTargetsResolution struct {
	State               string   `json:"state"`
	PlannedResolver     string   `json:"planned_resolver"`
	ResolverVerifiedAt  *string  `json:"resolver_verified_at"`
	DischargedByStories []string `json:"discharged_by_stories"`
	Statement           string   `json:"statement"`
}

// ProofTargetsInvocation records the conformance/differential invocation
// contract and which stories make it mechanical.
type ProofTargetsInvocation struct {
	Statement                    string   `json:"statement"`
	MechanicalEnforcementPending []string `json:"mechanical_enforcement_pending"`
}

// ProofTargetsAC1Family maps one AC1 property family to the target and
// symbols that carry it.
type ProofTargetsAC1Family struct {
	Family    string   `json:"family"`
	TargetID  string   `json:"target_id"`
	SymbolIDs []string `json:"symbol_ids"`
}

// ProofTarget is one row of the claim-ID bijection.
type ProofTarget struct {
	TargetID          string                    `json:"target_id"`
	FormalClaimID     string                    `json:"formal_claim_id"`
	Title             string                    `json:"title"`
	Statement         string                    `json:"statement"`
	PropertyFamilies  []string                  `json:"property_families"`
	PropertyClaimRefs []string                  `json:"property_claim_refs"`
	JavaAuthority     []ProofTargetJavaAnchor   `json:"java_authority"`
	MigrationBindings []ProofTargetBinding      `json:"migration_bindings"`
	ProductionSymbols []ProofTargetSymbol       `json:"production_symbols"`
	RequiredInvokers  []ProofTargetInvoker      `json:"required_invokers"`
	BehaviorFidelity  ProofTargetFidelity       `json:"behavior_fidelity"`
}

// ProofTargetJavaAnchor cites shipped Java behavior inside the digest-pinned
// quarantined tree.
type ProofTargetJavaAnchor struct {
	AnchorID  string `json:"anchor_id"`
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	SHA256    string `json:"sha256"`
	Behavior  string `json:"behavior"`
}

// ProofTargetBinding mirrors one migration-map row byte-for-byte.
type ProofTargetBinding struct {
	RowID                string `json:"row_id"`
	JavaSemanticID       string `json:"java_semantic_id"`
	RustSemanticID       string `json:"rust_semantic_id"`
	Excluded             bool   `json:"excluded"`
	RustIdentityVerified bool   `json:"rust_identity_verified"`
}

// ProofTargetSymbol names one future production Rust symbol pinned to a
// migration-map namespace, with a paired pending/verified resolution state.
type ProofTargetSymbol struct {
	SymbolID                string                      `json:"symbol_id"`
	PlannedSymbol           string                      `json:"planned_symbol"`
	NamespaceRustSemanticID string                      `json:"namespace_rust_semantic_id"`
	JavaAuthorityMembers    []string                    `json:"java_authority_members"`
	Resolution              ProofTargetSymbolResolution `json:"resolution"`
}

// ProofTargetSymbolResolution is the per-symbol paired state.
type ProofTargetSymbolResolution struct {
	State          string  `json:"state"`
	ResolvedSymbol *string `json:"resolved_symbol"`
}

// ProofTargetInvoker records one required harness invoker (conformance,
// differential, property) in paired FUTURE_REQUIRED/BOUND state.
type ProofTargetInvoker struct {
	Role          string  `json:"role"`
	StoryID       string  `json:"story_id"`
	State         string  `json:"state"`
	InvokerSymbol *string `json:"invoker_symbol"`
	Contract      string  `json:"contract"`
}

// ProofTargetFidelity fixes the shipped-behavior discipline: no formal
// language may outrun shipped-code evidence without a ledgered delta.
type ProofTargetFidelity struct {
	DivergencePolicy    string                         `json:"divergence_policy"`
	RFCStrictnessDeltas []ProofTargetDelta             `json:"rfc_strictness_deltas"`
	NonGoals            []string                       `json:"non_goals"`
	StrengtheningNotes  []ProofTargetStrengtheningNote `json:"strengthening_notes,omitempty"`
	LiveEvidence        *ProofTargetLiveEvidence       `json:"live_evidence"`
}

// ProofTargetStrengtheningNote records a planned Rust-side strengthening of a
// shipped Java behavior (e.g. exactly-once terminal delivery, checked
// packet-size arithmetic). It is an explicit future behavior-delta-ledger
// obligation for the implementing story — never part of the current formal
// claim. Paired states: PENDING_BEHAVIOR_DELTA_LEDGER_ENTRY carries a null
// ledger_record_id; LEDGERED must cite a record that exists in the ledger.
type ProofTargetStrengtheningNote struct {
	NoteID            string  `json:"note_id"`
	State             string  `json:"state"`
	LedgerRecordID    *string `json:"ledger_record_id"`
	ImplementingStory string  `json:"implementing_story"`
	Statement         string  `json:"statement"`
}

// ProofTargetDelta is one deliberate RFC-strictness divergence, valid only
// when the behavior-delta ledger carries the cited record.
type ProofTargetDelta struct {
	DeltaID        string `json:"delta_id"`
	LedgerRecordID string `json:"ledger_record_id"`
	Statement      string `json:"statement"`
}

// ProofTargetLiveEvidence cites live-executed evidence for a shipped
// behavior (US-005 handshake mapping for the accept-derivation target).
type ProofTargetLiveEvidence struct {
	Path         string   `json:"path"`
	SHA256       string   `json:"sha256"`
	EntriesCited []string `json:"entries_cited"`
	Statement    string   `json:"statement"`
}

// ProofTargetsAssuranceBanner is the honest assurance block.
type ProofTargetsAssuranceBanner struct {
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	Production               bool   `json:"production"`
	Signing                  bool   `json:"signing"`
	Publication              bool   `json:"publication"`
}

// ProofTargetsFinding is one typed validation failure.
type ProofTargetsFinding struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ProofTargetsReport is the deterministic validation verdict.
type ProofTargetsReport struct {
	OK               bool                  `json:"ok"`
	Findings         []ProofTargetsFinding `json:"findings"`
	ClaimsCovered    int                   `json:"claims_covered"`
	BindingsVerified int                   `json:"bindings_verified"`
	AnchorsVerified  int                   `json:"anchors_verified"`
	SymbolsPlanned   int                   `json:"symbols_planned"`
}

func (report *ProofTargetsReport) add(code, path, message string) {
	report.OK = false
	report.Findings = append(report.Findings, ProofTargetsFinding{
		Code:    code,
		Path:    path,
		Message: message,
	})
}

func (report *ProofTargetsReport) finish() {
	sort.Slice(report.Findings, func(left, right int) bool {
		a, b := report.Findings[left], report.Findings[right]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Message < b.Message
	})
}

// LoadProofTargets strictly decodes the committed proof-targets document.
func LoadProofTargets(root string) (*ProofTargetsDocument, error) {
	return targetsLoadAt(filepath.Join(root, ProofTargetsDocumentPath))
}

func targetsLoadAt(path string) (*ProofTargetsDocument, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", TargetsFindingDocumentUnreadable, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document ProofTargetsDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%s: %w", TargetsFindingStrictDecodeFailed, err)
	}
	return &document, nil
}

// VerifyProofTargets validates the committed document against the migration
// map, the quarantined Java tree, and the live handshake evidence.
func VerifyProofTargets(root string) ProofTargetsReport {
	return VerifyProofTargetsAt(root, filepath.Join(root, ProofTargetsDocumentPath))
}

// VerifyProofTargetsAt validates the document at documentPath against the
// repository inputs under root. Findings are typed per failure family and
// deterministically sorted; validation continues past non-fatal findings so
// one run surfaces every family it can still evaluate.
func VerifyProofTargetsAt(root, documentPath string) ProofTargetsReport {
	report := ProofTargetsReport{OK: true}
	defer func() { report.finish() }()

	content, err := os.ReadFile(documentPath)
	if err != nil {
		report.add(TargetsFindingDocumentUnreadable, "$", err.Error())
		return report
	}
	var generic interface{}
	if err := json.Unmarshal(content, &generic); err != nil {
		report.add(TargetsFindingDocumentUnreadable, "$", err.Error())
		return report
	}
	document, err := targetsLoadAt(documentPath)
	if err != nil {
		if strings.Contains(err.Error(), TargetsFindingDocumentUnreadable) {
			report.add(TargetsFindingDocumentUnreadable, "$", err.Error())
			return report
		}
		report.add(TargetsFindingStrictDecodeFailed, "$", err.Error())
		// Strict decode failed on an unknown field; the lenient decode below
		// still lets the remaining families run.
		lenient := ProofTargetsDocument{}
		if json.Unmarshal(content, &lenient) != nil {
			return report
		}
		document = &lenient
	}

	targetsValidateSchema(root, content, &report)

	migration, migrationOK := targetsLoadMigrationMap(root, document, &report)
	if migrationOK {
		targetsCheckBijection(document, migration, &report)
		targetsCheckResolutionState(document, migration, &report)
	}
	targetsCheckAnchors(root, document, &report)
	targetsCheckSymbols(document, &report)
	targetsCheckInvokers(document, &report)
	targetsCheckAC1Coverage(document, &report)
	targetsCheckHandshakeLiveEvidence(root, document, &report)
	targetsCheckStrictnessDeltas(root, document, &report)
	return report
}

// targetsValidateSchema validates the raw document bytes against the strict
// Draft 2020-12 schema.
func targetsValidateSchema(root string, content []byte, report *ProofTargetsReport) {
	schemaContent, err := os.ReadFile(filepath.Join(root, "schemas", ProofTargetsSchemaName))
	if err != nil {
		report.add(TargetsFindingSchemaViolation, "$", "schema unavailable: "+err.Error())
		return
	}
	schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaContent))
	if err != nil {
		report.add(TargetsFindingSchemaViolation, "$", "schema unreadable: "+err.Error())
		return
	}
	compiler := jsonschema.NewCompiler()
	resourceURL := "https://verified-java-websocket-port.invalid/" + ProofTargetsSchemaName
	if err := compiler.AddResource(resourceURL, schemaValue); err != nil {
		report.add(TargetsFindingSchemaViolation, "$", "schema resource: "+err.Error())
		return
	}
	schema, err := compiler.Compile(resourceURL)
	if err != nil {
		report.add(TargetsFindingSchemaViolation, "$", "schema compile: "+err.Error())
		return
	}
	documentValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(content))
	if err != nil {
		report.add(TargetsFindingDocumentUnreadable, "$", err.Error())
		return
	}
	if err := schema.Validate(documentValue); err != nil {
		var validationError *jsonschema.ValidationError
		if errors.As(err, &validationError) {
			for _, cause := range targetsFlattenSchemaError(validationError) {
				report.add(TargetsFindingSchemaViolation, "$", cause)
			}
			return
		}
		report.add(TargetsFindingSchemaViolation, "$", err.Error())
	}
}

func targetsFlattenSchemaError(validationError *jsonschema.ValidationError) []string {
	if validationError == nil {
		return nil
	}
	if len(validationError.Causes) == 0 {
		return []string{validationError.Error()}
	}
	var flattened []string
	for _, cause := range validationError.Causes {
		flattened = append(flattened, targetsFlattenSchemaError(cause)...)
	}
	sort.Strings(flattened)
	if len(flattened) > 25 {
		flattened = flattened[:25]
	}
	return flattened
}

// targetsLoadMigrationMap loads the migration map and verifies the document's
// digest pin against the real bytes.
func targetsLoadMigrationMap(root string, document *ProofTargetsDocument, report *ProofTargetsReport) (*portplan.MigrationMap, bool) {
	content, err := os.ReadFile(filepath.Join(root, targetsMigrationMapPath))
	if err != nil {
		report.add(TargetsFindingMigrationMapUnreadable, "$.sources.migration_map", err.Error())
		return nil, false
	}
	digest := targetsSHA256(content)
	if document.Sources.MigrationMap.SHA256 != digest {
		report.add(TargetsFindingMigrationMapDigestMismatch, "$.sources.migration_map.sha256",
			fmt.Sprintf("document pins %s but %s hashes to %s",
				document.Sources.MigrationMap.SHA256, targetsMigrationMapPath, digest))
	}
	var migration portplan.MigrationMap
	if err := json.Unmarshal(content, &migration); err != nil {
		report.add(TargetsFindingMigrationMapUnreadable, "$.sources.migration_map", err.Error())
		return nil, false
	}
	return &migration, true
}

// targetsCheckBijection verifies the claim-ID bijection and every
// migration binding byte-for-byte against the map rows.
func targetsCheckBijection(document *ProofTargetsDocument, migration *portplan.MigrationMap, report *ProofTargetsReport) {
	rowsByID := map[string]*portplan.MigrationRow{}
	rowsByClaim := map[string]map[string]bool{}
	mapClaims := map[string]bool{}
	for index := range migration.Rows {
		row := &migration.Rows[index]
		rowsByID[row.ID] = row
		for _, claim := range row.FormalClaimIDs {
			mapClaims[claim] = true
			if rowsByClaim[claim] == nil {
				rowsByClaim[claim] = map[string]bool{}
			}
			rowsByClaim[claim][row.ID] = true
		}
	}

	targetClaims := map[string]int{}
	for _, target := range document.Targets {
		targetClaims[target.FormalClaimID]++
	}
	covered := 0
	for claim := range mapClaims {
		switch targetClaims[claim] {
		case 0:
			report.add(TargetsFindingClaimNotCovered, "$.targets",
				fmt.Sprintf("migration-map formal claim %s has no proof target", claim))
		case 1:
			covered++
		default:
			covered++
		}
	}
	report.ClaimsCovered = covered
	for claim, count := range targetClaims {
		if !mapClaims[claim] {
			report.add(TargetsFindingClaimUnknown, "$.targets",
				fmt.Sprintf("target claim %s does not exist in the migration map", claim))
			continue
		}
		if count > 1 {
			report.add(TargetsFindingClaimDuplicated, "$.targets",
				fmt.Sprintf("claim %s is covered by %d targets, want exactly one", claim, count))
		}
	}

	for targetIndex, target := range document.Targets {
		expectedRows := rowsByClaim[target.FormalClaimID]
		if expectedRows == nil {
			continue // already reported as CLAIM_UNKNOWN
		}
		basePath := fmt.Sprintf("$.targets[%d]", targetIndex)
		boundRows := map[string]bool{}
		for bindingIndex, binding := range target.MigrationBindings {
			path := fmt.Sprintf("%s.migration_bindings[%d]", basePath, bindingIndex)
			row, exists := rowsByID[binding.RowID]
			if !exists || !expectedRows[binding.RowID] {
				report.add(TargetsFindingBindingRowUnknown, path,
					fmt.Sprintf("row %s does not carry claim %s in the migration map",
						binding.RowID, target.FormalClaimID))
				continue
			}
			boundRows[binding.RowID] = true
			verified := true
			if binding.JavaSemanticID != row.JavaSemanticID {
				report.add(TargetsFindingBindingJavaIdentityMismatch, path+".java_semantic_id",
					fmt.Sprintf("document has %q, map row has %q", binding.JavaSemanticID, row.JavaSemanticID))
				verified = false
			}
			if binding.RustSemanticID != row.RustSemanticID {
				report.add(TargetsFindingBindingRustIdentityMismatch, path+".rust_semantic_id",
					fmt.Sprintf("document has %q, map row has %q (byte-for-byte match required)",
						binding.RustSemanticID, row.RustSemanticID))
				verified = false
			}
			excludedInMap := strings.HasPrefix(row.RustSemanticID, targetsExcludedPrefix)
			if binding.Excluded != excludedInMap {
				report.add(TargetsFindingBindingExclusionMismatch, path+".excluded",
					fmt.Sprintf("document says excluded=%v but map row %s says %v",
						binding.Excluded, row.ID, excludedInMap))
				verified = false
			}
			if binding.RustIdentityVerified && !row.RustIdentityVerified {
				report.add(TargetsFindingBindingVerificationOverclaim, path+".rust_identity_verified",
					fmt.Sprintf("row %s is not resolver-verified in the migration map", row.ID))
				verified = false
			}
			if verified {
				report.BindingsVerified++
			}
		}
		for rowID := range expectedRows {
			if !boundRows[rowID] {
				report.add(TargetsFindingBindingRowOmitted, basePath+".migration_bindings",
					fmt.Sprintf("map row %s carries claim %s but is not bound by the target",
						rowID, target.FormalClaimID))
			}
		}
	}
}

// targetsCheckResolutionState blocks any resolver overclaim while the
// migration map still records the resolver blocker.
func targetsCheckResolutionState(document *ProofTargetsDocument, migration *portplan.MigrationMap, report *ProofTargetsReport) {
	anyUnverified := false
	for _, row := range migration.Rows {
		if !row.RustIdentityVerified {
			anyUnverified = true
			break
		}
	}
	blockerActive := migration.RustIdentityStatus.BlockerCode == targetsPendingBlocker && anyUnverified
	if !blockerActive {
		return
	}
	if document.RustIdentityResolution.State != targetsPendingBlocker {
		report.add(TargetsFindingResolutionStateOverclaim, "$.rust_identity_resolution.state",
			fmt.Sprintf("document claims %q while the migration map records blocker %s with unverified rows",
				document.RustIdentityResolution.State, targetsPendingBlocker))
	}
	for targetIndex, target := range document.Targets {
		for symbolIndex, symbol := range target.ProductionSymbols {
			if symbol.Resolution.State != targetsPendingSymbol {
				report.add(TargetsFindingSymbolResolutionOverclaim,
					fmt.Sprintf("$.targets[%d].production_symbols[%d].resolution.state", targetIndex, symbolIndex),
					fmt.Sprintf("symbol %s claims %q while the migration map blocker %s is active",
						symbol.SymbolID, symbol.Resolution.State, targetsPendingBlocker))
			}
		}
		for invokerIndex, invoker := range target.RequiredInvokers {
			if invoker.State != targetsFutureRequired {
				report.add(TargetsFindingInvokerStateOverclaim,
					fmt.Sprintf("$.targets[%d].required_invokers[%d].state", targetIndex, invokerIndex),
					fmt.Sprintf("invoker role %s claims %q while no harness story has landed and the resolver blocker is active",
						invoker.Role, invoker.State))
			}
		}
	}
}

// targetsCheckAnchors verifies every Java authority anchor against the
// digest-pinned quarantined tree.
func targetsCheckAnchors(root string, document *ProofTargetsDocument, report *ProofTargetsReport) {
	if document.Sources.QuarantinedJavaTree.ArchiveSHA256 != portplan.SourceArchiveSHA256 ||
		document.Sources.QuarantinedJavaTree.TreeDirectory != portplan.SourceTreeDirectory {
		report.add(TargetsFindingQuarantinePinMismatch, "$.sources.quarantined_java_tree",
			fmt.Sprintf("document pins archive %s tree %s; source-pins fix archive %s tree %s",
				document.Sources.QuarantinedJavaTree.ArchiveSHA256,
				document.Sources.QuarantinedJavaTree.TreeDirectory,
				portplan.SourceArchiveSHA256, portplan.SourceTreeDirectory))
	}
	treePath, err := portplan.EnsureQuarantinedSource(root)
	if err != nil {
		report.add(TargetsFindingQuarantineUnavailable, "$.sources.quarantined_java_tree", err.Error())
		return
	}
	type fileFacts struct {
		digest string
		lines  int
		err    error
	}
	factsByFile := map[string]fileFacts{}
	for targetIndex, target := range document.Targets {
		for anchorIndex, anchor := range target.JavaAuthority {
			path := fmt.Sprintf("$.targets[%d].java_authority[%d]", targetIndex, anchorIndex)
			facts, cached := factsByFile[anchor.File]
			if !cached {
				content, readErr := os.ReadFile(filepath.Join(treePath, filepath.FromSlash(anchor.File)))
				if readErr != nil {
					facts = fileFacts{err: readErr}
				} else {
					facts = fileFacts{
						digest: targetsSHA256(content),
						lines:  targetsLineCount(content),
					}
				}
				factsByFile[anchor.File] = facts
			}
			if facts.err != nil {
				report.add(TargetsFindingJavaAnchorFileMissing, path+".file",
					fmt.Sprintf("%s: %v", anchor.File, facts.err))
				continue
			}
			valid := true
			if anchor.SHA256 != facts.digest {
				report.add(TargetsFindingJavaAnchorDigestMismatch, path+".sha256",
					fmt.Sprintf("%s hashes to %s, document pins %s", anchor.File, facts.digest, anchor.SHA256))
				valid = false
			}
			if anchor.StartLine < 1 || anchor.EndLine < anchor.StartLine || anchor.EndLine > facts.lines {
				report.add(TargetsFindingJavaAnchorRangeInvalid, path,
					fmt.Sprintf("range %d-%d invalid for %s (%d lines)",
						anchor.StartLine, anchor.EndLine, anchor.File, facts.lines))
				valid = false
			}
			if valid {
				report.AnchorsVerified++
			}
		}
	}
}

// targetsCheckSymbols verifies every planned production symbol is pinned to a
// migration-map namespace bound by its own target.
func targetsCheckSymbols(document *ProofTargetsDocument, report *ProofTargetsReport) {
	for targetIndex, target := range document.Targets {
		included := map[string]bool{}
		excluded := map[string]bool{}
		for _, binding := range target.MigrationBindings {
			if binding.Excluded {
				excluded[binding.RustSemanticID] = true
			} else {
				included[binding.RustSemanticID] = true
			}
		}
		for symbolIndex, symbol := range target.ProductionSymbols {
			path := fmt.Sprintf("$.targets[%d].production_symbols[%d]", targetIndex, symbolIndex)
			valid := true
			if excluded[symbol.NamespaceRustSemanticID] {
				report.add(TargetsFindingSymbolNamespaceExcluded, path+".namespace_rust_semantic_id",
					fmt.Sprintf("namespace %q is an excluded row; no production symbol may target it",
						symbol.NamespaceRustSemanticID))
				valid = false
			} else if !included[symbol.NamespaceRustSemanticID] {
				report.add(TargetsFindingSymbolNamespaceUnbound, path+".namespace_rust_semantic_id",
					fmt.Sprintf("namespace %q is not a migration-map rust_semantic_id bound by target %s",
						symbol.NamespaceRustSemanticID, target.TargetID))
				valid = false
			}
			if symbol.PlannedSymbol != symbol.NamespaceRustSemanticID &&
				!strings.HasPrefix(symbol.PlannedSymbol, symbol.NamespaceRustSemanticID+"::") {
				report.add(TargetsFindingSymbolPrefixMismatch, path+".planned_symbol",
					fmt.Sprintf("planned symbol %q is outside namespace %q",
						symbol.PlannedSymbol, symbol.NamespaceRustSemanticID))
				valid = false
			}
			if symbol.Resolution.State == targetsPendingSymbol && symbol.Resolution.ResolvedSymbol != nil {
				report.add(TargetsFindingSymbolResolutionOverclaim, path+".resolution",
					"resolved_symbol must be null while resolution is pending")
				valid = false
			}
			if valid {
				report.SymbolsPlanned++
			}
		}
	}
}

// targetsCheckInvokers requires the conformance and differential invocation
// contract on every target.
func targetsCheckInvokers(document *ProofTargetsDocument, report *ProofTargetsReport) {
	for targetIndex, target := range document.Targets {
		roles := map[string]bool{}
		for _, invoker := range target.RequiredInvokers {
			roles[invoker.Role] = true
		}
		for _, required := range []string{"conformance", "differential"} {
			if !roles[required] {
				report.add(TargetsFindingInvokerRoleMissing,
					fmt.Sprintf("$.targets[%d].required_invokers", targetIndex),
					fmt.Sprintf("target %s lacks the %s invoker; the AC requires conformance and differential paths to invoke the exact symbols",
						target.TargetID, required))
			}
		}
	}
}

// targetsCheckAC1Coverage requires all six AC1 property families to be bound
// to real targets and symbols.
func targetsCheckAC1Coverage(document *ProofTargetsDocument, report *ProofTargetsReport) {
	symbolsByTarget := map[string]map[string]bool{}
	for _, target := range document.Targets {
		symbols := map[string]bool{}
		for _, symbol := range target.ProductionSymbols {
			symbols[symbol.SymbolID] = true
		}
		symbolsByTarget[target.TargetID] = symbols
	}
	seen := map[string]int{}
	for entryIndex, entry := range document.AC1Coverage {
		seen[entry.Family]++
		path := fmt.Sprintf("$.ac1_coverage[%d]", entryIndex)
		symbols, targetExists := symbolsByTarget[entry.TargetID]
		if !targetExists {
			report.add(TargetsFindingAC1FamilyUnbound, path+".target_id",
				fmt.Sprintf("family %s cites unknown target %s", entry.Family, entry.TargetID))
			continue
		}
		for _, symbolID := range entry.SymbolIDs {
			if !symbols[symbolID] {
				report.add(TargetsFindingAC1FamilyUnbound, path+".symbol_ids",
					fmt.Sprintf("family %s cites symbol %s absent from target %s",
						entry.Family, symbolID, entry.TargetID))
			}
		}
	}
	for _, family := range targetsAC1Families {
		if seen[family] == 0 {
			report.add(TargetsFindingAC1FamilyMissing, "$.ac1_coverage",
				fmt.Sprintf("AC1 property family %s is not covered", family))
		}
		if seen[family] > 1 {
			report.add(TargetsFindingAC1FamilyUnbound, "$.ac1_coverage",
				fmt.Sprintf("AC1 property family %s appears %d times, want once", family, seen[family]))
		}
	}
}

// targetsCheckHandshakeLiveEvidence requires the accept-derivation target to
// cite the US-005 live handshake mapping with a matching digest, so the plan
// encodes the shipped Java-permissive accept predicate rather than RFC
// strictness the shipped code does not implement.
func targetsCheckHandshakeLiveEvidence(root string, document *ProofTargetsDocument, report *ProofTargetsReport) {
	for targetIndex, target := range document.Targets {
		if target.FormalClaimID != targetsHandshakeClaimID {
			continue
		}
		path := fmt.Sprintf("$.targets[%d].behavior_fidelity.live_evidence", targetIndex)
		evidence := target.BehaviorFidelity.LiveEvidence
		if evidence == nil {
			report.add(TargetsFindingHandshakeLiveEvidenceMissing, path,
				"the accept-derivation target must cite the US-005 live handshake verdict mapping")
			return
		}
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(evidence.Path)))
		if err != nil {
			report.add(TargetsFindingHandshakeLiveEvidenceMissing, path+".path", err.Error())
			return
		}
		digest := targetsSHA256(content)
		if digest != evidence.SHA256 {
			report.add(TargetsFindingHandshakeLiveEvidenceDigestMismatch, path+".sha256",
				fmt.Sprintf("%s hashes to %s, document pins %s", evidence.Path, digest, evidence.SHA256))
		}
		return
	}
}

// targetsCheckStrictnessDeltas blocks any RFC-strictness delta that is not
// backed by a behavior-delta ledger record (the recorded Codex gap:
// canonical-length reject semantics Java does not implement, frozen with no
// ledger entry).
func targetsCheckStrictnessDeltas(root string, document *ProofTargetsDocument, report *ProofTargetsReport) {
	ledgerIDs := map[string]bool{}
	ledgerContent, err := os.ReadFile(filepath.Join(root, targetsDeltaLedgerPath))
	if err == nil {
		var ledger struct {
			Records []struct {
				Delta struct {
					DeltaID string `json:"delta_id"`
				} `json:"delta"`
			} `json:"records"`
		}
		if json.Unmarshal(ledgerContent, &ledger) == nil {
			for _, record := range ledger.Records {
				ledgerIDs[record.Delta.DeltaID] = true
			}
		}
	}
	for targetIndex, target := range document.Targets {
		for deltaIndex, delta := range target.BehaviorFidelity.RFCStrictnessDeltas {
			if !ledgerIDs[delta.LedgerRecordID] {
				report.add(TargetsFindingStrictnessDeltaUnledgered,
					fmt.Sprintf("$.targets[%d].behavior_fidelity.rfc_strictness_deltas[%d]", targetIndex, deltaIndex),
					fmt.Sprintf("delta %s cites ledger record %s which does not exist in %s; formal language may not outrun shipped-code evidence",
						delta.DeltaID, delta.LedgerRecordID, targetsDeltaLedgerPath))
			}
		}
		for noteIndex, note := range target.BehaviorFidelity.StrengtheningNotes {
			path := fmt.Sprintf("$.targets[%d].behavior_fidelity.strengthening_notes[%d]", targetIndex, noteIndex)
			switch note.State {
			case targetsNotePending:
				if note.LedgerRecordID != nil {
					report.add(TargetsFindingStrengtheningNoteStateInvalid, path,
						fmt.Sprintf("note %s is %s but cites ledger record %q; a pending strengthening must cite no record",
							note.NoteID, targetsNotePending, *note.LedgerRecordID))
				}
			case targetsNoteLedgered:
				if note.LedgerRecordID == nil {
					report.add(TargetsFindingStrengtheningNoteStateInvalid, path,
						fmt.Sprintf("note %s claims %s with a null ledger_record_id", note.NoteID, targetsNoteLedgered))
					continue
				}
				if !ledgerIDs[*note.LedgerRecordID] {
					report.add(TargetsFindingStrengtheningNoteUnledgered, path,
						fmt.Sprintf("note %s claims %s citing record %s which does not exist in %s; a strengthening may not outrun the behavior-delta ledger",
							note.NoteID, targetsNoteLedgered, *note.LedgerRecordID, targetsDeltaLedgerPath))
				}
			default:
				report.add(TargetsFindingStrengtheningNoteStateInvalid, path,
					fmt.Sprintf("note %s has unknown state %q; want %s or %s",
						note.NoteID, note.State, targetsNotePending, targetsNoteLedgered))
			}
		}
	}
}

func targetsSHA256(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func targetsLineCount(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	lines := bytes.Count(content, []byte("\n"))
	if content[len(content)-1] != '\n' {
		lines++
	}
	return lines
}
