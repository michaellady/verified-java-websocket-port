package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/provenance"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	coverageSchemaPath      = "schemas/kani-formal-coverage-1.0.0.schema.json"
	coverageCatalogPath     = "assurance/formal/obligation-catalog.json"
	coverageEvidenceKind    = "KANI_FORMAL_COVERAGE_PROJECTION"
	coverageClaimScope      = "SUPPLEMENTAL_RUST_FORMAL_COVERAGE_ONLY"
	coverageStatus          = "BLOCKED"
	coverageSchemaReference = "../../schemas/kani-formal-coverage-1.0.0.schema.json"
	coverageSchemaVersion   = "1.0.0"
	coverageCatalogID       = "us023-formal-obligations"
	coverageCatalogVersion  = "1.0.0"
	coverageSatisfied       = "SATISFIED"
	coverageBlocked         = "BLOCKED"
	coverageRequiredCount   = 24

	// Schema 1.1.0 exists because 1.0.0 pins the Java axis to a const, making Java
	// coverage schematically impossible to report. 1.0.0 and every projection
	// validated under it are retained untouched so old snapshots stay byte
	// replayable; the new axis behaviour lives only here.
	coverageSchemaPathV11      = "schemas/kani-formal-coverage-1.1.0.schema.json"
	coverageSchemaReferenceV11 = "../../schemas/kani-formal-coverage-1.1.0.schema.json"
	coverageSchemaVersionV11   = "1.1.0"

	javaFormalEvidenceKind  = "JAVA_BOUNDED_MODEL_OBLIGATION_EVIDENCE"
	javaFormalSchemaVersion = "1.0.0"
)

// coverageRelease binds a coverage schema version to its artifacts and shape.
// Dispatching on it keeps the 1.0.0 derivation path intact for replay while new
// behaviour is added under 1.1.0.
type coverageRelease struct {
	Version         string
	SchemaPath      string
	SchemaReference string
	LimitationCount int
}

func coverageReleaseFor(version string) (coverageRelease, error) {
	switch version {
	case coverageSchemaVersion:
		return coverageRelease{Version: coverageSchemaVersion, SchemaPath: coverageSchemaPath, SchemaReference: coverageSchemaReference, LimitationCount: 5}, nil
	case coverageSchemaVersionV11:
		return coverageRelease{Version: coverageSchemaVersionV11, SchemaPath: coverageSchemaPathV11, SchemaReference: coverageSchemaReferenceV11, LimitationCount: 6}, nil
	default:
		return coverageRelease{}, fmt.Errorf("unknown coverage schema version: %s", version)
	}
}

type gitIdentity struct {
	Commit       string `json:"commit"`
	Tree         string `json:"tree"`
	ObjectFormat string `json:"object_format"`
}

type gitArtifactBinding struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	GitBlob string `json:"git_blob"`
}

type qualifiedSourceBinding struct {
	QualifiedCommit string `json:"qualified_commit"`
	BindingCount    int    `json:"binding_count"`
}

type coverageRow struct {
	ObligationID     string   `json:"obligation_id"`
	JavaStatus       string   `json:"java_status"`
	RustStatus       string   `json:"rust_status"`
	RefinementStatus string   `json:"refinement_status"`
	MutationStatus   string   `json:"mutation_status"`
	AggregateStatus  string   `json:"aggregate_status"`
	BlockerIDs       []string `json:"blocker_ids"`
	// RustLinkage is absent under 1.0.0 and required under 1.1.0. It records
	// whether the crediting harness proves the cataloged bound symbol (DIRECT), a
	// leaf that symbol calls (SUPPORTING), or nothing (ABSENT).
	RustLinkage string `json:"rust_linkage,omitempty"`
}

type coverageCounts struct {
	Required            int `json:"required"`
	JavaSatisfied       int `json:"java_satisfied"`
	RustSatisfied       int `json:"rust_satisfied"`
	RustBlocked         int `json:"rust_blocked"`
	RefinementSatisfied int `json:"refinement_satisfied"`
	MutationSatisfied   int `json:"mutation_satisfied"`
	MutationBlocked     int `json:"mutation_blocked"`
	AggregateSatisfied  int `json:"aggregate_satisfied"`
	AggregateBlocked    int `json:"aggregate_blocked"`
	// RustSupporting counts obligations whose only Kani evidence proves a leaf the
	// bound symbol calls. It is a separate column and is never summed into
	// RustSatisfied. Absent under 1.0.0, which has no such concept.
	RustSupporting *int `json:"rust_supporting,omitempty"`
}

type coverageBlocker struct {
	BlockerID              string   `json:"blocker_id"`
	Code                   string   `json:"code"`
	UncoveredObligationIDs []string `json:"uncovered_obligation_ids"`
}

type coverageProjection struct {
	Schema          string             `json:"$schema"`
	SchemaVersion   string             `json:"schema_version"`
	EvidenceKind    string             `json:"evidence_kind"`
	ProjectionBasis gitIdentity        `json:"projection_basis"`
	Catalog         gitArtifactBinding `json:"catalog"`
	KaniReceipt     gitArtifactBinding `json:"kani_receipt"`
	// JavaReceipt is absent under 1.0.0, which cannot represent Java coverage at
	// all, and optional under 1.1.0. omitempty keeps 1.0.0 projections byte
	// identical to the retained ones.
	JavaReceipt              *gitArtifactBinding    `json:"java_receipt,omitempty"`
	CurrentHeadQualification gitArtifactBinding     `json:"current_head_qualification"`
	QualifiedSource          qualifiedSourceBinding `json:"qualified_source"`
	ProofSubject             gitIdentity            `json:"proof_subject"`
	Coverage                 []coverageRow          `json:"coverage"`
	Counts                   coverageCounts         `json:"counts"`
	Blockers                 []coverageBlocker      `json:"blockers"`
	Status                   string                 `json:"status"`
	ClaimScope               string                 `json:"claim_scope"`
	Limitations              []string               `json:"limitations"`
	Assurance                string                 `json:"assurance"`
	IndependentReviewClaimed bool                   `json:"independent_review_claimed"`
	Production               bool                   `json:"production"`
	Signing                  bool                   `json:"signing"`
	Publication              bool                   `json:"publication"`
}

type obligationCatalogProjection struct {
	SchemaVersion string `json:"schema_version"`
	CatalogID     string `json:"catalog_id"`
	Obligations   []struct {
		ObligationID string `json:"obligation_id"`
	} `json:"obligations"`
	JavaBindings []catalogBinding `json:"java_bindings"`
	RustBindings []catalogBinding `json:"rust_bindings"`
}

// catalogBinding is the catalog's record of which shipped symbol an obligation is
// actually about. It is the join key the projection needs and previously never read.
type catalogBinding struct {
	ObligationID     string `json:"obligation_id"`
	Language         string `json:"language"`
	ProductionSymbol string `json:"production_symbol"`
	SourcePath       string `json:"source_path"`
}

// coverageCatalog is the decoded, identity-checked catalog view.
type coverageCatalog struct {
	ObligationIDs []string
	JavaBindings  map[string]string
	// RustBindings maps an obligation to the shipped Rust symbol the catalog says
	// it is about. This is the join key the projection needs to tell a proof of the
	// bound symbol apart from a proof of something else wearing the same label.
	RustBindings map[string]string
}

// javaFormalReceipt is the minimal typed view of Java bounded-model evidence.
// It exists so a real Java result can raise the Java axis under schema 1.1.0.
type javaFormalReceipt struct {
	SchemaVersion string             `json:"schema_version"`
	EvidenceKind  string             `json:"evidence_kind"`
	Results       []javaFormalResult `json:"results"`
}

type javaFormalResult struct {
	ObligationID     string `json:"obligation_id"`
	ProductionSymbol string `json:"production_symbol"`
	Status           string `json:"status"`
}

// deriveJavaCoverage credits an obligation's Java axis only when the receipt
// reports a SATISFIED result whose production symbol is the one the catalog binds
// for that obligation. A self-declared obligation label is not evidence; that is
// the same discipline the Rust axis needs and is applied here from the start.
func deriveJavaCoverage(bindings map[string]string, catalogSet map[string]bool, value javaFormalReceipt) (map[string]bool, error) {
	if value.EvidenceKind != javaFormalEvidenceKind || value.SchemaVersion != javaFormalSchemaVersion {
		return nil, errors.New("Java formal receipt identity is not canonical")
	}
	covered := map[string]bool{}
	for _, result := range value.Results {
		if !catalogSet[result.ObligationID] {
			return nil, fmt.Errorf("Java result references obligation outside catalog: %s", result.ObligationID)
		}
		switch result.Status {
		case coverageSatisfied:
		case coverageBlocked, "FAILED":
			continue
		default:
			return nil, fmt.Errorf("Java result %s has an unrecognized status: %s", result.ObligationID, result.Status)
		}
		bound, ok := bindings[result.ObligationID]
		if !ok {
			return nil, fmt.Errorf("Java result %s has no catalog binding", result.ObligationID)
		}
		if bound != result.ProductionSymbol {
			return nil, fmt.Errorf("Java result %s targets %s but the catalog binds %s", result.ObligationID, result.ProductionSymbol, bound)
		}
		covered[result.ObligationID] = true
	}
	return covered, nil
}

var exactCoverageObligationIDs = []string{
	"obligation.checked-header-arithmetic",
	"obligation.control-fin-and-length",
	"obligation.length-canonical-16",
	"obligation.length-canonical-64-high-bit-zero",
	"obligation.length-canonical-7",
	"obligation.mask-equation",
	"obligation.mask-involution",
	"obligation.preallocation-cap",
	"obligation.role-masking",
	"surface.adapter.byte-stream",
	"surface.close.status-code",
	"surface.close.terminal-state",
	"surface.concurrency.command-order",
	"surface.control.ping-pong",
	"surface.errors.protocol-fault",
	"surface.fragmentation.continuation",
	"surface.framing.frame-octets",
	"surface.framing.masking",
	"surface.handshake.client-request",
	"surface.handshake.server-response",
	"surface.limits.allocation",
	"surface.messages.binary",
	"surface.messages.text-utf8",
	"surface.websocket-open",
}

func buildCoverageProjection(rootPath, relativeSummary, schemaVersion, relativeJavaReceipt string) (coverageProjection, error) {
	release, err := coverageReleaseFor(schemaVersion)
	if err != nil {
		return coverageProjection{}, err
	}
	root, err := filepath.Abs(rootPath)
	if err != nil {
		return coverageProjection{}, err
	}
	value, err := verify(root, relativeSummary)
	if err != nil {
		return coverageProjection{}, fmt.Errorf("Kani receipt: %w", err)
	}
	qualification, err := provenance.LoadAndValidateCurrentHeadQualification(root)
	if err != nil {
		return coverageProjection{}, fmt.Errorf("current-head qualification: %w", err)
	}
	head, err := gitOutput(root, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return coverageProjection{}, errors.New("projection basis commit is unavailable")
	}
	tree, err := gitOutput(root, "rev-parse", "--verify", head+"^{tree}")
	if err != nil {
		return coverageProjection{}, errors.New("projection basis tree is unavailable")
	}
	catalog, catalogBody, err := bindCurrentArtifact(root, head, coverageCatalogPath)
	if err != nil {
		return coverageProjection{}, err
	}
	receiptBinding, _, err := bindCurrentArtifact(root, head, relativeSummary)
	if err != nil {
		return coverageProjection{}, err
	}
	qualificationBinding, _, err := bindCurrentArtifact(root, head, provenance.CurrentHeadQualificationPath)
	if err != nil {
		return coverageProjection{}, err
	}
	catalogValue, err := decodeCoverageCatalog(catalogBody)
	if err != nil {
		return coverageProjection{}, err
	}
	var javaBinding *gitArtifactBinding
	javaCovered := map[string]bool{}
	if relativeJavaReceipt != "" {
		if release.Version == coverageSchemaVersion {
			return coverageProjection{}, errors.New("schema 1.0.0 cannot represent Java coverage; project under 1.1.0")
		}
		binding, javaBody, bindErr := bindCurrentArtifact(root, head, relativeJavaReceipt)
		if bindErr != nil {
			return coverageProjection{}, fmt.Errorf("Java receipt: %w", bindErr)
		}
		javaValue, decodeErr := decodeJavaFormalReceipt(javaBody)
		if decodeErr != nil {
			return coverageProjection{}, fmt.Errorf("Java receipt: %w", decodeErr)
		}
		catalogSet := make(map[string]bool, len(catalogValue.ObligationIDs))
		for _, obligationID := range catalogValue.ObligationIDs {
			catalogSet[obligationID] = true
		}
		javaCovered, err = deriveJavaCoverage(catalogValue.JavaBindings, catalogSet, javaValue)
		if err != nil {
			return coverageProjection{}, fmt.Errorf("Java receipt: %w", err)
		}
		javaBinding = &binding
	}
	rows, counts, blockers, err := deriveCoverageForRelease(release, catalogValue, value, javaCovered)
	if err != nil {
		return coverageProjection{}, err
	}
	projection := coverageProjection{
		Schema:                   release.SchemaReference,
		SchemaVersion:            release.Version,
		EvidenceKind:             coverageEvidenceKind,
		JavaReceipt:              javaBinding,
		ProjectionBasis:          gitIdentity{Commit: head, Tree: tree, ObjectFormat: "sha1"},
		Catalog:                  catalog,
		KaniReceipt:              receiptBinding,
		CurrentHeadQualification: qualificationBinding,
		QualifiedSource: qualifiedSourceBinding{
			QualifiedCommit: qualification.QualifiedCommit,
			BindingCount:    qualification.BindingCount,
		},
		ProofSubject: gitIdentity{
			Commit:       value.Subject.Commit,
			Tree:         value.Subject.Tree,
			ObjectFormat: value.Subject.ObjectFormat,
		},
		Coverage:                 rows,
		Counts:                   counts,
		Blockers:                 blockers,
		Status:                   coverageStatus,
		ClaimScope:               coverageClaimScope,
		Limitations:              exactCoverageLimitationsFor(release, counts),
		Assurance:                assurance,
		IndependentReviewClaimed: false,
		Production:               false,
		Signing:                  false,
		Publication:              false,
	}
	if err := validateCoverageProjection(root, projection); err != nil {
		return coverageProjection{}, fmt.Errorf("generated coverage projection is invalid: %w", err)
	}
	body, err := json.Marshal(projection)
	if err != nil {
		return coverageProjection{}, err
	}
	if err := validateCoverageSchema(root, release.SchemaPath, body); err != nil {
		return coverageProjection{}, fmt.Errorf("generated coverage projection fails schema: %w", err)
	}
	return projection, nil
}

func verifyCoverage(rootPath, relativePath string) (coverageProjection, error) {
	if !safeRelativePath(relativePath) {
		return coverageProjection{}, errors.New("coverage path must be repository-relative")
	}
	root, err := filepath.Abs(rootPath)
	if err != nil {
		return coverageProjection{}, err
	}
	body, err := readBoundedRegular(filepath.Join(root, filepath.FromSlash(relativePath)))
	if err != nil {
		return coverageProjection{}, err
	}
	var value coverageProjection
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return coverageProjection{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return coverageProjection{}, errors.New("coverage contains trailing JSON")
	}
	release, err := coverageReleaseFor(value.SchemaVersion)
	if err != nil {
		return coverageProjection{}, err
	}
	if err := validateCoverageSchema(root, release.SchemaPath, body); err != nil {
		return coverageProjection{}, fmt.Errorf("coverage schema validation: %w", err)
	}
	if err := validateCoverageProjection(root, value); err != nil {
		return coverageProjection{}, err
	}
	return value, nil
}

func validateCoverageProjection(rootPath string, value coverageProjection) error {
	root, err := filepath.Abs(rootPath)
	if err != nil {
		return err
	}
	release, err := coverageReleaseFor(value.SchemaVersion)
	if err != nil {
		return err
	}
	if value.Schema != release.SchemaReference ||
		value.EvidenceKind != coverageEvidenceKind || value.Status != coverageStatus ||
		value.ClaimScope != coverageClaimScope || value.Assurance != assurance ||
		value.IndependentReviewClaimed || value.Production || value.Signing || value.Publication ||
		!reflect.DeepEqual(value.Limitations, exactCoverageLimitationsFor(release, value.Counts)) {
		return errors.New("coverage posture is inflated or incomplete")
	}
	if release.Version == coverageSchemaVersion && value.JavaReceipt != nil {
		return errors.New("schema 1.0.0 cannot carry a Java receipt binding")
	}
	if !hexCommit.MatchString(value.ProjectionBasis.Commit) || !hexCommit.MatchString(value.ProjectionBasis.Tree) ||
		value.ProjectionBasis.ObjectFormat != "sha1" {
		return errors.New("projection basis identity is invalid")
	}
	resolvedTree, err := gitOutput(root, "rev-parse", "--verify", value.ProjectionBasis.Commit+"^{tree}")
	if err != nil || resolvedTree != value.ProjectionBasis.Tree {
		return errors.New("projection basis commit/tree binding is unavailable or inconsistent")
	}
	catalogBody, err := verifyCoverageArtifact(root, value.ProjectionBasis.Commit, value.Catalog)
	if err != nil {
		return err
	}
	receiptBody, err := verifyCoverageArtifact(root, value.ProjectionBasis.Commit, value.KaniReceipt)
	if err != nil {
		return err
	}
	qualificationBody, err := verifyCoverageArtifact(root, value.ProjectionBasis.Commit, value.CurrentHeadQualification)
	if err != nil {
		return err
	}
	if value.Catalog.Path != coverageCatalogPath || value.CurrentHeadQualification.Path != provenance.CurrentHeadQualificationPath {
		return errors.New("coverage input paths are not canonical")
	}
	receiptDirectory := filepath.Join(root, filepath.FromSlash(filepath.Dir(value.KaniReceipt.Path)))
	receiptValue, err := verifyReceiptDocument(root, receiptDirectory, receiptBody)
	if err != nil {
		return fmt.Errorf("Kani receipt: %w", err)
	}
	if value.ProofSubject != (gitIdentity{Commit: receiptValue.Subject.Commit, Tree: receiptValue.Subject.Tree, ObjectFormat: receiptValue.Subject.ObjectFormat}) {
		return errors.New("proof subject does not match the verified Kani receipt")
	}
	qualification, err := provenance.ValidateCurrentHeadQualification(root, qualificationBody)
	if err != nil {
		return fmt.Errorf("current-head qualification: %w", err)
	}
	if value.QualifiedSource != (qualifiedSourceBinding{QualifiedCommit: qualification.QualifiedCommit, BindingCount: qualification.BindingCount}) {
		return errors.New("qualified source identity does not match the verified current-head receipt")
	}
	catalog, err := decodeCoverageCatalog(catalogBody)
	if err != nil {
		return err
	}
	javaCovered, err := javaCoverageForProjection(root, catalog, value)
	if err != nil {
		return err
	}
	wantRows, wantCounts, wantBlockers, err := deriveCoverageForRelease(release, catalog, receiptValue, javaCovered)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(value.Coverage, wantRows) || !reflect.DeepEqual(value.Counts, wantCounts) || !reflect.DeepEqual(value.Blockers, wantBlockers) {
		return errors.New("coverage rows, counts, or blockers do not reconcile with the verified 24-obligation catalog and Kani receipt")
	}
	return nil
}

// javaCoverageForProjection re-verifies the cited Java receipt, if any, through the
// same git binding and content checks every other coverage input goes through.
func javaCoverageForProjection(root string, catalog coverageCatalog, value coverageProjection) (map[string]bool, error) {
	if value.JavaReceipt == nil {
		return map[string]bool{}, nil
	}
	body, err := verifyCoverageArtifact(root, value.ProjectionBasis.Commit, *value.JavaReceipt)
	if err != nil {
		return nil, fmt.Errorf("Java receipt: %w", err)
	}
	javaValue, err := decodeJavaFormalReceipt(body)
	if err != nil {
		return nil, fmt.Errorf("Java receipt: %w", err)
	}
	catalogSet := make(map[string]bool, len(catalog.ObligationIDs))
	for _, obligationID := range catalog.ObligationIDs {
		catalogSet[obligationID] = true
	}
	covered, err := deriveJavaCoverage(catalog.JavaBindings, catalogSet, javaValue)
	if err != nil {
		return nil, fmt.Errorf("Java receipt: %w", err)
	}
	return covered, nil
}

func decodeJavaFormalReceipt(body []byte) (javaFormalReceipt, error) {
	var value javaFormalReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return javaFormalReceipt{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return javaFormalReceipt{}, errors.New("Java receipt contains trailing JSON")
	}
	return value, nil
}

func deriveCoverage(obligationIDs []string, value receipt) ([]coverageRow, coverageCounts, []coverageBlocker, error) {
	rustCovered := map[string]bool{}
	for _, harness := range value.Execution.Harnesses {
		for _, obligationID := range harness.ObligationIDs {
			rustCovered[obligationID] = true
		}
	}
	mutationCovered := map[string]bool{}
	for _, mutation := range value.Execution.MutationCanaries {
		if mutation.Status != "COUNTEREXAMPLE" {
			continue
		}
		for _, obligationID := range mutation.ObligationIDs {
			mutationCovered[obligationID] = true
		}
	}
	catalogSet := make(map[string]bool, len(obligationIDs))
	for _, obligationID := range obligationIDs {
		catalogSet[obligationID] = true
	}
	for obligationID := range rustCovered {
		if !catalogSet[obligationID] {
			return nil, coverageCounts{}, nil, fmt.Errorf("Kani harness references obligation outside catalog: %s", obligationID)
		}
	}
	for obligationID := range mutationCovered {
		if !catalogSet[obligationID] || !rustCovered[obligationID] {
			return nil, coverageCounts{}, nil, fmt.Errorf("mutation coverage lacks a cataloged passing harness: %s", obligationID)
		}
	}
	rows := make([]coverageRow, 0, len(obligationIDs))
	missingRust := make([]string, 0)
	missingMutation := make([]string, 0)
	for _, obligationID := range obligationIDs {
		rustStatus := coverageBlocked
		mutationStatus := coverageBlocked
		blockerIDs := []string{"blocker-independent-host", "blocker-java-formal-bindings", "blocker-production-refinement"}
		if rustCovered[obligationID] {
			rustStatus = coverageSatisfied
		} else {
			missingRust = append(missingRust, obligationID)
			blockerIDs = append(blockerIDs, "blocker-kani-production-coverage")
		}
		if mutationCovered[obligationID] {
			mutationStatus = coverageSatisfied
		} else {
			missingMutation = append(missingMutation, obligationID)
			blockerIDs = append(blockerIDs, "blocker-kani-mutation-coverage")
		}
		sort.Strings(blockerIDs)
		rows = append(rows, coverageRow{
			ObligationID:     obligationID,
			JavaStatus:       coverageBlocked,
			RustStatus:       rustStatus,
			RefinementStatus: coverageBlocked,
			MutationStatus:   mutationStatus,
			AggregateStatus:  coverageBlocked,
			BlockerIDs:       blockerIDs,
		})
	}
	counts := coverageCounts{
		Required:            len(obligationIDs),
		JavaSatisfied:       0,
		RustSatisfied:       len(rustCovered),
		RustBlocked:         len(obligationIDs) - len(rustCovered),
		RefinementSatisfied: 0,
		MutationSatisfied:   len(mutationCovered),
		MutationBlocked:     len(obligationIDs) - len(mutationCovered),
		AggregateSatisfied:  0,
		AggregateBlocked:    len(obligationIDs),
	}
	blockers := []coverageBlocker{
		{BlockerID: "blocker-independent-host", Code: "INDEPENDENT_REPLAY_ABSENT", UncoveredObligationIDs: append([]string(nil), obligationIDs...)},
		{BlockerID: "blocker-java-formal-bindings", Code: "JAVA_FORMAL_BINDINGS_ABSENT", UncoveredObligationIDs: append([]string(nil), obligationIDs...)},
		{BlockerID: "blocker-kani-mutation-coverage", Code: "RUST_MUTATION_KANI_ABSENT", UncoveredObligationIDs: missingMutation},
		{BlockerID: "blocker-kani-production-coverage", Code: "RUST_PRODUCTION_KANI_ABSENT", UncoveredObligationIDs: missingRust},
		{BlockerID: "blocker-production-refinement", Code: "JAVA_RUST_REFINEMENT_ABSENT", UncoveredObligationIDs: append([]string(nil), obligationIDs...)},
	}
	return rows, counts, blockers, nil
}

// deriveCoverageForRelease routes to the derivation the projection's schema
// version declares. The 1.0.0 path is deriveCoverage, unchanged, so every retained
// projection replays byte for byte.
func deriveCoverageForRelease(release coverageRelease, catalog coverageCatalog, value receipt, javaCovered map[string]bool) ([]coverageRow, coverageCounts, []coverageBlocker, error) {
	switch release.Version {
	case coverageSchemaVersion:
		if len(javaCovered) != 0 {
			return nil, coverageCounts{}, nil, errors.New("schema 1.0.0 cannot represent Java coverage; project under 1.1.0")
		}
		return deriveCoverage(catalog.ObligationIDs, value)
	case coverageSchemaVersionV11:
		return deriveCoverageV11(catalog, value, javaCovered)
	default:
		return nil, coverageCounts{}, nil, fmt.Errorf("unknown coverage schema version: %s", release.Version)
	}
}

// deriveCoverageV11 is the 1.1.0 derivation. It differs from 1.0.0 only in that
// the Java axis is real rather than pinned to zero. Refinement and aggregate are
// separate axes with separate blockers and are deliberately left untouched.
func deriveCoverageV11(catalog coverageCatalog, value receipt, javaCovered map[string]bool) ([]coverageRow, coverageCounts, []coverageBlocker, error) {
	obligationIDs := catalog.ObligationIDs
	catalogSet := make(map[string]bool, len(obligationIDs))
	for _, obligationID := range obligationIDs {
		catalogSet[obligationID] = true
	}

	// The join that 1.0.0 never performed. An obligation earns rust credit only
	// when a harness both declares it AND targets the production symbol the catalog
	// binds for it. Proving a callee says nothing about the caller's dispatch,
	// ordering, or state gating, which is exactly what a step-bound obligation
	// asserts; crediting it anyway is a production-linkage overclaim.
	rustCovered := map[string]bool{}
	rustSupporting := map[string]bool{}
	harnessSymbols := map[string]string{}
	for _, harness := range value.Execution.Harnesses {
		harnessSymbols[harness.HarnessID] = harness.TargetSymbol
		for _, obligationID := range harness.ObligationIDs {
			if !catalogSet[obligationID] {
				return nil, coverageCounts{}, nil, fmt.Errorf("Kani harness references obligation outside catalog: %s", obligationID)
			}
			if catalog.RustBindings[obligationID] == harness.TargetSymbol {
				rustCovered[obligationID] = true
			} else {
				rustSupporting[obligationID] = true
			}
		}
	}
	for obligationID := range rustCovered {
		delete(rustSupporting, obligationID)
	}

	// Mutation sensitivity is credited on the same terms: the killed canary's
	// harness must itself prove the bound symbol, and the obligation must already
	// hold direct rust linkage.
	mutationCovered := map[string]bool{}
	for _, mutation := range value.Execution.MutationCanaries {
		if mutation.Status != "COUNTEREXAMPLE" {
			continue
		}
		for _, obligationID := range mutation.ObligationIDs {
			if !catalogSet[obligationID] {
				return nil, coverageCounts{}, nil, fmt.Errorf("mutation canary references obligation outside catalog: %s", obligationID)
			}
			if !rustCovered[obligationID] {
				continue
			}
			if catalog.RustBindings[obligationID] != harnessSymbols[mutation.HarnessID] {
				continue
			}
			mutationCovered[obligationID] = true
		}
	}
	for obligationID := range javaCovered {
		if !catalogSet[obligationID] {
			return nil, coverageCounts{}, nil, fmt.Errorf("Java evidence references obligation outside catalog: %s", obligationID)
		}
	}

	rows := make([]coverageRow, 0, len(obligationIDs))
	missingJava := make([]string, 0)
	missingRust := make([]string, 0)
	missingMutation := make([]string, 0)
	for _, obligationID := range obligationIDs {
		javaStatus := coverageBlocked
		rustStatus := coverageBlocked
		mutationStatus := coverageBlocked
		blockerIDs := []string{"blocker-independent-host", "blocker-production-refinement"}
		if javaCovered[obligationID] {
			javaStatus = coverageSatisfied
		} else {
			missingJava = append(missingJava, obligationID)
			blockerIDs = append(blockerIDs, "blocker-java-formal-bindings")
		}
		if rustCovered[obligationID] {
			rustStatus = coverageSatisfied
		} else {
			missingRust = append(missingRust, obligationID)
			blockerIDs = append(blockerIDs, "blocker-kani-production-coverage")
		}
		if mutationCovered[obligationID] {
			mutationStatus = coverageSatisfied
		} else {
			missingMutation = append(missingMutation, obligationID)
			blockerIDs = append(blockerIDs, "blocker-kani-mutation-coverage")
		}
		sort.Strings(blockerIDs)
		linkage := "ABSENT"
		if rustCovered[obligationID] {
			linkage = "DIRECT"
		} else if rustSupporting[obligationID] {
			linkage = "SUPPORTING"
		}
		rows = append(rows, coverageRow{
			ObligationID:     obligationID,
			JavaStatus:       javaStatus,
			RustStatus:       rustStatus,
			RefinementStatus: coverageBlocked,
			MutationStatus:   mutationStatus,
			AggregateStatus:  coverageBlocked,
			BlockerIDs:       blockerIDs,
			RustLinkage:      linkage,
		})
	}
	supporting := len(rustSupporting)
	counts := coverageCounts{
		Required:            len(obligationIDs),
		JavaSatisfied:       len(javaCovered),
		RustSatisfied:       len(rustCovered),
		RustBlocked:         len(obligationIDs) - len(rustCovered),
		RefinementSatisfied: 0,
		MutationSatisfied:   len(mutationCovered),
		MutationBlocked:     len(obligationIDs) - len(mutationCovered),
		AggregateSatisfied:  0,
		AggregateBlocked:    len(obligationIDs),
		RustSupporting:      &supporting,
	}
	blockers := []coverageBlocker{
		{BlockerID: "blocker-independent-host", Code: "INDEPENDENT_REPLAY_ABSENT", UncoveredObligationIDs: append([]string(nil), obligationIDs...)},
		{BlockerID: "blocker-java-formal-bindings", Code: "JAVA_FORMAL_BINDINGS_ABSENT", UncoveredObligationIDs: missingJava},
		{BlockerID: "blocker-kani-mutation-coverage", Code: "RUST_MUTATION_KANI_ABSENT", UncoveredObligationIDs: missingMutation},
		{BlockerID: "blocker-kani-production-coverage", Code: "RUST_PRODUCTION_KANI_ABSENT", UncoveredObligationIDs: missingRust},
		{BlockerID: "blocker-production-refinement", Code: "JAVA_RUST_REFINEMENT_ABSENT", UncoveredObligationIDs: append([]string(nil), obligationIDs...)},
	}
	return rows, counts, blockers, nil
}

func decodeCoverageCatalog(body []byte) (coverageCatalog, error) {
	var catalog obligationCatalogProjection
	if err := json.Unmarshal(body, &catalog); err != nil {
		return coverageCatalog{}, fmt.Errorf("catalog decode: %w", err)
	}
	if catalog.SchemaVersion != coverageCatalogVersion || catalog.CatalogID != coverageCatalogID || len(catalog.Obligations) != coverageRequiredCount {
		return coverageCatalog{}, errors.New("formal obligation catalog identity or denominator is invalid")
	}
	ids := make([]string, len(catalog.Obligations))
	for index, obligation := range catalog.Obligations {
		ids[index] = obligation.ObligationID
	}
	if !reflect.DeepEqual(ids, exactCoverageObligationIDs) {
		return coverageCatalog{}, errors.New("formal obligation catalog IDs or canonical order drifted")
	}
	javaBindings, err := indexCatalogBindings(catalog.JavaBindings, "JAVA", ids)
	if err != nil {
		return coverageCatalog{}, err
	}
	rustBindings, err := indexCatalogBindings(catalog.RustBindings, "RUST", ids)
	if err != nil {
		return coverageCatalog{}, err
	}
	return coverageCatalog{ObligationIDs: ids, JavaBindings: javaBindings, RustBindings: rustBindings}, nil
}

// indexCatalogBindings turns the catalog's binding list into an obligation-keyed
// lookup, requiring exactly one binding of the expected language per obligation.
func indexCatalogBindings(bindings []catalogBinding, language string, ids []string) (map[string]string, error) {
	indexed := make(map[string]string, len(bindings))
	for _, binding := range bindings {
		if binding.Language != language {
			return nil, fmt.Errorf("catalog %s binding for %s has language %s", language, binding.ObligationID, binding.Language)
		}
		if binding.ProductionSymbol == "" {
			return nil, fmt.Errorf("catalog %s binding for %s has no production symbol", language, binding.ObligationID)
		}
		if _, duplicate := indexed[binding.ObligationID]; duplicate {
			return nil, fmt.Errorf("catalog %s binding for %s is duplicated", language, binding.ObligationID)
		}
		indexed[binding.ObligationID] = binding.ProductionSymbol
	}
	for _, obligationID := range ids {
		if _, ok := indexed[obligationID]; !ok {
			return nil, fmt.Errorf("catalog has no %s binding for %s", language, obligationID)
		}
	}
	return indexed, nil
}

func bindCurrentArtifact(root, commit, relativePath string) (gitArtifactBinding, []byte, error) {
	if !safeRelativePath(relativePath) {
		return gitArtifactBinding{}, nil, fmt.Errorf("artifact path is unsafe: %s", relativePath)
	}
	body, err := readBoundedRegular(filepath.Join(root, filepath.FromSlash(relativePath)))
	if err != nil {
		return gitArtifactBinding{}, nil, err
	}
	blob, err := gitOutput(root, "rev-parse", "--verify", commit+":"+relativePath)
	if err != nil || !hexCommit.MatchString(blob) {
		return gitArtifactBinding{}, nil, fmt.Errorf("artifact is not committed at projection basis: %s", relativePath)
	}
	committed, err := gitBytes(root, "show", commit+":"+relativePath)
	if err != nil || !bytes.Equal(body, committed) {
		return gitArtifactBinding{}, nil, fmt.Errorf("artifact differs from projection basis: %s", relativePath)
	}
	return gitArtifactBinding{Path: relativePath, SHA256: digestBytes(body), GitBlob: blob}, body, nil
}

func verifyCoverageArtifact(root, commit string, binding gitArtifactBinding) ([]byte, error) {
	if !safeRelativePath(binding.Path) || !hexDigest.MatchString(binding.SHA256) || !hexCommit.MatchString(binding.GitBlob) {
		return nil, errors.New("coverage artifact binding is malformed")
	}
	blob, err := gitOutput(root, "rev-parse", "--verify", commit+":"+binding.Path)
	if err != nil || blob != binding.GitBlob {
		return nil, fmt.Errorf("coverage artifact Git binding failed for %s", binding.Path)
	}
	committed, err := gitBytes(root, "show", commit+":"+binding.Path)
	if err != nil || digestBytes(committed) != binding.SHA256 {
		return nil, fmt.Errorf("coverage artifact content binding failed for %s", binding.Path)
	}
	return committed, nil
}

func validateCoverageSchema(root, schemaPath string, document []byte) error {
	schemaBody, err := readBoundedRegular(filepath.Join(root, filepath.FromSlash(schemaPath)))
	if err != nil {
		return err
	}
	schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBody))
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource("mem:///kani-formal-coverage.json", schemaValue); err != nil {
		return err
	}
	schema, err := compiler.Compile("mem:///kani-formal-coverage.json")
	if err != nil {
		return err
	}
	documentValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(document))
	if err != nil {
		return err
	}
	return schema.Validate(documentValue)
}

// exactCoverageLimitationsFor returns the limitation text a projection must carry
// for its schema version.
func exactCoverageLimitationsFor(release coverageRelease, counts coverageCounts) []string {
	if release.Version == coverageSchemaVersionV11 {
		return exactCoverageLimitationsV11(counts)
	}
	return exactCoverageLimitations(counts)
}

func exactCoverageLimitationsV11(counts coverageCounts) []string {
	javaText := "Java formal bindings are absent for all 24 obligations."
	if counts.JavaSatisfied > 0 {
		javaText = fmt.Sprintf("Java formal evidence covers %d of 24 obligations on their cataloged bound symbols.", counts.JavaSatisfied)
	}
	supporting := 0
	if counts.RustSupporting != nil {
		supporting = *counts.RustSupporting
	}
	return []string{
		"Rust status is credited only when a harness in the verified retained Kani receipt targets the production symbol the catalog binds for that obligation; a harness's self-declared obligation label alone is not sufficient.",
		javaText,
		"Java-to-Rust refinement is absent for all 24 obligations, so aggregate formal coverage is 0/24; refinement and aggregate are separate axes with separate blockers and are unchanged by this schema version.",
		fmt.Sprintf("%d of 24 obligations have direct Kani linkage to their bound symbol and %d have only supporting evidence on a leaf that symbol calls; supporting evidence is reported separately and is never summed into rust_satisfied.", counts.RustSatisfied, supporting),
		fmt.Sprintf("%s obligations have no retained shipped-symbol Kani harness; %s have no obligation-specific killed exact source mutation on the bound symbol.", coverageCountText(counts.RustBlocked), strings.ToLower(coverageCountText(counts.MutationBlocked))),
		"The Kani execution is owner-attested on one darwin/arm64 host and is not independent-host evidence; no sbx isolation, Autobahn rerun, production deployment, signing, publication, or cutover is claimed.",
	}
}

func exactCoverageLimitations(counts coverageCounts) []string {
	return []string{
		"Rust status is credited only from the verified retained shipped-symbol Kani receipt; its logs, source bindings, toolchain, replay, and exact source mutations are transitively validated.",
		"Java formal bindings and Java-to-Rust refinement are absent for all 24 obligations, so aggregate formal coverage is 0/24.",
		fmt.Sprintf("%s obligations have no retained shipped-symbol Kani harness; %s have no obligation-specific killed exact source mutation.", coverageCountText(counts.RustBlocked), strings.ToLower(coverageCountText(counts.MutationBlocked))),
		"The Kani execution is owner-attested on one darwin/arm64 host and is not independent-host evidence.",
		"No sbx isolation, Autobahn rerun, production deployment, signing, publication, or cutover is claimed.",
	}
}

func coverageCountText(value int) string {
	switch value {
	case 13:
		return "Thirteen"
	case 15:
		return "Fifteen"
	default:
		return fmt.Sprintf("%d", value)
	}
}

func writeCoverageProjection(rootPath, relativePath string, value coverageProjection) error {
	if !safeRelativePath(relativePath) {
		return errors.New("coverage output path must be repository-relative")
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(relativePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
