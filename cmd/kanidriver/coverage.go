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
)

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
}

type coverageBlocker struct {
	BlockerID              string   `json:"blocker_id"`
	Code                   string   `json:"code"`
	UncoveredObligationIDs []string `json:"uncovered_obligation_ids"`
}

type coverageProjection struct {
	Schema                   string                 `json:"$schema"`
	SchemaVersion            string                 `json:"schema_version"`
	EvidenceKind             string                 `json:"evidence_kind"`
	ProjectionBasis          gitIdentity            `json:"projection_basis"`
	Catalog                  gitArtifactBinding     `json:"catalog"`
	KaniReceipt              gitArtifactBinding     `json:"kani_receipt"`
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

func buildCoverageProjection(rootPath, relativeSummary string) (coverageProjection, error) {
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
	obligationIDs, err := decodeCoverageCatalog(catalogBody)
	if err != nil {
		return coverageProjection{}, err
	}
	rows, counts, blockers, err := deriveCoverage(obligationIDs, value)
	if err != nil {
		return coverageProjection{}, err
	}
	projection := coverageProjection{
		Schema:                   coverageSchemaReference,
		SchemaVersion:            coverageSchemaVersion,
		EvidenceKind:             coverageEvidenceKind,
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
		Limitations:              exactCoverageLimitations(),
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
	if err := validateCoverageSchema(root, body); err != nil {
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
	if err := validateCoverageSchema(root, body); err != nil {
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
	if value.Schema != coverageSchemaReference || value.SchemaVersion != coverageSchemaVersion ||
		value.EvidenceKind != coverageEvidenceKind || value.Status != coverageStatus ||
		value.ClaimScope != coverageClaimScope || value.Assurance != assurance ||
		value.IndependentReviewClaimed || value.Production || value.Signing || value.Publication ||
		!reflect.DeepEqual(value.Limitations, exactCoverageLimitations()) {
		return errors.New("coverage posture is inflated or incomplete")
	}
	if !hexCommit.MatchString(value.ProjectionBasis.Commit) || !hexCommit.MatchString(value.ProjectionBasis.Tree) ||
		value.ProjectionBasis.ObjectFormat != "sha1" {
		return errors.New("projection basis identity is invalid")
	}
	resolvedTree, err := gitOutput(root, "rev-parse", "--verify", value.ProjectionBasis.Commit+"^{tree}")
	if err != nil || resolvedTree != value.ProjectionBasis.Tree {
		return errors.New("projection basis commit/tree binding is unavailable or inconsistent")
	}
	for _, binding := range []gitArtifactBinding{value.Catalog, value.KaniReceipt, value.CurrentHeadQualification} {
		if err := verifyCoverageArtifact(root, value.ProjectionBasis.Commit, binding); err != nil {
			return err
		}
	}
	if value.Catalog.Path != coverageCatalogPath || value.CurrentHeadQualification.Path != provenance.CurrentHeadQualificationPath {
		return errors.New("coverage input paths are not canonical")
	}
	receiptValue, err := verify(root, value.KaniReceipt.Path)
	if err != nil {
		return fmt.Errorf("Kani receipt: %w", err)
	}
	if value.ProofSubject != (gitIdentity{Commit: receiptValue.Subject.Commit, Tree: receiptValue.Subject.Tree, ObjectFormat: receiptValue.Subject.ObjectFormat}) {
		return errors.New("proof subject does not match the verified Kani receipt")
	}
	qualification, err := provenance.LoadAndValidateCurrentHeadQualification(root)
	if err != nil {
		return fmt.Errorf("current-head qualification: %w", err)
	}
	if value.QualifiedSource != (qualifiedSourceBinding{QualifiedCommit: qualification.QualifiedCommit, BindingCount: qualification.BindingCount}) {
		return errors.New("qualified source identity does not match the verified current-head receipt")
	}
	catalogBody, err := readBoundedRegular(filepath.Join(root, filepath.FromSlash(value.Catalog.Path)))
	if err != nil {
		return err
	}
	obligationIDs, err := decodeCoverageCatalog(catalogBody)
	if err != nil {
		return err
	}
	wantRows, wantCounts, wantBlockers, err := deriveCoverage(obligationIDs, receiptValue)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(value.Coverage, wantRows) || value.Counts != wantCounts || !reflect.DeepEqual(value.Blockers, wantBlockers) {
		return errors.New("coverage rows, counts, or blockers do not reconcile with the verified 24-obligation catalog and Kani receipt")
	}
	return nil
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

func decodeCoverageCatalog(body []byte) ([]string, error) {
	var catalog obligationCatalogProjection
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("catalog decode: %w", err)
	}
	if catalog.SchemaVersion != coverageCatalogVersion || catalog.CatalogID != coverageCatalogID || len(catalog.Obligations) != coverageRequiredCount {
		return nil, errors.New("formal obligation catalog identity or denominator is invalid")
	}
	ids := make([]string, len(catalog.Obligations))
	for index, obligation := range catalog.Obligations {
		ids[index] = obligation.ObligationID
	}
	if !reflect.DeepEqual(ids, exactCoverageObligationIDs) {
		return nil, errors.New("formal obligation catalog IDs or canonical order drifted")
	}
	return ids, nil
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

func verifyCoverageArtifact(root, commit string, binding gitArtifactBinding) error {
	if !safeRelativePath(binding.Path) || !hexDigest.MatchString(binding.SHA256) || !hexCommit.MatchString(binding.GitBlob) {
		return errors.New("coverage artifact binding is malformed")
	}
	blob, err := gitOutput(root, "rev-parse", "--verify", commit+":"+binding.Path)
	if err != nil || blob != binding.GitBlob {
		return fmt.Errorf("coverage artifact Git binding failed for %s", binding.Path)
	}
	committed, err := gitBytes(root, "show", commit+":"+binding.Path)
	if err != nil || digestBytes(committed) != binding.SHA256 {
		return fmt.Errorf("coverage artifact content binding failed for %s", binding.Path)
	}
	current, err := readBoundedRegular(filepath.Join(root, filepath.FromSlash(binding.Path)))
	if err != nil || !bytes.Equal(current, committed) {
		return fmt.Errorf("coverage artifact is stale at current checkout: %s", binding.Path)
	}
	return nil
}

func validateCoverageSchema(root string, document []byte) error {
	schemaBody, err := readBoundedRegular(filepath.Join(root, filepath.FromSlash(coverageSchemaPath)))
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

func exactCoverageLimitations() []string {
	return []string{
		"Rust status is credited only from the verified retained shipped-symbol Kani receipt; its logs, source bindings, toolchain, replay, and exact source mutations are transitively validated.",
		"Java formal bindings and Java-to-Rust refinement are absent for all 24 obligations, so aggregate formal coverage is 0/24.",
		"Thirteen obligations have no retained shipped-symbol Kani harness; fifteen have no obligation-specific killed exact source mutation.",
		"The Kani execution is owner-attested on one darwin/arm64 host and is not independent-host evidence.",
		"No sbx isolation, Autobahn rerun, production deployment, signing, publication, or cutover is claimed.",
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
