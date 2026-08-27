// Package formalplan implements the US-006 formal preflight validation.
//
// Lane C (this file) owns the backend-qualification document rules and the
// preflight orchestration across the three US-006 documents. Lanes A and B
// own their sibling files (targets.go, model.go, concurrency.go) with deep
// rules for the proof-targets document, the connection model, and the
// concurrency plan; this preflight invokes ALL of those deep validators
// (reality round 1, BLOCKING-2a) and merges their findings into one verdict,
// with typed findings for every absence.
//
// Design constraints (US-006 ACs + the build-decision document):
//   - No parallel validation stack: findings use the incumbent
//     foundation/protocol Finding type and dispositions, outcomes use the
//     foundation ProofObligation lattice verbatim (there is no skip value),
//     and executed records must satisfy the foundation EvidenceRun/replay
//     completeness field set (third_party/verified-java-to-rust-foundation/
//     foundation/evidence.go, validateReplayBundles / assurance ceilings).
//   - One distinct typed finding code per failure family — no catch-all code.
//   - Records may claim only as far as executions actually went: selection,
//     positive outcomes, canary detections, and receipts all require an
//     executed sbx record, and placeholder receipts on unexecuted records
//     block.
package formalplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/michaellady/verified-java-websocket-port/internal/portplan"
)

// isFullSha256Digest accepts only a complete "sha256:" + 64-lowercase-hex
// digest; a bare prefix or short/uppercase hex is not a digested value.
func isFullSha256Digest(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, c := range value[len(prefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

const (
	ModeFormalPreflight = "FORMAL_PREFLIGHT"
	ModeFormalReplay    = "FORMAL_REPLAY"

	preflightSchemaVersion = "1.0.0"
	preflightVerdictKind   = "formal-preflight-verdict"
	preflightAssurance     = "OWNER_ATTESTED_NOT_INDEPENDENT"

	BackendQualificationDocumentPath = "assurance/formal/backend-qualification.json"
	BackendQualificationSchemaPath   = "schemas/formal-backend-qualification-1.0.0.schema.json"
	ProofTargetsSchemaPath           = "schemas/formal-proof-targets-1.0.0.schema.json"
	ConcurrencyPlanDocumentPath      = "assurance/concurrency/plan.json"
	ConcurrencyPlanSchemaPath        = "schemas/concurrency-plan-1.0.0.schema.json"
	ConnectionModelTLAPath           = "assurance/formal/connection-model.tla"
	ConnectionModelCfgPath           = "assurance/formal/connection-model.cfg"

	sbxTemplateSourcePath       = "security/sbx-template.json"
	sandboxPolicySourcePath     = "security/sandbox-policy.json"
	corpusCalibrationSourcePath = "evidence/corpus-calibration.json"
)

// proofOutcomeLattice mirrors the foundation ProofObligation outcome lattice
// (third_party/verified-java-to-rust-foundation/foundation/evidence.go,
// validateProofObligations). "skip" is deliberately not a value.
var proofOutcomeLattice = map[string]int{
	"unsupported":       0,
	"disconnected":      0,
	"inconclusive":      1,
	"stale":             1,
	"model_observation": 2,
	"trace_observation": 3,
	"BoundedCheckPassed": 4,
	"ProofEstablished":   5,
}

// foundationLabelCeilings mirrors validateAssuranceProfiles in the foundation
// evidence validator.
var foundationLabelCeilings = map[string]string{
	"observed":                     "LAB",
	"differential":                 "LAB",
	"bounded":                      "CANDIDATE",
	"proved-model":                 "CANDIDATE",
	"proved-production/refinement": "PUBLISHED",
}

// foundationEvidenceRunFields mirrors the completeness predicate of
// validateReplayBundles in the foundation evidence validator: an executed
// backend record must bind every one of these.
var foundationEvidenceRunFields = []string{
	"source_revision", "specification_revision", "java_revision", "rust_revision",
	"java_semantic_ids", "rust_semantic_ids", "command", "working_directory",
	"tool_hashes", "container_hashes", "environment", "seed", "hardware",
	"assumptions", "bounds", "unsupported_constructs", "trusted_base",
	"exit_count", "obligation_count", "raw_log_ids", "artifact_ids",
	"normalized_diff_id", "counterexample_or_corpus_ids", "replay_command",
}

type PreflightRequest struct {
	RootPath string `json:"root_path"`
}

type PreflightDocumentStatus struct {
	Path          string `json:"path"`
	SchemaPath    string `json:"schema_path"`
	Present       bool   `json:"present"`
	SchemaPresent bool   `json:"schema_present"`
	Findings      int    `json:"findings"`
}

type PreflightVerdict struct {
	SchemaVersion                     string                    `json:"schema_version"`
	Kind                              string                    `json:"kind"`
	State                             string                    `json:"state"`
	Documents                         []PreflightDocumentStatus `json:"documents"`
	ObligationsEvaluated              int                       `json:"obligations_evaluated"`
	ObligationsPassed                 int                       `json:"obligations_passed"`
	ProductionLinkedObligationsPassed int                       `json:"production_linked_obligations_passed"`
	Findings                          []vendorprotocol.Finding  `json:"findings"`
	Assurance                         string                    `json:"assurance"`
	IndependentReviewClaimed          bool                      `json:"independent_review_claimed"`
}

// FormalPreflight evaluates the three US-006 documents against their schemas
// and the lane C deep rules. The evaluation snapshots every input file once
// and is fully deterministic.
func FormalPreflight(request PreflightRequest) (PreflightVerdict, error) {
	return evaluateFormal(request)
}

// FormalReplay re-runs the identical evaluation; preflight and replay verdicts
// over the same tree are byte-identical by construction.
func FormalReplay(request PreflightRequest) (PreflightVerdict, error) {
	return evaluateFormal(request)
}

// --- document model (lane C document only) ----------------------------------

type backendQualificationDocument struct {
	Schema                   string             `json:"$schema"`
	SchemaVersion            string             `json:"schema_version"`
	Kind                     string             `json:"kind"`
	Story                    string             `json:"story"`
	Lane                     string             `json:"lane"`
	Assurance                string             `json:"assurance"`
	IndependentReviewClaimed bool               `json:"independent_review_claimed"`
	AggregateState           string             `json:"aggregate_state"`
	SandboxProfile           sandboxProfile     `json:"sandbox_profile"`
	CanaryVocabulary         canaryVocabulary   `json:"canary_vocabulary"`
	Backends                 []backendRecord    `json:"backends"`
	FoundationBinding        foundationBinding  `json:"foundation_binding"`
	HonestyNotes             []string           `json:"honesty_notes"`
}

type sandboxProfile struct {
	AcceptedAttemptID     string   `json:"accepted_attempt_id"`
	ReceiptReference      string   `json:"receipt_reference"`
	AcceptanceCitations   []string `json:"acceptance_citations"`
	SbxCLIVersion         string   `json:"sbx_cli_version"`
	SbxCLICommit          string   `json:"sbx_cli_commit"`
	SbxCLIBinaryDigest    string   `json:"sbx_cli_binary_digest"`
	SbxDaemonVersion      string   `json:"sbx_daemon_version"`
	TemplateReference     string   `json:"template_reference"`
	TemplateManifestDigest string  `json:"template_manifest_digest"`
	TemplateIndexDigest   string   `json:"template_index_digest"`
	NetworkPolicyDigest   string   `json:"network_policy_digest"`
	SandboxPolicyDigest   string   `json:"sandbox_policy_digest"`
	ProfileSourcePaths    []string `json:"profile_source_paths"`
}

type canaryVocabulary struct {
	Source                    string          `json:"source"`
	RustEnvelopeKillInventory int             `json:"rust_envelope_kill_inventory"`
	Mutants                   []vocabularyMut `json:"mutants"`
}

type vocabularyMut struct {
	ID               string         `json:"id"`
	Kind             string         `json:"kind"`
	LiveKillEvidence string         `json:"live_kill_evidence"`
	Kills            int            `json:"kills"`
	KillBreakdown    map[string]int `json:"kill_breakdown"`
	Signature        string         `json:"signature"`
}

type backendRecord struct {
	BackendID             string              `json:"backend_id"`
	Tool                  backendTool         `json:"tool"`
	Method                string              `json:"method"`
	ClaimScope            string              `json:"claim_scope"`
	AssuranceLabelCeiling string              `json:"assurance_label_ceiling"`
	MaxOutcomeAllowed     string              `json:"max_outcome_allowed"`
	Selected              bool                `json:"selected"`
	SelectionState        string              `json:"selection_state"`
	AvailabilityProbe     availabilityProbe   `json:"availability_probe"`
	SbxExecution          sbxExecution        `json:"sbx_execution"`
	ExpectedProperties    []expectedProperty  `json:"expected_property_inventory"`
	Obligations           []backendObligation `json:"obligations"`
	Canaries              canaryPair          `json:"canaries"`
	Bounds                map[string]any      `json:"bounds"`
	Assumptions           []string            `json:"assumptions"`
	Provenance            []string            `json:"provenance"`
	UnsupportedConstructs []string            `json:"unsupported_constructs"`
	TrustedBase           []string            `json:"trusted_base"`
	RequiredArtifacts     []string            `json:"required_artifacts"`
	OutcomesSummary       outcomesSummary     `json:"outcomes_summary"`
}

type backendTool struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Identity        string `json:"identity"`
	Upstream        string `json:"upstream"`
	VersionObserved string `json:"version_observed"`
}

type availabilityProbe struct {
	Executed       bool           `json:"executed"`
	Venue          string         `json:"venue"`
	Host           string         `json:"host"`
	ProbedAt       string         `json:"probed_at"`
	ProbeSemantics string         `json:"probe_semantics"`
	Commands       []probeCommand `json:"commands"`
	Verdict        string         `json:"verdict"`
}

// probeCommand records one availability-probe invocation byte-honestly
// (re-review round 1 BLOCKING-1): the exact argv and working directory, the
// real exit code, and stdout/stderr captured verbatim as separate streams.
// When a stream is too long to embed whole, the record keeps a verbatim head,
// sets the truncated flag, and binds the full stream with its byte count and
// sha256 — paraphrased or merged output is never a probe record.
type probeCommand struct {
	Argv            string  `json:"argv"`
	Cwd             string  `json:"cwd"`
	ExitCode        *int    `json:"exit_code"`
	Stdout          *string `json:"stdout"`
	Stderr          *string `json:"stderr"`
	StdoutBytes     *int    `json:"stdout_bytes,omitempty"`
	StderrBytes     *int    `json:"stderr_bytes,omitempty"`
	StdoutSHA256    string  `json:"stdout_sha256,omitempty"`
	StderrSHA256    string  `json:"stderr_sha256,omitempty"`
	StdoutTruncated bool    `json:"stdout_truncated,omitempty"`
	StderrTruncated bool    `json:"stderr_truncated,omitempty"`
}

type sbxExecution struct {
	Status              string               `json:"status"`
	Reason              string               `json:"reason"`
	RequiredProfile     string               `json:"required_profile"`
	Receipt             *executionReceipt    `json:"receipt"`
	EvidenceRun         *evidenceRun         `json:"evidence_run"`
	ModelCheckExecution *modelCheckExecution `json:"model_check_execution"`
}

type executionReceipt struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// modelCheckExecution records a real in-sbx execution of the MODEL CHECK
// itself (US-006 attempt us007-sbx-output-live-0125: SANY + TLC on the
// connection model plus the seeded liveness defect) on a backend whose full
// qualification bundle has NOT executed. It pairs exclusively with sbx status
// EXECUTED_MODEL_CHECK_ONLY: receipts are re-hashed against real tree bytes,
// while selection, positive obligation outcomes, known-bad canary claims, and
// pass counting all remain gated on a full EXECUTED record.
type modelCheckExecution struct {
	AttemptID     string             `json:"attempt_id"`
	Authorization string             `json:"authorization"`
	PlanRecord    string             `json:"plan_record"`
	ToolIdentity  string             `json:"tool_identity"`
	ToolSHA256    string             `json:"tool_sha256"`
	JVM           string             `json:"jvm"`
	Receipts      []executionReceipt `json:"receipts"`
	Verdicts      modelCheckVerdicts `json:"verdicts"`
}

type modelCheckVerdicts struct {
	SANY                 string `json:"sany"`
	TLC                  string `json:"tlc"`
	SeededLivenessDefect string `json:"seeded_liveness_defect"`
}

type evidenceRun struct {
	SourceRevision            string         `json:"source_revision"`
	SpecificationRevision     string         `json:"specification_revision"`
	JavaRevision              string         `json:"java_revision"`
	RustRevision              string         `json:"rust_revision"`
	JavaSemanticIDs           []string       `json:"java_semantic_ids"`
	RustSemanticIDs           []string       `json:"rust_semantic_ids"`
	Command                   string         `json:"command"`
	WorkingDirectory          string         `json:"working_directory"`
	ToolHashes                []string       `json:"tool_hashes"`
	ContainerHashes           []string       `json:"container_hashes"`
	Environment               []string       `json:"environment"`
	Seed                      string         `json:"seed"`
	Hardware                  string         `json:"hardware"`
	Assumptions               []string       `json:"assumptions"`
	Bounds                    map[string]any `json:"bounds"`
	UnsupportedConstructs     []string       `json:"unsupported_constructs"`
	TrustedBase               []string       `json:"trusted_base"`
	ExitCount                 *int           `json:"exit_count"`
	ObligationCount           *int           `json:"obligation_count"`
	RawLogIDs                 []string       `json:"raw_log_ids"`
	ArtifactIDs               []string       `json:"artifact_ids"`
	NormalizedDiffID          string         `json:"normalized_diff_id"`
	CounterexampleOrCorpusIDs []string       `json:"counterexample_or_corpus_ids"`
	ReplayCommand             string         `json:"replay_command"`
}

type expectedProperty struct {
	PropertyID    string `json:"property_id"`
	Description   string `json:"description"`
	FormalClaimID string `json:"formal_claim_id"`
}

type backendObligation struct {
	ID                string          `json:"id"`
	Description       string          `json:"description"`
	FormalClaimID     string          `json:"formal_claim_id"`
	JavaAuthority     string          `json:"java_authority"`
	RequiredOutcome   string          `json:"required_outcome"`
	Outcome           string          `json:"outcome"`
	ProductionLink    productionLink  `json:"production_link"`
	ProductionCodeIDs []string        `json:"production_code_ids"`
}

type productionLink struct {
	PlannedSymbol  string `json:"planned_symbol"`
	RustSemanticID string `json:"rust_semantic_id"`
	ResolverStatus string `json:"resolver_status"`
}

type canaryPair struct {
	KnownGood *knownGoodCanary `json:"known_good"`
	KnownBad  *knownBadCanary  `json:"known_bad"`
}

type knownGoodCanary struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type knownBadCanary struct {
	ID                   string `json:"id"`
	MutantID             string `json:"mutant_id"`
	Description          string `json:"description"`
	ExpectedDetection    string `json:"expected_detection"`
	Status               string `json:"status"`
	CounterexampleDigest string `json:"counterexample_digest"`
}

type outcomesSummary struct {
	AvailabilityProbe string `json:"availability_probe"`
	ProofObligations  string `json:"proof_obligations"`
}

type foundationBinding struct {
	EntityPlan                    string              `json:"entity_plan"`
	OutcomeLattice                map[string]int      `json:"outcome_lattice"`
	AssuranceLabelCeilings        map[string]string   `json:"assurance_label_ceilings"`
	RequiredArtifactTypes         map[string][]string `json:"required_artifact_types"`
	EvidenceRunCompletenessFields []string            `json:"evidence_run_completeness_fields"`
}

// --- sbx template subset (acceptance source) --------------------------------

type sbxTemplateSource struct {
	Runtime struct {
		CLIVersion             string `json:"cli_version"`
		CLICommit              string `json:"cli_commit"`
		CLIBinaryDigest        string `json:"cli_binary_digest"`
		DaemonVersion          string `json:"daemon_version"`
		TemplateReference      string `json:"template_reference"`
		TemplateIndexDigest    string `json:"template_index_digest"`
		TemplateManifestDigest string `json:"template_manifest_digest"`
	} `json:"runtime"`
	Isolation struct {
		NetworkPolicy struct {
			CanonicalDigest string `json:"canonical_digest"`
		} `json:"network_policy"`
	} `json:"isolation"`
	SandboxPolicyDigest string `json:"sandbox_policy_digest"`
}

// --- evaluation -------------------------------------------------------------

type formalEvaluation struct {
	root     string
	findings []vendorprotocol.Finding
	perDoc   map[string]int
}

func (evaluation *formalEvaluation) add(code string, disposition vendorprotocol.Disposition, docPath, jsonPath, message string) {
	pathValue := docPath
	if jsonPath != "" {
		pathValue = docPath + "#" + jsonPath
	}
	evaluation.findings = append(evaluation.findings, vendorprotocol.Finding{
		Code:        code,
		Disposition: disposition,
		Path:        pathValue,
		Message:     message,
	})
	evaluation.perDoc[docPath]++
}

func (evaluation *formalEvaluation) readFile(relative string) ([]byte, bool) {
	data, err := os.ReadFile(filepath.Join(evaluation.root, filepath.FromSlash(relative)))
	if err != nil {
		return nil, false
	}
	return data, true
}

func evaluateFormal(request PreflightRequest) (PreflightVerdict, error) {
	if request.RootPath == "" {
		return PreflightVerdict{}, fmt.Errorf("root path is required")
	}
	info, err := os.Stat(request.RootPath)
	if err != nil || !info.IsDir() {
		return PreflightVerdict{}, fmt.Errorf("root %q is not a readable directory", request.RootPath)
	}

	evaluation := &formalEvaluation{root: request.RootPath, perDoc: map[string]int{}}
	verdict := PreflightVerdict{
		SchemaVersion:            preflightSchemaVersion,
		Kind:                     preflightVerdictKind,
		Findings:                 []vendorprotocol.Finding{},
		Assurance:                preflightAssurance,
		IndependentReviewClaimed: false,
	}

	// Every US-006 document receives its lane's DEEP semantic validation, not
	// schema-only validation (reality round 1, BLOCKING-2a): lane C's backend
	// rules run inside this loop; lane A (VerifyProofTargets) and lane B
	// (ValidateConcurrencyPlan + ValidateConnectionModel) run below once the
	// presence pass completes, and their findings merge into this verdict.
	documents := []struct {
		docPath    string
		schemaPath string
		deep       bool
	}{
		{BackendQualificationDocumentPath, BackendQualificationSchemaPath, true},
		{ProofTargetsDocumentPath, ProofTargetsSchemaPath, false},
		{ConcurrencyPlanDocumentPath, ConcurrencyPlanSchemaPath, false},
	}

	for _, document := range documents {
		docData, docPresent := evaluation.readFile(document.docPath)
		schemaData, schemaPresent := evaluation.readFile(document.schemaPath)
		status := PreflightDocumentStatus{
			Path:          document.docPath,
			SchemaPath:    document.schemaPath,
			Present:       docPresent,
			SchemaPresent: schemaPresent,
		}
		if !docPresent {
			evaluation.add("FORMAL_DOCUMENT_ABSENT", vendorprotocol.Block, document.docPath, "",
				"US-006 document is absent from this tree; formal preflight cannot qualify what does not exist")
			status.Findings = evaluation.perDoc[document.docPath]
			verdict.Documents = append(verdict.Documents, status)
			continue
		}

		var rawDocument any
		if err := vendorprotocol.DecodeStrict(docData, &rawDocument); err != nil {
			evaluation.add("FORMAL_DOCUMENT_INVALID", vendorprotocol.Block, document.docPath, "",
				"document is not strict canonical JSON: "+err.Error())
			status.Findings = evaluation.perDoc[document.docPath]
			verdict.Documents = append(verdict.Documents, status)
			continue
		}

		if !schemaPresent {
			evaluation.add("FORMAL_SCHEMA_ABSENT", vendorprotocol.Block, document.docPath, "",
				"schema "+document.schemaPath+" is absent; the document cannot be schema-validated")
		} else {
			if err := validateAgainstSchema(document.schemaPath, schemaData, rawDocument); err != nil {
				evaluation.add("FORMAL_SCHEMA_VALIDATION_FAILED", vendorprotocol.Block, document.docPath, "",
					"schema validation failed: "+compactError(err))
			}
		}

		if document.deep {
			evaluateBackendQualification(evaluation, docData, rawDocument, &verdict)
		}

		status.Findings = evaluation.perDoc[document.docPath]
		verdict.Documents = append(verdict.Documents, status)
	}

	// Lane A and lane B deep semantic validation (reality round 1,
	// BLOCKING-2a) plus the cross-artifact close-delivery consistency check
	// (BLOCKING-1d). Each runs only when its artifact is present; absence is
	// already a blocking FORMAL_DOCUMENT_ABSENT finding above.
	evaluateProofTargetsDeep(evaluation)
	evaluateConcurrencyPlanDeep(evaluation)
	evaluateCloseDeliveryConsistency(evaluation)

	sort.SliceStable(evaluation.findings, func(left, right int) bool {
		if evaluation.findings[left].Code != evaluation.findings[right].Code {
			return evaluation.findings[left].Code < evaluation.findings[right].Code
		}
		if evaluation.findings[left].Path != evaluation.findings[right].Path {
			return evaluation.findings[left].Path < evaluation.findings[right].Path
		}
		return evaluation.findings[left].Message < evaluation.findings[right].Message
	})
	if evaluation.findings == nil {
		evaluation.findings = []vendorprotocol.Finding{}
	}
	verdict.Findings = evaluation.findings

	// Recompute per-document counts after all rules ran.
	for index := range verdict.Documents {
		verdict.Documents[index].Findings = evaluation.perDoc[verdict.Documents[index].Path]
	}

	// Fail-closed: ANY finding blocks, including DEGRADE_NON_ASSURANCE
	// advisories (a citation set that could not be verified is not a pass).
	verdict.State = "OK"
	if len(verdict.Findings) != 0 {
		verdict.State = "BLOCKED"
	}
	return verdict, nil
}

// trimRootPrefix removes the evaluation root from paths and messages so
// verdicts are root-independent and byte-comparable across checkouts.
func trimRootPrefix(root, text string) string {
	cleaned := strings.TrimSuffix(filepath.ToSlash(root), "/") + "/"
	return strings.ReplaceAll(text, cleaned, "")
}

// evaluateProofTargetsDeep runs lane A's full semantic validation
// (claim-ID bijection against the migration map, digest-pinned quarantined
// Java anchors, symbol namespaces, invokers, AC1 coverage, live handshake
// evidence, strictness deltas) whenever the proof-targets document is
// present. Every lane A finding is blocking.
func evaluateProofTargetsDeep(evaluation *formalEvaluation) {
	if _, present := evaluation.readFile(ProofTargetsDocumentPath); !present {
		return
	}
	report := VerifyProofTargets(evaluation.root)
	for _, finding := range report.Findings {
		evaluation.add(finding.Code, vendorprotocol.Block, ProofTargetsDocumentPath,
			trimRootPrefix(evaluation.root, finding.Path),
			trimRootPrefix(evaluation.root, finding.Message))
	}
}

// evaluateConcurrencyPlanDeep runs lane B's full semantic validation of the
// concurrency plan AND the connection-model artifact whenever the plan
// document is present. Blocking lane B findings block; advisory findings
// (citation resolution without a quarantine tree) merge with the
// DEGRADE_NON_ASSURANCE disposition and still fail the preflight closed.
func evaluateConcurrencyPlanDeep(evaluation *formalEvaluation) {
	if _, present := evaluation.readFile(ConcurrencyPlanDocumentPath); !present {
		return
	}
	root := evaluation.root
	absolute := func(relative string) string {
		return filepath.Join(root, filepath.FromSlash(relative))
	}
	javaRoot := ""
	if treePath, err := portplan.EnsureQuarantinedSource(root); err == nil {
		javaRoot = filepath.Join(treePath, "src", "main", "java", "org", "java_websocket")
	}
	merge := func(docPath string, findings []ModelFinding) {
		for _, finding := range findings {
			disposition := vendorprotocol.Block
			if finding.Severity == SeverityAdvisory {
				disposition = vendorprotocol.DegradeNonAssurance
			}
			jsonPath := trimRootPrefix(root, finding.Path)
			if jsonPath == docPath {
				jsonPath = ""
			}
			evaluation.add(finding.Code, disposition, docPath, jsonPath,
				trimRootPrefix(root, finding.Detail))
		}
	}
	merge(ConnectionModelTLAPath, ValidateConnectionModel(
		absolute(ConnectionModelTLAPath), absolute(ConnectionModelCfgPath), javaRoot))
	merge(ConcurrencyPlanDocumentPath, ValidateConcurrencyPlan(ConcurrencyPlanInputs{
		PlanPath:           absolute(ConcurrencyPlanDocumentPath),
		SchemaPath:         absolute(ConcurrencyPlanSchemaPath),
		TLAPath:            absolute(ConnectionModelTLAPath),
		CfgPath:            absolute(ConnectionModelCfgPath),
		LedgerPath:         absolute(targetsDeltaLedgerPath),
		ReceiptRoot:        root,
		QuarantineJavaRoot: javaRoot,
	}))
}

func validateAgainstSchema(schemaPath string, schemaData []byte, document any) error {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.AssertContent()
	var resource any
	if err := json.Unmarshal(schemaData, &resource); err != nil {
		return fmt.Errorf("schema is not valid JSON: %w", err)
	}
	if err := compiler.AddResource("mem:///"+schemaPath, resource); err != nil {
		return err
	}
	schema, err := compiler.Compile("mem:///" + schemaPath)
	if err != nil {
		return err
	}
	return schema.Validate(document)
}

func compactError(err error) string {
	message := err.Error()
	message = strings.ReplaceAll(message, "\n", " ")
	message = strings.Join(strings.Fields(message), " ")
	const limit = 512
	if len(message) > limit {
		message = message[:limit]
	}
	return message
}

// evaluateBackendQualification applies the lane C deep rules.
func evaluateBackendQualification(evaluation *formalEvaluation, docData []byte, rawDocument any, verdict *PreflightVerdict) {
	docPath := BackendQualificationDocumentPath

	var document backendQualificationDocument
	if err := vendorprotocol.DecodeStrict(docData, &document); err != nil {
		evaluation.add("FORMAL_DOCUMENT_INVALID", vendorprotocol.Block, docPath, "",
			"document does not decode into the qualification record shape: "+err.Error())
		return
	}

	scanForSkipRepresentations(evaluation, docPath, rawDocument, "$")
	validateSandboxProfileBinding(evaluation, docPath, document.SandboxProfile)
	validateFoundationContract(evaluation, docPath, document.FoundationBinding)

	vocabulary := make(map[string]bool, len(document.CanaryVocabulary.Mutants))
	for _, mutant := range document.CanaryVocabulary.Mutants {
		vocabulary[mutant.ID] = true
	}

	for index, backend := range document.Backends {
		basePath := fmt.Sprintf("$.backends[%d]", index)
		executed := backend.SbxExecution.Status == "EXECUTED"
		modelCheckOnly := backend.SbxExecution.Status == "EXECUTED_MODEL_CHECK_ONLY"

		// Pass accounting (re-review round 1 BLOCKING-3): an obligation may
		// count as passed only when its outcome is a genuine lattice pass AND
		// the execution record satisfies the foundation EvidenceRun
		// completeness predicate (receipt verified against real bytes,
		// every completeness field bound) AND the backend's canary pair is
		// healthy (known-good PASSED, known-bad DETECTED with a digested
		// counterexample). Incomplete evidence or a FAILED/NOT_EXECUTED
		// canary excludes the pass — the typed finding records why. Canaries
		// left NOT_EXECUTED are legitimate only on backends that are
		// themselves NOT_EXECUTED, which never count passes at all.
		evidenceComplete := false

		if !backend.AvailabilityProbe.Executed {
			evaluation.add("BACKEND_PROBE_NOT_EXECUTED", vendorprotocol.Block, docPath, basePath+".availability_probe.executed",
				backend.BackendID+": availability probe was not executed; qualification records require a real probe with recorded output")
		} else if len(backend.AvailabilityProbe.Commands) == 0 {
			evaluation.add("PROBE_OUTPUT_MISSING", vendorprotocol.Block, docPath, basePath+".availability_probe.commands",
				backend.BackendID+": executed probe records no commands; probes must record real argv, exit code, and output snippets")
		} else {
			for commandIndex, command := range backend.AvailabilityProbe.Commands {
				commandPath := fmt.Sprintf("%s.availability_probe.commands[%d]", basePath, commandIndex)
				if command.Argv == "" || command.Cwd == "" || command.ExitCode == nil || command.Stdout == nil || command.Stderr == nil {
					evaluation.add("PROBE_OUTPUT_MISSING", vendorprotocol.Block, docPath, commandPath,
						backend.BackendID+": probe command must record argv, cwd, exit_code, and verbatim per-stream stdout/stderr")
				}
				if command.StdoutTruncated && (command.StdoutSHA256 == "" || command.StdoutBytes == nil) {
					evaluation.add("PROBE_OUTPUT_MISSING", vendorprotocol.Block, docPath, commandPath+".stdout",
						backend.BackendID+": a truncated stdout must bind the full stream with stdout_sha256 and stdout_bytes")
				}
				if command.StderrTruncated && (command.StderrSHA256 == "" || command.StderrBytes == nil) {
					evaluation.add("PROBE_OUTPUT_MISSING", vendorprotocol.Block, docPath, commandPath+".stderr",
						backend.BackendID+": a truncated stderr must bind the full stream with stderr_sha256 and stderr_bytes")
				}
			}
		}

		if backend.Selected && (!backend.AvailabilityProbe.Executed || !executed) {
			evaluation.add("BACKEND_SELECTED_WITHOUT_EXECUTION", vendorprotocol.Block, docPath, basePath+".selected",
				backend.BackendID+": a backend may be selected only after an executed availability probe AND a completed sbx execution inside the accepted profile")
		}

		if !executed && backend.SbxExecution.Receipt != nil {
			evaluation.add("PLACEHOLDER_EXECUTION_RECEIPT", vendorprotocol.Block, docPath, basePath+".sbx_execution.receipt",
				backend.BackendID+": a receipt on a NOT_EXECUTED record is a claims-shaped placeholder; receipts exist only for real executions (a model-check-only execution carries its receipts inside model_check_execution)")
		}

		if executed {
			evidenceComplete = validateExecutedRecord(evaluation, docPath, basePath, backend, len(document.Backends[index].Obligations))
		}
		if modelCheckOnly {
			validateModelCheckOnlyRecord(evaluation, docPath, basePath, backend)
		} else if backend.SbxExecution.ModelCheckExecution != nil {
			evaluation.add("MODEL_CHECK_EXECUTION_UNVERIFIED", vendorprotocol.Block, docPath, basePath+".sbx_execution.model_check_execution",
				backend.BackendID+": a model_check_execution record pairs exclusively with status EXECUTED_MODEL_CHECK_ONLY")
		}
		canariesHealthy := validateCanaries(evaluation, docPath, basePath, backend, vocabulary, backend.SbxExecution.Status)
		countable := executed && evidenceComplete && canariesHealthy

		if len(backend.Obligations) == 0 {
			evaluation.add("ZERO_BACKEND_OBLIGATIONS", vendorprotocol.Block, docPath, basePath+".obligations",
				backend.BackendID+": every qualified backend must carry nonzero proof obligations")
		}

		maxRank, maxKnown := proofOutcomeLattice[backend.MaxOutcomeAllowed]
		for obligationIndex, obligation := range backend.Obligations {
			obligationPath := fmt.Sprintf("%s.obligations[%d]", basePath, obligationIndex)
			outcomeRank, outcomeKnown := proofOutcomeLattice[obligation.Outcome]
			requiredRank, requiredKnown := proofOutcomeLattice[obligation.RequiredOutcome]

			if outcomeKnown && maxKnown && outcomeRank > maxRank {
				evaluation.add("INFLATED_BACKEND_CLAIM", vendorprotocol.Block, docPath, obligationPath+".outcome",
					backend.BackendID+": outcome "+obligation.Outcome+" exceeds this backend's ceiling "+backend.MaxOutcomeAllowed+" ("+backend.ClaimScope+")")
			}
			if requiredKnown && maxKnown && requiredRank > maxRank {
				evaluation.add("INFLATED_BACKEND_CLAIM", vendorprotocol.Block, docPath, obligationPath+".required_outcome",
					backend.BackendID+": required outcome "+obligation.RequiredOutcome+" exceeds this backend's ceiling "+backend.MaxOutcomeAllowed)
			}
			if outcomeKnown && outcomeRank >= 2 && !executed {
				evaluation.add("UNAVAILABLE_BACKEND_CLAIM", vendorprotocol.Block, docPath, obligationPath+".outcome",
					backend.BackendID+": positive outcome "+obligation.Outcome+" recorded without an executed sbx run; unavailable or unexecuted backends block their own claims and cannot be represented as inferred success")
			}

			verdict.ObligationsEvaluated++
			if countable && outcomeKnown && requiredKnown && outcomeRank >= requiredRank && outcomeRank >= 2 {
				// Reality round 1, BLOCKING-2b: a genuine lattice pass with no
				// resolvable production link is a DISCONNECTED PROOF — it gets
				// a typed blocking finding and is excluded from BOTH pass
				// counters; a pass that proves nothing about production code
				// must never be countable as progress.
				if productionLinked(evaluation.root, obligation.ProductionCodeIDs) {
					verdict.ObligationsPassed++
					verdict.ProductionLinkedObligationsPassed++
				} else {
					evaluation.add("DISCONNECTED_PROOF", vendorprotocol.Block, docPath, obligationPath+".production_code_ids",
						backend.BackendID+": obligation "+obligation.ID+" passes its required outcome but binds no resolvable production code; a proof disconnected from production is excluded from both pass counters")
				}
			}
		}
	}
}

// validateExecutedRecord checks an executed backend record against the
// foundation EvidenceRun completeness predicate and reports whether the record
// is complete: a verified receipt (real bytes, matching digest) plus every
// completeness field bound. Only a complete record may contribute to the pass
// counters (re-review round 1 BLOCKING-3).
func validateExecutedRecord(evaluation *formalEvaluation, docPath, basePath string, backend backendRecord, obligationCount int) bool {
	complete := true
	execution := backend.SbxExecution
	if execution.Receipt == nil || execution.Receipt.Path == "" || execution.Receipt.SHA256 == "" {
		evaluation.add("EVIDENCE_RUN_INCOMPLETE", vendorprotocol.Block, docPath, basePath+".sbx_execution.receipt",
			backend.BackendID+": an executed record requires a real receipt with path and digest")
		complete = false
	} else {
		receiptData, present := evaluation.readFile(execution.Receipt.Path)
		if !present {
			evaluation.add("EVIDENCE_RUN_INCOMPLETE", vendorprotocol.Block, docPath, basePath+".sbx_execution.receipt.path",
				backend.BackendID+": receipt file "+execution.Receipt.Path+" does not exist in this tree")
			complete = false
		} else {
			digest := sha256.Sum256(receiptData)
			if "sha256:"+hex.EncodeToString(digest[:]) != execution.Receipt.SHA256 {
				evaluation.add("EVIDENCE_RUN_INCOMPLETE", vendorprotocol.Block, docPath, basePath+".sbx_execution.receipt.sha256",
					backend.BackendID+": receipt digest does not match the receipt bytes")
				complete = false
			}
		}
	}

	run := execution.EvidenceRun
	if run == nil {
		evaluation.add("EVIDENCE_RUN_INCOMPLETE", vendorprotocol.Block, docPath, basePath+".sbx_execution.evidence_run",
			backend.BackendID+": an executed record requires an EvidenceRun-complete execution record (foundation completeness predicate)")
		return false
	}
	missing := missingEvidenceRunFields(run)
	if len(missing) != 0 {
		evaluation.add("EVIDENCE_RUN_INCOMPLETE", vendorprotocol.Block, docPath, basePath+".sbx_execution.evidence_run",
			backend.BackendID+": execution record is missing EvidenceRun completeness fields: "+strings.Join(missing, ", "))
		complete = false
	}
	if run.ObligationCount != nil && *run.ObligationCount != obligationCount {
		evaluation.add("EVIDENCE_RUN_INCOMPLETE", vendorprotocol.Block, docPath, basePath+".sbx_execution.evidence_run.obligation_count",
			fmt.Sprintf("%s: obligation_count %d must equal the backend's declared obligations %d", backend.BackendID, *run.ObligationCount, obligationCount))
		complete = false
	}
	return complete
}

func missingEvidenceRunFields(run *evidenceRun) []string {
	var missing []string
	requireString := func(name, value string) {
		if value == "" {
			missing = append(missing, name)
		}
	}
	requireList := func(name string, values []string) {
		if len(values) == 0 {
			missing = append(missing, name)
		}
	}
	requireString("source_revision", run.SourceRevision)
	requireString("specification_revision", run.SpecificationRevision)
	requireString("java_revision", run.JavaRevision)
	requireString("rust_revision", run.RustRevision)
	requireList("java_semantic_ids", run.JavaSemanticIDs)
	requireList("rust_semantic_ids", run.RustSemanticIDs)
	requireString("command", run.Command)
	requireString("working_directory", run.WorkingDirectory)
	requireList("tool_hashes", run.ToolHashes)
	requireList("container_hashes", run.ContainerHashes)
	requireList("environment", run.Environment)
	requireString("seed", run.Seed)
	requireString("hardware", run.Hardware)
	requireList("assumptions", run.Assumptions)
	if len(run.Bounds) == 0 {
		missing = append(missing, "bounds")
	}
	if run.UnsupportedConstructs == nil {
		missing = append(missing, "unsupported_constructs")
	}
	requireList("trusted_base", run.TrustedBase)
	if run.ExitCount == nil || *run.ExitCount < 0 {
		missing = append(missing, "exit_count")
	}
	if run.ObligationCount == nil || *run.ObligationCount < 0 {
		missing = append(missing, "obligation_count")
	}
	requireList("raw_log_ids", run.RawLogIDs)
	requireList("artifact_ids", run.ArtifactIDs)
	requireString("normalized_diff_id", run.NormalizedDiffID)
	requireList("counterexample_or_corpus_ids", run.CounterexampleOrCorpusIDs)
	requireString("replay_command", run.ReplayCommand)
	return missing
}

// validateModelCheckOnlyRecord checks an EXECUTED_MODEL_CHECK_ONLY record:
// a real model-check execution must bind its attempt, authorization, plan
// record, tool digest, JVM, per-check verdicts, and a receipt set whose every
// digest re-hashes against the actual bytes in this tree. One typed code
// covers the family: an unverifiable model-check execution record blocks.
func validateModelCheckOnlyRecord(evaluation *formalEvaluation, docPath, basePath string, backend backendRecord) {
	recordPath := basePath + ".sbx_execution.model_check_execution"
	record := backend.SbxExecution.ModelCheckExecution
	if record == nil {
		evaluation.add("MODEL_CHECK_EXECUTION_UNVERIFIED", vendorprotocol.Block, docPath, recordPath,
			backend.BackendID+": status EXECUTED_MODEL_CHECK_ONLY requires the model_check_execution record (attempt id, tool digest, digest-verified receipts)")
		return
	}
	if record.AttemptID == "" || record.Authorization == "" || record.PlanRecord == "" ||
		record.ToolIdentity == "" || record.JVM == "" ||
		record.Verdicts.SANY == "" || record.Verdicts.TLC == "" || record.Verdicts.SeededLivenessDefect == "" {
		evaluation.add("MODEL_CHECK_EXECUTION_UNVERIFIED", vendorprotocol.Block, docPath, recordPath,
			backend.BackendID+": the model-check execution record must bind attempt id, authorization, plan record, tool identity, JVM, and per-check verdicts")
	}
	if !isFullSha256Digest(record.ToolSHA256) {
		evaluation.add("MODEL_CHECK_EXECUTION_UNVERIFIED", vendorprotocol.Block, docPath, recordPath+".tool_sha256",
			backend.BackendID+": the model-check execution record must pin the tool with a full sha256 digest recorded at fetch")
	}
	if len(record.Receipts) == 0 {
		evaluation.add("MODEL_CHECK_EXECUTION_UNVERIFIED", vendorprotocol.Block, docPath, recordPath+".receipts",
			backend.BackendID+": a model-check execution without receipts is a claims-shaped placeholder")
		return
	}
	for index, receipt := range record.Receipts {
		receiptPath := fmt.Sprintf("%s.receipts[%d]", recordPath, index)
		if receipt.Path == "" || !isFullSha256Digest(receipt.SHA256) {
			evaluation.add("MODEL_CHECK_EXECUTION_UNVERIFIED", vendorprotocol.Block, docPath, receiptPath,
				backend.BackendID+": every model-check receipt must name an in-tree path and a full sha256 digest")
			continue
		}
		raw, present := evaluation.readFile(receipt.Path)
		if !present {
			evaluation.add("MODEL_CHECK_EXECUTION_UNVERIFIED", vendorprotocol.Block, docPath, receiptPath+".path",
				backend.BackendID+": model-check receipt "+receipt.Path+" does not exist in this tree")
			continue
		}
		digest := sha256.Sum256(raw)
		if "sha256:"+hex.EncodeToString(digest[:]) != receipt.SHA256 {
			evaluation.add("MODEL_CHECK_EXECUTION_UNVERIFIED", vendorprotocol.Block, docPath, receiptPath+".sha256",
				backend.BackendID+": model-check receipt digest does not match the receipt bytes of "+receipt.Path)
		}
	}
}

// validateCanaries applies the canary rules and reports whether the backend's
// canary pair is healthy enough to admit obligation passes: the pair exists,
// the known-bad mutant is inside the vocabulary, the known-good canary PASSED,
// and the known-bad canary was DETECTED with a digested counterexample. A
// FAILED (SURVIVED) or NOT_EXECUTED canary on an executed backend excludes
// every pass (re-review round 1 BLOCKING-3); unexecuted backends return false
// trivially because they can never count passes. A model-check-only execution
// (EXECUTED_MODEL_CHECK_ONLY) may record its known-good canary as PASSED —
// the clean model-check run IS the known-good check, receipts re-hashed by
// validateModelCheckOnlyRecord — but its known-bad canary stays NOT_EXECUTED
// and no pass is ever countable.
func validateCanaries(evaluation *formalEvaluation, docPath, basePath string, backend backendRecord, vocabulary map[string]bool, status string) bool {
	canaries := backend.Canaries
	if canaries.KnownGood == nil || canaries.KnownBad == nil {
		evaluation.add("MISSING_CANARY_PAIR", vendorprotocol.Block, docPath, basePath+".canaries",
			backend.BackendID+": every backend must declare both a known-good and a known-bad canary")
		return false
	}
	healthy := true
	if !vocabulary[canaries.KnownBad.MutantID] {
		evaluation.add("MISSING_CANARY_PAIR", vendorprotocol.Block, docPath, basePath+".canaries.known_bad.mutant_id",
			backend.BackendID+": known-bad canary mutant "+canaries.KnownBad.MutantID+" is outside the US-005 planted-mutant vocabulary")
		healthy = false
	}
	switch status {
	case "EXECUTED":
		if canaries.KnownGood.Status != "PASSED" {
			evaluation.add("CANARY_NOT_CONFIRMED", vendorprotocol.Block, docPath, basePath+".canaries.known_good.status",
				backend.BackendID+": executed backend must confirm its known-good canary (status PASSED)")
			healthy = false
		}
		if canaries.KnownBad.Status != "DETECTED" || !isFullSha256Digest(canaries.KnownBad.CounterexampleDigest) {
			evaluation.add("KNOWN_BAD_CANARY_SURVIVED", vendorprotocol.Block, docPath, basePath+".canaries.known_bad",
				backend.BackendID+": executed backend must detect its known-bad canary with a digested counterexample; a surviving seeded defect fails qualification")
			healthy = false
		}
		return healthy
	case "EXECUTED_MODEL_CHECK_ONLY":
		if canaries.KnownGood.Status != "NOT_EXECUTED" && canaries.KnownGood.Status != "PASSED" {
			evaluation.add("CANARY_CLAIM_WITHOUT_EXECUTION", vendorprotocol.Block, docPath, basePath+".canaries.known_good.status",
				backend.BackendID+": a model-check-only execution may record its known-good canary only as NOT_EXECUTED or PASSED (the clean model-check run is the known-good check itself)")
		}
		if canaries.KnownBad.Status != "NOT_EXECUTED" {
			evaluation.add("CANARY_CLAIM_WITHOUT_EXECUTION", vendorprotocol.Block, docPath, basePath+".canaries.known_bad.status",
				backend.BackendID+": the model-check-only execution did not run the declared known-bad canary mutation; its result may be recorded only by a full executed qualification run")
		}
		return false
	default:
		if canaries.KnownGood.Status != "NOT_EXECUTED" || canaries.KnownBad.Status != "NOT_EXECUTED" {
			evaluation.add("CANARY_CLAIM_WITHOUT_EXECUTION", vendorprotocol.Block, docPath, basePath+".canaries",
				backend.BackendID+": canary results are claimed without an executed sbx run; outcomes may be recorded only as far as executions actually went")
		}
		return false
	}
}

func validateSandboxProfileBinding(evaluation *formalEvaluation, docPath string, profile sandboxProfile) {
	templateData, present := evaluation.readFile(sbxTemplateSourcePath)
	if !present {
		evaluation.add("SBX_PROFILE_SOURCE_ABSENT", vendorprotocol.Block, docPath, "$.sandbox_profile",
			"accepted profile source "+sbxTemplateSourcePath+" is absent; the pinned digest set cannot be verified")
	} else {
		var source sbxTemplateSource
		if err := json.Unmarshal(templateData, &source); err != nil {
			evaluation.add("SBX_PROFILE_SOURCE_ABSENT", vendorprotocol.Block, docPath, "$.sandbox_profile",
				"accepted profile source "+sbxTemplateSourcePath+" does not decode: "+err.Error())
		} else {
			var mismatched []string
			compare := func(name, got, want string) {
				if got != want {
					mismatched = append(mismatched, name)
				}
			}
			compare("sbx_cli_version", profile.SbxCLIVersion, source.Runtime.CLIVersion)
			compare("sbx_cli_commit", profile.SbxCLICommit, source.Runtime.CLICommit)
			compare("sbx_cli_binary_digest", profile.SbxCLIBinaryDigest, source.Runtime.CLIBinaryDigest)
			compare("template_reference", profile.TemplateReference, source.Runtime.TemplateReference)
			compare("template_manifest_digest", profile.TemplateManifestDigest, source.Runtime.TemplateManifestDigest)
			compare("template_index_digest", profile.TemplateIndexDigest, source.Runtime.TemplateIndexDigest)
			compare("network_policy_digest", profile.NetworkPolicyDigest, source.Isolation.NetworkPolicy.CanonicalDigest)
			compare("sandbox_policy_digest", profile.SandboxPolicyDigest, source.SandboxPolicyDigest)
			if len(mismatched) != 0 {
				evaluation.add("SBX_PROFILE_DIGEST_MISMATCH", vendorprotocol.Block, docPath, "$.sandbox_profile",
					"pinned profile digests diverge from the accepted profile source ("+sbxTemplateSourcePath+"): "+strings.Join(mismatched, ", "))
			}
		}
	}

	// Byte-level pin reconciliation (re-review round 1 BLOCKING-2): a pinned
	// digest nobody re-hashes is not a pin — the same defect class as the
	// US-005 AC5 manifest-pin gap. Of the pinned profile digest set, exactly
	// one digest names bytes that live in this repository:
	// sandbox_policy_digest is the sha256 over the raw bytes of
	// security/sandbox-policy.json (verified here against the real file).
	// The CLI-binary, template, and network-policy digests describe
	// out-of-repo artifacts (host sbx binary, registry image, live sbx
	// policy rule); they are bound by the pin-vs-source comparison above and
	// by the accepted attempt's operator receipt, and cannot be re-hashed
	// from repo bytes.
	policyData, present := evaluation.readFile(sandboxPolicySourcePath)
	if !present {
		evaluation.add("PROFILE_ARTIFACT_UNREADABLE", vendorprotocol.Block, docPath, "$.sandbox_profile.sandbox_policy_digest",
			"pinned profile artifact "+sandboxPolicySourcePath+" cannot be read; the sandbox_policy_digest pin cannot be reconciled against real bytes")
	} else {
		policyDigest := sha256.Sum256(policyData)
		actual := "sha256:" + hex.EncodeToString(policyDigest[:])
		if actual != profile.SandboxPolicyDigest {
			evaluation.add("PROFILE_DIGEST_MISMATCH", vendorprotocol.Block, docPath, "$.sandbox_profile.sandbox_policy_digest",
				"pinned sandbox_policy_digest "+profile.SandboxPolicyDigest+" does not match the actual bytes of "+sandboxPolicySourcePath+" ("+actual+"); a stale pin cannot bind the accepted profile")
		}
	}

	calibrationData, present := evaluation.readFile(corpusCalibrationSourcePath)
	if !present {
		evaluation.add("ACCEPTANCE_EVIDENCE_ABSENT", vendorprotocol.Block, docPath, "$.sandbox_profile.accepted_attempt_id",
			"acceptance evidence "+corpusCalibrationSourcePath+" is absent; the attempt binding cannot be verified")
		return
	}
	if profile.AcceptedAttemptID == "" || !bytes.Contains(calibrationData, []byte(profile.AcceptedAttemptID)) {
		evaluation.add("STALE_SBX_ATTEMPT_BINDING", vendorprotocol.Block, docPath, "$.sandbox_profile.accepted_attempt_id",
			"accepted attempt "+profile.AcceptedAttemptID+" is not cited by "+corpusCalibrationSourcePath+"; the profile binding must pin the CURRENT accepted live attempt")
	}
}

func validateFoundationContract(evaluation *formalEvaluation, docPath string, binding foundationBinding) {
	if len(binding.OutcomeLattice) != len(proofOutcomeLattice) {
		evaluation.add("FOUNDATION_CONTRACT_MISMATCH", vendorprotocol.Block, docPath, "$.foundation_binding.outcome_lattice",
			"declared outcome lattice does not match the foundation ProofObligation lattice")
	} else {
		for outcome, rank := range proofOutcomeLattice {
			if binding.OutcomeLattice[outcome] != rank {
				evaluation.add("FOUNDATION_CONTRACT_MISMATCH", vendorprotocol.Block, docPath, "$.foundation_binding.outcome_lattice."+outcome,
					"declared rank diverges from the foundation lattice")
			}
		}
	}
	for label, ceiling := range binding.AssuranceLabelCeilings {
		if foundationLabelCeilings[label] != ceiling {
			evaluation.add("FOUNDATION_CONTRACT_MISMATCH", vendorprotocol.Block, docPath, "$.foundation_binding.assurance_label_ceilings."+label,
				"declared readiness ceiling diverges from the foundation assurance profiles")
		}
	}
	declared := map[string]bool{}
	for _, field := range binding.EvidenceRunCompletenessFields {
		declared[field] = true
	}
	for _, field := range foundationEvidenceRunFields {
		if !declared[field] {
			evaluation.add("FOUNDATION_CONTRACT_MISMATCH", vendorprotocol.Block, docPath, "$.foundation_binding.evidence_run_completeness_fields",
				"declared completeness fields omit foundation-required field "+field)
		}
	}
}

// scanForSkipRepresentations walks the raw document and blocks any outcome or
// status represented as a skip: the outcome vocabulary is closed and has no
// skip value, so a skip can only be an attempt to represent an unavailable
// backend as something other than blocking.
func scanForSkipRepresentations(evaluation *formalEvaluation, docPath string, node any, jsonPath string) {
	switch value := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := value[key]
			childPath := jsonPath + "." + key
			if text, ok := child.(string); ok && (key == "outcome" || key == "required_outcome" || key == "status") {
				lowered := strings.ToLower(text)
				if lowered == "skip" || lowered == "skipped" || lowered == "inferred_success" {
					evaluation.add("UNAVAILABLE_REPRESENTED_AS_SKIP", vendorprotocol.Block, docPath, childPath,
						"outcome vocabulary has no skip value; unavailable backends block their own claims and cannot be represented as skips or inferred success")
				}
			}
			scanForSkipRepresentations(evaluation, docPath, child, childPath)
		}
	case []any:
		for index, child := range value {
			scanForSkipRepresentations(evaluation, docPath, child, fmt.Sprintf("%s[%d]", jsonPath, index))
		}
	}
}

// productionLinked resolves each production_code_id as BOTH halves of the
// "path#symbol" contract: the file must exist AND, when a fragment is given,
// the file's bytes must contain the symbol token. Textual containment is a
// documented pre-resolver approximation (rust identities remain
// RUST_IDENTITIES_NOT_YET_RESOLVER_VERIFIED); it cannot confirm the symbol's
// kind or scope, but it does refuse a link to a file that never mentions the
// symbol at all — the round-2 integration-review gap.
func productionLinked(root string, productionCodeIDs []string) bool {
	if len(productionCodeIDs) == 0 {
		return false
	}
	for _, codeID := range productionCodeIDs {
		file, symbol, hasFragment := strings.Cut(codeID, "#")
		if file == "" {
			return false
		}
		path := filepath.Join(root, filepath.FromSlash(file))
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return false
		}
		if hasFragment {
			if symbol == "" {
				return false
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Contains(raw, []byte(symbol)) {
				return false
			}
		}
	}
	return true
}
