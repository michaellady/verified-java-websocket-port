package assurance

// CandidateMode selects verification of the committed projection or replay
// from the immutable Git objects named by that projection.
type CandidateMode string

const (
	CandidateVerify CandidateMode = "VERIFY"
	CandidateReplay CandidateMode = "REPLAY"

	candidateAssurance = "OWNER_ATTESTED_NOT_INDEPENDENT"
	candidateStory     = "US-023"
	candidateID        = "verified-java-websocket-port.us023"
)

type CandidateRequest struct {
	RootPath string
	Mode     CandidateMode
}

type GateCounts struct {
	Required  uint64 `json:"required"`
	Satisfied uint64 `json:"satisfied"`
	Blocked   uint64 `json:"blocked"`
}

type Blocker struct {
	BlockerID       string   `json:"blocker_id"`
	Code            string   `json:"code"`
	GateIDs         []string `json:"gate_ids"`
	Subject         string   `json:"subject"`
	EvidenceNodeIDs []string `json:"evidence_node_ids"`
	DetailCode      string   `json:"detail_code"`
}

type Finding struct {
	Code string `json:"code"`
	Path string `json:"path"`
}

type CandidateVerdict struct {
	SnapshotState            string     `json:"snapshot_state"`
	ParityState              string     `json:"parity_state"`
	CandidateRoot            string     `json:"candidate_root"`
	EvaluationRoot           string     `json:"evaluation_root"`
	TargetCommit             string     `json:"target_commit"`
	TargetTree               string     `json:"target_tree"`
	Assurance                string     `json:"assurance"`
	IndependentReviewClaimed bool       `json:"independent_review_claimed"`
	GateCounts               GateCounts `json:"gate_counts"`
	Blockers                 []Blocker  `json:"blockers"`
	Findings                 []Finding  `json:"findings"`
}

type candidateTarget struct {
	Commit       string `json:"commit"`
	Tree         string `json:"tree"`
	ObjectFormat string `json:"object_format"`
}

type candidateGit struct {
	Commit string `json:"commit"`
	Tree   string `json:"tree"`
	Blob   string `json:"blob"`
}

type candidateGraphNode struct {
	ID             string       `json:"id"`
	Kind           string       `json:"kind"`
	Classification string       `json:"classification"`
	Path           string       `json:"path"`
	Bytes          uint64       `json:"bytes"`
	SHA256         string       `json:"sha256"`
	Git            candidateGit `json:"git"`
	SubjectCommit  string       `json:"subject_commit"`
	SubjectTree    string       `json:"subject_tree"`
	Family         string       `json:"family"`
	ExecutionState string       `json:"execution_state"`
	ClaimStrength  string       `json:"claim_strength"`
}

type candidateGraphEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
}

type candidateGraph struct {
	Nodes []candidateGraphNode `json:"nodes"`
	Edges []candidateGraphEdge `json:"edges"`
}

type candidateReplayPaths struct {
	MachineReport    string `json:"machine_report"`
	FormalProjection string `json:"formal_projection"`
	FormalReport     string `json:"formal_report"`
	HumanReport      string `json:"human_report"`
}

type candidateManifest struct {
	Schema                   string               `json:"$schema"`
	SchemaVersion            string               `json:"schema_version"`
	StoryID                  string               `json:"story_id"`
	CandidateID              string               `json:"candidate_id"`
	SnapshotState            string               `json:"snapshot_state"`
	ParityState              string               `json:"parity_state"`
	Assurance                string               `json:"assurance"`
	IndependentReviewClaimed bool                 `json:"independent_review_claimed"`
	Publication              bool                 `json:"publication"`
	Production               bool                 `json:"production"`
	Signing                  bool                 `json:"signing"`
	PerformanceClaimed       bool                 `json:"performance_claimed"`
	CutoverClaimed           bool                 `json:"cutover_claimed"`
	Target                   candidateTarget      `json:"target"`
	Graph                    candidateGraph       `json:"graph"`
	RootNodeID               string               `json:"root_node_id"`
	CandidateRoot            string               `json:"candidate_root"`
	Replay                   candidateReplayPaths `json:"replay"`
}

type prdIdentity struct {
	AcceptanceCriteriaSHA256 string `json:"acceptance_criteria_sha256"`
	E2ESHA256                string `json:"e2e_sha256"`
}

type gateRow struct {
	GateID            string   `json:"gate_id"`
	CriterionID       string   `json:"criterion_id"`
	Required          bool     `json:"required"`
	RequirementSHA256 string   `json:"requirement_sha256"`
	Subject           string   `json:"subject"`
	RequiredState     string   `json:"required_state"`
	ObservedState     string   `json:"observed_state"`
	EvidenceNodeIDs   []string `json:"evidence_node_ids"`
	BlockerIDs        []string `json:"blocker_ids"`
}

type evidenceFamilyRow struct {
	Family                 string   `json:"family"`
	RequiredState          string   `json:"required_state"`
	ObservedState          string   `json:"observed_state"`
	CurrentRustConnection  string   `json:"current_rust_connection"`
	EvidenceNodeIDs        []string `json:"evidence_node_ids"`
	UnresolvedFindingCount uint64   `json:"unresolved_finding_count"`
	DivergenceCount        uint64   `json:"divergence_count"`
	BlockerIDs             []string `json:"blocker_ids"`
}

type candidateClaims struct {
	Schema                   string              `json:"$schema"`
	SchemaVersion            string              `json:"schema_version"`
	StoryID                  string              `json:"story_id"`
	CandidateID              string              `json:"candidate_id"`
	PRDIdentity              prdIdentity         `json:"prd_identity"`
	Gates                    []gateRow           `json:"gates"`
	EvidenceFamilies         []evidenceFamilyRow `json:"evidence_families"`
	Nonclaims                []string            `json:"nonclaims"`
	BlockerCatalog           []Blocker           `json:"blocker_catalog"`
	Assurance                string              `json:"assurance"`
	IndependentReviewClaimed bool                `json:"independent_review_claimed"`
	Publication              bool                `json:"publication"`
	Production               bool                `json:"production"`
	Signing                  bool                `json:"signing"`
}

type observedCounts struct {
	Discovered  uint64 `json:"discovered"`
	Executed    uint64 `json:"executed"`
	Passed      uint64 `json:"passed"`
	Failed      uint64 `json:"failed"`
	Skipped     uint64 `json:"skipped"`
	Filtered    uint64 `json:"filtered"`
	Ignored     uint64 `json:"ignored"`
	Quarantined uint64 `json:"quarantined"`
	TimedOut    uint64 `json:"timed_out"`
}

type attemptTool struct {
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	BinarySHA256 *string `json:"binary_sha256"`
}

type attemptRow struct {
	AttemptID         string         `json:"attempt_id"`
	GateID            string         `json:"gate_id"`
	Platform          string         `json:"platform"`
	Architecture      string         `json:"architecture"`
	ExecutionState    string         `json:"execution_state"`
	BlockerCode       string         `json:"blocker_code"`
	Argv              []string       `json:"argv"`
	WorkingDirectory  *string        `json:"working_directory"`
	EnvironmentSHA256 *string        `json:"environment_sha256"`
	Tool              *attemptTool   `json:"tool"`
	InputRoot         *string        `json:"input_root"`
	OutputSHA256      *string        `json:"output_sha256"`
	StdoutSHA256      *string        `json:"stdout_sha256"`
	StderrSHA256      *string        `json:"stderr_sha256"`
	ExitCode          *int           `json:"exit_code"`
	TimedOut          *bool          `json:"timed_out"`
	DurationMS        *uint64        `json:"duration_ms"`
	ObservedCounts    observedCounts `json:"observed_counts"`
}

type reconciliation struct {
	State            string   `json:"state"`
	AnchorPaths      []string `json:"anchor_paths"`
	PredecessorPaths []string `json:"predecessor_paths"`
	CurrentPaths     []string `json:"current_paths"`
	AddedPaths       []string `json:"added_paths"`
	MissingPaths     []string `json:"missing_paths"`
	ManifestSHA256s  []string `json:"manifest_sha256s"`
	BlockerIDs       []string `json:"blocker_ids"`
}

type attemptCounts struct {
	PlatformAttempts uint64 `json:"platform_attempts"`
	VerifierAttempts uint64 `json:"verifier_attempts"`
	ExecutedPass     uint64 `json:"executed_pass"`
	ExecutedFail     uint64 `json:"executed_fail"`
	NotExecuted      uint64 `json:"not_executed"`
	Unavailable      uint64 `json:"unavailable"`
}

type candidateAttempts struct {
	Schema               string          `json:"$schema"`
	SchemaVersion        string          `json:"schema_version"`
	StoryID              string          `json:"story_id"`
	CandidateID          string          `json:"candidate_id"`
	Target               candidateTarget `json:"target"`
	ChallengeSHA256      string          `json:"challenge_sha256"`
	PlatformAttempts     []attemptRow    `json:"platform_attempts"`
	VerifierAttempts     []attemptRow    `json:"verifier_attempts"`
	TestReconciliation   reconciliation  `json:"test_reconciliation"`
	SourceReconciliation reconciliation  `json:"source_reconciliation"`
	Counts               attemptCounts   `json:"counts"`
}

type artifactIdentity struct {
	Path   string       `json:"path"`
	SHA256 string       `json:"sha256"`
	Git    candidateGit `json:"git"`
}

type formalObligation struct {
	ObligationID          string   `json:"obligation_id"`
	SurfaceIDs            []string `json:"surface_ids"`
	Statement             string   `json:"statement"`
	NormativeRefs         []string `json:"normative_refs"`
	RequiredStrength      string   `json:"required_strength"`
	AllowedMethods        []string `json:"allowed_methods"`
	RequiredEvidenceKinds []string `json:"required_evidence_kinds"`
	RequiredMutationIDs   []string `json:"required_mutation_ids"`
}

type bindingIdentity struct {
	Commit        *string `json:"commit"`
	Tree          *string `json:"tree"`
	Blob          *string `json:"blob"`
	ArchiveSHA256 *string `json:"archive_sha256"`
}

type languageBinding struct {
	ObligationID        string          `json:"obligation_id"`
	Language            string          `json:"language"`
	ProductionSymbol    string          `json:"production_symbol"`
	ItemKind            string          `json:"item_kind"`
	SourcePath          string          `json:"source_path"`
	SourceSHA256        string          `json:"source_sha256"`
	Identity            bindingIdentity `json:"identity"`
	DeclarationIdentity string          `json:"declaration_identity"`
	ReachableFromEntry  bool            `json:"reachable_from_entry"`
	ConnectionState     string          `json:"connection_state"`
	BlockerIDs          []string        `json:"blocker_ids"`
}

type formalBounds struct {
	MaxFrameBytes *uint64 `json:"max_frame_bytes"`
	MaxSteps      *uint64 `json:"max_steps"`
}

type formalAssumptions struct {
	Role      string `json:"role"`
	Allocator string `json:"allocator"`
}

type formalTool struct {
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	BinarySHA256 *string `json:"binary_sha256"`
}

type formalRefinement struct {
	State          string  `json:"state"`
	FromSubject    string  `json:"from_subject"`
	ToSymbol       string  `json:"to_symbol"`
	ArtifactSHA256 *string `json:"artifact_sha256"`
}

type counterexample struct {
	SHA256          string `json:"sha256"`
	MinimizedSHA256 string `json:"minimized_sha256"`
}

type mutationSensitivity struct {
	MutantID    string `json:"mutant_id"`
	Anchor      string `json:"anchor"`
	Disposition string `json:"disposition"`
}

type formalEvidence struct {
	EvidenceID          string                `json:"evidence_id"`
	ObligationID        string                `json:"obligation_id"`
	SubjectLanguage     string                `json:"subject_language"`
	Method              string                `json:"method"`
	ExecutionState      string                `json:"execution_state"`
	ObservedStrength    string                `json:"observed_strength"`
	Bounds              formalBounds          `json:"bounds"`
	Assumptions         formalAssumptions     `json:"assumptions"`
	TrustedBase         []string              `json:"trusted_base"`
	Tool                formalTool            `json:"tool"`
	InputSHA256s        []string              `json:"input_sha256s"`
	OutputSHA256s       []string              `json:"output_sha256s"`
	Refinement          formalRefinement      `json:"refinement"`
	Counterexample      *counterexample       `json:"counterexample"`
	MutationSensitivity []mutationSensitivity `json:"mutation_sensitivity"`
}

type formalCoverageRow struct {
	ObligationID     string   `json:"obligation_id"`
	JavaStatus       string   `json:"java_status"`
	RustStatus       string   `json:"rust_status"`
	RefinementStatus string   `json:"refinement_status"`
	MutationStatus   string   `json:"mutation_status"`
	AggregateStatus  string   `json:"aggregate_status"`
	BlockerIDs       []string `json:"blocker_ids"`
}

type formalCatalog struct {
	Schema                   string              `json:"$schema"`
	SchemaVersion            string              `json:"schema_version"`
	CatalogID                string              `json:"catalog_id"`
	DenominatorBasis         []artifactIdentity  `json:"denominator_basis"`
	Obligations              []formalObligation  `json:"obligations"`
	JavaBindings             []languageBinding   `json:"java_bindings"`
	RustBindings             []languageBinding   `json:"rust_bindings"`
	Evidence                 []formalEvidence    `json:"evidence"`
	Coverage                 []formalCoverageRow `json:"coverage"`
	Assurance                string              `json:"assurance"`
	IndependentReviewClaimed bool                `json:"independent_review_claimed"`
}

type reviewTarget struct {
	Commit string `json:"commit"`
	Tree   string `json:"tree"`
}

type reviewScope struct {
	CandidateRoot string   `json:"candidate_root"`
	GateIDs       []string `json:"gate_ids"`
	BlockerIDs    []string `json:"blocker_ids"`
}

type reviewFinding struct {
	FindingID string `json:"finding_id"`
	Severity  string `json:"severity"`
	Code      string `json:"code"`
	Path      string `json:"path"`
}

type remediationTarget struct {
	PredecessorCandidateRoot string   `json:"predecessor_candidate_root"`
	SuccessorCandidateRoot   string   `json:"successor_candidate_root"`
	FindingIDs               []string `json:"finding_ids"`
}

type reviewReceipt struct {
	Schema                   string             `json:"$schema"`
	SchemaVersion            string             `json:"schema_version"`
	ReceiptID                string             `json:"receipt_id"`
	Role                     string             `json:"role"`
	ReviewKind               string             `json:"review_kind"`
	Status                   string             `json:"status"`
	Provider                 *string            `json:"provider"`
	Model                    *string            `json:"model"`
	ReasoningEffort          *string            `json:"reasoning_effort"`
	InvocationID             *string            `json:"invocation_id"`
	ReviewerIdentity         string             `json:"reviewer_identity"`
	CandidateRoot            string             `json:"candidate_root"`
	Target                   reviewTarget       `json:"target"`
	Scope                    reviewScope        `json:"scope"`
	CommentsOnly             bool               `json:"comments_only"`
	Findings                 []reviewFinding    `json:"findings"`
	RemediationTarget        *remediationTarget `json:"remediation_target"`
	ParentGateNodeIDs        []string           `json:"parent_gate_node_ids"`
	Assurance                string             `json:"assurance"`
	IndependentReviewClaimed bool               `json:"independent_review_claimed"`
}

type receiptDescriptor struct {
	Path              string             `json:"path"`
	Role              string             `json:"role"`
	ReviewKind        string             `json:"review_kind"`
	Status            string             `json:"status"`
	CandidateRoot     string             `json:"candidate_root"`
	RemediationTarget *remediationTarget `json:"remediation_target"`
	Bytes             uint64             `json:"bytes"`
	SHA256            string             `json:"sha256"`
	Git               candidateGit       `json:"git"`
}

type reviewChain struct {
	FullCodexReviews      uint64 `json:"full_codex_reviews"`
	TargetedClosures      uint64 `json:"targeted_closures"`
	HumanReviewsExecuted  uint64 `json:"human_reviews_executed"`
	BlockingFindings      uint64 `json:"blocking_findings"`
	IndependentAcceptance bool   `json:"independent_acceptance"`
}

type derivedCounts struct {
	Findings    uint64 `json:"findings"`
	Divergences uint64 `json:"divergences"`
	Survivors   uint64 `json:"survivors"`
}

type parityReplay struct {
	Schema           string              `json:"$schema"`
	SchemaVersion    string              `json:"schema_version"`
	StoryID          string              `json:"story_id"`
	CandidateID      string              `json:"candidate_id"`
	Target           candidateTarget     `json:"target"`
	CandidateRoot    string              `json:"candidate_root"`
	Receipts         []receiptDescriptor `json:"receipts"`
	EvaluationRoot   string              `json:"evaluation_root"`
	SnapshotState    string              `json:"snapshot_state"`
	ParityState      string              `json:"parity_state"`
	Gates            []gateRow           `json:"gates"`
	EvidenceFamilies []evidenceFamilyRow `json:"evidence_families"`
	FormalCoverage   []formalCoverageRow `json:"formal_coverage"`
	Blockers         []Blocker           `json:"blockers"`
	Nonclaims        []string            `json:"nonclaims"`
	ReviewChain      reviewChain         `json:"review_chain"`
	Counts           derivedCounts       `json:"counts"`
}

type formalCoverageProjection struct {
	Schema        string              `json:"$schema"`
	SchemaVersion string              `json:"schema_version"`
	CatalogID     string              `json:"catalog_id"`
	Target        candidateTarget     `json:"target"`
	Coverage      []formalCoverageRow `json:"coverage"`
	Counts        GateCounts          `json:"counts"`
	Blockers      []Blocker           `json:"blockers"`
}
