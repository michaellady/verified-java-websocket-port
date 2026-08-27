// Package formal validates the immutable US-006 proof-target, backend, model,
// and concurrency-plan bundle. It never launches a proof backend.
package formal

import (
	"context"
	"encoding/json"
)

const (
	ModePreflight = "PREFLIGHT"
	ModeReplay    = "REPLAY"

	proofTargetsPath         = "assurance/formal/proof-targets.json"
	backendQualificationPath = "assurance/formal/backend-qualification.json"
	connectionModelPath      = "assurance/formal/connection-model.tla"
	concurrencyPlanPath      = "assurance/concurrency/plan.json"

	proofTargetsSchemaPath = "schemas/formal-proof-targets-1.1.0.schema.json"
	backendSchemaPath      = "schemas/formal-backend-qualification-1.0.0.schema.json"
	concurrencySchemaPath  = "schemas/concurrency-plan-1.0.0.schema.json"

	assuranceCeiling = "OWNER_ATTESTED_NOT_INDEPENDENT"
)

// Request selects one of the two read-only validation modes.
type Request struct {
	RootPath string `json:"root_path"`
	Mode     string `json:"mode"`
}

// Finding is one normalized, deterministic failure.
type Finding struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
	Reason      string `json:"reason"`
	Path        string `json:"path"`
	Message     string `json:"message"`
}

// Verdict is the complete public result of Validate.
type Verdict struct {
	Valid                    bool      `json:"valid"`
	State                    string    `json:"state"`
	BundleDigest             string    `json:"bundle_digest"`
	ClaimScopes              []string  `json:"claim_scopes"`
	Findings                 []Finding `json:"findings"`
	Assurance                string    `json:"assurance"`
	IndependentReviewClaimed bool      `json:"independent_review_claimed"`
}

// Validate snapshots and validates the fixed US-006 bundle. REPLAY reconciles
// retained replay identities; neither mode executes a backend.
func Validate(ctx context.Context, request Request) (Verdict, error) {
	return validate(ctx, request)
}

type artifactRef struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Attribution string `json:"attribution"`
}

type proofTargets struct {
	Schema                   string        `json:"$schema"`
	SchemaVersion            string        `json:"schema_version"`
	EntityType               string        `json:"entity_type"`
	PlanID                   string        `json:"plan_id"`
	SourceBasis              []artifactRef `json:"source_basis"`
	Targets                  []target      `json:"targets"`
	RequiredConsumers        []string      `json:"required_consumers"`
	Assurance                string        `json:"assurance"`
	IndependentReviewClaimed bool          `json:"independent_review_claimed"`
	Production               bool          `json:"production"`
	Publication              bool          `json:"publication"`
}

type target struct {
	TargetID             string       `json:"target_id"`
	StoryID              string       `json:"story_id"`
	PlannedFile          string       `json:"planned_file"`
	RustSymbol           string       `json:"rust_symbol"`
	ItemKind             string       `json:"item_kind"`
	LinkageState         string       `json:"linkage_state"`
	SourceSHA256         *string      `json:"source_sha256"`
	SourceGitBlob        *string      `json:"source_git_blob"`
	SemanticIdentity     *string      `json:"semantic_identity"`
	BoundedEvidence      *artifactRef `json:"bounded_evidence"`
	RequiredCallPaths    []callPath   `json:"required_call_paths"`
	Obligations          []obligation `json:"obligations"`
	ProhibitedDuplicates []string     `json:"prohibited_duplicates"`
	MaximumCurrentScope  string       `json:"maximum_current_scope"`
}

type callPath struct {
	Consumer        string       `json:"consumer"`
	EntrySymbol     string       `json:"entry_symbol"`
	LinkageArtifact *artifactRef `json:"linkage_artifact"`
	State           string       `json:"state"`
}

type obligation struct {
	ObligationID                 string   `json:"obligation_id"`
	PropertyID                   string   `json:"property_id"`
	Statement                    string   `json:"statement"`
	RequiredBackendIDs           []string `json:"required_backend_ids"`
	ExpectedCanaryIDs            []string `json:"expected_canary_ids"`
	SubjectTargetID              string   `json:"subject_target_id"`
	MinimumObligationCount       int      `json:"minimum_obligation_count"`
	AllowedClaimScopes           []string `json:"allowed_claim_scopes"`
	ProductionRefinementRequired bool     `json:"production_refinement_required"`
}

type backendQualification struct {
	Schema                    string            `json:"$schema"`
	SchemaVersion             string            `json:"schema_version"`
	EntityType                string            `json:"entity_type"`
	QualificationID           string            `json:"qualification_id"`
	ProofTargets              artifactRef       `json:"proof_targets"`
	ConnectionModel           artifactRef       `json:"connection_model"`
	ConcurrencyPlan           artifactRef       `json:"concurrency_plan"`
	BorrowedSandboxFoundation sandboxFoundation `json:"borrowed_sandbox_foundation"`
	Backends                  []backend         `json:"backends"`
	AggregateState            string            `json:"aggregate_state"`
	Assurance                 string            `json:"assurance"`
	IndependentReviewClaimed  bool              `json:"independent_review_claimed"`
	Production                bool              `json:"production"`
	Signing                   bool              `json:"signing"`
	Publication               bool              `json:"publication"`
}

type sandboxFoundation struct {
	Attribution         string      `json:"attribution"`
	AttemptID           string      `json:"attempt_id"`
	SecurityValidation  artifactRef `json:"security_validation"`
	LiveEvidence        artifactRef `json:"live_evidence"`
	SBXTemplate         artifactRef `json:"sbx_template"`
	SandboxPolicy       artifactRef `json:"sandbox_policy"`
	ProjectionCanonical string      `json:"projection_canonical_digest"`
	TargetCommit        string      `json:"target_commit"`
	SourceTree          string      `json:"source_tree"`
	CLIPath             string      `json:"cli_path"`
	CLIVersion          string      `json:"cli_version"`
	CLICommit           string      `json:"cli_commit"`
	CLIBinaryDigest     string      `json:"cli_binary_digest"`
	DaemonVersion       string      `json:"daemon_version"`
	DaemonCommit        string      `json:"daemon_commit"`
	TemplateReference   string      `json:"template_reference"`
	SandboxPolicyDigest string      `json:"sandbox_policy_digest"`
	EnforcementModel    string      `json:"enforcement_model"`
	MemoryScope         string      `json:"memory_scope"`
	AuthorizedUse       string      `json:"authorized_use"`
	Limitations         []string    `json:"limitations"`
}

type backend struct {
	BackendID             string            `json:"backend_id"`
	Selected              bool              `json:"selected"`
	Method                string            `json:"method"`
	Tool                  tool              `json:"tool"`
	AvailabilityProbe     availabilityProbe `json:"availability_probe"`
	SBXExecution          sbxExecution      `json:"sbx_execution"`
	ExpectedPropertyIDs   []string          `json:"expected_property_ids"`
	ObligationIDs         []string          `json:"obligation_ids"`
	ObligationCount       int               `json:"obligation_count"`
	KnownGoodCanaries     []canary          `json:"known_good_canaries"`
	KnownBadCanaries      []canary          `json:"known_bad_canaries"`
	Bounds                json.RawMessage   `json:"bounds"`
	Assumptions           []string          `json:"assumptions"`
	Provenance            []string          `json:"provenance"`
	UnsupportedConstructs []string          `json:"unsupported_constructs"`
	TrustedBase           []string          `json:"trusted_base"`
	RequiredArtifacts     []string          `json:"required_artifacts"`
	ArtifactBindings      []evidenceBinding `json:"artifact_bindings"`
	ExecutionState        string            `json:"execution_state"`
	ClaimScope            string            `json:"claim_scope"`
	Outcomes              []outcome         `json:"outcomes"`
	Replay                replay            `json:"replay"`
	Limitations           []string          `json:"limitations"`
	evidenceKind          string
	evidenceRunID         string
}

type tool struct {
	Name                   string       `json:"name"`
	Version                *string      `json:"version"`
	Commit                 *string      `json:"commit"`
	BinarySHA256           *string      `json:"binary_sha256"`
	InstallationProvenance string       `json:"installation_provenance"`
	ExecutablePromotion    *artifactRef `json:"executable_promotion"`
}

type availabilityProbe struct {
	Executed    bool         `json:"executed"`
	Receipt     *artifactRef `json:"receipt"`
	ExitCode    *int         `json:"exit_code"`
	Observation string       `json:"observation"`
}

type sbxExecution struct {
	CLIVersion           *string      `json:"cli_version"`
	DaemonVersion        *string      `json:"daemon_version"`
	TemplateReference    *string      `json:"template_reference"`
	SandboxPolicyDigest  *string      `json:"sandbox_policy_digest"`
	RequestDigest        *string      `json:"request_digest"`
	ReceiptDigest        *string      `json:"receipt_digest"`
	InputRootDigest      *string      `json:"input_root_digest"`
	OutputRootDigest     *string      `json:"output_root_digest"`
	CleanupState         *string      `json:"cleanup_state"`
	ClassificationState  *string      `json:"classification_state"`
	Profile              *artifactRef `json:"profile"`
	CapabilityProbe      *artifactRef `json:"capability_probe"`
	Request              *artifactRef `json:"request"`
	Receipt              *artifactRef `json:"receipt"`
	InputManifest        *artifactRef `json:"input_manifest"`
	OutputManifest       *artifactRef `json:"output_manifest"`
	CleanupReceipt       *artifactRef `json:"cleanup_receipt"`
	ClassifierProjection *artifactRef `json:"classifier_projection"`
}

type evidenceBinding struct {
	Category string      `json:"category"`
	RunID    string      `json:"run_id"`
	Artifact artifactRef `json:"artifact"`
}

type canary struct {
	CanaryID        string          `json:"canary_id"`
	Input           artifactRef     `json:"input"`
	ExpectedOutcome string          `json:"expected_outcome"`
	ObservedOutcome string          `json:"observed_outcome"`
	Output          *artifactRef    `json:"output"`
	Counterexample  *counterexample `json:"counterexample"`
}

type counterexample struct {
	CounterexampleID string      `json:"counterexample_id"`
	Reason           string      `json:"reason"`
	TargetSymbol     string      `json:"target_symbol"`
	Input            string      `json:"input"`
	Steps            []string    `json:"steps"`
	Artifact         artifactRef `json:"artifact"`
}

type outcome struct {
	ObligationID   string          `json:"obligation_id"`
	RawOutcome     string          `json:"raw_outcome"`
	ClaimScope     string          `json:"claim_scope"`
	ArtifactRefs   []artifactRef   `json:"artifact_refs"`
	Counterexample *counterexample `json:"counterexample"`
}

type replay struct {
	ReplayID              *string     `json:"replay_id"`
	Argv                  []string    `json:"argv"`
	Environment           []string    `json:"environment"`
	WorkingDirectory      string      `json:"working_directory"`
	Seed                  *string     `json:"seed"`
	ExpectedExitCode      *int        `json:"expected_exit_code"`
	SemanticOutputDigest  *string     `json:"semantic_output_digest"`
	RepeatCount           int         `json:"repeat_count"`
	ReconciledIdentically bool        `json:"reconciled_identically"`
	Runs                  []replayRun `json:"runs"`
}

type replayRun struct {
	RunID                string      `json:"run_id"`
	Receipt              artifactRef `json:"receipt"`
	NormalizedOutput     artifactRef `json:"normalized_output"`
	SemanticOutputDigest string      `json:"semantic_output_digest"`
	ObligationIDs        []string    `json:"obligation_ids"`
}

type evidenceArtifactDocument struct {
	SchemaVersion            string   `json:"schema_version"`
	EntityType               string   `json:"entity_type"`
	FixtureKind              string   `json:"fixture_kind"`
	Provenance               string   `json:"provenance"`
	Role                     string   `json:"role"`
	State                    string   `json:"state"`
	BackendID                string   `json:"backend_id"`
	Method                   string   `json:"method"`
	RunID                    string   `json:"run_id"`
	ToolName                 string   `json:"tool_name"`
	ToolVersion              string   `json:"tool_version"`
	ToolBinarySHA256         string   `json:"tool_binary_sha256"`
	CLIVersion               string   `json:"cli_version"`
	DaemonVersion            string   `json:"daemon_version"`
	TemplateReference        string   `json:"template_reference"`
	SandboxPolicyDigest      string   `json:"sandbox_policy_digest"`
	ObligationIDs            []string `json:"obligation_ids"`
	Assurance                string   `json:"assurance"`
	IndependentReviewClaimed bool     `json:"independent_review_claimed"`
	Production               bool     `json:"production"`
}

type replayReceiptDocument struct {
	SchemaVersion            string      `json:"schema_version"`
	EntityType               string      `json:"entity_type"`
	FixtureKind              string      `json:"fixture_kind"`
	Provenance               string      `json:"provenance"`
	BackendID                string      `json:"backend_id"`
	RunID                    string      `json:"run_id"`
	ReplayID                 string      `json:"replay_id"`
	ExitCode                 int         `json:"exit_code"`
	ObligationIDs            []string    `json:"obligation_ids"`
	SemanticOutputDigest     string      `json:"semantic_output_digest"`
	NormalizedOutput         artifactRef `json:"normalized_output"`
	Assurance                string      `json:"assurance"`
	IndependentReviewClaimed bool        `json:"independent_review_claimed"`
	Production               bool        `json:"production"`
}

type linkageReceiptDocument struct {
	SchemaVersion            string        `json:"schema_version"`
	EntityType               string        `json:"entity_type"`
	FixtureKind              string        `json:"fixture_kind"`
	Provenance               string        `json:"provenance"`
	Method                   string        `json:"method"`
	EntrySymbol              string        `json:"entry_symbol"`
	TargetSymbol             string        `json:"target_symbol"`
	TargetFile               string        `json:"target_file"`
	TargetSourceSHA256       string        `json:"target_source_sha256"`
	SourceTree               artifactRef   `json:"source_tree"`
	Edges                    []linkageEdge `json:"edges"`
	Assurance                string        `json:"assurance"`
	IndependentReviewClaimed bool          `json:"independent_review_claimed"`
	Production               bool          `json:"production"`
}

type linkageEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type concurrencyPlan struct {
	Schema                   string                `json:"$schema"`
	SchemaVersion            string                `json:"schema_version"`
	EntityType               string                `json:"entity_type"`
	PlanID                   string                `json:"plan_id"`
	StoryID                  string                `json:"story_id"`
	ImplementationState      string                `json:"implementation_state"`
	OwnerSymbol              ownerSymbol           `json:"owner_symbol"`
	Actions                  []concurrencyAction   `json:"actions"`
	Bounds                   concurrencyBounds     `json:"bounds"`
	Fairness                 []string              `json:"fairness"`
	Properties               []concurrencyProperty `json:"properties"`
	SeededDefects            []seededDefect        `json:"seeded_defects"`
	RequiredArtifacts        []string              `json:"required_artifacts"`
	ClaimScope               string                `json:"claim_scope"`
	NativeThreadEvidence     nativeThreadEvidence  `json:"native_thread_evidence"`
	Assurance                string                `json:"assurance"`
	IndependentReviewClaimed bool                  `json:"independent_review_claimed"`
	Production               bool                  `json:"production"`
	Publication              bool                  `json:"publication"`
}

type ownerSymbol struct {
	Symbol string `json:"symbol"`
	State  string `json:"state"`
}

type concurrencyAction struct {
	ActionID                      string   `json:"action_id"`
	Actor                         string   `json:"actor"`
	Preconditions                 []string `json:"preconditions"`
	Effects                       []string `json:"effects"`
	ObservableOutcomes            []string `json:"observable_outcomes"`
	MaximumOccurrencesPerSchedule int      `json:"maximum_occurrences_per_schedule"`
}

type concurrencyBounds struct {
	ProducerTasks        int `json:"producer_tasks"`
	OwnerTasks           int `json:"owner_tasks"`
	InboundTasks         int `json:"inbound_tasks"`
	FlushTasks           int `json:"flush_tasks"`
	CallbackTasks        int `json:"callback_tasks"`
	ShutdownTasks        int `json:"shutdown_tasks"`
	MaxTasks             int `json:"max_tasks"`
	CommandQueueCapacity int `json:"command_queue_capacity"`
	WriteQueueCapacity   int `json:"write_queue_capacity"`
	EventQueueCapacity   int `json:"event_queue_capacity"`
	CommandsPerProducer  int `json:"commands_per_producer"`
	InboundActions       int `json:"inbound_actions"`
	FlushActions         int `json:"flush_actions"`
	CallbackActions      int `json:"callback_actions"`
	ShutdownActions      int `json:"shutdown_actions"`
	MaxSchedules         int `json:"max_schedules"`
	MaxPreemptions       int `json:"max_preemptions"`
	MaxBranches          int `json:"max_branches"`
}

type concurrencyProperty struct {
	PropertyID string `json:"property_id"`
	Statement  string `json:"statement"`
}

type seededDefect struct {
	DefectID        string `json:"defect_id"`
	PropertyID      string `json:"property_id"`
	Mutation        string `json:"mutation"`
	ExpectedOutcome string `json:"expected_outcome"`
}

type nativeThreadEvidence struct {
	State          string   `json:"state"`
	ClaimScope     string   `json:"claim_scope"`
	RequiredFields []string `json:"required_fields"`
	Limitations    []string `json:"limitations"`
}
