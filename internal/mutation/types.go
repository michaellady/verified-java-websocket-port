// Package mutation executes and verifies the closed US-022 planted-mutation campaign.
package mutation

import "time"

const (
	AssuranceOwner = "OWNER_ATTESTED_NOT_INDEPENDENT"
	PassOwner      = "PASS_OWNER_RELAXED"
	Unavailable    = "UNAVAILABLE_NOT_RUN"
)

// Config names every host capability used by RunPlanted. No PATH or
// environment fallback is permitted.
type Config struct {
	RepositoryRoot  string
	ScratchRoot     string
	JavaExecutable  string
	MavenExecutable string
	MavenRepository string
	CargoExecutable string
	RustcExecutable string
}

type GitAnchor struct {
	Commit string `json:"commit"`
	Tree   string `json:"tree"`
	Blob   string `json:"blob,omitempty"`
}

type Artifact struct {
	Path   string    `json:"path"`
	Bytes  uint64    `json:"bytes"`
	SHA256 string    `json:"sha256"`
	Git    GitAnchor `json:"git"`
}

type ExternalEngine struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	ResultCount uint64 `json:"result_count"`
}

type Mutant struct {
	Runtime                string   `json:"runtime"`
	MutantID               string   `json:"mutant_id"`
	Behavior               string   `json:"behavior"`
	Engine                 string   `json:"engine"`
	ProductionPath         string   `json:"production_path"`
	ProductionFileSHA256   string   `json:"production_file_sha256"`
	UniqueMatchBase64      string   `json:"unique_match_base64"`
	UniqueMatchSHA256      string   `json:"unique_match_sha256"`
	ReplacementBase64      string   `json:"replacement_base64"`
	ReplacementSHA256      string   `json:"replacement_sha256"`
	BuildArgv              []string `json:"build_argv"`
	TestArgv               []string `json:"test_argv"`
	TimeoutMS              uint64   `json:"timeout_ms"`
	ExpectedKillingTestIDs []string `json:"expected_killing_test_ids"`
}

type Plan struct {
	Schema                   string           `json:"$schema"`
	SchemaVersion            string           `json:"schema_version"`
	StoryID                  string           `json:"story_id"`
	Status                   string           `json:"status"`
	Assurance                string           `json:"assurance"`
	IndependentReviewClaimed bool             `json:"independent_review_claimed"`
	Signing                  bool             `json:"signing"`
	Production               bool             `json:"production"`
	Publication              bool             `json:"publication"`
	RepositoryAnchor         GitAnchor        `json:"repository_anchor"`
	Inputs                   []Artifact       `json:"inputs"`
	ExternalEngines          []ExternalEngine `json:"external_engines"`
	Mutants                  []Mutant         `json:"mutants"`
	MinimumPerRuntime        uint64           `json:"minimum_per_runtime"`
	IdealPerRuntime          uint64           `json:"ideal_per_runtime"`
	InventoryGap             string           `json:"inventory_gap"`
	Nonclaims                []string         `json:"nonclaims"`
}

var dispositions = []string{
	"KILLED", "SURVIVED", "NOT_EXECUTED", "UNCOVERED", "TIMEOUT",
	"TOOL_FAILURE", "FLAKY", "EQUIVALENT", "TECHNICALLY_UNVIABLE",
}

type DenominatorRow struct {
	Runtime     string `json:"runtime"`
	MutantID    string `json:"mutant_id"`
	Disposition string `json:"disposition"`
}

type DenominatorCounts struct {
	Killed              uint64 `json:"KILLED"`
	Survived            uint64 `json:"SURVIVED"`
	NotExecuted         uint64 `json:"NOT_EXECUTED"`
	Uncovered           uint64 `json:"UNCOVERED"`
	Timeout             uint64 `json:"TIMEOUT"`
	ToolFailure         uint64 `json:"TOOL_FAILURE"`
	Flaky               uint64 `json:"FLAKY"`
	Equivalent          uint64 `json:"EQUIVALENT"`
	TechnicallyUnviable uint64 `json:"TECHNICALLY_UNVIABLE"`
}

type Denominator struct {
	Schema                   string            `json:"$schema"`
	SchemaVersion            string            `json:"schema_version"`
	StoryID                  string            `json:"story_id"`
	Status                   string            `json:"status"`
	Assurance                string            `json:"assurance"`
	IndependentReviewClaimed bool              `json:"independent_review_claimed"`
	Signing                  bool              `json:"signing"`
	Production               bool              `json:"production"`
	Publication              bool              `json:"publication"`
	PlanSHA256               string            `json:"plan_sha256"`
	Rows                     []DenominatorRow  `json:"rows"`
	Counts                   DenominatorCounts `json:"counts"`
	Full                     uint64            `json:"full"`
	Excluded                 uint64            `json:"excluded"`
	Eligible                 uint64            `json:"eligible"`
	Missed                   uint64            `json:"missed"`
	ScoreBasisPoints         uint64            `json:"score_basis_points"`
}

type ProcessReceipt struct {
	Argv              []string `json:"argv"`
	WorkingDirectory  string   `json:"working_directory_class"`
	TimeoutMS         uint64   `json:"timeout_ms"`
	DurationMS        uint64   `json:"duration_ms"`
	ExitCode          int      `json:"exit_code"`
	TerminationReason string   `json:"termination_reason"`
	StdoutBytes       uint64   `json:"stdout_bytes"`
	StdoutSHA256      string   `json:"stdout_sha256"`
	StderrBytes       uint64   `json:"stderr_bytes"`
	StderrSHA256      string   `json:"stderr_sha256"`
}

type Observation struct {
	Repeat        uint64         `json:"repeat"`
	Build         ProcessReceipt `json:"build"`
	Test          ProcessReceipt `json:"test"`
	FailedTestIDs []string       `json:"failed_test_ids"`
	Killed        bool           `json:"killed"`
}

type MutationResult struct {
	MutantID         string        `json:"mutant_id"`
	Engine           string        `json:"engine"`
	Disposition      string        `json:"disposition"`
	ResultFileSHA256 string        `json:"result_file_sha256"`
	Observations     []Observation `json:"observations"`
}

type Baseline struct {
	Repeat        uint64         `json:"repeat"`
	Phase         string         `json:"phase"`
	Process       ProcessReceipt `json:"process"`
	TestsPassed   uint64         `json:"tests_passed"`
	TestsFailed   uint64         `json:"tests_failed"`
	TestsSkipped  uint64         `json:"tests_skipped"`
	TestsFiltered uint64         `json:"tests_filtered"`
}

type RuntimeEvidence struct {
	Schema                   string           `json:"$schema"`
	SchemaVersion            string           `json:"schema_version"`
	StoryID                  string           `json:"story_id"`
	Runtime                  string           `json:"runtime"`
	Status                   string           `json:"status"`
	Assurance                string           `json:"assurance"`
	IndependentReviewClaimed bool             `json:"independent_review_claimed"`
	Signing                  bool             `json:"signing"`
	Production               bool             `json:"production"`
	Publication              bool             `json:"publication"`
	PlanSHA256               string           `json:"plan_sha256"`
	SourceClosureSHA256      string           `json:"source_closure_sha256"`
	TestClosureSHA256        string           `json:"test_closure_sha256"`
	TestManifestSHA256       string           `json:"test_manifest_sha256"`
	Before                   []Baseline       `json:"before"`
	After                    []Baseline       `json:"after"`
	Results                  []MutationResult `json:"results"`
	ExternalEngines          []ExternalEngine `json:"external_engines"`
	NoRepositoryDrift        bool             `json:"no_repository_drift"`
	Nonclaims                []string         `json:"nonclaims"`
}

type Tier struct {
	Tier                  string `json:"tier"`
	ManifestSHA256        string `json:"manifest_sha256"`
	CorpusID              string `json:"corpus_id"`
	Expected              uint64 `json:"expected"`
	Selected              uint64 `json:"selected"`
	Executed              uint64 `json:"executed"`
	Passed                uint64 `json:"passed"`
	Failed                uint64 `json:"failed"`
	Skipped               uint64 `json:"skipped"`
	Filtered              uint64 `json:"filtered"`
	TimedOut              uint64 `json:"timed_out"`
	CommitmentRoot        string `json:"commitment_root"`
	TranscriptSHA256      string `json:"transcript_sha256"`
	ReportSHA256          string `json:"report_sha256"`
	CustodianPolicySHA256 string `json:"custodian_policy_sha256"`
}

type Subject struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type Isolation struct {
	Identity          string `json:"identity"`
	Workspace         string `json:"workspace"`
	Filesystem        string `json:"filesystem"`
	Cache             string `json:"cache"`
	Network           string `json:"network"`
	ProtectedStore    string `json:"protected_store"`
	SigningSeparation string `json:"signing_key_separation"`
}

type Budgets struct {
	QuerySpent      uint64 `json:"query_spent"`
	DiagnosticSpent uint64 `json:"diagnostic_spent"`
}

type LeakCounts struct {
	CaseIDs        uint64 `json:"case_ids"`
	CaseBodies     uint64 `json:"case_bodies"`
	Expected       uint64 `json:"expected_outputs"`
	Actual         uint64 `json:"actual_outputs"`
	Diagnostics    uint64 `json:"diagnostics"`
	Salts          uint64 `json:"salts"`
	Keys           uint64 `json:"keys"`
	Tokens         uint64 `json:"tokens"`
	Credentials    uint64 `json:"credentials"`
	ProtectedPaths uint64 `json:"protected_paths"`
	Timestamps     uint64 `json:"timestamps"`
	Prose          uint64 `json:"prose"`
}

type ProtectedReceipt struct {
	Schema                   string     `json:"$schema"`
	SchemaVersion            string     `json:"schema_version"`
	StoryID                  string     `json:"story_id"`
	Status                   string     `json:"status"`
	Assurance                string     `json:"assurance"`
	IndependentReviewClaimed bool       `json:"independent_review_claimed"`
	Signing                  bool       `json:"signing"`
	Production               bool       `json:"production"`
	Publication              bool       `json:"publication"`
	PolicySHA256             string     `json:"policy_sha256"`
	EvaluatorSHA256          string     `json:"evaluator_sha256"`
	Tiers                    []Tier     `json:"tiers"`
	Subjects                 []Subject  `json:"subjects"`
	Isolation                Isolation  `json:"isolation"`
	Budgets                  Budgets    `json:"budgets"`
	Leaks                    LeakCounts `json:"leaks"`
	CalibrationSHA256        string     `json:"calibration_sha256"`
	ProjectionSHA256         string     `json:"projection_sha256"`
}

// Kept here so tests can replace the clock without exposing timestamps in evidence.
var now = time.Now
