// Package frameformal validates the finite, actual-code US-012 frame-codec
// evidence receipt. It verifies retained evidence and never upgrades bounded
// tests into a proof or production-linkage claim.
package frameformal

const (
	ReceiptPath = "assurance/formal/frame-results.json"
	SchemaPath  = "schemas/frame-formal-results-1.0.0.schema.json"
)

// Request identifies the repository root containing the fixed receipt.
type Request struct {
	RootPath string `json:"root_path"`
}

// Finding is one deterministic, fail-closed validation result.
type Finding struct {
	Reason  string `json:"reason"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

// Verdict is the public validation result.
type Verdict struct {
	Valid                    bool      `json:"valid"`
	State                    string    `json:"state"`
	ClaimScope               string    `json:"claim_scope"`
	AggregateFormalState     string    `json:"aggregate_formal_state"`
	Findings                 []Finding `json:"findings"`
	Assurance                string    `json:"assurance"`
	IndependentReviewClaimed bool      `json:"independent_review_claimed"`
}

type artifactBinding struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	GitBlob string `json:"git_blob"`
}

type targetBinding struct {
	TargetID string          `json:"target_id"`
	Symbol   string          `json:"symbol"`
	Source   artifactBinding `json:"source"`
}

type harnessBinding struct {
	TestName string          `json:"test_name"`
	Source   artifactBinding `json:"source"`
}

type toolchainBinding struct {
	RustcVersion string          `json:"rustc_version"`
	CargoVersion string          `json:"cargo_version"`
	TargetTriple string          `json:"target_triple"`
	RustcSHA256  string          `json:"rustc_sha256"`
	CargoSHA256  string          `json:"cargo_sha256"`
	Pins         artifactBinding `json:"pins"`
	CargoLock    artifactBinding `json:"cargo_lock"`
}

type headerBounds struct {
	Canonical7         []uint64 `json:"canonical_7"`
	Canonical16        []uint64 `json:"canonical_16"`
	Canonical64        []uint64 `json:"canonical_64"`
	Noncanonical16     []uint64 `json:"noncanonical_16"`
	Noncanonical64     []uint64 `json:"noncanonical_64"`
	HighBit64          []string `json:"high_bit_64"`
	ControlCases       int      `json:"control_cases"`
	RoleMaskCases      int      `json:"role_mask_cases"`
	PreallocationCases int      `json:"preallocation_cases"`
}

type maskBounds struct {
	Keys              []string `json:"keys"`
	Offsets           []int    `json:"offsets"`
	MinimumLength     int      `json:"minimum_length"`
	MaximumLength     int      `json:"maximum_length"`
	InvolutionCases   int      `json:"involution_cases"`
	ByteEquationCases int      `json:"byte_equation_cases"`
}

type finiteBounds struct {
	Header headerBounds `json:"header"`
	Mask   maskBounds   `json:"mask"`
}

type obligationResult struct {
	ObligationID string `json:"obligation_id"`
	TargetSymbol string `json:"target_symbol"`
	CaseCount    int    `json:"case_count"`
	Outcome      string `json:"outcome"`
}

type mutationCanary struct {
	CanaryID            string   `json:"canary_id"`
	TargetSymbol        string   `json:"target_symbol"`
	Mutation            string   `json:"mutation"`
	BaselineSHA256      string   `json:"baseline_sha256"`
	MutatedSourceSHA256 string   `json:"mutated_source_sha256"`
	TestExitCode        int      `json:"test_exit_code"`
	DiagnosticSHA256    string   `json:"diagnostic_sha256"`
	ObligationIDs       []string `json:"obligation_ids"`
	Outcome             string   `json:"outcome"`
}

type retainedOutput struct {
	OutputID string `json:"output_id"`
	Kind     string `json:"kind"`
	Content  string `json:"content"`
	SHA256   string `json:"sha256"`
}

type replayRun struct {
	RunID              string             `json:"run_id"`
	ExitCode           int                `json:"exit_code"`
	RawOutputID        string             `json:"raw_output_id"`
	NormalizedOutputID string             `json:"normalized_output_id"`
	ObligationCounts   []obligationResult `json:"obligation_counts"`
}

type replayEvidence struct {
	Argv                  []string    `json:"argv"`
	Environment           []string    `json:"environment"`
	WorkingDirectory      string      `json:"working_directory"`
	RepeatCount           int         `json:"repeat_count"`
	ReconciledIdentically bool        `json:"reconciled_identically"`
	SemanticOutputDigest  string      `json:"semantic_output_digest"`
	Runs                  []replayRun `json:"runs"`
}

type receipt struct {
	Schema                   string             `json:"$schema"`
	SchemaVersion            string             `json:"schema_version"`
	EvidenceKind             string             `json:"evidence_kind"`
	StoryID                  string             `json:"story_id"`
	State                    string             `json:"state"`
	ClaimScope               string             `json:"claim_scope"`
	AggregateFormalState     string             `json:"aggregate_formal_state"`
	Targets                  []targetBinding    `json:"targets"`
	Harness                  harnessBinding     `json:"harness"`
	Toolchain                toolchainBinding   `json:"toolchain"`
	Bounds                   finiteBounds       `json:"bounds"`
	Obligations              []obligationResult `json:"obligations"`
	SourceMutationCanaries   []mutationCanary   `json:"source_mutation_canaries"`
	Outputs                  []retainedOutput   `json:"outputs"`
	Replay                   replayEvidence     `json:"replay"`
	Limitations              []string           `json:"limitations"`
	Assurance                string             `json:"assurance"`
	IndependentReviewClaimed bool               `json:"independent_review_claimed"`
	Production               bool               `json:"production"`
	Signing                  bool               `json:"signing"`
	Publication              bool               `json:"publication"`
}
