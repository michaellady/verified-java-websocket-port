// Package differential owns the bounded, public-only Java/Rust behavior
// comparison used by US-020.  Callers provide identities and destinations;
// the package owns projection, execution, adjudication, and verification.
package differential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/michaellady/verified-java-websocket-port/internal/provenance"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	StatusPass                     = "PASS"
	evidenceSchemaVersion          = "1.0.0"
	ledgerSchemaVersion            = "1.1.0"
	maximumDocumentBytes     int64 = 32 << 20
	maximumProcessOutput           = 4 << 20
	maximumProcessError            = 4 << 10
	neutralProtocolMaximum         = 4 << 20
	expectedPublicScenarios        = 74
	expectedProcessReceipts        = expectedPublicScenarios * 2 * 2
	maximumRuntimeImageBytes int64 = 1 << 30
	maximumRuntimeImageFiles       = 20000
	rustInputDerivationNote        = "input_bytes derives from public source kind plus Rust pre_state and typed INVALID_STATE or INPUT_LIMIT_EXCEEDED; it is not raw NOBS1 accounting and cannot change consumed_bytes"
)

// Budget bounds deterministic mismatch minimization.
type Budget struct {
	MaxCandidates int           `json:"max_candidates"`
	MaxDuration   time.Duration `json:"max_duration"`
}

// Config names every runtime and committed input explicitly.  There is no
// environment or PATH fallback.
type Config struct {
	RepositoryRoot       string
	PublicCorpus         string
	JavaExecutable       string
	JavaAdapterJar       string
	JavaRuntimeJar       string
	JavaSupportJars      []string
	RustTestee           string
	MigrationInventory   string
	CompatibilitySurface string
	LedgerPath           string
	EvidencePath         string
	OracleHierarchyPath  string
	ScenarioTimeout      time.Duration
	SuiteTimeout         time.Duration
	MinimizationBudget   Budget
	launchInputs         map[string][]LaunchIdentity
}

// Receipt is the small transport result; the complete auditable material is
// stored in the manifest named by EvidencePath.
type Receipt struct {
	Status          string `json:"status"`
	ScenarioCount   int    `json:"scenario_count"`
	ProcessReceipts int    `json:"process_receipts"`
	DeltaCount      int    `json:"delta_count"`
	EvidenceSHA256  string `json:"evidence_sha256"`
}

// RustReplayConfig bounds one Rust-only replay of the incumbent public corpus.
// It deliberately exposes no alternate corpus, protocol, or normalizer seam.
type RustReplayConfig struct {
	RepositoryRoot  string
	Executable      string
	ScenarioTimeout time.Duration
	SuiteTimeout    time.Duration
}

// RustReplayRow is one canonically ordered public scenario observation.
type RustReplayRow struct {
	ScenarioID       string `json:"scenario_id"`
	InputSHA256      string `json:"input_sha256"`
	NormalizedSHA256 string `json:"normalized_sha256"`
	ExitCode         int    `json:"exit_code"`
	TimedOut         bool   `json:"timed_out"`
}

// ReplayRustPublic executes exactly the frozen 74-scenario public corpus using
// the incumbent NDRV1 encoder, bounded child runner, NOBS1 parser, and Rust
// normalizer. The returned order is the canonical corpus order.
func ReplayRustPublic(ctx context.Context, cfg RustReplayConfig) ([]RustReplayRow, error) {
	if cfg.ScenarioTimeout <= 0 || cfg.ScenarioTimeout > 5*time.Second {
		return nil, errors.New("scenario timeout must be in (0,5s]")
	}
	if cfg.SuiteTimeout <= 0 || cfg.SuiteTimeout > 15*time.Minute {
		return nil, errors.New("suite timeout must be in (0,15m]")
	}
	if cfg.RepositoryRoot == "" || !filepath.IsAbs(cfg.RepositoryRoot) || filepath.Clean(cfg.RepositoryRoot) != cfg.RepositoryRoot || cfg.RepositoryRoot == string(filepath.Separator) {
		return nil, errors.New("repository root must be absolute, clean, and narrow")
	}
	if err := validateExistingPath(cfg.Executable, true); err != nil {
		return nil, fmt.Errorf("Rust replay executable: %w", err)
	}
	scenarios, _, err := loadPublicCorpus(cfg.RepositoryRoot, filepath.Join(cfg.RepositoryRoot, "corpora/public/scenarios.jsonl"))
	if err != nil {
		return nil, err
	}
	executable, err := artifact(cfg.Executable)
	if err != nil {
		return nil, err
	}
	home, err := os.MkdirTemp("/private/tmp", "us024-rust-replay-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(home)

	suiteCtx, cancel := context.WithTimeout(ctx, cfg.SuiteTimeout)
	defer cancel()
	incumbent := Config{
		RepositoryRoot:  cfg.RepositoryRoot,
		PublicCorpus:    filepath.Join(cfg.RepositoryRoot, "corpora/public/scenarios.jsonl"),
		RustTestee:      cfg.Executable,
		ScenarioTimeout: cfg.ScenarioTimeout,
		SuiteTimeout:    cfg.SuiteTimeout,
	}
	rows := make([]RustReplayRow, 0, len(scenarios))
	for _, scenario := range scenarios {
		input, err := encodeNeutralRequest(scenario)
		if err != nil {
			return nil, err
		}
		attempt, err := runAttempt(suiteCtx, incumbent, home, scenario, "rust", "refinement", executable.SHA256)
		if err != nil {
			return nil, err
		}
		rows = append(rows, RustReplayRow{
			ScenarioID:       scenario.ScenarioID,
			InputSHA256:      digest(input),
			NormalizedSHA256: attempt.receipt.NormalizedSHA256,
			ExitCode:         attempt.receipt.ExitCode,
			TimedOut:         false,
		})
	}
	if len(rows) != expectedPublicScenarios {
		return nil, fmt.Errorf("public replay count = %d, want %d", len(rows), expectedPublicScenarios)
	}
	return rows, nil
}

type ReproductionReceipt struct {
	Status              string `json:"status"`
	ReproducerID        string `json:"reproducer_id"`
	Mode                string `json:"mode"`
	ScenarioSHA256      string `json:"scenario_sha256"`
	FreshProcesses      int    `json:"fresh_processes"`
	CurrentlyReproduced bool   `json:"currently_reproduced"`
}

type DiagnosticFinding struct {
	ScenarioID     string `json:"scenario_id"`
	Pointer        string `json:"pointer"`
	Classification string `json:"classification"`
	JavaSHA256     string `json:"java_sha256,omitempty"`
	RustSHA256     string `json:"rust_sha256,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	JavaValue      string `json:"java_value,omitempty"`
	RustValue      string `json:"rust_value,omitempty"`
	Detail         string `json:"detail"`
}

// DiagnosticReport is deliberately in-memory and non-authoritative. It lets a
// bounded remediation pass see every public blocker without weakening the
// official facade's transactional, fail-closed evidence behavior.
type DiagnosticReport struct {
	Status           string              `json:"status"`
	ScenarioCount    int                 `json:"scenario_count"`
	ProcessReceipts  int                 `json:"process_receipts"`
	StableScenarios  int                 `json:"stable_scenarios"`
	AcceptedQuirks   int                 `json:"accepted_quirks"`
	BlockingFindings int                 `json:"blocking_findings"`
	EvidenceWrites   int                 `json:"evidence_writes"`
	LedgerWrites     int                 `json:"ledger_writes"`
	Findings         []DiagnosticFinding `json:"findings"`
}

type ArtifactIdentity struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type LaunchIdentity struct {
	Role         string `json:"role"`
	SourcePath   string `json:"source_path"`
	SourceSHA256 string `json:"source_sha256"`
	ObjectSHA256 string `json:"object_sha256"`
	ObjectName   string `json:"object_name"`
	Bytes        int64  `json:"bytes"`
}

type NormalizationLoss struct {
	Pointer     string `json:"pointer"`
	Reason      string `json:"reason"`
	ValueSHA256 string `json:"value_sha256"`
}

type NormalizationTrace struct {
	Runtime          string              `json:"runtime"`
	Attempt          string              `json:"attempt"`
	RawBase64        string              `json:"raw_base64"`
	RawSHA256        string              `json:"raw_sha256"`
	NormalizedSHA256 string              `json:"normalized_sha256"`
	Losses           []NormalizationLoss `json:"losses"`
}

type ProcessReceipt struct {
	ScenarioID       string           `json:"scenario_id"`
	Runtime          string           `json:"runtime"`
	Attempt          string           `json:"attempt"`
	PID              int              `json:"pid"`
	ExecutableSHA256 string           `json:"executable_sha256"`
	StdinSHA256      string           `json:"stdin_sha256"`
	StdinBytes       int              `json:"stdin_bytes"`
	StdoutSHA256     string           `json:"stdout_sha256"`
	StdoutBytes      int              `json:"stdout_bytes"`
	StderrSHA256     string           `json:"stderr_sha256"`
	StderrBytes      int              `json:"stderr_bytes"`
	ExitCode         int              `json:"exit_code"`
	StartedUnixNano  int64            `json:"started_unix_nano"`
	DurationNanos    int64            `json:"duration_nanos"`
	NormalizedSHA256 string           `json:"normalized_sha256"`
	LaunchedInputs   []LaunchIdentity `json:"launched_inputs"`
}

type ScenarioResult struct {
	ScenarioID             string               `json:"scenario_id"`
	JavaPrimary            string               `json:"java_primary_sha256"`
	JavaReplay             string               `json:"java_replay_sha256"`
	RustPrimary            string               `json:"rust_primary_sha256"`
	RustReplay             string               `json:"rust_replay_sha256"`
	NeutralExpected        string               `json:"neutral_expected_sha256"`
	Stable                 bool                 `json:"stable"`
	CurrentMismatch        bool                 `json:"current_mismatch"`
	Classification         string               `json:"classification"`
	JavaObservation        commonObservation    `json:"java_observation"`
	RustObservation        commonObservation    `json:"rust_observation"`
	RustStepDiagnostics    []rustStep           `json:"rust_step_diagnostics"`
	RustBootstrapSHA256    string               `json:"rust_bootstrap_sha256"`
	JavaNormalizationLoss  []string             `json:"java_normalization_loss"`
	RustNormalizationNotes []string             `json:"rust_normalization_notes"`
	NormalizationAudits    []NormalizationTrace `json:"normalization_audits"`
}

type CoverageRow struct {
	ID                    string             `json:"id"`
	SourcePointer         string             `json:"source_pointer"`
	SourceSHA256          string             `json:"source_sha256"`
	FreshUS020            bool               `json:"fresh_us020"`
	ScenarioIDs           []string           `json:"scenario_ids"`
	FieldPointers         []string           `json:"field_pointers"`
	PredecessorPaths      []string           `json:"predecessor_paths"`
	PredecessorIdentities []ArtifactIdentity `json:"predecessor_identities"`
	ExcludedReason        string             `json:"excluded_reason,omitempty"`
}

type mismatchSignature struct {
	Pointer        string `json:"pointer"`
	Classification string `json:"classification"`
}

type PublicReproducer struct {
	ReproducerID           string                `json:"reproducer_id"`
	LedgerDeltaID          string                `json:"ledger_delta_id"`
	ScenarioID             string                `json:"scenario_id"`
	Mode                   string                `json:"mode"`
	ProofScope             string                `json:"proof_scope"`
	CurrentlyReproduces    bool                  `json:"currently_reproduces"`
	Signature              mismatchSignature     `json:"signature"`
	Scenario               corpora.Scenario      `json:"scenario"`
	OriginalScenarioSHA256 string                `json:"original_scenario_sha256"`
	ScenarioSHA256         string                `json:"scenario_sha256"`
	Command                []string              `json:"command"`
	RepositoryAnchor       string                `json:"repository_anchor"`
	RuntimeInputs          []ArtifactIdentity    `json:"runtime_inputs"`
	CandidateAttempts      int                   `json:"candidate_attempts"`
	Irreducible            bool                  `json:"irreducible"`
	Processes              []ProcessReceipt      `json:"processes"`
	Attempts               []MinimizationAttempt `json:"attempts"`
	FindingJavaObservation string                `json:"finding_java_observation_sha256"`
	FindingRustObservation string                `json:"finding_rust_observation_sha256"`
	FindingRunAnchor       string                `json:"finding_run_anchor"`
	ClosingRunAnchor       string                `json:"closing_run_anchor,omitempty"`
	ClosingJavaObservation string                `json:"closing_java_observation_sha256,omitempty"`
	ClosingRustObservation string                `json:"closing_rust_observation_sha256,omitempty"`
}

func canonicalReproducerCommand(repositoryRoot, evidencePath, reproducerID string) []string {
	return []string{"differentialctl", "reproduce", "--repository-root", repositoryRoot, "--evidence", evidencePath, "--reproducer-id", reproducerID}
}

func validateReproducerCommand(command []string, repositoryRoot, evidencePath, reproducerID string) error {
	if !canonicalEqual(command, canonicalReproducerCommand(repositoryRoot, evidencePath, reproducerID)) {
		return errors.New("reproducer command is not the exact reviewed argv contract")
	}
	return nil
}

type MinimizationAttempt struct {
	Scenario       corpora.Scenario     `json:"scenario"`
	ScenarioSHA256 string               `json:"scenario_sha256"`
	Signature      mismatchSignature    `json:"signature"`
	Reproduced     bool                 `json:"reproduced"`
	Processes      []ProcessReceipt     `json:"processes"`
	EvidenceStatus string               `json:"evidence_status"`
	Audits         []NormalizationTrace `json:"normalization_audits"`
}

type evidenceScenarioWire struct {
	ScenarioID        string           `json:"scenario_id"`
	Tier              string           `json:"tier"`
	Family            string           `json:"family"`
	SeedIndex         int              `json:"seed_index"`
	Role              string           `json:"role"`
	InitialState      string           `json:"initial_state"`
	Limits            corpora.Limits   `json:"limits"`
	Steps             []corpora.Step   `json:"steps"`
	Expected          corpora.Expected `json:"expected"`
	ExpectationBasis  []string         `json:"expectation_basis"`
	ExpectationStatus string           `json:"expectation_status"`
}

func decodeEvidenceScenario(raw []byte) (corpora.Scenario, error) {
	var wire evidenceScenarioWire
	if err := decodeStrict(raw, &wire); err != nil {
		return corpora.Scenario{}, err
	}
	for _, values := range [][]map[string]any{wire.Expected.Events, wire.Expected.Frames, wire.Expected.Transitions} {
		for _, value := range values {
			if err := restoreEvidenceIntegers(value); err != nil {
				return corpora.Scenario{}, err
			}
		}
	}
	if err := restoreEvidenceIntegers(wire.Expected.Close); err != nil {
		return corpora.Scenario{}, err
	}
	return corpora.Scenario{
		ScenarioID: wire.ScenarioID, Tier: wire.Tier, Family: wire.Family, SeedIndex: wire.SeedIndex,
		Core:     corpora.ScenarioCore{Role: wire.Role, InitialState: wire.InitialState, Limits: wire.Limits, Steps: wire.Steps},
		Expected: wire.Expected, ExpectationBasis: wire.ExpectationBasis, ExpectationStatus: wire.ExpectationStatus,
	}, nil
}

func restoreEvidenceIntegers(value any) error {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]any:
		for key, item := range typed {
			if number, ok := item.(float64); ok {
				integer := int(number)
				if float64(integer) != number {
					return fmt.Errorf("evidence scenario field %s is not a bounded integer", key)
				}
				typed[key] = integer
				continue
			}
			if err := restoreEvidenceIntegers(item); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for index, item := range typed {
			if number, ok := item.(float64); ok {
				integer := int(number)
				if float64(integer) != number {
					return fmt.Errorf("evidence scenario array item %d is not a bounded integer", index)
				}
				typed[index] = integer
				continue
			}
			if err := restoreEvidenceIntegers(item); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

// UnmarshalJSON preserves the corpus scenario's intentionally flattened wire
// format. corpora.Scenario owns canonical marshaling but deliberately has no
// general-purpose decoder, so evidence decoding supplies the exact closed
// inverse here.
func (r *PublicReproducer) UnmarshalJSON(raw []byte) error {
	type alias PublicReproducer
	var value alias
	var wire struct {
		*alias
		Scenario json.RawMessage `json:"scenario"`
	}
	wire.alias = &value
	if err := decodeStrict(raw, &wire); err != nil {
		return err
	}
	scenario, err := decodeEvidenceScenario(wire.Scenario)
	if err != nil {
		return err
	}
	value.Scenario = scenario
	*r = PublicReproducer(value)
	return nil
}

func (a *MinimizationAttempt) UnmarshalJSON(raw []byte) error {
	type alias MinimizationAttempt
	var value alias
	var wire struct {
		*alias
		Scenario json.RawMessage `json:"scenario"`
	}
	wire.alias = &value
	if err := decodeStrict(raw, &wire); err != nil {
		return err
	}
	scenario, err := decodeEvidenceScenario(wire.Scenario)
	if err != nil {
		return err
	}
	value.Scenario = scenario
	*a = MinimizationAttempt(value)
	return nil
}

type CoverageSummary struct {
	MigrationRows          int `json:"migration_rows"`
	CompatibilityItems     int `json:"compatibility_items"`
	FreshRows              int `json:"fresh_rows"`
	PredecessorRows        int `json:"predecessor_rows"`
	CapabilityExcludedRows int `json:"capability_excluded_rows"`
	UnresolvedRows         int `json:"unresolved_rows"`
}

type CoverageReceipt struct {
	CurrentHeadQualification ArtifactIdentity `json:"current_head_qualification"`
	Summary                  CoverageSummary  `json:"summary"`
	Migration                []CoverageRow    `json:"migration"`
	Compatibility            []CoverageRow    `json:"compatibility"`
}

type ControlResult struct {
	ControlID       string `json:"control_id"`
	SeedSHA256      string `json:"seed_sha256"`
	ExpectedCode    string `json:"expected_code"`
	DetectedCode    string `json:"detected_code"`
	BaselinePassed  bool   `json:"baseline_passed"`
	LedgerUnchanged bool   `json:"ledger_unchanged"`
}

type ControlsReceipt struct {
	Total   int             `json:"total"`
	Killed  int             `json:"killed"`
	Results []ControlResult `json:"results"`
}

type LedgerBinding struct {
	PreHead  string `json:"pre_head"`
	PostHead string `json:"post_head"`
	Records  int    `json:"records"`
}

type CountsReceipt struct {
	Scenarios               int `json:"scenarios"`
	JavaPrimary             int `json:"java_primary"`
	JavaReplay              int `json:"java_replay"`
	RustPrimary             int `json:"rust_primary"`
	RustReplay              int `json:"rust_replay"`
	Processes               int `json:"processes"`
	Flakes                  int `json:"flakes"`
	CurrentMismatches       int `json:"current_mismatches"`
	UnresolvedDifferences   int `json:"unresolved_differences"`
	NormalizationCollisions int `json:"normalization_collisions"`
}

type Manifest struct {
	Schema                   string             `json:"$schema"`
	SchemaVersion            string             `json:"schema_version"`
	EvidenceID               string             `json:"evidence_id"`
	StoryID                  string             `json:"story_id"`
	Status                   string             `json:"status"`
	Assurance                string             `json:"assurance"`
	IndependentReviewClaimed bool               `json:"independent_review_claimed"`
	Production               bool               `json:"production"`
	Publication              bool               `json:"publication"`
	Signing                  bool               `json:"signing"`
	ParityScope              string             `json:"parity_scope"`
	RepositoryAnchor         string             `json:"repository_anchor"`
	Inputs                   []ArtifactIdentity `json:"inputs"`
	Counts                   CountsReceipt      `json:"counts"`
	Scenarios                []ScenarioResult   `json:"scenarios"`
	Processes                []ProcessReceipt   `json:"processes"`
	Coverage                 CoverageReceipt    `json:"coverage"`
	Controls                 ControlsReceipt    `json:"controls"`
	Ledger                   LedgerBinding      `json:"ledger"`
	Reproducers              []PublicReproducer `json:"reproducers"`
	Nonclaims                []string           `json:"nonclaims"`
}

type OracleEvidence struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

type OracleCell struct {
	ScenarioID     string           `json:"scenario_id"`
	Pointer        string           `json:"pointer"`
	Authority      string           `json:"authority"`
	Rank           int              `json:"rank"`
	ExpectedSHA256 string           `json:"expected_sha256"`
	Evidence       []OracleEvidence `json:"evidence"`
}

type OracleHierarchy struct {
	Schema        string       `json:"$schema"`
	SchemaVersion string       `json:"schema_version"`
	EvidenceKind  string       `json:"evidence_kind"`
	ScenarioCount int          `json:"scenario_count"`
	CellCount     int          `json:"cell_count"`
	Cells         []OracleCell `json:"cells"`
}

type AdjudicatedFinding struct {
	Pointer        string     `json:"pointer"`
	Classification string     `json:"classification"`
	Decision       OracleCell `json:"decision"`
	JavaSHA256     string     `json:"java_sha256"`
	RustSHA256     string     `json:"rust_sha256"`
}

type absentObservationValue struct {
	Absent bool `json:"__us020_absent__"`
}

type LedgerRecord struct {
	Sequence               int        `json:"sequence"`
	DeltaID                string     `json:"delta_id"`
	PreviousDigest         string     `json:"previous_digest"`
	RecordDigest           string     `json:"record_digest"`
	ScenarioID             string     `json:"scenario_id"`
	Pointer                string     `json:"pointer"`
	Classification         string     `json:"classification"`
	JavaObservation        string     `json:"java_observation_sha256"`
	RustObservation        string     `json:"rust_observation_sha256"`
	ReproducerSHA256       string     `json:"reproducer_sha256"`
	Decision               OracleCell `json:"decision"`
	Resolution             string     `json:"resolution"`
	FindingRunAnchor       string     `json:"finding_run_anchor"`
	ClosingRunAnchor       string     `json:"closing_run_anchor,omitempty"`
	ClosingJavaObservation string     `json:"closing_java_observation_sha256,omitempty"`
	ClosingRustObservation string     `json:"closing_rust_observation_sha256,omitempty"`
}

type Ledger struct {
	Schema                  string               `json:"$schema"`
	SchemaVersion           string               `json:"schema_version"`
	EvidenceKind            string               `json:"evidence_kind"`
	AcceptedRootDigest      string               `json:"accepted_root_digest"`
	Status                  string               `json:"status"`
	NormativeAuthority      string               `json:"normative_authority"`
	Head                    string               `json:"head"`
	Records                 []LedgerRecord       `json:"records"`
	AppendImplementation    string               `json:"append_implementation"`
	UnledgeredDisagreements int                  `json:"unledgered_disagreements"`
	Production              bool                 `json:"production"`
	Publication             bool                 `json:"publication"`
	MigrationSourceHead     string               `json:"migration_source_head,omitempty"`
	MigratedV1Records       []LegacyLedgerRecord `json:"migrated_v1_records,omitempty"`
}

type LegacyLedger struct {
	Schema                  string               `json:"$schema"`
	SchemaVersion           string               `json:"schema_version"`
	EvidenceKind            string               `json:"evidence_kind"`
	AcceptedRootDigest      string               `json:"accepted_root_digest"`
	Status                  string               `json:"status"`
	NormativeAuthority      string               `json:"normative_authority"`
	Head                    string               `json:"head"`
	Records                 []LegacyLedgerRecord `json:"records"`
	AppendImplementation    string               `json:"append_implementation"`
	UnledgeredDisagreements int                  `json:"unledgered_disagreements"`
	Production              bool                 `json:"production"`
	Publication             bool                 `json:"publication"`
}

type LegacyLedgerRecord struct {
	SchemaVersion  string      `json:"schema_version"`
	Sequence       int         `json:"sequence"`
	PreviousDigest string      `json:"previous_digest"`
	Delta          LegacyDelta `json:"delta"`
	RecordDigest   string      `json:"record_digest"`
}

type LegacyDelta struct {
	SchemaVersion         string   `json:"schema_version"`
	DeltaID               string   `json:"delta_id"`
	SubjectRef            string   `json:"subject_ref"`
	RFCRefs               []string `json:"rfc_refs"`
	RFCExpectationDigest  string   `json:"rfc_expectation_digest"`
	RFCValueDigest        string   `json:"rfc_value_digest"`
	JavaRef               string   `json:"java_ref"`
	JavaObservationDigest string   `json:"java_observation_digest"`
	JavaValueDigest       string   `json:"java_value_digest"`
	AutobahnRefs          []string `json:"autobahn_refs"`
	AutobahnResultDigest  string   `json:"autobahn_result_digest"`
	AutobahnValueDigest   string   `json:"autobahn_value_digest"`
	DisagreementDigest    string   `json:"disagreement_digest"`
	NormativeAuthority    string   `json:"normative_authority"`
	Disposition           string   `json:"disposition"`
	Rationale             string   `json:"rationale"`
}

// BehaviorLedgerSummary is the small, read-only compatibility projection
// exposed to consumers of the US-020 ledger. It deliberately does not expose
// append operations or let another package reinterpret individual records.
type BehaviorLedgerSummary struct {
	SchemaVersion         string
	AcceptedRootDigest    string
	Status                string
	Head                  string
	RecordCount           int
	CurrentDeltasResolved bool
	Production            bool
	Publication           bool
}

// SemanticObservation is the detector-facing subset used by synthetic
// controls.  It deliberately retains ordered events and distinct accounting
// and close/error fields.
type SemanticObservation struct {
	Events        []string `json:"events"`
	ErrorClass    string   `json:"error_class"`
	CloseOrigin   string   `json:"close_origin"`
	ConsumedBytes uint64   `json:"consumed_bytes"`
}

func (s SemanticObservation) Clone() SemanticObservation {
	out := s
	out.Events = append([]string(nil), s.Events...)
	return out
}

// Difference is an exact semantic detector result.
type Difference struct {
	Code    string `json:"code"`
	Pointer string `json:"pointer"`
}

// DetectSemanticDifference uses explicit fields rather than a generic JSON
// inequality so every planted control has one stable detector code.
func DetectSemanticDifference(want, got SemanticObservation) Difference {
	if len(want.Events) != len(got.Events) {
		return Difference{Code: "EVENT_ORDER_MISMATCH", Pointer: "/events"}
	}
	for i := range want.Events {
		if want.Events[i] != got.Events[i] {
			return Difference{Code: "EVENT_ORDER_MISMATCH", Pointer: fmt.Sprintf("/events/%d", i)}
		}
	}
	if want.ErrorClass != got.ErrorClass {
		return Difference{Code: "ERROR_CLASS_MISMATCH", Pointer: "/error_class"}
	}
	if want.CloseOrigin != got.CloseOrigin {
		return Difference{Code: "CLOSE_ORIGIN_MISMATCH", Pointer: "/close_origin"}
	}
	if want.ConsumedBytes != got.ConsumedBytes {
		return Difference{Code: "CONSUMED_BYTES_MISMATCH", Pointer: "/consumed_bytes"}
	}
	return Difference{}
}

type commonCounts struct {
	Actions              uint64 `json:"actions"`
	BufferedBytes        uint64 `json:"buffered_bytes"`
	ConsumedBytes        uint64 `json:"consumed_bytes"`
	Frames               uint64 `json:"frames"`
	InputBytes           uint64 `json:"input_bytes"`
	MessageBufferedBytes uint64 `json:"message_buffered_bytes"`
	WireBufferedBytes    uint64 `json:"wire_buffered_bytes"`
}

type commonEvent struct {
	Step       uint16       `json:"step"`
	Kind       string       `json:"kind"`
	PayloadB64 string       `json:"payload_base64,omitempty"`
	Text       string       `json:"text,omitempty"`
	Close      *commonClose `json:"close,omitempty"`
}

type commonFrame struct {
	Step       uint16 `json:"step"`
	Direction  string `json:"direction"`
	Fin        bool   `json:"fin"`
	Opcode     string `json:"opcode"`
	Masked     bool   `json:"masked"`
	PayloadB64 string `json:"payload_base64"`
	WireLength uint64 `json:"wire_length"`
}

type commonTransition struct {
	Step uint16 `json:"step"`
	From string `json:"from"`
	To   string `json:"to"`
}

type commonClose struct {
	Code   *uint16 `json:"code"`
	Reason string  `json:"reason"`
	Clean  bool    `json:"clean"`
	Origin string  `json:"origin"`
}

type commonError struct {
	Class    string `json:"class"`
	Terminal bool   `json:"terminal"`
}

type commonObservation struct {
	ScenarioID   string             `json:"scenario_id"`
	Role         string             `json:"role"`
	InitialState string             `json:"initial_state"`
	Outcome      string             `json:"outcome"`
	Events       []commonEvent      `json:"events"`
	Frames       []commonFrame      `json:"frames"`
	Transitions  []commonTransition `json:"transitions"`
	FinalState   string             `json:"final_state"`
	Close        *commonClose       `json:"close"`
	Error        *commonError       `json:"error"`
	Counts       commonCounts       `json:"counts"`
}

type rustObservation struct {
	ScenarioID string
	Role       string
	Initial    string
	Bootstrap  []byte
	Steps      []rustStep
	Final      string
	Close      *commonClose
}

type rustStep struct {
	Index           uint16     `json:"index"`
	InputKind       byte       `json:"input_kind"`
	PreState        string     `json:"pre_state"`
	PostState       string     `json:"post_state"`
	Consumed        uint64     `json:"consumed_bytes"`
	WireBuffered    uint64     `json:"wire_buffered_bytes"`
	MessageBuffered uint64     `json:"message_buffered_bytes"`
	Observations    []rustItem `json:"observations"`
}

type rustItem struct {
	Kind       byte              `json:"kind"`
	Event      *commonEvent      `json:"event,omitempty"`
	Frame      *commonFrame      `json:"frame,omitempty"`
	Transition *commonTransition `json:"transition,omitempty"`
	Close      *commonClose      `json:"close,omitempty"`
	Error      *commonError      `json:"error,omitempty"`
	Transport  []byte            `json:"transport,omitempty"`
}

type childRequest struct {
	Executable string
	Args       []string
	Input      []byte
	Home       string
	Timeout    time.Duration
}

type launchSource struct {
	Role       string
	Path       string
	Executable bool
}

type launchObject struct {
	Path   string
	SHA256 string
	Bytes  int64
}

type launchBundle struct {
	ByRole     map[string]launchObject
	Identities []LaunchIdentity
}

type runtimeImageEntry struct {
	Path       string `json:"path"`
	Executable bool   `json:"executable"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}

type javaRuntimeMaterialization struct {
	Root         string
	Executable   string
	Identity     ArtifactIdentity
	LaunchInputs []LaunchIdentity
}

var javaRuntimeImageCopyHook func(string)

func javaRuntimeRoot(javaExecutable string) (string, error) {
	if !filepath.IsAbs(javaExecutable) || filepath.Clean(javaExecutable) != javaExecutable || filepath.Base(javaExecutable) != "java" || filepath.Base(filepath.Dir(javaExecutable)) != "bin" {
		return "", errors.New("Java executable must be an absolute JDK bin/java path")
	}
	resolved, err := filepath.EvalSymlinks(javaExecutable)
	if err != nil || resolved != javaExecutable {
		return "", errors.New("Java executable may not resolve through a symlink")
	}
	root := filepath.Dir(filepath.Dir(javaExecutable))
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil || resolvedRoot != root {
		return "", errors.New("Java runtime root may not resolve through a symlink")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("Java runtime root must be a real directory")
	}
	return root, nil
}

func readStableRuntimeFile(path string) ([]byte, os.FileMode, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() < 0 || opened.Size() > maximumRuntimeImageBytes {
		return nil, 0, errors.New("Java runtime entry is not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumRuntimeImageBytes+1))
	if err != nil || int64(len(raw)) != opened.Size() {
		return nil, 0, errors.New("Java runtime entry changed while reading")
	}
	current, err := os.Stat(path)
	if err != nil || !os.SameFile(opened, current) || current.Size() != opened.Size() || current.ModTime() != opened.ModTime() || current.Mode() != opened.Mode() {
		return nil, 0, errors.New("Java runtime entry was replaced while reading")
	}
	return raw, opened.Mode(), nil
}

func runtimeImageSourceFile(root, path string, entry os.DirEntry) ([]byte, os.FileMode, error) {
	if entry.Type()&os.ModeSymlink == 0 {
		if !entry.Type().IsRegular() {
			return nil, 0, errors.New("Java runtime contains a nonregular entry")
		}
		return readStableRuntimeFile(path)
	}
	linkBefore, err := os.Readlink(path)
	if err != nil || filepath.IsAbs(linkBefore) {
		return nil, 0, errors.New("Java runtime symlink must be relative")
	}
	linkInfoBefore, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !within(root, resolved) || resolved == root {
		return nil, 0, errors.New("Java runtime symlink escapes or does not resolve to a file")
	}
	raw, mode, err := readStableRuntimeFile(resolved)
	if err != nil {
		return nil, 0, err
	}
	linkAfter, linkErr := os.Readlink(path)
	linkInfoAfter, statErr := os.Lstat(path)
	if linkErr != nil || statErr != nil || linkBefore != linkAfter || !os.SameFile(linkInfoBefore, linkInfoAfter) {
		return nil, 0, errors.New("Java runtime symlink changed while reading")
	}
	return raw, mode, nil
}

func writeImmutableRuntimeFile(path string, raw []byte, executable bool) error {
	mode := os.FileMode(0o400)
	if executable {
		mode = 0o500
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func removeImmutableTree(root string) error {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr == nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	return os.RemoveAll(root)
}

func scanJavaRuntimeImage(root, destination string) ([]runtimeImageEntry, int64, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, 0, errors.New("Java runtime image root must be a real directory")
	}
	entries := []runtimeImageEntry{}
	total := int64(0)
	directories := []string{}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return errors.New("Java runtime traversal escaped root")
		}
		if relative == "." {
			return nil
		}
		if len(entries) >= maximumRuntimeImageFiles {
			return errors.New("Java runtime file-count bound exceeded")
		}
		if entry.IsDir() {
			if destination != "" {
				output := filepath.Join(destination, relative)
				if err := os.Mkdir(output, 0o700); err != nil {
					return err
				}
				directories = append(directories, output)
			}
			return nil
		}
		raw, sourceMode, err := runtimeImageSourceFile(root, path, entry)
		if err != nil {
			return fmt.Errorf("Java runtime %s: %w", filepath.ToSlash(relative), err)
		}
		total += int64(len(raw))
		if total > maximumRuntimeImageBytes {
			return errors.New("Java runtime byte bound exceeded")
		}
		executable := sourceMode.Perm()&0o111 != 0
		entries = append(entries, runtimeImageEntry{Path: filepath.ToSlash(relative), Executable: executable, Bytes: int64(len(raw)), SHA256: digest(raw)})
		if destination != "" {
			if javaRuntimeImageCopyHook != nil {
				javaRuntimeImageCopyHook(filepath.ToSlash(relative))
			}
			if err := writeImmutableRuntimeFile(filepath.Join(destination, relative), raw, executable); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if len(entries) == 0 {
		return nil, 0, errors.New("Java runtime image is empty")
	}
	if destination != "" {
		for index := len(directories) - 1; index >= 0; index-- {
			if err := os.Chmod(directories[index], 0o500); err != nil {
				return nil, 0, err
			}
		}
	}
	return entries, total, nil
}

func runtimeImageArtifact(root string, entries []runtimeImageEntry, total int64) (ArtifactIdentity, error) {
	raw, err := canonical(entries)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	return ArtifactIdentity{Kind: "java-runtime-image", Path: root, SHA256: digest(raw), Bytes: total}, nil
}

func javaRuntimeImageIdentity(javaExecutable string) (ArtifactIdentity, error) {
	root, err := javaRuntimeRoot(javaExecutable)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	for _, required := range []string{javaExecutable, filepath.Join(root, "lib/modules")} {
		info, err := os.Stat(required)
		if err != nil || !info.Mode().IsRegular() {
			return ArtifactIdentity{}, errors.New("Java runtime image is incomplete")
		}
	}
	entries, total, err := scanJavaRuntimeImage(root, "")
	if err != nil {
		return ArtifactIdentity{}, err
	}
	return runtimeImageArtifact(root, entries, total)
}

func verifyMaterializedJavaRuntimeImage(root string, expected ArtifactIdentity) error {
	for _, required := range []string{filepath.Join(root, "bin/java"), filepath.Join(root, "lib/modules")} {
		info, err := os.Lstat(required)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("materialized Java runtime image is incomplete")
		}
	}
	entries, total, err := scanJavaRuntimeImage(root, "")
	if err != nil {
		return err
	}
	actual, err := runtimeImageArtifact(expected.Path, entries, total)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("materialized Java runtime tree identity mismatch")
	}
	return nil
}

func materializeJavaRuntimeImage(store, javaExecutable string, expected ArtifactIdentity) (javaRuntimeMaterialization, error) {
	root, err := javaRuntimeRoot(javaExecutable)
	if err != nil {
		return javaRuntimeMaterialization{}, err
	}
	if expected.Kind != "java-runtime-image" || expected.Path != root || !validLedgerDigest(expected.SHA256) || expected.Bytes <= 0 {
		return javaRuntimeMaterialization{}, errors.New("expected Java runtime tree identity invalid")
	}
	if err := os.Mkdir(store, 0o700); err != nil {
		return javaRuntimeMaterialization{}, err
	}
	staging, err := os.MkdirTemp(store, ".java-runtime-staging-")
	if err != nil {
		return javaRuntimeMaterialization{}, err
	}
	defer removeImmutableTree(staging)
	entries, total, err := scanJavaRuntimeImage(root, staging)
	if err != nil {
		return javaRuntimeMaterialization{}, err
	}
	first, err := runtimeImageArtifact(root, entries, total)
	if err != nil || first != expected {
		return javaRuntimeMaterialization{}, errors.New("Java runtime source identity changed before or during copy")
	}
	second, err := javaRuntimeImageIdentity(javaExecutable)
	if err != nil || second != expected {
		return javaRuntimeMaterialization{}, errors.New("Java runtime source identity changed during copy")
	}
	objectName := strings.TrimPrefix(expected.SHA256, "sha256:")
	finalRoot := filepath.Join(store, objectName)
	if err := os.Rename(staging, finalRoot); err != nil {
		return javaRuntimeMaterialization{}, err
	}
	if err := verifyMaterializedJavaRuntimeImage(finalRoot, expected); err != nil {
		return javaRuntimeMaterialization{}, err
	}
	javaFile, err := artifact(filepath.Join(finalRoot, "bin/java"))
	if err != nil {
		return javaRuntimeMaterialization{}, err
	}
	launches := []LaunchIdentity{
		{Role: "java-runtime-image", SourcePath: root, SourceSHA256: expected.SHA256, ObjectSHA256: expected.SHA256, ObjectName: objectName, Bytes: expected.Bytes},
		{Role: "java-executable", SourcePath: javaExecutable, SourceSHA256: javaFile.SHA256, ObjectSHA256: javaFile.SHA256, ObjectName: strings.TrimPrefix(javaFile.SHA256, "sha256:"), Bytes: javaFile.Bytes},
	}
	return javaRuntimeMaterialization{Root: finalRoot, Executable: filepath.Join(finalRoot, "bin/java"), Identity: expected, LaunchInputs: launches}, nil
}

func materializeLaunchInputs(store string, sources []launchSource) (launchBundle, error) {
	if len(sources) == 0 || len(sources) > 32 {
		return launchBundle{}, errors.New("launch source cardinality invalid")
	}
	if err := os.Mkdir(store, 0o700); err != nil {
		return launchBundle{}, err
	}
	bundle := launchBundle{ByRole: map[string]launchObject{}, Identities: []LaunchIdentity{}}
	for _, source := range sources {
		if source.Role == "" || bundle.ByRole[source.Role].Path != "" {
			return launchBundle{}, errors.New("launch role absent or duplicate")
		}
		raw, err := readRegularBounded(source.Path, 512<<20)
		if err != nil {
			return launchBundle{}, err
		}
		sha := digest(raw)
		name := strings.TrimPrefix(sha, "sha256:")
		objectPath := filepath.Join(store, name)
		mode := os.FileMode(0o400)
		if source.Executable {
			mode = 0o500
		}
		file, err := os.OpenFile(objectPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if errors.Is(err, os.ErrExist) {
			existing, readErr := readRegularBounded(objectPath, 512<<20)
			if readErr != nil || !bytes.Equal(existing, raw) {
				return launchBundle{}, errors.New("content-addressed launch object collision")
			}
			if source.Executable {
				if chmodErr := os.Chmod(objectPath, 0o500); chmodErr != nil {
					return launchBundle{}, chmodErr
				}
			}
		} else if err != nil {
			return launchBundle{}, err
		} else {
			if _, err := file.Write(raw); err != nil {
				file.Close()
				return launchBundle{}, err
			}
			if err := file.Sync(); err != nil {
				file.Close()
				return launchBundle{}, err
			}
			if err := file.Close(); err != nil {
				return launchBundle{}, err
			}
		}
		launched, err := readRegularBounded(objectPath, 512<<20)
		if err != nil || digest(launched) != sha {
			return launchBundle{}, errors.New("launched object identity mismatch")
		}
		object := launchObject{Path: objectPath, SHA256: sha, Bytes: int64(len(raw))}
		bundle.ByRole[source.Role] = object
		bundle.Identities = append(bundle.Identities, LaunchIdentity{Role: source.Role, SourcePath: source.Path, SourceSHA256: sha, ObjectSHA256: sha, ObjectName: name, Bytes: int64(len(raw))})
	}
	return bundle, nil
}

func materializeConfiguredLaunch(cfg Config, suiteRoot string, inputs []ArtifactIdentity) (Config, error) {
	inputByKind := map[string]ArtifactIdentity{}
	for _, input := range inputs {
		inputByKind[input.Kind] = input
	}
	javaImage, err := materializeJavaRuntimeImage(filepath.Join(suiteRoot, "java-runtime-images"), cfg.JavaExecutable, inputByKind["java-runtime-image"])
	if err != nil {
		return Config{}, err
	}
	sources := []launchSource{{Role: "java-adapter", Path: cfg.JavaAdapterJar}, {Role: "java-runtime", Path: cfg.JavaRuntimeJar}, {Role: "rust-testee", Path: cfg.RustTestee, Executable: true}}
	for index, path := range cfg.JavaSupportJars {
		sources = append(sources, launchSource{Role: fmt.Sprintf("java-support-%02d", index), Path: path})
	}
	bundle, err := materializeLaunchInputs(filepath.Join(suiteRoot, "launch-objects"), sources)
	if err != nil {
		return Config{}, err
	}
	launched := cfg
	launched.JavaExecutable = javaImage.Executable
	launched.JavaAdapterJar = bundle.ByRole["java-adapter"].Path
	launched.JavaRuntimeJar = bundle.ByRole["java-runtime"].Path
	launched.RustTestee = bundle.ByRole["rust-testee"].Path
	launched.JavaSupportJars = make([]string, len(cfg.JavaSupportJars))
	launched.launchInputs = map[string][]LaunchIdentity{"java": expectedLaunchIdentities("java", inputs), "rust": expectedLaunchIdentities("rust", inputs)}
	for _, identity := range bundle.Identities {
		if strings.HasPrefix(identity.Role, "java-support-") {
			index, _ := strconv.Atoi(strings.TrimPrefix(identity.Role, "java-support-"))
			launched.JavaSupportJars[index] = bundle.ByRole[identity.Role].Path
		}
	}
	return launched, nil
}

type childResult struct {
	PID      int
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Started  time.Time
	Duration time.Duration
}

var executeChild = executeBoundedChild
var commitEvidenceDocuments = commitEvidencePair
var readCommittedEvidence = readRegularBounded
var readVerificationLedger = readRegularBounded

type cappedBuffer struct {
	maximum int
	value   bytes.Buffer
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.maximum - b.value.Len()
	if remaining <= 0 {
		return 0, errors.New("process output exceeded bound")
	}
	if len(p) > remaining {
		_, _ = b.value.Write(p[:remaining])
		return remaining, errors.New("process output exceeded bound")
	}
	return b.value.Write(p)
}

func executeBoundedChild(ctx context.Context, request childRequest) (childResult, error) {
	childCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	cmd := exec.CommandContext(childCtx, request.Executable, request.Args...)
	cmd.Stdin = bytes.NewReader(request.Input)
	stdout := &cappedBuffer{maximum: maximumProcessOutput}
	stderr := &cappedBuffer{maximum: maximumProcessError}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Env = []string{
		"HOME=" + request.Home,
		"LANG=C",
		"LC_ALL=C",
		"TZ=UTC",
	}
	started := time.Now()
	if err := cmd.Start(); err != nil {
		return childResult{}, err
	}
	result := childResult{PID: cmd.Process.Pid, Started: started}
	err := cmd.Wait()
	result.Duration = time.Since(started)
	result.Stdout = append([]byte(nil), stdout.value.Bytes()...)
	result.Stderr = append([]byte(nil), stderr.value.Bytes()...)
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if childCtx.Err() != nil {
		return result, fmt.Errorf("child timeout: %w", childCtx.Err())
	}
	if err != nil {
		return result, fmt.Errorf("child exit %d: %w", result.ExitCode, err)
	}
	if result.ExitCode != 0 {
		return result, fmt.Errorf("child exit %d", result.ExitCode)
	}
	return result, nil
}

func appendTLV(dst *bytes.Buffer, tag byte, value []byte) {
	dst.WriteByte(tag)
	_ = binary.Write(dst, binary.BigEndian, uint32(len(value)))
	dst.Write(value)
}

func deterministicMask(scenarioID string, step int) [4]byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("us020-mask-v1|%s|%d", scenarioID, step)))
	return [4]byte{sum[0], sum[1], sum[2], sum[3]}
}

func appendKeyOption(dst *bytes.Buffer, role, scenarioID string, step int) {
	if role == "client" {
		dst.WriteByte(1)
		key := deterministicMask(scenarioID, step)
		dst.Write(key[:])
		return
	}
	dst.WriteByte(0)
}

func encodeNeutralRequest(sc corpora.Scenario) ([]byte, error) {
	body := &bytes.Buffer{}
	body.WriteString("NDRV1")
	appendTLV(body, 1, []byte(sc.ScenarioID))
	role := byte(0)
	switch sc.Core.Role {
	case "client":
		role = 1
	case "server":
		role = 2
	default:
		return nil, fmt.Errorf("unsupported role %q", sc.Core.Role)
	}
	appendTLV(body, 2, []byte{role})
	initial := map[string]byte{"open": 1, "closing": 2, "closed": 3}[sc.Core.InitialState]
	if initial == 0 {
		return nil, fmt.Errorf("unsupported initial state %q", sc.Core.InitialState)
	}
	appendTLV(body, 3, []byte{initial})
	limits := &bytes.Buffer{}
	for _, value := range []uint64{
		uint64(sc.Core.Limits.MaxActions), uint64(sc.Core.Limits.MaxBufferedBytes),
		uint64(sc.Core.Limits.MaxFrames), uint64(sc.Core.Limits.MaxInputBytes),
		uint64(sc.Core.Limits.MaxOutputBytes),
	} {
		_ = binary.Write(limits, binary.BigEndian, value)
	}
	appendTLV(body, 4, limits.Bytes())
	steps := &bytes.Buffer{}
	if len(sc.Core.Steps) > 65535 {
		return nil, errors.New("too many steps")
	}
	_ = binary.Write(steps, binary.BigEndian, uint16(len(sc.Core.Steps)))
	for index, step := range sc.Core.Steps {
		record := &bytes.Buffer{}
		if step.Kind == "bytes" {
			record.WriteByte(1)
			payload, err := base64.StdEncoding.DecodeString(step.DataBase64)
			if err != nil || base64.StdEncoding.EncodeToString(payload) != step.DataBase64 {
				return nil, fmt.Errorf("scenario %s step %d has noncanonical base64", sc.ScenarioID, index)
			}
			record.Write(payload)
		} else if step.Kind == "action" {
			switch step.Action {
			case "eof":
				record.WriteByte(2)
			case "send_text":
				record.WriteByte(0x10)
				appendKeyOption(record, sc.Core.Role, sc.ScenarioID, index)
				record.WriteString(step.Text)
			case "send_binary", "send_ping", "send_pong":
				kind := map[string]byte{"send_binary": 0x11, "send_ping": 0x13, "send_pong": 0x14}[step.Action]
				record.WriteByte(kind)
				appendKeyOption(record, sc.Core.Role, sc.ScenarioID, index)
				payload, err := base64.StdEncoding.DecodeString(step.DataBase64)
				if err != nil || base64.StdEncoding.EncodeToString(payload) != step.DataBase64 {
					return nil, fmt.Errorf("scenario %s step %d has noncanonical base64", sc.ScenarioID, index)
				}
				record.Write(payload)
			case "send_fragment":
				record.WriteByte(0x12)
				fragmentKind := map[string]byte{"text": 1, "binary": 2}[step.Opcode]
				if fragmentKind == 0 {
					return nil, fmt.Errorf("unsupported fragment opcode %q", step.Opcode)
				}
				record.WriteByte(fragmentKind)
				if step.Fin {
					record.WriteByte(1)
				} else {
					record.WriteByte(0)
				}
				appendKeyOption(record, sc.Core.Role, sc.ScenarioID, index)
				payload, err := base64.StdEncoding.DecodeString(step.DataBase64)
				if err != nil || base64.StdEncoding.EncodeToString(payload) != step.DataBase64 {
					return nil, fmt.Errorf("scenario %s step %d has noncanonical base64", sc.ScenarioID, index)
				}
				record.Write(payload)
			case "send_close":
				record.WriteByte(0x15)
				appendKeyOption(record, sc.Core.Role, sc.ScenarioID, index)
				if step.Code == 0 {
					record.WriteByte(0)
				} else if step.Code >= 0 && step.Code <= 65535 {
					record.WriteByte(1)
					_ = binary.Write(record, binary.BigEndian, uint16(step.Code))
				} else {
					return nil, fmt.Errorf("close code out of range")
				}
				record.WriteString(step.Reason)
			default:
				return nil, fmt.Errorf("unsupported action %q", step.Action)
			}
		} else {
			return nil, fmt.Errorf("unsupported step kind %q", step.Kind)
		}
		_ = binary.Write(steps, binary.BigEndian, uint32(record.Len()))
		steps.Write(record.Bytes())
	}
	appendTLV(body, 5, steps.Bytes())
	if body.Len() > neutralProtocolMaximum {
		return nil, errors.New("neutral request exceeds bound")
	}
	framed := &bytes.Buffer{}
	_ = binary.Write(framed, binary.BigEndian, uint32(body.Len()))
	framed.Write(body.Bytes())
	return framed.Bytes(), nil
}

type binaryReader struct{ *bytes.Reader }

func (r binaryReader) byte() (byte, error) { return r.ReadByte() }
func (r binaryReader) u16() (uint16, error) {
	var v uint16
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}
func (r binaryReader) u32() (uint32, error) {
	var v uint32
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}
func (r binaryReader) u64() (uint64, error) {
	var v uint64
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}
func (r binaryReader) exact(n uint32) ([]byte, error) {
	if uint64(n) > uint64(r.Len()) {
		return nil, io.ErrUnexpectedEOF
	}
	value := make([]byte, int(n))
	_, err := io.ReadFull(r, value)
	return value, err
}

func decodeState(value byte) (string, error) {
	switch value {
	case 1:
		return "open", nil
	case 2:
		return "closing", nil
	case 3:
		return "closed", nil
	}
	return "", fmt.Errorf("unknown state %d", value)
}

func decodeRole(value byte) (string, error) {
	switch value {
	case 1:
		return "client", nil
	case 2:
		return "server", nil
	}
	return "", fmt.Errorf("unknown role %d", value)
}

func decodeCloseBody(data []byte) (*commonClose, error) {
	r := binaryReader{bytes.NewReader(data)}
	present, err := r.byte()
	if err != nil {
		return nil, err
	}
	var code *uint16
	if present == 1 {
		value, err := r.u16()
		if err != nil {
			return nil, err
		}
		code = &value
	} else if present != 0 {
		return nil, errors.New("invalid close code option")
	}
	reasonLen, err := r.u32()
	if err != nil {
		return nil, err
	}
	reason, err := r.exact(reasonLen)
	if err != nil {
		return nil, err
	}
	clean, err := r.byte()
	if err != nil || clean > 1 {
		return nil, errors.New("invalid close clean flag")
	}
	originByte, err := r.byte()
	if err != nil {
		return nil, err
	}
	origins := map[byte]string{1: "local", 2: "remote", 3: "unknown_before_scenario", 4: "none", 5: "transport"}
	origin, ok := origins[originByte]
	if !ok {
		return nil, errors.New("invalid close origin")
	}
	if r.Len() != 0 {
		return nil, errors.New("trailing close bytes")
	}
	return &commonClose{Code: code, Reason: string(reason), Clean: clean == 1, Origin: origin}, nil
}

func decodeNeutralResponse(raw []byte) (rustObservation, error) {
	if len(raw) < 4 {
		return rustObservation{}, io.ErrUnexpectedEOF
	}
	length := binary.BigEndian.Uint32(raw[:4])
	if length > neutralProtocolMaximum || int(length) != len(raw)-4 {
		return rustObservation{}, errors.New("NOBS1 length or trailing bytes invalid")
	}
	body := raw[4:]
	if len(body) < 5 || string(body[:5]) != "NOBS1" {
		return rustObservation{}, errors.New("NOBS1 magic invalid")
	}
	r := binaryReader{bytes.NewReader(body[5:])}
	values := map[byte][]byte{}
	last := byte(0)
	for r.Len() > 0 {
		tag, err := r.byte()
		if err != nil {
			return rustObservation{}, err
		}
		if tag <= last || tag < 1 || tag > 7 {
			return rustObservation{}, errors.New("NOBS1 tag order invalid")
		}
		last = tag
		size, err := r.u32()
		if err != nil {
			return rustObservation{}, err
		}
		value, err := r.exact(size)
		if err != nil {
			return rustObservation{}, err
		}
		values[tag] = value
	}
	if len(values) != 7 {
		return rustObservation{}, errors.New("NOBS1 missing required tag")
	}
	result := rustObservation{ScenarioID: string(values[1]), Bootstrap: append([]byte(nil), values[4]...)}
	if len(values[2]) != 1 || len(values[3]) != 1 || len(values[6]) != 1 {
		return rustObservation{}, errors.New("NOBS1 scalar field length invalid")
	}
	var err error
	result.Role, err = decodeRole(values[2][0])
	if err != nil {
		return rustObservation{}, err
	}
	result.Initial, err = decodeState(values[3][0])
	if err != nil {
		return rustObservation{}, err
	}
	result.Final, err = decodeState(values[6][0])
	if err != nil {
		return rustObservation{}, err
	}
	steps := binaryReader{bytes.NewReader(values[5])}
	count, err := steps.u16()
	if err != nil {
		return rustObservation{}, err
	}
	result.Steps = make([]rustStep, 0, count)
	for index := uint16(0); index < count; index++ {
		size, err := steps.u32()
		if err != nil {
			return rustObservation{}, err
		}
		record, err := steps.exact(size)
		if err != nil {
			return rustObservation{}, err
		}
		step, err := decodeRustStep(record)
		if err != nil {
			return rustObservation{}, fmt.Errorf("step %d: %w", index, err)
		}
		if step.Index != index {
			return rustObservation{}, errors.New("NOBS1 step indexes are not contiguous")
		}
		result.Steps = append(result.Steps, step)
	}
	if steps.Len() != 0 {
		return rustObservation{}, errors.New("NOBS1 trailing step bytes")
	}
	closeValue := values[7]
	if len(closeValue) == 0 {
		return rustObservation{}, errors.New("NOBS1 terminal close option missing")
	}
	if closeValue[0] == 1 {
		result.Close, err = decodeCloseBody(closeValue[1:])
		if err != nil {
			return rustObservation{}, err
		}
	} else if closeValue[0] != 0 || len(closeValue) != 1 {
		return rustObservation{}, errors.New("NOBS1 terminal close option invalid")
	}
	return result, nil
}

func decodeRustStep(data []byte) (rustStep, error) {
	r := binaryReader{bytes.NewReader(data)}
	step := rustStep{Observations: []rustItem{}}
	var err error
	step.Index, err = r.u16()
	if err != nil {
		return step, err
	}
	step.InputKind, err = r.byte()
	if err != nil {
		return step, err
	}
	pre, err := r.byte()
	if err != nil {
		return step, err
	}
	step.PreState, err = decodeState(pre)
	if err != nil {
		return step, err
	}
	post, err := r.byte()
	if err != nil {
		return step, err
	}
	step.PostState, err = decodeState(post)
	if err != nil {
		return step, err
	}
	step.Consumed, err = r.u64()
	if err != nil {
		return step, err
	}
	step.WireBuffered, err = r.u64()
	if err != nil {
		return step, err
	}
	step.MessageBuffered, err = r.u64()
	if err != nil {
		return step, err
	}
	count, err := r.u16()
	if err != nil {
		return step, err
	}
	for index := uint16(0); index < count; index++ {
		size, err := r.u32()
		if err != nil {
			return step, err
		}
		record, err := r.exact(size)
		if err != nil {
			return step, err
		}
		item, err := decodeRustItem(step.Index, record)
		if err != nil {
			return step, fmt.Errorf("observation %d: %w", index, err)
		}
		step.Observations = append(step.Observations, item)
	}
	if r.Len() != 0 {
		return step, errors.New("trailing step bytes")
	}
	return step, nil
}

func decodeRustItem(step uint16, data []byte) (rustItem, error) {
	r := binaryReader{bytes.NewReader(data)}
	kind, err := r.byte()
	if err != nil {
		return rustItem{}, err
	}
	item := rustItem{Kind: kind}
	switch kind {
	case 1:
		eventKind, err := r.byte()
		if err != nil {
			return item, err
		}
		event := &commonEvent{Step: step}
		switch eventKind {
		case 1:
			event.Kind = "text"
			n, err := r.u32()
			if err != nil {
				return item, err
			}
			value, err := r.exact(n)
			if err != nil {
				return item, err
			}
			event.Text = string(value)
		case 2, 3, 4:
			event.Kind = map[byte]string{2: "binary", 3: "ping", 4: "pong"}[eventKind]
			n, err := r.u32()
			if err != nil {
				return item, err
			}
			value, err := r.exact(n)
			if err != nil {
				return item, err
			}
			event.PayloadB64 = base64.StdEncoding.EncodeToString(value)
		case 5:
			event.Kind = "close"
			value, err := io.ReadAll(r)
			if err != nil {
				return item, err
			}
			event.Close, err = decodeCloseBody(value)
			if err != nil {
				return item, err
			}
		case 6, 7:
			event.Kind = map[byte]string{6: "client_handshake_opened", 7: "server_handshake_opened"}[eventKind]
		default:
			return item, errors.New("unknown event kind")
		}
		if r.Len() != 0 {
			return item, errors.New("trailing event bytes")
		}
		item.Event = event
	case 2:
		direction, err := r.byte()
		if err != nil {
			return item, err
		}
		fin, err := r.byte()
		if err != nil || fin > 1 {
			return item, errors.New("invalid frame fin")
		}
		opcode, err := r.byte()
		if err != nil {
			return item, err
		}
		masked, err := r.byte()
		if err != nil || masked > 1 {
			return item, errors.New("invalid frame mask")
		}
		n, err := r.u32()
		if err != nil {
			return item, err
		}
		payload, err := r.exact(n)
		if err != nil {
			return item, err
		}
		wire, err := r.u64()
		if err != nil {
			return item, err
		}
		if r.Len() != 0 {
			return item, errors.New("trailing frame bytes")
		}
		directions := map[byte]string{1: "inbound", 2: "outbound"}
		opcodes := map[byte]string{0: "continuous", 1: "text", 2: "binary", 8: "closing", 9: "ping", 10: "pong"}
		directionName, ok := directions[direction]
		if !ok {
			return item, errors.New("unknown frame direction")
		}
		opcodeName, ok := opcodes[opcode]
		if !ok {
			return item, errors.New("unknown frame opcode")
		}
		item.Frame = &commonFrame{Step: step, Direction: directionName, Fin: fin == 1, Opcode: opcodeName, Masked: masked == 1, PayloadB64: base64.StdEncoding.EncodeToString(payload), WireLength: wire}
	case 3:
		from, err := r.byte()
		if err != nil {
			return item, err
		}
		to, err := r.byte()
		if err != nil {
			return item, err
		}
		if r.Len() != 0 {
			return item, errors.New("trailing transition bytes")
		}
		fromState, err := decodeState(from)
		if err != nil {
			return item, err
		}
		toState, err := decodeState(to)
		if err != nil {
			return item, err
		}
		item.Transition = &commonTransition{Step: step, From: fromState, To: toState}
	case 4:
		value, err := io.ReadAll(r)
		if err != nil {
			return item, err
		}
		item.Close, err = decodeCloseBody(value)
		if err != nil {
			return item, err
		}
	case 5:
		terminal, err := r.byte()
		if err != nil || terminal > 1 {
			return item, errors.New("invalid error terminal")
		}
		n, err := r.u16()
		if err != nil {
			return item, err
		}
		value, err := r.exact(uint32(n))
		if err != nil {
			return item, err
		}
		if r.Len() != 0 {
			return item, errors.New("trailing error bytes")
		}
		item.Error = &commonError{Class: string(value), Terminal: terminal == 1}
	case 6:
		_, err := r.byte()
		if err != nil {
			return item, err
		}
		n, err := r.u32()
		if err != nil {
			return item, err
		}
		item.Transport, err = r.exact(n)
		if err != nil {
			return item, err
		}
		if r.Len() != 0 {
			return item, errors.New("trailing transport bytes")
		}
	default:
		return item, errors.New("unknown observation kind")
	}
	return item, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonical(value any) ([]byte, error) { return json.Marshal(value) }

func readRegularBounded(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 0 || before.Size() > maximum {
		return nil, fmt.Errorf("unsafe regular file %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("file identity changed: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds bound: %s", path)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Size() != int64(len(data)) {
		return nil, fmt.Errorf("file drift: %s", path)
	}
	return data, nil
}

func loadPublicCorpus(root, corpusPath string) ([]corpora.Scenario, []byte, error) {
	if filepath.Clean(corpusPath) != filepath.Join(root, "corpora/public/scenarios.jsonl") {
		return nil, nil, errors.New("public corpus must be the exact committed allowlisted path")
	}
	raw, err := readRegularBounded(corpusPath, maximumDocumentBytes)
	if err != nil {
		return nil, nil, err
	}
	manifestRaw, err := readRegularBounded(filepath.Join(root, "corpora/public/manifest.json"), 1<<20)
	if err != nil {
		return nil, nil, err
	}
	var manifest struct {
		Generator struct {
			PublicSeed string `json:"public_seed"`
		} `json:"generator"`
		Counts struct {
			Selected int `json:"selected"`
			Executed int `json:"executed"`
		} `json:"counts"`
		Artifacts []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Bytes  int    `json:"bytes"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, nil, err
	}
	if manifest.Generator.PublicSeed == "" || manifest.Counts.Selected != expectedPublicScenarios || manifest.Counts.Executed != expectedPublicScenarios || len(manifest.Artifacts) != 1 || manifest.Artifacts[0].Path != "scenarios.jsonl" || manifest.Artifacts[0].SHA256 != digest(raw) || manifest.Artifacts[0].Bytes != len(raw) {
		return nil, nil, errors.New("public manifest does not bind exact 74-scenario corpus")
	}
	public, _, plan, err := corpora.GeneratePublic(manifest.Generator.PublicSeed)
	if err != nil {
		return nil, nil, err
	}
	if len(public) != expectedPublicScenarios || plan["public"].Selected != expectedPublicScenarios {
		return nil, nil, errors.New("public derivation count drift")
	}
	var derived bytes.Buffer
	for _, sc := range public {
		line, err := sc.CanonicalLine()
		if err != nil {
			return nil, nil, err
		}
		derived.Write(line)
		derived.WriteByte('\n')
	}
	if !bytes.Equal(raw, derived.Bytes()) {
		return nil, nil, errors.New("committed public corpus differs from exact deterministic rederivation")
	}
	return public, raw, nil
}

func scenarioExpectedMap(sc corpora.Scenario) (map[string]any, error) {
	raw, err := json.Marshal(sc)
	if err != nil {
		return nil, err
	}
	var all map[string]any
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, err
	}
	expected, ok := all["expected"].(map[string]any)
	if !ok {
		return nil, errors.New("scenario expected object absent")
	}
	expected["role"] = sc.Core.Role
	expected["initial_state"] = sc.Core.InitialState
	return expected, nil
}

func escapePointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func collectLeaves(value any, pointer string, out map[string]any) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			collectLeaves(typed[key], pointer+"/"+escapePointer(key), out)
		}
	case []any:
		if len(typed) == 0 {
			out[pointer] = typed
			return
		}
		for index, item := range typed {
			collectLeaves(item, fmt.Sprintf("%s/%d", pointer, index), out)
		}
	default:
		out[pointer] = typed
	}
}

func expectedClosePayloadBase64(sc corpora.Scenario) (string, bool) {
	if sc.Expected.Close == nil {
		return "", false
	}
	if sc.Family == "close-remote-empty" {
		return "", true
	}
	var code uint16
	switch value := sc.Expected.Close["code"].(type) {
	case int:
		if value < 0 || value > 65535 {
			return "", false
		}
		code = uint16(value)
	case float64:
		if value < 0 || value > 65535 || value != float64(uint16(value)) {
			return "", false
		}
		code = uint16(value)
	default:
		return "", false
	}
	reason, ok := sc.Expected.Close["reason"].(string)
	if !ok {
		return "", false
	}
	payload := make([]byte, 2, 2+len(reason))
	binary.BigEndian.PutUint16(payload, code)
	payload = append(payload, reason...)
	return base64.StdEncoding.EncodeToString(payload), true
}

func expectedCloseFrameWireLength(frame map[string]any, payloadBase64 string) (uint64, bool) {
	payload, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != payloadBase64 || len(payload) > 125 {
		return 0, false
	}
	masked, ok := frame["masked"].(bool)
	if !ok {
		return 0, false
	}
	wireLength := uint64(2 + len(payload))
	if masked {
		wireLength += 4
	}
	return wireLength, true
}

func terminalFailureTransition(sc corpora.Scenario) ([]commonTransition, bool) {
	if sc.Core.InitialState != "open" || sc.Expected.Outcome != "error" || sc.Expected.Error == nil || sc.Expected.Error.CloseCode == nil || len(sc.Core.Steps) == 0 || sc.Core.Steps[len(sc.Core.Steps)-1].Kind != "bytes" {
		return nil, false
	}
	return []commonTransition{{Step: uint16(len(sc.Core.Steps) - 1), From: "open", To: "closed"}}, true
}

func canonicalOracleValue(value any) ([]byte, error) {
	raw, err := canonical(value)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return canonical(generic)
}

func decodePublicInboundFrames(sc corpora.Scenario) ([]commonFrame, error) {
	frames := []commonFrame{}
	opcodes := map[byte]string{0: "continuous", 1: "text", 2: "binary", 8: "closing", 9: "ping", 10: "pong"}
	for stepIndex, step := range sc.Core.Steps {
		if step.Kind != "bytes" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(step.DataBase64)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != step.DataBase64 {
			return nil, fmt.Errorf("%s step %d is not canonical base64", sc.ScenarioID, stepIndex)
		}
		for offset := 0; offset < len(raw); {
			start := offset
			if len(raw)-offset < 2 {
				return nil, fmt.Errorf("%s step %d has a truncated frame header", sc.ScenarioID, stepIndex)
			}
			first, second := raw[offset], raw[offset+1]
			offset += 2
			opcode, ok := opcodes[first&0x0f]
			if !ok {
				return nil, fmt.Errorf("%s step %d has unsupported opcode", sc.ScenarioID, stepIndex)
			}
			payloadLength := uint64(second & 0x7f)
			switch payloadLength {
			case 126:
				if len(raw)-offset < 2 {
					return nil, fmt.Errorf("%s step %d has a truncated 16-bit length", sc.ScenarioID, stepIndex)
				}
				payloadLength = uint64(binary.BigEndian.Uint16(raw[offset : offset+2]))
				offset += 2
			case 127:
				if len(raw)-offset < 8 {
					return nil, fmt.Errorf("%s step %d has a truncated 64-bit length", sc.ScenarioID, stepIndex)
				}
				payloadLength = binary.BigEndian.Uint64(raw[offset : offset+8])
				offset += 8
			}
			masked := second&0x80 != 0
			var mask [4]byte
			if masked {
				if len(raw)-offset < len(mask) {
					return nil, fmt.Errorf("%s step %d has a truncated mask", sc.ScenarioID, stepIndex)
				}
				copy(mask[:], raw[offset:offset+len(mask)])
				offset += len(mask)
			}
			if payloadLength > uint64(len(raw)-offset) {
				return nil, fmt.Errorf("%s step %d has a truncated payload", sc.ScenarioID, stepIndex)
			}
			end := offset + int(payloadLength)
			payload := append([]byte(nil), raw[offset:end]...)
			if masked {
				for index := range payload {
					payload[index] ^= mask[index%len(mask)]
				}
			}
			offset = end
			frames = append(frames, commonFrame{Step: uint16(stepIndex), Direction: "inbound", Fin: first&0x80 != 0, Opcode: opcode, Masked: masked, PayloadB64: base64.StdEncoding.EncodeToString(payload), WireLength: uint64(offset - start)})
		}
	}
	return frames, nil
}

func selectedRejectedFrames(sc corpora.Scenario) ([]commonFrame, bool, error) {
	switch sc.Family {
	case "unexpected-continuation", "data-during-fragment", "fragment-restart", "state-frame-in-closing":
		frames, err := decodePublicInboundFrames(sc)
		return frames, true, err
	case "frame-limit":
		frames, err := decodePublicInboundFrames(sc)
		if err != nil {
			return nil, true, err
		}
		if sc.Core.Limits.MaxFrames < 0 {
			return nil, true, errors.New("frame-limit scenario has a negative frame bound")
		}
		accepted := sc.Core.Limits.MaxFrames
		if accepted > len(frames) {
			accepted = len(frames)
		}
		// A minimized candidate can contain fewer complete public frames than
		// the original limit. In that case every frame present was accepted;
		// the prefix is derived solely from the candidate's decoded bytes.
		return frames[:accepted], true, nil
	case "action-limit":
		if sc.Core.Limits.MaxActions < 0 {
			return nil, true, errors.New("action-limit scenario has a negative action bound")
		}
		accepted := sc.Core.Limits.MaxActions
		if accepted > len(sc.Core.Steps) {
			accepted = len(sc.Core.Steps)
		}
		frames := make([]commonFrame, 0, accepted)
		for index, step := range sc.Core.Steps[:accepted] {
			if step.Kind != "action" || step.Action != "send_text" {
				return nil, true, errors.New("action-limit frame derivation supports send_text only")
			}
			payload := []byte(step.Text)
			masked := sc.Core.Role == "client"
			wireLength := uint64(2 + len(payload))
			if masked {
				wireLength += 4
			}
			frames = append(frames, commonFrame{Step: uint16(index), Direction: "outbound", Fin: true, Opcode: "text", Masked: masked, PayloadB64: base64.StdEncoding.EncodeToString(payload), WireLength: wireLength})
		}
		return frames, true, nil
	default:
		return nil, false, nil
	}
}

func explicitRFCOracleOverride(sc corpora.Scenario, pointer string) (any, string, bool) {
	if sc.ScenarioID == "us005.pub.0035" {
		switch {
		case strings.HasPrefix(pointer, "/close/"), strings.HasPrefix(pointer, "/events/"), strings.HasPrefix(pointer, "/frames/"):
			return absentObservationValue{Absent: true}, "rfc6455.section-7-4", true
		case pointer == "/counts/frames":
			return float64(0), "rfc6455.section-7-4", true
		case pointer == "/error":
			return map[string]any{"class": "PROTOCOL_REJECTION", "terminal": false}, "rfc6455.section-7-4", true
		case pointer == "/final_state":
			return "closed", "rfc6455.section-7-4", true
		case pointer == "/outcome":
			return "error", "rfc6455.section-7-4", true
		case pointer == "/transitions/0/to":
			return "closed", "rfc6455.section-7-4", true
		}
	}
	if sc.Family == "close-remote-empty" {
		switch pointer {
		case "/close/code", "/events/0/close/code":
			return nil, "rfc6455.section-5-5-1", true
		case "/frames/0/payload_base64", "/frames/1/payload_base64":
			return "", "rfc6455.section-5-5-1", true
		case "/frames/1/wire_length":
			return float64(2), "rfc6455.section-5-5-1", true
		}
	}
	if payload, ok := expectedClosePayloadBase64(sc); ok {
		for index, frame := range sc.Expected.Frames {
			if frame["opcode"] != "closing" {
				continue
			}
			if frame["direction"] == "inbound" && pointer == fmt.Sprintf("/frames/%d/payload_base64", index) {
				return payload, "rfc6455.section-5-5-1", true
			}
			if sc.Family == "close-remote" && pointer == fmt.Sprintf("/frames/%d/payload_base64", index) {
				return payload, "rfc6455.section-5-5-1", true
			}
			if sc.Family == "close-remote" && pointer == fmt.Sprintf("/frames/%d/wire_length", index) {
				if wireLength, ok := expectedCloseFrameWireLength(frame, payload); ok {
					return float64(wireLength), "rfc6455.section-5-5-1", true
				}
			}
		}
	}
	return nil, "", false
}

// BuildOracleHierarchy creates one exact decision cell per field on the common
// lossless runtime surface. The hierarchy selects RFC 6455 over the incumbent
// Java behavior only where the public scenario cites the applicable clause;
// project-local accounting remains governed by the committed neutral oracle.
func BuildOracleHierarchy(scenarios []corpora.Scenario) (OracleHierarchy, error) {
	if len(scenarios) != expectedPublicScenarios {
		return OracleHierarchy{}, fmt.Errorf("scenario count %d", len(scenarios))
	}
	h := OracleHierarchy{Schema: "../schemas/oracle-hierarchy-1.0.0.schema.json", SchemaVersion: "1.0.0", EvidenceKind: "oracle-hierarchy", ScenarioCount: len(scenarios)}
	for _, sc := range scenarios {
		expected, err := neutralObservation(sc)
		if err != nil {
			return OracleHierarchy{}, err
		}
		raw, err := canonical(expected)
		if err != nil {
			return OracleHierarchy{}, err
		}
		var expectedValue any
		if err := json.Unmarshal(raw, &expectedValue); err != nil {
			return OracleHierarchy{}, err
		}
		leaves := map[string]any{}
		collectLeaves(expectedValue, "", leaves)
		pointers := make([]string, 0, len(leaves))
		for p := range leaves {
			pointers = append(pointers, p)
		}
		sort.Strings(pointers)
		for _, pointer := range pointers {
			value, err := canonical(leaves[pointer])
			if err != nil {
				return OracleHierarchy{}, err
			}
			cell := OracleCell{ScenarioID: sc.ScenarioID, Pointer: pointer, Authority: "neutral", Rank: 3, ExpectedSHA256: digest(value), Evidence: []OracleEvidence{{Kind: "committed_neutral_expectation", ID: sc.ScenarioID + "#expected" + pointer, SHA256: digest(value)}}}
			if pointer == "/transitions" {
				if transitions, ok := terminalFailureTransition(sc); ok {
					selected, err := canonicalOracleValue(transitions)
					if err != nil {
						return OracleHierarchy{}, err
					}
					cell.Authority = "rfc6455.section-7-1-7"
					cell.Rank = 1
					cell.ExpectedSHA256 = digest(selected)
					cell.Evidence = []OracleEvidence{{Kind: "rfc_clause", ID: cell.Authority, SHA256: digest([]byte("RFC6455.section-7-1-7"))}}
				}
			}
			if pointer == "/frames" {
				frames, selectedFrames, err := selectedRejectedFrames(sc)
				if err != nil {
					return OracleHierarchy{}, err
				}
				if selectedFrames {
					selected, err := canonicalOracleValue(frames)
					if err != nil {
						return OracleHierarchy{}, err
					}
					cell.ExpectedSHA256 = digest(selected)
					cell.Evidence = []OracleEvidence{{Kind: "committed_neutral_expectation", ID: sc.ScenarioID + "#decoded-rejected-frames", SHA256: digest(selected)}}
				}
			}
			selectedRFC := ""
			if pointer == "/final_state" && sc.Expected.Outcome == "error" && sc.Expected.Error != nil && sc.Expected.Error.CloseCode != nil && len(sc.Core.Steps) != 0 && sc.Core.Steps[0].Kind == "bytes" {
				selectedRFC = "rfc6455.section-7-1-7"
			}
			if pointer == "/final_state" && sc.ScenarioID == "us005.pub.0005" && contains(sc.ExpectationBasis, "rfc6455.section-5-2") {
				selectedRFC = "rfc6455.section-5-2"
			}
			if pointer == "/final_state" && sc.Family == "close-code-invalid-wire" && contains(sc.ExpectationBasis, "rfc6455.section-7-4") {
				selectedRFC = "rfc6455.section-7-4"
			}
			if selectedRFC != "" {
				selected, err := canonical("closed")
				if err != nil {
					return OracleHierarchy{}, err
				}
				cell.Authority = selectedRFC
				cell.Rank = 1
				cell.ExpectedSHA256 = digest(selected)
				cell.Evidence = []OracleEvidence{{Kind: "rfc_clause", ID: selectedRFC, SHA256: digest([]byte("RFC6455." + strings.TrimPrefix(selectedRFC, "rfc6455.")))}}
			}
			if selected, authority, ok := explicitRFCOracleOverride(sc, pointer); ok {
				selectedRaw, err := canonical(selected)
				if err != nil {
					return OracleHierarchy{}, err
				}
				cell.Authority = authority
				cell.Rank = 1
				cell.ExpectedSHA256 = digest(selectedRaw)
				cell.Evidence = []OracleEvidence{{Kind: "rfc_clause", ID: authority, SHA256: digest([]byte("RFC6455." + strings.TrimPrefix(authority, "rfc6455.")))}}
			}
			h.Cells = append(h.Cells, cell)
		}
	}
	h.CellCount = len(h.Cells)
	return h, nil
}

func observationValue(observation commonObservation, pointer string) (any, error) {
	raw, err := canonical(observation)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if pointer == "" {
		return value, nil
	}
	current := value
	for _, encoded := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		part := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		switch typed := current.(type) {
		case map[string]any:
			var present bool
			current, present = typed[part]
			if !present {
				return absentObservationValue{Absent: true}, nil
			}
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(typed) {
				return absentObservationValue{Absent: true}, nil
			}
			current = typed[index]
		default:
			return absentObservationValue{Absent: true}, nil
		}
	}
	return current, nil
}

func adjudicateScenario(sc corpora.Scenario, hierarchy OracleHierarchy, java, rust commonObservation) (string, []AdjudicatedFinding, error) {
	if java.ScenarioID != sc.ScenarioID || rust.ScenarioID != sc.ScenarioID {
		return "", nil, errors.New("observation scenario binding mismatch")
	}
	findings := []AdjudicatedFinding{}
	blocking := []string{}
	cells := 0
	for _, cell := range hierarchy.Cells {
		if cell.ScenarioID != sc.ScenarioID {
			continue
		}
		cells++
		javaValue, err := observationValue(java, cell.Pointer)
		if err != nil {
			return "", nil, fmt.Errorf("java %w", err)
		}
		rustValue, err := observationValue(rust, cell.Pointer)
		if err != nil {
			return "", nil, fmt.Errorf("rust %w", err)
		}
		javaRaw, err := canonical(javaValue)
		if err != nil {
			return "", nil, err
		}
		rustRaw, err := canonical(rustValue)
		if err != nil {
			return "", nil, err
		}
		javaDigest, rustDigest := digest(javaRaw), digest(rustRaw)
		if javaDigest == rustDigest {
			if javaDigest != cell.ExpectedSHA256 {
				return "", nil, fmt.Errorf("authority_conflict scenario=%s pointer=%s", sc.ScenarioID, cell.Pointer)
			}
			continue
		}
		finding := AdjudicatedFinding{Pointer: cell.Pointer, Decision: cell, JavaSHA256: javaDigest, RustSHA256: rustDigest}
		switch {
		case rustDigest == cell.ExpectedSHA256 && javaDigest != cell.ExpectedSHA256:
			finding.Classification = "java_quirk"
			findings = append(findings, finding)
		case javaDigest == cell.ExpectedSHA256 && rustDigest != cell.ExpectedSHA256:
			finding.Classification = "rust_defect"
			findings = append(findings, finding)
			blocking = append(blocking, "rust_defect:"+cell.Pointer)
		default:
			finding.Classification = "underspecified"
			findings = append(findings, finding)
			blocking = append(blocking, "underspecified:"+cell.Pointer)
		}
	}
	if cells == 0 {
		return "", nil, fmt.Errorf("oracle hierarchy has no cells for %s", sc.ScenarioID)
	}
	if len(blocking) != 0 {
		return "", findings, fmt.Errorf("%s scenario=%s", strings.Join(blocking, ","), sc.ScenarioID)
	}
	if len(findings) != 0 {
		return "java_quirk", findings, nil
	}
	return "agreement", findings, nil
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func ValidateOracleHierarchy(scenarios []corpora.Scenario, h OracleHierarchy) error {
	want, err := BuildOracleHierarchy(scenarios)
	if err != nil {
		return err
	}
	if h.SchemaVersion != "1.0.0" || h.EvidenceKind != "oracle-hierarchy" || h.ScenarioCount != len(scenarios) || h.CellCount != len(h.Cells) || len(h.Cells) != len(want.Cells) {
		return errors.New("oracle hierarchy cardinality invalid")
	}
	for index, cell := range h.Cells {
		expected := want.Cells[index]
		left, leftErr := canonical(cell)
		right, rightErr := canonical(expected)
		if leftErr != nil || rightErr != nil || !bytes.Equal(left, right) {
			return fmt.Errorf("oracle cell %d invalid", index)
		}
	}
	return nil
}

func PreparePublicOracleHierarchy(root, path string) error {
	scenarios, _, err := loadPublicCorpus(root, filepath.Join(root, "corpora/public/scenarios.jsonl"))
	if err != nil {
		return err
	}
	h, err := BuildOracleHierarchy(scenarios)
	if err != nil {
		return err
	}
	return writeJSONAtomic(path, h)
}

func migrateLedger(raw []byte) (Ledger, error) {
	var dispatch map[string]json.RawMessage
	if err := decodeStrict(raw, &dispatch); err != nil {
		return Ledger{}, err
	}
	var version string
	versionRaw, ok := dispatch["schema_version"]
	if !ok || json.Unmarshal(versionRaw, &version) != nil || version == "" {
		return Ledger{}, errors.New("ledger schema version absent")
	}
	if version == ledgerSchemaVersion {
		var ledger Ledger
		if err := decodeStrict(raw, &ledger); err != nil {
			return Ledger{}, err
		}
		return ledger, validateLedger(ledger)
	}
	if version != "1.0.0" {
		return Ledger{}, errors.New("unsupported ledger schema")
	}
	var old LegacyLedger
	if err := decodeStrict(raw, &old); err != nil {
		return Ledger{}, err
	}
	if err := validateLegacyLedger(old); err != nil {
		return Ledger{}, err
	}
	unresolved := 0
	for _, record := range old.Records {
		if record.Delta.Disposition == "unresolved" {
			unresolved++
		}
	}
	status := "PASS_NO_CURRENT_DELTAS"
	if len(old.Records) > 0 {
		status = "PASS_WITH_CLOSED_HISTORY"
	}
	if unresolved > 0 {
		status = "BLOCKED_UNRESOLVED_CURRENT_DELTAS"
	}
	ledger := Ledger{Schema: "../../schemas/behavior-delta-ledger-1.1.0.schema.json", SchemaVersion: ledgerSchemaVersion, EvidenceKind: "behavior-delta-ledger", AcceptedRootDigest: old.AcceptedRootDigest, Status: status, NormativeAuthority: "field-addressed-oracle-hierarchy", Head: old.Head, Records: []LedgerRecord{}, AppendImplementation: "hash-chained-cas", UnledgeredDisagreements: unresolved, Production: false, Publication: false}
	if len(old.Records) > 0 {
		ledger.MigrationSourceHead = old.Head
		ledger.MigratedV1Records = append([]LegacyLedgerRecord(nil), old.Records...)
	}
	return ledger, validateLedger(ledger)
}

func legacyRecordDigest(record LegacyLedgerRecord) (string, error) {
	copy := record
	copy.RecordDigest = ""
	raw, err := canonical(copy)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}

func validateLegacyLedger(ledger LegacyLedger) error {
	if ledger.Schema != "../../schemas/behavior-delta-ledger-1.0.0.schema.json" || ledger.SchemaVersion != "1.0.0" || ledger.EvidenceKind != "behavior-delta-ledger" || ledger.NormativeAuthority != "rfc6455" || ledger.AppendImplementation != "hash-chained-cas" || !validLedgerDigest(ledger.AcceptedRootDigest) || !validLedgerDigest(ledger.Head) || ledger.Records == nil || ledger.UnledgeredDisagreements != 0 || ledger.Production || ledger.Publication || (ledger.Status != "READY" && ledger.Status != "BLOCKED_PENDING_BASELINE") {
		return errors.New("legacy ledger envelope invalid")
	}
	previous := "sha256:" + strings.Repeat("0", 64)
	seen := map[string]bool{}
	for index, record := range ledger.Records {
		delta := record.Delta
		if record.SchemaVersion != "1.0.0" || record.Sequence != index+1 || record.PreviousDigest != previous || !validLedgerDigest(record.RecordDigest) || delta.SchemaVersion != "1.0.0" || !strings.HasPrefix(delta.DeltaID, "delta-") || len(delta.DeltaID) != len("delta-")+64 || seen[delta.DeltaID] || !strings.HasPrefix(delta.SubjectRef, "semantic:") || len(delta.RFCRefs) == 0 || len(delta.AutobahnRefs) == 0 || !validLedgerDigest(delta.RFCExpectationDigest) || !validLedgerDigest(delta.RFCValueDigest) || !validLedgerDigest(delta.JavaObservationDigest) || !validLedgerDigest(delta.JavaValueDigest) || !validLedgerDigest(delta.AutobahnResultDigest) || !validLedgerDigest(delta.AutobahnValueDigest) || !validLedgerDigest(delta.DisagreementDigest) || delta.NormativeAuthority != "rfc6455" || (delta.Disposition != "unresolved" && delta.Disposition != "rfc-governs") || delta.Rationale == "" || len(delta.Rationale) > 4096 {
			return fmt.Errorf("legacy ledger record invalid at %d", index)
		}
		seen[delta.DeltaID] = true
		want, err := legacyRecordDigest(record)
		if err != nil || want != record.RecordDigest {
			return fmt.Errorf("legacy ledger digest invalid at %d", index)
		}
		previous = record.RecordDigest
	}
	if ledger.Head != previous {
		return errors.New("legacy ledger head does not match chain")
	}
	return nil
}

func recordDigest(record LedgerRecord) (string, error) {
	copy := record
	copy.RecordDigest = ""
	raw, err := canonical(copy)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}

func validLedgerDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func validLedgerAnchor(value string) bool {
	if len(value) < 40 || len(value) > 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded)*2 == len(value)
}

func validLedgerScenarioID(value string) bool {
	const prefix = "us005.pub."
	if len(value) != len(prefix)+4 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, digit := range value[len(prefix):] {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// VerifyBehaviorDeltaLedger strictly decodes and verifies the closed US-020
// v1.1 format, including every record digest and genesis-to-head link. It is a
// read-only facade so legacy evidence consumers can support the new format
// without duplicating its hash algorithm or gaining append authority.
func VerifyBehaviorDeltaLedger(raw []byte) (BehaviorLedgerSummary, error) {
	if len(raw) == 0 || int64(len(raw)) > maximumDocumentBytes {
		return BehaviorLedgerSummary{}, errors.New("behavior ledger input is absent or oversized")
	}
	var ledger Ledger
	if err := decodeStrict(raw, &ledger); err != nil {
		return BehaviorLedgerSummary{}, err
	}
	if err := validateLedger(ledger); err != nil {
		return BehaviorLedgerSummary{}, err
	}
	return BehaviorLedgerSummary{
		SchemaVersion:         ledger.SchemaVersion,
		AcceptedRootDigest:    ledger.AcceptedRootDigest,
		Status:                ledger.Status,
		Head:                  ledger.Head,
		RecordCount:           len(ledger.Records),
		CurrentDeltasResolved: ledger.UnledgeredDisagreements == 0 && (ledger.Status == "PASS_NO_CURRENT_DELTAS" || ledger.Status == "PASS_WITH_CLOSED_HISTORY"),
		Production:            ledger.Production,
		Publication:           ledger.Publication,
	}, nil
}

func validateLedger(ledger Ledger) error {
	if ledger.Schema != "../../schemas/behavior-delta-ledger-1.1.0.schema.json" || ledger.SchemaVersion != ledgerSchemaVersion || ledger.EvidenceKind != "behavior-delta-ledger" || ledger.NormativeAuthority != "field-addressed-oracle-hierarchy" || ledger.AppendImplementation != "hash-chained-cas" || !validLedgerDigest(ledger.AcceptedRootDigest) || !validLedgerDigest(ledger.Head) || ledger.Records == nil || len(ledger.Records) > 4096 || ledger.UnledgeredDisagreements < 0 || ledger.Production || ledger.Publication {
		return errors.New("ledger envelope invalid")
	}
	if ledger.UnledgeredDisagreements > 0 {
		if ledger.Status != "BLOCKED_UNRESOLVED_CURRENT_DELTAS" {
			return errors.New("ledger unresolved status mismatch")
		}
	} else if len(ledger.Records)+len(ledger.MigratedV1Records) == 0 && ledger.Status != "PASS_NO_CURRENT_DELTAS" || ledger.UnledgeredDisagreements == 0 && len(ledger.Records)+len(ledger.MigratedV1Records) != 0 && ledger.Status != "PASS_WITH_CLOSED_HISTORY" {
		return errors.New("ledger status does not match closed history")
	}
	previous := "sha256:" + strings.Repeat("0", 64)
	if len(ledger.MigratedV1Records) > 0 {
		legacy := LegacyLedger{Schema: "../../schemas/behavior-delta-ledger-1.0.0.schema.json", SchemaVersion: "1.0.0", EvidenceKind: "behavior-delta-ledger", AcceptedRootDigest: ledger.AcceptedRootDigest, Status: "READY", NormativeAuthority: "rfc6455", Head: ledger.MigrationSourceHead, Records: ledger.MigratedV1Records, AppendImplementation: "hash-chained-cas"}
		if err := validateLegacyLedger(legacy); err != nil {
			return fmt.Errorf("migrated legacy history: %w", err)
		}
		previous = ledger.MigrationSourceHead
	} else if ledger.MigrationSourceHead != "" {
		return errors.New("migration source head without legacy records")
	}
	seen := make(map[string]struct{}, len(ledger.Records))
	for index, record := range ledger.Records {
		if record.Sequence != len(ledger.MigratedV1Records)+index+1 || record.PreviousDigest != previous || !validLedgerDigest(record.RecordDigest) || !strings.HasPrefix(record.DeltaID, "delta.") || len(record.DeltaID) > 256 || !validLedgerScenarioID(record.ScenarioID) || !strings.HasPrefix(record.Pointer, "/") || len(record.Pointer) > 512 || !validLedgerDigest(record.JavaObservation) || !validLedgerDigest(record.RustObservation) || !validLedgerDigest(record.ReproducerSHA256) || !validLedgerAnchor(record.FindingRunAnchor) {
			return fmt.Errorf("ledger chain broken at %d", index)
		}
		if _, duplicate := seen[record.DeltaID]; duplicate {
			return fmt.Errorf("duplicate ledger delta at %d", index)
		}
		seen[record.DeltaID] = struct{}{}
		if record.Decision.ScenarioID != record.ScenarioID || record.Decision.Pointer != record.Pointer || record.Decision.Authority == "" || len(record.Decision.Authority) > 128 || record.Decision.Rank < 1 || record.Decision.Rank > 5 || !validLedgerDigest(record.Decision.ExpectedSHA256) || len(record.Decision.Evidence) == 0 || len(record.Decision.Evidence) > 8 {
			return fmt.Errorf("ledger decision invalid at %d", index)
		}
		for _, evidence := range record.Decision.Evidence {
			if evidence.Kind == "" || len(evidence.Kind) > 64 || evidence.ID == "" || len(evidence.ID) > 768 || !validLedgerDigest(evidence.SHA256) {
				return fmt.Errorf("ledger decision evidence invalid at %d", index)
			}
		}
		switch record.Classification {
		case "java_quirk":
			if record.Resolution != "retained_java_quirk" || record.ClosingRunAnchor != "" || record.ClosingJavaObservation != "" || record.ClosingRustObservation != "" {
				return fmt.Errorf("retained Java quirk lifecycle invalid at %d", index)
			}
		case "rust_defect":
			if record.Resolution != "remediated" || !validLedgerAnchor(record.ClosingRunAnchor) || !validLedgerDigest(record.ClosingJavaObservation) || !validLedgerDigest(record.ClosingRustObservation) {
				return fmt.Errorf("remediated Rust defect lifecycle invalid at %d", index)
			}
		default:
			return fmt.Errorf("ledger classification invalid at %d", index)
		}
		want, err := recordDigest(record)
		if err != nil {
			return err
		}
		if record.RecordDigest != want {
			return fmt.Errorf("ledger record digest invalid at %d", index)
		}
		previous = record.RecordDigest
	}
	if ledger.Head != previous {
		return errors.New("ledger head does not match chain")
	}
	return nil
}

func appendJavaQuirk(ledger *Ledger, sc corpora.Scenario, finding AdjudicatedFinding, javaObservation, rustObservation, findingAnchor, reproducerSHA string) error {
	if finding.Classification != "java_quirk" || finding.Pointer == "" || finding.Decision.ScenarioID != sc.ScenarioID || finding.Decision.Pointer != finding.Pointer {
		return errors.New("invalid Java quirk finding")
	}
	if !validLedgerDigest(reproducerSHA) {
		return errors.New("Java quirk minimized reproducer identity invalid")
	}
	deltaID := deltaIDFor(sc.ScenarioID, finding.Pointer)
	record := LedgerRecord{
		DeltaID:          deltaID,
		ScenarioID:       sc.ScenarioID,
		Pointer:          finding.Pointer,
		Classification:   "java_quirk",
		JavaObservation:  javaObservation,
		RustObservation:  rustObservation,
		ReproducerSHA256: reproducerSHA,
		Decision:         finding.Decision,
		Resolution:       "retained_java_quirk",
		FindingRunAnchor: findingAnchor,
	}
	return appendLedgerRecord(ledger, ledger.Head, record)
}

func deltaIDFor(scenarioID, pointer string) string {
	suffix := strings.NewReplacer("/", "-", "~", "-").Replace(strings.TrimPrefix(pointer, "/"))
	return "delta." + scenarioID + "." + suffix
}

func appendLedgerRecord(ledger *Ledger, expectedHead string, record LedgerRecord) error {
	if ledger == nil {
		return errors.New("nil ledger")
	}
	if err := validateLedger(*ledger); err != nil {
		return err
	}
	if ledger.Head != expectedHead {
		return errors.New("stale ledger compare-and-swap head")
	}
	for _, existing := range ledger.Records {
		if existing.DeltaID == record.DeltaID {
			if samePersistentFinding(existing, record) {
				return nil
			}
			return errors.New("delta id conflict")
		}
	}
	record.Sequence = len(ledger.MigratedV1Records) + len(ledger.Records) + 1
	record.PreviousDigest = ledger.Head
	record.RecordDigest = ""
	computed, err := recordDigest(record)
	if err != nil {
		return err
	}
	record.RecordDigest = computed
	ledger.Records = append(ledger.Records, record)
	ledger.Head = computed
	ledger.Status = "PASS_WITH_CLOSED_HISTORY"
	return validateLedger(*ledger)
}

func samePersistentFinding(existing, candidate LedgerRecord) bool {
	existing.Sequence, candidate.Sequence = 0, 0
	existing.PreviousDigest, candidate.PreviousDigest = "", ""
	existing.RecordDigest, candidate.RecordDigest = "", ""
	// A rerun is a confirmation of the existing record, not a rewrite of the
	// first/closing execution anchors. The semantic identities must still match.
	existing.FindingRunAnchor, candidate.FindingRunAnchor = "", ""
	existing.ClosingRunAnchor, candidate.ClosingRunAnchor = "", ""
	left, leftErr := canonical(existing)
	right, rightErr := canonical(candidate)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

type retainedDefectEvidence struct {
	Pointer         string
	JavaObservation string
	RustObservation string
	FindingAnchor   string
}

var retainedDefects = map[string][]retainedDefectEvidence{
	"us005.pub.0005": {{Pointer: "/counts/consumed_bytes", JavaObservation: "sha256:13473d74240499994fec9601b20be094a7e55e25d97d20ae9cb4a9875d2b710b", RustObservation: "sha256:5e8b0f1d14d21e402d66df17de0cb3175c63b1b3ebd599b9e5072b346e68aeb1", FindingAnchor: "c44623e38b59563401c438c3321bf7f3e77e7e54"}},
	"us005.pub.0015": {
		{Pointer: "/counts/consumed_bytes", JavaObservation: "sha256:ce72d49f34a5193ed3b956da3722a6f6748fa063ec45126b9614f11c4cb2fa59", RustObservation: "sha256:96123fc665f1bef97f86a4dc3560836422ac2ddf4c04e2a3191dc983301c2e59", FindingAnchor: "9cc9d37e8b85dbf15c8018bce91c37071d63cf7c"},
		{Pointer: "/counts/input_bytes", JavaObservation: "sha256:ce72d49f34a5193ed3b956da3722a6f6748fa063ec45126b9614f11c4cb2fa59", RustObservation: "sha256:96123fc665f1bef97f86a4dc3560836422ac2ddf4c04e2a3191dc983301c2e59", FindingAnchor: "9cc9d37e8b85dbf15c8018bce91c37071d63cf7c"},
	},
	"us005.pub.0017": {
		{Pointer: "/error", JavaObservation: "sha256:031963dd643de70cc45b5f660ce92d68fa44491f5a1ee4bd408e7060914b06a7", RustObservation: "sha256:351b98501192ffa12a1a7d2527960b11d7ffd14e2b3a8e3e22c9c25b6dfd79aa", FindingAnchor: "abc8ddfd24c2fad2eae34e3757d9e047e443cfd6"},
		{Pointer: "/outcome", JavaObservation: "sha256:031963dd643de70cc45b5f660ce92d68fa44491f5a1ee4bd408e7060914b06a7", RustObservation: "sha256:351b98501192ffa12a1a7d2527960b11d7ffd14e2b3a8e3e22c9c25b6dfd79aa", FindingAnchor: "abc8ddfd24c2fad2eae34e3757d9e047e443cfd6"},
	},
}

func appendObservedRemediations(ledger *Ledger, hierarchy OracleHierarchy, sc corpora.Scenario, closingJavaObservation, closingRustObservation commonObservation, closingJavaDigest, closingRustDigest, closingAnchor string) error {
	defects := retainedDefects[sc.ScenarioID]
	if len(defects) == 0 {
		return nil
	}
	reproducer, err := sc.CanonicalLine()
	if err != nil {
		return err
	}
	for _, defect := range defects {
		var decision *OracleCell
		for index := range hierarchy.Cells {
			cell := &hierarchy.Cells[index]
			if cell.ScenarioID == sc.ScenarioID && cell.Pointer == defect.Pointer {
				decision = cell
				break
			}
		}
		if decision == nil {
			return fmt.Errorf("observed remediation oracle cell absent: %s", defect.Pointer)
		}
		javaValue, err := observationValue(closingJavaObservation, decision.Pointer)
		if err != nil {
			return err
		}
		rustValue, err := observationValue(closingRustObservation, decision.Pointer)
		if err != nil {
			return err
		}
		javaRaw, err := canonical(javaValue)
		if err != nil {
			return err
		}
		rustRaw, err := canonical(rustValue)
		if err != nil {
			return err
		}
		if digest(javaRaw) != decision.ExpectedSHA256 || digest(rustRaw) != decision.ExpectedSHA256 {
			return fmt.Errorf("observed remediation closing field is not aligned to authority: %s", defect.Pointer)
		}
		record := LedgerRecord{
			DeltaID: deltaIDFor(sc.ScenarioID, defect.Pointer), ScenarioID: sc.ScenarioID,
			Pointer: defect.Pointer, Classification: "rust_defect",
			JavaObservation: defect.JavaObservation, RustObservation: defect.RustObservation,
			ReproducerSHA256: digest(reproducer), Decision: *decision, Resolution: "remediated",
			FindingRunAnchor: defect.FindingAnchor, ClosingRunAnchor: closingAnchor,
			ClosingJavaObservation: closingJavaDigest, ClosingRustObservation: closingRustDigest,
		}
		if err := appendLedgerRecord(ledger, ledger.Head, record); err != nil {
			return err
		}
	}
	return nil
}

func historicalClosedReproducers(cfg Config, hierarchy OracleHierarchy, sc corpora.Scenario, closingJavaDigest, closingRustDigest, closingAnchor string, inputs []ArtifactIdentity) ([]PublicReproducer, error) {
	defects := retainedDefects[sc.ScenarioID]
	if len(defects) == 0 {
		return []PublicReproducer{}, nil
	}
	if len(sc.Core.Steps) > cfg.MinimizationBudget.MaxCandidates {
		return nil, errors.New("historical irreducibility witness exceeds candidate budget")
	}
	line, err := sc.CanonicalLine()
	if err != nil {
		return nil, err
	}
	scenarioSHA := digest(line)
	result := make([]PublicReproducer, 0, len(defects))
	for _, defect := range defects {
		signature := mismatchSignature{Pointer: defect.Pointer, Classification: "rust_defect"}
		signatureRaw, _ := canonical(signature)
		reproducerID := "reproducer." + sc.ScenarioID + "." + strings.TrimPrefix(digest(signatureRaw), "sha256:")[:16]
		attempts := []MinimizationAttempt{{Scenario: sc, ScenarioSHA256: scenarioSHA, Signature: signature, Reproduced: true, Processes: []ProcessReceipt{}, EvidenceStatus: "RETAINED_HISTORICAL_FINDING_OBSERVATIONS", Audits: []NormalizationTrace{}}}
		for index := range sc.Core.Steps {
			candidate := sc
			candidate.Core.Steps = append([]corpora.Step(nil), sc.Core.Steps[:index]...)
			candidate.Core.Steps = append(candidate.Core.Steps, sc.Core.Steps[index+1:]...)
			candidateLine, err := candidate.CanonicalLine()
			if err != nil {
				return nil, err
			}
			attempts = append(attempts, MinimizationAttempt{Scenario: candidate, ScenarioSHA256: digest(candidateLine), Signature: mismatchSignature{}, Reproduced: false, Processes: []ProcessReceipt{}, EvidenceStatus: "NO_RETAINED_HISTORICAL_FINDING_OBSERVATION", Audits: []NormalizationTrace{}})
		}
		foundDecision := false
		for _, cell := range hierarchy.Cells {
			if cell.ScenarioID == sc.ScenarioID && cell.Pointer == defect.Pointer {
				foundDecision = true
				break
			}
		}
		if !foundDecision {
			return nil, fmt.Errorf("historical reproducer decision absent %s", defect.Pointer)
		}
		reproducer := PublicReproducer{ReproducerID: reproducerID, LedgerDeltaID: deltaIDFor(sc.ScenarioID, defect.Pointer), ScenarioID: sc.ScenarioID, Mode: "HISTORICAL_CLOSED_IDENTITY_WITNESS", ProofScope: "RETAINED_HISTORICAL_OBSERVATION_IDENTITY", CurrentlyReproduces: false, Signature: signature, Scenario: sc, OriginalScenarioSHA256: scenarioSHA, ScenarioSHA256: scenarioSHA, Command: canonicalReproducerCommand(cfg.RepositoryRoot, cfg.EvidencePath, reproducerID), RepositoryAnchor: closingAnchor, RuntimeInputs: append([]ArtifactIdentity(nil), inputs...), CandidateAttempts: len(sc.Core.Steps), Irreducible: true, Processes: []ProcessReceipt{}, Attempts: attempts, FindingJavaObservation: defect.JavaObservation, FindingRustObservation: defect.RustObservation, FindingRunAnchor: defect.FindingAnchor, ClosingRunAnchor: closingAnchor, ClosingJavaObservation: closingJavaDigest, ClosingRustObservation: closingRustDigest}
		if closingJavaDigest == "" || closingRustDigest == "" {
			return nil, errors.New("historical closing observations absent")
		}
		result = append(result, reproducer)
	}
	return result, nil
}

func minimizeStrings(original []string, budget Budget, predicate func([]string) (string, bool)) ([]string, int, error) {
	if budget.MaxCandidates <= 0 || budget.MaxCandidates > 512 || budget.MaxDuration <= 0 || budget.MaxDuration > 30*time.Minute {
		return nil, 0, errors.New("invalid minimization budget")
	}
	signature, ok := predicate(original)
	if !ok || signature == "" {
		return nil, 0, errors.New("original mismatch does not reproduce")
	}
	deadline := time.Now().Add(budget.MaxDuration)
	best := append([]string(nil), original...)
	attempts := 0
	for index := 0; index < len(best) && attempts < budget.MaxCandidates && time.Now().Before(deadline); {
		candidate := append([]string(nil), best[:index]...)
		candidate = append(candidate, best[index+1:]...)
		attempts++
		got, reproduced := predicate(candidate)
		if reproduced && got == signature {
			best = candidate
			continue
		}
		index++
	}
	if attempts >= budget.MaxCandidates && len(best) > 1 {
		return best, attempts, errors.New("MINIMIZATION_INCOMPLETE")
	}
	return best, attempts, nil
}

func minimizeScenarioFresh(original corpora.Scenario, budget Budget, predicate func(corpora.Scenario) (mismatchSignature, []ProcessReceipt, error)) (PublicReproducer, error) {
	if budget.MaxCandidates <= 0 || budget.MaxCandidates > 512 || budget.MaxDuration <= 0 || budget.MaxDuration > 30*time.Minute {
		return PublicReproducer{}, errors.New("invalid minimization budget")
	}
	if len(original.Core.Steps) == 0 {
		return PublicReproducer{}, errors.New("mismatch scenario has no minimizable steps")
	}
	deadline := time.Now().Add(budget.MaxDuration)
	originalLine, err := original.CanonicalLine()
	if err != nil {
		return PublicReproducer{}, err
	}
	seenPIDs := map[int]bool{}
	processes := []ProcessReceipt{}
	history := []MinimizationAttempt{}
	run := func(candidate corpora.Scenario) (mismatchSignature, bool, error) {
		signature, receipts, err := predicate(candidate)
		if err != nil {
			return mismatchSignature{}, false, err
		}
		if len(receipts) < 2 {
			return mismatchSignature{}, false, errors.New("minimization candidate did not use fresh runtime processes")
		}
		for _, receipt := range receipts {
			if receipt.PID <= 0 || seenPIDs[receipt.PID] {
				return mismatchSignature{}, false, errors.New("minimization process identity reused")
			}
			seenPIDs[receipt.PID] = true
		}
		processes = append(processes, receipts...)
		reproduced := signature.Pointer != "" && signature.Classification != ""
		line, err := candidate.CanonicalLine()
		if err != nil {
			return mismatchSignature{}, false, err
		}
		history = append(history, MinimizationAttempt{Scenario: candidate, ScenarioSHA256: digest(line), Signature: signature, Reproduced: reproduced, Processes: append([]ProcessReceipt(nil), receipts...), EvidenceStatus: "FRESH_RUNTIME_OBSERVATION"})
		return signature, reproduced, nil
	}
	want, reproduced, err := run(original)
	if err != nil || !reproduced {
		if err == nil {
			err = errors.New("original mismatch does not reproduce")
		}
		return PublicReproducer{}, err
	}
	best := original
	attempts := 0
	for index := 0; index < len(best.Core.Steps); {
		if attempts >= budget.MaxCandidates || !time.Now().Before(deadline) {
			return PublicReproducer{}, errors.New("MINIMIZATION_INCOMPLETE")
		}
		candidate := best
		candidate.Core.Steps = append([]corpora.Step(nil), best.Core.Steps[:index]...)
		candidate.Core.Steps = append(candidate.Core.Steps, best.Core.Steps[index+1:]...)
		attempts++
		got, ok, err := run(candidate)
		if err != nil {
			return PublicReproducer{}, err
		}
		if ok && got == want {
			best = candidate
			continue
		}
		index++
	}
	line, err := best.CanonicalLine()
	if err != nil {
		return PublicReproducer{}, err
	}
	sha := digest(line)
	signatureRaw, _ := canonical(want)
	return PublicReproducer{ReproducerID: "reproducer." + best.ScenarioID + "." + strings.TrimPrefix(digest(signatureRaw), "sha256:")[:16], ScenarioID: best.ScenarioID, Mode: "FRESH_BOUNDED_MINIMIZATION", ProofScope: "FRESH_RUNTIME_DIFFERENCE", CurrentlyReproduces: true, Signature: want, Scenario: best, OriginalScenarioSHA256: digest(originalLine), ScenarioSHA256: sha, CandidateAttempts: attempts, Irreducible: true, Processes: processes, Attempts: history, RuntimeInputs: []ArtifactIdentity{}, Command: []string{}}, nil
}

func classifyAgainstNeutral(neutral, java, rust string) string {
	if java == rust {
		return "agreement"
	}
	if rust == neutral && java != neutral {
		return "java_quirk"
	}
	if java == neutral && rust != neutral {
		return "rust_defect"
	}
	return "underspecified"
}

func runSeededControls() (ControlsReceipt, error) {
	baseline := SemanticObservation{Events: []string{"input", "text"}, ErrorClass: "none", CloseOrigin: "none", ConsumedBytes: 7}
	baseRaw, _ := canonical(baseline)
	baseDigest := digest(baseRaw)
	results := []ControlResult{}
	add := func(id, expected, detected string, seed any) {
		raw, _ := canonical(seed)
		results = append(results, ControlResult{ControlID: id, SeedSHA256: digest(raw), ExpectedCode: expected, DetectedCode: detected, BaselinePassed: DetectSemanticDifference(baseline, baseline).Code == "", LedgerUnchanged: baseDigest == digest(baseRaw)})
	}
	javaClass := classifyAgainstNeutral("neutral", "mutated-java", "neutral")
	add("java-quirk", "java_quirk", javaClass, "mutated-java")
	rustClass := classifyAgainstNeutral("neutral", "neutral", "mutated-rust")
	add("rust-semantic-defect", "rust_defect", rustClass, "mutated-rust")
	for _, control := range []struct {
		id, code string
		mutate   func(*SemanticObservation)
	}{
		{"event-order", "EVENT_ORDER_MISMATCH", func(v *SemanticObservation) { v.Events[0], v.Events[1] = v.Events[1], v.Events[0] }},
		{"error-class", "ERROR_CLASS_MISMATCH", func(v *SemanticObservation) { v.ErrorClass = "protocol" }},
		{"close-origin", "CLOSE_ORIGIN_MISMATCH", func(v *SemanticObservation) { v.CloseOrigin = "remote" }},
		{"consumed-byte", "CONSUMED_BYTES_MISMATCH", func(v *SemanticObservation) { v.ConsumedBytes++ }},
	} {
		candidate := baseline.Clone()
		control.mutate(&candidate)
		difference := DetectSemanticDifference(baseline, candidate)
		add(control.id, control.code, difference.Code, candidate)
	}
	// The planted collision is executed through the same replay audit as the
	// real primary/replay path; it is not a predeclared detector result.
	shared := digest([]byte("normalized"))
	collisionCode, collisionErr := auditReplayNormalization(NormalizationTrace{Runtime: "java", RawSHA256: digest([]byte("raw-a")), NormalizedSHA256: shared}, NormalizationTrace{Runtime: "java", RawSHA256: digest([]byte("raw-b")), NormalizedSHA256: shared})
	if collisionErr == nil {
		return ControlsReceipt{}, errors.New("planted normalization collision was accepted")
	}
	add("normalization-collision", "NORMALIZATION_COLLISION", collisionCode, map[string]string{"raw_a": "a", "raw_b": "b", "normalized": "same"})
	killed := 0
	for _, result := range results {
		if result.ExpectedCode == result.DetectedCode && result.BaselinePassed && result.LedgerUnchanged {
			killed++
		}
	}
	if len(results) != 7 || killed != 7 {
		return ControlsReceipt{}, errors.New("mandatory control failed")
	}
	return ControlsReceipt{Total: len(results), Killed: killed, Results: results}, nil
}

func requireStablePair(ctx context.Context, request childRequest, normalize func([]byte) (string, error)) error {
	first, err := executeChild(ctx, request)
	if err != nil {
		return err
	}
	second, err := executeChild(ctx, request)
	if err != nil {
		return err
	}
	if first.PID <= 0 || second.PID <= 0 || first.PID == second.PID {
		return errors.New("fresh process identity absent")
	}
	left, err := normalize(first.Stdout)
	if err != nil {
		return err
	}
	right, err := normalize(second.Stdout)
	if err != nil {
		return err
	}
	if left != right {
		return errors.New("FLAKE: primary and replay differ")
	}
	return nil
}

type reviewedCoverage struct {
	Fresh         bool
	ScenarioIDs   []string
	FieldPointers []string
	Predecessors  []string
	Excluded      string
}

var commonCoverageFields = []string{"/final_state", "/counts", "/events", "/frames", "/transitions", "/close", "/error"}

func freshCoverage(scenarioID string) reviewedCoverage {
	return reviewedCoverage{Fresh: true, ScenarioIDs: []string{scenarioID}, FieldPointers: append([]string(nil), commonCoverageFields...)}
}

func predecessorCoverage(paths ...string) reviewedCoverage {
	return reviewedCoverage{Predecessors: append([]string(nil), paths...)}
}

// reviewedCoverageMap is deliberately exhaustive and literal. Its keys are
// the complete 47-row migration inventory plus 14-item compatibility surface;
// no identifier, feature, or substring inference is permitted here.
var reviewedCoverageMap = map[string]reviewedCoverage{
	"migration.org-java-websocket-websocket":                                   freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-websocketadapter":                            freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-websocketimpl":                               freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-websocketlistener":                           freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-drafts-draft":                                freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-drafts-draft-6455":                           freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-drafts-draft-6455-translatedpayloadmetadata": freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-enums-closehandshaketype":                    freshCoverage("us005.pub.0000"),
	"migration.org-java-websocket-enums-handshakestate":                        predecessorCoverage("evidence/us010-client-handshake.json", "evidence/us011-server-handshake.json"),
	"migration.org-java-websocket-enums-opcode":                                freshCoverage("us005.pub.0024"),
	"migration.org-java-websocket-enums-readystate":                            freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-enums-role":                                  freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-exceptions-incompleteexception":              freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-exceptions-incompletehandshakeexception":     predecessorCoverage("evidence/us010-client-handshake.json"),
	"migration.org-java-websocket-exceptions-invaliddataexception":             freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-exceptions-invalidencodingexception":         freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-exceptions-invalidframeexception":            freshCoverage("us005.pub.0024"),
	"migration.org-java-websocket-exceptions-invalidhandshakeexception":        predecessorCoverage("evidence/us010-client-handshake.json"),
	"migration.org-java-websocket-exceptions-limitexceededexception":           freshCoverage("us005.pub.0024"),
	"migration.org-java-websocket-exceptions-notsendableexception":             freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-exceptions-websocketnotconnectedexception":   freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-exceptions-wrappedioexception":               predecessorCoverage("evidence/us018-blocking-adapters.json"),
	"migration.org-java-websocket-framing-binaryframe":                         freshCoverage("us005.pub.0001"),
	"migration.org-java-websocket-framing-closeframe":                          freshCoverage("us005.pub.0000"),
	"migration.org-java-websocket-framing-continuousframe":                     freshCoverage("us005.pub.0024"),
	"migration.org-java-websocket-framing-controlframe":                        freshCoverage("us005.pub.0002"),
	"migration.org-java-websocket-framing-dataframe":                           freshCoverage("us005.pub.0024"),
	"migration.org-java-websocket-framing-framedata":                           freshCoverage("us005.pub.0024"),
	"migration.org-java-websocket-framing-framedataimpl1":                      freshCoverage("us005.pub.0024"),
	"migration.org-java-websocket-framing-pingframe":                           freshCoverage("us005.pub.0002"),
	"migration.org-java-websocket-framing-pongframe":                           freshCoverage("us005.pub.0002"),
	"migration.org-java-websocket-framing-textframe":                           freshCoverage("us005.pub.0001"),
	"migration.org-java-websocket-handshake-clienthandshake":                   predecessorCoverage("evidence/us010-client-handshake.json"),
	"migration.org-java-websocket-handshake-clienthandshakebuilder":            predecessorCoverage("evidence/us010-client-handshake.json"),
	"migration.org-java-websocket-handshake-handshakebuilder":                  predecessorCoverage("evidence/us010-client-handshake.json"),
	"migration.org-java-websocket-handshake-handshakeimpl1client":              predecessorCoverage("evidence/us010-client-handshake.json"),
	"migration.org-java-websocket-handshake-handshakeimpl1server":              predecessorCoverage("evidence/us011-server-handshake.json"),
	"migration.org-java-websocket-handshake-handshakedata":                     predecessorCoverage("evidence/us010-client-handshake.json"),
	"migration.org-java-websocket-handshake-handshakedataimpl1":                predecessorCoverage("evidence/us010-client-handshake.json"),
	"migration.org-java-websocket-handshake-serverhandshake":                   predecessorCoverage("evidence/us011-server-handshake.json"),
	"migration.org-java-websocket-handshake-serverhandshakebuilder":            predecessorCoverage("evidence/us011-server-handshake.json"),
	"migration.org-java-websocket-interfaces-isslchannel":                      {Excluded: "IN_SCOPE_SEMANTIC_ITEM_CAPABILITY_EXCLUDED"},
	"migration.org-java-websocket-util-base64":                                 predecessorCoverage("evidence/us010-client-handshake.json"),
	"migration.org-java-websocket-util-base64-outputstream":                    predecessorCoverage("evidence/us010-client-handshake.json"),
	"migration.org-java-websocket-util-bytebufferutils":                        freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-util-charsetfunctions":                       freshCoverage("us005.pub.0003"),
	"migration.org-java-websocket-util-namedthreadfactory":                     {Excluded: "IN_SCOPE_SEMANTIC_ITEM_CAPABILITY_EXCLUDED"},
	"surface.handshake.client-request":                                         predecessorCoverage("evidence/us010-client-handshake.json"),
	"surface.handshake.server-response":                                        predecessorCoverage("evidence/us011-server-handshake.json"),
	"surface.framing.frame-octets":                                             freshCoverage("us005.pub.0024"),
	"surface.framing.masking":                                                  freshCoverage("us005.pub.0024"),
	"surface.messages.text-utf8":                                               freshCoverage("us005.pub.0001"),
	"surface.messages.binary":                                                  freshCoverage("us005.pub.0001"),
	"surface.fragmentation.continuation":                                       freshCoverage("us005.pub.0001"),
	"surface.control.ping-pong":                                                freshCoverage("us005.pub.0002"),
	"surface.close.status-code":                                                freshCoverage("us005.pub.0000"),
	"surface.close.terminal-state":                                             freshCoverage("us005.pub.0000"),
	"surface.concurrency.command-order":                                        predecessorCoverage("evidence/us017-driver.json"),
	"surface.errors.protocol-fault":                                            freshCoverage("us005.pub.0024"),
	"surface.limits.allocation":                                                freshCoverage("us005.pub.0024"),
	"surface.adapter.byte-stream":                                              predecessorCoverage("evidence/us018-blocking-adapters.json"),
}

func applyReviewedCoverage(root string, base CoverageRow, mapping reviewedCoverage) (CoverageRow, error) {
	base.FreshUS020 = mapping.Fresh
	base.ScenarioIDs = append([]string{}, mapping.ScenarioIDs...)
	base.FieldPointers = append([]string{}, mapping.FieldPointers...)
	base.PredecessorPaths = append([]string{}, mapping.Predecessors...)
	base.PredecessorIdentities = []ArtifactIdentity{}
	base.ExcludedReason = mapping.Excluded
	for _, relative := range base.PredecessorPaths {
		identity, err := artifact(filepath.Join(root, relative))
		if err != nil {
			return CoverageRow{}, fmt.Errorf("predecessor %s: %w", relative, err)
		}
		identity.Kind = "predecessor-receipt"
		base.PredecessorIdentities = append(base.PredecessorIdentities, identity)
	}
	return base, nil
}

func buildCoverage(root string, scenarios []corpora.Scenario) (CoverageReceipt, error) {
	if len(reviewedCoverageMap) != 61 {
		return CoverageReceipt{}, errors.New("closed reviewed coverage map cardinality drift")
	}
	scenarioIDs := make(map[string]bool, len(scenarios))
	for _, scenario := range scenarios {
		scenarioIDs[scenario.ScenarioID] = true
	}
	migrationRaw, err := readRegularBounded(filepath.Join(root, "evidence/intake/semantic-id-migration-map.json"), maximumDocumentBytes)
	if err != nil {
		return CoverageReceipt{}, err
	}
	compatRaw, err := readRegularBounded(filepath.Join(root, "evidence/intake/compatibility-surface.json"), maximumDocumentBytes)
	if err != nil {
		return CoverageReceipt{}, err
	}
	var migration struct {
		Rows []json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(migrationRaw, &migration); err != nil {
		return CoverageReceipt{}, err
	}
	if len(migration.Rows) != 47 {
		return CoverageReceipt{}, fmt.Errorf("migration rows=%d", len(migration.Rows))
	}
	var compat struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(compatRaw, &compat); err != nil {
		return CoverageReceipt{}, err
	}
	if len(compat.Items) != 14 {
		return CoverageReceipt{}, fmt.Errorf("compatibility items=%d", len(compat.Items))
	}
	if _, err := provenance.LoadAndValidateCurrentHeadQualification(root); err != nil {
		return CoverageReceipt{}, fmt.Errorf("current-head qualification: %w", err)
	}
	qualification, err := artifact(filepath.Join(root, provenance.CurrentHeadQualificationPath))
	if err != nil {
		return CoverageReceipt{}, err
	}
	qualification.Kind = "current-head-qualification"
	receipt := CoverageReceipt{CurrentHeadQualification: qualification, Summary: CoverageSummary{MigrationRows: 47, CompatibilityItems: 14}}
	for index, raw := range migration.Rows {
		var row struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return CoverageReceipt{}, err
		}
		mapping, ok := reviewedCoverageMap[row.ID]
		if !ok {
			return CoverageReceipt{}, fmt.Errorf("unreviewed migration row %q", row.ID)
		}
		coverage, err := applyReviewedCoverage(root, CoverageRow{ID: row.ID, SourcePointer: fmt.Sprintf("/rows/%d", index), SourceSHA256: digest(raw), ScenarioIDs: []string{}, FieldPointers: []string{}, PredecessorPaths: []string{}, PredecessorIdentities: []ArtifactIdentity{}}, mapping)
		if err != nil {
			return CoverageReceipt{}, err
		}
		if coverage.ExcludedReason != "" {
			receipt.Summary.CapabilityExcludedRows++
		} else if coverage.FreshUS020 {
			receipt.Summary.FreshRows++
		} else if len(coverage.PredecessorPaths) > 0 {
			receipt.Summary.PredecessorRows++
		} else {
			receipt.Summary.UnresolvedRows++
		}
		for _, scenarioID := range coverage.ScenarioIDs {
			if !scenarioIDs[scenarioID] {
				return CoverageReceipt{}, fmt.Errorf("reviewed scenario absent: %s", scenarioID)
			}
		}
		receipt.Migration = append(receipt.Migration, coverage)
	}
	for index, raw := range compat.Items {
		var item struct {
			SurfaceID string `json:"surface_id"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			return CoverageReceipt{}, err
		}
		mapping, ok := reviewedCoverageMap[item.SurfaceID]
		if !ok {
			return CoverageReceipt{}, fmt.Errorf("unreviewed compatibility item %q", item.SurfaceID)
		}
		coverage, err := applyReviewedCoverage(root, CoverageRow{ID: item.SurfaceID, SourcePointer: fmt.Sprintf("/items/%d", index), SourceSHA256: digest(raw), ScenarioIDs: []string{}, FieldPointers: []string{}, PredecessorPaths: []string{}, PredecessorIdentities: []ArtifactIdentity{}}, mapping)
		if err != nil {
			return CoverageReceipt{}, err
		}
		if coverage.FreshUS020 {
			receipt.Summary.FreshRows++
		} else if len(coverage.PredecessorPaths) > 0 {
			receipt.Summary.PredecessorRows++
		} else {
			receipt.Summary.UnresolvedRows++
		}
		receipt.Compatibility = append(receipt.Compatibility, coverage)
	}
	if receipt.Summary.UnresolvedRows != 0 {
		return CoverageReceipt{}, errors.New("coverage has unresolved rows")
	}
	return receipt, nil
}

func uintValue(value any) (uint64, error) {
	number, ok := value.(float64)
	if !ok || number < 0 || number != float64(uint64(number)) {
		return 0, errors.New("invalid unsigned JSON number")
	}
	return uint64(number), nil
}

func commonCloseFromJava(value any) (*commonClose, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("Java close is not object")
	}
	codeNumber, ok := object["code"].(float64)
	if !ok || codeNumber < 0 || codeNumber > 65535 {
		return nil, errors.New("Java close code invalid")
	}
	code := uint16(codeNumber)
	reason, ok := object["reason"].(string)
	if !ok {
		return nil, errors.New("Java close reason invalid")
	}
	origin, ok := object["origin"].(string)
	if !ok {
		return nil, errors.New("Java close origin invalid")
	}
	clean, ok := object["handshake_complete"].(bool)
	if !ok {
		return nil, errors.New("Java close handshake flag invalid")
	}
	return &commonClose{Code: &code, Reason: reason, Clean: clean, Origin: origin}, nil
}

func normalizeJavaErrorClass(sc corpora.Scenario, value string) string {
	if sc.Family == "buffer-limit-frame" && value == "JAVA_INVALID_DATA" {
		return "LIMIT_EXCEEDED"
	}
	switch value {
	case "JAVA_INVALID_DATA", "JAVA_NOT_SENDABLE", "JAVA_RUNTIME_REJECTION":
		return "PROTOCOL_REJECTION"
	case "STATE_VIOLATION":
		return "INVALID_STATE"
	case "INPUT_LIMIT_EXCEEDED", "BUFFER_LIMIT_EXCEEDED", "ACTION_LIMIT_EXCEEDED", "FRAME_LIMIT_EXCEEDED", "OUTPUT_LIMIT_EXCEEDED":
		return "LIMIT_EXCEEDED"
	default:
		return value
	}
}

var rustCommonErrorClasses = map[string]string{
	"PROTOCOL_SLICE_UNAVAILABLE": "PROTOCOL_SLICE_UNAVAILABLE", "HANDSHAKE": "HANDSHAKE",
	"FRAME_RESERVED_BITS": "PROTOCOL_REJECTION", "FRAME_RESERVED_OPCODE": "PROTOCOL_REJECTION", "FRAME_FRAGMENTED_CONTROL": "PROTOCOL_REJECTION", "FRAME_CONTROL_PAYLOAD_TOO_LARGE": "PROTOCOL_REJECTION", "FRAME_NONCANONICAL_LENGTH16": "PROTOCOL_REJECTION", "FRAME_NONCANONICAL_LENGTH64": "PROTOCOL_REJECTION", "FRAME_LENGTH_HIGH_BIT": "PROTOCOL_REJECTION", "FRAME_INCORRECT_MASKING": "PROTOCOL_REJECTION", "FRAME_LENGTH_PLATFORM": "PROTOCOL_REJECTION", "FRAME_ARITHMETIC_OVERFLOW": "PROTOCOL_REJECTION", "FRAME_ALLOCATION_FAILED": "PROTOCOL_REJECTION", "FRAME_UNEXPECTED_EOF": "PROTOCOL_REJECTION", "FRAME_MISSING_MASK_KEY": "PROTOCOL_REJECTION", "FRAME_UNEXPECTED_MASK_KEY": "PROTOCOL_REJECTION",
	"UTF8_UNEXPECTED_CONTINUATION": "PROTOCOL_REJECTION", "UTF8_INVALID_LEADING_BYTE": "PROTOCOL_REJECTION", "UTF8_INVALID_CONTINUATION": "PROTOCOL_REJECTION", "UTF8_OVERLONG": "PROTOCOL_REJECTION", "UTF8_SURROGATE": "PROTOCOL_REJECTION", "UTF8_OUT_OF_RANGE": "PROTOCOL_REJECTION", "UTF8_TRUNCATED": "PROTOCOL_REJECTION",
	"FRAGMENT_CONTINUATION_WITHOUT_MESSAGE": "PROTOCOL_REJECTION", "FRAGMENT_DATA_WHILE_ACTIVE": "PROTOCOL_REJECTION", "FRAGMENT_UNEXPECTED_EOF": "PROTOCOL_REJECTION",
	"CLOSE_PAYLOAD_LENGTH_ONE": "PROTOCOL_REJECTION", "CLOSE_REASON_WITHOUT_CODE": "PROTOCOL_REJECTION", "CLOSE_INVALID_CODE": "PROTOCOL_REJECTION", "CLOSE_DUPLICATE_LOCAL": "PROTOCOL_REJECTION", "CLOSE_DUPLICATE_PEER": "PROTOCOL_REJECTION", "CLOSE_ACK_MISMATCH": "PROTOCOL_REJECTION", "CLOSE_DATA_AFTER_CLOSE": "PROTOCOL_REJECTION", "CLOSE_TRAILING_BYTES": "PROTOCOL_REJECTION", "CLOSE_UNEXPECTED_EOF_OPEN": "PROTOCOL_REJECTION", "CLOSE_EOF_BEFORE_PEER": "PROTOCOL_REJECTION", "CLOSE_EOF_BEFORE_ACK": "PROTOCOL_REJECTION", "CLOSE_EOF_BEFORE_FLUSH": "PROTOCOL_REJECTION",
	"LIMIT_HANDSHAKE_BYTES": "LIMIT_EXCEEDED", "LIMIT_HANDSHAKE_HEADER_COUNT": "LIMIT_EXCEEDED", "LIMIT_HANDSHAKE_LINE_BYTES": "LIMIT_EXCEEDED", "LIMIT_FRAME_BYTES": "LIMIT_EXCEEDED", "LIMIT_MESSAGE_BYTES": "LIMIT_EXCEEDED", "LIMIT_TOTAL_BUFFERED_BYTES": "LIMIT_EXCEEDED", "LIMIT_EVENT_ENTRIES": "LIMIT_EXCEEDED", "LIMIT_COMMAND_ENTRIES": "LIMIT_EXCEEDED", "LIMIT_WRITE_ENTRIES": "LIMIT_EXCEEDED",
	"ACTION_LIMIT_EXCEEDED": "LIMIT_EXCEEDED", "FRAME_LIMIT_EXCEEDED": "LIMIT_EXCEEDED", "INPUT_LIMIT_EXCEEDED": "LIMIT_EXCEEDED",
	"BACKPRESSURE_EVENT": "BACKPRESSURE", "BACKPRESSURE_COMMAND": "BACKPRESSURE", "BACKPRESSURE_WRITE": "BACKPRESSURE", "INVALID_STATE": "INVALID_STATE",
}

func normalizeRustErrorClass(value string) (string, error) {
	common, ok := rustCommonErrorClasses[value]
	if !ok {
		return "", fmt.Errorf("unmapped Rust error class %q", value)
	}
	return common, nil
}

func normalizeJava(sc corpora.Scenario, raw []byte) (commonObservation, []string, error) {
	trimmed := bytes.TrimSuffix(raw, []byte("\n"))
	if bytes.Contains(trimmed, []byte("\n")) || len(trimmed) == 0 {
		return commonObservation{}, nil, errors.New("Java emitted zero or multiple records")
	}
	var object map[string]any
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return commonObservation{}, nil, err
	}
	if object["request_id"] != sc.ScenarioID || object["protocol"] != "java-websocket-oracle" || object["version"] != "1.0.0" {
		return commonObservation{}, nil, errors.New("Java response binding invalid")
	}
	if initial, present := object["initial_state"]; present && initial != sc.Core.InitialState {
		return commonObservation{}, nil, errors.New("Java initial state binding invalid")
	}
	if role, present := object["role"]; present && role != sc.Core.Role {
		return commonObservation{}, nil, errors.New("Java role binding invalid")
	}
	result := commonObservation{ScenarioID: sc.ScenarioID, Role: sc.Core.Role, InitialState: sc.Core.InitialState, Events: []commonEvent{}, Frames: []commonFrame{}, Transitions: []commonTransition{}}
	var ok bool
	result.Outcome, ok = object["outcome"].(string)
	if !ok {
		return commonObservation{}, nil, errors.New("Java outcome absent")
	}
	result.FinalState, ok = object["final_state"].(string)
	if !ok {
		return commonObservation{}, nil, errors.New("Java final state absent")
	}
	counts, ok := object["counts"].(map[string]any)
	if !ok {
		return commonObservation{}, nil, errors.New("Java counts absent")
	}
	if err := requireObjectKeys(counts, "actions", "buffered_bytes", "consumed_bytes", "frames", "input_bytes", "message_buffered_bytes", "wire_buffered_bytes"); err != nil {
		return commonObservation{}, nil, fmt.Errorf("Java counts: %w", err)
	}
	for name, target := range map[string]*uint64{"actions": &result.Counts.Actions, "buffered_bytes": &result.Counts.BufferedBytes, "consumed_bytes": &result.Counts.ConsumedBytes, "frames": &result.Counts.Frames, "input_bytes": &result.Counts.InputBytes, "message_buffered_bytes": &result.Counts.MessageBufferedBytes, "wire_buffered_bytes": &result.Counts.WireBufferedBytes} {
		value, err := uintValue(counts[name])
		if err != nil {
			return commonObservation{}, nil, fmt.Errorf("Java count %s: %w", name, err)
		}
		*target = value
	}
	loss := []string{"/runtime", "/protocol", "/version", "/request_digest", "/request_id"}
	if result.Outcome == "error" {
		if err := requireObjectKeys(object, "counts", "error", "final_state", "outcome", "protocol", "request_digest", "request_id", "runtime", "version"); err != nil {
			return commonObservation{}, nil, fmt.Errorf("Java error envelope: %w", err)
		}
		errorObject, ok := object["error"].(map[string]any)
		if !ok {
			return commonObservation{}, nil, errors.New("Java error absent")
		}
		class, ok := errorObject["code"].(string)
		if !ok {
			return commonObservation{}, nil, errors.New("Java error class absent")
		}
		result.Error = &commonError{Class: normalizeJavaErrorClass(sc, class), Terminal: false}
		if err := requireObjectKeys(errorObject, "close_code", "code", "detail"); err != nil {
			return commonObservation{}, nil, err
		}
		loss = append(loss, "/error/detail")
		if _, ok := errorObject["close_code"]; ok {
			loss = append(loss, "/error/close_code")
		}
		return result, loss, nil
	}
	if err := requireObjectKeys(object, "close", "counts", "events", "final_state", "frames", "initial_state", "outcome", "protocol", "request_digest", "request_id", "role", "runtime", "transitions", "version"); err != nil {
		return commonObservation{}, nil, fmt.Errorf("Java success envelope: %w", err)
	}
	if events, ok := object["events"].([]any); ok {
		for index, value := range events {
			event, keep, err := normalizeJavaEvent(value)
			if err != nil {
				return commonObservation{}, nil, fmt.Errorf("Java event %d: %w", index, err)
			}
			if keep {
				result.Events = append(result.Events, event)
				object, _ := value.(map[string]any)
				switch object["type"] {
				case "text":
					loss = append(loss, fmt.Sprintf("/events/%d/utf8_bytes(java-event-diagnostic)", index))
				case "binary", "ping", "pong":
					loss = append(loss, fmt.Sprintf("/events/%d/bytes(java-event-diagnostic)", index))
				case "close", "close_initiated", "eof":
					loss = append(loss, fmt.Sprintf("/events/%d/remote(java-close-diagnostic)", index))
				}
			} else {
				loss = append(loss, fmt.Sprintf("/events/%d(adapter-only)", index))
			}
		}
	}
	if frames, ok := object["frames"].([]any); ok {
		for index, value := range frames {
			frame, err := normalizeJavaFrame(value)
			if err != nil {
				return commonObservation{}, nil, fmt.Errorf("Java frame %d: %w", index, err)
			}
			result.Frames = append(result.Frames, frame)
			for _, field := range []string{"payload_bytes", "rsv1", "rsv2", "rsv3"} {
				loss = append(loss, fmt.Sprintf("/frames/%d/%s(java-frame-diagnostic)", index, field))
			}
			pointer := fmt.Sprintf("/frames/%d/payload_base64", index)
			if selected, _, selectedByRFC := explicitRFCOracleOverride(sc, pointer); selectedByRFC {
				selectedPayload, isString := selected.(string)
				if isString && selectedPayload != frame.PayloadB64 {
					loss = append(loss, pointer+"(java-close-payload-projection)")
				}
			}
		}
	}
	if transitions, ok := object["transitions"].([]any); ok {
		for index, value := range transitions {
			transition, err := normalizeJavaTransition(value)
			if err != nil {
				return commonObservation{}, nil, fmt.Errorf("Java transition %d: %w", index, err)
			}
			result.Transitions = append(result.Transitions, transition)
			loss = append(loss, fmt.Sprintf("/transitions/%d/cause(java-only)", index))
		}
	}
	var err error
	result.Close, err = commonCloseFromJava(object["close"])
	if err != nil {
		return commonObservation{}, nil, err
	}
	if result.Close != nil {
		closeObject, _ := object["close"].(map[string]any)
		if err := requireObjectKeys(closeObject, "code", "handshake_complete", "origin", "reason", "remote"); err != nil {
			return commonObservation{}, nil, err
		}
		loss = append(loss, "/close/remote(java-close-diagnostic)")
	}
	return result, loss, nil
}

func normalizeJavaEvent(value any) (commonEvent, bool, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return commonEvent{}, false, errors.New("not object")
	}
	kind, ok := object["type"].(string)
	if !ok {
		return commonEvent{}, false, errors.New("type absent")
	}
	step, err := uintValue(object["step"])
	if err != nil || step > 65535 {
		return commonEvent{}, false, errors.New("step invalid")
	}
	event := commonEvent{Step: uint16(step), Kind: kind}
	switch kind {
	case "text":
		if err := requireObjectKeys(object, "text", "type", "step", "utf8_bytes"); err != nil {
			return commonEvent{}, false, err
		}
		event.Text, ok = object["text"].(string)
		if !ok {
			return commonEvent{}, false, errors.New("text absent")
		}
	case "binary", "ping", "pong":
		if err := requireObjectKeys(object, "bytes", "data_base64", "type", "step"); err != nil {
			return commonEvent{}, false, err
		}
		event.PayloadB64, ok = object["data_base64"].(string)
		if !ok {
			return commonEvent{}, false, errors.New("data_base64 absent")
		}
	case "close", "close_initiated", "eof":
		if err := requireObjectKeys(object, "code", "handshake_complete", "origin", "reason", "remote", "type", "step"); err != nil {
			return commonEvent{}, false, err
		}
		close, err := commonCloseFromJava(object)
		if err != nil {
			return commonEvent{}, false, err
		}
		event.Kind = "close"
		event.Close = close
	default:
		if _, allowed := javaAdapterOnlyEvents[kind]; !allowed {
			return commonEvent{}, false, fmt.Errorf("unmapped Java event type %q", kind)
		}
		if err := requireObjectKeys(object, javaAdapterOnlyEvents[kind]...); err != nil {
			return commonEvent{}, false, err
		}
		return commonEvent{}, false, nil
	}
	return event, true, nil
}

var javaAdapterOnlyEvents = map[string][]string{
	"input_chunk":             {"bytes", "step", "type"},
	"send_text":               {"opcode", "step", "type"},
	"send_binary":             {"opcode", "step", "type"},
	"send_ping":               {"opcode", "step", "type"},
	"send_pong":               {"opcode", "step", "type"},
	"send_close":              {"opcode", "step", "type"},
	"send_fragment":           {"opcode", "step", "type"},
	"echo_close":              {"opcode", "step", "type"},
	"open":                    {"step", "type"},
	"runtime_close":           {"code", "reason", "remote", "step", "type"},
	"runtime_closing":         {"code", "reason", "remote", "step", "type"},
	"runtime_close_initiated": {"code", "reason", "step", "type"},
	"listener_error":          {"class", "step", "type"},
	"write_demand":            {"step", "type"},
}

func requireObjectKeys(object map[string]any, allowed ...string) error {
	set := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		set[key] = true
	}
	for key := range object {
		if !set[key] {
			return fmt.Errorf("unreviewed field %q", key)
		}
	}
	return nil
}

func jsonPointerValue(root any, pointer string) (any, bool) {
	if pointer == "" {
		return root, true
	}
	current := root
	for _, encoded := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		part := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		switch value := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = value[part]
			if !ok {
				return nil, false
			}
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(value) {
				return nil, false
			}
			current = value[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func buildNormalizationTrace(runtimeName, attempt string, raw []byte, normalizedSHA string, loss []string) (NormalizationTrace, error) {
	trace := NormalizationTrace{Runtime: runtimeName, Attempt: attempt, RawBase64: base64.StdEncoding.EncodeToString(raw), RawSHA256: digest(raw), NormalizedSHA256: normalizedSHA, Losses: []NormalizationLoss{}}
	if runtimeName != "java" {
		return trace, nil
	}
	var value any
	if err := json.Unmarshal(bytes.TrimSuffix(raw, []byte("\n")), &value); err != nil {
		return NormalizationTrace{}, err
	}
	seen := map[string]bool{}
	for _, annotated := range loss {
		pointer := annotated
		reason := "reviewed common-surface projection"
		if at := strings.Index(pointer, "("); at >= 0 {
			reason = strings.TrimSuffix(pointer[at+1:], ")")
			pointer = pointer[:at]
		}
		if seen[annotated] {
			return NormalizationTrace{}, fmt.Errorf("duplicate normalization loss %s", annotated)
		}
		seen[annotated] = true
		rawValue, ok := jsonPointerValue(value, pointer)
		if !ok {
			return NormalizationTrace{}, fmt.Errorf("normalization loss pointer absent: %s", pointer)
		}
		encoded, err := canonical(rawValue)
		if err != nil {
			return NormalizationTrace{}, err
		}
		trace.Losses = append(trace.Losses, NormalizationLoss{Pointer: pointer, Reason: reason, ValueSHA256: digest(encoded)})
	}
	return trace, nil
}

func auditReplayNormalization(primary, replay NormalizationTrace) (string, error) {
	if primary.Runtime != replay.Runtime || primary.NormalizedSHA256 == "" || replay.NormalizedSHA256 == "" {
		return "NORMALIZATION_AUDIT_INVALID", errors.New("normalization trace binding invalid")
	}
	if primary.RawSHA256 == replay.RawSHA256 {
		if primary.NormalizedSHA256 != replay.NormalizedSHA256 {
			return "NORMALIZATION_NONDETERMINISM", errors.New("equal raw observations normalized differently")
		}
		return "", nil
	}
	if primary.NormalizedSHA256 == replay.NormalizedSHA256 {
		return "NORMALIZATION_COLLISION", errors.New("distinct raw observations collapsed to one normalized observation")
	}
	return "RAW_REPLAY_DIFFERENCE", errors.New("primary and replay raw observations differ")
}

func normalizeJavaFrame(value any) (commonFrame, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return commonFrame{}, errors.New("not object")
	}
	if err := requireObjectKeys(object, "direction", "fin", "masked", "opcode", "payload_base64", "payload_bytes", "rsv1", "rsv2", "rsv3", "step", "wire_bytes"); err != nil {
		return commonFrame{}, err
	}
	step, err := uintValue(object["step"])
	if err != nil || step > 65535 {
		return commonFrame{}, errors.New("step invalid")
	}
	wire, err := uintValue(object["wire_bytes"])
	if err != nil {
		return commonFrame{}, err
	}
	direction, _ := object["direction"].(string)
	opcode, _ := object["opcode"].(string)
	fin, _ := object["fin"].(bool)
	masked, _ := object["masked"].(bool)
	payload, _ := object["payload_base64"].(string)
	decoded, decodeErr := base64.StdEncoding.DecodeString(payload)
	payloadBytes, countErr := uintValue(object["payload_bytes"])
	if decodeErr != nil || base64.StdEncoding.EncodeToString(decoded) != payload || countErr != nil || payloadBytes != uint64(len(decoded)) {
		return commonFrame{}, errors.New("Java frame payload accounting invalid")
	}
	for _, field := range []string{"rsv1", "rsv2", "rsv3"} {
		if _, ok := object[field].(bool); !ok {
			return commonFrame{}, errors.New("Java frame RSV diagnostic invalid")
		}
	}
	return commonFrame{Step: uint16(step), Direction: direction, Fin: fin, Opcode: opcode, Masked: masked, PayloadB64: payload, WireLength: wire}, nil
}

func normalizeJavaTransition(value any) (commonTransition, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return commonTransition{}, errors.New("not object")
	}
	if err := requireObjectKeys(object, "cause", "from", "step", "to"); err != nil {
		return commonTransition{}, err
	}
	step, err := uintValue(object["step"])
	if err != nil || step > 65535 {
		return commonTransition{}, errors.New("step invalid")
	}
	from, _ := object["from"].(string)
	to, _ := object["to"].(string)
	return commonTransition{Step: uint16(step), From: from, To: to}, nil
}

func acceptedRustInputBytes(source corpora.Step, step rustStep) (uint64, error) {
	if source.Kind != "bytes" {
		return 0, nil
	}
	payload, err := base64.StdEncoding.DecodeString(source.DataBase64)
	if err != nil {
		return 0, err
	}
	if step.Consumed > uint64(len(payload)) {
		return 0, errors.New("Rust consumed more bytes than offered")
	}
	if len(payload) == 0 {
		if step.Consumed != 0 {
			return 0, errors.New("zero-length byte step consumed input")
		}
		return 0, nil
	}
	for _, item := range step.Observations {
		if item.Error != nil && item.Error.Class == "INPUT_LIMIT_EXCEEDED" {
			if step.Consumed != 0 {
				return 0, errors.New("input-limit rejection consumed input")
			}
			return 0, nil
		}
	}
	if step.PreState != "closed" {
		return uint64(len(payload)), nil
	}
	for _, item := range step.Observations {
		if item.Error != nil && item.Error.Class == "INVALID_STATE" {
			if step.Consumed != 0 {
				return 0, errors.New("closed-state rejection consumed input")
			}
			return 0, nil
		}
	}
	return 0, errors.New("closed-state byte step lacks INVALID_STATE rejection")
}

func validateRustDerivedCounters(sc corpora.Scenario, result ScenarioResult) error {
	if len(result.RustStepDiagnostics) != len(sc.Core.Steps) {
		return errors.New("Rust diagnostic step count does not bind the public scenario")
	}
	var inputBytes, consumedBytes uint64
	hasByteStep := false
	for index, step := range result.RustStepDiagnostics {
		source := sc.Core.Steps[index]
		if source.Kind == "bytes" {
			hasByteStep = true
			accepted, err := acceptedRustInputBytes(source, step)
			if err != nil {
				return err
			}
			if inputBytes > ^uint64(0)-accepted {
				return errors.New("Rust derived input counter overflow")
			}
			inputBytes += accepted
		}
		if consumedBytes > ^uint64(0)-step.Consumed {
			return errors.New("Rust consumed counter overflow")
		}
		consumedBytes += step.Consumed
	}
	if result.RustObservation.Counts.InputBytes != inputBytes || result.RustObservation.Counts.ConsumedBytes != consumedBytes {
		return errors.New("Rust aggregate counters do not match bounded diagnostic derivation")
	}
	if hasByteStep && !contains(result.RustNormalizationNotes, rustInputDerivationNote) {
		return errors.New("Rust input derivation audit note absent")
	}
	return nil
}

func normalizeRust(sc corpora.Scenario, raw []byte) (commonObservation, rustObservation, error) {
	decoded, err := decodeNeutralResponse(raw)
	if err != nil {
		return commonObservation{}, rustObservation{}, err
	}
	if decoded.ScenarioID != sc.ScenarioID || decoded.Role != sc.Core.Role || decoded.Initial != sc.Core.InitialState {
		return commonObservation{}, rustObservation{}, errors.New("Rust response binding invalid")
	}
	result := commonObservation{ScenarioID: sc.ScenarioID, Role: decoded.Role, InitialState: decoded.Initial, Outcome: "ok", Events: []commonEvent{}, Frames: []commonFrame{}, Transitions: []commonTransition{}, FinalState: decoded.Final, Close: decoded.Close}
	if len(decoded.Steps) > len(sc.Core.Steps) {
		return commonObservation{}, rustObservation{}, errors.New("Rust returned extra steps")
	}
	for index, step := range decoded.Steps {
		source := sc.Core.Steps[index]
		if source.Kind == "bytes" {
			accepted, err := acceptedRustInputBytes(source, step)
			if err != nil {
				return commonObservation{}, rustObservation{}, err
			}
			result.Counts.InputBytes += accepted
		} else if source.Kind == "action" {
			result.Counts.Actions++
		}
		result.Counts.ConsumedBytes += step.Consumed
		result.Counts.WireBufferedBytes = step.WireBuffered
		result.Counts.MessageBufferedBytes = step.MessageBuffered
		for _, item := range step.Observations {
			if item.Event != nil {
				result.Events = append(result.Events, *item.Event)
			}
			if item.Frame != nil {
				result.Frames = append(result.Frames, *item.Frame)
				result.Counts.Frames++
			}
			if item.Transition != nil {
				result.Transitions = append(result.Transitions, *item.Transition)
			}
			if item.Error != nil && result.Error == nil {
				class, err := normalizeRustErrorClass(item.Error.Class)
				if err != nil {
					return commonObservation{}, rustObservation{}, err
				}
				result.Error = &commonError{Class: class, Terminal: false}
				result.Outcome = "error"
			}
			if item.Close != nil {
				result.Close = item.Close
			}
		}
	}
	result.Counts.BufferedBytes = result.Counts.WireBufferedBytes + result.Counts.MessageBufferedBytes
	return result, decoded, nil
}

func normalizeDigest(value commonObservation) (string, error) {
	raw, err := canonical(value)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}

func neutralObservation(sc corpora.Scenario) (commonObservation, error) {
	raw, err := json.Marshal(sc)
	if err != nil {
		return commonObservation{}, err
	}
	var scenario map[string]any
	if err := json.Unmarshal(raw, &scenario); err != nil {
		return commonObservation{}, err
	}
	expected, ok := scenario["expected"].(map[string]any)
	if !ok {
		return commonObservation{}, errors.New("expected absent")
	}
	response := map[string]any{"request_id": sc.ScenarioID, "protocol": "java-websocket-oracle", "version": "1.0.0", "outcome": expected["outcome"], "final_state": expected["final_state"], "counts": expected["counts"]}
	if expected["outcome"] == "error" {
		errorValue := expected["error"].(map[string]any)
		copyError := map[string]any{}
		for key, value := range errorValue {
			copyError[key] = value
		}
		copyError["detail"] = "neutral"
		response["error"] = copyError
	} else {
		for _, field := range []string{"events", "frames", "transitions", "close"} {
			if value, present := expected[field]; present {
				response[field] = value
			}
		}
	}
	encoded, err := canonical(response)
	if err != nil {
		return commonObservation{}, err
	}
	normalized, _, err := normalizeJava(sc, append(encoded, '\n'))
	return normalized, err
}

func hasForbiddenCorpusComponent(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == "hidden" || part == "sealed" {
			return true
		}
	}
	return false
}

func validateExistingPath(path string, executable bool) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || hasForbiddenCorpusComponent(path) {
		return fmt.Errorf("path must be absolute clean public-only: %s", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if resolved != path {
		return fmt.Errorf("symlink path forbidden: %s", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("non-regular path: %s", path)
	}
	if executable && info.Mode()&0o111 == 0 {
		return fmt.Errorf("not executable: %s", path)
	}
	return nil
}

func within(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateOutputParent(path string) error {
	parent := filepath.Dir(path)
	for {
		info, err := os.Lstat(parent)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("output ancestor is not a real directory")
			}
			resolved, err := filepath.EvalSymlinks(parent)
			if err != nil || resolved != parent {
				return errors.New("output ancestor resolves through symlink")
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		next := filepath.Dir(parent)
		if next == parent {
			return errors.New("no real output ancestor")
		}
		parent = next
	}
}

func validateConfig(cfg Config) error {
	if cfg.ScenarioTimeout <= 0 || cfg.ScenarioTimeout > 5*time.Second {
		return errors.New("scenario timeout must be in (0,5s]")
	}
	if cfg.SuiteTimeout <= 0 || cfg.SuiteTimeout > 15*time.Minute {
		return errors.New("suite timeout must be in (0,15m]")
	}
	if cfg.MinimizationBudget.MaxCandidates <= 0 || cfg.MinimizationBudget.MaxCandidates > 512 || cfg.MinimizationBudget.MaxDuration <= 0 || cfg.MinimizationBudget.MaxDuration > 30*time.Minute {
		return errors.New("minimization budget invalid")
	}
	if cfg.RepositoryRoot == "" || !filepath.IsAbs(cfg.RepositoryRoot) || filepath.Clean(cfg.RepositoryRoot) != cfg.RepositoryRoot || cfg.RepositoryRoot == string(filepath.Separator) {
		return errors.New("repository root must be absolute, clean, and narrow")
	}
	rootResolved, err := filepath.EvalSymlinks(cfg.RepositoryRoot)
	if err != nil || rootResolved != cfg.RepositoryRoot {
		return errors.New("repository root may not resolve through symlink")
	}
	rootInfo, err := os.Lstat(cfg.RepositoryRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("repository root must be a real directory")
	}
	inputs := []struct {
		path                   string
		executable, repository bool
	}{{cfg.PublicCorpus, false, true}, {cfg.JavaExecutable, true, false}, {cfg.JavaAdapterJar, false, false}, {cfg.JavaRuntimeJar, false, false}, {cfg.RustTestee, true, false}, {cfg.MigrationInventory, false, true}, {cfg.CompatibilitySurface, false, true}, {cfg.LedgerPath, false, true}, {cfg.OracleHierarchyPath, false, true}}
	if len(cfg.JavaSupportJars) == 0 || len(cfg.JavaSupportJars) > 16 {
		return errors.New("java support jars must contain 1..16 paths")
	}
	for _, path := range cfg.JavaSupportJars {
		inputs = append(inputs, struct {
			path                   string
			executable, repository bool
		}{path, false, false})
	}
	seen := map[string]bool{}
	for _, input := range inputs {
		if err := validateExistingPath(input.path, input.executable); err != nil {
			return err
		}
		if input.repository && !within(cfg.RepositoryRoot, input.path) {
			return fmt.Errorf("repository input escapes root: %s", input.path)
		}
		if seen[input.path] {
			return fmt.Errorf("duplicate input alias: %s", input.path)
		}
		seen[input.path] = true
	}
	for _, output := range []string{cfg.EvidencePath, cfg.LedgerPath} {
		if output == "" || !filepath.IsAbs(output) || filepath.Clean(output) != output || !within(cfg.RepositoryRoot, output) || hasForbiddenCorpusComponent(output) {
			return fmt.Errorf("output path invalid: %s", output)
		}
		if output != cfg.LedgerPath {
			if seen[output] {
				return errors.New("output aliases input")
			}
			if err := validateOutputParent(output); err != nil {
				return err
			}
		}
	}
	return nil
}

func artifact(path string) (ArtifactIdentity, error) {
	raw, err := readRegularBounded(path, 512<<20)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	return ArtifactIdentity{Path: path, SHA256: digest(raw), Bytes: int64(len(raw))}, nil
}

func collectInputIdentities(cfg Config) ([]ArtifactIdentity, error) {
	specs := []struct{ kind, path string }{
		{"public-corpus", cfg.PublicCorpus},
		{"public-corpus-manifest", filepath.Join(cfg.RepositoryRoot, "corpora/public/manifest.json")},
		{"java-executable", cfg.JavaExecutable},
		{"java-adapter-jar", cfg.JavaAdapterJar},
		{"java-runtime-jar", cfg.JavaRuntimeJar},
		{"rust-testee", cfg.RustTestee},
		{"migration-inventory", cfg.MigrationInventory},
		{"compatibility-surface", cfg.CompatibilitySurface},
		{"oracle-hierarchy", cfg.OracleHierarchyPath},
	}
	for index, path := range cfg.JavaSupportJars {
		specs = append(specs, struct{ kind, path string }{fmt.Sprintf("java-support-jar-%02d", index), path})
	}
	qualification := filepath.Join(cfg.RepositoryRoot, "evidence/us020-current-head-qualification.json")
	if _, err := os.Lstat(qualification); err == nil {
		specs = append(specs, struct{ kind, path string }{"current-head-qualification", qualification})
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	inputs := make([]ArtifactIdentity, 0, len(specs))
	for _, spec := range specs {
		identity, err := artifact(spec.path)
		if err != nil {
			return nil, err
		}
		identity.Kind = spec.kind
		inputs = append(inputs, identity)
		if spec.kind == "java-executable" {
			image, err := javaRuntimeImageIdentity(cfg.JavaExecutable)
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, image)
		}
	}
	return inputs, nil
}

func gitAnchor(root string) (string, error) {
	cmd := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	raw, err := cmd.Output()
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if len(value) != 40 && len(value) != 64 {
		return "", errors.New("git anchor malformed")
	}
	return value, nil
}

type attemptOutput struct {
	observation commonObservation
	rust        rustObservation
	receipt     ProcessReceipt
	loss        []string
	trace       NormalizationTrace
}

func runAttempt(ctx context.Context, cfg Config, suiteHome string, sc corpora.Scenario, runtimeName, attempt, executableDigest string) (attemptOutput, error) {
	request := childRequest{Home: suiteHome, Timeout: cfg.ScenarioTimeout}
	if runtimeName == "java" {
		line, err := corpora.OracleRequestLine(sc)
		if err != nil {
			return attemptOutput{}, err
		}
		request.Input = append(line, '\n')
		classpath := append([]string{cfg.JavaAdapterJar, cfg.JavaRuntimeJar}, cfg.JavaSupportJars...)
		request.Executable = cfg.JavaExecutable
		request.Args = []string{"-Dslf4j.internal.verbosity=ERROR", "-cp", strings.Join(classpath, string(os.PathListSeparator)), "OracleMain"}
	} else {
		input, err := encodeNeutralRequest(sc)
		if err != nil {
			return attemptOutput{}, err
		}
		request.Input = input
		request.Executable = cfg.RustTestee
		request.Args = []string{"neutral-oracle", "--protocol", "NDRV1"}
	}
	result, err := executeChild(ctx, request)
	if err != nil {
		return attemptOutput{}, fmt.Errorf("%s %s %s: %w", sc.ScenarioID, runtimeName, attempt, err)
	}
	output := attemptOutput{}
	if runtimeName == "java" {
		output.observation, output.loss, err = normalizeJava(sc, result.Stdout)
	} else {
		output.observation, output.rust, err = normalizeRust(sc, result.Stdout)
	}
	if err != nil {
		return attemptOutput{}, fmt.Errorf("normalize %s %s: %w", runtimeName, sc.ScenarioID, err)
	}
	normalizedDigest, err := normalizeDigest(output.observation)
	if err != nil {
		return attemptOutput{}, err
	}
	output.trace, err = buildNormalizationTrace(runtimeName, attempt, result.Stdout, normalizedDigest, output.loss)
	if err != nil {
		return attemptOutput{}, err
	}
	output.receipt = ProcessReceipt{ScenarioID: sc.ScenarioID, Runtime: runtimeName, Attempt: attempt, PID: result.PID, ExecutableSHA256: executableDigest, StdinSHA256: digest(request.Input), StdinBytes: len(request.Input), StdoutSHA256: digest(result.Stdout), StdoutBytes: len(result.Stdout), StderrSHA256: digest(result.Stderr), StderrBytes: len(result.Stderr), ExitCode: result.ExitCode, StartedUnixNano: result.Started.UnixNano(), DurationNanos: result.Duration.Nanoseconds(), NormalizedSHA256: normalizedDigest, LaunchedInputs: append([]LaunchIdentity(nil), cfg.launchInputs[runtimeName]...)}
	return output, nil
}

func hierarchyForCandidate(all []corpora.Scenario, candidate corpora.Scenario) (OracleHierarchy, error) {
	copyScenarios := append([]corpora.Scenario(nil), all...)
	found := false
	for index := range copyScenarios {
		if copyScenarios[index].ScenarioID == candidate.ScenarioID {
			copyScenarios[index] = candidate
			found = true
			break
		}
	}
	if !found {
		return OracleHierarchy{}, errors.New("minimization candidate is outside public corpus")
	}
	return BuildOracleHierarchy(copyScenarios)
}

func minimizeRuntimeMismatch(ctx context.Context, cfg Config, suiteRoot string, all []corpora.Scenario, original corpora.Scenario, signature mismatchSignature, anchor, javaDigest, rustDigest string, inputs []ArtifactIdentity) (PublicReproducer, error) {
	candidateNumber := 0
	auditsByScenario := map[string][][]NormalizationTrace{}
	predicate := func(candidate corpora.Scenario) (mismatchSignature, []ProcessReceipt, error) {
		candidateNumber++
		home := filepath.Join(suiteRoot, "minimize", original.ScenarioID, fmt.Sprintf("%04d", candidateNumber))
		if err := os.MkdirAll(home, 0o700); err != nil {
			return mismatchSignature{}, nil, err
		}
		javaPrimary, err := runAttempt(ctx, cfg, home, candidate, "java", fmt.Sprintf("candidate-%04d-primary", candidateNumber), javaDigest)
		if err != nil {
			return mismatchSignature{}, nil, err
		}
		javaReplay, err := runAttempt(ctx, cfg, home, candidate, "java", fmt.Sprintf("candidate-%04d-replay", candidateNumber), javaDigest)
		if err != nil {
			return mismatchSignature{}, nil, err
		}
		rustPrimary, err := runAttempt(ctx, cfg, home, candidate, "rust", fmt.Sprintf("candidate-%04d-primary", candidateNumber), rustDigest)
		if err != nil {
			return mismatchSignature{}, nil, err
		}
		rustReplay, err := runAttempt(ctx, cfg, home, candidate, "rust", fmt.Sprintf("candidate-%04d-replay", candidateNumber), rustDigest)
		if err != nil {
			return mismatchSignature{}, nil, err
		}
		receipts := []ProcessReceipt{javaPrimary.receipt, javaReplay.receipt, rustPrimary.receipt, rustReplay.receipt}
		line, lineErr := candidate.CanonicalLine()
		if lineErr != nil {
			return mismatchSignature{}, receipts, lineErr
		}
		sha := digest(line)
		auditsByScenario[sha] = append(auditsByScenario[sha], []NormalizationTrace{javaPrimary.trace, javaReplay.trace, rustPrimary.trace, rustReplay.trace})
		if _, err := auditReplayNormalization(javaPrimary.trace, javaReplay.trace); err != nil {
			return mismatchSignature{}, receipts, err
		}
		if _, err := auditReplayNormalization(rustPrimary.trace, rustReplay.trace); err != nil {
			return mismatchSignature{}, receipts, err
		}
		candidateHierarchy, err := hierarchyForCandidate(all, candidate)
		if err != nil {
			return mismatchSignature{}, receipts, err
		}
		_, findings, _ := adjudicateScenario(candidate, candidateHierarchy, javaPrimary.observation, rustPrimary.observation)
		for _, finding := range findings {
			got := mismatchSignature{Pointer: finding.Pointer, Classification: finding.Classification}
			if got == signature {
				return got, receipts, nil
			}
		}
		return mismatchSignature{}, receipts, nil
	}
	reproducer, err := minimizeScenarioFresh(original, cfg.MinimizationBudget, predicate)
	if err != nil {
		return PublicReproducer{}, err
	}
	used := map[string]int{}
	for index := range reproducer.Attempts {
		sha := reproducer.Attempts[index].ScenarioSHA256
		at := used[sha]
		if at >= len(auditsByScenario[sha]) {
			return PublicReproducer{}, errors.New("minimization audit transcript absent")
		}
		reproducer.Attempts[index].Audits = auditsByScenario[sha][at]
		used[sha]++
	}
	reproducer.RepositoryAnchor = anchor
	reproducer.RuntimeInputs = append([]ArtifactIdentity(nil), inputs...)
	reproducer.Command = canonicalReproducerCommand(cfg.RepositoryRoot, cfg.EvidencePath, reproducer.ReproducerID)
	return reproducer, nil
}

func firstDifference(left, right commonObservation) (string, error) {
	leftRaw, err := canonical(left)
	if err != nil {
		return "", err
	}
	rightRaw, err := canonical(right)
	if err != nil {
		return "", err
	}
	var leftValue, rightValue any
	if err := json.Unmarshal(leftRaw, &leftValue); err != nil {
		return "", err
	}
	if err := json.Unmarshal(rightRaw, &rightValue); err != nil {
		return "", err
	}
	return firstJSONDifference(leftValue, rightValue, ""), nil
}

func diagnosticValue(observation commonObservation, pointer string) (string, error) {
	value, err := observationValue(observation, pointer)
	if err != nil {
		return "", err
	}
	raw, err := canonical(value)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func firstJSONDifference(left, right any, pointer string) string {
	leftMap, leftOK := left.(map[string]any)
	rightMap, rightOK := right.(map[string]any)
	if leftOK || rightOK {
		if !leftOK || !rightOK {
			return pointer
		}
		keys := map[string]bool{}
		for key := range leftMap {
			keys[key] = true
		}
		for key := range rightMap {
			keys[key] = true
		}
		ordered := make([]string, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			next := pointer + "/" + escapePointer(key)
			lv, lPresent := leftMap[key]
			rv, rPresent := rightMap[key]
			if !lPresent || !rPresent {
				return next
			}
			if difference := firstJSONDifference(lv, rv, next); difference != "" {
				return difference
			}
		}
		return ""
	}
	leftArray, leftOK := left.([]any)
	rightArray, rightOK := right.([]any)
	if leftOK || rightOK {
		if !leftOK || !rightOK || len(leftArray) != len(rightArray) {
			return pointer
		}
		for index := range leftArray {
			if difference := firstJSONDifference(leftArray[index], rightArray[index], fmt.Sprintf("%s/%d", pointer, index)); difference != "" {
				return difference
			}
		}
		return ""
	}
	leftRaw, _ := canonical(left)
	rightRaw, _ := canonical(right)
	if !bytes.Equal(leftRaw, rightRaw) {
		return pointer
	}
	return ""
}

func marshalIndented(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// RunPublicDifferential executes the full public suite. Validation remains at
// the facade so an invalid configuration cannot launch either runtime.
func RunPublicDifferential(ctx context.Context, cfg Config) (Receipt, error) {
	if err := validateConfig(cfg); err != nil {
		return Receipt{}, err
	}
	lock, err := acquireEvidenceLock(cfg.RepositoryRoot, cfg.LedgerPath, cfg.EvidencePath)
	if err != nil {
		return Receipt{}, err
	}
	defer func() { _ = lock.Release() }()
	if err := recoverEvidencePair(lock, cfg.LedgerPath, cfg.EvidencePath); err != nil {
		return Receipt{}, err
	}
	suiteCtx, cancel := context.WithTimeout(ctx, cfg.SuiteTimeout)
	defer cancel()
	suiteRoot, err := os.MkdirTemp("", "us020-differential-")
	if err != nil {
		return Receipt{}, err
	}
	defer removeImmutableTree(suiteRoot)
	scenarios, _, err := loadPublicCorpus(cfg.RepositoryRoot, cfg.PublicCorpus)
	if err != nil {
		return Receipt{}, err
	}
	hierarchyRaw, err := readRegularBounded(cfg.OracleHierarchyPath, maximumDocumentBytes)
	if err != nil {
		return Receipt{}, err
	}
	var hierarchy OracleHierarchy
	if err := decodeStrict(hierarchyRaw, &hierarchy); err != nil {
		return Receipt{}, err
	}
	if err := ValidateOracleHierarchy(scenarios, hierarchy); err != nil {
		return Receipt{}, err
	}
	ledgerRaw, err := readRegularBounded(cfg.LedgerPath, maximumDocumentBytes)
	if err != nil {
		return Receipt{}, err
	}
	ledger, err := migrateLedger(ledgerRaw)
	if err != nil {
		return Receipt{}, err
	}
	preHead := ledger.Head
	ledgerInputSHA := digest(ledgerRaw)
	coverage, err := buildCoverage(cfg.RepositoryRoot, scenarios)
	if err != nil {
		return Receipt{}, err
	}
	controls, err := runSeededControls()
	if err != nil {
		return Receipt{}, err
	}
	anchor, err := gitAnchor(cfg.RepositoryRoot)
	if err != nil {
		return Receipt{}, err
	}
	inputs, err := collectInputIdentities(cfg)
	if err != nil {
		return Receipt{}, err
	}
	inputByKind := map[string]ArtifactIdentity{}
	for _, input := range inputs {
		inputByKind[input.Kind] = input
	}
	javaIdentity, javaOK := inputByKind["java-executable"]
	rustIdentity, rustOK := inputByKind["rust-testee"]
	if !javaOK || !rustOK {
		return Receipt{}, errors.New("runtime input identity absent")
	}
	launchedCfg, err := materializeConfiguredLaunch(cfg, suiteRoot, inputs)
	if err != nil {
		return Receipt{}, err
	}
	manifest := Manifest{Schema: "../../schemas/differential-evidence-1.0.0.schema.json", SchemaVersion: evidenceSchemaVersion, EvidenceID: "evidence.us-020-public-differential", StoryID: "US-020", Status: StatusPass, Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT", ParityScope: "RUNTIME_COMMON_AGGREGATE", RepositoryAnchor: anchor, Inputs: inputs, Coverage: coverage, Controls: controls, Reproducers: []PublicReproducer{}, Nonclaims: []string{"no per-step Java counter parity", rustInputDerivationNote, "no hidden or sealed corpus access", "no Docker Autobahn wstest Linux or network execution", "no wire interoperability browser performance allocation concurrency TLS or NIO parity", "fresh child receipts prove invocation not an uncontaminated host", "no production publication signing or independent review claim"}}
	for _, sc := range scenarios {
		neutral, err := neutralObservation(sc)
		if err != nil {
			return Receipt{}, err
		}
		neutralDigest, err := normalizeDigest(neutral)
		if err != nil {
			return Receipt{}, err
		}
		home := filepath.Join(suiteRoot, sc.ScenarioID)
		if err := os.Mkdir(home, 0o700); err != nil {
			return Receipt{}, err
		}
		javaPrimary, err := runAttempt(suiteCtx, launchedCfg, home, sc, "java", "primary", javaIdentity.SHA256)
		if err != nil {
			return Receipt{}, err
		}
		javaReplay, err := runAttempt(suiteCtx, launchedCfg, home, sc, "java", "replay", javaIdentity.SHA256)
		if err != nil {
			return Receipt{}, err
		}
		rustPrimary, err := runAttempt(suiteCtx, launchedCfg, home, sc, "rust", "primary", rustIdentity.SHA256)
		if err != nil {
			return Receipt{}, err
		}
		rustReplay, err := runAttempt(suiteCtx, launchedCfg, home, sc, "rust", "replay", rustIdentity.SHA256)
		if err != nil {
			return Receipt{}, err
		}
		manifest.Processes = append(manifest.Processes, javaPrimary.receipt, javaReplay.receipt, rustPrimary.receipt, rustReplay.receipt)
		if code, err := auditReplayNormalization(javaPrimary.trace, javaReplay.trace); err != nil {
			return Receipt{}, fmt.Errorf("%s Java replay %s: %w", sc.ScenarioID, code, err)
		}
		if code, err := auditReplayNormalization(rustPrimary.trace, rustReplay.trace); err != nil {
			return Receipt{}, fmt.Errorf("%s Rust replay %s: %w", sc.ScenarioID, code, err)
		}
		stable := true
		classification, findings, err := adjudicateScenario(sc, hierarchy, javaPrimary.observation, rustPrimary.observation)
		if err != nil {
			pointer, _ := firstDifference(javaPrimary.observation, rustPrimary.observation)
			return Receipt{}, fmt.Errorf("US020_DIFFERENCE scenario=%s pointer=%s adjudication=%w java=%s rust=%s neutral=%s java_value=%+v rust_value=%+v", sc.ScenarioID, pointer, err, javaPrimary.receipt.NormalizedSHA256, rustPrimary.receipt.NormalizedSHA256, neutralDigest, javaPrimary.observation, rustPrimary.observation)
		}
		rustNotes := []string{}
		for _, step := range sc.Core.Steps {
			if step.Kind == "bytes" {
				rustNotes = append(rustNotes, rustInputDerivationNote)
				break
			}
		}
		result := ScenarioResult{ScenarioID: sc.ScenarioID, JavaPrimary: javaPrimary.receipt.NormalizedSHA256, JavaReplay: javaReplay.receipt.NormalizedSHA256, RustPrimary: rustPrimary.receipt.NormalizedSHA256, RustReplay: rustReplay.receipt.NormalizedSHA256, NeutralExpected: neutralDigest, Stable: stable, CurrentMismatch: false, Classification: classification, JavaObservation: javaPrimary.observation, RustObservation: rustPrimary.observation, RustStepDiagnostics: rustPrimary.rust.Steps, RustBootstrapSHA256: digest(rustPrimary.rust.Bootstrap), JavaNormalizationLoss: javaPrimary.loss, RustNormalizationNotes: rustNotes, NormalizationAudits: []NormalizationTrace{javaPrimary.trace, javaReplay.trace, rustPrimary.trace, rustReplay.trace}}
		if err := validateRustDerivedCounters(sc, result); err != nil {
			return Receipt{}, fmt.Errorf("Rust derived counter verification %s: %w", sc.ScenarioID, err)
		}
		manifest.Scenarios = append(manifest.Scenarios, result)
		for _, finding := range findings {
			signature := mismatchSignature{Pointer: finding.Pointer, Classification: finding.Classification}
			reproducer, err := minimizeRuntimeMismatch(suiteCtx, launchedCfg, suiteRoot, scenarios, sc, signature, anchor, javaIdentity.SHA256, rustIdentity.SHA256, inputs)
			if err != nil {
				return Receipt{}, fmt.Errorf("minimize %s%s: %w", sc.ScenarioID, finding.Pointer, err)
			}
			reproducer.LedgerDeltaID = deltaIDFor(sc.ScenarioID, finding.Pointer)
			reproducer.FindingJavaObservation = javaPrimary.receipt.NormalizedSHA256
			reproducer.FindingRustObservation = rustPrimary.receipt.NormalizedSHA256
			reproducer.FindingRunAnchor = anchor
			manifest.Reproducers = append(manifest.Reproducers, reproducer)
			if err := appendJavaQuirk(&ledger, sc, finding, javaPrimary.receipt.NormalizedSHA256, rustPrimary.receipt.NormalizedSHA256, anchor, reproducer.OriginalScenarioSHA256); err != nil {
				return Receipt{}, err
			}
		}
		if err := appendObservedRemediations(&ledger, hierarchy, sc, javaPrimary.observation, rustPrimary.observation, javaPrimary.receipt.NormalizedSHA256, rustPrimary.receipt.NormalizedSHA256, anchor); err != nil {
			return Receipt{}, err
		}
		historicalReproducers, err := historicalClosedReproducers(cfg, hierarchy, sc, javaPrimary.receipt.NormalizedSHA256, rustPrimary.receipt.NormalizedSHA256, anchor, inputs)
		if err != nil {
			return Receipt{}, err
		}
		manifest.Reproducers = append(manifest.Reproducers, historicalReproducers...)
	}
	recordByDelta := map[string]LedgerRecord{}
	for _, record := range ledger.Records {
		recordByDelta[record.DeltaID] = record
	}
	for index := range manifest.Reproducers {
		record, ok := recordByDelta[manifest.Reproducers[index].LedgerDeltaID]
		if !ok {
			return Receipt{}, fmt.Errorf("reproducer ledger record absent: %s", manifest.Reproducers[index].LedgerDeltaID)
		}
		manifest.Reproducers[index].FindingJavaObservation = record.JavaObservation
		manifest.Reproducers[index].FindingRustObservation = record.RustObservation
		manifest.Reproducers[index].FindingRunAnchor = record.FindingRunAnchor
		manifest.Reproducers[index].ClosingRunAnchor = record.ClosingRunAnchor
		manifest.Reproducers[index].ClosingJavaObservation = record.ClosingJavaObservation
		manifest.Reproducers[index].ClosingRustObservation = record.ClosingRustObservation
	}
	manifest.Counts = CountsReceipt{Scenarios: len(scenarios), JavaPrimary: len(scenarios), JavaReplay: len(scenarios), RustPrimary: len(scenarios), RustReplay: len(scenarios), Processes: len(manifest.Processes)}
	manifest.Ledger = LedgerBinding{PreHead: preHead, PostHead: ledger.Head, Records: len(ledger.MigratedV1Records) + len(ledger.Records)}
	if len(ledger.MigratedV1Records)+len(ledger.Records) == 0 {
		ledger.Status = "PASS_NO_CURRENT_DELTAS"
	} else {
		ledger.Status = "PASS_WITH_CLOSED_HISTORY"
	}
	ledger.UnledgeredDisagreements = 0
	ledgerDocument, err := marshalIndented(ledger)
	if err != nil {
		return Receipt{}, err
	}
	manifestDocument, err := marshalIndented(manifest)
	if err != nil {
		return Receipt{}, err
	}
	if err := compileAndValidateSchema(filepath.Join(cfg.RepositoryRoot, "schemas/behavior-delta-ledger-1.1.0.schema.json"), ledgerDocument); err != nil {
		return Receipt{}, fmt.Errorf("ledger schema: %w", err)
	}
	if err := compileAndValidateSchema(filepath.Join(cfg.RepositoryRoot, "schemas/differential-evidence-1.0.0.schema.json"), manifestDocument); err != nil {
		return Receipt{}, fmt.Errorf("evidence schema: %w", err)
	}
	if err := recheckLedgerCAS(cfg.LedgerPath, ledgerInputSHA, preHead); err != nil {
		return Receipt{}, err
	}
	if err := commitEvidenceDocuments(lock, cfg.LedgerPath, ledgerDocument, cfg.EvidencePath, manifestDocument); err != nil {
		return Receipt{}, err
	}
	committed, err := readCommittedEvidence(cfg.EvidencePath, maximumDocumentBytes)
	if err != nil {
		return Receipt{}, err
	}
	if err := VerifyPublicDifferential(cfg.RepositoryRoot, committed); err != nil {
		return Receipt{}, err
	}
	return Receipt{Status: StatusPass, ScenarioCount: len(scenarios), ProcessReceipts: len(manifest.Processes), DeltaCount: len(ledger.MigratedV1Records) + len(ledger.Records), EvidenceSHA256: digest(committed)}, nil
}

// ReproducePublicDifferential executes one public minimized witness. Fresh
// witnesses rerun both runtimes in primary/replay child processes. Historical
// closed witnesses verify their immutable finding/closing identities without
// falsely claiming that the remediated Rust behavior still reproduces.
func ReproducePublicDifferential(ctx context.Context, repositoryRoot string, receiptBytes []byte, reproducerID string) (ReproductionReceipt, error) {
	if err := VerifyPublicDifferential(repositoryRoot, receiptBytes); err != nil {
		return ReproductionReceipt{}, err
	}
	var manifest Manifest
	if err := decodeStrict(receiptBytes, &manifest); err != nil {
		return ReproductionReceipt{}, err
	}
	var reproducer *PublicReproducer
	for index := range manifest.Reproducers {
		if manifest.Reproducers[index].ReproducerID == reproducerID {
			reproducer = &manifest.Reproducers[index]
			break
		}
	}
	if reproducer == nil {
		return ReproductionReceipt{}, errors.New("public reproducer id absent")
	}
	if reproducer.Mode == "HISTORICAL_CLOSED_IDENTITY_WITNESS" {
		return ReproductionReceipt{Status: "PASS_HISTORICAL_IDENTITY_CURRENT_DEFECT_CLOSED", ReproducerID: reproducerID, Mode: reproducer.Mode, ScenarioSHA256: reproducer.ScenarioSHA256, FreshProcesses: 0, CurrentlyReproduced: false}, nil
	}
	cfg, inputs, err := configFromManifestInputs(repositoryRoot, manifest)
	if err != nil {
		return ReproductionReceipt{}, err
	}
	suiteRoot, err := os.MkdirTemp("", "us020-reproducer-")
	if err != nil {
		return ReproductionReceipt{}, err
	}
	defer removeImmutableTree(suiteRoot)
	launched, err := materializeConfiguredLaunch(cfg, suiteRoot, inputs)
	if err != nil {
		return ReproductionReceipt{}, err
	}
	byKind := map[string]ArtifactIdentity{}
	for _, input := range inputs {
		byKind[input.Kind] = input
	}
	attempts := []attemptOutput{}
	for _, runtimeName := range []string{"java", "rust"} {
		for _, attempt := range []string{"primary", "replay"} {
			digest := byKind["rust-testee"].SHA256
			if runtimeName == "java" {
				digest = byKind["java-executable"].SHA256
			}
			output, err := runAttempt(ctx, launched, suiteRoot, reproducer.Scenario, runtimeName, attempt, digest)
			if err != nil {
				return ReproductionReceipt{}, err
			}
			attempts = append(attempts, output)
		}
	}
	if _, err := auditReplayNormalization(attempts[0].trace, attempts[1].trace); err != nil {
		return ReproductionReceipt{}, err
	}
	if _, err := auditReplayNormalization(attempts[2].trace, attempts[3].trace); err != nil {
		return ReproductionReceipt{}, err
	}
	scenarios, _, err := loadPublicCorpus(repositoryRoot, filepath.Join(repositoryRoot, "corpora/public/scenarios.jsonl"))
	if err != nil {
		return ReproductionReceipt{}, err
	}
	hierarchy, err := hierarchyForCandidate(scenarios, reproducer.Scenario)
	if err != nil {
		return ReproductionReceipt{}, err
	}
	_, findings, _ := adjudicateScenario(reproducer.Scenario, hierarchy, attempts[0].observation, attempts[2].observation)
	reproduced := false
	for _, finding := range findings {
		if (mismatchSignature{Pointer: finding.Pointer, Classification: finding.Classification}) == reproducer.Signature {
			reproduced = true
			break
		}
	}
	if !reproduced {
		return ReproductionReceipt{}, errors.New("fresh minimized difference did not reproduce")
	}
	return ReproductionReceipt{Status: "PASS_FRESH_DIFFERENCE_REPRODUCED", ReproducerID: reproducerID, Mode: reproducer.Mode, ScenarioSHA256: reproducer.ScenarioSHA256, FreshProcesses: 4, CurrentlyReproduced: true}, nil
}

// RunPublicDiagnostic executes the same bounded public primary/replay matrix
// but never reads or writes the behavior ledger or evidence destination. A
// semantic divergence is accumulated instead of ending the sweep; preflight,
// process, codec, and replay failures remain explicit diagnostic findings.
func RunPublicDiagnostic(ctx context.Context, cfg Config) (DiagnosticReport, error) {
	if err := validateConfig(cfg); err != nil {
		return DiagnosticReport{}, err
	}
	suiteCtx, cancel := context.WithTimeout(ctx, cfg.SuiteTimeout)
	defer cancel()
	suiteRoot, err := os.MkdirTemp("", "us020-diagnostic-")
	if err != nil {
		return DiagnosticReport{}, err
	}
	defer removeImmutableTree(suiteRoot)
	scenarios, _, err := loadPublicCorpus(cfg.RepositoryRoot, cfg.PublicCorpus)
	if err != nil {
		return DiagnosticReport{}, err
	}
	hierarchyRaw, err := readRegularBounded(cfg.OracleHierarchyPath, maximumDocumentBytes)
	if err != nil {
		return DiagnosticReport{}, err
	}
	var hierarchy OracleHierarchy
	if err := decodeStrict(hierarchyRaw, &hierarchy); err != nil {
		return DiagnosticReport{}, err
	}
	if err := ValidateOracleHierarchy(scenarios, hierarchy); err != nil {
		return DiagnosticReport{}, err
	}
	javaIdentity, err := artifact(cfg.JavaExecutable)
	if err != nil {
		return DiagnosticReport{}, err
	}
	rustIdentity, err := artifact(cfg.RustTestee)
	if err != nil {
		return DiagnosticReport{}, err
	}
	inputs, err := collectInputIdentities(cfg)
	if err != nil {
		return DiagnosticReport{}, err
	}
	launchedCfg, err := materializeConfiguredLaunch(cfg, suiteRoot, inputs)
	if err != nil {
		return DiagnosticReport{}, err
	}
	report := DiagnosticReport{Status: "DIAGNOSTIC_ONLY_NO_WRITES", ScenarioCount: len(scenarios), Findings: []DiagnosticFinding{}}
	for _, sc := range scenarios {
		home := filepath.Join(suiteRoot, sc.ScenarioID)
		if err := os.Mkdir(home, 0o700); err != nil {
			return DiagnosticReport{}, err
		}
		javaPrimary, javaPrimaryErr := runAttempt(suiteCtx, launchedCfg, home, sc, "java", "primary", javaIdentity.SHA256)
		javaReplay, javaReplayErr := runAttempt(suiteCtx, launchedCfg, home, sc, "java", "replay", javaIdentity.SHA256)
		rustPrimary, rustPrimaryErr := runAttempt(suiteCtx, launchedCfg, home, sc, "rust", "primary", rustIdentity.SHA256)
		rustReplay, rustReplayErr := runAttempt(suiteCtx, launchedCfg, home, sc, "rust", "replay", rustIdentity.SHA256)
		attempts := []struct {
			name string
			out  attemptOutput
			err  error
		}{{"java-primary", javaPrimary, javaPrimaryErr}, {"java-replay", javaReplay, javaReplayErr}, {"rust-primary", rustPrimary, rustPrimaryErr}, {"rust-replay", rustReplay, rustReplayErr}}
		failed := false
		for _, attempt := range attempts {
			if attempt.err != nil {
				report.Findings = append(report.Findings, DiagnosticFinding{ScenarioID: sc.ScenarioID, Pointer: "/processes/" + attempt.name, Classification: "infrastructure_failure", Detail: attempt.err.Error()})
				failed = true
				continue
			}
			report.ProcessReceipts++
		}
		if failed {
			continue
		}
		javaCode, javaAuditErr := auditReplayNormalization(javaPrimary.trace, javaReplay.trace)
		rustCode, rustAuditErr := auditReplayNormalization(rustPrimary.trace, rustReplay.trace)
		if javaAuditErr != nil || rustAuditErr != nil {
			report.Findings = append(report.Findings, DiagnosticFinding{ScenarioID: sc.ScenarioID, Pointer: "/replay", Classification: "flake", JavaSHA256: javaPrimary.receipt.NormalizedSHA256, RustSHA256: rustPrimary.receipt.NormalizedSHA256, Detail: "raw replay audit: java=" + javaCode + " rust=" + rustCode})
			continue
		}
		report.StableScenarios++
		classification, findings, adjudicationErr := adjudicateScenario(sc, hierarchy, javaPrimary.observation, rustPrimary.observation)
		for _, finding := range findings {
			if finding.Classification == "java_quirk" {
				report.AcceptedQuirks++
				continue
			}
			javaValue, javaValueErr := diagnosticValue(javaPrimary.observation, finding.Pointer)
			rustValue, rustValueErr := diagnosticValue(rustPrimary.observation, finding.Pointer)
			if javaValueErr != nil || rustValueErr != nil {
				report.Findings = append(report.Findings, DiagnosticFinding{ScenarioID: sc.ScenarioID, Pointer: finding.Pointer, Classification: "diagnostic_failure", Detail: "encode field values"})
				continue
			}
			report.Findings = append(report.Findings, DiagnosticFinding{ScenarioID: sc.ScenarioID, Pointer: finding.Pointer, Classification: finding.Classification, JavaSHA256: finding.JavaSHA256, RustSHA256: finding.RustSHA256, ExpectedSHA256: finding.Decision.ExpectedSHA256, JavaValue: javaValue, RustValue: rustValue, Detail: "field-addressed adjudication"})
		}
		if adjudicationErr != nil && len(findings) == 0 {
			pointer, _ := firstDifference(javaPrimary.observation, rustPrimary.observation)
			report.Findings = append(report.Findings, DiagnosticFinding{ScenarioID: sc.ScenarioID, Pointer: pointer, Classification: "adjudication_failure", JavaSHA256: javaPrimary.receipt.NormalizedSHA256, RustSHA256: rustPrimary.receipt.NormalizedSHA256, Detail: adjudicationErr.Error()})
		}
		if adjudicationErr == nil {
			notes := []string{}
			for _, step := range sc.Core.Steps {
				if step.Kind == "bytes" {
					notes = append(notes, rustInputDerivationNote)
					break
				}
			}
			result := ScenarioResult{ScenarioID: sc.ScenarioID, RustObservation: rustPrimary.observation, RustStepDiagnostics: rustPrimary.rust.Steps, RustNormalizationNotes: notes, Classification: classification}
			if err := validateRustDerivedCounters(sc, result); err != nil {
				report.Findings = append(report.Findings, DiagnosticFinding{ScenarioID: sc.ScenarioID, Pointer: "/counts", Classification: "normalization_failure", Detail: err.Error()})
			}
		}
	}
	for _, finding := range report.Findings {
		if finding.Classification != "java_quirk" {
			report.BlockingFindings++
		}
	}
	return report, nil
}

func decodeStrict(raw []byte, destination any) error {
	if len(raw) <= 8<<20 {
		return intake.DecodeStrict(raw, destination)
	}
	if int64(len(raw)) > maximumDocumentBytes {
		return errors.New("JSON document exceeds differential evidence bound")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("top-level null is not a document")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are forbidden")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 128 {
			return errors.New("JSON nesting exceeds 128")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				seen[key] = true
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("unterminated JSON object")
			}
		case '[':
			for decoder.More() {
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("unterminated JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := scan(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are forbidden")
		}
		return err
	}
	return nil
}

func writeJSONAtomic(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".us020-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

type evidenceLock struct {
	path         string
	file         *os.File
	repository   string
	ledgerPath   string
	manifestPath string
}

func canonicalCoordinationInputs(repositoryRoot, ledgerPath, manifestPath string) (string, string, string, error) {
	paths := []string{repositoryRoot, ledgerPath, manifestPath}
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return "", "", "", errors.New("coordination paths must be absolute and clean")
		}
	}
	resolvedRoot, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		return "", "", "", errors.New("coordination repository root cannot be canonicalized")
	}
	canonicalOutput := func(path string) (string, error) {
		parent := filepath.Dir(path)
		resolved, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return "", errors.New("coordination output parent cannot be canonicalized")
		}
		return filepath.Join(resolved, filepath.Base(path)), nil
	}
	ledger, err := canonicalOutput(ledgerPath)
	if err != nil {
		return "", "", "", err
	}
	manifest, err := canonicalOutput(manifestPath)
	if err != nil {
		return "", "", "", err
	}
	return resolvedRoot, ledger, manifest, nil
}

func evidenceCoordinationPath(repositoryRoot, ledgerPath, manifestPath string) (string, error) {
	repository, ledger, manifest, err := canonicalCoordinationInputs(repositoryRoot, ledgerPath, manifestPath)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte(repository + "\x00" + ledger + "\x00" + manifest))
	// /tmp is the shared macOS/Linux process-coordination namespace. Do not use
	// TMPDIR: independent writers may have different environment values and
	// must still contend on the same canonical-path key.
	directory := filepath.Join(string(filepath.Separator), "tmp", fmt.Sprintf("verified-java-websocket-port-us020-%d", os.Getuid()))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("evidence coordination directory is not private and real")
	}
	path := filepath.Join(directory, hex.EncodeToString(key[:])+".lock")
	if within(repository, path) {
		return "", errors.New("evidence coordination file must be outside repository")
	}
	return path, nil
}

func acquireEvidenceLock(repositoryRoot, ledgerPath, manifestPath string) (*evidenceLock, error) {
	repository, ledger, manifest, err := canonicalCoordinationInputs(repositoryRoot, ledgerPath, manifestPath)
	if err != nil {
		return nil, err
	}
	path, err := evidenceCoordinationPath(repository, ledger, manifest)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open evidence coordination file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	closeOnError := func(cause error) (*evidenceLock, error) {
		if closeErr := file.Close(); closeErr != nil {
			return nil, errors.Join(cause, closeErr)
		}
		return nil, cause
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return closeOnError(errors.New("evidence coordination file is not private and regular"))
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return closeOnError(errors.New("evidence coordination file identity changed"))
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return closeOnError(fmt.Errorf("live evidence writer coordination held: %w", err))
	}
	return &evidenceLock{path: path, file: file, repository: repository, ledgerPath: ledger, manifestPath: manifest}, nil
}

func (lock *evidenceLock) Release() error {
	if lock == nil || lock.file == nil {
		return errors.New("invalid evidence lock")
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}

func validateEvidenceLock(lock *evidenceLock, ledgerPath, manifestPath string) error {
	if lock == nil || lock.file == nil {
		return errors.New("evidence coordination is not exclusively held")
	}
	_, ledger, manifest, err := canonicalCoordinationInputs(lock.repository, ledgerPath, manifestPath)
	if err != nil {
		return err
	}
	if ledger != lock.ledgerPath || manifest != lock.manifestPath {
		return errors.New("evidence coordination path binding mismatch")
	}
	opened, err := lock.file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(lock.path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return errors.New("held evidence coordination identity changed")
	}
	return nil
}

type pairJournal struct {
	SchemaVersion  string `json:"schema_version"`
	LedgerPath     string `json:"ledger_path"`
	LedgerStage    string `json:"ledger_stage"`
	LedgerSHA256   string `json:"ledger_sha256"`
	ManifestPath   string `json:"manifest_path"`
	ManifestStage  string `json:"manifest_stage"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

func stageDocument(destination string, raw []byte) (string, error) {
	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(dir, ".us020-pair-*.stage")
	if err != nil {
		return "", err
	}
	name := file.Name()
	failed := true
	defer func() {
		if failed {
			file.Close()
			os.Remove(name)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := file.Write(raw); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	failed = false
	return name, nil
}

func installJournalDocument(stage, destination, expected string) error {
	if raw, err := readRegularBounded(stage, maximumDocumentBytes); err == nil {
		if digest(raw) != expected {
			return errors.New("journal stage digest mismatch")
		}
		return os.Rename(stage, destination)
	}
	raw, err := readRegularBounded(destination, maximumDocumentBytes)
	if err != nil || digest(raw) != expected {
		return errors.New("journal destination/stage unavailable")
	}
	return nil
}

func recoverEvidencePair(lock *evidenceLock, ledgerPath, manifestPath string) error {
	if err := validateEvidenceLock(lock, ledgerPath, manifestPath); err != nil {
		return err
	}
	journalPath := ledgerPath + ".us020-journal"
	raw, err := readRegularBounded(journalPath, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal pairJournal
	if err := decodeStrict(raw, &journal); err != nil {
		return err
	}
	if journal.SchemaVersion != "1.0.0" || journal.LedgerPath != ledgerPath || journal.ManifestPath != manifestPath || !validLedgerDigest(journal.LedgerSHA256) || !validLedgerDigest(journal.ManifestSHA256) {
		return errors.New("pair journal binding invalid")
	}
	if err := installJournalDocument(journal.LedgerStage, journal.LedgerPath, journal.LedgerSHA256); err != nil {
		return err
	}
	if err := installJournalDocument(journal.ManifestStage, journal.ManifestPath, journal.ManifestSHA256); err != nil {
		return err
	}
	if err := os.Remove(journalPath); err != nil {
		return err
	}
	for _, dir := range []string{filepath.Dir(ledgerPath), filepath.Dir(manifestPath)} {
		directory, err := os.Open(dir)
		if err != nil {
			return err
		}
		err = directory.Sync()
		directory.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func commitEvidencePair(lock *evidenceLock, ledgerPath string, ledgerRaw []byte, manifestPath string, manifestRaw []byte) error {
	if err := recoverEvidencePair(lock, ledgerPath, manifestPath); err != nil {
		return fmt.Errorf("recover evidence pair: %w", err)
	}
	ledgerStage, err := stageDocument(ledgerPath, ledgerRaw)
	if err != nil {
		return err
	}
	manifestStage, err := stageDocument(manifestPath, manifestRaw)
	if err != nil {
		os.Remove(ledgerStage)
		return err
	}
	journal := pairJournal{SchemaVersion: "1.0.0", LedgerPath: ledgerPath, LedgerStage: ledgerStage, LedgerSHA256: digest(ledgerRaw), ManifestPath: manifestPath, ManifestStage: manifestStage, ManifestSHA256: digest(manifestRaw)}
	if err := writeJSONAtomic(ledgerPath+".us020-journal", journal); err != nil {
		os.Remove(ledgerStage)
		os.Remove(manifestStage)
		return err
	}
	return recoverEvidencePair(lock, ledgerPath, manifestPath)
}

func recheckLedgerCAS(path, expectedDocumentSHA, expectedHead string) error {
	raw, err := readRegularBounded(path, maximumDocumentBytes)
	if err != nil {
		return err
	}
	ledger, err := migrateLedger(raw)
	if err != nil {
		return err
	}
	if digest(raw) != expectedDocumentSHA || ledger.Head != expectedHead {
		return errors.New("stale on-disk ledger compare-and-swap")
	}
	return nil
}

func compileAndValidateSchema(schemaPath string, document []byte) error {
	schemaRaw, err := readRegularBounded(schemaPath, maximumDocumentBytes)
	if err != nil {
		return err
	}
	schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	resource := "https://verified-java-websocket-port.invalid/" + filepath.Base(schemaPath)
	if err := compiler.AddResource(resource, schemaValue); err != nil {
		return err
	}
	if filepath.Base(schemaPath) == "differential-evidence-1.0.0.schema.json" {
		corpusSchemaPath := filepath.Join(filepath.Dir(schemaPath), "corpus-scenario-1.0.0.schema.json")
		corpusSchemaRaw, err := readRegularBounded(corpusSchemaPath, maximumDocumentBytes)
		if err != nil {
			return err
		}
		corpusSchemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(corpusSchemaRaw))
		if err != nil {
			return err
		}
		if err := compiler.AddResource("https://verified-java-websocket-port.invalid/corpus-scenario-1.0.0.schema.json", corpusSchemaValue); err != nil {
			return err
		}
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		return err
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(document))
	if err != nil {
		return err
	}
	return schema.Validate(value)
}

func verifyManifestValue(root string, raw []byte) error {
	var manifest Manifest
	if err := decodeStrict(raw, &manifest); err != nil {
		return err
	}
	if manifest.SchemaVersion != evidenceSchemaVersion || manifest.EvidenceID != "evidence.us-020-public-differential" || manifest.StoryID != "US-020" || manifest.Status != StatusPass {
		return errors.New("manifest identity/status invalid")
	}
	if manifest.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || manifest.IndependentReviewClaimed || manifest.Production || manifest.Publication || manifest.Signing {
		return errors.New("assurance claim invalid")
	}
	if manifest.ParityScope != "RUNTIME_COMMON_AGGREGATE" || !contains(manifest.Nonclaims, "no per-step Java counter parity") || !contains(manifest.Nonclaims, rustInputDerivationNote) {
		return errors.New("per-step Java parity overclaim or nonclaim absent")
	}
	counts := manifest.Counts
	if counts.Scenarios != expectedPublicScenarios || counts.JavaPrimary != expectedPublicScenarios || counts.JavaReplay != expectedPublicScenarios || counts.RustPrimary != expectedPublicScenarios || counts.RustReplay != expectedPublicScenarios || counts.Processes != expectedProcessReceipts || counts.Flakes != 0 || counts.CurrentMismatches != 0 || counts.UnresolvedDifferences != 0 || counts.NormalizationCollisions != 0 {
		return errors.New("manifest counts invalid")
	}
	if len(manifest.Scenarios) != expectedPublicScenarios || len(manifest.Processes) != expectedProcessReceipts {
		return errors.New("manifest array cardinality invalid")
	}
	if len(manifest.Reproducers) != 103 {
		return errors.New("manifest must retain exactly 103 public reproducers")
	}
	if manifest.Controls.Total != 7 || manifest.Controls.Killed != 7 || len(manifest.Controls.Results) != 7 {
		return errors.New("control receipt invalid")
	}
	if len(manifest.Coverage.Migration) != 47 || len(manifest.Coverage.Compatibility) != 14 || manifest.Coverage.Summary.UnresolvedRows != 0 {
		return errors.New("coverage receipt invalid")
	}
	seenScenarios := map[string]bool{}
	for _, scenario := range manifest.Scenarios {
		if scenario.ScenarioID == "" || seenScenarios[scenario.ScenarioID] || !scenario.Stable || scenario.CurrentMismatch {
			return errors.New("scenario receipt invalid")
		}
		seenScenarios[scenario.ScenarioID] = true
	}
	seenProcesses := map[string]bool{}
	for _, process := range manifest.Processes {
		key := process.ScenarioID + "|" + process.Runtime + "|" + process.Attempt
		if seenProcesses[key] || process.PID <= 0 || process.ExitCode != 0 || !strings.HasPrefix(process.ExecutableSHA256, "sha256:") || !strings.HasPrefix(process.NormalizedSHA256, "sha256:") {
			return errors.New("process receipt invalid")
		}
		seenProcesses[key] = true
	}
	if root == "" || !filepath.IsAbs(root) {
		return errors.New("repository root invalid")
	}
	return nil
}

func canonicalEqual(left, right any) bool {
	l, lerr := canonical(left)
	r, rerr := canonical(right)
	return lerr == nil && rerr == nil && bytes.Equal(l, r)
}

func configFromManifestInputs(root string, manifest Manifest) (Config, []ArtifactIdentity, error) {
	inputs := append([]ArtifactIdentity(nil), manifest.Inputs...)
	byKind := map[string]ArtifactIdentity{}
	for _, input := range inputs {
		if input.Kind == "" || byKind[input.Kind].Path != "" {
			return Config{}, nil, errors.New("input kind absent or duplicate")
		}
		byKind[input.Kind] = input
	}
	repositoryPaths := map[string]string{
		"public-corpus":          filepath.Join(root, "corpora/public/scenarios.jsonl"),
		"public-corpus-manifest": filepath.Join(root, "corpora/public/manifest.json"),
		"migration-inventory":    filepath.Join(root, "evidence/intake/semantic-id-migration-map.json"),
		"compatibility-surface":  filepath.Join(root, "evidence/intake/compatibility-surface.json"),
		"oracle-hierarchy":       filepath.Join(root, "evidence/oracle-hierarchy.json"),
	}
	qualification := filepath.Join(root, "evidence/us020-current-head-qualification.json")
	if _, statErr := os.Lstat(qualification); statErr != nil {
		return Config{}, nil, statErr
	}
	repositoryPaths["current-head-qualification"] = qualification
	for kind, path := range repositoryPaths {
		if byKind[kind].Path != path {
			return Config{}, nil, fmt.Errorf("repository input %s path drift", kind)
		}
	}
	for _, kind := range []string{"java-executable", "java-adapter-jar", "java-runtime-jar", "rust-testee"} {
		if byKind[kind].Path == "" {
			return Config{}, nil, fmt.Errorf("runtime input %s absent", kind)
		}
	}
	support := []string{}
	for index := 0; ; index++ {
		kind := fmt.Sprintf("java-support-jar-%02d", index)
		input, ok := byKind[kind]
		if !ok {
			break
		}
		support = append(support, input.Path)
	}
	if len(support) == 0 || len(byKind) != len(repositoryPaths)+5+len(support) || byKind["java-runtime-image"].Path == "" {
		return Config{}, nil, errors.New("input kind set is not exact")
	}
	cfg := Config{RepositoryRoot: root, PublicCorpus: repositoryPaths["public-corpus"], JavaExecutable: byKind["java-executable"].Path, JavaAdapterJar: byKind["java-adapter-jar"].Path, JavaRuntimeJar: byKind["java-runtime-jar"].Path, JavaSupportJars: support, RustTestee: byKind["rust-testee"].Path, MigrationInventory: repositoryPaths["migration-inventory"], CompatibilitySurface: repositoryPaths["compatibility-surface"], LedgerPath: filepath.Join(root, "evidence/java/behavior-delta-ledger.json"), EvidencePath: filepath.Join(root, "evidence/differential/manifest.json"), OracleHierarchyPath: repositoryPaths["oracle-hierarchy"], ScenarioTimeout: 5 * time.Second, SuiteTimeout: 15 * time.Minute, MinimizationBudget: Budget{MaxCandidates: 128, MaxDuration: 10 * time.Minute}}
	want, err := collectInputIdentities(cfg)
	if err != nil {
		return Config{}, nil, err
	}
	if !canonicalEqual(inputs, want) {
		return Config{}, nil, errors.New("manifest input identity drift")
	}
	return cfg, inputs, nil
}

func validateExecutionAnchor(root, anchor string, inputs []ArtifactIdentity) error {
	if !validLedgerAnchor(anchor) {
		return errors.New("repository execution anchor malformed")
	}
	command := exec.Command("git", "-C", root, "cat-file", "-e", anchor+"^{commit}")
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	if err := command.Run(); err != nil {
		return errors.New("repository execution anchor is not a commit")
	}
	repositoryKinds := map[string]bool{"public-corpus": true, "public-corpus-manifest": true, "migration-inventory": true, "compatibility-surface": true, "oracle-hierarchy": true}
	for _, input := range inputs {
		if !repositoryKinds[input.Kind] {
			continue
		}
		relative, err := filepath.Rel(root, input.Path)
		if err != nil {
			return err
		}
		show := exec.Command("git", "-C", root, "show", anchor+":"+filepath.ToSlash(relative))
		show.Env = []string{"LANG=C", "LC_ALL=C"}
		raw, err := show.Output()
		if err != nil || digest(raw) != input.SHA256 || int64(len(raw)) != input.Bytes {
			return fmt.Errorf("repository input %s is not bound at execution anchor", input.Kind)
		}
	}
	return nil
}

func expectedLaunchIdentities(runtimeName string, inputs []ArtifactIdentity) []LaunchIdentity {
	result := []LaunchIdentity{}
	for _, input := range inputs {
		role := ""
		switch {
		case runtimeName == "rust" && input.Kind == "rust-testee":
			role = "rust-testee"
		case runtimeName == "java" && input.Kind == "java-executable":
			role = "java-executable"
		case runtimeName == "java" && input.Kind == "java-runtime-image":
			role = "java-runtime-image"
		case runtimeName == "java" && input.Kind == "java-adapter-jar":
			role = "java-adapter"
		case runtimeName == "java" && input.Kind == "java-runtime-jar":
			role = "java-runtime"
		case runtimeName == "java" && strings.HasPrefix(input.Kind, "java-support-jar-"):
			role = strings.Replace(input.Kind, "java-support-jar-", "java-support-", 1)
		}
		if role != "" {
			result = append(result, LaunchIdentity{Role: role, SourcePath: input.Path, SourceSHA256: input.SHA256, ObjectSHA256: input.SHA256, ObjectName: strings.TrimPrefix(input.SHA256, "sha256:"), Bytes: input.Bytes})
		}
	}
	return result
}

func processKey(scenarioID, runtimeName, attempt string) string {
	return scenarioID + "|" + runtimeName + "|" + attempt
}

func verifyProcessMatrix(manifest Manifest, scenarios []corpora.Scenario, inputs []ArtifactIdentity) (map[string]ProcessReceipt, error) {
	expectedScenario := map[string]corpora.Scenario{}
	for _, scenario := range scenarios {
		expectedScenario[scenario.ScenarioID] = scenario
	}
	inputByKind := map[string]ArtifactIdentity{}
	for _, input := range inputs {
		inputByKind[input.Kind] = input
	}
	processes := map[string]ProcessReceipt{}
	pids := map[int]bool{}
	for _, process := range manifest.Processes {
		key := processKey(process.ScenarioID, process.Runtime, process.Attempt)
		scenario, exists := expectedScenario[process.ScenarioID]
		if !exists || processes[key].PID != 0 || pids[process.PID] || process.PID <= 0 || process.ExitCode != 0 || process.StartedUnixNano <= 0 || process.DurationNanos < 0 || process.DurationNanos > int64(5*time.Second) {
			return nil, fmt.Errorf("invalid process receipt %s", key)
		}
		if (process.Runtime != "java" && process.Runtime != "rust") || (process.Attempt != "primary" && process.Attempt != "replay") {
			return nil, fmt.Errorf("unexpected process key %s", key)
		}
		var stdin []byte
		var err error
		executable := inputByKind["rust-testee"]
		if process.Runtime == "java" {
			stdin, err = corpora.OracleRequestLine(scenario)
			stdin = append(stdin, '\n')
			executable = inputByKind["java-executable"]
		} else {
			stdin, err = encodeNeutralRequest(scenario)
		}
		if err != nil {
			return nil, err
		}
		if process.ExecutableSHA256 != executable.SHA256 || process.StdinSHA256 != digest(stdin) || process.StdinBytes != len(stdin) || !validLedgerDigest(process.StdoutSHA256) || process.StdoutBytes <= 0 || !validLedgerDigest(process.StderrSHA256) || process.StderrBytes < 0 || process.StderrBytes > maximumProcessError || !validLedgerDigest(process.NormalizedSHA256) {
			return nil, fmt.Errorf("process identity/source link invalid %s", key)
		}
		if !canonicalEqual(process.LaunchedInputs, expectedLaunchIdentities(process.Runtime, inputs)) {
			return nil, fmt.Errorf("launched input binding invalid %s", key)
		}
		processes[key], pids[process.PID] = process, true
	}
	for _, scenario := range scenarios {
		for _, runtimeName := range []string{"java", "rust"} {
			for _, attempt := range []string{"primary", "replay"} {
				key := processKey(scenario.ScenarioID, runtimeName, attempt)
				if processes[key].PID == 0 {
					return nil, fmt.Errorf("process absent %s", key)
				}
			}
		}
	}
	if len(processes) != expectedProcessReceipts {
		return nil, errors.New("process set cardinality drift")
	}
	return processes, nil
}

func verifyTrace(sc corpora.Scenario, trace NormalizationTrace, process ProcessReceipt) (commonObservation, rustObservation, []string, error) {
	if trace.Runtime != process.Runtime || trace.Attempt != process.Attempt {
		return commonObservation{}, rustObservation{}, nil, errors.New("normalization trace process binding invalid")
	}
	raw, err := base64.StdEncoding.DecodeString(trace.RawBase64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != trace.RawBase64 || trace.RawSHA256 != digest(raw) || trace.RawSHA256 != process.StdoutSHA256 || len(raw) != process.StdoutBytes {
		return commonObservation{}, rustObservation{}, nil, errors.New("normalization raw identity invalid")
	}
	var observation commonObservation
	var rust rustObservation
	loss := []string{}
	if trace.Runtime == "java" {
		observation, loss, err = normalizeJava(sc, raw)
	} else {
		observation, rust, err = normalizeRust(sc, raw)
	}
	if err != nil {
		return commonObservation{}, rustObservation{}, nil, err
	}
	normalized, err := normalizeDigest(observation)
	if err != nil {
		return commonObservation{}, rustObservation{}, nil, err
	}
	want, err := buildNormalizationTrace(trace.Runtime, trace.Attempt, raw, normalized, loss)
	if err != nil || !canonicalEqual(trace, want) || trace.NormalizedSHA256 != process.NormalizedSHA256 {
		return commonObservation{}, rustObservation{}, nil, errors.New("normalization trace rederivation drift")
	}
	return observation, rust, loss, nil
}

func verifyScenarioMatrix(manifest Manifest, scenarios []corpora.Scenario, hierarchy OracleHierarchy, processes map[string]ProcessReceipt) (map[string][]AdjudicatedFinding, error) {
	if len(manifest.Scenarios) != len(scenarios) {
		return nil, errors.New("scenario result cardinality drift")
	}
	findingsByScenario := map[string][]AdjudicatedFinding{}
	for index, sc := range scenarios {
		result := manifest.Scenarios[index]
		if result.ScenarioID != sc.ScenarioID || !result.Stable || result.CurrentMismatch {
			return nil, fmt.Errorf("scenario ordering/status drift at %d", index)
		}
		javaPrimaryProcess := processes[processKey(sc.ScenarioID, "java", "primary")]
		javaReplayProcess := processes[processKey(sc.ScenarioID, "java", "replay")]
		rustPrimaryProcess := processes[processKey(sc.ScenarioID, "rust", "primary")]
		rustReplayProcess := processes[processKey(sc.ScenarioID, "rust", "replay")]
		if result.JavaPrimary != javaPrimaryProcess.NormalizedSHA256 || result.JavaReplay != javaReplayProcess.NormalizedSHA256 || result.RustPrimary != rustPrimaryProcess.NormalizedSHA256 || result.RustReplay != rustReplayProcess.NormalizedSHA256 || result.JavaPrimary != result.JavaReplay || result.RustPrimary != result.RustReplay {
			return nil, fmt.Errorf("scenario/process observation link drift %s", sc.ScenarioID)
		}
		javaObservation, rustObservation := result.JavaObservation, result.RustObservation
		if len(result.NormalizationAudits) != 4 {
			return nil, fmt.Errorf("normalization audit set invalid %s", sc.ScenarioID)
		}
		{
			traces := map[string]NormalizationTrace{}
			for _, trace := range result.NormalizationAudits {
				key := trace.Runtime + "|" + trace.Attempt
				if _, duplicate := traces[key]; duplicate {
					return nil, errors.New("duplicate normalization trace")
				}
				traces[key] = trace
			}
			jp, _, javaLoss, err := verifyTrace(sc, traces["java|primary"], javaPrimaryProcess)
			if err != nil {
				return nil, fmt.Errorf("%s Java primary: %w", sc.ScenarioID, err)
			}
			jr, _, _, err := verifyTrace(sc, traces["java|replay"], javaReplayProcess)
			if err != nil {
				return nil, fmt.Errorf("%s Java replay: %w", sc.ScenarioID, err)
			}
			rp, rustRaw, _, err := verifyTrace(sc, traces["rust|primary"], rustPrimaryProcess)
			if err != nil {
				return nil, fmt.Errorf("%s Rust primary: %w", sc.ScenarioID, err)
			}
			rr, _, _, err := verifyTrace(sc, traces["rust|replay"], rustReplayProcess)
			if err != nil {
				return nil, fmt.Errorf("%s Rust replay: %w", sc.ScenarioID, err)
			}
			if code, err := auditReplayNormalization(traces["java|primary"], traces["java|replay"]); err != nil {
				return nil, fmt.Errorf("%s Java %s: %w", sc.ScenarioID, code, err)
			}
			if code, err := auditReplayNormalization(traces["rust|primary"], traces["rust|replay"]); err != nil {
				return nil, fmt.Errorf("%s Rust %s: %w", sc.ScenarioID, code, err)
			}
			if !canonicalEqual(jp, jr) || !canonicalEqual(rp, rr) || !canonicalEqual(jp, result.JavaObservation) || !canonicalEqual(rp, result.RustObservation) || !canonicalEqual(javaLoss, result.JavaNormalizationLoss) || !canonicalEqual(rustRaw.Steps, result.RustStepDiagnostics) || digest(rustRaw.Bootstrap) != result.RustBootstrapSHA256 {
				return nil, fmt.Errorf("raw-to-normalized receipt drift %s", sc.ScenarioID)
			}
			javaObservation, rustObservation = jp, rp
		}
		javaDigest, err := normalizeDigest(javaObservation)
		if err != nil {
			return nil, err
		}
		rustDigest, err := normalizeDigest(rustObservation)
		if err != nil {
			return nil, err
		}
		neutral, err := neutralObservation(sc)
		if err != nil {
			return nil, err
		}
		neutralDigest, err := normalizeDigest(neutral)
		if err != nil {
			return nil, err
		}
		if javaDigest != result.JavaPrimary || rustDigest != result.RustPrimary || neutralDigest != result.NeutralExpected {
			return nil, fmt.Errorf("scenario observation digest drift %s", sc.ScenarioID)
		}
		classification, findings, adjudicationErr := adjudicateScenario(sc, hierarchy, javaObservation, rustObservation)
		if adjudicationErr != nil || classification != result.Classification {
			return nil, fmt.Errorf("scenario adjudication drift %s: %w", sc.ScenarioID, adjudicationErr)
		}
		if err := validateRustDerivedCounters(sc, result); err != nil {
			return nil, fmt.Errorf("Rust derived counters %s: %w", sc.ScenarioID, err)
		}
		findingsByScenario[sc.ScenarioID] = findings
	}
	return findingsByScenario, nil
}

func verifyCandidateProcesses(sc corpora.Scenario, attempt MinimizationAttempt, inputs []ArtifactIdentity) error {
	if len(attempt.Processes) != 4 || len(attempt.Audits) != 4 {
		return errors.New("fresh minimization attempt receipt set invalid")
	}
	processes := map[string]ProcessReceipt{}
	for _, process := range attempt.Processes {
		key := process.Runtime + "|" + strings.TrimSuffix(strings.TrimPrefix(process.Attempt, strings.Split(process.Attempt, "-")[0]+"-"), "")
		_ = key
		short := ""
		if strings.HasSuffix(process.Attempt, "-primary") {
			short = process.Runtime + "|primary"
		}
		if strings.HasSuffix(process.Attempt, "-replay") {
			short = process.Runtime + "|replay"
		}
		if short == "" || processes[short].PID != 0 || process.ScenarioID != sc.ScenarioID || process.PID <= 0 {
			return errors.New("minimization process key invalid")
		}
		processes[short] = process
	}
	inputByKind := map[string]ArtifactIdentity{}
	for _, input := range inputs {
		inputByKind[input.Kind] = input
	}
	traces := map[string]NormalizationTrace{}
	for _, trace := range attempt.Audits {
		traces[trace.Runtime+"|"+trace.Attempt] = trace
	}
	for _, runtimeName := range []string{"java", "rust"} {
		for _, name := range []string{"primary", "replay"} {
			process := processes[runtimeName+"|"+name]
			var stdin []byte
			var err error
			executable := inputByKind["rust-testee"]
			if runtimeName == "java" {
				stdin, err = corpora.OracleRequestLine(sc)
				stdin = append(stdin, '\n')
				executable = inputByKind["java-executable"]
			} else {
				stdin, err = encodeNeutralRequest(sc)
			}
			if err != nil || process.ExecutableSHA256 != executable.SHA256 || process.StdinSHA256 != digest(stdin) || process.StdinBytes != len(stdin) || !canonicalEqual(process.LaunchedInputs, expectedLaunchIdentities(runtimeName, inputs)) {
				return errors.New("minimization process source binding invalid")
			}
			trace := traces[runtimeName+"|"+process.Attempt]
			if _, _, _, err := verifyTrace(sc, trace, process); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyReproducer(reproducer PublicReproducer, original corpora.Scenario, record LedgerRecord, manifest Manifest, inputs []ArtifactIdentity) error {
	originalLine, err := original.CanonicalLine()
	if err != nil {
		return err
	}
	line, err := reproducer.Scenario.CanonicalLine()
	if err != nil {
		return err
	}
	// The repository root is directly recoverable from the fixed corpus path.
	root := filepath.Clean(filepath.Join(filepath.Dir(manifest.Inputs[0].Path), "../.."))
	if reproducer.LedgerDeltaID != record.DeltaID || reproducer.ScenarioID != original.ScenarioID || reproducer.Signature.Pointer != record.Pointer || reproducer.Signature.Classification != record.Classification || reproducer.OriginalScenarioSHA256 != digest(originalLine) || record.ReproducerSHA256 != reproducer.OriginalScenarioSHA256 || reproducer.ScenarioSHA256 != digest(line) || !reproducer.Irreducible || reproducer.CandidateAttempts <= 0 || !canonicalEqual(reproducer.RuntimeInputs, inputs) || validateReproducerCommand(reproducer.Command, root, filepath.Join(root, "evidence/differential/manifest.json"), reproducer.ReproducerID) != nil || reproducer.RepositoryAnchor != manifest.RepositoryAnchor || reproducer.FindingJavaObservation != record.JavaObservation || reproducer.FindingRustObservation != record.RustObservation || reproducer.FindingRunAnchor != record.FindingRunAnchor || reproducer.ClosingRunAnchor != record.ClosingRunAnchor || reproducer.ClosingJavaObservation != record.ClosingJavaObservation || reproducer.ClosingRustObservation != record.ClosingRustObservation {
		return errors.New("reproducer/ledger binding invalid")
	}
	if reproducer.Mode == "FRESH_BOUNDED_MINIMIZATION" {
		if !reproducer.CurrentlyReproduces || reproducer.ProofScope != "FRESH_RUNTIME_DIFFERENCE" || len(reproducer.Attempts) != reproducer.CandidateAttempts+1 {
			return errors.New("fresh minimization envelope invalid")
		}
		seenFinal := false
		flattened := []ProcessReceipt{}
		for _, attempt := range reproducer.Attempts {
			attemptLine, err := attempt.Scenario.CanonicalLine()
			if err != nil || digest(attemptLine) != attempt.ScenarioSHA256 || attempt.EvidenceStatus != "FRESH_RUNTIME_OBSERVATION" {
				return errors.New("fresh minimization attempt invalid")
			}
			if err := verifyCandidateProcesses(attempt.Scenario, attempt, inputs); err != nil {
				return err
			}
			flattened = append(flattened, attempt.Processes...)
			if attempt.ScenarioSHA256 == reproducer.ScenarioSHA256 && attempt.Reproduced && attempt.Signature == reproducer.Signature {
				seenFinal = true
			}
		}
		if !seenFinal || !canonicalEqual(flattened, reproducer.Processes) {
			return errors.New("fresh minimization transcript link invalid")
		}
		for index := range reproducer.Scenario.Core.Steps {
			candidate := reproducer.Scenario
			candidate.Core.Steps = append([]corpora.Step(nil), reproducer.Scenario.Core.Steps[:index]...)
			candidate.Core.Steps = append(candidate.Core.Steps, reproducer.Scenario.Core.Steps[index+1:]...)
			candidateLine, _ := candidate.CanonicalLine()
			candidateSHA := digest(candidateLine)
			disproved := false
			for _, attempt := range reproducer.Attempts {
				if attempt.ScenarioSHA256 == candidateSHA && !attempt.Reproduced {
					disproved = true
					break
				}
			}
			if !disproved {
				return errors.New("minimized scenario lacks one-step irreducibility proof")
			}
		}
	} else if reproducer.Mode == "HISTORICAL_CLOSED_IDENTITY_WITNESS" {
		if reproducer.CurrentlyReproduces || reproducer.ProofScope != "RETAINED_HISTORICAL_OBSERVATION_IDENTITY" || reproducer.ScenarioSHA256 != reproducer.OriginalScenarioSHA256 || len(reproducer.Processes) != 0 || len(reproducer.Attempts) != len(original.Core.Steps)+1 || reproducer.CandidateAttempts != len(original.Core.Steps) {
			return errors.New("historical witness envelope invalid")
		}
		if !reproducer.Attempts[0].Reproduced || reproducer.Attempts[0].Signature != reproducer.Signature || reproducer.Attempts[0].EvidenceStatus != "RETAINED_HISTORICAL_FINDING_OBSERVATIONS" {
			return errors.New("historical finding witness absent")
		}
		for index := range original.Core.Steps {
			candidate := original
			candidate.Core.Steps = append([]corpora.Step(nil), original.Core.Steps[:index]...)
			candidate.Core.Steps = append(candidate.Core.Steps, original.Core.Steps[index+1:]...)
			candidateLine, _ := candidate.CanonicalLine()
			attempt := reproducer.Attempts[index+1]
			if attempt.ScenarioSHA256 != digest(candidateLine) || attempt.Reproduced || attempt.EvidenceStatus != "NO_RETAINED_HISTORICAL_FINDING_OBSERVATION" || len(attempt.Processes) != 0 || len(attempt.Audits) != 0 {
				return errors.New("historical bounded identity witness invalid")
			}
		}
	} else {
		return errors.New("unknown reproducer proof mode")
	}
	return nil
}

func verifyLedgerClosure(manifest Manifest, ledger Ledger, scenarios []corpora.Scenario, hierarchy OracleHierarchy, findings map[string][]AdjudicatedFinding, inputs []ArtifactIdentity) error {
	if ledger.Head != manifest.Ledger.PostHead || len(ledger.Records)+len(ledger.MigratedV1Records) != manifest.Ledger.Records || !validLedgerDigest(manifest.Ledger.PreHead) {
		return errors.New("ledger binding drift")
	}
	scenarioByID := map[string]corpora.Scenario{}
	resultByID := map[string]ScenarioResult{}
	for index, sc := range scenarios {
		scenarioByID[sc.ScenarioID] = sc
		resultByID[sc.ScenarioID] = manifest.Scenarios[index]
	}
	expected := map[string]bool{}
	for scenarioID, scenarioFindings := range findings {
		for _, finding := range scenarioFindings {
			expected[deltaIDFor(scenarioID, finding.Pointer)] = true
		}
	}
	for scenarioID, defects := range retainedDefects {
		for _, defect := range defects {
			expected[deltaIDFor(scenarioID, defect.Pointer)] = true
		}
	}
	if len(ledger.Records) != len(expected) {
		return fmt.Errorf("ledger exact record set drift got=%d want=%d", len(ledger.Records), len(expected))
	}
	reproducerByDelta := map[string]PublicReproducer{}
	for _, reproducer := range manifest.Reproducers {
		if reproducerByDelta[reproducer.LedgerDeltaID].ReproducerID != "" {
			return errors.New("duplicate reproducer delta link")
		}
		reproducerByDelta[reproducer.LedgerDeltaID] = reproducer
	}
	if len(reproducerByDelta) != len(expected) {
		return errors.New("reproducer exact set drift")
	}
	for _, record := range ledger.Records {
		if !expected[record.DeltaID] {
			return fmt.Errorf("unreviewed ledger record %s", record.DeltaID)
		}
		scenario := scenarioByID[record.ScenarioID]
		result := resultByID[record.ScenarioID]
		var decision *OracleCell
		for index := range hierarchy.Cells {
			cell := &hierarchy.Cells[index]
			if cell.ScenarioID == record.ScenarioID && cell.Pointer == record.Pointer {
				decision = cell
				break
			}
		}
		if decision == nil || !canonicalEqual(record.Decision, *decision) {
			return fmt.Errorf("ledger decision drift %s", record.DeltaID)
		}
		if record.Classification == "java_quirk" {
			if record.JavaObservation != result.JavaPrimary || record.RustObservation != result.RustPrimary || record.Resolution != "retained_java_quirk" {
				return fmt.Errorf("Java quirk record link drift %s", record.DeltaID)
			}
		} else {
			matched := false
			for _, defect := range retainedDefects[record.ScenarioID] {
				if defect.Pointer == record.Pointer && defect.JavaObservation == record.JavaObservation && defect.RustObservation == record.RustObservation && defect.FindingAnchor == record.FindingRunAnchor {
					matched = true
					break
				}
			}
			// The append-only ledger retains the first execution that proved the
			// defect closed. A later confirming run must bind the same current
			// observations without rewriting that historical closing anchor.
			if !matched || record.ClosingJavaObservation != result.JavaPrimary || record.ClosingRustObservation != result.RustPrimary || !validLedgerAnchor(record.ClosingRunAnchor) {
				return fmt.Errorf("remediated defect record link drift %s", record.DeltaID)
			}
		}
		if err := verifyReproducer(reproducerByDelta[record.DeltaID], scenario, record, manifest, inputs); err != nil {
			return fmt.Errorf("%s: %w", record.DeltaID, err)
		}
	}
	return nil
}

// VerifyPublicDifferential independently validates a committed receipt.
func VerifyPublicDifferential(repositoryRoot string, receiptBytes []byte) error {
	if repositoryRoot == "" || !filepath.IsAbs(repositoryRoot) || filepath.Clean(repositoryRoot) != repositoryRoot {
		return errors.New("repository root must be absolute and clean")
	}
	if len(receiptBytes) == 0 || int64(len(receiptBytes)) > maximumDocumentBytes {
		return errors.New("receipt is empty or oversized")
	}
	if err := compileAndValidateSchema(filepath.Join(repositoryRoot, "schemas/differential-evidence-1.0.0.schema.json"), receiptBytes); err != nil {
		return fmt.Errorf("evidence schema: %w", err)
	}
	if err := verifyManifestValue(repositoryRoot, receiptBytes); err != nil {
		return err
	}
	var manifest Manifest
	if err := decodeStrict(receiptBytes, &manifest); err != nil {
		return err
	}
	_, inputs, err := configFromManifestInputs(repositoryRoot, manifest)
	if err != nil {
		return err
	}
	if err := validateExecutionAnchor(repositoryRoot, manifest.RepositoryAnchor, inputs); err != nil {
		return err
	}
	scenarios, _, err := loadPublicCorpus(repositoryRoot, filepath.Join(repositoryRoot, "corpora/public/scenarios.jsonl"))
	if err != nil {
		return err
	}
	hierarchyRaw, err := readRegularBounded(filepath.Join(repositoryRoot, "evidence/oracle-hierarchy.json"), maximumDocumentBytes)
	if err != nil {
		return err
	}
	var hierarchy OracleHierarchy
	if err := decodeStrict(hierarchyRaw, &hierarchy); err != nil {
		return err
	}
	if err := ValidateOracleHierarchy(scenarios, hierarchy); err != nil {
		return err
	}
	wantControls, err := runSeededControls()
	if err != nil || !canonicalEqual(manifest.Controls, wantControls) {
		return errors.New("control set/rederivation drift")
	}
	wantCoverage, err := buildCoverage(repositoryRoot, scenarios)
	if err != nil {
		return err
	}
	if !canonicalEqual(manifest.Coverage, wantCoverage) {
		leftRaw, _ := canonical(manifest.Coverage)
		rightRaw, _ := canonical(wantCoverage)
		var left, right any
		_ = json.Unmarshal(leftRaw, &left)
		_ = json.Unmarshal(rightRaw, &right)
		return fmt.Errorf("coverage mapping/source/identity drift at %s", firstJSONDifference(left, right, ""))
	}
	processes, err := verifyProcessMatrix(manifest, scenarios, inputs)
	if err != nil {
		return err
	}
	findings, err := verifyScenarioMatrix(manifest, scenarios, hierarchy, processes)
	if err != nil {
		return err
	}
	ledgerRaw, err := readVerificationLedger(filepath.Join(repositoryRoot, "evidence/java/behavior-delta-ledger.json"), maximumDocumentBytes)
	if err != nil {
		return err
	}
	ledger, err := migrateLedger(ledgerRaw)
	if err != nil {
		return err
	}
	if err := verifyLedgerClosure(manifest, ledger, scenarios, hierarchy, findings, inputs); err != nil {
		return err
	}
	preHeadKnown := manifest.Ledger.PreHead == "sha256:"+strings.Repeat("0", 64) || manifest.Ledger.PreHead == ledger.Head
	for _, record := range ledger.Records {
		if record.RecordDigest == manifest.Ledger.PreHead {
			preHeadKnown = true
			break
		}
	}
	if !preHeadKnown {
		return errors.New("ledger pre-head is not a chain boundary")
	}
	wantCounts := CountsReceipt{Scenarios: len(scenarios), JavaPrimary: len(scenarios), JavaReplay: len(scenarios), RustPrimary: len(scenarios), RustReplay: len(scenarios), Processes: len(processes)}
	if !canonicalEqual(manifest.Counts, wantCounts) {
		return errors.New("manifest counts do not rederive")
	}
	return nil
}
