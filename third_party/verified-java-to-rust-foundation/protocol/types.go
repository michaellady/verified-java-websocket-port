// Package protocol defines the Java-to-Rust assurance protocol's transport
// types. It deliberately does not choose oracles or make assurance judgments;
// those enter the kernel as explicit policy and evidence fields.
package protocol

import "time"

const SchemaVersion = "1.0.0"

type Disposition string

const (
	Retry               Disposition = "RETRY"
	DegradeNonAssurance Disposition = "DEGRADE_NON_ASSURANCE"
	Block               Disposition = "BLOCK"
	Invalidate          Disposition = "INVALIDATE"
	Quarantine          Disposition = "QUARANTINE"
	Revoke              Disposition = "REVOKE"
)

type Finding struct {
	Code        string      `json:"code"`
	Disposition Disposition `json:"disposition"`
	Path        string      `json:"path"`
	Message     string      `json:"message"`
}

type Policy struct {
	Version                        string              `json:"version"`
	Company                        string              `json:"company"`
	Project                        string              `json:"project"`
	AllowedNodeKinds               []string            `json:"allowed_node_kinds"`
	AllowedEdgeKinds               []string            `json:"allowed_edge_kinds"`
	TransientErrorTypes            []string            `json:"transient_error_types"`
	SemanticErrorTypes             []string            `json:"semantic_error_types"`
	SecurityErrorTypes             []string            `json:"security_error_types"`
	IntegrityErrorTypes            []string            `json:"integrity_error_types"`
	LSPErrorTypes                  []string            `json:"lsp_error_types"`
	IncompatibleRoles              map[string][]string `json:"incompatible_roles"`
	RequiredStages                 []string            `json:"required_stages"`
	RequiredAttestationRoles       []string            `json:"required_attestation_roles"`
	ActionRoles                    map[string][]string `json:"action_roles"`
	AllowedSnapshotTransitions     map[string][]string `json:"allowed_snapshot_transitions"`
	MaximumAuthorizationAgeSeconds int                 `json:"maximum_authorization_age_seconds"`
	MaximumAttemptsPerStage        int                 `json:"maximum_attempts_per_stage"`
	MaximumBackoffSeconds          int                 `json:"maximum_backoff_seconds"`
}

type Bundle struct {
	SchemaVersion string            `json:"schema_version"`
	Company       string            `json:"company"`
	Project       string            `json:"project"`
	VerifiedAt    time.Time         `json:"verified_at"`
	Snapshot      Snapshot          `json:"snapshot"`
	RootNodeID    string            `json:"root_node_id"`
	Nodes         []Node            `json:"nodes"`
	Edges         []Edge            `json:"edges"`
	Stages        []Stage           `json:"stages"`
	Attempts      []Attempt         `json:"attempts"`
	Failures      []FailureEnvelope `json:"failures"`
	Authorization Authorization     `json:"authorization"`
	Attestations  []Attestation     `json:"attestations"`
	Publication   PublicationPlan   `json:"publication"`
}

type Snapshot struct {
	ID              string `json:"id"`
	CandidateDigest string `json:"candidate_digest"`
	PreviousState   string `json:"previous_state"`
	State           string `json:"state"`
	Stale           bool   `json:"stale"`
	Supersedes      string `json:"supersedes,omitempty"`
}

type Node struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"`
	Digest            string `json:"digest"`
	ContentBase64     string `json:"content_base64"`
	Classification    string `json:"classification"`
	Stale             bool   `json:"stale"`
	Contradictory     bool   `json:"contradictory"`
	Migrated          bool   `json:"migrated"`
	MigrationLossless bool   `json:"migration_lossless"`
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type RetryPolicy struct {
	MaximumAttempts int           `json:"maximum_attempts"`
	InitialBackoff  time.Duration `json:"initial_backoff"`
	MaximumBackoff  time.Duration `json:"maximum_backoff"`
}

type Stage struct {
	ID             string      `json:"id"`
	SnapshotID     string      `json:"snapshot_id"`
	IdempotencyKey string      `json:"idempotency_key"`
	Inputs         []string    `json:"inputs"`
	Outputs        []string    `json:"outputs"`
	LeaseSeconds   int         `json:"lease_seconds"`
	LeaseExpiresAt time.Time   `json:"lease_expires_at,omitempty"`
	Retry          RetryPolicy `json:"retry"`
	State          string      `json:"state"`
	RequiredRoles  []string    `json:"required_roles"`
}

type Attempt struct {
	ID                    string      `json:"id"`
	StageID               string      `json:"stage_id"`
	SnapshotID            string      `json:"snapshot_id"`
	Ordinal               int         `json:"ordinal"`
	ActorID               string      `json:"actor_id"`
	Role                  string      `json:"role"`
	RunID                 string      `json:"run_id"`
	StartedAt             time.Time   `json:"started_at"`
	FinishedAt            time.Time   `json:"finished_at"`
	Outcome               string      `json:"outcome"`
	ErrorType             string      `json:"error_type,omitempty"`
	Disposition           Disposition `json:"disposition,omitempty"`
	FailureID             string      `json:"failure_id,omitempty"`
	QueryBudgetConsumed   int         `json:"query_budget_consumed"`
	SecurityFindingIDs    []string    `json:"security_finding_ids"`
	ReviewerInterventions []string    `json:"reviewer_interventions"`
}

type FailureEnvelope struct {
	ID                    string      `json:"failure_id"`
	AttemptID             string      `json:"attempt_id"`
	StageID               string      `json:"stage_id"`
	SnapshotID            string      `json:"snapshot_id"`
	ErrorType             string      `json:"error_type"`
	Phase                 string      `json:"phase"`
	Codepath              string      `json:"codepath"`
	Severity              string      `json:"severity"`
	Retryability          string      `json:"retryability"`
	Disposition           Disposition `json:"disposition"`
	AffectedClaimIDs      []string    `json:"affected_claim_ids"`
	AffectedArtifactIDs   []string    `json:"affected_artifact_ids"`
	ActorID               string      `json:"actor_id"`
	Role                  string      `json:"role"`
	RunID                 string      `json:"run_id"`
	SafeMessage           string      `json:"safe_message"`
	CauseChain            []string    `json:"cause_chain"`
	DiagnosticArtifactID  string      `json:"diagnostic_artifact_id"`
	OccurredAt            time.Time   `json:"occurred_at"`
	QueryBudgetConsumed   int         `json:"query_budget_consumed"`
	SecurityFindingIDs    []string    `json:"security_finding_ids"`
	ReviewerInterventions []string    `json:"reviewer_interventions"`
}

type Authorization struct {
	ActorID           string    `json:"actor_id"`
	Role              string    `json:"role"`
	SnapshotRoles     []string  `json:"snapshot_roles"`
	SnapshotDigest    string    `json:"snapshot_digest"`
	PolicyVersion     string    `json:"policy_version"`
	Nonce             string    `json:"nonce"`
	PriorNonces       []string  `json:"prior_nonces"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	SignatureVerified bool      `json:"signature_verified"`
	Revoked           bool      `json:"revoked"`
	CommandID         string    `json:"command_id,omitempty"`
	Action            string    `json:"action,omitempty"`
	StageID           string    `json:"stage_id,omitempty"`
	IntentDigest      string    `json:"intent_digest,omitempty"`
}

type Attestation struct {
	ID             string `json:"id"`
	ActorID        string `json:"actor_id"`
	Role           string `json:"role"`
	SnapshotDigest string `json:"snapshot_digest"`
	Independent    bool   `json:"independent"`
}

type PublicationPlan struct {
	Requested      bool     `json:"requested"`
	Complete       bool     `json:"complete"`
	Classification string   `json:"classification"`
	ObjectDigests  []string `json:"object_digests"`
	ReplayCommand  string   `json:"replay_command"`
}

type Checkpoint struct {
	SchemaVersion string    `json:"schema_version"`
	StateDigest   string    `json:"state_digest"`
	CreatedAt     time.Time `json:"created_at"`
	State         RunState  `json:"state"`
}

type RunState struct {
	SchemaVersion           string                   `json:"schema_version"`
	SnapshotID              string                   `json:"snapshot_id"`
	SnapshotDigest          string                   `json:"snapshot_digest"`
	Status                  string                   `json:"status"`
	Stages                  []Stage                  `json:"stages"`
	Attempts                []Attempt                `json:"attempts"`
	Failures                []FailureEnvelope        `json:"failures"`
	CompletedOutputs        []string                 `json:"completed_outputs"`
	AppliedCommands         map[string]string        `json:"applied_commands"`
	ConsumedNonces          []string                 `json:"consumed_nonces"`
	CheckpointVerifications []CheckpointVerification `json:"checkpoint_verifications"`
	VerifiedCheckpoint      string                   `json:"verified_checkpoint,omitempty"`
	VerifiedByCommandID     string                   `json:"verified_by_command_id,omitempty"`
	VerifiedByNonce         string                   `json:"verified_by_nonce,omitempty"`
	CancelledAt             *time.Time               `json:"cancelled_at,omitempty"`
	SupersededBy            string                   `json:"superseded_by,omitempty"`
	PromotedDigest          string                   `json:"promoted_digest,omitempty"`
	Verification            VerificationReceipt      `json:"verification"`
}

type CheckpointVerification struct {
	Command                    Command             `json:"command"`
	PreVerificationStateDigest string              `json:"pre_verification_state_digest"`
	Verification               VerificationReceipt `json:"verification"`
}

type Verifier func(Bundle, Policy) []Finding

type NamedVerifier struct {
	ID     string
	Verify Verifier
}

type VerificationReceipt struct {
	BundleDigest    string   `json:"bundle_digest"`
	PolicyDigest    string   `json:"policy_digest"`
	VerifierIDs     []string `json:"verifier_ids"`
	AgreementDigest string   `json:"agreement_digest"`
}

type Command struct {
	ID                    string        `json:"id"`
	Kind                  string        `json:"kind"`
	SnapshotID            string        `json:"snapshot_id"`
	StageID               string        `json:"stage_id,omitempty"`
	IdempotencyKey        string        `json:"idempotency_key,omitempty"`
	AttemptID             string        `json:"attempt_id,omitempty"`
	RunID                 string        `json:"run_id,omitempty"`
	Outcome               string        `json:"outcome,omitempty"`
	ErrorType             string        `json:"error_type,omitempty"`
	SafeMessage           string        `json:"safe_message,omitempty"`
	CauseChain            []string      `json:"cause_chain,omitempty"`
	Codepath              string        `json:"codepath,omitempty"`
	Severity              string        `json:"severity,omitempty"`
	DiagnosticArtifactID  string        `json:"diagnostic_artifact_id,omitempty"`
	AffectedClaimIDs      []string      `json:"affected_claim_ids,omitempty"`
	AffectedArtifactIDs   []string      `json:"affected_artifact_ids,omitempty"`
	Authorization         Authorization `json:"authorization"`
	OccurredAt            time.Time     `json:"occurred_at"`
	SupersededBy          string        `json:"superseded_by,omitempty"`
	CheckpointDigest      string        `json:"checkpoint_digest,omitempty"`
	QueryBudgetConsumed   int           `json:"query_budget_consumed,omitempty"`
	SecurityFindingIDs    []string      `json:"security_finding_ids,omitempty"`
	ReviewerInterventions []string      `json:"reviewer_interventions,omitempty"`
}

type Decision struct {
	Disposition Disposition   `json:"disposition,omitempty"`
	RetryAfter  time.Duration `json:"retry_after,omitempty"`
	Finding     *Finding      `json:"finding,omitempty"`
}
