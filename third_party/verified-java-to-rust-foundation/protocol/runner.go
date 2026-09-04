package protocol

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"
)

var (
	ErrInvalidCommand       = errors.New("invalid protocol command")
	ErrCheckpointMismatch   = errors.New("checkpoint digest mismatch")
	ErrTerminalRun          = errors.New("run is cancelled, superseded, blocked, quarantined, or promoted")
	ErrVerificationRejected = errors.New("independent verifier agreement rejected the bundle")
)

type Clock func() time.Time

type Runner struct {
	mu       sync.Mutex
	policy   Policy
	promoter TransactionalPromoter
	clock    Clock
	state    RunState
}

func NewRunner(bundle Bundle, policy Policy, promoter TransactionalPromoter, clock Clock, verifiers ...NamedVerifier) (*Runner, error) {
	if bundle.Snapshot.ID == "" || bundle.Snapshot.CandidateDigest == "" {
		return nil, fmt.Errorf("%w: snapshot identity is required", ErrInvalidCommand)
	}
	if clock == nil {
		clock = time.Now
	}
	receipt, err := VerifyCandidate(bundle, policy, verifiers...)
	if err != nil {
		return nil, err
	}
	stages := append([]Stage(nil), bundle.Stages...)
	for index := range stages {
		stages[index].State = "PENDING"
		stages[index].LeaseExpiresAt = time.Time{}
	}
	return &Runner{
		policy:   policy,
		promoter: promoter,
		clock:    clock,
		state: RunState{
			SchemaVersion:           SchemaVersion,
			SnapshotID:              bundle.Snapshot.ID,
			SnapshotDigest:          bundle.Snapshot.CandidateDigest,
			Status:                  "RUNNING",
			Stages:                  stages,
			Attempts:                []Attempt{},
			Failures:                []FailureEnvelope{},
			CompletedOutputs:        []string{},
			AppliedCommands:         map[string]string{},
			ConsumedNonces:          []string{},
			CheckpointVerifications: []CheckpointVerification{},
			Verification:            receipt,
		},
	}, nil
}

func Resume(checkpoint Checkpoint, bundle Bundle, policy Policy, promoter TransactionalPromoter, clock Clock, verifiers ...NamedVerifier) (*Runner, error) {
	if checkpoint.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported checkpoint schema", ErrCheckpointMismatch)
	}
	digest, err := stateDigest(checkpoint.State)
	if err != nil || checkpoint.StateDigest != digest {
		return nil, ErrCheckpointMismatch
	}
	if clock == nil {
		clock = time.Now
	}
	state, err := cloneState(checkpoint.State)
	if err != nil {
		return nil, err
	}
	freshReceipt, err := VerifyCandidate(bundle, policy, verifiers...)
	if err != nil || bundle.Snapshot.ID != state.SnapshotID || bundle.Snapshot.CandidateDigest != state.SnapshotDigest || !sameVerificationReceipt(freshReceipt, state.Verification) {
		return nil, fmt.Errorf("%w: checkpoint is not bound to freshly verified bundle bytes", ErrVerificationRejected)
	}
	if err := validateResumedState(state, bundle); err != nil {
		return nil, err
	}
	if err := validateReceipt(state.Verification, policy); err != nil {
		return nil, err
	}
	if err := validateCheckpointVerifications(state, policy, clock().UTC()); err != nil {
		return nil, err
	}
	return &Runner{policy: policy, promoter: promoter, clock: clock, state: state}, nil
}

func VerifyCandidate(bundle Bundle, policy Policy, verifiers ...NamedVerifier) (VerificationReceipt, error) {
	if len(verifiers) < 2 {
		return VerificationReceipt{}, fmt.Errorf("%w: two named verifier implementations are required", ErrVerificationRejected)
	}
	ids := make([]string, 0, len(verifiers))
	seen := make(map[string]bool, len(verifiers))
	implementations := make(map[uintptr]bool, len(verifiers))
	var agreed []Finding
	for index, verifier := range verifiers {
		implementation := uintptr(0)
		if verifier.Verify != nil {
			implementation = reflect.ValueOf(verifier.Verify).Pointer()
		}
		if verifier.ID == "" || verifier.Verify == nil || seen[verifier.ID] || implementations[implementation] {
			return VerificationReceipt{}, fmt.Errorf("%w: verifier identities must be unique and callable", ErrVerificationRejected)
		}
		seen[verifier.ID] = true
		implementations[implementation] = true
		ids = append(ids, verifier.ID)
		findings := NormalizeFindings(verifier.Verify(bundle, policy))
		if index == 0 {
			agreed = findings
			continue
		}
		left, _ := CanonicalJSON(agreed)
		right, _ := CanonicalJSON(findings)
		if string(left) != string(right) {
			return VerificationReceipt{}, fmt.Errorf("%w: verifier findings disagree", ErrVerificationRejected)
		}
	}
	if len(agreed) != 0 {
		return VerificationReceipt{}, fmt.Errorf("%w: %s/%s", ErrVerificationRejected, agreed[0].Code, agreed[0].Disposition)
	}
	sort.Strings(ids)
	bundleDigest, err := Digest(bundle)
	if err != nil {
		return VerificationReceipt{}, err
	}
	policyDigest, err := Digest(policy)
	if err != nil {
		return VerificationReceipt{}, err
	}
	agreementDigest, err := receiptAgreementDigest(bundleDigest, policyDigest, ids)
	if err != nil {
		return VerificationReceipt{}, err
	}
	return VerificationReceipt{BundleDigest: bundleDigest, PolicyDigest: policyDigest, VerifierIDs: ids, AgreementDigest: agreementDigest}, nil
}

func validateReceipt(receipt VerificationReceipt, policy Policy) error {
	policyDigest, err := Digest(policy)
	if err != nil || receipt.PolicyDigest != policyDigest || len(receipt.VerifierIDs) < 2 || !validDigest(receipt.BundleDigest) || !validDigest(receipt.AgreementDigest) {
		return fmt.Errorf("%w: checkpoint verification receipt is invalid", ErrVerificationRejected)
	}
	for index, id := range receipt.VerifierIDs {
		if id == "" || (index > 0 && receipt.VerifierIDs[index-1] >= id) {
			return fmt.Errorf("%w: verifier receipt identities are not unique and sorted", ErrVerificationRejected)
		}
	}
	expected, err := receiptAgreementDigest(receipt.BundleDigest, receipt.PolicyDigest, receipt.VerifierIDs)
	if err != nil || expected != receipt.AgreementDigest {
		return fmt.Errorf("%w: verifier receipt agreement digest is invalid", ErrVerificationRejected)
	}
	return nil
}

func receiptAgreementDigest(bundleDigest, policyDigest string, verifierIDs []string) (string, error) {
	return Digest(struct {
		BundleDigest string    `json:"bundle_digest"`
		PolicyDigest string    `json:"policy_digest"`
		VerifierIDs  []string  `json:"verifier_ids"`
		Findings     []Finding `json:"findings"`
	}{bundleDigest, policyDigest, verifierIDs, []Finding{}})
}

func sameVerificationReceipt(left, right VerificationReceipt) bool {
	return left.BundleDigest == right.BundleDigest && left.PolicyDigest == right.PolicyDigest && left.AgreementDigest == right.AgreementDigest && SameStrings(left.VerifierIDs, right.VerifierIDs)
}

func (value *Runner) State() RunState {
	value.mu.Lock()
	defer value.mu.Unlock()
	state, _ := cloneState(value.state)
	return state
}

func (value *Runner) Checkpoint() (Checkpoint, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	state, err := cloneState(value.state)
	if err != nil {
		return Checkpoint{}, err
	}
	digest, err := stateDigest(state)
	if err != nil {
		return Checkpoint{}, err
	}
	return Checkpoint{SchemaVersion: SchemaVersion, StateDigest: digest, CreatedAt: value.clock().UTC(), State: state}, nil
}

func (value *Runner) Apply(ctx context.Context, command Command) (Decision, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	if command.ID == "" || command.Kind == "" || command.SnapshotID != value.state.SnapshotID {
		return Decision{}, fmt.Errorf("%w: command identity or snapshot binding", ErrInvalidCommand)
	}
	commandDigest, err := Digest(command)
	if err != nil {
		return Decision{}, err
	}
	if prior, exists := value.state.AppliedCommands[command.ID]; exists {
		if prior != commandDigest {
			return Decision{}, fmt.Errorf("%w: command ID replayed with different bytes", ErrInvalidCommand)
		}
		return value.replayedDecision(command), nil
	}
	next, err := cloneState(value.state)
	if err != nil {
		return Decision{}, err
	}
	if command.OccurredAt.IsZero() || command.OccurredAt.After(value.clock().UTC()) {
		return Decision{}, fmt.Errorf("%w: command timestamp is zero or in the future", ErrInvalidCommand)
	}
	if err := value.validateCommandAuthorization(&next, command); err != nil {
		return Decision{}, err
	}
	decision, err := value.applyTo(ctx, &next, command)
	if err != nil {
		return Decision{}, err
	}
	next.AppliedCommands[command.ID] = commandDigest
	next.ConsumedNonces = appendUnique(next.ConsumedNonces, command.Authorization.Nonce)
	value.state = next
	return decision, nil
}

func (value *Runner) validateCommandAuthorization(state *RunState, command Command) error {
	if !validCommandAuthorization(value.policy, *state, command, false) {
		return fmt.Errorf("%w: command authorization is invalid, replayed, revoked, or role-conflicted", ErrInvalidCommand)
	}
	return nil
}

func validCommandAuthorization(policy Policy, state RunState, command Command, requireConsumedNonce bool) bool {
	auth := command.Authorization
	roles := policy.ActionRoles[command.Kind+":"+command.StageID]
	valid := auth.CommandID == command.ID && auth.Action == command.Kind && auth.StageID == command.StageID
	valid = valid && auth.ActorID != "" && Contains(roles, auth.Role) && auth.SnapshotDigest == state.SnapshotDigest
	valid = valid && Contains(auth.SnapshotRoles, auth.Role)
	for _, role := range auth.SnapshotRoles {
		for _, incompatible := range policy.IncompatibleRoles[role] {
			if Contains(auth.SnapshotRoles, incompatible) {
				valid = false
			}
		}
	}
	intentDigest, intentErr := CommandIntentDigest(command)
	valid = valid && intentErr == nil && auth.IntentDigest == intentDigest
	valid = valid && auth.PolicyVersion == policy.Version && auth.SignatureVerified && !auth.Revoked
	nonceConsumed := Contains(state.ConsumedNonces, auth.Nonce)
	valid = valid && auth.Nonce == command.ID && !Contains(auth.PriorNonces, auth.Nonce) && nonceConsumed == requireConsumedNonce
	valid = valid && !auth.IssuedAt.IsZero() && !auth.ExpiresAt.IsZero() && !command.OccurredAt.Before(auth.IssuedAt) && !command.OccurredAt.After(auth.ExpiresAt)
	valid = valid && auth.ExpiresAt.Sub(auth.IssuedAt) <= time.Duration(policy.MaximumAuthorizationAgeSeconds)*time.Second
	return valid
}

// CommandIntentDigest binds every action field while excluding only the
// separately verified authorization envelope and its signature metadata.
func CommandIntentDigest(command Command) (string, error) {
	command.Authorization = Authorization{}
	return Digest(command)
}

func (value *Runner) applyTo(ctx context.Context, state *RunState, command Command) (Decision, error) {
	switch command.Kind {
	case "START_STAGE":
		return value.startStage(state, command)
	case "COMPLETE_ATTEMPT":
		return value.completeAttempt(state, command)
	case "CANCEL":
		return value.cancel(state, command)
	case "SUPERSEDE":
		return value.supersede(state, command)
	case "AUTHORIZE_RETRY":
		return value.authorizeRetry(state, command)
	case "VERIFY_CHECKPOINT":
		return value.verifyCheckpoint(state, command)
	case "PROMOTE":
		return value.promote(ctx, state, command)
	default:
		return Decision{}, fmt.Errorf("%w: unknown kind %q", ErrInvalidCommand, command.Kind)
	}
}

func (value *Runner) startStage(state *RunState, command Command) (Decision, error) {
	if state.Status != "RUNNING" {
		return Decision{}, ErrTerminalRun
	}
	stage, err := findStage(state, command.StageID)
	if err != nil {
		return Decision{}, err
	}
	if command.IdempotencyKey == "" || command.IdempotencyKey != stage.IdempotencyKey {
		return Decision{}, fmt.Errorf("%w: stage idempotency key mismatch", ErrInvalidCommand)
	}
	if stage.State == "RUNNING" || stage.State == "SUCCEEDED" || stage.State == "DEGRADED" {
		return Decision{}, nil
	}
	for _, input := range stage.Inputs {
		if !Contains(state.CompletedOutputs, input) {
			return Decision{}, fmt.Errorf("%w: stage %s input %s is not verified", ErrInvalidCommand, stage.ID, input)
		}
	}
	if stage.LeaseSeconds <= 0 || stage.LeaseSeconds > 300 {
		return Decision{}, fmt.Errorf("%w: stage lease must be between 1 and 300 seconds", ErrInvalidCommand)
	}
	stage.State = "RUNNING"
	stage.LeaseExpiresAt = command.OccurredAt.Add(time.Duration(stage.LeaseSeconds) * time.Second)
	return Decision{}, nil
}

func (value *Runner) completeAttempt(state *RunState, command Command) (Decision, error) {
	if state.Status != "RUNNING" {
		return Decision{}, ErrTerminalRun
	}
	stage, err := findStage(state, command.StageID)
	if err != nil {
		return Decision{}, err
	}
	if stage.State != "RUNNING" || command.AttemptID == "" {
		return Decision{}, fmt.Errorf("%w: stage is not running or attempt ID is empty", ErrInvalidCommand)
	}
	for _, attempt := range state.Attempts {
		if attempt.ID == command.AttemptID {
			return Decision{}, fmt.Errorf("%w: attempt ID is immutable", ErrInvalidCommand)
		}
	}
	ordinal := 1
	for _, attempt := range state.Attempts {
		if attempt.StageID == stage.ID && attempt.Ordinal >= ordinal {
			ordinal = attempt.Ordinal + 1
		}
	}
	if ordinal > stage.Retry.MaximumAttempts || ordinal > value.policy.MaximumAttemptsPerStage {
		return Decision{}, fmt.Errorf("%w: attempt bound exceeded", ErrInvalidCommand)
	}
	startedAt := stage.LeaseExpiresAt.Add(-time.Duration(stage.LeaseSeconds) * time.Second)
	if command.OccurredAt.Before(startedAt) {
		return Decision{}, fmt.Errorf("%w: attempt finishes before its lease starts", ErrInvalidCommand)
	}
	attempt := Attempt{
		ID: command.AttemptID, StageID: stage.ID, SnapshotID: state.SnapshotID, Ordinal: ordinal,
		ActorID: command.Authorization.ActorID, Role: command.Authorization.Role, RunID: command.RunID,
		StartedAt: startedAt, FinishedAt: command.OccurredAt, Outcome: command.Outcome,
		ErrorType: command.ErrorType, QueryBudgetConsumed: command.QueryBudgetConsumed,
		SecurityFindingIDs:    append([]string(nil), command.SecurityFindingIDs...),
		ReviewerInterventions: append([]string(nil), command.ReviewerInterventions...),
	}
	if command.OccurredAt.After(stage.LeaseExpiresAt) {
		attempt.Outcome = "FAILED"
		attempt.ErrorType = "LEASE_EXPIRED"
	}
	if attempt.Outcome == "SUCCEEDED" {
		if command.ErrorType != "" || command.RunID == "" || command.QueryBudgetConsumed < 0 || hasFailureProvenance(command) {
			return Decision{}, fmt.Errorf("%w: successful attempt contains invalid or failure-only provenance", ErrInvalidCommand)
		}
		stage.State = "SUCCEEDED"
		stage.LeaseExpiresAt = time.Time{}
		state.CompletedOutputs = appendUnique(state.CompletedOutputs, stage.Outputs...)
		state.Attempts = append(state.Attempts, attempt)
		return Decision{}, nil
	}
	if attempt.Outcome != "FAILED" || attempt.ErrorType == "" {
		return Decision{}, fmt.Errorf("%w: attempt outcome must be SUCCEEDED or a typed FAILED", ErrInvalidCommand)
	}
	if command.SafeMessage == "" || len(command.CauseChain) == 0 || command.Codepath == "" || command.Severity == "" || command.DiagnosticArtifactID == "" || len(command.AffectedClaimIDs) == 0 || len(command.AffectedArtifactIDs) == 0 || command.QueryBudgetConsumed < 0 || command.RunID == "" {
		return Decision{}, fmt.Errorf("%w: failed attempt requires the universal failure envelope fields", ErrInvalidCommand)
	}
	disposition := DispositionFor(value.policy, attempt.ErrorType)
	if Contains(value.policy.SemanticErrorTypes, attempt.ErrorType) && priorSemanticFailure(state.Failures, stage.ID, attempt.ErrorType, command.CauseChain) {
		attempt.ErrorType = "FLAKY_OUTCOME_ERROR"
		disposition = Block
	}
	if disposition == Retry && ordinal >= minPositive(stage.Retry.MaximumAttempts, value.policy.MaximumAttemptsPerStage) {
		attempt.ErrorType = "RETRY_EXHAUSTED"
		disposition = Block
	}
	attempt.Disposition = disposition
	attempt.FailureID = "failure." + attempt.ID
	failure := FailureEnvelope{
		ID: attempt.FailureID, AttemptID: attempt.ID, StageID: stage.ID, SnapshotID: state.SnapshotID,
		ErrorType: attempt.ErrorType, Phase: stage.ID, Codepath: command.Codepath, Severity: command.Severity,
		Retryability: retryability(disposition), Disposition: disposition,
		AffectedClaimIDs: append([]string(nil), command.AffectedClaimIDs...), AffectedArtifactIDs: append([]string(nil), command.AffectedArtifactIDs...),
		ActorID: attempt.ActorID, Role: attempt.Role, RunID: attempt.RunID, SafeMessage: command.SafeMessage,
		CauseChain: append([]string(nil), command.CauseChain...), DiagnosticArtifactID: command.DiagnosticArtifactID, OccurredAt: command.OccurredAt,
		QueryBudgetConsumed:   command.QueryBudgetConsumed,
		SecurityFindingIDs:    append([]string(nil), command.SecurityFindingIDs...),
		ReviewerInterventions: append([]string(nil), command.ReviewerInterventions...),
	}
	state.Attempts = append(state.Attempts, attempt)
	state.Failures = append(state.Failures, failure)
	stage.LeaseExpiresAt = time.Time{}
	decision := Decision{Disposition: disposition}
	switch disposition {
	case Retry:
		stage.State = "PENDING"
		decision.RetryAfter = retryBackoff(stage.Retry, ordinal, time.Duration(value.policy.MaximumBackoffSeconds)*time.Second)
	case DegradeNonAssurance:
		stage.State = "DEGRADED"
	case Quarantine:
		stage.State = "FAILED"
		state.Status = "QUARANTINED"
	default:
		stage.State = "FAILED"
		state.Status = "BLOCKED"
	}
	return decision, nil
}

func hasFailureProvenance(command Command) bool {
	return command.SafeMessage != "" || len(command.CauseChain) != 0 || command.Codepath != "" || command.Severity != "" ||
		command.DiagnosticArtifactID != "" || len(command.AffectedClaimIDs) != 0 || len(command.AffectedArtifactIDs) != 0
}

func (value *Runner) cancel(state *RunState, command Command) (Decision, error) {
	if state.Status == "PROMOTED" || state.Status == "SUPERSEDED" {
		return Decision{}, ErrTerminalRun
	}
	timestamp := command.OccurredAt.UTC()
	state.CancelledAt = &timestamp
	state.Status = "CANCELLED"
	return Decision{Disposition: Block}, nil
}

func (value *Runner) supersede(state *RunState, command Command) (Decision, error) {
	if command.SupersededBy == "" || command.SupersededBy == state.SnapshotID || state.Status == "PROMOTED" {
		return Decision{}, fmt.Errorf("%w: invalid supersession", ErrInvalidCommand)
	}
	state.SupersededBy = command.SupersededBy
	state.Status = "SUPERSEDED"
	return Decision{Disposition: Invalidate}, nil
}

func (value *Runner) authorizeRetry(state *RunState, command Command) (Decision, error) {
	if state.Status != "BLOCKED" || len(command.ReviewerInterventions) == 0 {
		return Decision{}, fmt.Errorf("%w: blocked semantic retry requires an explicit reviewer intervention", ErrInvalidCommand)
	}
	stage, err := findStage(state, command.StageID)
	if err != nil || stage.State != "FAILED" {
		return Decision{}, fmt.Errorf("%w: retry target is not a failed stage", ErrInvalidCommand)
	}
	if len(state.Attempts) == 0 {
		return Decision{}, fmt.Errorf("%w: retry target has no retained attempt", ErrInvalidCommand)
	}
	prior := state.Attempts[len(state.Attempts)-1]
	if prior.StageID != stage.ID || !Contains(value.policy.SemanticErrorTypes, prior.ErrorType) {
		return Decision{}, fmt.Errorf("%w: only a reviewer may reopen a semantic failure", ErrInvalidCommand)
	}
	stage.State = "PENDING"
	state.Status = "RUNNING"
	return Decision{}, nil
}

func (value *Runner) verifyCheckpoint(state *RunState, command Command) (Decision, error) {
	digest, err := stateDigest(*state)
	if err != nil {
		return Decision{}, err
	}
	if command.CheckpointDigest != digest {
		return Decision{}, ErrCheckpointMismatch
	}
	state.CheckpointVerifications = append(state.CheckpointVerifications, CheckpointVerification{
		Command:                    cloneCommand(command),
		PreVerificationStateDigest: digest,
		Verification:               state.Verification,
	})
	state.VerifiedCheckpoint = digest
	state.VerifiedByCommandID = command.ID
	state.VerifiedByNonce = command.Authorization.Nonce
	return Decision{}, nil
}

func (value *Runner) promote(ctx context.Context, state *RunState, command Command) (Decision, error) {
	if state.Status != "RUNNING" || state.VerifiedCheckpoint == "" {
		return Decision{}, fmt.Errorf("%w: promotion requires a verified checkpoint", ErrInvalidCommand)
	}
	if err := validateReceipt(state.Verification, value.policy); err != nil {
		return Decision{}, err
	}
	for _, required := range value.policy.RequiredStages {
		stage, err := findStage(state, required)
		if err != nil || stage.State != "SUCCEEDED" {
			return Decision{}, fmt.Errorf("%w: required stage %s is incomplete", ErrInvalidCommand, required)
		}
	}
	comparison, err := cloneState(*state)
	if err != nil {
		return Decision{}, err
	}
	verificationIndex := -1
	for index := range comparison.CheckpointVerifications {
		if comparison.CheckpointVerifications[index].Command.ID == comparison.VerifiedByCommandID {
			verificationIndex = index
		}
	}
	if verificationIndex < 0 {
		return Decision{}, ErrCheckpointMismatch
	}
	comparison.CheckpointVerifications = append(comparison.CheckpointVerifications[:verificationIndex], comparison.CheckpointVerifications[verificationIndex+1:]...)
	delete(comparison.AppliedCommands, comparison.VerifiedByCommandID)
	filtered := make([]string, 0, len(comparison.ConsumedNonces))
	for _, nonce := range comparison.ConsumedNonces {
		if nonce != comparison.VerifiedByNonce {
			filtered = append(filtered, nonce)
		}
	}
	comparison.ConsumedNonces = filtered
	currentDigest, err := stateDigest(comparison)
	if err != nil || currentDigest != state.VerifiedCheckpoint {
		return Decision{}, ErrCheckpointMismatch
	}
	terminal, err := cloneState(*state)
	if err != nil {
		return Decision{}, err
	}
	commandDigest, err := Digest(command)
	if err != nil {
		return Decision{}, err
	}
	terminal.AppliedCommands[command.ID] = commandDigest
	terminal.ConsumedNonces = appendUnique(terminal.ConsumedNonces, command.Authorization.Nonce)
	terminal.Status = "PROMOTED"
	terminal.PromotedDigest, err = stateDigest(terminal)
	if err != nil {
		return Decision{}, err
	}
	stateBytes, err := CanonicalJSON(terminal)
	if err != nil {
		return Decision{}, err
	}
	object := PromotionObject{Key: state.SnapshotID + "/run-state.json", Digest: DigestBytes(stateBytes), Bytes: stateBytes}
	if value.promoter == nil {
		return Decision{}, fmt.Errorf("%w: no transactional promoter", ErrInvalidCommand)
	}
	if err := value.promoter.Promote(ctx, PromotionBatch{SnapshotID: state.SnapshotID, SnapshotDigest: state.SnapshotDigest, Objects: []PromotionObject{object}}); err != nil {
		if command.AttemptID == "" || command.RunID == "" || command.DiagnosticArtifactID == "" || len(command.AffectedClaimIDs) == 0 || len(command.AffectedArtifactIDs) == 0 || command.QueryBudgetConsumed < 0 {
			return Decision{}, fmt.Errorf("%w: failed promotion requires complete universal provenance", ErrInvalidCommand)
		}
		stage, stageErr := findStage(state, "publish")
		if stageErr != nil {
			return Decision{}, stageErr
		}
		ordinal := 1
		for _, attempt := range state.Attempts {
			if attempt.ID == command.AttemptID {
				return Decision{}, fmt.Errorf("%w: failed promotion attempt ID is not immutable", ErrInvalidCommand)
			}
			if attempt.StageID == stage.ID && attempt.Ordinal >= ordinal {
				ordinal = attempt.Ordinal + 1
			}
		}
		if ordinal > minPositive(stage.Retry.MaximumAttempts, value.policy.MaximumAttemptsPerStage) {
			return Decision{}, fmt.Errorf("%w: failed promotion attempt bound exceeded", ErrInvalidCommand)
		}
		attempt := Attempt{ID: command.AttemptID, StageID: stage.ID, SnapshotID: state.SnapshotID, Ordinal: ordinal, ActorID: command.Authorization.ActorID, Role: command.Authorization.Role, RunID: command.RunID, StartedAt: command.OccurredAt, FinishedAt: command.OccurredAt, Outcome: "FAILED", ErrorType: "PARTIAL_PUBLICATION", Disposition: Quarantine, FailureID: "failure." + command.AttemptID, QueryBudgetConsumed: command.QueryBudgetConsumed, SecurityFindingIDs: append([]string(nil), command.SecurityFindingIDs...), ReviewerInterventions: append([]string(nil), command.ReviewerInterventions...)}
		failure := FailureEnvelope{ID: attempt.FailureID, AttemptID: attempt.ID, StageID: stage.ID, SnapshotID: state.SnapshotID, ErrorType: attempt.ErrorType, Phase: stage.ID, Codepath: "protocol.MemoryPromoter.Promote", Severity: "security", Retryability: "non-retryable", Disposition: attempt.Disposition, AffectedClaimIDs: append([]string(nil), command.AffectedClaimIDs...), AffectedArtifactIDs: append([]string(nil), command.AffectedArtifactIDs...), ActorID: attempt.ActorID, Role: attempt.Role, RunID: attempt.RunID, SafeMessage: "transactional publication did not commit", CauseChain: []string{DigestBytes([]byte(err.Error()))}, DiagnosticArtifactID: command.DiagnosticArtifactID, OccurredAt: command.OccurredAt, QueryBudgetConsumed: command.QueryBudgetConsumed, SecurityFindingIDs: append([]string(nil), command.SecurityFindingIDs...), ReviewerInterventions: append([]string(nil), command.ReviewerInterventions...)}
		state.Attempts = append(state.Attempts, attempt)
		state.Failures = append(state.Failures, failure)
		state.Status = "QUARANTINED"
		return Decision{Disposition: Quarantine, Finding: &Finding{Code: "PARTIAL_PUBLICATION", Disposition: Quarantine, Path: "$.publication", Message: "transactional publication did not commit"}}, nil
	}
	*state = terminal
	return Decision{}, nil
}

func validateResumedState(state RunState, bundle Bundle) error {
	if state.SchemaVersion != SchemaVersion || len(state.Stages) != len(bundle.Stages) {
		return fmt.Errorf("%w: checkpoint stage topology is invalid", ErrCheckpointMismatch)
	}
	switch state.Status {
	case "RUNNING", "BLOCKED", "QUARANTINED", "CANCELLED", "SUPERSEDED", "PROMOTED":
	default:
		return fmt.Errorf("%w: checkpoint run status is invalid", ErrCheckpointMismatch)
	}
	if len(state.AppliedCommands) != len(state.ConsumedNonces) {
		return fmt.Errorf("%w: applied commands and consumed nonces differ", ErrCheckpointMismatch)
	}
	retainedNonces := make(map[string]bool, len(state.ConsumedNonces))
	for _, nonce := range state.ConsumedNonces {
		if nonce == "" || retainedNonces[nonce] {
			return fmt.Errorf("%w: consumed nonce history is invalid", ErrCheckpointMismatch)
		}
		retainedNonces[nonce] = true
	}
	for commandID, digest := range state.AppliedCommands {
		if commandID == "" || !validDigest(digest) || !retainedNonces[commandID] {
			return fmt.Errorf("%w: applied command receipt is invalid", ErrCheckpointMismatch)
		}
	}
	stageByID := make(map[string]Stage, len(state.Stages))
	succeeded := make(map[string]bool, len(state.Stages))
	degraded := make(map[string]bool, len(state.Stages))
	failed := make(map[string]bool, len(state.Stages))
	for index, stage := range state.Stages {
		if !sameStageDefinition(stage, bundle.Stages[index]) {
			return fmt.Errorf("%w: checkpoint changed immutable stage definition", ErrCheckpointMismatch)
		}
		switch stage.State {
		case "PENDING", "RUNNING", "SUCCEEDED", "DEGRADED", "FAILED":
		default:
			return fmt.Errorf("%w: checkpoint has invalid stage state", ErrCheckpointMismatch)
		}
		if stage.State == "RUNNING" && stage.LeaseExpiresAt.IsZero() || stage.State != "RUNNING" && !stage.LeaseExpiresAt.IsZero() {
			return fmt.Errorf("%w: checkpoint lease does not match stage state", ErrCheckpointMismatch)
		}
		stageByID[stage.ID] = stage
	}
	attemptByID := make(map[string]Attempt, len(state.Attempts))
	ordinals := make(map[string]int, len(state.Stages))
	for _, attempt := range state.Attempts {
		stage, stageExists := stageByID[attempt.StageID]
		if attempt.ID == "" || attempt.SnapshotID != state.SnapshotID || attempt.Ordinal != ordinals[attempt.StageID]+1 ||
			attempt.ActorID == "" || attempt.Role == "" || attempt.RunID == "" || !stageExists || !Contains(stage.RequiredRoles, attempt.Role) ||
			attempt.StartedAt.IsZero() || attempt.FinishedAt.Before(attempt.StartedAt) || attempt.QueryBudgetConsumed < 0 || attempt.Ordinal > stage.Retry.MaximumAttempts {
			return fmt.Errorf("%w: checkpoint attempt identity or ordinal is invalid", ErrCheckpointMismatch)
		}
		if _, exists := attemptByID[attempt.ID]; exists {
			return fmt.Errorf("%w: checkpoint reuses an immutable attempt ID", ErrCheckpointMismatch)
		}
		ordinals[attempt.StageID] = attempt.Ordinal
		attemptByID[attempt.ID] = attempt
		switch attempt.Outcome {
		case "SUCCEEDED":
			if attempt.ErrorType != "" || attempt.FailureID != "" || attempt.Disposition != "" || succeeded[attempt.StageID] {
				return fmt.Errorf("%w: successful checkpoint attempt contains failure state", ErrCheckpointMismatch)
			}
			succeeded[attempt.StageID] = true
		case "FAILED":
			if attempt.ErrorType == "" || attempt.FailureID == "" {
				return fmt.Errorf("%w: failed checkpoint attempt lacks failure identity", ErrCheckpointMismatch)
			}
			switch attempt.Disposition {
			case DegradeNonAssurance:
				degraded[attempt.StageID] = true
			case Block, Quarantine:
				failed[attempt.StageID] = true
			}
		default:
			return fmt.Errorf("%w: checkpoint attempt outcome is invalid", ErrCheckpointMismatch)
		}
	}
	failureIDs := make(map[string]bool, len(state.Failures))
	for _, failure := range state.Failures {
		attempt, exists := attemptByID[failure.AttemptID]
		exact := exists && attempt.Outcome == "FAILED" && attempt.FailureID == failure.ID && attempt.StageID == failure.StageID && attempt.SnapshotID == failure.SnapshotID &&
			attempt.ErrorType == failure.ErrorType && attempt.Disposition == failure.Disposition && attempt.ActorID == failure.ActorID && attempt.Role == failure.Role &&
			attempt.RunID == failure.RunID && attempt.FinishedAt.Equal(failure.OccurredAt) && attempt.QueryBudgetConsumed == failure.QueryBudgetConsumed &&
			SameStrings(attempt.SecurityFindingIDs, failure.SecurityFindingIDs) && SameStrings(attempt.ReviewerInterventions, failure.ReviewerInterventions)
		if !exact || failure.ID == "" || failureIDs[failure.ID] || !validFailureEnvelope(failure) {
			return fmt.Errorf("%w: checkpoint failure history is invalid", ErrCheckpointMismatch)
		}
		failureIDs[failure.ID] = true
	}
	for _, attempt := range state.Attempts {
		if attempt.Outcome == "FAILED" && !failureIDs[attempt.FailureID] {
			return fmt.Errorf("%w: checkpoint failed attempt has no retained envelope", ErrCheckpointMismatch)
		}
	}
	expectedOutputs := []string{}
	for _, stage := range state.Stages {
		if stage.State != "SUCCEEDED" && succeeded[stage.ID] {
			return fmt.Errorf("%w: checkpoint hides a successful attempt behind a non-success stage", ErrCheckpointMismatch)
		}
		switch stage.State {
		case "SUCCEEDED":
			if !succeeded[stage.ID] {
				return fmt.Errorf("%w: checkpoint stage succeeded without an immutable attempt", ErrCheckpointMismatch)
			}
			expectedOutputs = appendUnique(expectedOutputs, stage.Outputs...)
		case "DEGRADED":
			if !degraded[stage.ID] {
				return fmt.Errorf("%w: checkpoint stage degraded without a retained failure", ErrCheckpointMismatch)
			}
		case "FAILED":
			if !failed[stage.ID] {
				return fmt.Errorf("%w: checkpoint stage failed without a retained blocking failure", ErrCheckpointMismatch)
			}
		}
	}
	if !SameStrings(expectedOutputs, state.CompletedOutputs) {
		return fmt.Errorf("%w: checkpoint completed outputs do not match successful stages", ErrCheckpointMismatch)
	}
	return nil
}

func validateCheckpointVerifications(state RunState, policy Policy, now time.Time) error {
	if state.VerifiedCheckpoint == "" || state.VerifiedByCommandID == "" || state.VerifiedByNonce == "" || len(state.CheckpointVerifications) == 0 {
		return fmt.Errorf("%w: checkpoint has no durable verification action", ErrCheckpointMismatch)
	}
	seenCommands := make(map[string]bool, len(state.CheckpointVerifications))
	seenNonces := make(map[string]bool, len(state.CheckpointVerifications))
	for _, verification := range state.CheckpointVerifications {
		command := verification.Command
		commandDigest, err := Digest(command)
		valid := err == nil && command.Kind == "VERIFY_CHECKPOINT" && command.StageID == "" && command.SnapshotID == state.SnapshotID
		valid = valid && validDigest(verification.PreVerificationStateDigest) && command.CheckpointDigest == verification.PreVerificationStateDigest
		valid = valid && !command.OccurredAt.IsZero() && !command.OccurredAt.After(now)
		valid = valid && !seenCommands[command.ID] && !seenNonces[command.Authorization.Nonce]
		valid = valid && state.AppliedCommands[command.ID] == commandDigest && Contains(state.ConsumedNonces, command.Authorization.Nonce)
		valid = valid && validCommandAuthorization(policy, state, command, true)
		valid = valid && sameVerificationReceipt(verification.Verification, state.Verification)
		if !valid {
			return fmt.Errorf("%w: retained checkpoint verification action is invalid", ErrCheckpointMismatch)
		}
		seenCommands[command.ID] = true
		seenNonces[command.Authorization.Nonce] = true
	}
	latest := state.CheckpointVerifications[len(state.CheckpointVerifications)-1]
	if latest.Command.ID != state.VerifiedByCommandID || latest.Command.Authorization.Nonce != state.VerifiedByNonce || latest.PreVerificationStateDigest != state.VerifiedCheckpoint {
		return fmt.Errorf("%w: active checkpoint verification markers do not match the durable action", ErrCheckpointMismatch)
	}
	return nil
}

func sameStageDefinition(left, right Stage) bool {
	return left.ID == right.ID && left.SnapshotID == right.SnapshotID && left.IdempotencyKey == right.IdempotencyKey &&
		left.LeaseSeconds == right.LeaseSeconds && reflect.DeepEqual(left.Inputs, right.Inputs) && reflect.DeepEqual(left.Outputs, right.Outputs) &&
		reflect.DeepEqual(left.Retry, right.Retry) && reflect.DeepEqual(left.RequiredRoles, right.RequiredRoles)
}

func validFailureEnvelope(failure FailureEnvelope) bool {
	return failure.ID != "" && failure.AttemptID != "" && failure.StageID != "" && failure.SnapshotID != "" && failure.ErrorType != "" &&
		failure.Phase == failure.StageID && failure.Codepath != "" && failure.Severity != "" && failure.Retryability == retryability(failure.Disposition) && failure.Disposition != "" &&
		len(failure.AffectedClaimIDs) > 0 && len(failure.AffectedArtifactIDs) > 0 && failure.ActorID != "" && failure.Role != "" && failure.RunID != "" &&
		failure.SafeMessage != "" && len(failure.CauseChain) > 0 && failure.DiagnosticArtifactID != "" && !failure.OccurredAt.IsZero() && failure.QueryBudgetConsumed >= 0
}

func findStage(state *RunState, id string) (*Stage, error) {
	for index := range state.Stages {
		if state.Stages[index].ID == id {
			return &state.Stages[index], nil
		}
	}
	return nil, fmt.Errorf("%w: unknown stage %q", ErrInvalidCommand, id)
}

func priorSemanticFailure(failures []FailureEnvelope, stageID, errorType string, causeChain []string) bool {
	for _, failure := range failures {
		if failure.StageID == stageID && failure.ErrorType == errorType && reflect.DeepEqual(failure.CauseChain, causeChain) {
			return true
		}
	}
	return false
}

func (value *Runner) replayedDecision(command Command) Decision {
	switch command.Kind {
	case "CANCEL":
		return Decision{Disposition: Block}
	case "SUPERSEDE":
		return Decision{Disposition: Invalidate}
	case "COMPLETE_ATTEMPT", "PROMOTE":
		for _, attempt := range value.state.Attempts {
			if attempt.ID != command.AttemptID {
				continue
			}
			decision := Decision{Disposition: attempt.Disposition}
			if attempt.Disposition == Retry {
				if stage, err := findStage(&value.state, attempt.StageID); err == nil {
					decision.RetryAfter = retryBackoff(stage.Retry, attempt.Ordinal, time.Duration(value.policy.MaximumBackoffSeconds)*time.Second)
				}
			}
			if command.Kind == "PROMOTE" && attempt.ErrorType == "PARTIAL_PUBLICATION" {
				decision.Finding = &Finding{Code: "PARTIAL_PUBLICATION", Disposition: Quarantine, Path: "$.publication", Message: "transactional publication did not commit"}
			}
			return decision
		}
	}
	return Decision{}
}

func retryBackoff(policy RetryPolicy, ordinal int, maximum time.Duration) time.Duration {
	backoff := policy.InitialBackoff
	for index := 1; index < ordinal; index++ {
		backoff *= 2
	}
	if policy.MaximumBackoff > 0 && backoff > policy.MaximumBackoff {
		backoff = policy.MaximumBackoff
	}
	if maximum > 0 && backoff > maximum {
		backoff = maximum
	}
	return backoff
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value] = true
	}
	for _, addition := range additions {
		if !seen[addition] {
			values = append(values, addition)
			seen[addition] = true
		}
	}
	sort.Strings(values)
	return values
}

func cloneState(state RunState) (RunState, error) {
	data, err := CanonicalJSON(state)
	if err != nil {
		return RunState{}, err
	}
	var clone RunState
	if err := DecodeStrict(data, &clone); err != nil {
		return RunState{}, err
	}
	return clone, nil
}

func cloneCommand(command Command) Command {
	command.CauseChain = cloneStrings(command.CauseChain)
	command.AffectedClaimIDs = cloneStrings(command.AffectedClaimIDs)
	command.AffectedArtifactIDs = cloneStrings(command.AffectedArtifactIDs)
	command.SecurityFindingIDs = cloneStrings(command.SecurityFindingIDs)
	command.ReviewerInterventions = cloneStrings(command.ReviewerInterventions)
	command.Authorization.SnapshotRoles = cloneStrings(command.Authorization.SnapshotRoles)
	command.Authorization.PriorNonces = cloneStrings(command.Authorization.PriorNonces)
	return command
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func stateDigest(state RunState) (string, error) {
	clone, err := cloneState(state)
	if err != nil {
		return "", err
	}
	clone.VerifiedCheckpoint = ""
	clone.VerifiedByCommandID = ""
	clone.VerifiedByNonce = ""
	clone.PromotedDigest = ""
	return Digest(clone)
}

func minPositive(left, right int) int {
	if left <= 0 {
		return right
	}
	if right <= 0 || left < right {
		return left
	}
	return right
}

func retryability(disposition Disposition) string {
	if disposition == Retry {
		return "transient"
	}
	return "non-retryable"
}
