package assurance

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

func TestUS004ProtocolAcceptance_FailureRegistryClosedSet(t *testing.T) {
	t.Parallel()

	data := mustReadRepoFile(t, failuresPath)
	var registry failureRegistry
	if err := vendorprotocol.DecodeStrict(data, &registry); err != nil {
		t.Fatalf("decode failure registry: %v", err)
	}

	seenCodes := make(map[string]int, len(registry.Entries))
	seenDispositions := make(map[vendorprotocol.Disposition]int, 6)
	retryCodes := make([]string, 0, 5)
	for _, entry := range registry.Entries {
		seenCodes[entry.Code]++
		seenDispositions[entry.Disposition]++
		if entry.Disposition == vendorprotocol.Retry {
			retryCodes = append(retryCodes, entry.Code)
		}
	}
	for code, count := range seenCodes {
		if count != 1 {
			t.Fatalf("code %q mapped %d times", code, count)
		}
	}
	for _, disposition := range []vendorprotocol.Disposition{
		vendorprotocol.Retry,
		vendorprotocol.DegradeNonAssurance,
		vendorprotocol.Block,
		vendorprotocol.Invalidate,
		vendorprotocol.Quarantine,
		vendorprotocol.Revoke,
	} {
		if seenDispositions[disposition] == 0 {
			t.Fatalf("missing disposition %s in failure registry", disposition)
		}
	}
	assertExactStringSet(t, retryCodes, []string{
		"LEASE_EXPIRED",
		"NETWORK_DENIED",
		"QUARANTINE_UNAVAILABLE",
		"STORAGE_UNAVAILABLE",
		"WORKER_INTERRUPTED",
	})
}

func TestUS004ProtocolAcceptance_FailureAndAttemptFindings(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		mutate      func(t *testing.T, root string)
		expected    string
		disposition vendorprotocol.Disposition
	}{
		{
			name: "unknown failure code",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				bundle = appendFailedAttemptAndFailure(bundle, failedAttemptOptions{
					StageID:     "verify",
					AttemptID:   "attempt-verify-2",
					FailureID:   "failure.attempt-verify-2",
					Ordinal:     2,
					ErrorType:   "NON_ALLOWLISTED_UNKNOWN",
					Disposition: vendorprotocol.Block,
				})
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "UNKNOWN_FAILURE_CODE",
			disposition: vendorprotocol.Block,
		},
		{
			name: "wrong disposition",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				bundle = appendFailedAttemptAndFailure(bundle, failedAttemptOptions{
					StageID:     "verify",
					AttemptID:   "attempt-verify-2",
					FailureID:   "failure.attempt-verify-2",
					Ordinal:     2,
					ErrorType:   "NETWORK_DENIED",
					Disposition: vendorprotocol.Block,
				})
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "INVALID_FAILURE_BINDING",
			disposition: vendorprotocol.Block,
		},
		{
			name: "hidden failed attempt",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				stage := mustStage(t, bundle, "verify")
				stage.Retry.MaximumAttempts = 2
				updateStage(t, &bundle, stage)
				bundle.Attempts = append(bundle.Attempts, buildFailedAttempt(bundle, failedAttemptOptions{
					StageID:     "verify",
					AttemptID:   "attempt-verify-2",
					FailureID:   "failure.attempt-verify-2",
					Ordinal:     2,
					ErrorType:   "SEMANTIC_INCONSISTENCY",
					Disposition: vendorprotocol.Block,
				}))
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "HIDDEN_FAILED_ATTEMPT",
			disposition: vendorprotocol.Block,
		},
		{
			name: "orphan failure",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				stage := mustStage(t, bundle, "verify")
				stage.Retry.MaximumAttempts = 2
				updateStage(t, &bundle, stage)
				bundle.Failures = append(bundle.Failures, buildFailureEnvelope(bundle, failedAttemptOptions{
					StageID:     "verify",
					AttemptID:   "attempt-verify-2",
					FailureID:   "failure.attempt-verify-2",
					Ordinal:     2,
					ErrorType:   "SEMANTIC_INCONSISTENCY",
					Disposition: vendorprotocol.Block,
				}))
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "ORPHAN_FAILURE",
			disposition: vendorprotocol.Block,
		},
		{
			name: "failure attempt binding mismatch",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				bundle = appendFailedAttemptAndFailure(bundle, failedAttemptOptions{
					StageID:     "verify",
					AttemptID:   "attempt-verify-2",
					FailureID:   "failure.attempt-verify-2",
					Ordinal:     2,
					ErrorType:   "SEMANTIC_INCONSISTENCY",
					Disposition: vendorprotocol.Block,
				})
				bundle.Failures[len(bundle.Failures)-1].SnapshotID = "snapshot-mismatch"
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "INVALID_FAILURE_BINDING",
			disposition: vendorprotocol.Block,
		},
		{
			name: "duplicate attempt id",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				bundle.Attempts = append(bundle.Attempts, bundle.Attempts[0])
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "DUPLICATE_ID",
			disposition: vendorprotocol.Block,
		},
		{
			name: "noncontiguous per stage ordinals",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				bundle = appendFailedAttemptAndFailure(bundle, failedAttemptOptions{
					StageID:     "verify",
					AttemptID:   "attempt-verify-3",
					FailureID:   "failure.attempt-verify-3",
					Ordinal:     3,
					ErrorType:   "SEMANTIC_INCONSISTENCY",
					Disposition: vendorprotocol.Block,
				})
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "NONCONTIGUOUS_ATTEMPTS",
			disposition: vendorprotocol.Block,
		},
		{
			name: "retry of nonallowlisted error",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				bundle = appendFailedAttemptAndFailure(bundle, failedAttemptOptions{
					StageID:     "verify",
					AttemptID:   "attempt-verify-2",
					FailureID:   "failure.attempt-verify-2",
					Ordinal:     2,
					ErrorType:   "SEMANTIC_INCONSISTENCY",
					Disposition: vendorprotocol.Retry,
				})
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "INVALID_RETRY_ERROR_TYPE",
			disposition: vendorprotocol.Block,
		},
		{
			name: "retry bound exhaustion",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				options := failedAttemptOptions{
					StageID:     "verify",
					AttemptID:   "attempt-verify-2",
					FailureID:   "failure.attempt-verify-2",
					Ordinal:     2,
					ErrorType:   "NETWORK_DENIED",
					Disposition: vendorprotocol.Retry,
				}
				bundle.Attempts = append(bundle.Attempts, buildFailedAttempt(bundle, options))
				bundle.Failures = append(bundle.Failures, buildFailureEnvelope(bundle, options))
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "RETRY_BOUND_EXCEEDED",
			disposition: vendorprotocol.Block,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			root := copiedAssuranceRoot(t)
			testCase.mutate(t, root)

			verdict, err := Replay(context.Background(), Request{
				RootPath:      root,
				LifecyclePath: lifecyclePathDefault,
				Mode:          ModeReplay,
			})
			if err != nil {
				t.Fatalf("replay: %v", err)
			}
			assertFinding(t, verdict.Findings, testCase.expected, testCase.disposition)
		})
	}
}

func TestUS004ProtocolAcceptance_CheckpointResume(t *testing.T) {
	t.Parallel()

	bundle := readLifecycleBundle(t, repoRoot(t), lifecyclePathDefault)
	policy := childPolicy()
	clock := fixedClock(bundle.VerifiedAt.UTC())

	makeRunnerCheckpoint := func(t *testing.T) vendorprotocol.Checkpoint {
		t.Helper()
		return buildChildCheckpointFixture(t, bundle, policy)
	}

	t.Run("state digest tamper rejected", func(t *testing.T) {
		checkpoint := makeRunnerCheckpoint(t)
		checkpoint.StateDigest = "sha256:deadbeef"
		_, err := vendorprotocol.Resume(checkpoint, bundle, policy, nil, clock, protocolVerifiers()...)
		if !errors.Is(err, vendorprotocol.ErrCheckpointMismatch) {
			t.Fatalf("err = %v, want checkpoint mismatch", err)
		}
	})

	t.Run("snapshot digest drift rejected", func(t *testing.T) {
		checkpoint := makeRunnerCheckpoint(t)
		checkpoint.State.SnapshotDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		checkpoint.StateDigest = stateDigestForTest(t, checkpoint.State)
		_, err := vendorprotocol.Resume(checkpoint, bundle, policy, nil, clock, protocolVerifiers()...)
		if !errors.Is(err, vendorprotocol.ErrVerificationRejected) {
			t.Fatalf("err = %v, want verification rejected", err)
		}
	})

	t.Run("bundle drift rejected", func(t *testing.T) {
		checkpoint := makeRunnerCheckpoint(t)
		driftedBundle := bundle
		driftedBundle.Nodes = append([]vendorprotocol.Node(nil), bundle.Nodes...)
		driftedBundle.Nodes[0].Digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		_, err := vendorprotocol.Resume(checkpoint, driftedBundle, policy, nil, clock, protocolVerifiers()...)
		if !errors.Is(err, vendorprotocol.ErrVerificationRejected) {
			t.Fatalf("err = %v, want verification rejected", err)
		}
	})

	t.Run("policy drift rejected", func(t *testing.T) {
		checkpoint := makeRunnerCheckpoint(t)
		driftedPolicy := policy
		driftedPolicy.Version = policy.Version + "-drift"
		_, err := vendorprotocol.Resume(checkpoint, bundle, driftedPolicy, nil, clock, protocolVerifiers()...)
		if !errors.Is(err, vendorprotocol.ErrVerificationRejected) {
			t.Fatalf("err = %v, want verification rejected", err)
		}
	})

	t.Run("verification receipt drift rejected", func(t *testing.T) {
		checkpoint := makeRunnerCheckpoint(t)
		checkpoint.State.Verification.BundleDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		checkpoint.StateDigest = stateDigestForTest(t, checkpoint.State)
		_, err := vendorprotocol.Resume(checkpoint, bundle, policy, nil, clock, protocolVerifiers()...)
		if !errors.Is(err, vendorprotocol.ErrVerificationRejected) {
			t.Fatalf("err = %v, want verification rejected", err)
		}
	})

	t.Run("duplicate prior attempt rejected", func(t *testing.T) {
		checkpoint := makeRunnerCheckpoint(t)
		checkpoint.State.Attempts = append(checkpoint.State.Attempts,
			syntheticCheckpointAttempt(bundle, "attempt-dup", "ingest", 1),
			syntheticCheckpointAttempt(bundle, "attempt-dup", "verify", 1),
		)
		checkpoint.StateDigest = stateDigestForTest(t, checkpoint.State)
		_, err := vendorprotocol.Resume(checkpoint, bundle, policy, nil, clock, protocolVerifiers()...)
		if !errors.Is(err, vendorprotocol.ErrCheckpointMismatch) {
			t.Fatalf("err = %v, want checkpoint mismatch", err)
		}
	})

	t.Run("rewritten prior attempt rejected", func(t *testing.T) {
		checkpoint := makeRunnerCheckpoint(t)
		checkpoint.State.Attempts = append(checkpoint.State.Attempts, syntheticCheckpointAttempt(bundle, "attempt-invalid", "ingest", 1))
		checkpoint.State.Attempts[0].FinishedAt = checkpoint.State.Attempts[0].StartedAt.Add(-1 * time.Second)
		checkpoint.StateDigest = stateDigestForTest(t, checkpoint.State)
		_, err := vendorprotocol.Resume(checkpoint, bundle, policy, nil, clock, protocolVerifiers()...)
		if !errors.Is(err, vendorprotocol.ErrCheckpointMismatch) {
			t.Fatalf("err = %v, want checkpoint mismatch", err)
		}
	})

	t.Run("valid checkpoint resumes without rewriting prior state", func(t *testing.T) {
		checkpoint := makeRunnerCheckpoint(t)
		before, err := vendorprotocol.CanonicalJSON(checkpoint.State)
		if err != nil {
			t.Fatalf("canonical state before resume: %v", err)
		}

		resumed, err := vendorprotocol.Resume(checkpoint, bundle, policy, nil, clock, protocolVerifiers()...)
		if err != nil {
			t.Fatalf("resume: %v", err)
		}
		after, err := vendorprotocol.CanonicalJSON(resumed.State())
		if err != nil {
			t.Fatalf("canonical state after resume: %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("checkpoint state rewritten across resume:\nbefore=%s\nafter=%s", before, after)
		}
	})
}

func TestUS004ProtocolAcceptance_CheckedInCheckpointMatchesGeneratedFixture(t *testing.T) {
	t.Parallel()

	bundle := readLifecycleBundle(t, repoRoot(t), lifecyclePathDefault)
	checkpoint := buildChildCheckpointFixture(t, bundle, childPolicy())
	expected, err := vendorprotocol.CanonicalJSON(checkpoint)
	if err != nil {
		t.Fatalf("canonical generated checkpoint: %v", err)
	}
	actual := mustReadRepoFile(t, checkpointPath)
	if !bytes.Equal(bytes.TrimSpace(actual), expected) {
		t.Fatalf("checked-in checkpoint drifted from generated fixture\nactual=%s\nexpected=%s", actual, expected)
	}
}

func TestUS004ProtocolAcceptance_CheckpointInvalidThroughVerifyReplay(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		mutate func(t *testing.T, root string)
	}{
		{
			name: "state digest tamper",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				checkpoint := readCheckpoint(t, root)
				checkpoint.StateDigest = "sha256:deadbeef"
				writeJSONFile(t, filepath.Join(root, checkpointPath), checkpoint)
			},
		},
		{
			name: "verification receipt drift",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				checkpoint := readCheckpoint(t, root)
				checkpoint.State.Verification.BundleDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
				checkpoint.StateDigest = stateDigestForTest(t, checkpoint.State)
				writeJSONFile(t, filepath.Join(root, checkpointPath), checkpoint)
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			root := copiedAssuranceRoot(t)
			testCase.mutate(t, root)

			for _, mode := range []string{ModeVerify, ModeReplay} {
				verdict, err := Verify(context.Background(), Request{RootPath: root, LifecyclePath: lifecyclePathDefault, Mode: mode})
				if mode == ModeReplay {
					verdict, err = Replay(context.Background(), Request{RootPath: root, LifecyclePath: lifecyclePathDefault, Mode: mode})
				}
				if err != nil {
					t.Fatalf("%s: %v", mode, err)
				}
				assertFinding(t, verdict.Findings, "CHECKPOINT_INVALID", vendorprotocol.Block)
			}
		})
	}
}

func TestUS004ProtocolAcceptance_BadEvidenceAndLeakageCases(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		mode        string
		lifecycle   string
		mutate      func(t *testing.T, root string)
		expected    string
		disposition vendorprotocol.Disposition
	}{
		{
			name: "bad external receipt strongest supported code",
			mode: ModeVerify,
			mutate: func(t *testing.T, root string) {
				t.Helper()
				value := readGenericJSON(t, filepath.Join(root, evidenceModelPath))
				replayBundles := value["replay_bundles"].([]any)
				replayBundles[0].(map[string]any)["replay_command"] = ""
				writeJSONFile(t, filepath.Join(root, evidenceModelPath), value)
			},
			expected:    "INCOMPLETE_REPLAY_BUNDLE",
			disposition: vendorprotocol.Block,
		},
		{
			name: "zero proof obligations strongest supported code",
			mode: ModeVerify,
			mutate: func(t *testing.T, root string) {
				t.Helper()
				value := readGenericJSON(t, filepath.Join(root, evidenceModelPath))
				value["proof_obligations"] = []any{}
				writeJSONFile(t, filepath.Join(root, evidenceModelPath), value)
			},
			expected:    "MISSING_PROOF_OBLIGATION",
			disposition: vendorprotocol.Block,
		},
		{
			name: "missing evidence strongest supported code",
			mode: ModeVerify,
			mutate: func(t *testing.T, root string) {
				t.Helper()
				value := readGenericJSON(t, filepath.Join(root, evidenceModelPath))
				claims := value["claims"].([]any)
				claims[0].(map[string]any)["evidence_ids"] = []any{"missing-evidence-id"}
				writeJSONFile(t, filepath.Join(root, evidenceModelPath), value)
			},
			expected:    "MISSING_REQUIRED_EVIDENCE",
			disposition: vendorprotocol.Block,
		},
		{
			name: "post review root mutation strongest supported code",
			mode: ModeReplay,
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				bundle.Nodes[1].Digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "DIGEST_MISMATCH",
			disposition: vendorprotocol.Quarantine,
		},
		{
			name:        "stale pin",
			mode:        ModeReplay,
			lifecycle:   "assurance/replay/fixtures/stale/lifecycle.json",
			expected:    "STALE_INPUT",
			disposition: vendorprotocol.Invalidate,
		},
		{
			name:        "role conflict",
			mode:        ModeReplay,
			lifecycle:   "assurance/replay/fixtures/role-conflict/lifecycle.json",
			expected:    "ROLE_CONFLICT",
			disposition: vendorprotocol.Quarantine,
		},
		{
			name: "protected leakage strongest supported code",
			mode: ModeVerify,
			mutate: func(t *testing.T, root string) {
				t.Helper()
				contract := readPublicContract(t, root)
				contract.WhyBlocked = "raw_diagnostic canary"
				writeJSONFile(t, filepath.Join(root, publicContractPath), contract)
			},
			expected:    "PROTECTED_PUBLICATION_DISCLOSURE",
			disposition: vendorprotocol.Revoke,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			root := copiedAssuranceRoot(t)
			lifecyclePath := lifecyclePathDefault
			if testCase.lifecycle != "" {
				lifecyclePath = testCase.lifecycle
			}
			if testCase.mutate != nil {
				testCase.mutate(t, root)
			}

			request := Request{RootPath: root, LifecyclePath: lifecyclePath, Mode: testCase.mode}
			var (
				verdict Verdict
				err     error
			)
			if testCase.mode == ModeReplay {
				verdict, err = Replay(context.Background(), request)
			} else {
				verdict, err = Verify(context.Background(), request)
			}
			if err != nil {
				t.Fatalf("evaluate %s: %v", testCase.mode, err)
			}
			assertFinding(t, verdict.Findings, testCase.expected, testCase.disposition)
		})
	}
}

func TestUS004ProtocolAcceptance_CanonicalAssuranceCeiling(t *testing.T) {
	t.Parallel()

	verifyVerdict, err := Verify(context.Background(), Request{
		RootPath:      repoRoot(t),
		LifecyclePath: lifecyclePathDefault,
		Mode:          ModeVerify,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	replayVerdict, err := Replay(context.Background(), Request{
		RootPath:      repoRoot(t),
		LifecyclePath: lifecyclePathDefault,
		Mode:          ModeReplay,
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	for _, verdict := range []Verdict{verifyVerdict, replayVerdict} {
		if verdict.Assurance != assuranceCeiling {
			t.Fatalf("assurance = %q, want %q", verdict.Assurance, assuranceCeiling)
		}
		if verdict.IndependentReviewClaimed {
			t.Fatal("canonical result must not claim human independence")
		}
	}
}

type failedAttemptOptions struct {
	StageID     string
	AttemptID   string
	FailureID   string
	Ordinal     int
	ErrorType   string
	Disposition vendorprotocol.Disposition
}

func appendFailedAttemptAndFailure(bundle vendorprotocol.Bundle, options failedAttemptOptions) vendorprotocol.Bundle {
	stage := mustStage(nil, bundle, options.StageID)
	stage.Retry.MaximumAttempts = maxInt(stage.Retry.MaximumAttempts, options.Ordinal)
	updateStage(nil, &bundle, stage)
	bundle.Attempts = append(bundle.Attempts, buildFailedAttempt(bundle, options))
	bundle.Failures = append(bundle.Failures, buildFailureEnvelope(bundle, options))
	return bundle
}

func buildFailedAttempt(bundle vendorprotocol.Bundle, options failedAttemptOptions) vendorprotocol.Attempt {
	stage := mustStage(nil, bundle, options.StageID)
	finishedAt := bundle.VerifiedAt.Add(-30 * time.Second)
	startedAt := finishedAt.Add(-5 * time.Second)
	return vendorprotocol.Attempt{
		ID:                    options.AttemptID,
		StageID:               options.StageID,
		SnapshotID:            bundle.Snapshot.ID,
		Ordinal:               options.Ordinal,
		ActorID:               "github:michaellady",
		Role:                  stage.RequiredRoles[0],
		RunID:                 "run-" + options.AttemptID,
		StartedAt:             startedAt,
		FinishedAt:            finishedAt,
		Outcome:               "FAILED",
		ErrorType:             options.ErrorType,
		Disposition:           options.Disposition,
		FailureID:             options.FailureID,
		QueryBudgetConsumed:   0,
		SecurityFindingIDs:    []string{},
		ReviewerInterventions: []string{},
	}
}

func buildFailureEnvelope(bundle vendorprotocol.Bundle, options failedAttemptOptions) vendorprotocol.FailureEnvelope {
	attempt := buildFailedAttempt(bundle, options)
	retryability := "non-retryable"
	if options.Disposition == vendorprotocol.Retry {
		retryability = "transient"
	}
	return vendorprotocol.FailureEnvelope{
		ID:                    options.FailureID,
		AttemptID:             options.AttemptID,
		StageID:               options.StageID,
		SnapshotID:            bundle.Snapshot.ID,
		ErrorType:             options.ErrorType,
		Phase:                 options.StageID,
		Codepath:              "internal/assurance/us004_protocol_acceptance_test",
		Severity:              "error",
		Retryability:          retryability,
		Disposition:           options.Disposition,
		AffectedClaimIDs:      []string{"claim-us004"},
		AffectedArtifactIDs:   []string{"evidence-upstream-manifest"},
		ActorID:               attempt.ActorID,
		Role:                  attempt.Role,
		RunID:                 attempt.RunID,
		SafeMessage:           "synthetic protocol failure",
		CauseChain:            []string{"synthetic"},
		DiagnosticArtifactID:  "evidence-upstream-manifest",
		OccurredAt:            attempt.FinishedAt,
		QueryBudgetConsumed:   0,
		SecurityFindingIDs:    []string{},
		ReviewerInterventions: []string{},
	}
}

func mustStage(t *testing.T, bundle vendorprotocol.Bundle, stageID string) vendorprotocol.Stage {
	for _, stage := range bundle.Stages {
		if stage.ID == stageID {
			return stage
		}
	}
	if t != nil {
		t.Fatalf("missing stage %s", stageID)
	}
	panic("missing stage " + stageID)
}

func updateStage(t *testing.T, bundle *vendorprotocol.Bundle, stage vendorprotocol.Stage) {
	for index := range bundle.Stages {
		if bundle.Stages[index].ID == stage.ID {
			bundle.Stages[index] = stage
			return
		}
	}
	if t != nil {
		t.Fatalf("missing stage %s", stage.ID)
	}
	panic("missing stage " + stage.ID)
}

func protocolAcceptancePolicy() vendorprotocol.Policy {
	policy := childPolicy()
	policy.MaximumAttemptsPerStage = 3
	policy.ActionRoles["START_STAGE:ingest"] = []string{"port-implementer"}
	return policy
}

func authorizeCommand(t *testing.T, policy vendorprotocol.Policy, snapshotDigest, role string, command vendorprotocol.Command) vendorprotocol.Command {
	t.Helper()
	command.Authorization = vendorprotocol.Authorization{
		ActorID:           "github:michaellady",
		Role:              role,
		SnapshotRoles:     []string{role},
		SnapshotDigest:    snapshotDigest,
		PolicyVersion:     policy.Version,
		Nonce:             command.ID,
		PriorNonces:       []string{},
		IssuedAt:          command.OccurredAt.Add(-30 * time.Second),
		ExpiresAt:         command.OccurredAt.Add(30 * time.Second),
		SignatureVerified: true,
		Revoked:           false,
		CommandID:         command.ID,
		Action:            command.Kind,
		StageID:           command.StageID,
	}
	intentDigest, err := vendorprotocol.CommandIntentDigest(command)
	if err != nil {
		t.Fatalf("command intent digest: %v", err)
	}
	command.Authorization.IntentDigest = intentDigest
	return command
}

func fixedClock(now time.Time) vendorprotocol.Clock {
	return func() time.Time { return now }
}

func buildChildCheckpointFixture(t *testing.T, bundle vendorprotocol.Bundle, policy vendorprotocol.Policy) vendorprotocol.Checkpoint {
	t.Helper()

	baseTime := bundle.VerifiedAt.UTC()
	runner, err := vendorprotocol.NewRunner(bundle, policy, nil, fixedClock(baseTime), protocolVerifiers()...)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	preVerify, err := runner.Checkpoint()
	if err != nil {
		t.Fatalf("checkpoint before verify: %v", err)
	}
	command := authorizeCommand(t, policy, bundle.Snapshot.CandidateDigest, "release-attestor", vendorprotocol.Command{
		ID:               "cmd-verify-checkpoint-initial",
		Kind:             "VERIFY_CHECKPOINT",
		SnapshotID:       bundle.Snapshot.ID,
		CheckpointDigest: preVerify.StateDigest,
		OccurredAt:       bundle.VerifiedAt.Add(-30 * time.Second).UTC(),
	})
	if _, err := runner.Apply(context.Background(), command); err != nil {
		t.Fatalf("verify checkpoint: %v", err)
	}
	checkpoint, err := runner.Checkpoint()
	if err != nil {
		t.Fatalf("checkpoint after verify: %v", err)
	}
	return checkpoint
}

func syntheticCheckpointAttempt(bundle vendorprotocol.Bundle, attemptID, stageID string, ordinal int) vendorprotocol.Attempt {
	stage := mustStage(nil, bundle, stageID)
	finishedAt := bundle.VerifiedAt.Add(-30 * time.Second)
	startedAt := finishedAt.Add(-5 * time.Second)
	return vendorprotocol.Attempt{
		ID:                    attemptID,
		StageID:               stageID,
		SnapshotID:            bundle.Snapshot.ID,
		Ordinal:               ordinal,
		ActorID:               "github:michaellady",
		Role:                  stage.RequiredRoles[0],
		RunID:                 "run-" + attemptID,
		StartedAt:             startedAt,
		FinishedAt:            finishedAt,
		Outcome:               "SUCCEEDED",
		QueryBudgetConsumed:   0,
		SecurityFindingIDs:    []string{},
		ReviewerInterventions: []string{},
	}
}

func stateDigestForTest(t *testing.T, state vendorprotocol.RunState) string {
	t.Helper()
	state.VerifiedCheckpoint = ""
	state.VerifiedByCommandID = ""
	state.VerifiedByNonce = ""
	state.PromotedDigest = ""
	digest, err := vendorprotocol.Digest(state)
	if err != nil {
		t.Fatalf("state digest: %v", err)
	}
	return digest
}

func readGenericJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var value map[string]any
	if err := vendorprotocol.DecodeStrict(data, &value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return value
}

func readCheckpoint(t *testing.T, root string) vendorprotocol.Checkpoint {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, checkpointPath))
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	var checkpoint vendorprotocol.Checkpoint
	if err := vendorprotocol.DecodeStrict(data, &checkpoint); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	return checkpoint
}

func assertExactStringSet(t *testing.T, actual, expected []string) {
	t.Helper()
	left, err := vendorprotocol.CanonicalJSON(sortedStrings(actual))
	if err != nil {
		t.Fatalf("canonical actual set: %v", err)
	}
	right, err := vendorprotocol.CanonicalJSON(sortedStrings(expected))
	if err != nil {
		t.Fatalf("canonical expected set: %v", err)
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("set mismatch: actual=%s expected=%s", left, right)
	}
}

func sortedStrings(values []string) []string {
	clone := append([]string(nil), values...)
	for index := 0; index < len(clone); index++ {
		for next := index + 1; next < len(clone); next++ {
			if clone[next] < clone[index] {
				clone[index], clone[next] = clone[next], clone[index]
			}
		}
	}
	return clone
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
