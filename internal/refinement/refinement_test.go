package refinement

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func fakeDigest(value byte) string {
	return "sha256:" + strings.Repeat(fmt.Sprintf("%x", value), 64)
}

func fixture() Evidence {
	artifact := func(path, sha string) Artifact { return Artifact{Path: path, SHA256: sha, Bytes: 1} }
	rows := make([]PairRow, 74)
	for index := range rows {
		rows[index] = PairRow{ScenarioID: fmt.Sprintf("us005.pub.%04d", index), Input: fakeDigest(1), Before: fakeDigest(2), After: fakeDigest(2)}
	}
	evidence := Evidence{
		Schema: SchemaPath, SchemaVersion: "1.0.0", StoryID: "US-024", Status: "IMPLEMENTATION_REPLAY_PASS_PENDING_REVIEW_QA_REALITY", Assurance: assurance,
		Before:        Subject{Commit: beforeCommit, Tree: beforeTree, RustTree: fakeDigest(3), CargoLock: "sha256:4e889e0da92e71acff96ad07d7bc2ffcee24968fbb21d580b8b0c9aad9a043cb", Binary: fakeDigest(4), BinarySize: 1},
		After:         Subject{Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), RustTree: fakeDigest(5), CargoLock: "sha256:4e889e0da92e71acff96ad07d7bc2ffcee24968fbb21d580b8b0c9aad9a043cb", Binary: fakeDigest(6), BinarySize: 1},
		US023:         ImmutableUS023{TargetCommit: "1ff89fa30cb0ab6ff339afd3ce486a36e9f7f325", TargetTree: "dfb1950301e9680b1c47f0bd9debc0fc026d0e4f", CandidateRoot: candidateRoot, EvaluationRoot: evaluationRoot, SnapshotState: "FROZEN", ParityState: "BLOCKED", RequiredGates: 44, BlockedGates: 44, ProtectedFiles: []Artifact{artifact("assurance/candidate-manifest.json", "sha256:ab24fb6cbc3b811ef1d08c46c3c1b4925b03595836f5ccd65f0858fea66c9925"), artifact("evidence/parity-replay.json", "sha256:f2ca5d490429609977fc4782da3890e29629a9353fd5bfdc9bc6390a89c5f182"), artifact("evidence/java/behavior-delta-ledger.json", "sha256:e4800359d8a667524216b74947e43c169153406338398473221286bfbba9724a")}},
		Membership:    Membership{Production: []Artifact{artifact("rust/websocket-driver/src/lib.rs", fakeDigest(7)), artifact("rust/websocket-driver/src/output.rs", fakeDigest(8))}, Tests: []Artifact{artifact("rust/websocket-driver/tests/refinement_contract.rs", fakeDigest(9))}, Tools: []Artifact{}},
		PublicReplay:  PublicReplay{Kind: "FRESH_BEFORE_AFTER_PUBLIC_REPLAY", Counts: ReplayCounts{Expected: 74, Selected: 74, Executed: 74, Compared: 74, Equal: 74}, Rows: rows, ReverseAllEqual: true},
		LocalReplays:  []LocalReplay{},
		TestInventory: TestInventory{BeforeNames: []string{"internal/differential/differential_test.go::TestOld"}, AfterNames: []string{"internal/differential/differential_test.go::TestNew", "internal/differential/differential_test.go::TestOld"}, AddedNames: []string{"internal/differential/differential_test.go::TestNew"}},
		Connections:   Connections{FormalConnection: "DISCONNECTED_BLOCKED", FormalBackend: "NOT_EXECUTED", ProductionRefinement: "ABSENT", ConcurrencyConnection: "RETAINED_DIFFERENT_SUBJECT_BLOCKED", SystematicTests: "FRESH_LOCAL_TEST_REPLAY", FormalEquivalence: "NOT_CLAIMED"},
		Gates:         GateSummary{Counts: GateCounts{Required: 12, Passed: 4, Blocked: 8}, Blockers: []string{"A", "B", "C", "D", "E", "F", "G", "H"}},
		Provenance:    PhaseProvenance{Review: "NOT_EXECUTED", QA: "NOT_EXECUTED", Reality: "NOT_EXECUTED"},
		Nonclaims:     []string{"no fresh Java differential comparison", "no Autobahn or Docker/wstest rerun", "no hidden or sealed confirmation", "no formal proof or equivalence", "no independent host or human review", "no performance result", "no production, publication, signing, or cutover"},
	}
	for index := 0; index < 34; index++ {
		before := CommandResult{Status: "PASS", TestsPassed: 1}
		before.ResultSHA256 = commandResultDigest(before)
		after := CommandResult{Status: "PASS", TestsPassed: 1}
		after.ResultSHA256 = commandResultDigest(after)
		evidence.LocalReplays = append(evidence.LocalReplays, LocalReplay{Kind: "FRESH_LOCAL_TEST_REPLAY", Manifest: artifact("evidence/property/manifest.json", fakeDigest(14)), TargetID: fmt.Sprintf("property.target-%02d", index), Profile: "debug", Command: []string{"cargo", "test", "--locked"}, Repeat: 1, Before: before, After: after})
	}
	evidence.PublicReplay.ForwardRoot = replayRoot("us024-refinement-forward-v1", evidence.Before, evidence.After, rows, false)
	evidence.PublicReplay.ReverseRoot = replayRoot("us024-refinement-reverse-v1", evidence.Before, evidence.After, rows, true)
	return evidence
}

func cloneEvidence(t *testing.T, evidence Evidence) Evidence {
	t.Helper()
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var result Evidence
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestStaticVerifierRejectsDriftCanaries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Evidence)
	}{
		{"changed after observation", func(e *Evidence) { e.PublicReplay.Rows[0].After = fakeDigest(10) }},
		{"missing scenario", func(e *Evidence) { e.PublicReplay.Rows = e.PublicReplay.Rows[:73] }},
		{"duplicate scenario", func(e *Evidence) { e.PublicReplay.Rows[1].ScenarioID = e.PublicReplay.Rows[0].ScenarioID }},
		{"reordered scenario", func(e *Evidence) {
			e.PublicReplay.Rows[0], e.PublicReplay.Rows[1] = e.PublicReplay.Rows[1], e.PublicReplay.Rows[0]
		}},
		{"swapped binary identity malformed", func(e *Evidence) { e.Before.Binary = e.After.Commit }},
		{"deleted hostile test", func(e *Evidence) { e.Membership.Tests = nil }},
		{"changed candidate root", func(e *Evidence) { e.US023.CandidateRoot = fakeDigest(11) }},
		{"shortened ledger identity", func(e *Evidence) { e.US023.ProtectedFiles[2].Bytes = 0 }},
		{"rewritten ledger record", func(e *Evidence) { e.US023.ProtectedFiles[2].SHA256 = fakeDigest(12) }},
		{"path escape", func(e *Evidence) { e.Membership.Tests[0].Path = "../escape" }},
		{"zero executed", func(e *Evidence) { e.PublicReplay.Counts.Executed = 0 }},
		{"zero local tests executed", func(e *Evidence) { e.LocalReplays[0].Before.TestsPassed = 0 }},
		{"deleted allowed-file test name", func(e *Evidence) { e.TestInventory.AfterNames = e.TestInventory.AfterNames[:1] }},
		{"pass unavailable formal gate", func(e *Evidence) { e.Connections.FormalBackend = "PASS" }},
		{"changed cargo lock", func(e *Evidence) { e.After.CargoLock = fakeDigest(13) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := cloneEvidence(t, fixture())
			test.mutate(&evidence)
			if err := validateStatic(evidence); err == nil {
				t.Fatal("drift canary passed")
			}
		})
	}
}

func TestStrictDecoderRejectsDuplicateUnknownAndTrailingJSON(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"schema_version":"1.0.0","schema_version":"1.0.0"}`),
		[]byte(`{"unknown":true}`),
		[]byte(`{} {}`),
	} {
		var evidence Evidence
		if err := decodeStrict(raw, &evidence); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestVerifierRejectsOversizedReceiptBeforeFilesystemAccess(t *testing.T) {
	if err := Verify(t.TempDir(), make([]byte, maximumEvidence+1)); err == nil {
		t.Fatal("oversized receipt accepted")
	}
}

func TestCaptureRejectsDirtyOrNonGitSubjectIdentity(t *testing.T) {
	_, err := Capture(context.Background(), CaptureConfig{RepositoryRoot: t.TempDir(), BeforeCommit: "HEAD", AfterCommit: "dirty", Cargo: "/bin/false"})
	if err == nil {
		t.Fatal("symbolic or dirty source identity accepted")
	}
}

func TestFixtureIsValid(t *testing.T) {
	evidence := fixture()
	if err := validateStatic(evidence); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSchema(filepath.Clean("../.."), raw); err != nil {
		t.Fatal(err)
	}
}
