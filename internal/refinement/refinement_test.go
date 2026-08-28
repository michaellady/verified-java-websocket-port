package refinement

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
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
		Before:        Subject{Commit: beforeCommit, Tree: beforeTree, RustTree: fakeDigest(3), CargoLock: "sha256:4e889e0da92e71acff96ad07d7bc2ffcee24968fbb21d580b8b0c9aad9a043cb", Binary: fakeDigest(4), BinarySize: 1, BinaryCanonicalization: binaryCanonicalization},
		After:         Subject{Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), RustTree: fakeDigest(5), CargoLock: "sha256:4e889e0da92e71acff96ad07d7bc2ffcee24968fbb21d580b8b0c9aad9a043cb", Binary: fakeDigest(6), BinarySize: 1, BinaryCanonicalization: binaryCanonicalization},
		US023:         ImmutableUS023{TargetCommit: "1ff89fa30cb0ab6ff339afd3ce486a36e9f7f325", TargetTree: "dfb1950301e9680b1c47f0bd9debc0fc026d0e4f", CandidateRoot: candidateRoot, EvaluationRoot: evaluationRoot, SnapshotState: "FROZEN", ParityState: "BLOCKED", RequiredGates: 44, BlockedGates: 44, ProtectedFiles: []Artifact{artifact("assurance/candidate-manifest.json", "sha256:ab24fb6cbc3b811ef1d08c46c3c1b4925b03595836f5ccd65f0858fea66c9925"), artifact("evidence/parity-replay.json", "sha256:f2ca5d490429609977fc4782da3890e29629a9353fd5bfdc9bc6390a89c5f182"), artifact("evidence/java/behavior-delta-ledger.json", "sha256:e4800359d8a667524216b74947e43c169153406338398473221286bfbba9724a")}},
		Membership:    Membership{Production: []Artifact{artifact("rust/websocket-driver/src/lib.rs", fakeDigest(7)), artifact("rust/websocket-driver/src/output.rs", fakeDigest(8))}, Tests: []Artifact{artifact("rust/websocket-driver/tests/refinement_contract.rs", fakeDigest(9)), artifact("rust/websocket-testee/tests/process.rs", fakeDigest(10))}, Tools: []Artifact{}},
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
		{"promoted repository status", func(e *Evidence) { e.Status = "PASS_OWNER_RELAXED_MECHANICS" }},
		{"invented review provenance", func(e *Evidence) { e.Provenance.Review = "owner-review" }},
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

func TestFreshRederivationBindsEveryReceiptClaim(t *testing.T) {
	want := fixture()
	if err := verifyRederivedClaims(want, cloneEvidence(t, want)); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Evidence){
		func(e *Evidence) { e.Gates.Blockers[0] = "FORGED_BLOCKER" },
		func(e *Evidence) { e.Nonclaims[0] = "forged nonclaim" },
		func(e *Evidence) { e.Provenance.QA = "forged provenance" },
		func(e *Evidence) { e.Status = "PASS_OWNER_RELAXED_MECHANICS" },
	}
	for index, mutate := range mutations {
		got := cloneEvidence(t, want)
		mutate(&got)
		if err := verifyRederivedClaims(got, want); err == nil {
			t.Fatalf("unbound receipt claim %d", index)
		}
	}
}

func TestCargoEnvironmentIsClosedAndContained(t *testing.T) {
	t.Setenv("RUSTC_WRAPPER", "/tmp/poison")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/poison")
	root := t.TempDir()
	environment, err := cargoEnvironment(root, "/toolchain/bin/cargo")
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || values[key] != "" {
			t.Fatalf("malformed or duplicate environment entry %q", entry)
		}
		values[key] = value
	}
	for _, forbidden := range []string{"RUSTC_WRAPPER", "RUSTDOC_WRAPPER", "DYLD_INSERT_LIBRARIES", "CARGO_BUILD_RUSTC_WRAPPER"} {
		if _, ok := values[forbidden]; ok {
			t.Fatalf("ambient override survived: %s", forbidden)
		}
	}
	wantRoot := filepath.Join(root, "rust", "target", ".us024-environment")
	for _, key := range []string{"HOME", "CARGO_HOME", "TMPDIR"} {
		if !strings.HasPrefix(values[key], wantRoot+string(filepath.Separator)) {
			t.Fatalf("%s escaped the subject: %q", key, values[key])
		}
	}
	if values["PATH"] != "/toolchain/bin:/usr/bin:/bin" || values["RUSTC"] != "/toolchain/bin/rustc" || values["RUSTDOC"] != "/toolchain/bin/rustdoc" || len(values) != 14 {
		t.Fatalf("closed tool environment drift: %#v", values)
	}
	if !strings.Contains(values["RUSTFLAGS"], "-C strip=debuginfo") {
		t.Fatalf("debug paths remain in replay binaries: %q", values["RUSTFLAGS"])
	}
}

func TestDerivedInventoryCoversEveryChangedTestBearingSource(t *testing.T) {
	root := filepath.Clean("../..")
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Skip("Git metadata unavailable")
	}
	inventory, err := deriveTestInventory(root, beforeCommit, "579aa003760e6eac6a98d1d394fd07b81f447451")
	if err != nil {
		t.Fatal(err)
	}
	wantPrefixes := []string{
		"cmd/refinementctl/main_test.go::",
		"internal/refinement/refinement_test.go::",
		"rust/websocket-driver/src/lib.rs::",
		"rust/websocket-driver/tests/refinement_contract.rs::",
		"rust/websocket-testee/tests/process.rs::",
	}
	for _, prefix := range wantPrefixes {
		found := false
		for _, name := range inventory.AfterNames {
			if strings.HasPrefix(name, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("changed test-bearing path absent from inventory: %s", prefix)
		}
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

func TestMachOUUIDCanonicalizationIgnoresLinkerRandomness(t *testing.T) {
	makeBinary := func(uuidMarker, signatureMarker byte) []byte {
		raw := make([]byte, 128)
		binary.LittleEndian.PutUint32(raw[:4], 0xfeedfacf)
		binary.LittleEndian.PutUint32(raw[16:20], 2)
		binary.LittleEndian.PutUint32(raw[20:24], 40)
		binary.LittleEndian.PutUint32(raw[32:36], 0x1b)
		binary.LittleEndian.PutUint32(raw[36:40], 24)
		for index := 40; index < 56; index++ {
			raw[index] = uuidMarker
		}
		binary.LittleEndian.PutUint32(raw[56:60], 0x1d)
		binary.LittleEndian.PutUint32(raw[60:64], 16)
		binary.LittleEndian.PutUint32(raw[64:68], 96)
		binary.LittleEndian.PutUint32(raw[68:72], 32)
		for index := 96; index < 128; index++ {
			raw[index] = signatureMarker
		}
		return raw
	}
	paths := []string{filepath.Join(t.TempDir(), "left"), filepath.Join(t.TempDir(), "right")}
	for index, path := range paths {
		if err := os.WriteFile(path, makeBinary(byte(index+1), byte(index+11)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := canonicalizeMachOUUID(path); err != nil {
			t.Fatal(err)
		}
	}
	left, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	right, err := os.ReadFile(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left[40:56], right[40:56]) {
		t.Fatal("canonical UUID retains original UUID or signature bytes")
	}
	if bytes.Equal(left[96:128], right[96:128]) {
		t.Fatal("test fixture did not retain distinct signature blobs")
	}

	malformed := []struct {
		name   string
		mutate func([]byte)
	}{
		{"short signature command", func(raw []byte) { binary.LittleEndian.PutUint32(raw[60:64], 8) }},
		{"out of bounds signature", func(raw []byte) { binary.LittleEndian.PutUint32(raw[64:68], 120) }},
		{"multiple signatures", func(raw []byte) {
			binary.LittleEndian.PutUint32(raw[16:20], 3)
			binary.LittleEndian.PutUint32(raw[20:24], 56)
			binary.LittleEndian.PutUint32(raw[72:76], 0x1d)
			binary.LittleEndian.PutUint32(raw[76:80], 16)
			binary.LittleEndian.PutUint32(raw[80:84], 112)
			binary.LittleEndian.PutUint32(raw[84:88], 16)
		}},
	}
	for _, test := range malformed {
		t.Run(test.name, func(t *testing.T) {
			raw := makeBinary(1, 2)
			test.mutate(raw)
			path := filepath.Join(t.TempDir(), "malformed")
			if err := os.WriteFile(path, raw, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := canonicalizeMachOUUID(path); err == nil {
				t.Fatal("malformed code-signature command accepted")
			}
		})
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
