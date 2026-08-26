package formal

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

func TestUS006SyntheticExecutedMethodFixturesAreMechanicallyValidAndNonClaiming(t *testing.T) {
	for _, backendID := range []string{
		"backend.finite-mask-prototype",
		"backend.loom-concurrency",
		"backend.tlc-connection-model",
	} {
		t.Run(backendID, func(t *testing.T) {
			root := copyFixtureRoot(t)
			makeSyntheticExecutedBackend(t, root, backendID)
			var qualification backendQualification
			if err := decodeStrict(readFile(t, filepath.Join(root, backendQualificationPath)), &qualification); err != nil {
				t.Fatal(err)
			}
			if backendPointer(t, &qualification, backendID).ClaimScope != "UNAVAILABLE_BACKEND_BLOCKED" {
				t.Fatal("synthetic executed fixture must retain the explicit blocked scope")
			}
			for _, mode := range []string{ModePreflight, ModeReplay} {
				verdict, err := Validate(context.Background(), Request{RootPath: root, Mode: mode})
				if err != nil {
					t.Fatal(err)
				}
				if !verdict.Valid || verdict.State != "BLOCKED" || len(verdict.Findings) != 0 {
					t.Fatalf("%s verdict = %#v, want valid BLOCKED with other unavailable backends scoped", mode, verdict)
				}
				if backendID == "backend.finite-mask-prototype" && contains(verdict.ClaimScopes, "BOUNDED_TEST_EVIDENCE") ||
					backendID == "backend.tlc-connection-model" && contains(verdict.ClaimScopes, "PROVED_MODEL") {
					t.Fatalf("%s synthetic backend emitted a claim-bearing scope: %v", mode, verdict.ClaimScopes)
				}
			}
		})
	}
}

func TestUS006ExecutedPassRejectsCounterexampleOutcomeAndAggregate(t *testing.T) {
	root := copyFixtureRoot(t)
	makeSyntheticExecutedBackend(t, root, "backend.finite-mask-prototype")
	path := filepath.Join(root, backendQualificationPath)
	var qualification backendQualification
	if err := decodeStrict(readFile(t, path), &qualification); err != nil {
		t.Fatal(err)
	}
	backend := backendPointer(t, &qualification, "backend.finite-mask-prototype")
	outcome := &backend.Outcomes[0]
	outcome.RawOutcome = "COUNTEREXAMPLE"
	outcome.Counterexample = syntheticOutcomeCounterexample(t, *backend, *outcome, backend.KnownBadCanaries[0].Counterexample.Artifact)
	writeTypedQualification(t, path, qualification)

	verdict, err := Validate(context.Background(), Request{RootPath: root, Mode: ModeReplay})
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(verdict.Findings, "COUNTEREXAMPLE_STATE_MISMATCH") || verdict.State != "BLOCKED" {
		t.Fatalf("verdict = %#v, want counterexample state mismatch and blocked aggregate", verdict)
	}
}

func TestUS006ExecutedReceiptAndReplayCannotBeSelfAsserted(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		mutate func(*backend)
	}{
		{
			name: "cleanup flag without receipt", reason: "MISSING_REQUIRED_ARTIFACT",
			mutate: func(backend *backend) { backend.SBXExecution.CleanupReceipt = nil },
		},
		{
			name: "reconciled flag without second run", reason: "REPLAY_MISMATCH",
			mutate: func(backend *backend) { backend.Replay.Runs = backend.Replay.Runs[:1] },
		},
		{
			name: "counterexample identity substitution", reason: "REPLAY_MISMATCH",
			mutate: func(backend *backend) {
				backend.KnownBadCanaries[0].Counterexample.CounterexampleID = "counterexample.0000000000000000"
			},
		},
		{
			name: "generic receipt reused as input manifest", reason: "EXECUTION_RECEIPT_INVALID",
			mutate: func(backend *backend) {
				backend.SBXExecution.InputManifest = backend.SBXExecution.Receipt
				backend.SBXExecution.InputRootDigest = backend.SBXExecution.ReceiptDigest
				for index := range backend.ArtifactBindings {
					if backend.ArtifactBindings[index].Category == "INPUT_MANIFEST" {
						backend.ArtifactBindings[index].Artifact = *backend.SBXExecution.Receipt
					}
				}
			},
		},
		{
			name: "synthetic evidence promoted to method claim", reason: "INFLATED_CLAIM",
			mutate: func(backend *backend) {
				backend.ClaimScope = executedScope(backend.Method)
				for index := range backend.Outcomes {
					backend.Outcomes[index].ClaimScope = backend.ClaimScope
				}
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := copyFixtureRoot(t)
			makeSyntheticExecutedBackend(t, root, "backend.finite-mask-prototype")
			path := filepath.Join(root, backendQualificationPath)
			var qualification backendQualification
			if err := decodeStrict(readFile(t, path), &qualification); err != nil {
				t.Fatal(err)
			}
			test.mutate(backendPointer(t, &qualification, "backend.finite-mask-prototype"))
			writeTypedQualification(t, path, qualification)
			verdict, err := Validate(context.Background(), Request{RootPath: root, Mode: ModeReplay})
			if err != nil {
				t.Fatal(err)
			}
			if !hasReason(verdict.Findings, test.reason) {
				t.Fatalf("findings = %#v, want %s", verdict.Findings, test.reason)
			}
		})
	}
}

func TestUS006ResolvedLinkageRequiresExactReachableEdgeChain(t *testing.T) {
	edges := []linkageEdge{{From: "consumer::entry", To: "adapter::step"}, {From: "adapter::step", To: "production::target"}}
	if !linkageReachable("consumer::entry", "production::target", edges) {
		t.Fatal("exact edge chain should reach the production target")
	}
	if linkageReachable("consumer::entry", "production::target_v2", edges) {
		t.Fatal("filename or symbol-prefix similarity must not satisfy linkage")
	}
	if linkageReachable("consumer::entry", "production::target", append(edges, edges[0])) {
		t.Fatal("duplicate receipt edges must not satisfy strict linkage")
	}
}

func TestUS006SyntheticOrUnprovenancedLinkageCannotResolveProduction(t *testing.T) {
	receipt := linkageReceiptDocument{
		FixtureKind: "PUBLIC_LINKAGE_RECEIPT", Provenance: "PUBLIC_DERIVED_SOURCE_TREE",
		SourceTree: artifactRef{Attribution: "PUBLIC_SOURCE_TREE"},
	}
	if !claimBearingLinkage(receipt) {
		t.Fatal("accepted public linkage provenance should be claim-bearing")
	}
	receipt.FixtureKind = "SYNTHETIC_NON_CLAIM"
	if claimBearingLinkage(receipt) {
		t.Fatal("synthetic linkage must not resolve production")
	}
	receipt.FixtureKind = "PUBLIC_LINKAGE_RECEIPT"
	receipt.Provenance = ""
	if claimBearingLinkage(receipt) {
		t.Fatal("empty linkage provenance must not resolve production")
	}
}

func TestUS006TLAConcurrencyShutdownShapeIsFrozen(t *testing.T) {
	canonical := string(readFile(t, filepath.Join(repositoryRoot(t), connectionModelPath)))
	mutations := map[string][2]string{
		"accept while closing":       {"/\\ state = \"Open\"\n    /\\ shutdownRequested = FALSE", "/\\ state \\in {\"Open\", \"Closing\"}\n    /\\ shutdownRequested = FALSE"},
		"duplicate terminal enqueue": {"/\\ state \\in {\"Open\", \"Closing\"}\n    /\\ terminalQueued = FALSE", "/\\ state \\in {\"Open\", \"Closing\"}"},
		"close before event drain":   {"/\\ Len(writeQ) = 0\n    /\\ Len(eventQ) = 0", "/\\ Len(writeQ) = 0"},
		"unfair final close":         {"/\\ WF_vars(FinishClose)", "/\\ WF_vars(ApplyBackpressure)"},
	}
	if err := validateTLA([]byte(canonical)); err != nil {
		t.Fatalf("canonical TLA shape: %v", err)
	}
	for name, replacement := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := strings.Replace(canonical, replacement[0], replacement[1], 1)
			if mutated == canonical {
				t.Fatal("test mutation did not match canonical model")
			}
			if err := validateTLA([]byte(mutated)); err == nil {
				t.Fatal("unsafe TLA transition shape was accepted")
			}
		})
	}
}

func makeSyntheticExecutedBackend(t *testing.T, root, backendID string) {
	t.Helper()
	qualificationPath := filepath.Join(root, backendQualificationPath)
	var qualification backendQualification
	if err := decodeStrict(readFile(t, qualificationPath), &qualification); err != nil {
		t.Fatal(err)
	}
	backend := backendPointer(t, &qualification, backendID)
	short := strings.TrimPrefix(backendID, "backend.")
	runID := "run." + short + ".primary"
	fixtureDirectory := filepath.Join("assurance/formal/fixtures/runtime", short)

	toolRef := writeFixtureArtifact(t, root, filepath.Join(fixtureDirectory, "tool-binary.json"), map[string]any{
		"fixture_kind": "SYNTHETIC_NON_CLAIM", "tool_binary": backend.Tool.Name,
	})
	toolVersion := "fixture-1.0.0"
	toolCommit := strings.Repeat("a", 40)
	backend.Tool.Version = &toolVersion
	backend.Tool.Commit = &toolCommit
	backend.Tool.BinarySHA256 = &toolRef.SHA256
	backend.Tool.ExecutablePromotion = &toolRef
	writeRole := func(role, state, name string) artifactRef {
		return writeFixtureEvidence(t, root, filepath.Join(fixtureDirectory, name), qualification, *backend, runID, role, state)
	}
	profileRef := writeRole("SBX_PROFILE", "QUALIFIED", "profile.json")
	capabilityRef := writeRole("CAPABILITY_PROBE", "SUCCEEDED", "capability-probe.json")
	requestRef := writeRole("SBX_REQUEST", "ACCEPTED", "request.json")
	receiptRef := writeRole("SBX_RECEIPT", "SUCCEEDED", "sbx-receipt.json")
	inputRef := writeRole("INPUT_MANIFEST", "SEALED", "input-manifest.json")
	outputRef := writeRole("OUTPUT_MANIFEST", "SEALED", "output-manifest.json")
	cleanupRef := writeRole("CLEANUP_RECEIPT", "CLEAN", "cleanup-receipt.json")
	classifierRef := writeRole("CLASSIFIER_PROJECTION", "PUBLIC_DERIVED", "classifier-projection.json")
	toolIdentityRef := writeRole("TOOL_IDENTITY", "QUALIFIED", "tool-identity.json")
	obligationRef := writeRole("OBLIGATION_INVENTORY", "SEALED", "obligation-inventory.json")
	goodRef := writeRole("GOOD_CANARY_RESULT", "PASS", "good-canary-result.json")
	badRef := writeRole("BAD_CANARY_COUNTEREXAMPLE", "COUNTEREXAMPLE", "bad-canary-counterexample.json")
	rawRef := writeRole("RAW_TOOL_RESULT", "PASS", "raw-tool-result.json")
	exitCode := 0
	backend.AvailabilityProbe = availabilityProbe{Executed: true, Receipt: &capabilityRef, ExitCode: &exitCode, Observation: "CAPABILITY_PROBE_EXECUTED_PASS"}
	cliVersion := qualification.BorrowedSandboxFoundation.CLIVersion
	daemonVersion := qualification.BorrowedSandboxFoundation.DaemonVersion
	template := qualification.BorrowedSandboxFoundation.TemplateReference
	policy := qualification.BorrowedSandboxFoundation.SandboxPolicyDigest
	clean := "CLEAN"
	classified := "PUBLIC_DERIVED"
	backend.SBXExecution = sbxExecution{
		CLIVersion: &cliVersion, DaemonVersion: &daemonVersion, TemplateReference: &template, SandboxPolicyDigest: &policy,
		RequestDigest: &requestRef.SHA256, ReceiptDigest: &receiptRef.SHA256,
		InputRootDigest: &inputRef.SHA256, OutputRootDigest: &outputRef.SHA256,
		CleanupState: &clean, ClassificationState: &classified,
		Profile: &profileRef, CapabilityProbe: &capabilityRef, Request: &requestRef, Receipt: &receiptRef,
		InputManifest: &inputRef, OutputManifest: &outputRef, CleanupReceipt: &cleanupRef, ClassifierProjection: &classifierRef,
	}
	backend.ExecutionState = "EXECUTED_PASS"
	backend.ClaimScope = "UNAVAILABLE_BACKEND_BLOCKED"
	setExecutedCount(t, backend)

	normalized := syntheticEvidenceDocument(qualification, *backend, runID, "NORMALIZED_RESULT", "PASS")
	normalizedOne := writeFixtureArtifact(t, root, filepath.Join(fixtureDirectory, "normalized-run-1.json"), normalized)
	normalizedTwo := writeFixtureArtifact(t, root, filepath.Join(fixtureDirectory, "normalized-run-2.json"), normalized)
	if normalizedOne.SHA256 != normalizedTwo.SHA256 {
		t.Fatal("synthetic normalized outputs are not byte-identical")
	}
	for index := range backend.KnownGoodCanaries {
		backend.KnownGoodCanaries[index].ObservedOutcome = "PASS"
		backend.KnownGoodCanaries[index].Output = &goodRef
	}
	for index := range backend.KnownBadCanaries {
		canary := &backend.KnownBadCanaries[index]
		canary.ObservedOutcome = "COUNTEREXAMPLE"
		canary.Output = &badRef
		canary.Counterexample = syntheticCanaryCounterexample(t, *backend, *canary, badRef)
	}
	passOutcome := methodPassOutcome(backend.Method)
	for index := range backend.Outcomes {
		backend.Outcomes[index].RawOutcome = passOutcome
		backend.Outcomes[index].ClaimScope = "UNAVAILABLE_BACKEND_BLOCKED"
		backend.Outcomes[index].ArtifactRefs = []artifactRef{normalizedOne}
		backend.Outcomes[index].Counterexample = nil
	}
	seed := "synthetic-fixed-seed"
	backend.Replay = replay{
		Argv: []string{"fixture-only-no-execution"}, Environment: []string{"FIXTURE=SYNTHETIC_NON_CLAIM"},
		WorkingDirectory: ".", Seed: &seed, ExpectedExitCode: &exitCode,
		SemanticOutputDigest: &normalizedOne.SHA256, RepeatCount: 2, ReconciledIdentically: true,
	}
	replayID, err := replayDigest(&qualification, backend)
	if err != nil {
		t.Fatal(err)
	}
	backend.Replay.ReplayID = &replayID
	backend.Replay.Runs = []replayRun{
		writeReplayRun(t, root, fixtureDirectory, *backend, "run."+short+".one", normalizedOne, 1),
		writeReplayRun(t, root, fixtureDirectory, *backend, "run."+short+".two", normalizedTwo, 2),
	}

	categoryRefs := map[string]artifactRef{
		"SBX_REQUEST": requestRef, "SBX_RECEIPT": receiptRef, "TOOL_IDENTITY": toolIdentityRef,
		"INPUT_MANIFEST": inputRef, "OUTPUT_MANIFEST": outputRef, "OBLIGATION_INVENTORY": obligationRef,
		"GOOD_CANARY_RESULT": goodRef, "BAD_CANARY_COUNTEREXAMPLE": badRef,
		"RAW_TOOL_RESULT": rawRef, "NORMALIZED_RESULT": normalizedOne,
		"REPLAY_RECEIPT": backend.Replay.Runs[0].Receipt, "CLEANUP_RECEIPT": cleanupRef,
		"CLASSIFIER_PROJECTION": classifierRef,
	}
	backend.ArtifactBindings = make([]evidenceBinding, 0, len(requiredBackendArtifacts))
	for _, category := range requiredBackendArtifacts {
		backend.ArtifactBindings = append(backend.ArtifactBindings, evidenceBinding{Category: category, RunID: runID, Artifact: categoryRefs[category]})
	}
	sort.Slice(backend.ArtifactBindings, func(i, j int) bool {
		return backend.ArtifactBindings[i].Category < backend.ArtifactBindings[j].Category
	})
	writeTypedQualification(t, qualificationPath, qualification)
}

func writeReplayRun(t *testing.T, root, directory string, backend backend, runID string, normalized artifactRef, ordinal int) replayRun {
	t.Helper()
	receipt := replayReceiptDocument{
		SchemaVersion: "1.0.0", EntityType: "FormalReplayReceipt", FixtureKind: "SYNTHETIC_NON_CLAIM", Provenance: "SYNTHETIC_TEST_FIXTURE",
		BackendID: backend.BackendID, RunID: runID, ReplayID: *backend.Replay.ReplayID,
		ExitCode: *backend.Replay.ExpectedExitCode, ObligationIDs: append([]string(nil), backend.ObligationIDs...),
		SemanticOutputDigest: normalized.SHA256, NormalizedOutput: normalized,
		Assurance: assuranceCeiling, IndependentReviewClaimed: false, Production: false,
	}
	receiptRef := writeFixtureArtifact(t, root, filepath.Join(directory, "replay-receipt-"+string(rune('0'+ordinal))+".json"), receipt)
	return replayRun{RunID: runID, Receipt: receiptRef, NormalizedOutput: normalized, SemanticOutputDigest: normalized.SHA256, ObligationIDs: append([]string(nil), backend.ObligationIDs...)}
}

func writeFixtureEvidence(t *testing.T, root, path string, qualification backendQualification, backend backend, runID, role, state string) artifactRef {
	t.Helper()
	return writeFixtureArtifact(t, root, path, syntheticEvidenceDocument(qualification, backend, runID, role, state))
}

func syntheticEvidenceDocument(qualification backendQualification, backend backend, runID, role, state string) evidenceArtifactDocument {
	return evidenceArtifactDocument{
		SchemaVersion: "1.0.0", EntityType: "FormalEvidenceArtifact", FixtureKind: "SYNTHETIC_NON_CLAIM", Provenance: "SYNTHETIC_TEST_FIXTURE",
		Role: role, State: state, BackendID: backend.BackendID, Method: backend.Method, RunID: runID,
		ToolName: backend.Tool.Name, ToolVersion: *backend.Tool.Version, ToolBinarySHA256: *backend.Tool.BinarySHA256,
		CLIVersion: qualification.BorrowedSandboxFoundation.CLIVersion, DaemonVersion: qualification.BorrowedSandboxFoundation.DaemonVersion,
		TemplateReference: qualification.BorrowedSandboxFoundation.TemplateReference, SandboxPolicyDigest: qualification.BorrowedSandboxFoundation.SandboxPolicyDigest,
		ObligationIDs: append([]string(nil), backend.ObligationIDs...), Assurance: assuranceCeiling, IndependentReviewClaimed: false, Production: false,
	}
}

func syntheticCanaryCounterexample(t *testing.T, backend backend, canary canary, artifact artifactRef) *counterexample {
	t.Helper()
	value := &counterexample{Reason: "SEEDED_DEFECT_DETECTED", TargetSymbol: methodTarget(backend.Method), Input: "synthetic seeded-bad input", Steps: []string{"inject defect", "observe invariant violation"}, Artifact: artifact}
	tuple := struct {
		BackendID string          `json:"backend_id"`
		CanaryID  string          `json:"canary_id"`
		Input     artifactRef     `json:"input"`
		Bounds    json.RawMessage `json:"bounds"`
		Reason    string          `json:"reason"`
		Target    string          `json:"target"`
		Steps     []string        `json:"steps"`
	}{backend.BackendID, canary.CanaryID, canary.Input, backend.Bounds, value.Reason, value.TargetSymbol, value.Steps}
	value.CounterexampleID = digestCounterexampleTuple(t, tuple)
	return value
}

func syntheticOutcomeCounterexample(t *testing.T, backend backend, outcome outcome, artifact artifactRef) *counterexample {
	t.Helper()
	value := &counterexample{Reason: "IMPLEMENTATION_COUNTEREXAMPLE", TargetSymbol: methodTarget(backend.Method), Input: "synthetic obligation input", Steps: []string{"evaluate obligation", "observe counterexample"}, Artifact: artifact}
	tuple := struct {
		BackendID  string          `json:"backend_id"`
		Obligation string          `json:"obligation_id"`
		Input      string          `json:"input"`
		Bounds     json.RawMessage `json:"bounds"`
		Reason     string          `json:"reason"`
		Target     string          `json:"target"`
		Steps      []string        `json:"steps"`
	}{backend.BackendID, outcome.ObligationID, value.Input, backend.Bounds, value.Reason, value.TargetSymbol, value.Steps}
	value.CounterexampleID = digestCounterexampleTuple(t, tuple)
	return value
}

func digestCounterexampleTuple(t *testing.T, value any) string {
	t.Helper()
	data, err := vendorprotocol.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return "counterexample." + strings.TrimPrefix(vendorprotocol.DigestBytes(data), "sha256:")[:16]
}

func writeFixtureArtifact(t *testing.T, root, relative string, value any) artifactRef {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	rendered := append(data, '\n')
	writeFile(t, path, rendered)
	return artifactRef{Path: relative, SHA256: vendorprotocol.DigestBytes(rendered), Attribution: "US006_OWNED"}
}

func backendPointer(t *testing.T, qualification *backendQualification, id string) *backend {
	t.Helper()
	for index := range qualification.Backends {
		if qualification.Backends[index].BackendID == id {
			return &qualification.Backends[index]
		}
	}
	t.Fatalf("backend %s not found", id)
	return nil
}

func writeTypedQualification(t *testing.T, path string, qualification backendQualification) {
	t.Helper()
	data, err := json.MarshalIndent(qualification, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, append(data, '\n'))
}

func setExecutedCount(t *testing.T, backend *backend) {
	t.Helper()
	var bounds map[string]any
	if err := json.Unmarshal(backend.Bounds, &bounds); err != nil {
		t.Fatal(err)
	}
	switch backend.Method {
	case "FINITE_EXHAUSTIVE_PROTOTYPE", "KANI_BOUNDED_MODEL_CHECKING":
		bounds["cases_evaluated"] = float64(1)
	case "LOOM_SYSTEMATIC_SCHEDULE_EXPLORATION":
		bounds["schedule_count"] = float64(1)
	case "TLC_EXPLICIT_STATE_MODEL_CHECKING":
		bounds["distinct_states"] = float64(1)
		bounds["transitions"] = float64(1)
	}
	data, err := json.Marshal(bounds)
	if err != nil {
		t.Fatal(err)
	}
	backend.Bounds = data
}

func executedScope(method string) string {
	switch method {
	case "FINITE_EXHAUSTIVE_PROTOTYPE", "KANI_BOUNDED_MODEL_CHECKING":
		return "BOUNDED_TEST_EVIDENCE"
	case "LOOM_SYSTEMATIC_SCHEDULE_EXPLORATION":
		return "SYSTEMATIC_CONCURRENCY_TESTING"
	case "TLC_EXPLICIT_STATE_MODEL_CHECKING":
		return "PROVED_MODEL"
	default:
		return ""
	}
}

func methodPassOutcome(method string) string {
	switch method {
	case "FINITE_EXHAUSTIVE_PROTOTYPE", "KANI_BOUNDED_MODEL_CHECKING":
		return "BOUNDED_CHECK_PASSED"
	case "LOOM_SYSTEMATIC_SCHEDULE_EXPLORATION":
		return "SYSTEMATIC_EXPLORATION_PASSED"
	case "TLC_EXPLICIT_STATE_MODEL_CHECKING":
		return "MODEL_CHECK_PASSED"
	default:
		return ""
	}
}

func methodTarget(method string) string {
	switch method {
	case "FINITE_EXHAUSTIVE_PROTOTYPE", "KANI_BOUNDED_MODEL_CHECKING":
		return "websocket_core::frame::mask::apply_mask_in_place"
	case "LOOM_SYSTEMATIC_SCHEDULE_EXPLORATION":
		return "websocket_driver::owner::ConnectionOwner::step"
	case "TLC_EXPLICIT_STATE_MODEL_CHECKING":
		return "ConnectionModel"
	default:
		return ""
	}
}
