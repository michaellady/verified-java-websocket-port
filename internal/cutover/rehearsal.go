package cutover

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

const (
	MechanicsPass  = "PASS_OWNER_RELAXED_REHEARSAL_MECHANICS"
	CutoverBlocked = "CUTOVER_BLOCKED"
	Assurance      = "OWNER_ATTESTED_NOT_INDEPENDENT"
	SubjectCommit  = "84935acb5665ed50bd5eb718e918ed19adfcc646"
	SubjectTree    = "838fd4f551312447af3be1958916a1c5c2b5c885"
)

type FailureCode string

const (
	FailureInputAbsent              FailureCode = "INPUT_ABSENT"
	FailureInputSymlinkOrNonregular FailureCode = "INPUT_SYMLINK_OR_NONREGULAR"
	FailureInputDigestMismatch      FailureCode = "INPUT_DIGEST_MISMATCH"
	FailureSubjectMismatch          FailureCode = "SUBJECT_MISMATCH"
	FailureContractMismatch         FailureCode = "CONTRACT_MISMATCH"
	FailureFixtureMismatch          FailureCode = "FIXTURE_MISMATCH"
	FailureStateSkipOrReorder       FailureCode = "STATE_SKIP_OR_REORDER"
	FailureRouteCountMismatch       FailureCode = "ROUTE_COUNT_MISMATCH"
	FailureArtifactDrift            FailureCode = "ARTIFACT_DRIFT"
	FailureCaptureLocked            FailureCode = "CAPTURE_LOCKED"
	FailureCutoverReadyForbidden    FailureCode = "CUTOVER_READY_FORBIDDEN"
	FailureResourceFixturePromoted  FailureCode = "RESOURCE_FIXTURE_PROMOTED"
	FailureFailedAttemptNotRetained FailureCode = "FAILED_ATTEMPT_NOT_RETAINED"
)

type Failure struct {
	Code FailureCode
	Err  error
}

func (failure *Failure) Error() string {
	if failure.Err == nil {
		return string(failure.Code)
	}
	return fmt.Sprintf("%s: %v", failure.Code, failure.Err)
}

func (failure *Failure) Unwrap() error { return failure.Err }

func fail(code FailureCode, format string, args ...any) error {
	return &Failure{Code: code, Err: fmt.Errorf(format, args...)}
}

type Summary struct {
	MechanicsStatus            string `json:"mechanics_status"`
	CutoverAcceptance          string `json:"cutover_acceptance"`
	ShadowComparisons          int    `json:"shadow_comparisons"`
	RustSelections             int    `json:"rust_selections"`
	FailedAttempts             int    `json:"failed_attempts"`
	RollbackActions            int    `json:"rollback_actions"`
	SoakTicks                  int    `json:"soak_ticks"`
	ReconciledEffects          int    `json:"reconciled_effects"`
	DuplicateEffectsSuppressed int    `json:"duplicate_effects_suppressed"`
}

type inputBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type subjectIdentity struct {
	Commit string `json:"commit"`
	Tree   string `json:"tree"`
}

type requestFixture struct {
	RequestID      string `json:"request_id"`
	IdempotencyKey string `json:"idempotency_key"`
	InputSHA256    string `json:"input_sha256"`
	SemanticSHA256 string `json:"semantic_sha256"`
	EffectSHA256   string `json:"effect_sha256"`
	RetryOf        string `json:"retry_of"`
}

type fixtureSpec struct {
	Label                  string           `json:"label"`
	Requests               []requestFixture `json:"requests"`
	RouteProjection        string           `json:"route_projection"`
	RustSelectionCount     int              `json:"rust_selection_count"`
	RustSelectedRequestIDs []string         `json:"rust_selected_request_ids"`
	NominalTrace           []string         `json:"nominal_trace"`
	MismatchTrace          []string         `json:"mismatch_trace"`
	RollbackActions        []string         `json:"rollback_actions"`
	SoakTicks              int              `json:"soak_ticks"`
}

type javaFallbackFact struct {
	RouteTarget                   string `json:"route_target"`
	SourceIdentitySHA256          string `json:"source_identity_sha256"`
	BuildInputPath                string `json:"build_input_path"`
	BuildInputSHA256              string `json:"build_input_sha256"`
	ExecutablePresenceFact        string `json:"executable_presence_fact"`
	JavaFallbackExecutableDrilled bool   `json:"java_fallback_executable_drilled"`
}

type contractDocument struct {
	Schema                   string             `json:"$schema"`
	SchemaID                 string             `json:"schema"`
	StoryID                  string             `json:"story_id"`
	ContractID               string             `json:"contract_id"`
	Subject                  subjectIdentity    `json:"subject"`
	AuthoritativeInputs      []inputBinding     `json:"authoritative_inputs"`
	RejectedAuthorities      []string           `json:"rejected_authorities"`
	FixtureSHA256            string             `json:"fixture_sha256"`
	Fixture                  fixtureSpec        `json:"fixture"`
	JavaFallback             javaFallbackFact   `json:"java_fallback"`
	CanonicalReadinessLadder []string           `json:"canonical_readiness_ladder"`
	MechanicsStatusCeiling   string             `json:"mechanics_status_ceiling"`
	CutoverAcceptanceCeiling string             `json:"cutover_acceptance_ceiling"`
	ProductionShapedEnv      string             `json:"production_shaped_environment"`
	LiveTrafficExecuted      bool               `json:"live_traffic_executed"`
	LiveSideEffectsExecuted  bool               `json:"live_side_effects_executed"`
	ResourceEvidenceKind     string             `json:"resource_evidence_kind"`
	CutoverReadyReachable    bool               `json:"cutover_ready_reachable"`
	Assurance                string             `json:"assurance"`
	IndependentReviewClaimed bool               `json:"independent_review_claimed"`
	Provenance               producerProvenance `json:"provenance"`
}

type producerProvenance struct {
	Review  string `json:"review"`
	QA      string `json:"qa"`
	Reality string `json:"reality"`
}

type comparison struct {
	RequestID          string `json:"request_id"`
	JavaSemanticSHA256 string `json:"java_semantic_sha256"`
	RustSemanticSHA256 string `json:"rust_semantic_sha256"`
	JavaEffectSHA256   string `json:"java_effect_sha256"`
	RustEffectSHA256   string `json:"rust_effect_sha256"`
	CPUFixtureUnits    int    `json:"cpu_fixture_units"`
	MemoryFixtureUnits int    `json:"memory_fixture_units"`
	BackpressureUnits  int    `json:"backpressure_units"`
	Equal              bool   `json:"equal"`
}

type failedAttempt struct {
	RequestID              string `json:"request_id"`
	Route                  string `json:"route"`
	Reason                 string `json:"reason"`
	ExpectedSemantic       string `json:"expected_semantic_sha256"`
	ObservedSemantic       string `json:"observed_semantic_sha256"`
	Preserved              bool   `json:"preserved"`
	RealEffectCommitted    bool   `json:"real_effect_committed"`
	FixtureEffectCommitted bool   `json:"fixture_effect_committed"`
}

type effectRecord struct {
	IdempotencyKey string `json:"idempotency_key"`
	EffectSHA256   string `json:"effect_sha256"`
	Route          string `json:"route"`
}

type tickRecord struct {
	Tick              int `json:"tick"`
	QueueFixtureUnits int `json:"queue_fixture_units"`
	ErrorFixtureCount int `json:"error_fixture_count"`
	BackpressureUnits int `json:"backpressure_units"`
}

type phaseRun struct {
	RunID                      string          `json:"run_id"`
	Outcome                    string          `json:"outcome"`
	States                     []string        `json:"states"`
	RequestIDs                 []string        `json:"request_ids"`
	SelectedRequestIDs         []string        `json:"selected_request_ids"`
	RustAttemptedRequestIDs    []string        `json:"rust_attempted_request_ids"`
	Comparisons                []comparison    `json:"comparisons"`
	IsolatedEffectCount        int             `json:"isolated_effect_count"`
	FailedAttempts             []failedAttempt `json:"failed_attempts"`
	CommittedFixtureEffects    []effectRecord  `json:"committed_fixture_effects"`
	ExpectedEffectCount        int             `json:"expected_effect_count"`
	MissingEffectCount         int             `json:"missing_effect_count"`
	ExtraEffectCount           int             `json:"extra_effect_count"`
	DuplicateEffectsSuppressed int             `json:"duplicate_effects_suppressed"`
	RollbackActions            []string        `json:"rollback_actions"`
	Ticks                      []tickRecord    `json:"ticks"`
	SoakResult                 string          `json:"soak_result"`
}

type phaseReceipt struct {
	Schema                   string          `json:"$schema"`
	SchemaID                 string          `json:"schema"`
	StoryID                  string          `json:"story_id"`
	Phase                    string          `json:"phase"`
	ContractSHA256           string          `json:"contract_sha256"`
	FixtureSHA256            string          `json:"fixture_sha256"`
	PredecessorPath          string          `json:"predecessor_path"`
	PredecessorSHA256        string          `json:"predecessor_sha256"`
	Subject                  subjectIdentity `json:"subject"`
	Runs                     []phaseRun      `json:"runs"`
	MechanicsStatus          string          `json:"mechanics_status"`
	CutoverAcceptance        string          `json:"cutover_acceptance"`
	ResourceEvidenceKind     string          `json:"resource_evidence_kind"`
	LiveTrafficExecuted      bool            `json:"live_traffic_executed"`
	LiveSideEffectsExecuted  bool            `json:"live_side_effects_executed"`
	CutoverReadyReached      bool            `json:"cutover_ready_reached"`
	Assurance                string          `json:"assurance"`
	IndependentReviewClaimed bool            `json:"independent_review_claimed"`
}

type artifactDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type evidenceDocument struct {
	Schema                   string             `json:"$schema"`
	SchemaID                 string             `json:"schema"`
	StoryID                  string             `json:"story_id"`
	Subject                  subjectIdentity    `json:"subject"`
	Artifacts                []artifactDigest   `json:"artifacts"`
	Summary                  Summary            `json:"summary"`
	MechanicsStatus          string             `json:"mechanics_status"`
	CutoverAcceptance        string             `json:"cutover_acceptance"`
	CutoverReadyReached      bool               `json:"cutover_ready_reached"`
	Assurance                string             `json:"assurance"`
	IndependentReviewClaimed bool               `json:"independent_review_claimed"`
	Production               bool               `json:"production"`
	Signing                  bool               `json:"signing"`
	Publication              bool               `json:"publication"`
	Blockers                 []string           `json:"blockers"`
	Nonclaims                []string           `json:"nonclaims"`
	Provenance               producerProvenance `json:"provenance"`
}

type namedArtifact struct {
	path  string
	bytes []byte
}

type artifactSet struct {
	artifacts []namedArtifact
	summary   Summary
}

var nominalTrace = []string{
	"SOURCE_QUALIFIED", "SNAPSHOT_BOUND", "FIXTURE_READY", "SHADOW_VERIFIED_FIXTURE",
	"CANARY_VERIFIED_FIXTURE", "SOAK_VERIFIED_FIXTURE", "REHEARSAL_MECHANICS_COMPLETE", "CUTOVER_BLOCKED",
}

var mismatchTrace = []string{
	"SOURCE_QUALIFIED", "SNAPSHOT_BOUND", "FIXTURE_READY", "SHADOW_VERIFIED_FIXTURE",
	"CANARY_ABORTED_FIXTURE", "JAVA_FALLBACK_SELECTED_FIXTURE", "FALLBACK_RECONCILED_FIXTURE", "CUTOVER_BLOCKED",
}

var canonicalReadinessLadder = []string{
	"SOURCE_QUALIFIED", "SEMANTICALLY_VERIFIED", "OPERATIONALLY_VERIFIED",
	"SHADOW_VERIFIED", "CANARY_VERIFIED", "CUTOVER_READY",
}

var retainedBlockers = []string{
	"PRODUCTION_SHAPED_ENVIRONMENT_NOT_BOUND",
	"LIVE_SHADOW_NOT_EXECUTED",
	"LIVE_CANARY_NOT_EXECUTED",
	"REAL_SIDE_EFFECT_ISOLATION_NOT_EXECUTED",
	"US025_MEASURED_CAPACITY_NOT_ACCEPTED",
	"REAL_RESOURCE_MONITORING_NOT_EXECUTED",
	"WALL_CLOCK_SOAK_NOT_EXECUTED",
	"REAL_JAVA_FALLBACK_BINARY_NOT_REBUILT_OR_DRILLED",
	"REAL_ROLLBACK_BOUND_NOT_MEASURED",
	"INDEPENDENT_ATTESTATION_NOT_EXECUTED",
	"PRODUCTION_DEPLOYMENT_NOT_AUTHORIZED",
	"JAVA_REMOVAL_NOT_AUTHORIZED",
}

var retainedNonclaims = []string{
	"no production-shaped rehearsal",
	"no live traffic or effects",
	"no measured capacity or resources",
	"no elapsed soak or rollback bound",
	"no executable Java fallback drill",
	"no CUTOVER_READY or deployment readiness",
	"no production mutation, publication, signing, or Java removal",
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func buildFixture() fixtureSpec {
	requests := make([]requestFixture, 0, 16)
	for i := 0; i < 16; i++ {
		keyIndex := i
		retryOf := ""
		if i == 15 {
			keyIndex = 7
			retryOf = "request-07"
		}
		requestID := fmt.Sprintf("request-%02d", i)
		key := fmt.Sprintf("us026-idempotency-%02d", keyIndex)
		requests = append(requests, requestFixture{
			RequestID: requestID, IdempotencyKey: key,
			InputSHA256:    digest([]byte("input:" + requestID)),
			SemanticSHA256: digest([]byte("semantic:" + key)),
			EffectSHA256:   digest([]byte("effect:" + key)), RetryOf: retryOf,
		})
	}
	selected := selectRustRequests(requests)
	return fixtureSpec{
		Label: "SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT", Requests: requests,
		RouteProjection:    "two-lowest-sha256-idempotency-keys-among-first-attempts",
		RustSelectionCount: 2, RustSelectedRequestIDs: selected,
		NominalTrace: append([]string(nil), nominalTrace...), MismatchTrace: append([]string(nil), mismatchTrace...),
		RollbackActions: []string{"abort", "select-java", "reconcile"}, SoakTicks: 32,
	}
}

func selectRustRequests(requests []requestFixture) []string {
	type projection struct{ hash, requestID string }
	var projections []projection
	for _, request := range requests {
		if request.RetryOf == "" {
			projections = append(projections, projection{digest([]byte(request.IdempotencyKey)), request.RequestID})
		}
	}
	sort.Slice(projections, func(i, j int) bool { return projections[i].hash < projections[j].hash })
	selected := []string{projections[0].requestID, projections[1].requestID}
	sort.Strings(selected)
	return selected
}

func comparisonsFor(fixture fixtureSpec) []comparison {
	result := make([]comparison, 0, len(fixture.Requests))
	for i, request := range fixture.Requests {
		result = append(result, comparison{
			RequestID: request.RequestID, JavaSemanticSHA256: request.SemanticSHA256,
			RustSemanticSHA256: request.SemanticSHA256, JavaEffectSHA256: request.EffectSHA256,
			RustEffectSHA256: request.EffectSHA256, CPUFixtureUnits: 10 + i,
			MemoryFixtureUnits: 100 + i, BackpressureUnits: i % 3, Equal: true,
		})
	}
	return result
}

func requestIDs(fixture fixtureSpec) []string {
	ids := make([]string, len(fixture.Requests))
	for i, request := range fixture.Requests {
		ids[i] = request.RequestID
	}
	return ids
}

func effectLedger(fixture fixtureSpec, mismatch bool) ([]effectRecord, int, string) {
	selected := map[string]bool{}
	for _, id := range fixture.RustSelectedRequestIDs {
		selected[id] = true
	}
	aborted := false
	seen := map[string]bool{}
	var effects []effectRecord
	duplicates := 0
	firstAttempted := ""
	for _, request := range fixture.Requests {
		route := "java"
		if mismatch && aborted {
			route = "java-fallback"
		}
		if selected[request.RequestID] && !aborted {
			route = "rust"
			if mismatch {
				firstAttempted = request.RequestID
				aborted = true
				route = "java-fallback"
			}
		}
		if seen[request.IdempotencyKey] {
			duplicates++
			continue
		}
		seen[request.IdempotencyKey] = true
		effects = append(effects, effectRecord{IdempotencyKey: request.IdempotencyKey, EffectSHA256: request.EffectSHA256, Route: route})
	}
	return effects, duplicates, firstAttempted
}

func phaseRuns(phase string, fixture fixtureSpec) []phaseRun {
	comparisons := comparisonsFor(fixture)
	ids := requestIDs(fixture)
	nominalEffects, nominalDuplicates, _ := effectLedger(fixture, false)
	mismatchEffects, mismatchDuplicates, mismatchID := effectLedger(fixture, true)
	mismatchExpected := ""
	for _, request := range fixture.Requests {
		if request.RequestID == mismatchID {
			mismatchExpected = request.SemanticSHA256
			break
		}
	}
	mismatchObserved := digest([]byte("seeded-mismatch:" + mismatchID))
	nominal := phaseRun{
		RunID: "nominal", Outcome: "REHEARSAL_MECHANICS_COMPLETE", States: append([]string(nil), nominalTrace...),
		RequestIDs: ids, SelectedRequestIDs: append([]string(nil), fixture.RustSelectedRequestIDs...),
		RustAttemptedRequestIDs: append([]string(nil), fixture.RustSelectedRequestIDs...),
		Comparisons:             comparisons, FailedAttempts: []failedAttempt{}, RollbackActions: []string{}, Ticks: []tickRecord{},
		CommittedFixtureEffects: nominalEffects, ExpectedEffectCount: 15,
		DuplicateEffectsSuppressed: nominalDuplicates, SoakResult: "NOT_APPLICABLE_TO_PHASE",
	}
	mismatch := phaseRun{
		RunID: "seeded-mismatch", Outcome: "FALLBACK_RECONCILED", States: append([]string(nil), mismatchTrace...),
		RequestIDs: ids, SelectedRequestIDs: append([]string(nil), fixture.RustSelectedRequestIDs...),
		RustAttemptedRequestIDs: []string{mismatchID}, Comparisons: comparisons,
		FailedAttempts: []failedAttempt{{
			RequestID: mismatchID, Route: "rust", Reason: "SEMANTIC_MISMATCH",
			ExpectedSemantic: mismatchExpected, ObservedSemantic: mismatchObserved,
			Preserved: true, RealEffectCommitted: false, FixtureEffectCommitted: false,
		}},
		CommittedFixtureEffects: mismatchEffects, ExpectedEffectCount: 15,
		DuplicateEffectsSuppressed: mismatchDuplicates,
		RollbackActions:            append([]string(nil), fixture.RollbackActions...), Ticks: []tickRecord{},
		SoakResult: "NOT_ENTERED_ABORTED_CANARY",
	}
	switch phase {
	case "shadow":
		nominal.CommittedFixtureEffects = []effectRecord{}
		mismatch.CommittedFixtureEffects = []effectRecord{}
		nominal.ExpectedEffectCount = 0
		mismatch.ExpectedEffectCount = 0
		nominal.DuplicateEffectsSuppressed = 0
		mismatch.DuplicateEffectsSuppressed = 0
		nominal.RollbackActions = []string{}
		mismatch.RollbackActions = []string{}
		nominal.FailedAttempts = []failedAttempt{}
		mismatch.FailedAttempts = []failedAttempt{}
	case "canary":
		nominal.RollbackActions = []string{}
		mismatch.RollbackActions = []string{}
	case "rollback":
		nominal.Comparisons = []comparison{}
		mismatch.Comparisons = []comparison{}
	case "soak":
		nominal.Comparisons = []comparison{}
		mismatch.Comparisons = []comparison{}
		nominal.RollbackActions = []string{}
		mismatch.RollbackActions = []string{}
		nominal.SoakResult = "SIMULATED_32_TICKS_COMPLETE"
		for tick := 0; tick < fixture.SoakTicks; tick++ {
			nominal.Ticks = append(nominal.Ticks, tickRecord{Tick: tick, QueueFixtureUnits: tick % 3, ErrorFixtureCount: 0, BackpressureUnits: tick % 2})
		}
	}
	return []phaseRun{nominal, mismatch}
}

func deriveArtifacts(inputs []inputBinding) (artifactSet, error) {
	fixture := buildFixture()
	if len(fixture.RustSelectedRequestIDs) != 2 {
		return artifactSet{}, fail(FailureRouteCountMismatch, "selected %d Rust requests", len(fixture.RustSelectedRequestIDs))
	}
	fixtureRaw, err := canonicalJSON(fixture)
	if err != nil {
		return artifactSet{}, err
	}
	contract := contractDocument{
		Schema: "../schemas/cutover-rehearsal-contract-1.0.0.schema.json", SchemaID: "vjwp-cutover-rehearsal-contract/1.0.0",
		StoryID: "US-026", ContractID: "us026.fixture-only.disposable-rehearsal",
		Subject: subjectIdentity{Commit: SubjectCommit, Tree: SubjectTree}, AuthoritativeInputs: inputs,
		RejectedAuthorities: []string{"assurance/developer-tools/cutover-contract.json"}, FixtureSHA256: digest(fixtureRaw), Fixture: fixture,
		JavaFallback: javaFallbackFact{
			RouteTarget: "java-oracle", SourceIdentitySHA256: inputs[1].SHA256,
			BuildInputPath: "java-oracle/pom.xml", BuildInputSHA256: inputs[4].SHA256,
			ExecutablePresenceFact: "SOURCE_AND_BUILD_INPUT_RETAINED_EXECUTABLE_NOT_DRILLED", JavaFallbackExecutableDrilled: false,
		},
		CanonicalReadinessLadder: append([]string(nil), canonicalReadinessLadder...),
		MechanicsStatusCeiling:   MechanicsPass, CutoverAcceptanceCeiling: CutoverBlocked,
		ProductionShapedEnv: "NOT_BOUND", LiveTrafficExecuted: false, LiveSideEffectsExecuted: false,
		ResourceEvidenceKind: "SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT", CutoverReadyReachable: false,
		Assurance: Assurance, IndependentReviewClaimed: false,
		Provenance: producerProvenance{Review: "NOT_EXECUTED", QA: "NOT_EXECUTED", Reality: "NOT_EXECUTED"},
	}
	contractRaw, err := canonicalJSON(contract)
	if err != nil {
		return artifactSet{}, err
	}
	contractDigest := digest(contractRaw)
	artifacts := []namedArtifact{{path: "cutover/contract.json", bytes: contractRaw}}
	predecessorPath, predecessorDigest := "cutover/contract.json", contractDigest
	for _, phase := range []string{"shadow", "canary", "rollback", "soak"} {
		receipt := phaseReceipt{
			Schema: "../schemas/cutover-phase-receipt-1.0.0.schema.json", SchemaID: "vjwp-cutover-phase-receipt/1.0.0",
			StoryID: "US-026", Phase: phase, ContractSHA256: contractDigest, FixtureSHA256: contract.FixtureSHA256,
			PredecessorPath: predecessorPath, PredecessorSHA256: predecessorDigest,
			Subject: contract.Subject, Runs: phaseRuns(phase, fixture), MechanicsStatus: MechanicsPass,
			CutoverAcceptance: CutoverBlocked, ResourceEvidenceKind: contract.ResourceEvidenceKind,
			LiveTrafficExecuted: false, LiveSideEffectsExecuted: false, CutoverReadyReached: false,
			Assurance: Assurance, IndependentReviewClaimed: false,
		}
		raw, err := canonicalJSON(receipt)
		if err != nil {
			return artifactSet{}, err
		}
		path := "cutover/" + phase + ".json"
		artifacts = append(artifacts, namedArtifact{path: path, bytes: raw})
		predecessorPath, predecessorDigest = path, digest(raw)
	}
	summary := Summary{
		MechanicsStatus: MechanicsPass, CutoverAcceptance: CutoverBlocked,
		ShadowComparisons: 32, RustSelections: 2, FailedAttempts: 1,
		RollbackActions: 3, SoakTicks: 32, ReconciledEffects: 15, DuplicateEffectsSuppressed: 1,
	}
	bindings := make([]artifactDigest, len(artifacts))
	for i, artifact := range artifacts {
		bindings[i] = artifactDigest{Path: artifact.path, SHA256: digest(artifact.bytes), Bytes: len(artifact.bytes)}
	}
	evidence := evidenceDocument{
		Schema: "../schemas/cutover-evidence-1.0.0.schema.json", SchemaID: "vjwp-cutover-evidence/1.0.0",
		StoryID: "US-026", Subject: contract.Subject, Artifacts: bindings, Summary: summary,
		MechanicsStatus: MechanicsPass, CutoverAcceptance: CutoverBlocked, CutoverReadyReached: false,
		Assurance: Assurance, IndependentReviewClaimed: false, Production: false, Signing: false, Publication: false,
		Blockers: append([]string(nil), retainedBlockers...), Nonclaims: append([]string(nil), retainedNonclaims...),
		Provenance: producerProvenance{Review: "NOT_EXECUTED", QA: "NOT_EXECUTED", Reality: "NOT_EXECUTED"},
	}
	evidenceRaw, err := canonicalJSON(evidence)
	if err != nil {
		return artifactSet{}, err
	}
	artifacts = append(artifacts, namedArtifact{path: "evidence/cutover.json", bytes: evidenceRaw})
	return artifactSet{artifacts: artifacts, summary: summary}, nil
}
