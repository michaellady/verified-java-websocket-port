package formal

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

type backendSpec struct {
	ID              string
	Method          string
	ObligationIDs   []string
	PropertyIDs     []string
	ExecutedScope   string
	CanaryInputPath string
}

var requiredBackendArtifacts = []string{
	"BAD_CANARY_COUNTEREXAMPLE",
	"CLASSIFIER_PROJECTION",
	"CLEANUP_RECEIPT",
	"GOOD_CANARY_RESULT",
	"INPUT_MANIFEST",
	"NORMALIZED_RESULT",
	"OBLIGATION_INVENTORY",
	"OUTPUT_MANIFEST",
	"RAW_TOOL_RESULT",
	"REPLAY_RECEIPT",
	"SBX_RECEIPT",
	"SBX_REQUEST",
	"TOOL_IDENTITY",
}

func validateGraph(snap *snapshot, targets *proofTargets, qualification *backendQualification, plan *concurrencyPlan, mode string, collector *findingCollector) {
	if qualification.ProofTargets.Path != proofTargetsPath || qualification.ConnectionModel.Path != connectionModelPath || qualification.ConcurrencyPlan.Path != concurrencyPlanPath {
		collector.semantic("MISSING_TARGET", backendQualificationPath, "qualification must bind the three exact US-006 artifact paths")
	}
	for path, ref := range map[string]artifactRef{
		"$.proof_targets":    qualification.ProofTargets,
		"$.connection_model": qualification.ConnectionModel,
		"$.concurrency_plan": qualification.ConcurrencyPlan,
	} {
		if ref.Attribution != "US006_OWNED" {
			collector.semantic("BORROWED_FOUNDATION_DRIFT", path+".attribution", "US-006 artifacts must not be attributed as independently borrowed evidence")
		}
	}

	proofObligations := map[string]obligation{}
	proofProperties := map[string]string{}
	for _, target := range targets.Targets {
		if target.LinkageState == "RESOLVED_PRODUCTION_SYMBOL" {
			validateResolvedLinkage(snap, &target, collector)
		}
		for _, item := range target.Obligations {
			proofObligations[item.ObligationID] = item
			proofProperties[item.ObligationID] = item.PropertyID
		}
	}
	concurrencyProperties := make([]string, 0, len(plan.Properties))
	for _, property := range plan.Properties {
		concurrencyProperties = append(concurrencyProperties, property.PropertyID)
	}
	modelProperties := []string{
		"model.accepted-commands-disposed-exactly-once",
		"model.accepted-commands-eventually-disposed",
		"model.backpressure-preserves-accepted-work",
		"model.closed-is-terminal",
		"model.lifecycle-monotonic",
		"model.queue-bounds",
		"model.terminal-delivered-at-most-once",
		"model.terminal-delivery-eventually",
		"model.termination-under-fairness",
	}
	maskObligations := []string{"obligation.mask-equation", "obligation.mask-involution"}
	allProofObligations := mapKeys(proofObligations)
	allProofProperties := make([]string, 0, len(allProofObligations))
	for _, id := range allProofObligations {
		allProofProperties = append(allProofProperties, proofProperties[id])
	}
	sort.Strings(allProofProperties)
	specs := []backendSpec{
		{ID: "backend.finite-mask-prototype", Method: "FINITE_EXHAUSTIVE_PROTOTYPE", ObligationIDs: maskObligations, PropertyIDs: []string{"mask.equation", "mask.involution"}, ExecutedScope: "BOUNDED_TEST_EVIDENCE", CanaryInputPath: proofTargetsPath},
		{ID: "backend.kani-production", Method: "KANI_BOUNDED_MODEL_CHECKING", ObligationIDs: allProofObligations, PropertyIDs: allProofProperties, ExecutedScope: "BOUNDED_TEST_EVIDENCE", CanaryInputPath: proofTargetsPath},
		{ID: "backend.loom-concurrency", Method: "LOOM_SYSTEMATIC_SCHEDULE_EXPLORATION", ObligationIDs: concurrencyProperties, PropertyIDs: concurrencyProperties, ExecutedScope: "SYSTEMATIC_CONCURRENCY_TESTING", CanaryInputPath: concurrencyPlanPath},
		{ID: "backend.tlc-connection-model", Method: "TLC_EXPLICIT_STATE_MODEL_CHECKING", ObligationIDs: modelProperties, PropertyIDs: modelProperties, ExecutedScope: "PROVED_MODEL", CanaryInputPath: connectionModelPath},
	}
	if len(qualification.Backends) != len(specs) || !sortedBy(qualification.Backends, func(value backend) string { return value.BackendID }) {
		collector.semantic("MISSING_TARGET", "$.backends", "the exact four selected backends must be sorted by backend_id")
	}
	backendByID := map[string]*backend{}
	globalCanaries := map[string]bool{}
	for index := range qualification.Backends {
		backend := &qualification.Backends[index]
		path := fmt.Sprintf("$.backends[%d]", index)
		if backendByID[backend.BackendID] != nil {
			collector.semantic("DUPLICATE_IDENTIFIER", path+".backend_id", "backend identifier is duplicated")
		}
		backendByID[backend.BackendID] = backend
		for _, canary := range append(append([]canary{}, backend.KnownGoodCanaries...), backend.KnownBadCanaries...) {
			globalCanaries[canary.CanaryID] = true
		}
	}
	for index, spec := range specs {
		backend := backendByID[spec.ID]
		if backend == nil {
			collector.semantic("MISSING_TARGET", "$.backends", "missing backend "+spec.ID)
			continue
		}
		validateBackend(snap, targets, qualification, plan, backend, spec, mode, fmt.Sprintf("$.backends[%d]", index), collector)
	}
	for obligationID, item := range proofObligations {
		for _, backendID := range item.RequiredBackendIDs {
			backend := backendByID[backendID]
			if backend == nil || !contains(backend.ObligationIDs, obligationID) {
				collector.semantic("MISSING_TARGET", "$.targets.obligations", obligationID+" does not reach required backend "+backendID)
			}
		}
		for _, canaryID := range item.ExpectedCanaryIDs {
			if !globalCanaries[canaryID] {
				collector.semantic("MISSING_REQUIRED_ARTIFACT", "$.targets.obligations", obligationID+" expected canary is absent: "+canaryID)
			}
		}
	}
	validateAggregateState(qualification, collector)
}

func validateResolvedLinkage(snap *snapshot, target *target, collector *findingCollector) {
	for index, call := range target.RequiredCallPaths {
		path := fmt.Sprintf("$.targets.%s.required_call_paths[%d]", target.TargetID, index)
		if call.LinkageArtifact == nil {
			continue
		}
		data, err := snap.read(call.LinkageArtifact.Path, maxJSONBytes)
		if err != nil {
			collector.semantic("MISSING_REQUIRED_ARTIFACT", path+".linkage_artifact", err.Error())
			continue
		}
		var receipt linkageReceiptDocument
		if err := decodeStrict(data, &receipt); err != nil {
			collector.semantic("DISCONNECTED_TARGET", path+".linkage_artifact", "linkage receipt is not a strict typed document: "+err.Error())
			continue
		}
		if receipt.SchemaVersion != "1.0.0" || receipt.EntityType != "FormalLinkageReceipt" ||
			!claimBearingLinkage(receipt) ||
			call.LinkageArtifact.Attribution != "PUBLIC_LINKAGE_EVIDENCE" ||
			(receipt.Method != "COMPILER_CALL_GRAPH" && receipt.Method != "INSTRUMENTED_TRACE") ||
			receipt.EntrySymbol != call.EntrySymbol || receipt.TargetSymbol != target.RustSymbol ||
			receipt.TargetFile != target.PlannedFile || target.SourceSHA256 == nil || receipt.TargetSourceSHA256 != *target.SourceSHA256 ||
			receipt.Assurance != assuranceCeiling || receipt.IndependentReviewClaimed || receipt.Production {
			collector.semantic("DISCONNECTED_TARGET", path+".linkage_artifact", "typed linkage receipt must be non-synthetic public-derived evidence binding method, provenance, entry, exact target symbol/file/source, and assurance posture")
		}
		if !linkageReachable(receipt.EntrySymbol, receipt.TargetSymbol, receipt.Edges) {
			collector.semantic("DISCONNECTED_TARGET", path+".linkage_artifact.edges", "typed linkage receipt has no reachable edge chain from entry to exact target")
		}
		verifyArtifactRef(snap, receipt.SourceTree, path+".linkage_artifact.source_tree", collector)
	}
}

func claimBearingLinkage(receipt linkageReceiptDocument) bool {
	return receipt.FixtureKind == "PUBLIC_LINKAGE_RECEIPT" &&
		receipt.Provenance == "PUBLIC_DERIVED_SOURCE_TREE" &&
		receipt.SourceTree.Attribution == "PUBLIC_SOURCE_TREE"
}

func linkageReachable(entry, target string, edges []linkageEdge) bool {
	adjacent := map[string][]string{}
	seenEdges := map[string]bool{}
	for _, edge := range edges {
		if edge.From == "" || edge.To == "" {
			return false
		}
		key := edge.From + "\x00" + edge.To
		if seenEdges[key] {
			return false
		}
		seenEdges[key] = true
		adjacent[edge.From] = append(adjacent[edge.From], edge.To)
	}
	queue := []string{entry}
	visited := map[string]bool{entry: true}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == target {
			return true
		}
		for _, next := range adjacent[current] {
			if !visited[next] {
				visited[next] = true
				queue = append(queue, next)
			}
		}
	}
	return false
}

func validateBackend(snap *snapshot, targets *proofTargets, qualification *backendQualification, plan *concurrencyPlan, backend *backend, spec backendSpec, mode, path string, collector *findingCollector) {
	if backend.Method != spec.Method || !backend.Selected {
		collector.semantic("MISSING_TARGET", path, "backend method or selection differs from the frozen inventory")
	}
	if len(backend.ObligationIDs) == 0 || backend.ObligationCount == 0 || len(backend.Outcomes) == 0 {
		collector.semantic("ZERO_OBLIGATIONS", path, "selected backend must carry a nonzero obligation inventory and outcomes")
	}
	checkSortedUnique(backend.ExpectedPropertyIDs, path+".expected_property_ids", collector)
	checkSortedUnique(backend.ObligationIDs, path+".obligation_ids", collector)
	checkSortedUnique(backend.RequiredArtifacts, path+".required_artifacts", collector)
	checkSortedUnique(backend.Assumptions, path+".assumptions", collector)
	checkSortedUnique(backend.Provenance, path+".provenance", collector)
	checkSortedUnique(backend.UnsupportedConstructs, path+".unsupported_constructs", collector)
	checkSortedUnique(backend.TrustedBase, path+".trusted_base", collector)
	if !sameSet(backend.ObligationIDs, spec.ObligationIDs) {
		collector.semantic("MISSING_TARGET", path+".obligation_ids", "backend obligation inventory does not resolve to its proof, model, or concurrency subject")
	}
	if !sameSet(backend.ExpectedPropertyIDs, spec.PropertyIDs) {
		collector.semantic("MISSING_TARGET", path+".expected_property_ids", "expected-property inventory does not match the linked obligations")
	}
	if backend.ObligationCount != len(backend.ObligationIDs) || len(backend.Outcomes) != len(backend.ObligationIDs) {
		reason := "INFLATED_COUNT"
		if backend.ObligationCount == 0 || len(backend.ObligationIDs) == 0 {
			reason = "ZERO_OBLIGATIONS"
		}
		collector.semantic(reason, path+".obligation_count", "declared obligation count must equal retained obligation and outcome arrays")
	}
	if !sameSet(backend.RequiredArtifacts, requiredBackendArtifacts) {
		collector.semantic("MISSING_REQUIRED_ARTIFACT", path+".required_artifacts", "backend required-artifact inventory is incomplete")
	}
	if !contains(backend.Provenance, "BORROWED_OPERATIONAL_FOUNDATION_CLAUDE_US007_ATTEMPT_0123") {
		collector.semantic("BORROWED_FOUNDATION_DRIFT", path+".provenance", "backend must attribute Claude US-007 attempt 0123 as borrowed operational foundation")
	}
	if len(backend.KnownGoodCanaries) == 0 || len(backend.KnownBadCanaries) == 0 {
		collector.semantic("MISSING_REQUIRED_ARTIFACT", path+".known_good_canaries", "backend requires nonempty good and seeded-bad canaries")
	}
	validateCanaries(backend, spec, path, collector)
	validateOutcomes(backend, spec, path, collector)
	validateBounds(backend, plan, path, collector)

	if len(backend.UnsupportedConstructs) > 0 {
		for _, outcome := range backend.Outcomes {
			if outcome.RawOutcome == "BOUNDED_CHECK_PASSED" || outcome.RawOutcome == "SYSTEMATIC_EXPLORATION_PASSED" || outcome.RawOutcome == "MODEL_CHECK_PASSED" {
				collector.semantic("UNSUPPORTED_CONSTRUCT_CLAIMED", path+".unsupported_constructs", "observed unsupported constructs cannot be claimed as covered")
				break
			}
		}
	}

	switch backend.ExecutionState {
	case "UNAVAILABLE_BACKEND_BLOCKED":
		validateUnavailableBackend(backend, path, collector)
	case "EXECUTED_PASS", "EXECUTED_COUNTEREXAMPLE":
		validateExecutedBackend(snap, targets, qualification, backend, spec, path, collector)
	default:
		collector.semantic("UNAVAILABLE_REPRESENTED_AS_SKIP", path+".execution_state", "backend execution state must never be skip or not-applicable")
	}
	validateReplayIdentity(snap, qualification, backend, mode, path, collector)

	for _, canary := range append(append([]canary{}, backend.KnownGoodCanaries...), backend.KnownBadCanaries...) {
		if canary.Input.Path != spec.CanaryInputPath {
			collector.semantic("MISSING_TARGET", path+".known_bad_canaries", "canary input does not bind the backend subject")
		}
	}
	_ = snap
}

func validateCanaries(backend *backend, spec backendSpec, path string, collector *findingCollector) {
	if !sortedBy(backend.KnownGoodCanaries, func(value canary) string { return value.CanaryID }) {
		collector.semantic("NONCANONICAL_SET_ORDER", path+".known_good_canaries", "good canaries must be sorted by canary_id")
	}
	if !sortedBy(backend.KnownBadCanaries, func(value canary) string { return value.CanaryID }) {
		collector.semantic("NONCANONICAL_SET_ORDER", path+".known_bad_canaries", "bad canaries must be sorted by canary_id")
	}
	seen := map[string]bool{}
	for index, canary := range backend.KnownGoodCanaries {
		itemPath := fmt.Sprintf("%s.known_good_canaries[%d]", path, index)
		if seen[canary.CanaryID] {
			collector.semantic("DUPLICATE_IDENTIFIER", itemPath, "canary identifier is duplicated")
		}
		seen[canary.CanaryID] = true
		if canary.ExpectedOutcome != "PASS" {
			collector.semantic("KNOWN_BAD_CANARY_SURVIVED", itemPath, "known-good canary must expect PASS")
		}
		if canary.ObservedOutcome == "COUNTEREXAMPLE" {
			collector.semantic("SEMANTIC_INCONSISTENCY", itemPath, "known-good canary produced a counterexample")
		}
	}
	for index, canary := range backend.KnownBadCanaries {
		itemPath := fmt.Sprintf("%s.known_bad_canaries[%d]", path, index)
		if seen[canary.CanaryID] {
			collector.semantic("DUPLICATE_IDENTIFIER", itemPath, "canary identifier is duplicated")
		}
		seen[canary.CanaryID] = true
		if canary.ExpectedOutcome != "COUNTEREXAMPLE" || canary.ObservedOutcome == "PASS" {
			collector.semantic("KNOWN_BAD_CANARY_SURVIVED", itemPath, "seeded bad canary survived or did not require a counterexample")
		}
		if canary.ObservedOutcome == "COUNTEREXAMPLE" {
			if canary.Counterexample == nil || canary.Output == nil {
				collector.semantic("KNOWN_BAD_CANARY_SURVIVED", itemPath, "observed seeded defect requires retained output and minimized counterexample")
			} else {
				validateCounterexample(backend, canary, spec, itemPath, collector)
			}
		}
	}
}

func validateCounterexample(backend *backend, canary canary, spec backendSpec, path string, collector *findingCollector) {
	counterexample := canary.Counterexample
	if len(counterexample.Steps) == 0 || counterexample.Reason == "" || counterexample.TargetSymbol == "" {
		collector.semantic("KNOWN_BAD_CANARY_SURVIVED", path+".counterexample", "counterexample must retain a reason, target, and nonempty minimized steps")
		return
	}
	tuple := struct {
		BackendID string          `json:"backend_id"`
		CanaryID  string          `json:"canary_id"`
		Input     artifactRef     `json:"input"`
		Bounds    json.RawMessage `json:"bounds"`
		Reason    string          `json:"reason"`
		Target    string          `json:"target"`
		Steps     []string        `json:"steps"`
	}{backend.BackendID, canary.CanaryID, canary.Input, backend.Bounds, counterexample.Reason, counterexample.TargetSymbol, counterexample.Steps}
	data, err := vendorprotocol.CanonicalJSON(tuple)
	if err != nil {
		collector.semantic("REPLAY_MISMATCH", path+".counterexample", err.Error())
		return
	}
	expectedID := "counterexample." + strings.TrimPrefix(vendorprotocol.DigestBytes(data), "sha256:")[:16]
	if counterexample.CounterexampleID != expectedID {
		collector.semantic("REPLAY_MISMATCH", path+".counterexample.counterexample_id", "counterexample identity does not bind its canonical input, bounds, reason, target, and minimized steps")
	}
	if !counterexampleTargetAllowed(backend.Method, counterexample.TargetSymbol) {
		collector.semantic("MISSING_TARGET", path+".counterexample.target_symbol", "canary counterexample does not name the exact backend subject")
	}
	_ = spec
}

func validateOutcomes(backend *backend, spec backendSpec, path string, collector *findingCollector) {
	if !sortedBy(backend.Outcomes, func(value outcome) string { return value.ObligationID }) {
		collector.semantic("NONCANONICAL_SET_ORDER", path+".outcomes", "outcomes must be sorted by obligation_id")
	}
	seen := map[string]bool{}
	for index, outcome := range backend.Outcomes {
		itemPath := fmt.Sprintf("%s.outcomes[%d]", path, index)
		if seen[outcome.ObligationID] {
			collector.semantic("DUPLICATE_IDENTIFIER", itemPath, "outcome obligation is duplicated")
		}
		seen[outcome.ObligationID] = true
		if !contains(spec.ObligationIDs, outcome.ObligationID) {
			collector.semantic("MISSING_TARGET", itemPath+".obligation_id", "outcome does not resolve to the backend subject")
		}
		if len(outcome.ArtifactRefs) == 0 {
			collector.semantic("MISSING_REQUIRED_ARTIFACT", itemPath+".artifact_refs", "every outcome requires a digest-bound artifact or blocker")
		}
		if outcome.RawOutcome == "COUNTEREXAMPLE" {
			if outcome.Counterexample == nil {
				collector.semantic("KNOWN_BAD_CANARY_SURVIVED", itemPath+".counterexample", "counterexample outcome requires a retained minimized counterexample")
			} else {
				validateOutcomeCounterexample(backend, outcome, spec, itemPath, collector)
			}
		} else if outcome.Counterexample != nil {
			collector.semantic("SEMANTIC_INCONSISTENCY", itemPath+".counterexample", "only COUNTEREXAMPLE permits a counterexample object")
		}
	}
}

func validateOutcomeCounterexample(backend *backend, outcome outcome, spec backendSpec, path string, collector *findingCollector) {
	counterexample := outcome.Counterexample
	if counterexample.Reason == "" || counterexample.Input == "" || counterexample.TargetSymbol == "" || len(counterexample.Steps) == 0 {
		collector.semantic("COUNTEREXAMPLE_INVALID", path+".counterexample", "outcome counterexample requires canonical input, reason, exact target, and minimized steps")
		return
	}
	artifactBound := false
	for _, ref := range outcome.ArtifactRefs {
		artifactBound = artifactBound || ref == counterexample.Artifact
	}
	if !artifactBound {
		collector.semantic("COUNTEREXAMPLE_INVALID", path+".counterexample.artifact", "counterexample artifact must be one of the outcome's independently reopenable artifacts")
	}
	tuple := struct {
		BackendID  string          `json:"backend_id"`
		Obligation string          `json:"obligation_id"`
		Input      string          `json:"input"`
		Bounds     json.RawMessage `json:"bounds"`
		Reason     string          `json:"reason"`
		Target     string          `json:"target"`
		Steps      []string        `json:"steps"`
	}{backend.BackendID, outcome.ObligationID, counterexample.Input, backend.Bounds, counterexample.Reason, counterexample.TargetSymbol, counterexample.Steps}
	data, err := vendorprotocol.CanonicalJSON(tuple)
	if err != nil {
		collector.semantic("COUNTEREXAMPLE_INVALID", path+".counterexample", err.Error())
		return
	}
	expectedID := "counterexample." + strings.TrimPrefix(vendorprotocol.DigestBytes(data), "sha256:")[:16]
	if counterexample.CounterexampleID != expectedID {
		collector.semantic("REPLAY_MISMATCH", path+".counterexample.counterexample_id", "outcome counterexample identity does not bind backend, obligation, canonical input, bounds, target, reason, and steps")
	}
	if !counterexampleTargetAllowed(backend.Method, counterexample.TargetSymbol) {
		collector.semantic("MISSING_TARGET", path+".counterexample.target_symbol", "counterexample does not name the exact backend subject")
	}
	_ = spec
}

func counterexampleTargetAllowed(method, target string) bool {
	switch method {
	case "FINITE_EXHAUSTIVE_PROTOTYPE", "KANI_BOUNDED_MODEL_CHECKING":
		return target == "websocket_core::frame::mask::apply_mask_in_place" || target == "websocket_core::frame::decode::FrameHeaderDecoder::decode_header"
	case "LOOM_SYSTEMATIC_SCHEDULE_EXPLORATION":
		return target == "websocket_driver::owner::ConnectionOwner::step"
	case "TLC_EXPLICIT_STATE_MODEL_CHECKING":
		return target == "ConnectionModel"
	default:
		return false
	}
}

func validateUnavailableBackend(backend *backend, path string, collector *findingCollector) {
	if strings.Contains(strings.ToUpper(backend.ClaimScope), "SKIP") || strings.Contains(strings.ToUpper(backend.ClaimScope), "NOT_APPLICABLE") {
		collector.semantic("UNAVAILABLE_REPRESENTED_AS_SKIP", path+".claim_scope", "unavailable backend cannot be represented as skip or not-applicable")
	} else if backend.ClaimScope != "UNAVAILABLE_BACKEND_BLOCKED" {
		collector.semantic("INFLATED_CLAIM", path+".claim_scope", "unavailable backend cannot carry a success scope")
	}
	if !backend.AvailabilityProbe.Executed && !strings.Contains(backend.AvailabilityProbe.Observation, "OWNER_AUTHORIZATION_REQUIRED") {
		collector.semantic("UNAVAILABLE_BACKEND_BLOCKED", path+".availability_probe", "selected unavailable backend requires a failed capability probe unless authorization is the blocker")
	}
	if backend.AvailabilityProbe.Executed && (backend.AvailabilityProbe.Receipt == nil || backend.AvailabilityProbe.ExitCode == nil) {
		collector.semantic("MISSING_REQUIRED_ARTIFACT", path+".availability_probe", "executed availability probe requires receipt and exit code")
	}
	if backend.Tool.Version != nil || backend.Tool.BinarySHA256 != nil || backend.Tool.ExecutablePromotion != nil {
		collector.semantic("UNAVAILABLE_REPRESENTED_AS_SUCCESS", path+".tool", "unavailable backend must not invent a qualified tool identity")
	}
	if !sbxExecutionEmpty(backend.SBXExecution) {
		collector.semantic("UNAVAILABLE_REPRESENTED_AS_SUCCESS", path+".sbx_execution", "unavailable backend must not invent an sbx execution")
	}
	if len(backend.ArtifactBindings) != 0 {
		collector.semantic("UNAVAILABLE_REPRESENTED_AS_SUCCESS", path+".artifact_bindings", "unavailable backend cannot carry execution evidence bindings")
	}
	for _, canary := range append(append([]canary{}, backend.KnownGoodCanaries...), backend.KnownBadCanaries...) {
		if canary.ObservedOutcome != "NOT_EXECUTED" || canary.Output != nil || canary.Counterexample != nil {
			reason := "UNAVAILABLE_REPRESENTED_AS_SUCCESS"
			if canary.ExpectedOutcome == "COUNTEREXAMPLE" && canary.ObservedOutcome == "PASS" {
				reason = "KNOWN_BAD_CANARY_SURVIVED"
			}
			collector.semantic(reason, path+".known_bad_canaries", "unavailable backend cannot carry an observed canary result")
		}
	}
	for _, outcome := range backend.Outcomes {
		if outcome.RawOutcome != "BACKEND_UNAVAILABLE" || outcome.ClaimScope != "UNAVAILABLE_BACKEND_BLOCKED" {
			reason := "UNAVAILABLE_REPRESENTED_AS_SUCCESS"
			if strings.Contains(outcome.RawOutcome, "SKIP") {
				reason = "UNAVAILABLE_REPRESENTED_AS_SKIP"
			}
			collector.semantic(reason, path+".outcomes", "unavailable backend outcomes must remain explicit blockers")
		}
		if backend.AvailabilityProbe.Receipt != nil {
			bound := false
			for _, ref := range outcome.ArtifactRefs {
				bound = bound || ref == *backend.AvailabilityProbe.Receipt
			}
			if !bound {
				collector.semantic("MISSING_REQUIRED_ARTIFACT", path+".outcomes", "unavailable outcome must reopen through its authorization or capability blocker receipt")
			}
		}
	}
}

func validateExecutedBackend(snap *snapshot, targets *proofTargets, qualification *backendQualification, backend *backend, spec backendSpec, path string, collector *findingCollector) {
	backend.evidenceKind, backend.evidenceRunID = validateExecutedBindings(snap, qualification, backend, path, collector)
	expectedScope := spec.ExecutedScope
	if backend.evidenceKind == "SYNTHETIC_NON_CLAIM" {
		expectedScope = "UNAVAILABLE_BACKEND_BLOCKED"
	}
	if backend.ClaimScope != expectedScope {
		reason := "INFLATED_CLAIM"
		if backend.Method == "TLC_EXPLICIT_STATE_MODEL_CHECKING" && backend.ClaimScope == "FUTURE_PRODUCTION_REFINEMENT" {
			reason = "REFINEMENT_MISSING"
		}
		collector.semantic(reason, path+".claim_scope", "backend claim exceeds or differs from its exact evidence-kind and method ceiling")
	}
	if backend.Method == "KANI_BOUNDED_MODEL_CHECKING" {
		for _, target := range targets.Targets {
			if target.LinkageState != "RESOLVED_PRODUCTION_SYMBOL" {
				collector.semantic("DISCONNECTED_TARGET", path, "Kani production result requires both exact shipped Rust symbols and all consumers resolved")
				break
			}
		}
	}
	for _, canary := range backend.KnownGoodCanaries {
		if canary.ObservedOutcome != "PASS" || canary.Output == nil {
			collector.semantic("MISSING_REQUIRED_ARTIFACT", path+".known_good_canaries", "executed backend requires retained passing good-canary output")
		}
	}
	for _, canary := range backend.KnownBadCanaries {
		if canary.ObservedOutcome != "COUNTEREXAMPLE" || canary.Output == nil || canary.Counterexample == nil {
			collector.semantic("KNOWN_BAD_CANARY_SURVIVED", path+".known_bad_canaries", "executed backend must kill every seeded bad canary with a reproducible counterexample")
		}
	}
	expectedPassOutcome := map[string]string{
		"FINITE_EXHAUSTIVE_PROTOTYPE":          "BOUNDED_CHECK_PASSED",
		"KANI_BOUNDED_MODEL_CHECKING":          "BOUNDED_CHECK_PASSED",
		"LOOM_SYSTEMATIC_SCHEDULE_EXPLORATION": "SYSTEMATIC_EXPLORATION_PASSED",
		"TLC_EXPLICIT_STATE_MODEL_CHECKING":    "MODEL_CHECK_PASSED",
	}[backend.Method]
	counterexampleCount := 0
	for _, outcome := range backend.Outcomes {
		if outcome.RawOutcome == "COUNTEREXAMPLE" {
			counterexampleCount++
		}
		if outcome.RawOutcome == "BACKEND_UNAVAILABLE" || outcome.RawOutcome == "UNSUPPORTED_CONSTRUCT" || outcome.RawOutcome == "DISCONNECTED" {
			collector.semantic("UNAVAILABLE_REPRESENTED_AS_SUCCESS", path+".outcomes", "non-satisfying outcome cannot appear under executed success")
		}
		if backend.ExecutionState == "EXECUTED_PASS" && outcome.RawOutcome != expectedPassOutcome {
			collector.semantic("COUNTEREXAMPLE_STATE_MISMATCH", path+".outcomes", "EXECUTED_PASS requires every obligation to retain the method-specific passing outcome")
		}
		if outcome.ClaimScope != backend.ClaimScope && outcome.RawOutcome != "COUNTEREXAMPLE" {
			collector.semantic("INFLATED_CLAIM", path+".outcomes", "outcome scope differs from backend method ceiling")
		}
	}
	if backend.ExecutionState == "EXECUTED_COUNTEREXAMPLE" && counterexampleCount == 0 {
		collector.semantic("COUNTEREXAMPLE_STATE_MISMATCH", path+".outcomes", "EXECUTED_COUNTEREXAMPLE requires at least one typed counterexample outcome")
	}
	_ = qualification
}

func validateExecutedBindings(snap *snapshot, qualification *backendQualification, backend *backend, path string, collector *findingCollector) (string, string) {
	execution := backend.SBXExecution
	complete := backend.AvailabilityProbe.Executed && backend.AvailabilityProbe.Receipt != nil && backend.AvailabilityProbe.ExitCode != nil && *backend.AvailabilityProbe.ExitCode == 0 &&
		backend.Tool.Version != nil && backend.Tool.BinarySHA256 != nil && backend.Tool.ExecutablePromotion != nil &&
		execution.CLIVersion != nil && execution.DaemonVersion != nil && execution.TemplateReference != nil && execution.SandboxPolicyDigest != nil &&
		execution.RequestDigest != nil && execution.ReceiptDigest != nil && execution.InputRootDigest != nil && execution.OutputRootDigest != nil &&
		execution.CleanupState != nil && execution.ClassificationState != nil && execution.Profile != nil && execution.CapabilityProbe != nil &&
		execution.Request != nil && execution.Receipt != nil && execution.InputManifest != nil && execution.OutputManifest != nil &&
		execution.CleanupReceipt != nil && execution.ClassifierProjection != nil
	if !complete {
		collector.semantic("MISSING_REQUIRED_ARTIFACT", path, "executed backend requires a complete typed probe, profile, request, receipt, manifests, cleanup, classification, and promoted tool binding")
		return "", ""
	}
	foundation := qualification.BorrowedSandboxFoundation
	if *execution.CLIVersion != foundation.CLIVersion || *execution.DaemonVersion != foundation.DaemonVersion ||
		*execution.TemplateReference != foundation.TemplateReference || *execution.SandboxPolicyDigest != foundation.SandboxPolicyDigest ||
		*execution.CleanupState != "CLEAN" || *execution.ClassificationState != "PUBLIC_DERIVED" ||
		*execution.RequestDigest != execution.Request.SHA256 || *execution.ReceiptDigest != execution.Receipt.SHA256 ||
		*execution.InputRootDigest != execution.InputManifest.SHA256 || *execution.OutputRootDigest != execution.OutputManifest.SHA256 ||
		*backend.AvailabilityProbe.Receipt != *execution.CapabilityProbe {
		collector.semantic("EXECUTION_RECEIPT_INVALID", path+".sbx_execution", "executed binding values do not reconcile to the borrowed profile and typed artifact references")
	}
	bindings := map[string][]evidenceBinding{}
	for index, binding := range backend.ArtifactBindings {
		if binding.RunID == "" {
			collector.semantic("EXECUTION_RECEIPT_INVALID", fmt.Sprintf("%s.artifact_bindings[%d]", path, index), "evidence binding requires a run_id")
		}
		bindings[binding.Category] = append(bindings[binding.Category], binding)
	}
	for _, category := range requiredBackendArtifacts {
		if len(bindings[category]) != 1 {
			collector.semantic("MISSING_REQUIRED_ARTIFACT", path+".artifact_bindings", "missing typed category binding: "+category)
		}
	}
	expectedRefs := map[string]artifactRef{
		"SBX_REQUEST":           *execution.Request,
		"SBX_RECEIPT":           *execution.Receipt,
		"INPUT_MANIFEST":        *execution.InputManifest,
		"OUTPUT_MANIFEST":       *execution.OutputManifest,
		"CLEANUP_RECEIPT":       *execution.CleanupReceipt,
		"CLASSIFIER_PROJECTION": *execution.ClassifierProjection,
	}
	for category, ref := range expectedRefs {
		matched := false
		for _, binding := range bindings[category] {
			matched = matched || binding.Artifact == ref
		}
		if !matched {
			collector.semantic("EXECUTION_RECEIPT_INVALID", path+".artifact_bindings", category+" does not bind its typed execution artifact")
		}
	}
	categoryRefs := map[string]artifactRef{}
	for category, values := range bindings {
		if len(values) == 1 {
			categoryRefs[category] = values[0].Artifact
		}
	}
	if replayRef, ok := categoryRefs["REPLAY_RECEIPT"]; ok {
		matched := false
		for _, run := range backend.Replay.Runs {
			matched = matched || replayRef == run.Receipt
		}
		if !matched {
			collector.semantic("EXECUTION_RECEIPT_INVALID", path+".artifact_bindings", "REPLAY_RECEIPT must bind one independently retained replay run")
		}
	}
	receipt, ok := readEvidenceArtifact(snap, *execution.Receipt, "SBX_RECEIPT", "SUCCEEDED", qualification, backend, "", path+".sbx_execution.receipt", collector)
	if !ok {
		return "", ""
	}
	runID := receipt.RunID
	roleRefs := map[string]artifactRef{
		"SBX_PROFILE": *execution.Profile, "CAPABILITY_PROBE": *execution.CapabilityProbe,
	}
	for category, ref := range categoryRefs {
		if category != "REPLAY_RECEIPT" {
			roleRefs[category] = ref
		}
	}
	states := map[string]string{
		"SBX_PROFILE": "QUALIFIED", "CAPABILITY_PROBE": "SUCCEEDED", "SBX_REQUEST": "ACCEPTED",
		"SBX_RECEIPT": "SUCCEEDED", "TOOL_IDENTITY": "QUALIFIED", "INPUT_MANIFEST": "SEALED",
		"OUTPUT_MANIFEST": "SEALED", "OBLIGATION_INVENTORY": "SEALED", "GOOD_CANARY_RESULT": "PASS",
		"BAD_CANARY_COUNTEREXAMPLE": "COUNTEREXAMPLE", "RAW_TOOL_RESULT": "PASS", "NORMALIZED_RESULT": "PASS",
		"CLEANUP_RECEIPT": "CLEAN", "CLASSIFIER_PROJECTION": "PUBLIC_DERIVED",
	}
	seenPaths := map[string]string{}
	seenDigests := map[string]string{}
	for role, ref := range roleRefs {
		if previous := seenPaths[ref.Path]; previous != "" && previous != role {
			collector.semantic("EXECUTION_RECEIPT_INVALID", path+".artifact_bindings", role+" reuses "+previous+" artifact path")
		}
		if previous := seenDigests[ref.SHA256]; previous != "" && previous != role {
			collector.semantic("EXECUTION_RECEIPT_INVALID", path+".artifact_bindings", role+" reuses "+previous+" artifact digest")
		}
		seenPaths[ref.Path], seenDigests[ref.SHA256] = role, role
		document, valid := readEvidenceArtifact(snap, ref, role, states[role], qualification, backend, runID, path+".evidence."+strings.ToLower(role), collector)
		if valid && document.FixtureKind != receipt.FixtureKind {
			collector.semantic("EXECUTION_RECEIPT_INVALID", path+".evidence."+strings.ToLower(role), "all role-specific evidence must share one fixture kind")
		}
	}
	for _, canary := range backend.KnownGoodCanaries {
		if canary.Output == nil || *canary.Output != categoryRefs["GOOD_CANARY_RESULT"] {
			collector.semantic("EXECUTION_RECEIPT_INVALID", path+".known_good_canaries", "good canary output must bind the typed GOOD_CANARY_RESULT role")
		}
	}
	for _, canary := range backend.KnownBadCanaries {
		if canary.Output == nil || *canary.Output != categoryRefs["BAD_CANARY_COUNTEREXAMPLE"] || canary.Counterexample == nil || canary.Counterexample.Artifact != categoryRefs["BAD_CANARY_COUNTEREXAMPLE"] {
			collector.semantic("EXECUTION_RECEIPT_INVALID", path+".known_bad_canaries", "bad canary output and counterexample must bind the typed BAD_CANARY_COUNTEREXAMPLE role")
		}
	}
	for _, outcome := range backend.Outcomes {
		if len(outcome.ArtifactRefs) != 1 || outcome.ArtifactRefs[0] != categoryRefs["NORMALIZED_RESULT"] {
			collector.semantic("EXECUTION_RECEIPT_INVALID", path+".outcomes", "executed outcomes must bind only the typed NORMALIZED_RESULT role")
		}
	}
	for _, binding := range backend.ArtifactBindings {
		if binding.RunID != runID {
			collector.semantic("EXECUTION_RECEIPT_INVALID", path+".artifact_bindings", "category run_id does not match the typed execution run")
		}
	}
	if receipt.FixtureKind == "SYNTHETIC_NON_CLAIM" && receipt.Provenance != "SYNTHETIC_TEST_FIXTURE" ||
		receipt.FixtureKind == "PUBLIC_EXECUTION_RECEIPT" && receipt.Provenance != "PUBLIC_DERIVED_EXECUTION" {
		collector.semantic("EXECUTION_RECEIPT_INVALID", path+".sbx_execution.receipt.provenance", "execution fixture kind and provenance do not reconcile")
	}
	return receipt.FixtureKind, runID
}

func readEvidenceArtifact(snap *snapshot, ref artifactRef, role, state string, qualification *backendQualification, backend *backend, runID, path string, collector *findingCollector) (evidenceArtifactDocument, bool) {
	data, err := snap.read(ref.Path, maxJSONBytes)
	if err != nil {
		collector.semantic("MISSING_REQUIRED_ARTIFACT", path, err.Error())
		return evidenceArtifactDocument{}, false
	}
	var document evidenceArtifactDocument
	if err := decodeStrict(data, &document); err != nil {
		collector.semantic("EXECUTION_RECEIPT_INVALID", path, "evidence artifact is not a strict role-specific document: "+err.Error())
		return evidenceArtifactDocument{}, false
	}
	foundation := qualification.BorrowedSandboxFoundation
	validKind := document.FixtureKind == "SYNTHETIC_NON_CLAIM" || document.FixtureKind == "PUBLIC_EXECUTION_RECEIPT"
	validProvenance := document.FixtureKind == "SYNTHETIC_NON_CLAIM" && document.Provenance == "SYNTHETIC_TEST_FIXTURE" ||
		document.FixtureKind == "PUBLIC_EXECUTION_RECEIPT" && document.Provenance == "PUBLIC_DERIVED_EXECUTION"
	validAttribution := document.FixtureKind == "SYNTHETIC_NON_CLAIM" && ref.Attribution == "US006_OWNED" ||
		document.FixtureKind == "PUBLIC_EXECUTION_RECEIPT" && ref.Attribution == "PUBLIC_DERIVED_EXECUTION"
	if document.SchemaVersion != "1.0.0" || document.EntityType != "FormalEvidenceArtifact" || !validKind || !validProvenance || !validAttribution ||
		document.Role != role || document.State != state || document.BackendID != backend.BackendID || document.Method != backend.Method ||
		document.RunID == "" || runID != "" && document.RunID != runID || backend.Tool.Version == nil || backend.Tool.BinarySHA256 == nil ||
		document.ToolName != backend.Tool.Name || document.ToolVersion != *backend.Tool.Version || document.ToolBinarySHA256 != *backend.Tool.BinarySHA256 ||
		document.CLIVersion != foundation.CLIVersion || document.DaemonVersion != foundation.DaemonVersion ||
		document.TemplateReference != foundation.TemplateReference || document.SandboxPolicyDigest != foundation.SandboxPolicyDigest ||
		!equalStrings(document.ObligationIDs, backend.ObligationIDs) || document.Assurance != assuranceCeiling || document.IndependentReviewClaimed || document.Production {
		collector.semantic("EXECUTION_RECEIPT_INVALID", path, "role-specific evidence does not reconcile role, state, provenance, run, tool, profile, obligations, and assurance")
		return document, false
	}
	return document, true
}

func validateReplayIdentity(snap *snapshot, qualification *backendQualification, backend *backend, mode, path string, collector *findingCollector) {
	if backend.ExecutionState == "UNAVAILABLE_BACKEND_BLOCKED" {
		if backend.Replay.ReplayID != nil || len(backend.Replay.Argv) != 0 || len(backend.Replay.Environment) != 0 || backend.Replay.Seed != nil || backend.Replay.ExpectedExitCode != nil || backend.Replay.SemanticOutputDigest != nil || backend.Replay.RepeatCount != 0 || backend.Replay.ReconciledIdentically || len(backend.Replay.Runs) != 0 {
			collector.semantic("REPLAY_MISMATCH", path+".replay", "unavailable backend cannot invent a replay identity or semantic output")
		}
		return
	}
	if backend.Replay.ReplayID == nil || backend.Replay.ExpectedExitCode == nil || backend.Replay.SemanticOutputDigest == nil || backend.Replay.Seed == nil || len(backend.Replay.Argv) == 0 {
		collector.semantic("MISSING_REQUIRED_ARTIFACT", path+".replay", "executed backend requires a complete replay identity")
		return
	}
	if !sort.StringsAreSorted(backend.Replay.Environment) {
		collector.semantic("NONCANONICAL_SET_ORDER", path+".replay.environment", "replay environment must be sorted")
	}
	if backend.ExecutionState == "EXECUTED_PASS" && (backend.Replay.RepeatCount < 2 || !backend.Replay.ReconciledIdentically) {
		collector.semantic("REPLAY_MISMATCH", path+".replay", "passing execution requires at least two identical semantic replays")
	}
	expected, err := replayDigest(qualification, backend)
	if err != nil || *backend.Replay.ReplayID != expected {
		collector.semantic("REPLAY_MISMATCH", path+".replay.replay_id", "replay identity does not bind the canonical backend tuple")
	}
	validateReplayRuns(snap, qualification, backend, path, collector)
	_ = mode
}

func validateReplayRuns(snap *snapshot, qualification *backendQualification, backend *backend, path string, collector *findingCollector) {
	if backend.Replay.RepeatCount != len(backend.Replay.Runs) || len(backend.Replay.Runs) == 0 {
		collector.semantic("REPLAY_MISMATCH", path+".replay.runs", "repeat_count must derive from independently retained replay runs")
		return
	}
	seenRunIDs := map[string]bool{}
	seenReceipts := map[string]bool{}
	seenOutputs := map[string]bool{}
	for index, run := range backend.Replay.Runs {
		runPath := fmt.Sprintf("%s.replay.runs[%d]", path, index)
		if seenRunIDs[run.RunID] || seenReceipts[run.Receipt.Path] || seenOutputs[run.NormalizedOutput.Path] {
			collector.semantic("REPLAY_MISMATCH", runPath, "each replay needs a unique run_id, receipt path, and normalized-output path")
		}
		seenRunIDs[run.RunID] = true
		seenReceipts[run.Receipt.Path] = true
		seenOutputs[run.NormalizedOutput.Path] = true
		if backend.Replay.SemanticOutputDigest == nil || run.SemanticOutputDigest != *backend.Replay.SemanticOutputDigest ||
			run.NormalizedOutput.SHA256 != run.SemanticOutputDigest || !equalStrings(run.ObligationIDs, backend.ObligationIDs) {
			collector.semantic("REPLAY_MISMATCH", runPath, "replay run must bind the identical normalized output digest and exact obligation inventory")
		}
		data, err := snap.read(run.Receipt.Path, maxJSONBytes)
		if err != nil {
			collector.semantic("MISSING_REQUIRED_ARTIFACT", runPath+".receipt", err.Error())
			continue
		}
		var receipt replayReceiptDocument
		if err := decodeStrict(data, &receipt); err != nil {
			collector.semantic("REPLAY_MISMATCH", runPath+".receipt", "replay receipt is not a strict typed document: "+err.Error())
			continue
		}
		if receipt.SchemaVersion != "1.0.0" || receipt.EntityType != "FormalReplayReceipt" ||
			(receipt.FixtureKind != "SYNTHETIC_NON_CLAIM" && receipt.FixtureKind != "PUBLIC_EXECUTION_RECEIPT") ||
			receipt.FixtureKind != backend.evidenceKind ||
			(receipt.FixtureKind == "SYNTHETIC_NON_CLAIM" && receipt.Provenance != "SYNTHETIC_TEST_FIXTURE") ||
			(receipt.FixtureKind == "PUBLIC_EXECUTION_RECEIPT" && receipt.Provenance != "PUBLIC_DERIVED_EXECUTION") ||
			(receipt.FixtureKind == "SYNTHETIC_NON_CLAIM" && run.Receipt.Attribution != "US006_OWNED") ||
			(receipt.FixtureKind == "PUBLIC_EXECUTION_RECEIPT" && run.Receipt.Attribution != "PUBLIC_DERIVED_EXECUTION") ||
			receipt.BackendID != backend.BackendID || receipt.RunID != run.RunID || backend.Replay.ReplayID == nil || receipt.ReplayID != *backend.Replay.ReplayID ||
			backend.Replay.ExpectedExitCode == nil || receipt.ExitCode != *backend.Replay.ExpectedExitCode ||
			!equalStrings(receipt.ObligationIDs, backend.ObligationIDs) || receipt.SemanticOutputDigest != run.SemanticOutputDigest ||
			receipt.NormalizedOutput != run.NormalizedOutput || receipt.Assurance != assuranceCeiling || receipt.IndependentReviewClaimed || receipt.Production {
			collector.semantic("REPLAY_MISMATCH", runPath+".receipt", "typed replay receipt does not reconcile run identity, exit, obligations, normalized output, and assurance")
		}
		document, valid := readEvidenceArtifact(snap, run.NormalizedOutput, "NORMALIZED_RESULT", "PASS", qualification, backend, backend.evidenceRunID, runPath+".normalized_output", collector)
		if valid && document.FixtureKind != backend.evidenceKind {
			collector.semantic("REPLAY_MISMATCH", runPath+".normalized_output", "normalized replay output fixture kind differs from the executed evidence tree")
		}
	}
	for _, outcome := range backend.Outcomes {
		bound := false
		for _, ref := range outcome.ArtifactRefs {
			for _, run := range backend.Replay.Runs {
				bound = bound || ref == run.NormalizedOutput
			}
		}
		if !bound {
			collector.semantic("REPLAY_MISMATCH", path+".outcomes", "every executed outcome must reopen through a retained normalized replay output")
		}
	}
	_ = qualification
}

func replayDigest(qualification *backendQualification, backend *backend) (string, error) {
	var bounds any
	if err := json.Unmarshal(backend.Bounds, &bounds); err != nil {
		return "", err
	}
	foundationData, err := vendorprotocol.CanonicalJSON(qualification.BorrowedSandboxFoundation)
	if err != nil {
		return "", err
	}
	promotionDigest := ""
	if backend.Tool.ExecutablePromotion != nil {
		promotionDigest = backend.Tool.ExecutablePromotion.SHA256
	}
	tuple := struct {
		BackendID             string   `json:"backend_id"`
		Method                string   `json:"method"`
		ToolDigest            *string  `json:"tool_digest"`
		ExecutablePromotion   string   `json:"executable_promotion"`
		BorrowedProfileDigest string   `json:"borrowed_profile_digest"`
		RequestDigest         *string  `json:"request_digest"`
		InputRootDigest       *string  `json:"input_root_digest"`
		ProofTargetsDigest    string   `json:"proof_targets_digest"`
		ConnectionModelDigest string   `json:"connection_model_digest"`
		ConcurrencyPlanDigest string   `json:"concurrency_plan_digest"`
		PropertyIDs           []string `json:"property_ids"`
		ObligationIDs         []string `json:"obligation_ids"`
		Bounds                any      `json:"bounds"`
		Assumptions           []string `json:"assumptions"`
		UnsupportedConstructs []string `json:"unsupported_constructs"`
		Argv                  []string `json:"argv"`
		Environment           []string `json:"environment"`
		WorkingDirectory      string   `json:"working_directory"`
		Seed                  *string  `json:"seed"`
	}{
		backend.BackendID, backend.Method, backend.Tool.BinarySHA256, promotionDigest,
		vendorprotocol.DigestBytes(foundationData), backend.SBXExecution.RequestDigest, backend.SBXExecution.InputRootDigest,
		qualification.ProofTargets.SHA256, qualification.ConnectionModel.SHA256, qualification.ConcurrencyPlan.SHA256,
		backend.ExpectedPropertyIDs, backend.ObligationIDs, bounds, backend.Assumptions, backend.UnsupportedConstructs,
		backend.Replay.Argv, backend.Replay.Environment, backend.Replay.WorkingDirectory, backend.Replay.Seed,
	}
	data, err := vendorprotocol.CanonicalJSON(tuple)
	if err != nil {
		return "", err
	}
	return vendorprotocol.DigestBytes(data), nil
}

func validateBounds(backend *backend, plan *concurrencyPlan, path string, collector *findingCollector) {
	switch backend.Method {
	case "FINITE_EXHAUSTIVE_PROTOTYPE":
		var bounds struct {
			PayloadLengths []int    `json:"payload_lengths"`
			Offsets        []int    `json:"offsets"`
			Keys           []string `json:"keys"`
			ByteValues     []int    `json:"byte_values"`
			CasesEvaluated int      `json:"cases_evaluated"`
		}
		if err := decodeStrict(backend.Bounds, &bounds); err != nil {
			collector.semantic("SCHEMA_VIOLATION", path+".bounds", err.Error())
			return
		}
		if backend.ExecutionState != "UNAVAILABLE_BACKEND_BLOCKED" && bounds.CasesEvaluated == 0 {
			collector.semantic("ZERO_OBLIGATIONS", path+".bounds.cases_evaluated", "executed finite backend requires nonzero evaluated cases")
		}
	case "KANI_BOUNDED_MODEL_CHECKING":
		var bounds struct {
			CasesEvaluated int `json:"cases_evaluated"`
		}
		if err := json.Unmarshal(backend.Bounds, &bounds); err != nil {
			collector.semantic("SCHEMA_VIOLATION", path+".bounds", err.Error())
		} else if backend.ExecutionState != "UNAVAILABLE_BACKEND_BLOCKED" && bounds.CasesEvaluated == 0 {
			collector.semantic("ZERO_OBLIGATIONS", path+".bounds.cases_evaluated", "executed Kani backend requires nonzero evaluated cases")
		}
	case "LOOM_SYSTEMATIC_SCHEDULE_EXPLORATION":
		var bounds struct {
			MaxTasks       int   `json:"max_tasks"`
			MaxSchedules   int   `json:"max_schedules"`
			MaxPreemptions int   `json:"max_preemptions"`
			MaxBranches    int   `json:"max_branches"`
			QueueCaps      []int `json:"queue_capacities"`
			ScheduleCount  int   `json:"schedule_count"`
		}
		if err := decodeStrict(backend.Bounds, &bounds); err != nil {
			collector.semantic("SCHEMA_VIOLATION", path+".bounds", err.Error())
			return
		}
		if bounds.MaxTasks != plan.Bounds.MaxTasks || bounds.MaxSchedules != plan.Bounds.MaxSchedules || bounds.MaxPreemptions != plan.Bounds.MaxPreemptions || bounds.MaxBranches != plan.Bounds.MaxBranches || !equalInts(bounds.QueueCaps, []int{plan.Bounds.CommandQueueCapacity}) {
			collector.stale("CONCURRENCY_BOUND_DRIFT", path+".bounds", "Loom bounds do not match the fixed concurrency plan")
		}
		if bounds.ScheduleCount > bounds.MaxSchedules {
			collector.semantic("INFLATED_COUNT", path+".bounds.schedule_count", "schedule count exceeds the declared bound")
		}
		if backend.ExecutionState != "UNAVAILABLE_BACKEND_BLOCKED" && bounds.ScheduleCount == 0 {
			collector.semantic("ZERO_OBLIGATIONS", path+".bounds.schedule_count", "executed Loom backend requires a nonzero explored schedule count")
		}
	case "TLC_EXPLICIT_STATE_MODEL_CHECKING":
		var bounds struct {
			StateBound      int `json:"state_bound"`
			CommandCapacity int `json:"command_capacity"`
			WriteCapacity   int `json:"write_capacity"`
			EventCapacity   int `json:"event_capacity"`
			DistinctStates  int `json:"distinct_states"`
			Transitions     int `json:"transitions"`
		}
		if err := json.Unmarshal(backend.Bounds, &bounds); err != nil {
			collector.semantic("SCHEMA_VIOLATION", path+".bounds", err.Error())
			return
		}
		if bounds.StateBound != 4 || bounds.CommandCapacity != 2 || bounds.WriteCapacity != 2 || bounds.EventCapacity != 2 {
			collector.stale("CONCURRENCY_BOUND_DRIFT", path+".bounds", "TLC state and queue bounds must match ConnectionModel")
		}
		if backend.ExecutionState != "UNAVAILABLE_BACKEND_BLOCKED" && (bounds.DistinctStates == 0 || bounds.Transitions == 0) {
			collector.semantic("ZERO_OBLIGATIONS", path+".bounds", "executed TLC backend requires nonzero state and transition counts")
		}
	}
}

func validateAggregateState(qualification *backendQualification, collector *findingCollector) {
	passes := map[string]bool{}
	blocked := false
	for _, backend := range qualification.Backends {
		if backend.ExecutionState == "UNAVAILABLE_BACKEND_BLOCKED" || backend.ExecutionState == "EXECUTED_COUNTEREXAMPLE" || backend.evidenceKind == "SYNTHETIC_NON_CLAIM" || !backendOutcomesPass(backend) {
			blocked = true
		} else {
			passes[backend.ClaimScope] = true
		}
	}
	wanted := "BLOCKED"
	if !blocked && len(passes) == 1 {
		switch {
		case passes["BOUNDED_TEST_EVIDENCE"]:
			wanted = "BOUNDED_ONLY"
		case passes["SYSTEMATIC_CONCURRENCY_TESTING"]:
			wanted = "SYSTEMATIC_ONLY"
		case passes["PROVED_MODEL"]:
			wanted = "MODEL_ONLY"
		}
	} else if !blocked && len(passes) > 1 {
		wanted = "MIXED_NON_PRODUCTION"
	}
	if qualification.AggregateState != wanted {
		collector.semantic("INFLATED_CLAIM", "$.aggregate_state", "aggregate state does not derive from backend execution states and claim ceilings")
	}
}

func backendOutcomesPass(backend backend) bool {
	wanted := map[string]string{
		"FINITE_EXHAUSTIVE_PROTOTYPE":          "BOUNDED_CHECK_PASSED",
		"KANI_BOUNDED_MODEL_CHECKING":          "BOUNDED_CHECK_PASSED",
		"LOOM_SYSTEMATIC_SCHEDULE_EXPLORATION": "SYSTEMATIC_EXPLORATION_PASSED",
		"TLC_EXPLICIT_STATE_MODEL_CHECKING":    "MODEL_CHECK_PASSED",
	}[backend.Method]
	if backend.ExecutionState != "EXECUTED_PASS" || backend.evidenceKind == "SYNTHETIC_NON_CLAIM" || len(backend.Outcomes) == 0 {
		return false
	}
	for _, outcome := range backend.Outcomes {
		if outcome.RawOutcome != wanted || outcome.Counterexample != nil || outcome.ClaimScope != backend.ClaimScope {
			return false
		}
	}
	return true
}

func sbxExecutionEmpty(value sbxExecution) bool {
	return value.CLIVersion == nil && value.DaemonVersion == nil && value.TemplateReference == nil && value.SandboxPolicyDigest == nil && value.RequestDigest == nil && value.ReceiptDigest == nil && value.InputRootDigest == nil && value.OutputRootDigest == nil && value.CleanupState == nil && value.ClassificationState == nil && value.Profile == nil && value.CapabilityProbe == nil && value.Request == nil && value.Receipt == nil && value.InputManifest == nil && value.OutputManifest == nil && value.CleanupReceipt == nil && value.ClassifierProjection == nil
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
