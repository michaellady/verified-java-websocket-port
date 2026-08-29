package formal

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"sort"
	"strings"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
	"github.com/michaellady/verified-java-websocket-port/internal/provenance"
)

type findingCollector struct {
	values []Finding
}

func (collector *findingCollector) semantic(reason, path, message string) {
	collector.add("SEMANTIC_INCONSISTENCY", "BLOCK", reason, path, message)
}

func (collector *findingCollector) digest(reason, path, message string) {
	collector.add("DIGEST_MISMATCH", "QUARANTINE", reason, path, message)
}

func (collector *findingCollector) stale(reason, path, message string) {
	collector.add("STALE_INPUT", "INVALIDATE", reason, path, message)
}

func (collector *findingCollector) add(code, disposition, reason, path, message string) {
	collector.values = append(collector.values, Finding{
		Code: code, Disposition: disposition, Reason: reason, Path: path, Message: message,
	})
}

func (collector *findingCollector) normalized() []Finding {
	sort.Slice(collector.values, func(i, j int) bool {
		left, right := collector.values[i], collector.values[j]
		return strings.Join([]string{left.Code, left.Reason, left.Path, left.Message}, "\x00") <
			strings.Join([]string{right.Code, right.Reason, right.Path, right.Message}, "\x00")
	})
	result := make([]Finding, 0, len(collector.values))
	for _, finding := range collector.values {
		if len(result) == 0 || result[len(result)-1] != finding {
			result = append(result, finding)
		}
	}
	return result
}

func validate(ctx context.Context, request Request) (Verdict, error) {
	if err := ctx.Err(); err != nil {
		return Verdict{}, err
	}
	if request.RootPath == "" {
		return Verdict{}, errors.New("root path is required")
	}
	if request.Mode == "" {
		request.Mode = ModePreflight
	}
	if request.Mode != ModePreflight && request.Mode != ModeReplay {
		return Verdict{}, fmt.Errorf("mode %q must be %s or %s", request.Mode, ModePreflight, ModeReplay)
	}

	snap, err := newSnapshot(request.RootPath)
	if err != nil {
		return Verdict{}, err
	}
	defer func() { _ = snap.close() }()

	collector := &findingCollector{}
	if proofDocument := snap.files[proofTargetsPath]; proofDocument != nil {
		if commit, resolveErr := provenance.ResolveHistoricalArtifactCommit(request.RootPath, proofTargetsPath, proofDocument); resolveErr == nil {
			snap.historicalCommit = commit
			if _, qualificationErr := provenance.LoadAndValidateCurrentHeadQualification(request.RootPath); qualificationErr != nil {
				collector.semantic("CURRENT_QUALIFICATION_INVALID", provenance.CurrentHeadQualificationPath, qualificationErr.Error())
			}
		}
	}
	for _, required := range []string{
		proofTargetsPath,
		backendQualificationPath,
		connectionModelPath,
		concurrencyPlanPath,
		proofTargetsSchemaPath,
		backendSchemaPath,
		concurrencySchemaPath,
	} {
		if readErr := snap.errors[required]; readErr != nil {
			reason := "INVALID_ARTIFACT_SNAPSHOT"
			if errors.Is(readErr, fs.ErrNotExist) {
				reason = "MISSING_REQUIRED_ARTIFACT"
			}
			collector.semantic(reason, required, readErr.Error())
		}
	}

	var targets proofTargets
	targetsOK := decodeDocument(snap.files[proofTargetsPath], proofTargetsPath, &targets, collector)
	var qualification backendQualification
	qualificationOK := decodeDocument(snap.files[backendQualificationPath], backendQualificationPath, &qualification, collector)
	var plan concurrencyPlan
	planOK := decodeDocument(snap.files[concurrencyPlanPath], concurrencyPlanPath, &plan, collector)

	validateSchemaDocument(snap, proofTargetsSchemaPath, proofTargetsPath, collector)
	validateSchemaDocument(snap, backendSchemaPath, backendQualificationPath, collector)
	validateSchemaDocument(snap, concurrencySchemaPath, concurrencyPlanPath, collector)

	if model, ok := snap.files[connectionModelPath]; ok {
		if err := validateTLA(model); err != nil {
			collector.semantic("MALFORMED_TLA_MODULE", connectionModelPath, err.Error())
		}
	}

	if targetsOK {
		validateProofTargets(&targets, collector)
	}
	if planOK {
		validateConcurrencyPlan(&plan, collector)
	}
	if qualificationOK {
		validateQualificationFoundation(&qualification, collector)
	}
	if targetsOK && qualificationOK && planOK {
		validateGraph(snap, &targets, &qualification, &plan, request.Mode, collector)
		validateDeclaredArtifacts(snap, &targets, &qualification, collector)
	}

	findings := collector.normalized()
	state := "BLOCKED"
	if qualificationOK {
		state = qualification.AggregateState
	}
	return Verdict{
		Valid:                    len(findings) == 0,
		State:                    state,
		BundleDigest:             bundleDigest(snap),
		ClaimScopes:              collectClaimScopes(targetsOK, &targets, qualificationOK, &qualification, planOK, &plan),
		Findings:                 findings,
		Assurance:                assuranceCeiling,
		IndependentReviewClaimed: false,
	}, nil
}

func decodeDocument(data []byte, path string, target any, collector *findingCollector) bool {
	if data == nil {
		return false
	}
	if err := decodeStrict(data, target); err != nil {
		collector.semantic(decodeReason(err), path, err.Error())
		return false
	}
	return true
}

func validateSchemaDocument(snap *snapshot, schemaPath, documentPath string, collector *findingCollector) {
	schemaData, schemaOK := snap.files[schemaPath]
	documentData, documentOK := snap.files[documentPath]
	if !schemaOK || !documentOK {
		return
	}
	schema, err := compileSchema(schemaData, schemaPath)
	if err != nil {
		collector.semantic("SCHEMA_INVALID", schemaPath, err.Error())
		return
	}
	var document any
	if err := decodeStrict(documentData, &document); err != nil {
		return
	}
	if err := schema.Validate(document); err != nil {
		for _, message := range schemaMessages(err) {
			collector.semantic("SCHEMA_VIOLATION", documentPath, message)
		}
	}
}

func validateProofTargets(targets *proofTargets, collector *findingCollector) {
	if targets.Assurance != assuranceCeiling || targets.IndependentReviewClaimed || targets.Production || targets.Publication {
		collector.semantic("INFLATED_CLAIM", proofTargetsPath, "proof-target assurance must remain owner-attested, non-independent, non-production, and non-publication")
	}
	if !equalStrings(targets.RequiredConsumers, []string{"CONFORMANCE", "DIFFERENTIAL", "PRODUCTION"}) {
		collector.semantic("DISCONNECTED_TARGET", "$.required_consumers", "all three exact consumers are required")
	}
	checkSortedArtifactRefs(targets.SourceBasis, "$.source_basis", collector)
	expectedSources := map[string]artifactRef{
		"assurance/evidence-model.json":              {Path: "assurance/evidence-model.json", SHA256: "sha256:8202a03d9a0eddcd2d57df366f501fc99dc79177cfe7c1eaf9549e0d6e6e368f", Attribution: "BORROWED_CLAUDE_US004"},
		"corpora/public/manifest.json":               {Path: "corpora/public/manifest.json", SHA256: "sha256:202a3e0d0c84c41cc635adc41a8d2eb3c1e62962c1e343697987ef8f0c69c54b", Attribution: "BORROWED_CLAUDE_US005"},
		"corpora/public/scenarios.jsonl":             {Path: "corpora/public/scenarios.jsonl", SHA256: "sha256:fe1735bc42c11f66afe2965a7449fc6cad31cca3e2048305388241c781501e5f", Attribution: "BORROWED_CLAUDE_US005"},
		"evidence/corpus-calibration.json":           {Path: "evidence/corpus-calibration.json", SHA256: "sha256:59845d2713fcd429de792670f687dba29542a74b9e5cfa5351159d5e7fea987a", Attribution: "BORROWED_CLAUDE_US005"},
		"evidence/intake/compatibility-surface.json": {Path: "evidence/intake/compatibility-surface.json", SHA256: "sha256:0117560795fbfbe92e1c11a999bcec937c4ab27950ba6e5a1d0f0c73a286602c", Attribution: "BORROWED_CLAUDE_US003"},
		"evidence/intake/cutover-contract.json":      {Path: "evidence/intake/cutover-contract.json", SHA256: "sha256:ea6d6148dd67b705e74db48056dd5f17f22626fda48d148aef01f37de2d46f76", Attribution: "AUGMENTED_CODEX_US010"},
		"evidence/intake/port-seam-dossier.json":     {Path: "evidence/intake/port-seam-dossier.json", SHA256: "sha256:5e117e4300bb5c68a1ce255e1e4af6c8bd93af132cd6c2144a881fad95d1d854", Attribution: "BORROWED_CLAUDE_US003"},
	}
	if len(targets.SourceBasis) != len(expectedSources) {
		collector.semantic("BORROWED_FOUNDATION_DRIFT", "$.source_basis", "borrowed US-003/004/005 source basis is incomplete")
	}
	for _, source := range targets.SourceBasis {
		if expected, ok := expectedSources[source.Path]; !ok || source != expected {
			collector.semantic("BORROWED_FOUNDATION_DRIFT", "$.source_basis", "borrowed source path, digest, or attribution drifted: "+source.Path)
		}
	}
	expectedTargets := map[string]struct {
		file, symbol, kind, sha256, gitBlob string
	}{
		"target.frame-header-decoder": {
			"rust/connection-core/src/frame/decode.rs",
			"websocket_core::frame::decode::FrameHeaderDecoder::decode_header",
			"ASSOCIATED_FUNCTION",
			"sha256:973f7f00cd1cf862fba289b4317d772fc58d2d774ec1f92f8d42c049e9ee4e88",
			"58d0350bea1baefcaae36cac3229d3d30dfe7212",
		},
		"target.frame-mask": {
			"rust/connection-core/src/frame/mask.rs",
			"websocket_core::frame::mask::apply_mask_in_place",
			"FUNCTION",
			"sha256:316ec1c447d3c37d4b8593ac7ccb82567b272158a7102d90846797e26d8deb29",
			"15bf4ff702775073a7995534c1acdc40001d2def",
		},
	}
	if len(targets.Targets) != len(expectedTargets) {
		collector.semantic("MISSING_TARGET", "$.targets", "the two exact US-012 production targets are required")
	}
	if !sortedBy(targets.Targets, func(value target) string { return value.TargetID }) {
		collector.semantic("NONCANONICAL_SET_ORDER", "$.targets", "targets must be sorted by target_id")
	}
	seenTargets := map[string]bool{}
	seenObligations := map[string]bool{}
	for index := range targets.Targets {
		target := &targets.Targets[index]
		path := fmt.Sprintf("$.targets[%d]", index)
		expected, ok := expectedTargets[target.TargetID]
		if !ok {
			collector.semantic("MISSING_TARGET", path+".target_id", "target does not name a frozen US-012 production identity")
			continue
		}
		if seenTargets[target.TargetID] {
			collector.semantic("DUPLICATE_IDENTIFIER", path+".target_id", "target identifier is duplicated")
		}
		seenTargets[target.TargetID] = true
		if target.PlannedFile != expected.file || target.ItemKind != expected.kind {
			collector.semantic("DISCONNECTED_TARGET", path, "planned file or item kind differs from the frozen target")
		}
		if target.RustSymbol != expected.symbol {
			reason := "DISCONNECTED_TARGET"
			if strings.Contains(strings.ToLower(target.RustSymbol), "proof") || strings.Contains(strings.ToLower(target.RustSymbol), "test") {
				reason = "PROOF_ONLY_DUPLICATE"
			}
			collector.semantic(reason, path+".rust_symbol", "result must attach to the exact frozen production symbol")
		}
		if target.SourceSHA256 == nil || *target.SourceSHA256 != expected.sha256 || target.SourceGitBlob == nil || *target.SourceGitBlob != expected.gitBlob {
			collector.semantic("MISSING_DIGEST", path, "resolved bounded target must bind the exact shipped SHA-256 and Git blob")
		}
		expectedSemanticIdentity := "git-blob:" + expected.gitBlob + "#" + expected.symbol
		if target.SemanticIdentity == nil || *target.SemanticIdentity != expectedSemanticIdentity {
			collector.semantic("DISCONNECTED_TARGET", path+".semantic_identity", "semantic identity must bind the exact shipped Git blob and Rust symbol")
		}
		if len(target.Obligations) == 0 {
			collector.semantic("ZERO_OBLIGATIONS", path+".obligations", "a proof target must carry nonzero obligations")
		}
		validateTargetLinkage(target, path, collector)
		if !sortedBy(target.Obligations, func(value obligation) string { return value.ObligationID }) {
			collector.semantic("NONCANONICAL_SET_ORDER", path+".obligations", "obligations must be sorted by obligation_id")
		}
		for obligationIndex := range target.Obligations {
			item := &target.Obligations[obligationIndex]
			itemPath := fmt.Sprintf("%s.obligations[%d]", path, obligationIndex)
			if seenObligations[item.ObligationID] {
				collector.semantic("DUPLICATE_IDENTIFIER", itemPath+".obligation_id", "obligation identifier is duplicated")
			}
			seenObligations[item.ObligationID] = true
			if item.SubjectTargetID != target.TargetID {
				collector.semantic("MISSING_TARGET", itemPath+".subject_target_id", "obligation subject does not resolve to its containing production target")
			}
			if item.MinimumObligationCount < 1 {
				collector.semantic("ZERO_OBLIGATIONS", itemPath+".minimum_obligation_count", "minimum obligation count must be nonzero")
			}
			checkSortedUnique(item.RequiredBackendIDs, itemPath+".required_backend_ids", collector)
			checkSortedUnique(item.ExpectedCanaryIDs, itemPath+".expected_canary_ids", collector)
			checkSortedUnique(item.AllowedClaimScopes, itemPath+".allowed_claim_scopes", collector)
			if !item.ProductionRefinementRequired {
				collector.semantic("REFINEMENT_MISSING", itemPath+".production_refinement_required", "every production-code obligation requires future refinement")
			}
		}
	}
	wantedObligations := []string{
		"obligation.checked-header-arithmetic",
		"obligation.control-fin-and-length",
		"obligation.length-canonical-16",
		"obligation.length-canonical-64-high-bit-zero",
		"obligation.length-canonical-7",
		"obligation.mask-equation",
		"obligation.mask-involution",
		"obligation.preallocation-cap",
		"obligation.role-masking",
	}
	if !sameSet(mapKeys(seenObligations), wantedObligations) {
		collector.semantic("MISSING_TARGET", "$.targets.obligations", "the exact nine US-012 obligations are required")
	}
}

func validateTargetLinkage(target *target, path string, collector *findingCollector) {
	if !sortedBy(target.RequiredCallPaths, func(value callPath) string { return value.Consumer }) || len(target.RequiredCallPaths) != 3 {
		collector.semantic("DISCONNECTED_TARGET", path+".required_call_paths", "consumer call paths must be the exact sorted three-record set")
	}
	consumerSet := make([]string, 0, len(target.RequiredCallPaths))
	for _, call := range target.RequiredCallPaths {
		consumerSet = append(consumerSet, call.Consumer)
	}
	if !equalStrings(consumerSet, []string{"CONFORMANCE", "DIFFERENTIAL", "PRODUCTION"}) {
		collector.semantic("DISCONNECTED_TARGET", path+".required_call_paths", "conformance, differential, and production must all reach the same symbol")
	}
	switch target.LinkageState {
	case "UNRESOLVED_FUTURE_PRODUCTION_SYMBOL":
		if target.SourceSHA256 != nil || target.SourceGitBlob != nil || target.SemanticIdentity != nil || target.BoundedEvidence != nil || target.MaximumCurrentScope != "FUTURE_PRODUCTION_REFINEMENT" {
			collector.semantic("INFLATED_CLAIM", path, "an unresolved target permits only a null source identity and future refinement scope")
		}
		for _, call := range target.RequiredCallPaths {
			if call.State != "FUTURE_REQUIRED" || call.LinkageArtifact != nil {
				collector.semantic("DISCONNECTED_TARGET", path+".required_call_paths", "unresolved target consumers must remain explicit future requirements")
			}
		}
	case "RESOLVED_ACTUAL_SYMBOL_BOUNDED_PENDING_CONSUMERS":
		expectedEvidence := artifactRef{Path: "assurance/formal/frame-results.json", SHA256: "sha256:5d332a60b82652e326678af78658f8af6e449b1bdb196b38d4eda8a62b6665c2", Attribution: "US012_OWNED"}
		if target.SourceSHA256 == nil || target.SourceGitBlob == nil || target.SemanticIdentity == nil || target.BoundedEvidence == nil || *target.BoundedEvidence != expectedEvidence || target.MaximumCurrentScope != "BOUNDED_TEST_EVIDENCE" {
			collector.semantic("MISSING_DIGEST", path, "resolved bounded target requires source SHA-256, Git blob, semantic identity, and bounded-test ceiling")
		}
		for _, call := range target.RequiredCallPaths {
			if call.State != "PENDING_CONSUMER" || call.LinkageArtifact != nil {
				collector.semantic("DISCONNECTED_TARGET", path+".required_call_paths", "resolved bounded target must keep all three unlinked consumers explicit")
			}
		}
	case "RESOLVED_PRODUCTION_SYMBOL":
		if target.SourceSHA256 == nil || target.SourceGitBlob == nil || target.SemanticIdentity == nil {
			collector.semantic("MISSING_DIGEST", path, "resolved production target requires source digest and semantic identity")
		}
		for _, call := range target.RequiredCallPaths {
			if call.State != "LINKED" || call.LinkageArtifact == nil {
				collector.semantic("DISCONNECTED_TARGET", path+".required_call_paths", "resolved production target requires three digest-bound linked consumers")
			}
		}
	case "DISCONNECTED":
		collector.semantic("DISCONNECTED_TARGET", path+".linkage_state", "a disconnected production target blocks every attached claim")
	default:
		collector.semantic("DISCONNECTED_TARGET", path+".linkage_state", "unknown production linkage state")
	}
}

func validateConcurrencyPlan(plan *concurrencyPlan, collector *findingCollector) {
	if plan.Assurance != assuranceCeiling || plan.IndependentReviewClaimed || plan.Production || plan.Publication {
		collector.semantic("INFLATED_CLAIM", concurrencyPlanPath, "concurrency plan must remain owner-attested, non-independent, non-production, and non-publication")
	}
	if plan.OwnerSymbol.Symbol != "websocket_driver::owner::ConnectionOwner::step" || plan.OwnerSymbol.State != "UNRESOLVED_FUTURE_PRODUCTION_SYMBOL" || plan.ClaimScope != "SYSTEMATIC_CONCURRENCY_TESTING" {
		collector.semantic("INFLATED_CLAIM", "$.owner_symbol", "the future owner symbol and systematic-only ceiling are fixed")
	}
	wantedActions := []string{"backpressure", "callback-delivery", "command-enqueue", "finish-close", "inbound-close", "inbound-frame", "outbound-flush", "owner-step", "shutdown"}
	actionIDs := make([]string, 0, len(plan.Actions))
	for index, action := range plan.Actions {
		actionIDs = append(actionIDs, action.ActionID)
		if action.MaximumOccurrencesPerSchedule < 1 || len(action.Preconditions) == 0 || len(action.Effects) == 0 || len(action.ObservableOutcomes) == 0 {
			collector.semantic("ZERO_OBLIGATIONS", fmt.Sprintf("$.actions[%d]", index), "every concurrency action must be bounded and observable")
		}
		checkSortedUnique(action.Preconditions, fmt.Sprintf("$.actions[%d].preconditions", index), collector)
		checkSortedUnique(action.Effects, fmt.Sprintf("$.actions[%d].effects", index), collector)
		checkSortedUnique(action.ObservableOutcomes, fmt.Sprintf("$.actions[%d].observable_outcomes", index), collector)
	}
	if !equalStrings(actionIDs, wantedActions) {
		collector.semantic("CONCURRENCY_BOUND_DRIFT", "$.actions", "the exact nine sorted concurrency actions are required")
	}
	wantedBounds := concurrencyBounds{
		ProducerTasks: 2, OwnerTasks: 1, InboundTasks: 1, FlushTasks: 1, CallbackTasks: 1, ShutdownTasks: 1,
		MaxTasks: 7, CommandQueueCapacity: 2, WriteQueueCapacity: 2, EventQueueCapacity: 2,
		CommandsPerProducer: 2, InboundActions: 2, FlushActions: 3, CallbackActions: 3, ShutdownActions: 1,
		MaxSchedules: 100000, MaxPreemptions: 3, MaxBranches: 1000000,
	}
	if plan.Bounds != wantedBounds {
		collector.stale("CONCURRENCY_BOUND_DRIFT", "$.bounds", "version-1 concurrency bounds changed")
	}
	wantedFairness := []string{
		"NO_PRODUCER_ADMISSION_FAIRNESS_QUEUE_FULL_RETURNS_BACKPRESSURE",
		"WEAK_CALLBACK_PROGRESS_WHEN_EVENT_PENDING",
		"WEAK_FLUSH_PROGRESS_WHEN_WRITABLE",
		"WEAK_OWNER_PROGRESS_WHEN_WORK_PENDING",
	}
	if !equalStrings(plan.Fairness, wantedFairness) {
		collector.stale("CONCURRENCY_BOUND_DRIFT", "$.fairness", "fairness assumptions changed")
	}
	propertyIDs := make([]string, 0, len(plan.Properties))
	for _, property := range plan.Properties {
		propertyIDs = append(propertyIDs, property.PropertyID)
		if property.PropertyID == "concurrency.accepted-eventual-exactly-once" && property.Statement != "Every accepted command is eventually disposed exactly once as APPLIED or as one typed terminal rejection; it is never lost or disposed twice." {
			collector.semantic("CONCURRENCY_BOUND_DRIFT", "$.properties", "accepted-command property must state eventual exactly-once disposition")
		}
	}
	wantedProperties := []string{"concurrency.accepted-eventual-exactly-once", "concurrency.bounded-counterexample", "concurrency.close-convergence", "concurrency.fifo-owner-order", "concurrency.no-post-terminal", "concurrency.no-write-bypass", "concurrency.queue-bounds", "concurrency.receiver-drop-typed", "concurrency.terminal-exactly-once"}
	if !equalStrings(propertyIDs, wantedProperties) {
		collector.semantic("MISSING_TARGET", "$.properties", "the exact sorted concurrency property inventory is required")
	}
	defectIDs := make([]string, 0, len(plan.SeededDefects))
	for _, defect := range plan.SeededDefects {
		defectIDs = append(defectIDs, defect.DefectID)
		if !contains(propertyIDs, defect.PropertyID) || defect.ExpectedOutcome != "COUNTEREXAMPLE" {
			collector.semantic("KNOWN_BAD_CANARY_SURVIVED", "$.seeded_defects", "every seeded defect must link to a property and require a counterexample")
		}
		if defect.DefectID == "lost-command" && defect.Mutation != "drop an accepted command without an APPLIED or typed terminal-rejection disposition" {
			collector.semantic("KNOWN_BAD_CANARY_SURVIVED", "$.seeded_defects", "lost-command must violate eventual exactly-once disposition")
		}
	}
	if !equalStrings(defectIDs, []string{"close-race", "duplicate-delivery", "lock-sharing", "lost-command", "queue-bypass", "write-reorder"}) {
		collector.semantic("KNOWN_BAD_CANARY_SURVIVED", "$.seeded_defects", "the exact six sorted seeded defects are required")
	}
	checkSortedUnique(plan.RequiredArtifacts, "$.required_artifacts", collector)
}

func validateQualificationFoundation(qualification *backendQualification, collector *findingCollector) {
	if qualification.Assurance != assuranceCeiling || qualification.IndependentReviewClaimed || qualification.Production || qualification.Signing || qualification.Publication {
		collector.semantic("INFLATED_CLAIM", backendQualificationPath, "qualification must remain owner-attested, non-independent, and non-production")
	}
	foundation := qualification.BorrowedSandboxFoundation
	expectedRefs := map[string]artifactRef{
		"security_validation": {Path: "evidence/security-validation.json", SHA256: "sha256:147f6fc2c29762dbf4e5035daefbe3edeecc224dfcb90d9fbf4f1734f857c36b", Attribution: "BORROWED_CLAUDE_US007"},
		"live_evidence":       {Path: "evidence/sbx-validation.json", SHA256: "sha256:ba746b0411cfe4759ee90460106ccc33f47992a5c72c13500f9022e5ce823be2", Attribution: "BORROWED_CLAUDE_US007"},
		"sbx_template":        {Path: "security/sbx-template.json", SHA256: "sha256:a5325fcb926253c267fe9e4baffb0dd397340a9e9edea521cab7f20bbfe3f312", Attribution: "BORROWED_CLAUDE_US007"},
		"sandbox_policy":      {Path: "security/sandbox-policy.json", SHA256: "sha256:64ef802a579cc5bd04f1cd430f1b0a1ec0829e3ee3f73a5e9f5c0c508c171854", Attribution: "BORROWED_CLAUDE_US007"},
	}
	actualRefs := map[string]artifactRef{
		"security_validation": foundation.SecurityValidation,
		"live_evidence":       foundation.LiveEvidence,
		"sbx_template":        foundation.SBXTemplate,
		"sandbox_policy":      foundation.SandboxPolicy,
	}
	for name, expected := range expectedRefs {
		if actualRefs[name] != expected {
			collector.semantic("BORROWED_FOUNDATION_DRIFT", "$.borrowed_sandbox_foundation."+name, "borrowed Claude US-007 artifact path, digest, or attribution drifted")
		}
	}
	if foundation.Attribution != "BORROWED_CLAUDE_US007" || foundation.AttemptID != "us007-sbx-output-live-0123" ||
		foundation.TargetCommit != "870aac28139604e217ae44469e679557994f7a0d" || foundation.SourceTree != "4937f8fab01300b542ca4dd23f90f6202ed3f268" ||
		foundation.ProjectionCanonical != "sha256:f89d23b18b1f7784d315e411ec90b38055f88026d08ffb188bd4fc8d1c961685" ||
		foundation.CLIVersion != "v0.39.0" || foundation.DaemonVersion != "v0.39.0" ||
		foundation.CLICommit != "def8cb0523a77e757bdd6ef52b459fe374f3783e" || foundation.DaemonCommit != "def8cb0523a77e757bdd6ef52b459fe374f3783e" ||
		foundation.CLIBinaryDigest != "sha256:f2a9e83f41a1cc20292d1f0e40974c495065f59a933aaec98f0619c286ddbeaf" ||
		foundation.CLIPath != "/opt/homebrew/Caskroom/sbx/0.39.0/bin/sbx" ||
		foundation.TemplateReference != "docker.io/docker/sandbox-templates:shell@sha256:1e642f7fadebcbff3d8de67114e9b42a5971ba9b4287ebffa1d05662f5a0f5ec" ||
		foundation.SandboxPolicyDigest != "sha256:64ef802a579cc5bd04f1cd430f1b0a1ec0829e3ee3f73a5e9f5c0c508c171854" ||
		foundation.EnforcementModel != "PARENT_SET_POSIX_RLIMIT_ENVELOPE" || foundation.AuthorizedUse != "OPERATIONAL_ISOLATION_FOUNDATION_ONLY" {
		collector.semantic("BORROWED_FOUNDATION_DRIFT", "$.borrowed_sandbox_foundation", "borrowed Claude US-007 attempt 0123 identity drifted")
	}
	if !strings.Contains(foundation.MemoryScope, "memory-allocation canary") || !strings.Contains(foundation.MemoryScope, "outer sbx") || !strings.Contains(foundation.MemoryScope, "no uniform per-workload memory cap") {
		collector.semantic("BORROWED_FOUNDATION_DRIFT", "$.borrowed_sandbox_foundation.memory_scope", "owner-accepted memory scoping amendment is not preserved")
	}
	limitations := strings.Join(foundation.Limitations, " ")
	for _, required := range []string{"owner authorization", "promotion", "cleanup", "classification", "public projection"} {
		if !strings.Contains(strings.ToLower(limitations), required) {
			collector.semantic("BORROWED_FOUNDATION_DRIFT", "$.borrowed_sandbox_foundation.limitations", "missing limitation: "+required)
		}
	}
}

func validateDeclaredArtifacts(snap *snapshot, targets *proofTargets, qualification *backendQualification, collector *findingCollector) {
	refs := append([]artifactRef{}, targets.SourceBasis...)
	refs = append(refs, qualification.ProofTargets, qualification.ConnectionModel, qualification.ConcurrencyPlan)
	foundation := qualification.BorrowedSandboxFoundation
	refs = append(refs, foundation.SecurityValidation, foundation.LiveEvidence, foundation.SBXTemplate, foundation.SandboxPolicy)
	for _, target := range targets.Targets {
		for _, call := range target.RequiredCallPaths {
			if call.LinkageArtifact != nil {
				refs = append(refs, *call.LinkageArtifact)
			}
		}
		if (target.LinkageState == "RESOLVED_PRODUCTION_SYMBOL" || target.LinkageState == "RESOLVED_ACTUAL_SYMBOL_BOUNDED_PENDING_CONSUMERS") && target.SourceSHA256 != nil {
			refs = append(refs, artifactRef{Path: target.PlannedFile, SHA256: *target.SourceSHA256, Attribution: "US006_OWNED"})
		}
		if target.BoundedEvidence != nil {
			refs = append(refs, *target.BoundedEvidence)
		}
	}
	for _, backend := range qualification.Backends {
		if backend.Tool.ExecutablePromotion != nil {
			refs = append(refs, *backend.Tool.ExecutablePromotion)
		}
		if backend.AvailabilityProbe.Receipt != nil {
			refs = append(refs, *backend.AvailabilityProbe.Receipt)
		}
		for _, binding := range backend.ArtifactBindings {
			refs = append(refs, binding.Artifact)
		}
		for _, ref := range []*artifactRef{
			backend.SBXExecution.Profile,
			backend.SBXExecution.CapabilityProbe,
			backend.SBXExecution.Request,
			backend.SBXExecution.Receipt,
			backend.SBXExecution.InputManifest,
			backend.SBXExecution.OutputManifest,
			backend.SBXExecution.CleanupReceipt,
			backend.SBXExecution.ClassifierProjection,
		} {
			if ref != nil {
				refs = append(refs, *ref)
			}
		}
		for _, run := range backend.Replay.Runs {
			refs = append(refs, run.Receipt, run.NormalizedOutput)
		}
		for _, canary := range append(append([]canary{}, backend.KnownGoodCanaries...), backend.KnownBadCanaries...) {
			refs = append(refs, canary.Input)
			if canary.Output != nil {
				refs = append(refs, *canary.Output)
			}
			if canary.Counterexample != nil {
				refs = append(refs, canary.Counterexample.Artifact)
			}
		}
		for _, outcome := range backend.Outcomes {
			refs = append(refs, outcome.ArtifactRefs...)
			if outcome.Counterexample != nil {
				refs = append(refs, outcome.Counterexample.Artifact)
			}
		}
	}
	seen := map[string]string{}
	for _, ref := range refs {
		if ref.SHA256 == "" {
			collector.semantic("MISSING_DIGEST", ref.Path, "required artifact reference has no SHA-256 digest")
			continue
		}
		if _, err := canonicalPath(ref.Path); err != nil {
			collector.semantic("NONCANONICAL_PATH", ref.Path, err.Error())
			continue
		}
		if prior, ok := seen[ref.Path]; ok && prior == ref.SHA256 {
			continue
		}
		seen[ref.Path] = ref.SHA256
		data, err := snap.read(ref.Path, maxJSONBytes)
		if err != nil {
			reason := "MISSING_REQUIRED_ARTIFACT"
			if !errors.Is(err, fs.ErrNotExist) {
				reason = "INVALID_ARTIFACT_SNAPSHOT"
			}
			collector.semantic(reason, ref.Path, err.Error())
			continue
		}
		actual := vendorprotocol.DigestBytes(data)
		if actual != ref.SHA256 {
			if snap.historicalCommit != "" {
				historical, historicalErr := provenance.ReadHistoricalArtifact(snap.rootPath, snap.historicalCommit, ref.Path)
				if historicalErr == nil && vendorprotocol.DigestBytes(historical) == ref.SHA256 {
					continue
				}
			}
			collector.digest("DIGEST_SUBSTITUTION", ref.Path, fmt.Sprintf("declared %s, snapshotted %s", ref.SHA256, actual))
		}
	}
}

func verifyArtifactRef(snap *snapshot, ref artifactRef, path string, collector *findingCollector) {
	if _, err := canonicalPath(ref.Path); err != nil {
		collector.semantic("NONCANONICAL_PATH", path, err.Error())
		return
	}
	data, err := snap.read(ref.Path, maxJSONBytes)
	if err != nil {
		collector.semantic("MISSING_REQUIRED_ARTIFACT", path, err.Error())
		return
	}
	if actual := vendorprotocol.DigestBytes(data); actual != ref.SHA256 {
		if snap.historicalCommit != "" {
			historical, historicalErr := provenance.ReadHistoricalArtifact(snap.rootPath, snap.historicalCommit, ref.Path)
			if historicalErr == nil && vendorprotocol.DigestBytes(historical) == ref.SHA256 {
				return
			}
		}
		collector.digest("DIGEST_SUBSTITUTION", path, fmt.Sprintf("declared %s, snapshotted %s", ref.SHA256, actual))
	}
}

func bundleDigest(snap *snapshot) string {
	type entry struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	entries := make([]entry, 0, 4)
	for _, path := range []string{backendQualificationPath, concurrencyPlanPath, connectionModelPath, proofTargetsPath} {
		if data := snap.files[path]; data != nil {
			entries = append(entries, entry{Path: path, SHA256: vendorprotocol.DigestBytes(data)})
		}
	}
	data, err := vendorprotocol.CanonicalJSON(entries)
	if err != nil {
		return ""
	}
	return vendorprotocol.DigestBytes(data)
}

func collectClaimScopes(targetsOK bool, targets *proofTargets, qualificationOK bool, qualification *backendQualification, planOK bool, plan *concurrencyPlan) []string {
	allowed := map[string]bool{
		"BOUNDED_TEST_EVIDENCE": true, "SYSTEMATIC_CONCURRENCY_TESTING": true, "PROVED_MODEL": true,
		"UNAVAILABLE_BACKEND_BLOCKED": true, "FUTURE_PRODUCTION_REFINEMENT": true,
	}
	set := map[string]bool{}
	if targetsOK {
		for _, target := range targets.Targets {
			if allowed[target.MaximumCurrentScope] {
				set[target.MaximumCurrentScope] = true
			}
		}
	}
	if qualificationOK {
		for _, backend := range qualification.Backends {
			if backend.ExecutionState != "UNAVAILABLE_BACKEND_BLOCKED" && backend.evidenceKind != "PUBLIC_EXECUTION_RECEIPT" {
				continue
			}
			if allowed[backend.ClaimScope] {
				set[backend.ClaimScope] = true
			}
		}
	}
	if planOK && allowed[plan.ClaimScope] {
		set[plan.ClaimScope] = true
	}
	return mapKeys(set)
}

func checkSortedArtifactRefs(values []artifactRef, path string, collector *findingCollector) {
	if !sortedBy(values, func(value artifactRef) string { return value.Path }) {
		collector.semantic("NONCANONICAL_SET_ORDER", path, "artifact references must be sorted by canonical path")
	}
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value.Path] {
			collector.semantic("DUPLICATE_IDENTIFIER", path, "artifact path is duplicated")
		}
		seen[value.Path] = true
	}
}

func checkSortedUnique(values []string, path string, collector *findingCollector) {
	if !sort.StringsAreSorted(values) {
		collector.semantic("NONCANONICAL_SET_ORDER", path, "set-valued array must be sorted")
	}
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			collector.semantic("DUPLICATE_IDENTIFIER", path, "set-valued array contains a duplicate")
			return
		}
	}
}

func sortedBy[T any](values []T, key func(T) string) bool {
	for index := 1; index < len(values); index++ {
		if key(values[index-1]) >= key(values[index]) {
			return false
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
	return reflect.DeepEqual(left, right)
}

func sameSet(left, right []string) bool {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	return equalStrings(left, right)
}

func mapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
