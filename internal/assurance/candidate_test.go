package assurance

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

func TestUS023StrictCandidateJSONRejectsDuplicateUnknownAndTrailing(t *testing.T) {
	valid, err := json.Marshal(buildCandidateClaims())
	if err != nil {
		t.Fatal(err)
	}
	var destination candidateClaims
	if err := decodeCandidateJSON(valid, &destination); err != nil {
		t.Fatalf("valid claims rejected: %v", err)
	}
	variants := [][]byte{
		append(append([]byte(nil), valid...), []byte(` {}`)...),
		[]byte(strings.Replace(string(valid), `"schema_version":"1.0.0"`, `"schema_version":"1.0.0","schema_version":"1.0.0"`, 1)),
		[]byte(strings.Replace(string(valid), `"story_id":"US-023"`, `"story_id":"US-023","unknown":false`, 1)),
	}
	for index, raw := range variants {
		if err := decodeCandidateJSON(raw, &candidateClaims{}); err == nil {
			t.Fatalf("hostile variant %d passed", index)
		}
	}
}

func TestUS023ClosedGateAndFamilyDenominatorsStayBlocked(t *testing.T) {
	claims := buildCandidateClaims()
	if len(claims.Gates) != len(gateContracts) || len(claims.EvidenceFamilies) != len(evidenceFamilies) {
		t.Fatal("closed denominator changed")
	}
	for _, gate := range claims.Gates {
		if !gate.Required || gate.RequiredState != "SATISFIED" || gate.ObservedState != "BLOCKED" || len(gate.BlockerIDs) == 0 {
			t.Fatalf("gate overclaim: %#v", gate)
		}
	}
	for index, family := range claims.EvidenceFamilies {
		if family.Family != evidenceFamilies[index] || family.ObservedState != "BLOCKED" || len(family.BlockerIDs) == 0 {
			t.Fatalf("family drift: %#v", family)
		}
	}
}

func TestUS023AttemptReconciliationDerivesDeletedAndSilentInputs(t *testing.T) {
	target := candidateTarget{Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), ObjectFormat: "sha1"}
	paths := []string{"rust/Cargo.lock", "rust/connection-core/src/lib.rs", "rust/connection-core/tests/scaffold_smoke.rs"}
	want := buildCandidateAttempts(target, paths)
	withoutTest := buildCandidateAttempts(target, paths[:2])
	if reflect.DeepEqual(want.TestReconciliation, withoutTest.TestReconciliation) {
		t.Fatal("deleted test did not change anchor-derived reconciliation")
	}
	if want.TestReconciliation.State != "BLOCKED" || want.Counts.ExecutedPass != 0 {
		t.Fatal("silent/non-executed tests were represented as pass")
	}
}

func TestUS023ProtectedMembershipNeverFollowsManifestEdges(t *testing.T) {
	target := []string{
		"corpora/hidden/manifest.json",
		"corpora/hidden/private/scenarios.jsonl",
		"corpora/sealed/manifest.json",
		"corpora/sealed/private/scenarios.jsonl",
	}
	paths := expectedCandidatePaths(target, nil)
	want := []string{"corpora/hidden/manifest.json", "corpora/sealed/manifest.json"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("protected edge admitted: got %v", paths)
	}
}

func TestUS023DecodedSecretValueAndReleaseOverclaimFailClosed(t *testing.T) {
	if err := rejectCandidateSecrets(map[string]any{"detail_code": "sk-hostile"}, ""); err == nil {
		t.Fatal("decoded secret value passed")
	}
	manifest := candidateManifest{
		Schema: "../schemas/us023-candidate-manifest-1.0.0.schema.json", SchemaVersion: "1.0.0",
		StoryID: candidateStory, CandidateID: candidateID, SnapshotState: "FROZEN", ParityState: "BLOCKED",
		Assurance: candidateAssurance, Production: true, RootNodeID: rootNodeID,
		Replay: candidateReplayPaths{MachineReport: parityReplayPath, FormalProjection: formalProjectionPath, FormalReport: formalReportPath, HumanReport: parityReportPath},
	}
	if err := validateManifestClaims(manifest); err == nil || codeOf(err) != "ASSURANCE_OR_RELEASE_OVERCLAIM" {
		t.Fatalf("production overclaim not rejected: %v", err)
	}
}

func TestUS023HumanReceiptRejectsAIAndReviewCycleExpansion(t *testing.T) {
	manifest := candidateManifest{CandidateRoot: "sha256:" + strings.Repeat("a", 64), Target: candidateTarget{Commit: strings.Repeat("b", 40), Tree: strings.Repeat("c", 40)}}
	receipt := buildPlaceholderReceipt("HUMAN_REVIEWER", manifest)
	provider, model, effort, invocation := "openai", "gpt-5.6-sol", "xhigh", "/root/fake"
	receipt.Status, receipt.ReviewKind, receipt.CommentsOnly = "EXECUTED", "FULL", true
	receipt.Provider, receipt.Model, receipt.ReasoningEffort, receipt.InvocationID = &provider, &model, &effort, &invocation
	receipt.ReviewerIdentity = "Codex AI"
	if err := validateReviewReceipt(reviewPaths[1], receipt, manifest); err == nil || codeOf(err) != "AI_AS_HUMAN" {
		t.Fatalf("AI-as-human passed: %v", err)
	}
	closure := buildPlaceholderReceipt("CODEX_REVIEWER", manifest)
	closure.Status, closure.ReviewKind, closure.CommentsOnly = "EXECUTED", "TARGETED_CLOSURE", true
	closure.Provider, closure.Model, closure.ReasoningEffort, closure.InvocationID = &provider, &model, &effort, &invocation
	closure.RemediationTarget = &remediationTarget{PredecessorCandidateRoot: manifest.CandidateRoot, SuccessorCandidateRoot: manifest.CandidateRoot, FindingIDs: []string{"F-1"}}
	closure.Findings = []reviewFinding{{FindingID: "F-2", Severity: "NIT", Code: "NEW_SCOPE", Path: "new"}}
	if err := validateReviewLineage([]reviewReceipt{closure}); err == nil || codeOf(err) != "TARGETED_CLOSURE_SCOPE_EXPANDED" {
		t.Fatalf("targeted closure expanded scope: %v", err)
	}
}

func TestUS023SchemasAreClosedAtEveryDeclaredObject(t *testing.T) {
	for path, raw := range CandidateSchemaDocuments() {
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if schema["type"] != "object" || schema["additionalProperties"] != false || !allSchemaObjectsClosed(schema) {
			t.Fatalf("%s is not a closed root schema", path)
		}
	}
}

func allSchemaObjectsClosed(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		if typed["type"] == "object" && typed["additionalProperties"] != false {
			return false
		}
		for _, child := range typed {
			if !allSchemaObjectsClosed(child) {
				return false
			}
		}
	case []any:
		for _, child := range typed {
			if !allSchemaObjectsClosed(child) {
				return false
			}
		}
	}
	return true
}

func TestUS023AggregateAndCandidateRootsBindEveryNodeAndEdge(t *testing.T) {
	target := candidateTarget{Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), ObjectFormat: "sha1"}
	nodes := []candidateGraphNode{{ID: "file.a", SHA256: "sha256:" + strings.Repeat("c", 64), Git: candidateGit{Blob: strings.Repeat("d", 40)}}, {ID: rootNodeID, Kind: "ROOT_INPUT"}}
	graph := candidateGraph{Nodes: nodes, Edges: []candidateGraphEdge{{From: rootNodeID, To: "file.a", Relation: "CONTAINS"}}}
	before := calculateCandidateRoot(target, graph)
	graph.Edges[0].Relation = "SUPPORTS"
	after := calculateCandidateRoot(target, graph)
	if before == after || aggregateDigest(nodes) == digestCandidate(nil) {
		t.Fatal("root derivation omitted graph content")
	}
}

func TestUS023HistoricalOwnerAttestationsRemainTypedAndNonIndependent(t *testing.T) {
	verdict := Verdict{State: "BLOCKED", Assurance: candidateAssurance, Findings: []vendorprotocol.Finding{
		{Code: "INVALID_ATTESTATION", Path: "$.attestations[0]"},
		{Code: "INVALID_ATTESTATION", Path: "$.attestations[1]"},
	}}
	if !acceptedHistoricalLifecycle(verdict) {
		t.Fatal("exact incumbent owner-relaxed lifecycle was rejected")
	}
	verdict.IndependentReviewClaimed = true
	if acceptedHistoricalLifecycle(verdict) {
		t.Fatal("independence overclaim passed")
	}
}

func TestUS023FormalHostileStatesHaveTypedFailures(t *testing.T) {
	base := formalCatalog{
		Obligations:  []formalObligation{{ObligationID: "o", SurfaceIDs: []string{"s"}, AllowedMethods: []string{"KANI"}, RequiredEvidenceKinds: []string{"PRODUCTION_LINKAGE"}, RequiredMutationIDs: []string{"m"}}},
		JavaBindings: []languageBinding{{ObligationID: "o"}},
		RustBindings: []languageBinding{{ObligationID: "o", ProductionSymbol: "crate::production", SourcePath: "rust/src/lib.rs", ReachableFromEntry: true, ConnectionState: "CONNECTED"}},
		Evidence:     []formalEvidence{{ObligationID: "o", ExecutionState: "NOT_EXECUTED", ObservedStrength: "NONE", Assumptions: formalAssumptions{Role: "UNRESOLVED", Allocator: "UNRESOLVED"}, Refinement: formalRefinement{State: "DISCONNECTED"}, MutationSensitivity: []mutationSensitivity{{MutantID: "m", Disposition: "RETAINED_KILLED_DIFFERENT_SUBJECT"}}}},
		Coverage:     []formalCoverageRow{{ObligationID: "o", AggregateStatus: "BLOCKED"}},
	}
	variants := []struct {
		code   string
		mutate func(*formalCatalog)
	}{
		{code: "SHIPPED_RUST_DISCONNECTED", mutate: func(value *formalCatalog) { value.RustBindings[0].ConnectionState = "DISCONNECTED" }},
		{code: "FORMAL_BOUND_OR_ASSUMPTION_INCOMPATIBLE", mutate: func(value *formalCatalog) { steps := uint64(1); value.Evidence[0].Bounds.MaxSteps = &steps }},
		{code: "FORMAL_STRENGTH_OVERSTATED", mutate: func(value *formalCatalog) { value.Evidence[0].ObservedStrength = "PRODUCTION_REFINEMENT" }},
		{code: "MUTATION_SURVIVOR", mutate: func(value *formalCatalog) { value.Evidence[0].MutationSensitivity[0].Disposition = "SURVIVED" }},
	}
	for _, variant := range variants {
		value := base
		value.RustBindings = append([]languageBinding(nil), base.RustBindings...)
		value.Evidence = append([]formalEvidence(nil), base.Evidence...)
		value.Evidence[0].MutationSensitivity = append([]mutationSensitivity(nil), base.Evidence[0].MutationSensitivity...)
		variant.mutate(&value)
		if err := validateFormalSemantics(value); err == nil || codeOf(err) != variant.code {
			t.Fatalf("%s: %v", variant.code, err)
		}
	}
}
