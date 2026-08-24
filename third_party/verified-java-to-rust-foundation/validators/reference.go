// Package validators contains two deliberately separate snapshot verifier
// implementations. They share protocol data types, but not acceptance logic.
package validators

import (
	"encoding/base64"
	"fmt"
	"sort"
	"time"

	"github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

// VerifyReference indexes the bundle and uses recursive depth-first graph
// validation. It is the primary verifier.
func VerifyReference(bundle protocol.Bundle, policy protocol.Policy) []protocol.Finding {
	findings := make([]protocol.Finding, 0)
	add := func(code string, disposition protocol.Disposition, path, message string) {
		findings = append(findings, protocol.Finding{Code: code, Disposition: disposition, Path: path, Message: message})
	}
	if bundle.SchemaVersion != protocol.SchemaVersion {
		add("INVALID_SCHEMA_VERSION", protocol.Block, "$.schema_version", "unsupported assurance protocol schema")
	}
	if bundle.Company != policy.Company || bundle.Project != policy.Project {
		add("CROSS_COMPANY_REFERENCE", protocol.Quarantine, "$.company", "bundle scope differs from policy scope")
	}
	if bundle.Snapshot.ID == "" || !digestValid(bundle.Snapshot.CandidateDigest) {
		add("INVALID_SNAPSHOT_BINDING", protocol.Block, "$.snapshot", "snapshot identity and candidate digest are required")
	}
	if !protocol.Contains(policy.AllowedSnapshotTransitions[bundle.Snapshot.PreviousState], bundle.Snapshot.State) {
		add("INVALID_TRANSITION", protocol.Block, "$.snapshot.state", "snapshot milestone transition is not allowed")
	}
	if bundle.Snapshot.Stale {
		add("STALE_INPUT", protocol.Invalidate, "$.snapshot.stale", "snapshot candidate is stale")
	}

	nodes := make(map[string]protocol.Node, len(bundle.Nodes))
	if len(bundle.Nodes) == 0 {
		add("MISSING_EVIDENCE", protocol.Block, "$.nodes", "snapshot has no evidence nodes")
	}
	for index, node := range bundle.Nodes {
		itemPath := fmt.Sprintf("$.nodes[%d]", index)
		if node.ID == "" {
			add("MISSING_EVIDENCE", protocol.Block, itemPath+".id", "evidence node identity is empty")
		}
		if _, exists := nodes[node.ID]; exists {
			add("DUPLICATE_ID", protocol.Block, itemPath+".id", "evidence node identity is not unique")
		}
		nodes[node.ID] = node
		if !protocol.Contains(policy.AllowedNodeKinds, node.Kind) {
			add("INVALID_NODE_KIND", protocol.Block, itemPath+".kind", "evidence node kind is not allowlisted")
		}
		content, err := base64.StdEncoding.Strict().DecodeString(node.ContentBase64)
		if err != nil || len(content) == 0 {
			add("EMPTY_EVIDENCE", protocol.Block, itemPath+".content_base64", "evidence content must be non-empty canonical base64")
		} else if !digestValid(node.Digest) || protocol.DigestBytes(content) != node.Digest {
			add("DIGEST_MISMATCH", protocol.Quarantine, itemPath+".digest", "evidence digest does not bind decoded bytes")
		}
		if node.Classification != "PUBLIC" && node.Classification != "PUBLIC_DERIVED" && node.Classification != "INTERNAL" && node.Classification != "PROTECTED_HELD_OUT" && node.Classification != "QUARANTINED" {
			add("INVALID_CLASSIFICATION", protocol.Quarantine, itemPath+".classification", "evidence classification is not recognized")
		}
		if node.Stale {
			add("STALE_INPUT", protocol.Invalidate, itemPath+".stale", "connected evidence is stale")
		}
		if node.Contradictory {
			add("SEMANTIC_INCONSISTENCY", protocol.Block, itemPath+".contradictory", "connected evidence is contradictory")
		}
		if node.Migrated && !node.MigrationLossless {
			add("LOSSY_MIGRATION", protocol.Block, itemPath+".migration_lossless", "migrated evidence is not lossless")
		}
	}
	if _, exists := nodes[bundle.RootNodeID]; !exists {
		add("MISSING_ROOT", protocol.Block, "$.root_node_id", "root evidence node does not resolve")
	}

	adjacency := make(map[string][]string, len(nodes))
	graphUsable := true
	seenEdges := make(map[string]bool, len(bundle.Edges))
	for index, edge := range bundle.Edges {
		itemPath := fmt.Sprintf("$.edges[%d]", index)
		_, fromExists := nodes[edge.From]
		_, toExists := nodes[edge.To]
		if !fromExists || !toExists {
			add("DANGLING_EDGE", protocol.Block, itemPath, "typed evidence edge has an unresolved endpoint")
			graphUsable = false
			continue
		}
		if !protocol.Contains(policy.AllowedEdgeKinds, edge.Kind) {
			add("INVALID_EDGE_KIND", protocol.Block, itemPath+".kind", "evidence edge kind is not allowlisted")
			graphUsable = false
			continue
		}
		identity := edge.From + "\x00" + edge.To + "\x00" + edge.Kind
		if seenEdges[identity] {
			add("DUPLICATE_EDGE", protocol.Block, itemPath, "typed evidence edge is duplicated")
			graphUsable = false
			continue
		}
		seenEdges[identity] = true
		adjacency[edge.From] = append(adjacency[edge.From], edge.To)
	}
	if graphUsable {
		color := make(map[string]uint8, len(nodes))
		reachable := make(map[string]bool, len(nodes))
		cycle := false
		var visit func(string)
		visit = func(id string) {
			if color[id] == 1 {
				cycle = true
				return
			}
			if color[id] == 2 {
				return
			}
			color[id] = 1
			reachable[id] = true
			for _, dependency := range adjacency[id] {
				visit(dependency)
			}
			color[id] = 2
		}
		if _, exists := nodes[bundle.RootNodeID]; exists {
			visit(bundle.RootNodeID)
		}
		if cycle {
			add("CYCLIC_GRAPH", protocol.Block, "$.edges", "snapshot evidence graph must be acyclic")
		} else if len(reachable) != len(nodes) {
			add("DISCONNECTED_EVIDENCE", protocol.Block, "$.edges", "every evidence node must be reachable from the snapshot root")
		}
	}

	stageByID := make(map[string]protocol.Stage, len(bundle.Stages))
	for index, stage := range bundle.Stages {
		itemPath := fmt.Sprintf("$.stages[%d]", index)
		if _, exists := stageByID[stage.ID]; exists {
			add("DUPLICATE_ID", protocol.Block, itemPath+".id", "stage identity is not unique")
		}
		stageByID[stage.ID] = stage
		if stage.SnapshotID != bundle.Snapshot.ID || stage.IdempotencyKey == "" || stage.LeaseSeconds <= 0 || stage.LeaseSeconds > 300 || stage.Retry.MaximumAttempts <= 0 || stage.Retry.MaximumAttempts > policy.MaximumAttemptsPerStage || stage.Retry.InitialBackoff <= 0 || stage.Retry.MaximumBackoff <= 0 || stage.Retry.InitialBackoff > stage.Retry.MaximumBackoff || stage.Retry.MaximumBackoff > time.Duration(policy.MaximumBackoffSeconds)*time.Second || !protocol.SameStrings(stage.RequiredRoles, policy.ActionRoles["COMPLETE_ATTEMPT:"+stage.ID]) {
			add("INVALID_STAGE_CONTRACT", protocol.Block, itemPath, "stage must bind the snapshot, idempotency key, short lease, and bounded retry policy")
		}
		for _, nodeID := range append(append([]string{}, stage.Inputs...), stage.Outputs...) {
			if _, exists := nodes[nodeID]; !exists {
				add("DANGLING_EDGE", protocol.Block, itemPath, "stage input or output does not resolve to evidence")
				break
			}
		}
		if stage.State != "SUCCEEDED" {
			add("INCOMPLETE_STAGE", protocol.Block, itemPath+".state", "snapshot contains an incomplete required stage")
		}
	}
	for _, required := range policy.RequiredStages {
		if _, exists := stageByID[required]; !exists {
			add("MISSING_STAGE", protocol.Block, "$.stages", "required protocol stage is absent")
		}
	}

	failuresByID := make(map[string]protocol.FailureEnvelope, len(bundle.Failures))
	for index, failure := range bundle.Failures {
		itemPath := fmt.Sprintf("$.failures[%d]", index)
		if failure.ID == "" || failuresByID[failure.ID].ID != "" {
			add("DUPLICATE_ID", protocol.Block, itemPath+".id", "failure identity is empty or duplicated")
		}
		failuresByID[failure.ID] = failure
		expectedRetryability := "non-retryable"
		if failure.Disposition == protocol.Retry {
			expectedRetryability = "transient"
		}
		if failure.AttemptID == "" || failure.StageID == "" || failure.SnapshotID != bundle.Snapshot.ID || failure.ErrorType == "" || failure.Phase != failure.StageID || failure.Codepath == "" || failure.Severity == "" || failure.Retryability != expectedRetryability || len(failure.AffectedClaimIDs) == 0 || len(failure.AffectedArtifactIDs) == 0 || failure.ActorID == "" || failure.Role == "" || failure.RunID == "" || failure.SafeMessage == "" || len(failure.CauseChain) == 0 || failure.DiagnosticArtifactID == "" || failure.OccurredAt.IsZero() || failure.OccurredAt.After(bundle.VerifiedAt) || failure.QueryBudgetConsumed < 0 {
			add("INVALID_FAILURE_BINDING", protocol.Block, itemPath, "failure envelope is incomplete or not snapshot-bound")
		}
	}
	attemptIDs := make(map[string]bool, len(bundle.Attempts))
	ordinalsByStage := make(map[string][]int, len(bundle.Stages))
	successByStage := make(map[string]bool, len(bundle.Stages))
	for index, attempt := range bundle.Attempts {
		itemPath := fmt.Sprintf("$.attempts[%d]", index)
		stage, stageExists := stageByID[attempt.StageID]
		if attempt.ID == "" || attemptIDs[attempt.ID] {
			add("DUPLICATE_ID", protocol.Block, itemPath+".id", "attempt identity is empty or duplicated")
		}
		attemptIDs[attempt.ID] = true
		ordinalsByStage[attempt.StageID] = append(ordinalsByStage[attempt.StageID], attempt.Ordinal)
		if !stageExists || attempt.SnapshotID != bundle.Snapshot.ID || attempt.Ordinal <= 0 || attempt.ActorID == "" || attempt.Role == "" || attempt.RunID == "" || (stageExists && !protocol.Contains(stage.RequiredRoles, attempt.Role)) || attempt.StartedAt.IsZero() || attempt.FinishedAt.Before(attempt.StartedAt) || attempt.FinishedAt.After(bundle.VerifiedAt) || attempt.QueryBudgetConsumed < 0 {
			add("INVALID_ATTEMPT_BINDING", protocol.Block, itemPath, "attempt chronology or stage and snapshot binding is invalid")
		}
		if stageExists && attempt.Ordinal > stage.Retry.MaximumAttempts {
			add("RETRY_BOUND_EXCEEDED", protocol.Block, itemPath+".ordinal", "attempt exceeds the stage retry bound")
		}
		switch attempt.Outcome {
		case "SUCCEEDED":
			successByStage[attempt.StageID] = true
			if attempt.ErrorType != "" || attempt.FailureID != "" || attempt.Disposition != "" {
				add("INVALID_SUCCESS_ATTEMPT", protocol.Block, itemPath, "successful attempt cannot carry failure metadata")
			}
		case "FAILED":
			failure, visible := failuresByID[attempt.FailureID]
			expected := protocol.DispositionFor(policy, attempt.ErrorType)
			if !visible || attempt.FailureID == "" || attempt.Disposition != expected || failure.AttemptID != attempt.ID || failure.StageID != attempt.StageID || failure.SnapshotID != attempt.SnapshotID || failure.ErrorType != attempt.ErrorType || failure.Disposition != attempt.Disposition || failure.ActorID != attempt.ActorID || failure.Role != attempt.Role || failure.RunID != attempt.RunID || failure.QueryBudgetConsumed != attempt.QueryBudgetConsumed || !protocol.SameStrings(failure.SecurityFindingIDs, attempt.SecurityFindingIDs) || !protocol.SameStrings(failure.ReviewerInterventions, attempt.ReviewerInterventions) {
				add("HIDDEN_FAILED_ATTEMPT", protocol.Block, itemPath, "failed attempt requires a visible typed failure and exact disposition")
			}
		default:
			add("INVALID_ATTEMPT_OUTCOME", protocol.Block, itemPath+".outcome", "attempt outcome is not recognized")
		}
	}
	for stageID, ordinals := range ordinalsByStage {
		sort.Ints(ordinals)
		for index, ordinal := range ordinals {
			if ordinal != index+1 {
				add("NONCONTIGUOUS_ATTEMPTS", protocol.Block, "$.attempts", "attempt ordinals for stage "+stageID+" must be unique and contiguous")
				break
			}
		}
	}
	for _, stage := range bundle.Stages {
		if stage.State == "SUCCEEDED" && !successByStage[stage.ID] {
			add("EMPTY_SUCCESS_STAGE", protocol.Block, "$.stages", "succeeded stage requires a retained successful attempt")
		}
	}
	for index, failure := range bundle.Failures {
		attemptFound := false
		for _, attempt := range bundle.Attempts {
			attemptFound = attemptFound || (attempt.ID == failure.AttemptID && attempt.FailureID == failure.ID)
		}
		if !attemptFound {
			add("ORPHAN_FAILURE", protocol.Block, fmt.Sprintf("$.failures[%d]", index), "failure envelope must bind exactly one retained failed attempt")
		}
	}

	verifyReferenceAuthorization(&findings, bundle, policy)
	verifyReferenceAttestations(&findings, bundle, policy)
	verifyReferencePublication(&findings, bundle, nodes)
	return protocol.NormalizeFindings(findings)
}

func verifyReferenceAuthorization(findings *[]protocol.Finding, bundle protocol.Bundle, policy protocol.Policy) {
	add := func(code string, disposition protocol.Disposition, path, message string) {
		*findings = append(*findings, protocol.Finding{Code: code, Disposition: disposition, Path: path, Message: message})
	}
	auth := bundle.Authorization
	if auth.ActorID == "" || auth.Role == "" || !auth.SignatureVerified || auth.SnapshotDigest != bundle.Snapshot.CandidateDigest || auth.PolicyVersion != policy.Version || auth.IssuedAt.IsZero() || auth.ExpiresAt.IsZero() || auth.ExpiresAt.Before(bundle.VerifiedAt) || auth.IssuedAt.After(bundle.VerifiedAt) || auth.ExpiresAt.Sub(auth.IssuedAt) > time.Duration(policy.MaximumAuthorizationAgeSeconds)*time.Second {
		add("AUTHORIZATION_DENIED", protocol.Quarantine, "$.authorization", "authorization signature, scope, lifetime, or snapshot binding is invalid")
	}
	if auth.Revoked {
		add("REVOKED_KEY", protocol.Quarantine, "$.authorization.revoked", "authorization identity or key is revoked")
	}
	if auth.Nonce == "" || protocol.Contains(auth.PriorNonces, auth.Nonce) {
		add("REPLAYED_AUTHORIZATION", protocol.Quarantine, "$.authorization.nonce", "authorization nonce is empty or already consumed")
	}
	roles := append([]string(nil), auth.SnapshotRoles...)
	roles = append(roles, auth.Role)
	for _, role := range roles {
		for _, incompatible := range policy.IncompatibleRoles[role] {
			if protocol.Contains(roles, incompatible) {
				add("ROLE_CONFLICT", protocol.Quarantine, "$.authorization.snapshot_roles", "snapshot combines incompatible duties")
				return
			}
		}
	}
}

func verifyReferenceAttestations(findings *[]protocol.Finding, bundle protocol.Bundle, policy protocol.Policy) {
	roles := make(map[string]bool, len(bundle.Attestations))
	ids := make(map[string]bool, len(bundle.Attestations))
	actors := make(map[string]bool, len(bundle.Attestations))
	for index, attestation := range bundle.Attestations {
		if attestation.ID == "" || ids[attestation.ID] || attestation.ActorID == "" || actors[attestation.ActorID] || attestation.ActorID == bundle.Authorization.ActorID || !attestation.Independent || attestation.SnapshotDigest != bundle.Snapshot.CandidateDigest {
			*findings = append(*findings, protocol.Finding{Code: "INVALID_ATTESTATION", Disposition: protocol.Block, Path: fmt.Sprintf("$.attestations[%d]", index), Message: "attestation must be unique, independent, and snapshot-bound"})
		}
		ids[attestation.ID] = true
		actors[attestation.ActorID] = true
		roles[attestation.Role] = true
	}
	for _, required := range policy.RequiredAttestationRoles {
		if !roles[required] {
			*findings = append(*findings, protocol.Finding{Code: "MISSING_ATTESTATION", Disposition: protocol.Block, Path: "$.attestations", Message: "required independent verifier attestation is absent"})
		}
	}
}

func verifyReferencePublication(findings *[]protocol.Finding, bundle protocol.Bundle, nodes map[string]protocol.Node) {
	if !bundle.Publication.Requested {
		return
	}
	if bundle.Publication.Classification != "PUBLIC" && bundle.Publication.Classification != "PUBLIC_DERIVED" {
		*findings = append(*findings, protocol.Finding{Code: "INVALID_PUBLICATION_CLASSIFICATION", Disposition: protocol.Quarantine, Path: "$.publication.classification", Message: "publication classification must be public"})
	}
	if bundle.Authorization.Role != "release-attestor" {
		*findings = append(*findings, protocol.Finding{Code: "PUBLICATION_ROLE_DENIED", Disposition: protocol.Quarantine, Path: "$.authorization.role", Message: "publication requires the release-attestor role"})
	}
	publicDigests := make([]string, 0)
	protected := false
	for _, node := range nodes {
		if node.Classification == "PROTECTED_HELD_OUT" || node.Classification == "INTERNAL" || node.Classification == "QUARANTINED" {
			protected = true
			continue
		}
		publicDigests = append(publicDigests, node.Digest)
	}
	if protected {
		*findings = append(*findings, protocol.Finding{Code: "PROTECTED_DISCLOSURE", Disposition: protocol.Quarantine, Path: "$.publication", Message: "publication bundle includes non-public evidence"})
	}
	if !bundle.Publication.Complete || !protocol.SameStrings(publicDigests, bundle.Publication.ObjectDigests) {
		*findings = append(*findings, protocol.Finding{Code: "PARTIAL_PUBLICATION", Disposition: protocol.Quarantine, Path: "$.publication", Message: "publication must contain exactly every public object"})
	}
	if bundle.Publication.ReplayCommand == "" {
		*findings = append(*findings, protocol.Finding{Code: "MISSING_REPLAY_COMMAND", Disposition: protocol.Block, Path: "$.publication.replay_command", Message: "public result requires a copy-paste replay command"})
	}
}

func digestValid(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, character := range value[7:] {
		if !protocol.Contains([]string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"}, string(character)) {
			return false
		}
	}
	return true
}
