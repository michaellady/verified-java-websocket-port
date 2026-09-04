package validators

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

// VerifyIndependent intentionally avoids the reference verifier's indexes,
// recursive traversal, and helper functions. It uses sorted records, pairwise
// membership checks, and Kahn elimination so a graph bug is less likely to be
// shared by both implementations.
func VerifyIndependent(bundle protocol.Bundle, policy protocol.Policy) []protocol.Finding {
	result := make([]protocol.Finding, 0)
	record := func(code string, disposition protocol.Disposition, location, explanation string) {
		result = append(result, protocol.Finding{Code: code, Disposition: disposition, Path: location, Message: explanation})
	}
	if bundle.SchemaVersion != protocol.SchemaVersion {
		record("INVALID_SCHEMA_VERSION", protocol.Block, "$.schema_version", "unsupported assurance protocol schema")
	}
	if bundle.Company != policy.Company || bundle.Project != policy.Project {
		record("CROSS_COMPANY_REFERENCE", protocol.Quarantine, "$.company", "bundle scope differs from policy scope")
	}
	if bundle.Snapshot.ID == "" || !independentDigestValid(bundle.Snapshot.CandidateDigest) {
		record("INVALID_SNAPSHOT_BINDING", protocol.Block, "$.snapshot", "snapshot identity and candidate digest are required")
	}
	transitionAllowed := false
	for _, destination := range policy.AllowedSnapshotTransitions[bundle.Snapshot.PreviousState] {
		transitionAllowed = transitionAllowed || destination == bundle.Snapshot.State
	}
	if !transitionAllowed {
		record("INVALID_TRANSITION", protocol.Block, "$.snapshot.state", "snapshot milestone transition is not allowed")
	}
	if bundle.Snapshot.Stale {
		record("STALE_INPUT", protocol.Invalidate, "$.snapshot.stale", "snapshot candidate is stale")
	}

	orderedNodes := append([]protocol.Node(nil), bundle.Nodes...)
	sort.Slice(orderedNodes, func(i, j int) bool { return orderedNodes[i].ID < orderedNodes[j].ID })
	if len(orderedNodes) == 0 {
		record("MISSING_EVIDENCE", protocol.Block, "$.nodes", "snapshot has no evidence nodes")
	}
	rootPresent := false
	for position, node := range bundle.Nodes {
		location := fmt.Sprintf("$.nodes[%d]", position)
		if node.ID == "" {
			record("MISSING_EVIDENCE", protocol.Block, location+".id", "evidence node identity is empty")
		}
		rootPresent = rootPresent || node.ID == bundle.RootNodeID
		duplicates := 0
		for _, candidate := range bundle.Nodes {
			if candidate.ID == node.ID {
				duplicates++
			}
		}
		if duplicates > 1 && firstNodePosition(bundle.Nodes, node.ID) == position {
			record("DUPLICATE_ID", protocol.Block, location+".id", "evidence node identity is not unique")
		}
		allowedKind := false
		for _, kind := range policy.AllowedNodeKinds {
			allowedKind = allowedKind || kind == node.Kind
		}
		if !allowedKind {
			record("INVALID_NODE_KIND", protocol.Block, location+".kind", "evidence node kind is not allowlisted")
		}
		decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(node.ContentBase64)
		if decodeErr != nil || len(decoded) == 0 {
			record("EMPTY_EVIDENCE", protocol.Block, location+".content_base64", "evidence content must be non-empty canonical base64")
		} else if !independentDigestValid(node.Digest) || protocol.DigestBytes(decoded) != node.Digest {
			record("DIGEST_MISMATCH", protocol.Quarantine, location+".digest", "evidence digest does not bind decoded bytes")
		}
		switch node.Classification {
		case "PUBLIC", "PUBLIC_DERIVED", "INTERNAL", "PROTECTED_HELD_OUT", "QUARANTINED":
		default:
			record("INVALID_CLASSIFICATION", protocol.Quarantine, location+".classification", "evidence classification is not recognized")
		}
		if node.Stale {
			record("STALE_INPUT", protocol.Invalidate, location+".stale", "connected evidence is stale")
		}
		if node.Contradictory {
			record("SEMANTIC_INCONSISTENCY", protocol.Block, location+".contradictory", "connected evidence is contradictory")
		}
		if node.Migrated && !node.MigrationLossless {
			record("LOSSY_MIGRATION", protocol.Block, location+".migration_lossless", "migrated evidence is not lossless")
		}
	}
	if !rootPresent {
		record("MISSING_ROOT", protocol.Block, "$.root_node_id", "root evidence node does not resolve")
	}

	edgesUsable := true
	indegree := make([]int, len(orderedNodes))
	for edgeIndex, edge := range bundle.Edges {
		location := fmt.Sprintf("$.edges[%d]", edgeIndex)
		fromIndex := sortedNodeIndex(orderedNodes, edge.From)
		toIndex := sortedNodeIndex(orderedNodes, edge.To)
		if fromIndex < 0 || toIndex < 0 {
			record("DANGLING_EDGE", protocol.Block, location, "typed evidence edge has an unresolved endpoint")
			edgesUsable = false
			continue
		}
		kindAllowed := false
		for _, kind := range policy.AllowedEdgeKinds {
			kindAllowed = kindAllowed || kind == edge.Kind
		}
		if !kindAllowed {
			record("INVALID_EDGE_KIND", protocol.Block, location+".kind", "evidence edge kind is not allowlisted")
			edgesUsable = false
			continue
		}
		duplicate := false
		for prior := 0; prior < edgeIndex; prior++ {
			candidate := bundle.Edges[prior]
			duplicate = duplicate || (candidate.From == edge.From && candidate.To == edge.To && candidate.Kind == edge.Kind)
		}
		if duplicate {
			record("DUPLICATE_EDGE", protocol.Block, location, "typed evidence edge is duplicated")
			edgesUsable = false
			continue
		}
		// Kahn runs on the declared dependent -> dependency direction.
		indegree[toIndex]++
	}
	if edgesUsable {
		queue := make([]int, 0, len(orderedNodes))
		for index, degree := range indegree {
			if degree == 0 {
				queue = append(queue, index)
			}
		}
		removed := 0
		degrees := append([]int(nil), indegree...)
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			removed++
			for _, edge := range bundle.Edges {
				if edge.From != orderedNodes[current].ID {
					continue
				}
				to := sortedNodeIndex(orderedNodes, edge.To)
				degrees[to]--
				if degrees[to] == 0 {
					queue = append(queue, to)
				}
			}
		}
		if removed != len(orderedNodes) {
			record("CYCLIC_GRAPH", protocol.Block, "$.edges", "snapshot evidence graph must be acyclic")
		} else if rootPresent {
			frontier := []string{bundle.RootNodeID}
			visited := []string{}
			for len(frontier) > 0 {
				current := frontier[len(frontier)-1]
				frontier = frontier[:len(frontier)-1]
				if stringInSlice(visited, current) {
					continue
				}
				visited = append(visited, current)
				for _, edge := range bundle.Edges {
					if edge.From == current && !stringInSlice(visited, edge.To) {
						frontier = append(frontier, edge.To)
					}
				}
			}
			if len(visited) != len(orderedNodes) {
				record("DISCONNECTED_EVIDENCE", protocol.Block, "$.edges", "every evidence node must be reachable from the snapshot root")
			}
		}
	}

	for index, stage := range bundle.Stages {
		location := fmt.Sprintf("$.stages[%d]", index)
		if countStage(bundle.Stages, stage.ID) > 1 && firstStagePosition(bundle.Stages, stage.ID) == index {
			record("DUPLICATE_ID", protocol.Block, location+".id", "stage identity is not unique")
		}
		contractValid := stage.SnapshotID == bundle.Snapshot.ID && stage.IdempotencyKey != "" && stage.LeaseSeconds > 0 && stage.LeaseSeconds <= 300
		contractValid = contractValid && stage.Retry.MaximumAttempts > 0 && stage.Retry.MaximumAttempts <= policy.MaximumAttemptsPerStage
		contractValid = contractValid && stage.Retry.InitialBackoff > 0 && stage.Retry.MaximumBackoff > 0 && stage.Retry.InitialBackoff <= stage.Retry.MaximumBackoff
		contractValid = contractValid && stage.Retry.MaximumBackoff <= time.Duration(policy.MaximumBackoffSeconds)*time.Second
		declaredRoles := append([]string(nil), stage.RequiredRoles...)
		expectedRoles := append([]string(nil), policy.ActionRoles["COMPLETE_ATTEMPT:"+stage.ID]...)
		sort.Strings(declaredRoles)
		sort.Strings(expectedRoles)
		contractValid = contractValid && strings.Join(declaredRoles, "\x00") == strings.Join(expectedRoles, "\x00")
		if !contractValid {
			record("INVALID_STAGE_CONTRACT", protocol.Block, location, "stage must bind the snapshot, idempotency key, short lease, and bounded retry policy")
		}
		resolved := true
		for _, dependency := range append(append([]string{}, stage.Inputs...), stage.Outputs...) {
			resolved = resolved && sortedNodeIndex(orderedNodes, dependency) >= 0
		}
		if !resolved {
			record("DANGLING_EDGE", protocol.Block, location, "stage input or output does not resolve to evidence")
		}
		if stage.State != "SUCCEEDED" {
			record("INCOMPLETE_STAGE", protocol.Block, location+".state", "snapshot contains an incomplete required stage")
		}
	}
	for _, required := range policy.RequiredStages {
		if countStage(bundle.Stages, required) == 0 {
			record("MISSING_STAGE", protocol.Block, "$.stages", "required protocol stage is absent")
		}
	}
	for index, failure := range bundle.Failures {
		location := fmt.Sprintf("$.failures[%d]", index)
		if failure.ID == "" || countFailure(bundle.Failures, failure.ID) > 1 {
			if firstFailurePosition(bundle.Failures, failure.ID) == index {
				record("DUPLICATE_ID", protocol.Block, location+".id", "failure identity is empty or duplicated")
			}
		}
		expectedRetryability := "non-retryable"
		if failure.Disposition == protocol.Retry {
			expectedRetryability = "transient"
		}
		valid := failure.AttemptID != "" && failure.StageID != "" && failure.SnapshotID == bundle.Snapshot.ID && failure.ErrorType != "" && failure.Phase == failure.StageID && failure.Codepath != "" && failure.Severity != "" && failure.Retryability == expectedRetryability
		valid = valid && len(failure.AffectedClaimIDs) > 0 && len(failure.AffectedArtifactIDs) > 0 && failure.ActorID != "" && failure.Role != "" && failure.RunID != "" && failure.SafeMessage != "" && len(failure.CauseChain) > 0 && failure.DiagnosticArtifactID != "" && !failure.OccurredAt.IsZero() && !failure.OccurredAt.After(bundle.VerifiedAt) && failure.QueryBudgetConsumed >= 0
		if !valid {
			record("INVALID_FAILURE_BINDING", protocol.Block, location, "failure envelope is incomplete or not snapshot-bound")
		}
	}

	for index, attempt := range bundle.Attempts {
		location := fmt.Sprintf("$.attempts[%d]", index)
		stageIndex := firstStagePosition(bundle.Stages, attempt.StageID)
		if attempt.ID == "" || countAttempt(bundle.Attempts, attempt.ID) > 1 {
			if firstAttemptPosition(bundle.Attempts, attempt.ID) == index {
				record("DUPLICATE_ID", protocol.Block, location+".id", "attempt identity is empty or duplicated")
			}
		}
		bindingValid := stageIndex >= 0 && attempt.SnapshotID == bundle.Snapshot.ID && attempt.Ordinal > 0 && attempt.ActorID != "" && attempt.Role != "" && attempt.RunID != "" && !attempt.StartedAt.IsZero()
		bindingValid = bindingValid && (stageIndex < 0 || stringInSlice(bundle.Stages[stageIndex].RequiredRoles, attempt.Role))
		bindingValid = bindingValid && !attempt.FinishedAt.Before(attempt.StartedAt) && !attempt.FinishedAt.After(bundle.VerifiedAt) && attempt.QueryBudgetConsumed >= 0
		if !bindingValid {
			record("INVALID_ATTEMPT_BINDING", protocol.Block, location, "attempt chronology or stage and snapshot binding is invalid")
		}
		if stageIndex >= 0 && attempt.Ordinal > bundle.Stages[stageIndex].Retry.MaximumAttempts {
			record("RETRY_BOUND_EXCEEDED", protocol.Block, location+".ordinal", "attempt exceeds the stage retry bound")
		}
		if attempt.Outcome == "SUCCEEDED" {
			if attempt.ErrorType != "" || attempt.FailureID != "" || attempt.Disposition != "" {
				record("INVALID_SUCCESS_ATTEMPT", protocol.Block, location, "successful attempt cannot carry failure metadata")
			}
		} else if attempt.Outcome == "FAILED" {
			expected := independentDisposition(policy, attempt.ErrorType)
			failureFound := false
			for _, failure := range bundle.Failures {
				if failure.ID != attempt.FailureID {
					continue
				}
				failureFound = failure.AttemptID == attempt.ID && failure.StageID == attempt.StageID && failure.SnapshotID == attempt.SnapshotID && failure.ActorID == attempt.ActorID && failure.Role == attempt.Role && failure.RunID == attempt.RunID
				failureFound = failureFound && failure.ErrorType == attempt.ErrorType && failure.Disposition == attempt.Disposition
				failureFound = failureFound && failure.QueryBudgetConsumed == attempt.QueryBudgetConsumed
				leftSecurity := append([]string(nil), failure.SecurityFindingIDs...)
				rightSecurity := append([]string(nil), attempt.SecurityFindingIDs...)
				leftReview := append([]string(nil), failure.ReviewerInterventions...)
				rightReview := append([]string(nil), attempt.ReviewerInterventions...)
				sort.Strings(leftSecurity)
				sort.Strings(rightSecurity)
				sort.Strings(leftReview)
				sort.Strings(rightReview)
				failureFound = failureFound && strings.Join(leftSecurity, "\x00") == strings.Join(rightSecurity, "\x00") && strings.Join(leftReview, "\x00") == strings.Join(rightReview, "\x00")
			}
			if !failureFound || attempt.FailureID == "" || attempt.Disposition != expected {
				record("HIDDEN_FAILED_ATTEMPT", protocol.Block, location, "failed attempt requires a visible typed failure and exact disposition")
			}
		} else {
			record("INVALID_ATTEMPT_OUTCOME", protocol.Block, location+".outcome", "attempt outcome is not recognized")
		}
	}
	for _, stage := range bundle.Stages {
		ordinals := []int{}
		hasSuccess := false
		for _, attempt := range bundle.Attempts {
			if attempt.StageID == stage.ID {
				ordinals = append(ordinals, attempt.Ordinal)
				hasSuccess = hasSuccess || attempt.Outcome == "SUCCEEDED"
			}
		}
		sort.Ints(ordinals)
		for index, ordinal := range ordinals {
			if ordinal != index+1 {
				record("NONCONTIGUOUS_ATTEMPTS", protocol.Block, "$.attempts", "attempt ordinals for stage "+stage.ID+" must be unique and contiguous")
				break
			}
		}
		if stage.State == "SUCCEEDED" && !hasSuccess {
			record("EMPTY_SUCCESS_STAGE", protocol.Block, "$.stages", "succeeded stage requires a retained successful attempt")
		}
	}
	for index, failure := range bundle.Failures {
		bound := false
		for _, attempt := range bundle.Attempts {
			bound = bound || (attempt.ID == failure.AttemptID && attempt.FailureID == failure.ID)
		}
		if !bound {
			record("ORPHAN_FAILURE", protocol.Block, fmt.Sprintf("$.failures[%d]", index), "failure envelope must bind exactly one retained failed attempt")
		}
	}

	auth := bundle.Authorization
	authValid := auth.ActorID != "" && auth.Role != "" && auth.SignatureVerified && auth.SnapshotDigest == bundle.Snapshot.CandidateDigest && auth.PolicyVersion == policy.Version
	authValid = authValid && !auth.IssuedAt.IsZero() && !auth.ExpiresAt.IsZero() && !auth.ExpiresAt.Before(bundle.VerifiedAt) && !auth.IssuedAt.After(bundle.VerifiedAt)
	authValid = authValid && auth.ExpiresAt.Sub(auth.IssuedAt) <= time.Duration(policy.MaximumAuthorizationAgeSeconds)*time.Second
	if !authValid {
		record("AUTHORIZATION_DENIED", protocol.Quarantine, "$.authorization", "authorization signature, scope, lifetime, or snapshot binding is invalid")
	}
	if auth.Revoked {
		record("REVOKED_KEY", protocol.Quarantine, "$.authorization.revoked", "authorization identity or key is revoked")
	}
	nonceUsed := auth.Nonce == ""
	for _, prior := range auth.PriorNonces {
		nonceUsed = nonceUsed || prior == auth.Nonce
	}
	if nonceUsed {
		record("REPLAYED_AUTHORIZATION", protocol.Quarantine, "$.authorization.nonce", "authorization nonce is empty or already consumed")
	}
	allRoles := append(append([]string(nil), auth.SnapshotRoles...), auth.Role)
	roleConflict := false
	for _, left := range allRoles {
		for _, right := range allRoles {
			if left == right {
				continue
			}
			for _, forbidden := range policy.IncompatibleRoles[left] {
				roleConflict = roleConflict || forbidden == right
			}
		}
	}
	if roleConflict {
		record("ROLE_CONFLICT", protocol.Quarantine, "$.authorization.snapshot_roles", "snapshot combines incompatible duties")
	}

	seenAttestationActors := map[string]bool{}
	for index, attestation := range bundle.Attestations {
		valid := attestation.ID != "" && countAttestation(bundle.Attestations, attestation.ID) == 1 && attestation.ActorID != "" && !seenAttestationActors[attestation.ActorID] && attestation.ActorID != bundle.Authorization.ActorID && attestation.Independent && attestation.SnapshotDigest == bundle.Snapshot.CandidateDigest
		if !valid {
			record("INVALID_ATTESTATION", protocol.Block, fmt.Sprintf("$.attestations[%d]", index), "attestation must be unique, independent, and snapshot-bound")
		}
		seenAttestationActors[attestation.ActorID] = true
	}
	for _, role := range policy.RequiredAttestationRoles {
		found := false
		for _, attestation := range bundle.Attestations {
			found = found || attestation.Role == role
		}
		if !found {
			record("MISSING_ATTESTATION", protocol.Block, "$.attestations", "required independent verifier attestation is absent")
		}
	}

	if bundle.Publication.Requested {
		if bundle.Publication.Classification != "PUBLIC" && bundle.Publication.Classification != "PUBLIC_DERIVED" {
			record("INVALID_PUBLICATION_CLASSIFICATION", protocol.Quarantine, "$.publication.classification", "publication classification must be public")
		}
		if bundle.Authorization.Role != "release-attestor" {
			record("PUBLICATION_ROLE_DENIED", protocol.Quarantine, "$.authorization.role", "publication requires the release-attestor role")
		}
		publishable := []string{}
		nonPublic := false
		for _, node := range bundle.Nodes {
			switch node.Classification {
			case "PUBLIC", "PUBLIC_DERIVED":
				publishable = append(publishable, node.Digest)
			default:
				nonPublic = true
			}
		}
		if nonPublic {
			record("PROTECTED_DISCLOSURE", protocol.Quarantine, "$.publication", "publication bundle includes non-public evidence")
		}
		sort.Strings(publishable)
		declared := append([]string(nil), bundle.Publication.ObjectDigests...)
		sort.Strings(declared)
		if !bundle.Publication.Complete || strings.Join(publishable, "\x00") != strings.Join(declared, "\x00") {
			record("PARTIAL_PUBLICATION", protocol.Quarantine, "$.publication", "publication must contain exactly every public object")
		}
		if bundle.Publication.ReplayCommand == "" {
			record("MISSING_REPLAY_COMMAND", protocol.Block, "$.publication.replay_command", "public result requires a copy-paste replay command")
		}
	}
	return protocol.NormalizeFindings(result)
}

func independentDisposition(policy protocol.Policy, errorType string) protocol.Disposition {
	for _, value := range policy.TransientErrorTypes {
		if value == errorType {
			return protocol.Retry
		}
	}
	for _, value := range policy.LSPErrorTypes {
		if value == errorType {
			return protocol.DegradeNonAssurance
		}
	}
	for _, values := range [][]string{policy.SecurityErrorTypes, policy.IntegrityErrorTypes} {
		for _, value := range values {
			if value == errorType {
				return protocol.Quarantine
			}
		}
	}
	return protocol.Block
}

func independentDigestValid(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	for index := 7; index < len(value); index++ {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func sortedNodeIndex(nodes []protocol.Node, id string) int {
	index := sort.Search(len(nodes), func(index int) bool { return nodes[index].ID >= id })
	if index < len(nodes) && nodes[index].ID == id {
		return index
	}
	return -1
}

func firstNodePosition(nodes []protocol.Node, id string) int {
	for index, node := range nodes {
		if node.ID == id {
			return index
		}
	}
	return -1
}

func countStage(stages []protocol.Stage, id string) int {
	count := 0
	for _, stage := range stages {
		if stage.ID == id {
			count++
		}
	}
	return count
}

func firstStagePosition(stages []protocol.Stage, id string) int {
	for index, stage := range stages {
		if stage.ID == id {
			return index
		}
	}
	return -1
}

func countAttempt(attempts []protocol.Attempt, id string) int {
	count := 0
	for _, attempt := range attempts {
		if attempt.ID == id {
			count++
		}
	}
	return count
}

func countFailure(failures []protocol.FailureEnvelope, id string) int {
	count := 0
	for _, failure := range failures {
		if failure.ID == id {
			count++
		}
	}
	return count
}

func firstFailurePosition(failures []protocol.FailureEnvelope, id string) int {
	for index, failure := range failures {
		if failure.ID == id {
			return index
		}
	}
	return -1
}

func firstAttemptPosition(attempts []protocol.Attempt, id string) int {
	for index, attempt := range attempts {
		if attempt.ID == id {
			return index
		}
	}
	return -1
}

func countAttestation(attestations []protocol.Attestation, id string) int {
	count := 0
	for _, attestation := range attestations {
		if attestation.ID == id {
			count++
		}
	}
	return count
}

func stringInSlice(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
