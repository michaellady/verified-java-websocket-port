package assurance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
	"github.com/michaellady/verified-java-websocket-port/internal/campaign"
	"github.com/michaellady/verified-java-websocket-port/internal/formal"
	"github.com/michaellady/verified-java-websocket-port/internal/mutation"
)

// EvaluateCandidate verifies or replays the closed US-023 projection. Both
// modes are read-only and resolve only objects already present in the caller's
// checkout.
func EvaluateCandidate(ctx context.Context, request CandidateRequest) (CandidateVerdict, error) {
	if err := ctx.Err(); err != nil {
		return CandidateVerdict{}, err
	}
	if request.Mode != CandidateVerify && request.Mode != CandidateReplay {
		return CandidateVerdict{}, fmt.Errorf("candidate mode must be VERIFY or REPLAY")
	}
	rootPath, err := candidateRootAbsolute(request.RootPath)
	if err != nil {
		return CandidateVerdict{}, err
	}
	rootInfo, err := os.Lstat(rootPath)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&fs.ModeSymlink != 0 {
		return CandidateVerdict{}, fmt.Errorf("repository root must be a real directory")
	}
	root, err := openProjectRoot(rootPath)
	if err != nil {
		return CandidateVerdict{}, err
	}
	defer root.Close()

	invalid := func(code, path string) (CandidateVerdict, error) {
		return CandidateVerdict{
			SnapshotState:            "INVALID",
			ParityState:              "BLOCKED",
			Assurance:                candidateAssurance,
			IndependentReviewClaimed: false,
			Blockers:                 []Blocker{},
			Findings:                 []Finding{{Code: code, Path: path}},
		}, nil
	}

	manifestRaw, err := readRegularFile(root, candidateManifestPath, 16<<20)
	if err != nil {
		return invalid("CANDIDATE_MANIFEST_READ_FAILED", candidateManifestPath)
	}
	var manifest candidateManifest
	if err := decodeCandidateJSON(manifestRaw, &manifest); err != nil {
		return invalid("CANDIDATE_MANIFEST_INVALID", candidateManifestPath)
	}
	if err := validateManifestClaims(manifest); err != nil {
		return invalid(codeOf(err), candidateManifestPath)
	}
	if manifest.Target.Commit != canonicalTargetCommit || manifest.Target.Tree != canonicalTargetTree {
		return invalid("TARGET_SUBJECT_DRIFT", candidateManifestPath)
	}
	if err := verifyWorkingGitBytes(rootPath, candidateManifestPath, manifestRaw, "HEAD"); err != nil {
		return invalid("ROOT_ENVELOPE_GIT_DRIFT", candidateManifestPath)
	}
	if err := verifyTarget(rootPath, manifest.Target); err != nil {
		return invalid("TARGET_GIT_DRIFT", candidateManifestPath)
	}
	if err := verifyCandidateGraph(root, rootPath, manifest); err != nil {
		return invalid(codeOf(err), candidateManifestPath)
	}

	claimsRaw, err := readRegularFile(root, candidateClaimsPath, 8<<20)
	if err != nil {
		return invalid("CLAIMS_READ_FAILED", candidateClaimsPath)
	}
	var claims candidateClaims
	if err := decodeCandidateJSON(claimsRaw, &claims); err != nil {
		return invalid("CLAIMS_INVALID", candidateClaimsPath)
	}
	wantClaims := buildCandidateClaims()
	if !reflect.DeepEqual(claims, wantClaims) {
		return invalid("CLAIM_DERIVATION_DRIFT", candidateClaimsPath)
	}

	targetPaths, err := gitLines(rootPath, "ls-tree", "-r", "--name-only", manifest.Target.Commit)
	if err != nil {
		return invalid("TARGET_MEMBERSHIP_UNAVAILABLE", candidateAttemptsPath)
	}
	attemptsRaw, err := readRegularFile(root, candidateAttemptsPath, 16<<20)
	if err != nil {
		return invalid("ATTEMPTS_READ_FAILED", candidateAttemptsPath)
	}
	var attempts candidateAttempts
	if err := decodeCandidateJSON(attemptsRaw, &attempts); err != nil {
		return invalid("ATTEMPTS_INVALID", candidateAttemptsPath)
	}
	wantAttempts := buildCandidateAttempts(manifest.Target, targetPaths)
	if !reflect.DeepEqual(attempts, wantAttempts) {
		return invalid("ATTEMPT_OR_RECONCILIATION_DRIFT", candidateAttemptsPath)
	}

	catalogRaw, err := readRegularFile(root, formalCatalogPath, 16<<20)
	if err != nil {
		return invalid("FORMAL_CATALOG_READ_FAILED", formalCatalogPath)
	}
	var catalog formalCatalog
	if err := decodeCandidateJSON(catalogRaw, &catalog); err != nil {
		return invalid("FORMAL_CATALOG_INVALID", formalCatalogPath)
	}
	if err := validateFormalSemantics(catalog); err != nil {
		return invalid(codeOf(err), formalCatalogPath)
	}
	if err := validateRustBindingAnchors(rootPath, manifest.Target, catalog); err != nil {
		return invalid(codeOf(err), formalCatalogPath)
	}
	wantCatalog, err := buildFormalCatalog(rootPath, manifest.Target)
	if err != nil {
		return invalid("FORMAL_DENOMINATOR_UNAVAILABLE", formalCatalogPath)
	}
	if !reflect.DeepEqual(catalog, wantCatalog) {
		return invalid("FORMAL_COVERAGE_DERIVATION_DRIFT", formalCatalogPath)
	}

	for _, schemaPath := range candidateSchemaPaths {
		raw, readErr := readRegularFile(root, schemaPath, 4<<20)
		if readErr != nil {
			return invalid("SCHEMA_READ_FAILED", schemaPath)
		}
		want, ok := CandidateSchemaDocuments()[schemaPath]
		if !ok || !bytes.Equal(raw, want) {
			return invalid("SCHEMA_DRIFT", schemaPath)
		}
	}

	receipts := make([]reviewReceipt, 0, len(reviewPaths))
	receiptRaw := make(map[string][]byte, len(reviewPaths))
	for _, reviewPath := range reviewPaths {
		raw, readErr := readRegularFile(root, reviewPath, 4<<20)
		if readErr != nil {
			return invalid("REVIEW_RECEIPT_READ_FAILED", reviewPath)
		}
		var receipt reviewReceipt
		if decodeErr := decodeCandidateJSON(raw, &receipt); decodeErr != nil {
			return invalid("REVIEW_RECEIPT_INVALID", reviewPath)
		}
		if validationErr := validateReviewReceipt(reviewPath, receipt, manifest); validationErr != nil {
			return invalid(codeOf(validationErr), reviewPath)
		}
		receipts = append(receipts, receipt)
		receiptRaw[reviewPath] = raw
	}
	if err := validateReviewLineage(receipts, manifest); err != nil {
		return invalid(codeOf(err), "assurance/reviews")
	}

	replayRaw, err := readRegularFile(root, parityReplayPath, 16<<20)
	if err != nil {
		return invalid("PARITY_REPLAY_READ_FAILED", parityReplayPath)
	}
	var replay parityReplay
	if err := decodeCandidateJSON(replayRaw, &replay); err != nil {
		return invalid("PARITY_REPLAY_INVALID", parityReplayPath)
	}
	wantReplay, err := buildParityReplay(rootPath, manifest, claims, catalog, receipts, receiptRaw)
	if err != nil {
		return invalid("EVALUATION_DERIVATION_FAILED", parityReplayPath)
	}
	if !reflect.DeepEqual(replay, wantReplay) {
		return invalid("EVALUATION_REPORT_DRIFT", parityReplayPath)
	}
	if err := verifyWorkingGitBytes(rootPath, parityReplayPath, replayRaw, "HEAD"); err != nil {
		return invalid("EVALUATION_REPORT_GIT_DRIFT", parityReplayPath)
	}

	projectionRaw, err := readRegularFile(root, formalProjectionPath, 8<<20)
	if err != nil {
		return invalid("FORMAL_PROJECTION_READ_FAILED", formalProjectionPath)
	}
	var projection formalCoverageProjection
	if err := decodeCandidateJSON(projectionRaw, &projection); err != nil {
		return invalid("FORMAL_PROJECTION_INVALID", formalProjectionPath)
	}
	wantProjection := buildFormalProjection(manifest.Target, catalog, claims.BlockerCatalog)
	if !reflect.DeepEqual(projection, wantProjection) {
		return invalid("FORMAL_PROJECTION_DRIFT", formalProjectionPath)
	}

	formalReportRaw, err := readRegularFile(root, formalReportPath, 8<<20)
	if err != nil || !bytes.Equal(formalReportRaw, renderFormalCoverage(wantProjection)) {
		return invalid("FORMAL_REPORT_DRIFT", formalReportPath)
	}
	parityReportRaw, err := readRegularFile(root, parityReportPath, 8<<20)
	if err != nil || !bytes.Equal(parityReportRaw, renderParityCoverage(wantReplay)) {
		return invalid("PARITY_REPORT_DRIFT", parityReportPath)
	}
	if err := verifyWorkingGitBytes(rootPath, formalProjectionPath, projectionRaw, "HEAD"); err != nil {
		return invalid("FORMAL_PROJECTION_GIT_DRIFT", formalProjectionPath)
	}
	if err := verifyWorkingGitBytes(rootPath, formalReportPath, formalReportRaw, "HEAD"); err != nil {
		return invalid("FORMAL_REPORT_GIT_DRIFT", formalReportPath)
	}
	if err := verifyWorkingGitBytes(rootPath, parityReportPath, parityReportRaw, "HEAD"); err != nil {
		return invalid("PARITY_REPORT_GIT_DRIFT", parityReportPath)
	}

	// Existing verifiers are dispatched read-only. They validate the historical
	// lifecycle, formal replay, US-021 campaigns, and US-022 projection without
	// launching any of their workload runners.
	historical, historyErr := Verify(ctx, Request{RootPath: rootPath, Mode: ModeVerify})
	if historyErr != nil || !acceptedHistoricalLifecycle(historical) {
		return invalid("HISTORICAL_LIFECYCLE_RECONCILIATION_FAILED", "assurance/evidence-dag.json")
	}
	formalVerdict, formalErr := formal.Validate(ctx, formal.Request{RootPath: rootPath, Mode: formal.ModeReplay})
	if formalErr != nil || !formalVerdict.Valid {
		return invalid("INCUMBENT_FORMAL_RECONCILIATION_FAILED", "assurance/formal")
	}
	if err := campaign.Verify(rootPath); err != nil {
		return invalid("INCUMBENT_CAMPAIGN_RECONCILIATION_FAILED", "evidence")
	}
	if err := mutation.Verify(rootPath); err != nil {
		return invalid("INCUMBENT_MUTATION_RECONCILIATION_FAILED", "evidence/mutation")
	}

	counts := countGates(claims.Gates)
	return CandidateVerdict{
		SnapshotState:            "FROZEN",
		ParityState:              "BLOCKED",
		CandidateRoot:            manifest.CandidateRoot,
		EvaluationRoot:           replay.EvaluationRoot,
		TargetCommit:             manifest.Target.Commit,
		TargetTree:               manifest.Target.Tree,
		Assurance:                candidateAssurance,
		IndependentReviewClaimed: false,
		GateCounts:               counts,
		Blockers:                 claims.BlockerCatalog,
		Findings:                 []Finding{},
	}, nil
}

func acceptedHistoricalLifecycle(verdict Verdict) bool {
	if verdict.State != "BLOCKED" || verdict.Assurance != candidateAssurance || verdict.IndependentReviewClaimed || len(verdict.Findings) != 2 {
		return false
	}
	for index, finding := range verdict.Findings {
		if finding.Code != "INVALID_ATTESTATION" || finding.Path != fmt.Sprintf("$.attestations[%d]", index) {
			return false
		}
	}
	return true
}

func decodeCandidateJSON(raw []byte, destination any) error {
	if !json.Valid(raw) {
		return errors.New("invalid JSON or UTF-8")
	}
	if err := vendorprotocol.DecodeStrict(raw, destination); err != nil {
		return err
	}
	var decoded any
	if err := vendorprotocol.DecodeStrict(raw, &decoded); err != nil {
		return err
	}
	return rejectCandidateSecrets(decoded, "")
}

func rejectCandidateSecrets(value any, key string) error {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			lower := strings.ToLower(childKey)
			if strings.Contains(lower, "password") || strings.Contains(lower, "credential") || strings.Contains(lower, "private_key") || strings.Contains(lower, "access_token") || strings.Contains(lower, "secret_value") {
				return fmt.Errorf("secret-bearing decoded key")
			}
			if err := rejectCandidateSecrets(child, childKey); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := rejectCandidateSecrets(child, key); err != nil {
				return err
			}
		}
	case string:
		lower := strings.ToLower(typed)
		if strings.HasPrefix(lower, "-----begin ") || strings.HasPrefix(lower, "ghp_") || strings.HasPrefix(lower, "github_pat_") || strings.HasPrefix(lower, "sk-") {
			return fmt.Errorf("secret-bearing decoded string")
		}
		if strings.HasSuffix(strings.ToLower(key), "path") && key != "$schema" {
			if strings.Contains(typed, "\\") || strings.HasPrefix(typed, "/") || strings.Contains(typed, "../") {
				return fmt.Errorf("noncanonical decoded path")
			}
		}
	}
	return nil
}

func validateManifestClaims(manifest candidateManifest) error {
	if manifest.Schema != "../schemas/us023-candidate-manifest-1.0.0.schema.json" || manifest.SchemaVersion != "1.0.0" || manifest.StoryID != candidateStory || manifest.CandidateID != candidateID {
		return errors.New("MANIFEST_IDENTITY_DRIFT")
	}
	if manifest.SnapshotState != "FROZEN" || manifest.ParityState != "BLOCKED" {
		return errors.New("STATUS_OVERCLAIM")
	}
	if manifest.Assurance != candidateAssurance || manifest.IndependentReviewClaimed || manifest.Publication || manifest.Production || manifest.Signing || manifest.PerformanceClaimed || manifest.CutoverClaimed {
		return errors.New("ASSURANCE_OR_RELEASE_OVERCLAIM")
	}
	if manifest.RootNodeID != rootNodeID || manifest.Replay != (candidateReplayPaths{MachineReport: parityReplayPath, FormalProjection: formalProjectionPath, FormalReport: formalReportPath, HumanReport: parityReportPath}) {
		return errors.New("MANIFEST_PATH_DRIFT")
	}
	return nil
}

func verifyTarget(root string, target candidateTarget) error {
	if target.ObjectFormat != "sha1" || !fullGitObjectID(target.Commit) || !fullGitObjectID(target.Tree) {
		return errors.New("invalid target identity")
	}
	if _, err := gitBytesCandidate(root, "cat-file", "-e", target.Commit+"^{commit}"); err != nil {
		return err
	}
	tree, err := gitTextCandidate(root, "rev-parse", target.Commit+"^{tree}")
	if err != nil || tree != target.Tree {
		return errors.New("target tree mismatch")
	}
	return nil
}

func verifyCandidateGraph(root *projectRoot, rootPath string, manifest candidateManifest) error {
	if len(manifest.Graph.Nodes) < 2 || !sort.SliceIsSorted(manifest.Graph.Nodes, func(i, j int) bool { return manifest.Graph.Nodes[i].ID < manifest.Graph.Nodes[j].ID }) {
		return errors.New("GRAPH_ORDER_OR_DENOMINATOR_DRIFT")
	}
	seenIDs := map[string]bool{}
	pathNodes := map[string]candidateGraphNode{}
	var aggregate *candidateGraphNode
	var contentCommit string
	for index := range manifest.Graph.Nodes {
		node := manifest.Graph.Nodes[index]
		if seenIDs[node.ID] || !candidateNodeKinds[node.Kind] {
			return errors.New("GRAPH_NODE_INVALID")
		}
		seenIDs[node.ID] = true
		if node.SubjectCommit != manifest.Target.Commit || node.SubjectTree != manifest.Target.Tree || node.Classification != "PUBLIC_INTERNAL" {
			return errors.New("SUBJECT_LINEAGE_OR_CLASSIFICATION_DRIFT")
		}
		if node.Kind == "ROOT_INPUT" {
			if node.ID != rootNodeID || node.Path != "" || node.Git.Blob != "" || !fullGitObjectID(node.Git.Commit) || !fullGitObjectID(node.Git.Tree) || aggregate != nil {
				return errors.New("ROOT_NODE_INVALID")
			}
			aggregate = &manifest.Graph.Nodes[index]
			continue
		}
		if !fullGitObjectID(node.Git.Commit) || !fullGitObjectID(node.Git.Tree) || !fullGitObjectID(node.Git.Blob) {
			return errors.New("GRAPH_GIT_OBJECT_ID_NOT_CANONICAL")
		}
		if node.ID != pathNodeID(node.Path) || nodeKind(node.Path) != node.Kind || nodeFamily(node.Path) != node.Family || node.ExecutionState != "IDENTITY_ONLY" || node.ClaimStrength != "IMMUTABLE_INPUT" {
			return errors.New("GRAPH_NODE_DERIVATION_DRIFT")
		}
		if _, exists := pathNodes[node.Path]; exists {
			return errors.New("GRAPH_DUPLICATE_PATH")
		}
		pathNodes[node.Path] = node
		if node.Path == candidateClaimsPath {
			contentCommit = node.Git.Commit
		}
	}
	if aggregate == nil || contentCommit == "" || contentCommit == manifest.Target.Commit {
		return errors.New("GRAPH_CONTENT_ANCHOR_INVALID")
	}
	if _, err := gitBytesCandidate(rootPath, "merge-base", "--is-ancestor", manifest.Target.Commit, contentCommit); err != nil {
		return errors.New("CONTENT_COMMIT_NOT_DESCENDED_FROM_TARGET")
	}
	targetPaths, err := gitLines(rootPath, "ls-tree", "-r", "--name-only", manifest.Target.Commit)
	if err != nil {
		return errors.New("TARGET_MEMBERSHIP_UNAVAILABLE")
	}
	contentPaths, err := gitLines(rootPath, "ls-tree", "-r", "--name-only", contentCommit)
	if err != nil {
		return errors.New("CONTENT_MEMBERSHIP_UNAVAILABLE")
	}
	wantPaths := expectedCandidatePaths(targetPaths, contentPaths)
	gotPaths := make([]string, 0, len(pathNodes))
	for file := range pathNodes {
		gotPaths = append(gotPaths, file)
	}
	sort.Strings(gotPaths)
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		return errors.New("GRAPH_MEMBERSHIP_DRIFT")
	}
	for _, file := range wantPaths {
		node := pathNodes[file]
		if strings.Contains(file, "/hidden/") || strings.Contains(file, "/sealed/") {
			if file != "corpora/hidden/manifest.json" && file != "corpora/sealed/manifest.json" {
				return errors.New("PROTECTED_EDGE_FORBIDDEN")
			}
		}
		if _, err := canonicalPath(file); err != nil {
			return errors.New("NONCANONICAL_GRAPH_PATH")
		}
		if err := verifyGraphFileNode(rootPath, node); err != nil {
			return errors.New("GRAPH_GIT_OR_DIGEST_DRIFT")
		}
	}
	wantEdges := make([]candidateGraphEdge, 0, len(wantPaths))
	for _, file := range wantPaths {
		wantEdges = append(wantEdges, candidateGraphEdge{From: rootNodeID, To: pathNodeID(file), Relation: "CONTAINS"})
	}
	sort.Slice(wantEdges, func(i, j int) bool {
		if wantEdges[i].From != wantEdges[j].From {
			return wantEdges[i].From < wantEdges[j].From
		}
		if wantEdges[i].To != wantEdges[j].To {
			return wantEdges[i].To < wantEdges[j].To
		}
		return wantEdges[i].Relation < wantEdges[j].Relation
	})
	if !reflect.DeepEqual(manifest.Graph.Edges, wantEdges) {
		return errors.New("GRAPH_EDGE_OR_REACHABILITY_DRIFT")
	}
	wantAggregate := aggregateDigest(manifest.Graph.Nodes)
	if aggregate.SHA256 != wantAggregate || aggregate.Bytes != uint64(len(aggregateListing(manifest.Graph.Nodes))) || aggregate.Family != "STRUCTURAL" || aggregate.ExecutionState != "IDENTITY_ONLY" || aggregate.ClaimStrength != "IMMUTABLE_ROOT" {
		return errors.New("ROOT_NODE_DIGEST_DRIFT")
	}
	if tree, err := gitTextCandidate(rootPath, "rev-parse", aggregate.Git.Commit+"^{tree}"); err != nil || tree != aggregate.Git.Tree || aggregate.Git.Commit != contentCommit {
		return errors.New("ROOT_NODE_GIT_DRIFT")
	}
	if manifest.CandidateRoot != calculateCandidateRoot(manifest.Target, manifest.Graph) {
		return errors.New("CANDIDATE_ROOT_DRIFT")
	}
	return nil
}

func verifyGraphFileNode(rootPath string, node candidateGraphNode) error {
	if !fullGitObjectID(node.Git.Commit) || !fullGitObjectID(node.Git.Tree) || !fullGitObjectID(node.Git.Blob) {
		return errors.New("git object ID is not canonical")
	}
	tree, err := gitTextCandidate(rootPath, "rev-parse", node.Git.Commit+"^{tree}")
	if err != nil || tree != node.Git.Tree || node.Git.Blob == "" {
		return errors.New("git anchor mismatch")
	}
	blob, err := gitTextCandidate(rootPath, "rev-parse", node.Git.Commit+":"+node.Path)
	if err != nil || blob != node.Git.Blob {
		return errors.New("git blob mismatch")
	}
	committed, err := gitBytesCandidate(rootPath, "show", node.Git.Commit+":"+node.Path)
	if err != nil || uint64(len(committed)) != node.Bytes || digestCandidate(committed) != node.SHA256 {
		return errors.New("git object identity mismatch")
	}
	return nil
}

func validateReviewReceipt(path string, receipt reviewReceipt, manifest candidateManifest) error {
	roleByPath := map[string]string{reviewPaths[0]: "CODEX_REVIEWER", reviewPaths[1]: "HUMAN_REVIEWER", reviewPaths[2]: "QA", reviewPaths[3]: "REALITY", reviewPaths[4]: "CODEX_REVIEWER"}
	wantRoot := manifest.CandidateRoot
	if path == reviewPaths[0] {
		wantRoot = predecessorRoot
	}
	if receipt.Schema != "../../schemas/us023-review-receipt-1.0.0.schema.json" || receipt.SchemaVersion != "1.0.0" || receipt.Role != roleByPath[path] || receipt.CandidateRoot != wantRoot || receipt.Scope.CandidateRoot != wantRoot || receipt.Target != (reviewTarget{Commit: manifest.Target.Commit, Tree: manifest.Target.Tree}) {
		return errors.New("REVIEW_SUBJECT_OR_ROLE_DRIFT")
	}
	if receipt.Assurance != candidateAssurance || receipt.IndependentReviewClaimed || !sortedUnique(receipt.Scope.GateIDs) || !sortedUnique(receipt.Scope.BlockerIDs) || !sortedUnique(receipt.ParentGateNodeIDs) {
		return errors.New("REVIEW_ASSURANCE_OR_SCOPE_OVERCLAIM")
	}
	if receipt.Status == "NOT_EXECUTED" {
		closurePlaceholder := path == targetedClosurePath && receipt.ReviewKind == "TARGETED_CLOSURE" && validTargetedRemediation(receipt.RemediationTarget, manifest.CandidateRoot)
		if (!closurePlaceholder && receipt.ReviewKind != "NOT_EXECUTED") || receipt.Provider != nil || receipt.Model != nil || receipt.ReasoningEffort != nil || receipt.InvocationID != nil || len(receipt.Findings) != 0 || (!closurePlaceholder && receipt.RemediationTarget != nil) || receipt.CommentsOnly {
			return errors.New("NOT_EXECUTED_REVIEW_OVERCLAIM")
		}
		if receipt.Role == "HUMAN_REVIEWER" && !contains(receipt.Scope.BlockerIDs, "blocker-human-review") {
			return errors.New("HUMAN_REVIEW_BLOCKER_MISSING")
		}
		return nil
	}
	if receipt.Status != "EXECUTED" || (receipt.ReviewKind != "FULL" && receipt.ReviewKind != "TARGETED_CLOSURE") || !receipt.CommentsOnly {
		return errors.New("REVIEW_STATUS_INVALID")
	}
	if receipt.Role == "HUMAN_REVIEWER" {
		if receipt.Provider != nil || receipt.Model != nil || receipt.ReasoningEffort != nil || receipt.InvocationID != nil || strings.Contains(strings.ToUpper(receipt.ReviewerIdentity), "AI") || strings.Contains(strings.ToUpper(receipt.ReviewerIdentity), "GPT") || strings.Contains(strings.ToUpper(receipt.ReviewerIdentity), "CODEX") {
			return errors.New("AI_AS_HUMAN")
		}
	} else {
		if receipt.Provider == nil || *receipt.Provider != "openai" || receipt.Model == nil || *receipt.Model != "gpt-5.6-sol" || receipt.ReasoningEffort == nil || *receipt.ReasoningEffort != "xhigh" || receipt.InvocationID == nil || !strings.HasPrefix(*receipt.InvocationID, "/root/") {
			return errors.New("REVIEW_PROVENANCE_INVALID")
		}
	}
	seen := map[string]bool{}
	for _, finding := range receipt.Findings {
		if finding.FindingID == "" || seen[finding.FindingID] || (finding.Severity != "BLOCKING" && finding.Severity != "IMPORTANT" && finding.Severity != "NIT") || finding.Code == "" || finding.Path == "" {
			return errors.New("REVIEW_FINDING_INVALID")
		}
		seen[finding.FindingID] = true
	}
	if receipt.ReviewKind == "FULL" && receipt.RemediationTarget != nil {
		return errors.New("REVIEW_LINEAGE_INVALID")
	}
	if receipt.ReviewKind == "TARGETED_CLOSURE" && !validTargetedRemediation(receipt.RemediationTarget, manifest.CandidateRoot) {
		return errors.New("REVIEW_LINEAGE_INVALID")
	}
	return nil
}

func validateReviewLineage(receipts []reviewReceipt, manifest candidateManifest) error {
	full := 0
	closures := 0
	var fullReceipt *reviewReceipt
	var closureReceipt *reviewReceipt
	for _, receipt := range receipts {
		if receipt.Role == "CODEX_REVIEWER" && receipt.ReviewKind == "FULL" && receipt.Status == "EXECUTED" {
			full++
			copy := receipt
			fullReceipt = &copy
		}
		if receipt.ReviewKind == "TARGETED_CLOSURE" {
			closures++
			copy := receipt
			closureReceipt = &copy
			if len(receipt.Findings) != 0 {
				return errors.New("TARGETED_CLOSURE_SCOPE_EXPANDED")
			}
		}
	}
	if full != 1 || closures != 1 || fullReceipt == nil || closureReceipt == nil {
		return errors.New("REVIEW_LINEAGE_INCOMPLETE")
	}
	if fullReceipt.CandidateRoot != predecessorRoot || !validTargetedRemediation(closureReceipt.RemediationTarget, manifest.CandidateRoot) {
		return errors.New("REVIEW_LINEAGE_INVALID")
	}
	if closureReceipt.Status == "EXECUTED" {
		if closureReceipt.Provider == nil || fullReceipt.Provider == nil || *closureReceipt.Provider != *fullReceipt.Provider || closureReceipt.Model == nil || fullReceipt.Model == nil || *closureReceipt.Model != *fullReceipt.Model || closureReceipt.ReasoningEffort == nil || fullReceipt.ReasoningEffort == nil || *closureReceipt.ReasoningEffort != *fullReceipt.ReasoningEffort || closureReceipt.ReviewerIdentity != fullReceipt.ReviewerIdentity || closureReceipt.InvocationID == nil || fullReceipt.InvocationID == nil || !strings.HasPrefix(*closureReceipt.InvocationID, *fullReceipt.InvocationID) {
			return errors.New("TARGETED_CLOSURE_REVIEWER_DRIFT")
		}
	}
	if full > 1 {
		return errors.New("SECOND_FULL_REVIEW_FORBIDDEN")
	}
	return nil
}

func validTargetedRemediation(target *remediationTarget, successorRoot string) bool {
	return target != nil && target.PredecessorCandidateRoot == predecessorRoot && target.SuccessorCandidateRoot == successorRoot && reflect.DeepEqual(target.FindingIDs, blockingReviewFindingIDs)
}

func validateFormalSemantics(catalog formalCatalog) error {
	if len(catalog.Obligations) == 0 || len(catalog.JavaBindings) != len(catalog.Obligations) || len(catalog.RustBindings) != len(catalog.Obligations) || len(catalog.Evidence) != len(catalog.Obligations) || len(catalog.Coverage) != len(catalog.Obligations) {
		return errors.New("FORMAL_DENOMINATOR_DRIFT")
	}
	for index, obligation := range catalog.Obligations {
		if obligation.ObligationID == "" || len(obligation.SurfaceIDs) == 0 || len(obligation.RequiredMutationIDs) == 0 || len(obligation.AllowedMethods) == 0 || len(obligation.RequiredEvidenceKinds) == 0 {
			return errors.New("FORMAL_DENOMINATOR_DRIFT")
		}
		javaBinding, rustBinding := catalog.JavaBindings[index], catalog.RustBindings[index]
		evidence, coverage := catalog.Evidence[index], catalog.Coverage[index]
		if javaBinding.ObligationID != obligation.ObligationID || rustBinding.ObligationID != obligation.ObligationID || evidence.ObligationID != obligation.ObligationID || coverage.ObligationID != obligation.ObligationID {
			return errors.New("FORMAL_DENOMINATOR_DRIFT")
		}
		lowerPath, lowerSymbol := strings.ToLower(rustBinding.SourcePath), strings.ToLower(rustBinding.ProductionSymbol)
		if rustBinding.ConnectionState != "DISCONNECTED" || rustBinding.ReachableFromEntry || !contains(rustBinding.BlockerIDs, "blocker-formal-refinement") || strings.Contains(lowerPath, "/tests/") || strings.Contains(lowerSymbol, "proof") || strings.Contains(lowerSymbol, "adapter_local") {
			return errors.New("RUST_PRODUCTION_LINKAGE_OVERCLAIM")
		}
		if evidence.ExecutionState != "NOT_EXECUTED" || evidence.ObservedStrength != "NONE" {
			if evidence.Refinement.State != "CONNECTED" || evidence.Refinement.ArtifactSHA256 == nil || evidence.ExecutionState != "EXECUTED_PASS" {
				return errors.New("FORMAL_STRENGTH_OVERSTATED")
			}
		}
		if evidence.Bounds.MaxFrameBytes != nil || evidence.Bounds.MaxSteps != nil || evidence.Assumptions.Role != "UNRESOLVED" || evidence.Assumptions.Allocator != "UNRESOLVED" {
			return errors.New("FORMAL_BOUND_OR_ASSUMPTION_INCOMPATIBLE")
		}
		if evidence.Refinement.State == "CONNECTED" && evidence.Refinement.ArtifactSHA256 == nil {
			return errors.New("FORMAL_REFINEMENT_DISCONNECTED")
		}
		if len(evidence.MutationSensitivity) == 0 {
			return errors.New("MUTATION_SURVIVOR")
		}
		mutants := map[string]bool{}
		for _, mutation := range evidence.MutationSensitivity {
			mutants[mutation.MutantID] = true
			if mutation.Disposition == "SURVIVED" || mutation.Disposition == "NOT_EXECUTED" || mutation.Disposition == "UNCOVERED" {
				return errors.New("MUTATION_SURVIVOR")
			}
		}
		for _, required := range obligation.RequiredMutationIDs {
			if !mutants[required] {
				return errors.New("MUTATION_SURVIVOR")
			}
		}
		if coverage.AggregateStatus == "SATISFIED" && (coverage.JavaStatus != "SATISFIED" || coverage.RustStatus != "SATISFIED" || coverage.RefinementStatus != "SATISFIED" || coverage.MutationStatus != "SATISFIED") {
			return errors.New("FORMAL_STRENGTH_OVERSTATED")
		}
	}
	return nil
}

func validateRustBindingAnchors(root string, target candidateTarget, catalog formalCatalog) error {
	for _, binding := range catalog.RustBindings {
		if binding.Identity.Commit == nil || binding.Identity.Tree == nil || binding.Identity.Blob == nil || binding.Identity.ArchiveSHA256 != nil || !fullGitObjectID(*binding.Identity.Commit) || !fullGitObjectID(*binding.Identity.Tree) || !fullGitObjectID(*binding.Identity.Blob) || *binding.Identity.Commit != target.Commit || *binding.Identity.Tree != target.Tree {
			return errors.New("RUST_PRODUCTION_SOURCE_UNRESOLVED")
		}
		raw, err := gitBytesCandidate(root, "show", target.Commit+":"+binding.SourcePath)
		if err != nil || digestCandidate(raw) != binding.SourceSHA256 || !rustDeclarationExists(raw, binding.ProductionSymbol) {
			return errors.New("RUST_PRODUCTION_SYMBOL_UNRESOLVED")
		}
		blob, err := gitTextCandidate(root, "rev-parse", target.Commit+":"+binding.SourcePath)
		if err != nil || blob != *binding.Identity.Blob || binding.DeclarationIdentity != "git-blob:"+blob+"#"+binding.ProductionSymbol {
			return errors.New("RUST_PRODUCTION_SOURCE_UNRESOLVED")
		}
	}
	return nil
}

func aggregateListing(nodes []candidateGraphNode) []byte {
	var buffer bytes.Buffer
	for _, node := range nodes {
		if node.Kind == "ROOT_INPUT" {
			continue
		}
		buffer.WriteString(node.ID)
		buffer.WriteByte(0)
		buffer.WriteString(node.SHA256)
		buffer.WriteByte(0)
		buffer.WriteString(node.Git.Blob)
		buffer.WriteByte(0)
	}
	return buffer.Bytes()
}

func aggregateDigest(nodes []candidateGraphNode) string {
	return digestCandidate(aggregateListing(nodes))
}

func calculateCandidateRoot(target candidateTarget, graph candidateGraph) string {
	raw, _ := json.Marshal(graph)
	message := append([]byte("US023-CANDIDATE-V1\x00"+target.Commit+target.Tree), raw...)
	return digestCandidate(message)
}

func digestCandidate(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fullGitObjectID(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func gitTextCandidate(root string, arguments ...string) (string, error) {
	raw, err := gitBytesCandidate(root, arguments...)
	return strings.TrimSpace(string(raw)), err
}

func gitBytesCandidate(root string, arguments ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1"}
	return command.Output()
}

func gitLines(root string, arguments ...string) ([]string, error) {
	raw, err := gitBytesCandidate(root, arguments...)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return []string{}, nil
	}
	values := strings.Split(trimmed, "\n")
	sort.Strings(values)
	return values, nil
}

func verifyWorkingGitBytes(root, path string, raw []byte, commit string) error {
	committed, err := gitBytesCandidate(root, "show", commit+":"+path)
	if err != nil || !bytes.Equal(committed, raw) {
		return errors.New("working tree differs from Git")
	}
	return nil
}

func codeOf(err error) string {
	if err == nil {
		return "UNKNOWN"
	}
	code := err.Error()
	if index := strings.IndexAny(code, ": "); index > 0 {
		code = code[:index]
	}
	return code
}

func countGates(gates []gateRow) GateCounts {
	counts := GateCounts{}
	for _, gate := range gates {
		if gate.Required {
			counts.Required++
		}
		if gate.ObservedState == "SATISFIED" {
			counts.Satisfied++
		} else if gate.ObservedState == "BLOCKED" {
			counts.Blocked++
		}
	}
	return counts
}
