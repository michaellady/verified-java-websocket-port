package assurance

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
	vendorvalidators "github.com/michaellady/verified-java-to-rust/foundation/validators"
)

const (
	ModeVerify       = "VERIFY"
	ModeReplay       = "REPLAY"
	assuranceCeiling = "OWNER_ATTESTED_NOT_INDEPENDENT"

	upstreamSnapshotRoot = "sha256:3362b2e93e78dd10a739af3f474286a60a4ae487e93d1b24c91a029e5faeb14b"
	upstreamPublicRoot   = "sha256:7868eb6731d3703ff1cf5048b7e9c353444dd1ee5a41faff439862e274c4f487"

	upstreamManifestPath = "assurance/upstream-manifest.json"
	lifecyclePathDefault = "assurance/lifecycle.json"
	evidenceModelPath    = "assurance/evidence-model.json"
	evolutionPath        = "assurance/evolution.json"
	evidenceDAGPath      = "assurance/evidence-dag.json"
	checkpointPath       = "assurance/replay/checkpoint.json"
	failuresPath         = "assurance/failures.json"
	publicContractPath   = "assurance/public-contract.json"
	jdtLSPath            = "assurance/developer-tools/jdt-ls.json"
	rustAnalyzerPath     = "assurance/developer-tools/rust-analyzer.json"
	glancerPath          = "assurance/developer-tools/glancer.json"
)

var retryAllowlist = map[string]bool{
	"NETWORK_DENIED":         true,
	"WORKER_INTERRUPTED":     true,
	"STORAGE_UNAVAILABLE":    true,
	"LEASE_EXPIRED":          true,
	"QUARANTINE_UNAVAILABLE": true,
}

type Request struct {
	RootPath      string `json:"root_path"`
	LifecyclePath string `json:"lifecycle_path"`
	Mode          string `json:"mode"`
}

type Verdict struct {
	State                    string                   `json:"state"`
	SnapshotRoot             string                   `json:"snapshot_root"`
	PublicEvidenceRoot       string                   `json:"public_evidence_root"`
	Findings                 []vendorprotocol.Finding `json:"findings"`
	Assurance                string                   `json:"assurance"`
	IndependentReviewClaimed bool                     `json:"independent_review_claimed"`
}

type projectRoot struct{ root *os.Root }

type upstreamManifest struct {
	AcceptedSnapshotRoot string                  `json:"accepted_snapshot_root"`
	AcceptedPublicRoot   string                  `json:"accepted_public_root"`
	Entries              []upstreamManifestEntry `json:"entries"`
}

type upstreamManifestEntry struct {
	SourcePath string `json:"source_path"`
	TargetPath string `json:"target_path"`
	SHA256     string `json:"sha256"`
}

type failureRegistry struct {
	SchemaVersion string                 `json:"schema_version"`
	Entries       []failureRegistryEntry `json:"entries"`
}

type failureRegistryEntry struct {
	Code        string                     `json:"code"`
	Disposition vendorprotocol.Disposition `json:"disposition"`
}

type publicContract struct {
	State                    string   `json:"state"`
	Assurance                string   `json:"assurance"`
	IndependentReviewClaimed bool     `json:"independent_review_claimed"`
	ReplayCommand            string   `json:"replay_command"`
	ReplayTool               string   `json:"replay_tool"`
	WhyBlocked               string   `json:"why_blocked"`
	Freshness                string   `json:"freshness"`
	DeveloperTools           []string `json:"developer_tools"`
	PublicationRequested     bool     `json:"publication_requested"`
	PublicEvidence           []struct {
		ID             string `json:"id"`
		Classification string `json:"classification"`
		Reachable      bool   `json:"reachable"`
	} `json:"public_evidence"`
}

func Verify(ctx context.Context, request Request) (Verdict, error) {
	return evaluate(ctx, request, ModeVerify)
}

func Replay(ctx context.Context, request Request) (Verdict, error) {
	return evaluate(ctx, request, ModeReplay)
}

func evaluate(ctx context.Context, request Request, expectedMode string) (Verdict, error) {
	if err := ctx.Err(); err != nil {
		return Verdict{}, err
	}
	if request.RootPath == "" {
		return Verdict{}, errors.New("root path is required")
	}
	if request.Mode == "" {
		request.Mode = expectedMode
	}
	if request.Mode != expectedMode {
		return Verdict{}, fmt.Errorf("mode %q does not match %s", request.Mode, expectedMode)
	}
	if request.LifecyclePath == "" {
		request.LifecyclePath = lifecyclePathDefault
	}
	root, err := openProjectRoot(request.RootPath)
	if err != nil {
		return Verdict{}, err
	}
	defer func() { _ = root.Close() }()

	findings := make([]vendorprotocol.Finding, 0)
	add := func(code string, disposition vendorprotocol.Disposition, path, message string) {
		findings = append(findings, vendorprotocol.Finding{Code: code, Disposition: disposition, Path: path, Message: message})
	}

	if err := verifyUpstreamManifest(root, add); err != nil {
		return Verdict{}, err
	}

	bundleData, err := readRegularFile(root, request.LifecyclePath, vendorprotocol.MaxJSONBytes)
	if err != nil {
		return Verdict{}, err
	}
	if err := rejectNullRequiredBundleFields(bundleData); err != nil {
		return Verdict{}, err
	}
	var bundle vendorprotocol.Bundle
	if err := vendorprotocol.DecodeStrict(bundleData, &bundle); err != nil {
		return Verdict{}, err
	}

	policy := childPolicy()
	reference := vendorprotocol.NormalizeFindings(vendorvalidators.VerifyReference(bundle, policy))
	independent := vendorprotocol.NormalizeFindings(vendorvalidators.VerifyIndependent(bundle, policy))
	checkpointEligible := false
	if !sameFindings(reference, independent) {
		add("PARENT_VALIDATOR_DISAGREEMENT", vendorprotocol.Block, request.LifecyclePath, "reference and independent protocol validators disagree")
	} else {
		findings = append(findings, reference...)
		checkpointEligible = len(reference) == 0
	}

	validateEvidenceArtifacts(root, add)
	bindingValid := validateEvidenceNodeBindings(root, bundle, add)
	if checkpointEligible && bindingValid {
		validateCheckpoint(root, bundle, policy, add)
	} else if !bindingValid {
		add("CHECKPOINT_INVALID", vendorprotocol.Block, checkpointPath, "checkpoint identity is stale because retained evidence bytes no longer match the lifecycle snapshot binding")
	}
	validateIdentifierUniqueness(bundle, add)
	validateFailureRegistry(root, bundle, add)
	validateDeveloperToolRuns(root, add)
	validateEvidenceDAG(root, bundle, add)
	validatePublicContract(root, bundle, add)

	findings = vendorprotocol.NormalizeFindings(findings)
	if findings == nil {
		findings = []vendorprotocol.Finding{}
	}
	snapshotRoot, err := vendorprotocol.Digest(bundle)
	if err != nil {
		return Verdict{}, err
	}
	publicData, err := readRegularFile(root, publicContractPath, vendorprotocol.MaxJSONBytes)
	if err != nil {
		return Verdict{}, err
	}
	publicRoot := vendorprotocol.DigestBytes(publicData)
	return Verdict{
		State:                    "BLOCKED",
		SnapshotRoot:             snapshotRoot,
		PublicEvidenceRoot:       publicRoot,
		Findings:                 findings,
		Assurance:                assuranceCeiling,
		IndependentReviewClaimed: false,
	}, nil
}

func childPolicy() vendorprotocol.Policy {
	policy := vendorprotocol.JavaToRustPolicy()
	policy.Version = "foundation-1.0.0+java-websocket-single-owner-1.0.0"
	policy.Company = "open-source-projects"
	policy.Project = "verified-java-websocket-port"
	policy.RequiredAttestationRoles = nil
	policy.TransientErrorTypes = append(append([]string(nil), policy.TransientErrorTypes...), "QUARANTINE_UNAVAILABLE")
	policy.ActionRoles = map[string][]string{
		"COMPLETE_ATTEMPT:ingest":  {"port-implementer"},
		"COMPLETE_ATTEMPT:verify":  {"port-implementer"},
		"COMPLETE_ATTEMPT:attest":  {"port-implementer"},
		"COMPLETE_ATTEMPT:publish": {"release-attestor"},
		"VERIFY_CHECKPOINT:":       {"release-attestor"},
	}
	return policy
}

func verifyUpstreamManifest(root *projectRoot, add func(string, vendorprotocol.Disposition, string, string)) error {
	data, err := readRegularFile(root, upstreamManifestPath, vendorprotocol.MaxJSONBytes)
	if err != nil {
		add("INVALID_UPSTREAM_MANIFEST", vendorprotocol.Block, upstreamManifestPath, err.Error())
		return nil
	}
	var manifest upstreamManifest
	if err := vendorprotocol.DecodeStrict(data, &manifest); err != nil {
		add("INVALID_UPSTREAM_MANIFEST", vendorprotocol.Block, upstreamManifestPath, err.Error())
		return nil
	}
	if manifest.AcceptedSnapshotRoot != upstreamSnapshotRoot || manifest.AcceptedPublicRoot != upstreamPublicRoot {
		add("UPSTREAM_ROOT_MISMATCH", vendorprotocol.Block, upstreamManifestPath, "accepted upstream roots do not match the frozen Laboratory Zero pin")
	}
	expectedByTarget := make(map[string]upstreamManifestEntry, len(expectedUpstreamEntries))
	for _, entry := range expectedUpstreamEntries {
		expectedByTarget[entry.TargetPath] = entry
	}
	seenTargets := make(map[string]bool, len(manifest.Entries))
	if len(manifest.Entries) != len(expectedUpstreamEntries) {
		add("INVALID_UPSTREAM_MANIFEST", vendorprotocol.Block, upstreamManifestPath, "entry count drifted from the accepted closed set")
	}
	for index, entry := range manifest.Entries {
		expected, ok := expectedByTarget[entry.TargetPath]
		switch {
		case entry.TargetPath == "" || entry.SHA256 == "" || entry.SourcePath == "":
			add("INVALID_UPSTREAM_MANIFEST", vendorprotocol.Block, fmt.Sprintf("$.entries[%d]", index), "source path, target path, and digest are required")
			continue
		case seenTargets[entry.TargetPath]:
			add("INVALID_UPSTREAM_MANIFEST", vendorprotocol.Block, fmt.Sprintf("$.entries[%d].target_path", index), "manifest target paths must be unique")
			continue
		case !ok:
			add("INVALID_UPSTREAM_MANIFEST", vendorprotocol.Block, fmt.Sprintf("$.entries[%d].target_path", index), "manifest target path is outside the accepted closed set")
			continue
		case entry.SourcePath != expected.SourcePath || entry.SHA256 != expected.SHA256:
			add("INVALID_UPSTREAM_MANIFEST", vendorprotocol.Block, fmt.Sprintf("$.entries[%d]", index), "manifest entry drifted from the accepted source-path and digest anchor")
		}
		seenTargets[entry.TargetPath] = true
	}
	for _, entry := range expectedUpstreamEntries {
		if !seenTargets[entry.TargetPath] {
			add("INVALID_UPSTREAM_MANIFEST", vendorprotocol.Block, upstreamManifestPath, "manifest is missing an accepted vendored target")
		}
		data, readErr := readRegularFile(root, entry.TargetPath, 8<<20)
		if readErr != nil {
			add("MISSING_VENDORED_FILE", vendorprotocol.Block, entry.TargetPath, readErr.Error())
			continue
		}
		if vendorprotocol.DigestBytes(data) != entry.SHA256 {
			add("VENDORED_FILE_DIGEST_MISMATCH", vendorprotocol.Block, entry.TargetPath, "vendored or copied upstream bytes drifted from the frozen pin")
		}
	}
	closedSet := make(map[string]string, len(expectedUpstreamEntries))
	for _, entry := range expectedUpstreamEntries {
		closedSet[entry.TargetPath] = entry.SHA256
	}
	for _, prefix := range []string{"third_party/verified-java-to-rust-foundation", "assurance/schema"} {
		if err := walkClosedSet(root, prefix, closedSet, add); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidenceNodeBindings(root *projectRoot, bundle vendorprotocol.Bundle, add func(string, vendorprotocol.Disposition, string, string)) bool {
	nodeByID := make(map[string]vendorprotocol.Node, len(bundle.Nodes))
	for _, node := range bundle.Nodes {
		nodeByID[node.ID] = node
	}
	digests := make(map[string]string, len(expectedEvidenceNodes))
	valid := true
	for _, expected := range expectedEvidenceNodes {
		node, ok := nodeByID[expected.ID]
		if !ok {
			add("EVIDENCE_NODE_BINDING_MISMATCH", vendorprotocol.Block, expected.Path, "lifecycle is missing a retained evidence node")
			valid = false
			continue
		}
		data, err := readRegularFile(root, expected.Path, 8<<20)
		if err != nil {
			add("EVIDENCE_NODE_BINDING_MISMATCH", vendorprotocol.Block, expected.Path, err.Error())
			valid = false
			continue
		}
		decoded, decodeErr := base64.StdEncoding.DecodeString(node.ContentBase64)
		var binding struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		}
		if decodeErr != nil || vendorprotocol.DecodeStrict(decoded, &binding) != nil || binding.Path != expected.Path || binding.SHA256 != vendorprotocol.DigestBytes(data) || node.Digest != vendorprotocol.DigestBytes(decoded) || node.Classification != expected.Classification {
			add("EVIDENCE_NODE_BINDING_MISMATCH", vendorprotocol.Block, expected.Path, "lifecycle evidence node does not bind the exact retained artifact bytes and classification")
			valid = false
		}
		digests[expected.ID] = vendorprotocol.DigestBytes(data)
	}
	if digest, err := snapshotBindingDigest(bundle, digests); err != nil {
		add("EVIDENCE_NODE_BINDING_MISMATCH", vendorprotocol.Block, lifecyclePathDefault, err.Error())
		valid = false
	} else if bundle.Snapshot.CandidateDigest != digest {
		add("EVIDENCE_NODE_BINDING_MISMATCH", vendorprotocol.Block, "$.snapshot.candidate_digest", "snapshot identity drifted from the retained evidence-byte binding")
		valid = false
	}
	return valid
}

func snapshotBindingDigest(bundle vendorprotocol.Bundle, digests map[string]string) (string, error) {
	type binding struct {
		Company       string            `json:"company"`
		Project       string            `json:"project"`
		RootNodeID    string            `json:"root_node_id"`
		EvidenceBytes map[string]string `json:"evidence_bytes"`
	}
	return vendorprotocol.Digest(binding{
		Company:       bundle.Company,
		Project:       bundle.Project,
		RootNodeID:    bundle.RootNodeID,
		EvidenceBytes: digests,
	})
}

func walkClosedSet(root *projectRoot, prefix string, expected map[string]string, add func(string, vendorprotocol.Disposition, string, string)) error {
	return fs.WalkDir(root, prefix, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if _, ok := expected[path]; !ok {
			add("UNEXPECTED_VENDORED_FILE", vendorprotocol.Block, path, "closed inherited file set contains an unexpected path")
		}
		return nil
	})
}

func validateEvidenceArtifacts(root *projectRoot, add func(string, vendorprotocol.Disposition, string, string)) {
	evidenceData, err := readRegularFile(root, evidenceModelPath, 8<<20)
	if err != nil {
		add("MISSING_EVIDENCE", vendorprotocol.Block, evidenceModelPath, err.Error())
		return
	}
	for _, failure := range vendorvalidators.VerifyFoundationEvidence(evidenceData) {
		add(failure.Code, vendorprotocol.Block, evidenceModelPath+failure.Path, failure.Message)
	}
	evolutionData, err := readRegularFile(root, evolutionPath, 8<<20)
	if err != nil {
		add("MISSING_EVIDENCE", vendorprotocol.Block, evolutionPath, err.Error())
		return
	}
	for _, failure := range vendorvalidators.VerifyFoundationEvolution(evolutionData) {
		add(failure.Code, vendorprotocol.Block, evolutionPath+failure.Path, failure.Message)
	}
}

func validateCheckpoint(root *projectRoot, bundle vendorprotocol.Bundle, policy vendorprotocol.Policy, add func(string, vendorprotocol.Disposition, string, string)) {
	data, err := readRegularFile(root, checkpointPath, vendorprotocol.MaxJSONBytes)
	if err != nil {
		add("CHECKPOINT_INVALID", vendorprotocol.Block, checkpointPath, err.Error())
		return
	}
	if err := rejectNullRequiredCheckpointFields(data); err != nil {
		add("CHECKPOINT_INVALID", vendorprotocol.Block, checkpointPath, err.Error())
		return
	}
	var checkpoint vendorprotocol.Checkpoint
	if err := vendorprotocol.DecodeStrict(data, &checkpoint); err != nil {
		add("CHECKPOINT_INVALID", vendorprotocol.Block, checkpointPath, err.Error())
		return
	}
	if _, err := vendorprotocol.Resume(checkpoint, bundle, policy, nil, checkpointClock(bundle), protocolVerifiers()...); err != nil {
		add("CHECKPOINT_INVALID", vendorprotocol.Block, checkpointPath, err.Error())
	}
}

func validateFailureRegistry(root *projectRoot, bundle vendorprotocol.Bundle, add func(string, vendorprotocol.Disposition, string, string)) {
	data, err := readRegularFile(root, failuresPath, vendorprotocol.MaxJSONBytes)
	if err != nil {
		add("MISSING_FAILURE_REGISTRY", vendorprotocol.Block, failuresPath, err.Error())
		return
	}
	var registry failureRegistry
	if err := vendorprotocol.DecodeStrict(data, &registry); err != nil {
		add("INVALID_FAILURE_REGISTRY", vendorprotocol.Block, failuresPath, err.Error())
		return
	}
	if registry.SchemaVersion != vendorprotocol.SchemaVersion {
		add("INVALID_FAILURE_REGISTRY", vendorprotocol.Block, failuresPath, "failure registry schema version drifted from the accepted child schema")
	}
	expected := make(map[string]vendorprotocol.Disposition, len(expectedFailureRegistryEntries))
	expectedRetry := make([]string, 0, 5)
	for _, entry := range expectedFailureRegistryEntries {
		expected[entry.Code] = entry.Disposition
		if entry.Disposition == vendorprotocol.Retry {
			expectedRetry = append(expectedRetry, entry.Code)
		}
	}
	known := make(map[string]vendorprotocol.Disposition, len(registry.Entries))
	actualRetry := make([]string, 0, len(registry.Entries))
	for index, entry := range registry.Entries {
		switch {
		case entry.Code == "":
			add("INVALID_FAILURE_REGISTRY", vendorprotocol.Block, fmt.Sprintf("$.entries[%d].code", index), "failure registry codes must be non-empty")
		case known[entry.Code] != "":
			add("INVALID_FAILURE_REGISTRY", vendorprotocol.Block, fmt.Sprintf("$.entries[%d].code", index), "failure registry codes must be unique")
		case expected[entry.Code] == "":
			add("INVALID_FAILURE_REGISTRY", vendorprotocol.Block, fmt.Sprintf("$.entries[%d].code", index), "failure registry code is outside the accepted closed set")
		}
		known[entry.Code] = entry.Disposition
		if entry.Disposition == vendorprotocol.Retry {
			actualRetry = append(actualRetry, entry.Code)
		}
	}
	if len(registry.Entries) != len(expectedFailureRegistryEntries) {
		add("INVALID_FAILURE_REGISTRY", vendorprotocol.Block, failuresPath, "failure registry entry count drifted from the accepted closed set")
	}
	for code, disposition := range expected {
		if known[code] == "" {
			add("INVALID_FAILURE_REGISTRY", vendorprotocol.Block, failuresPath, "failure registry is missing an accepted code")
			continue
		}
		if known[code] != disposition {
			add("INVALID_FAILURE_REGISTRY", vendorprotocol.Block, failuresPath, "failure registry disposition drifted from the accepted closed set")
		}
	}
	actualRetryJSON, _ := vendorprotocol.CanonicalJSON(sortedStringsStable(actualRetry))
	expectedRetryJSON, _ := vendorprotocol.CanonicalJSON(sortedStringsStable(expectedRetry))
	if !bytes.Equal(actualRetryJSON, expectedRetryJSON) {
		add("INVALID_FAILURE_REGISTRY", vendorprotocol.Block, failuresPath, "failure registry retry allowlist drifted from the accepted closed set")
	}
	for _, disposition := range []vendorprotocol.Disposition{
		vendorprotocol.Retry, vendorprotocol.DegradeNonAssurance, vendorprotocol.Block,
		vendorprotocol.Invalidate, vendorprotocol.Quarantine, vendorprotocol.Revoke,
	} {
		if !registryHasDisposition(known, disposition) {
			add("INCOMPLETE_FAILURE_REGISTRY", vendorprotocol.Block, failuresPath, "registry must retain all six protocol dispositions")
		}
	}
	for index, failure := range bundle.Failures {
		disposition, ok := known[failure.ErrorType]
		if !ok {
			add("UNKNOWN_FAILURE_CODE", vendorprotocol.Block, fmt.Sprintf("$.failures[%d].error_type", index), "failure error type is absent from the closed registry")
			continue
		}
		if disposition != failure.Disposition {
			add("INVALID_FAILURE_BINDING", vendorprotocol.Block, fmt.Sprintf("$.failures[%d].disposition", index), "failure disposition does not match the closed registry")
		}
		if failure.Disposition == vendorprotocol.Retry && (!retryAllowlist[failure.ErrorType] || (failure.ErrorType == "QUARANTINE_UNAVAILABLE" && failure.StageID != "ingest")) {
			add("INVALID_RETRY_ERROR_TYPE", vendorprotocol.Block, fmt.Sprintf("$.failures[%d].error_type", index), "only the retry allowlist may emit RETRY, and QUARANTINE_UNAVAILABLE may retry only during ingest")
		}
	}
	for index, attempt := range bundle.Attempts {
		if attempt.Disposition == vendorprotocol.Retry && (!retryAllowlist[attempt.ErrorType] || (attempt.ErrorType == "QUARANTINE_UNAVAILABLE" && attempt.StageID != "ingest")) {
			add("INVALID_RETRY_ERROR_TYPE", vendorprotocol.Block, fmt.Sprintf("$.attempts[%d].error_type", index), "only the retry allowlist may emit RETRY, and QUARANTINE_UNAVAILABLE may retry only during ingest")
		}
	}
}

func validateIdentifierUniqueness(bundle vendorprotocol.Bundle, add func(string, vendorprotocol.Disposition, string, string)) {
	seenAttempts := make(map[string]bool, len(bundle.Attempts))
	for index, attempt := range bundle.Attempts {
		if attempt.ID == "" || seenAttempts[attempt.ID] {
			add("DUPLICATE_ID", vendorprotocol.Block, fmt.Sprintf("$.attempts[%d].id", index), "attempt identity is empty or duplicated")
			continue
		}
		seenAttempts[attempt.ID] = true
	}
	seenFailures := make(map[string]bool, len(bundle.Failures))
	for index, failure := range bundle.Failures {
		if failure.ID == "" || seenFailures[failure.ID] {
			add("DUPLICATE_ID", vendorprotocol.Block, fmt.Sprintf("$.failures[%d].id", index), "failure identity is empty or duplicated")
			continue
		}
		seenFailures[failure.ID] = true
	}
}

func validateDeveloperToolRuns(root *projectRoot, add func(string, vendorprotocol.Disposition, string, string)) {
	seenProfiles := map[string]bool{}
	for _, item := range expectedDeveloperToolRuns {
		data, err := readRegularFile(root, item.Path, 8<<20)
		if err != nil {
			add("MISSING_DEVELOPER_TOOL_RUN", vendorprotocol.Block, item.Path, err.Error())
			continue
		}
		if err := validateDeveloperToolRunDocument(data, item); err != nil {
			add("INVALID_DEVELOPER_TOOL_RUN", vendorprotocol.Block, item.Path, err.Error())
			continue
		}
		var run developerToolRunDocument
		if err := vendorprotocol.DecodeStrict(data, &run); err != nil {
			add("INVALID_DEVELOPER_TOOL_RUN", vendorprotocol.Block, item.Path, err.Error())
			continue
		}
		if len(run.AssuranceClaims) != 0 || len(run.GateEffects) != 0 {
			add("LSP_ASSURANCE_BOUNDARY", vendorprotocol.Block, item.Path, "developer-tool evidence must keep assurance claims and gate effects empty")
		}
		if seenProfiles[run.ProfileID] {
			add("LSP_PROFILE_OVERLAP", vendorprotocol.Block, item.Path, "developer-tool profiles must be mutually exclusive and unique")
		}
		seenProfiles[run.ProfileID] = true
	}
}

func validateEvidenceDAG(root *projectRoot, bundle vendorprotocol.Bundle, add func(string, vendorprotocol.Disposition, string, string)) {
	declared, err := readRegularFile(root, evidenceDAGPath, vendorprotocol.MaxJSONBytes)
	if err != nil {
		add("MISSING_EVIDENCE_DAG", vendorprotocol.Block, evidenceDAGPath, err.Error())
		return
	}
	type graphNode struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	type graphEdge struct {
		From string `json:"from"`
		To   string `json:"to"`
		Kind string `json:"kind"`
	}
	type projection struct {
		SchemaVersion string      `json:"schema_version"`
		RootNodeID    string      `json:"root_node_id"`
		Nodes         []graphNode `json:"nodes"`
		Edges         []graphEdge `json:"edges"`
	}
	computed := projection{
		SchemaVersion: "1.0.0",
		RootNodeID:    bundle.RootNodeID,
		Nodes:         make([]graphNode, 0, len(bundle.Nodes)),
		Edges:         make([]graphEdge, 0, len(bundle.Edges)),
	}
	for _, node := range bundle.Nodes {
		computed.Nodes = append(computed.Nodes, graphNode{ID: node.ID, Kind: node.Kind})
	}
	for _, edge := range bundle.Edges {
		computed.Edges = append(computed.Edges, graphEdge{From: edge.From, To: edge.To, Kind: edge.Kind})
	}
	sort.Slice(computed.Nodes, func(i, j int) bool { return computed.Nodes[i].ID < computed.Nodes[j].ID })
	sort.Slice(computed.Edges, func(i, j int) bool {
		if computed.Edges[i].From != computed.Edges[j].From {
			return computed.Edges[i].From < computed.Edges[j].From
		}
		if computed.Edges[i].To != computed.Edges[j].To {
			return computed.Edges[i].To < computed.Edges[j].To
		}
		return computed.Edges[i].Kind < computed.Edges[j].Kind
	})
	expected, err := vendorprotocol.CanonicalJSON(computed)
	if err != nil {
		add("ROOT_BINDING_MISMATCH", vendorprotocol.Block, evidenceDAGPath, err.Error())
		return
	}
	var expectedAny any
	if err := vendorprotocol.DecodeStrict(expected, &expectedAny); err != nil {
		add("ROOT_BINDING_MISMATCH", vendorprotocol.Block, evidenceDAGPath, err.Error())
		return
	}
	normalizedExpected, err := vendorprotocol.CanonicalJSON(expectedAny)
	if err != nil {
		add("ROOT_BINDING_MISMATCH", vendorprotocol.Block, evidenceDAGPath, err.Error())
		return
	}
	var declaredAny any
	if err := vendorprotocol.DecodeStrict(declared, &declaredAny); err != nil {
		add("ROOT_BINDING_MISMATCH", vendorprotocol.Block, evidenceDAGPath, err.Error())
		return
	}
	normalizedDeclared, err := vendorprotocol.CanonicalJSON(declaredAny)
	if err != nil {
		add("ROOT_BINDING_MISMATCH", vendorprotocol.Block, evidenceDAGPath, err.Error())
		return
	}
	if !bytes.Equal(normalizedExpected, normalizedDeclared) {
		add("ROOT_BINDING_MISMATCH", vendorprotocol.Block, evidenceDAGPath, "evidence-dag projection does not match the canonical lifecycle DAG")
	}
}

func validatePublicContract(root *projectRoot, bundle vendorprotocol.Bundle, add func(string, vendorprotocol.Disposition, string, string)) {
	data, err := readRegularFile(root, publicContractPath, vendorprotocol.MaxJSONBytes)
	if err != nil {
		add("MISSING_PUBLIC_CONTRACT", vendorprotocol.Block, publicContractPath, err.Error())
		return
	}
	var value publicContract
	if err := vendorprotocol.DecodeStrict(data, &value); err != nil {
		add("INVALID_PUBLIC_CONTRACT", vendorprotocol.Block, publicContractPath, err.Error())
		return
	}
	expected := expectedPublicContract(bundle)
	left, leftErr := vendorprotocol.CanonicalJSON(value)
	right, rightErr := vendorprotocol.CanonicalJSON(expected)
	if leftErr != nil || rightErr != nil || !bytes.Equal(left, right) {
		add("INVALID_PUBLIC_CONTRACT", vendorprotocol.Block, publicContractPath, "public contract drifted from the exact blocked owner-only public boundary")
	}
	if value.Assurance != assuranceCeiling || value.IndependentReviewClaimed {
		add("INVALID_PUBLIC_CONTRACT", vendorprotocol.Block, publicContractPath, "public contract must disclose the single-owner assurance ceiling")
	}
	lower := strings.ToLower(string(data))
	for _, forbidden := range []string{"protected_case", "sealed_case", "raw_diagnostic", "expected_output", "protected_output"} {
		if strings.Contains(lower, forbidden) {
			add("PROTECTED_PUBLICATION_DISCLOSURE", vendorprotocol.Revoke, publicContractPath, "public contract leaked protected or raw diagnostic material")
			return
		}
	}
}

func expectedPublicContract(bundle vendorprotocol.Bundle) publicContract {
	adjacency := make(map[string][]string, len(bundle.Edges))
	for _, edge := range bundle.Edges {
		adjacency[edge.From] = append(adjacency[edge.From], edge.To)
	}
	visited := map[string]bool{bundle.RootNodeID: true}
	queue := []string{bundle.RootNodeID}
	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		for _, next := range adjacency[current] {
			if !visited[next] {
				visited[next] = true
				queue = append(queue, next)
			}
		}
	}
	publicEvidence := make([]struct {
		ID             string `json:"id"`
		Classification string `json:"classification"`
		Reachable      bool   `json:"reachable"`
	}, 0, len(expectedEvidenceNodes))
	nodeByID := make(map[string]vendorprotocol.Node, len(bundle.Nodes))
	for _, node := range bundle.Nodes {
		nodeByID[node.ID] = node
	}
	for _, item := range expectedEvidenceNodes {
		node := nodeByID[item.ID]
		publicEvidence = append(publicEvidence, struct {
			ID             string `json:"id"`
			Classification string `json:"classification"`
			Reachable      bool   `json:"reachable"`
		}{ID: item.ID, Classification: node.Classification, Reachable: visited[item.ID]})
	}
	sort.Slice(publicEvidence, func(i, j int) bool { return publicEvidence[i].ID < publicEvidence[j].ID })
	return publicContract{
		State:                    "BLOCKED",
		Assurance:                assuranceCeiling,
		IndependentReviewClaimed: false,
		ReplayCommand:            "go run ./cmd/assurectl replay --root . --lifecycle assurance/lifecycle.json",
		ReplayTool:               "assurectl",
		WhyBlocked:               "US-004 instantiates the inherited lifecycle mechanics with synthetic non-claim evidence and no independent attestation.",
		Freshness:                "FRESH",
		DeveloperTools:           []string{jdtLSPath, rustAnalyzerPath, glancerPath},
		PublicationRequested:     false,
		PublicEvidence:           publicEvidence,
	}
}

func sameFindings(left, right []vendorprotocol.Finding) bool {
	leftBytes, leftErr := vendorprotocol.CanonicalJSON(left)
	rightBytes, rightErr := vendorprotocol.CanonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func registryHasDisposition(values map[string]vendorprotocol.Disposition, wanted vendorprotocol.Disposition) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func protocolVerifiers() []vendorprotocol.NamedVerifier {
	return []vendorprotocol.NamedVerifier{
		{ID: "reference", Verify: vendorvalidators.VerifyReference},
		{ID: "independent", Verify: vendorvalidators.VerifyIndependent},
	}
}

func checkpointClock(bundle vendorprotocol.Bundle) vendorprotocol.Clock {
	now := bundle.VerifiedAt.UTC()
	return func() time.Time { return now }
}

func openProjectRoot(path string) (*projectRoot, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &projectRoot{root: root}, nil
}

func (value *projectRoot) Open(name string) (fs.File, error)      { return value.root.Open(name) }
func (value *projectRoot) Stat(name string) (fs.FileInfo, error)  { return value.root.Stat(name) }
func (value *projectRoot) Lstat(name string) (fs.FileInfo, error) { return value.root.Lstat(name) }
func (value *projectRoot) Close() error                           { return value.root.Close() }

func readRegularFile(root *projectRoot, name string, limit int64) ([]byte, error) {
	canonical, err := canonicalPath(name)
	if err != nil {
		return nil, err
	}
	beforeInfo, err := root.Lstat(canonical)
	if err != nil {
		return nil, err
	}
	if !beforeInfo.Mode().IsRegular() || beforeInfo.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is not a regular file", canonical)
	}
	beforeIdentity, ok := fileIdentityOf(beforeInfo)
	if !ok || beforeIdentity.nlink != 1 {
		return nil, fmt.Errorf("%s is not an immutable single-link file", canonical)
	}
	file, err := root.Open(canonical)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fileInfoBefore, err := file.Stat()
	if err != nil {
		return nil, err
	}
	fileIdentityBefore, ok := fileIdentityOf(fileInfoBefore)
	if !ok || beforeIdentity != fileIdentityBefore || beforeInfo.Size() != fileInfoBefore.Size() {
		return nil, fmt.Errorf("%s changed while being opened", canonical)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds limit", canonical)
	}
	fileInfoAfter, err := file.Stat()
	if err != nil {
		return nil, err
	}
	fileIdentityAfter, ok := fileIdentityOf(fileInfoAfter)
	if !ok || beforeIdentity != fileIdentityAfter || fileInfoBefore.Size() != fileInfoAfter.Size() {
		return nil, fmt.Errorf("%s changed while being read", canonical)
	}
	afterInfo, err := root.Lstat(canonical)
	if err != nil {
		return nil, err
	}
	afterIdentity, ok := fileIdentityOf(afterInfo)
	if !ok || beforeIdentity != afterIdentity || beforeInfo.Size() != afterInfo.Size() {
		return nil, fmt.Errorf("%s changed while being read", canonical)
	}
	return data, nil
}

func canonicalPath(name string) (string, error) {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("path must be slash-relative")
	}
	if strings.Contains(name, "//") || strings.HasPrefix(name, "./") || strings.Contains(name, "/./") {
		return "", fmt.Errorf("path must be canonical")
	}
	clean := path.Clean(name)
	if clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("path escapes root")
	}
	parts := strings.Split(clean, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("path is not canonical")
		}
	}
	return clean, nil
}

func rejectNullRequiredBundleFields(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	required := []string{
		"schema_version",
		"company",
		"project",
		"verified_at",
		"snapshot",
		"root_node_id",
		"nodes",
		"edges",
		"stages",
		"attempts",
		"failures",
		"authorization",
		"attestations",
		"publication",
	}
	for _, field := range required {
		value, ok := raw[field]
		if !ok {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("cannot unmarshal null into required lifecycle field %q", field)
		}
	}
	return rejectNullPublicationFields(raw["publication"])
}

func rejectNullRequiredCheckpointFields(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	for _, field := range []string{"schema_version", "state_digest", "created_at", "state"} {
		value, ok := raw[field]
		if !ok {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("cannot unmarshal null into required checkpoint field %q", field)
		}
	}
	return nil
}

func rejectNullPublicationFields(data json.RawMessage) error {
	if len(data) == 0 {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	for _, field := range []string{"requested", "complete", "classification", "object_digests", "replay_command"} {
		value, ok := raw[field]
		if !ok {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("cannot unmarshal null into required lifecycle field %q", "publication."+field)
		}
	}
	return nil
}

type fileIdentity struct {
	dev   uint64
	ino   uint64
	nlink uint64
}

func fileIdentityOf(info fs.FileInfo) (fileIdentity, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, false
	}
	return fileIdentity{dev: uint64(stat.Dev), ino: uint64(stat.Ino), nlink: uint64(stat.Nlink)}, true
}
