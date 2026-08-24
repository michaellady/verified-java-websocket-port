package assurance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

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
	WhyBlocked               string   `json:"why_blocked"`
	Freshness                string   `json:"freshness"`
	DeveloperTools           []string `json:"developer_tools"`
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
	var bundle vendorprotocol.Bundle
	if err := vendorprotocol.DecodeStrict(bundleData, &bundle); err != nil {
		return Verdict{}, err
	}

	policy := childPolicy()
	reference := vendorprotocol.NormalizeFindings(vendorvalidators.VerifyReference(bundle, policy))
	independent := vendorprotocol.NormalizeFindings(vendorvalidators.VerifyIndependent(bundle, policy))
	if !sameFindings(reference, independent) {
		add("PARENT_VALIDATOR_DISAGREEMENT", vendorprotocol.Block, request.LifecyclePath, "reference and independent protocol validators disagree")
	} else {
		findings = append(findings, reference...)
	}

	validateEvidenceArtifacts(root, add)
	validateFailureRegistry(root, bundle, add)
	validateDeveloperToolRuns(root, add)
	validateEvidenceDAG(root, bundle, add)
	validatePublicContract(root, add)

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
	state := bundle.Snapshot.State
	if len(findings) != 0 {
		state = "BLOCKED"
	}
	return Verdict{
		State:                    state,
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
	policy.ActionRoles = map[string][]string{
		"COMPLETE_ATTEMPT:ingest":  {"port-implementer"},
		"COMPLETE_ATTEMPT:verify":  {"port-implementer"},
		"COMPLETE_ATTEMPT:attest":  {"port-implementer"},
		"COMPLETE_ATTEMPT:publish": {"release-attestor"},
	}
	return policy
}

func verifyUpstreamManifest(root *projectRoot, add func(string, vendorprotocol.Disposition, string, string)) error {
	data, err := readRegularFile(root, upstreamManifestPath, vendorprotocol.MaxJSONBytes)
	if err != nil {
		return err
	}
	var manifest upstreamManifest
	if err := vendorprotocol.DecodeStrict(data, &manifest); err != nil {
		return err
	}
	if manifest.AcceptedSnapshotRoot != upstreamSnapshotRoot || manifest.AcceptedPublicRoot != upstreamPublicRoot {
		add("UPSTREAM_ROOT_MISMATCH", vendorprotocol.Block, upstreamManifestPath, "accepted upstream roots do not match the frozen Laboratory Zero pin")
	}
	expected := make(map[string]string, len(manifest.Entries))
	for index, entry := range manifest.Entries {
		if entry.TargetPath == "" || entry.SHA256 == "" {
			add("INVALID_UPSTREAM_MANIFEST", vendorprotocol.Block, fmt.Sprintf("$.entries[%d]", index), "target path and digest are required")
			continue
		}
		expected[entry.TargetPath] = entry.SHA256
		data, readErr := readRegularFile(root, entry.TargetPath, 8<<20)
		if readErr != nil {
			add("MISSING_VENDORED_FILE", vendorprotocol.Block, entry.TargetPath, readErr.Error())
			continue
		}
		if vendorprotocol.DigestBytes(data) != entry.SHA256 {
			add("VENDORED_FILE_DIGEST_MISMATCH", vendorprotocol.Block, entry.TargetPath, "vendored or copied upstream bytes drifted from the frozen pin")
		}
	}
	for _, prefix := range []string{"third_party/verified-java-to-rust-foundation", "assurance/schema"} {
		if err := walkClosedSet(root, prefix, expected, add); err != nil {
			return err
		}
	}
	return nil
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
	known := make(map[string]vendorprotocol.Disposition, len(registry.Entries))
	for _, entry := range registry.Entries {
		known[entry.Code] = entry.Disposition
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
		if failure.Disposition == vendorprotocol.Retry && !retryAllowlist[failure.ErrorType] {
			add("INVALID_RETRY_ERROR_TYPE", vendorprotocol.Block, fmt.Sprintf("$.failures[%d].error_type", index), "only the retry allowlist may emit RETRY")
		}
	}
	for index, attempt := range bundle.Attempts {
		if attempt.Disposition == vendorprotocol.Retry && !retryAllowlist[attempt.ErrorType] {
			add("INVALID_RETRY_ERROR_TYPE", vendorprotocol.Block, fmt.Sprintf("$.attempts[%d].error_type", index), "only the retry allowlist may emit RETRY")
		}
	}
}

func validateDeveloperToolRuns(root *projectRoot, add func(string, vendorprotocol.Disposition, string, string)) {
	type expectedRun struct {
		path      string
		profileID string
		language  string
		name      string
		version   string
	}
	expected := []expectedRun{
		{path: jdtLSPath, profileID: "profile.jdt-ls.java.v1", language: "java", name: "Eclipse JDT Language Server", version: "1.60.0"},
		{path: rustAnalyzerPath, profileID: "profile.rust-analyzer.baseline.v1", language: "rust", name: "rust-analyzer", version: "2026-08-17.4"},
		{path: glancerPath, profileID: "profile.glancer.experimental.v1", language: "rust", name: "Rust Glancer", version: "v0.1.1"},
	}
	seenProfiles := map[string]bool{}
	for _, item := range expected {
		data, err := readRegularFile(root, item.path, 8<<20)
		if err != nil {
			add("MISSING_DEVELOPER_TOOL_RUN", vendorprotocol.Block, item.path, err.Error())
			continue
		}
		var run map[string]any
		if err := vendorprotocol.DecodeStrict(data, &run); err != nil {
			add("INVALID_DEVELOPER_TOOL_RUN", vendorprotocol.Block, item.path, err.Error())
			continue
		}
		tool, _ := run["tool"].(map[string]any)
		claims, claimsOK := run["assurance_claims"].([]any)
		effects, effectsOK := run["gate_effects"].([]any)
		if run["schema_version"] != "1.0.0" || run["entity_type"] != "DeveloperToolRun" || run["profile_id"] != item.profileID || run["language"] != item.language || tool["name"] != item.name || tool["version"] != item.version {
			add("INVALID_DEVELOPER_TOOL_RUN", vendorprotocol.Block, item.path, "developer-tool run does not match the frozen profile identity")
		}
		if !claimsOK || !effectsOK || len(claims) != 0 || len(effects) != 0 {
			add("LSP_ASSURANCE_BOUNDARY", vendorprotocol.Block, item.path, "developer-tool evidence must keep assurance claims and gate effects empty")
		}
		profileID, _ := run["profile_id"].(string)
		if seenProfiles[profileID] {
			add("LSP_PROFILE_OVERLAP", vendorprotocol.Block, item.path, "developer-tool profiles must be mutually exclusive and unique")
		}
		seenProfiles[profileID] = true
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
		computed.Edges = append(computed.Edges, graphEdge{From: edge.From, To: edge.To})
	}
	sort.Slice(computed.Nodes, func(i, j int) bool { return computed.Nodes[i].ID < computed.Nodes[j].ID })
	sort.Slice(computed.Edges, func(i, j int) bool {
		if computed.Edges[i].From != computed.Edges[j].From {
			return computed.Edges[i].From < computed.Edges[j].From
		}
		return computed.Edges[i].To < computed.Edges[j].To
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

func validatePublicContract(root *projectRoot, add func(string, vendorprotocol.Disposition, string, string)) {
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
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds limit", canonical)
	}
	afterInfo, err := root.Stat(canonical)
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
	clean := filepath.ToSlash(filepath.Clean(name))
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
