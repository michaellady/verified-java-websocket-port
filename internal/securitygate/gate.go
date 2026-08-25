// Package securitygate implements US-007's deterministic security transport.
// Candidate bytes are inspected and promoted, never interpreted or executed.
package securitygate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/assurance"
	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/michaellady/verified-java-websocket-port/internal/lab"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	OperationVerify        = "VERIFY"
	OperationIngest        = "INGEST"
	OperationVerifySandbox = "VERIFY_SANDBOX"
	OperationProject       = "PROJECT"
	AssuranceOwnerOnly     = "OWNER_ATTESTED_NOT_INDEPENDENT"
	policyVersion          = "1.0.0"
	requiredCompany        = "open-source-projects"
	requiredProject        = "verified-java-websocket-port"
	requiredLaboratory     = "lab-java-websocket"
)

var policyPaths = []string{"security/ingestion-policy.json", "security/sandbox-policy.json", "security/release-firewall.json"}
var schemaPaths = []string{"schemas/security-ingestion-policy-1.0.0.schema.json", "schemas/security-sandbox-policy-1.0.0.schema.json", "schemas/security-release-firewall-1.0.0.schema.json", "schemas/security-fixture-catalog-1.0.0.schema.json", "schemas/security-validation-1.0.0.schema.json"}
var baselineEvidencePaths = []string{"evidence/java/build.json", "evidence/java/adapter-baseline.json", "evidence/java/test-manifest.json", "evidence/java/autobahn-baseline.json", "evidence/java/behavior-delta-ledger.json"}

type Request struct {
	RootPath      string `json:"root_path"`
	Operation     string `json:"operation"`
	CandidateRoot string `json:"candidate_root,omitempty"`
	FixtureID     string `json:"fixture_id,omitempty"`
	StorePath     string `json:"store_path,omitempty"`
	PlanPath      string `json:"plan_path,omitempty"`
	ReceiptPath   string `json:"receipt_path,omitempty"`

	// fixtureSourcePath is the only mutable-directory source seam. It is
	// deliberately package-private so command/API callers cannot substitute a
	// working tree for an accepted content-addressed root.
	fixtureSourcePath string
}
type Finding struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
	Path        string `json:"path"`
	Message     string `json:"message"`
}
type Verdict struct {
	State                    string    `json:"state"`
	SecurityEvidenceRoot     string    `json:"security_evidence_root"`
	QuarantineRoot           string    `json:"quarantine_root"`
	ProjectionRoot           string    `json:"projection_root"`
	Findings                 []Finding `json:"findings"`
	Assurance                string    `json:"assurance"`
	IndependentReviewClaimed bool      `json:"independent_review_claimed"`
	PublicationAuthorized    bool      `json:"publication_authorized"`
}
type CanaryRequest struct {
	RootPath   string `json:"root_path"`
	CanaryID   string `json:"canary_id"`
	PlanDigest string `json:"plan_digest"`
}
type SandboxReceipt struct {
	SchemaVersion            string `json:"schema_version"`
	CanaryID                 string `json:"canary_id"`
	TerminationReason        string `json:"termination_reason"`
	CleanupComplete          bool   `json:"cleanup_complete"`
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
}

type scope struct {
	Company    string `json:"company"`
	Project    string `json:"project"`
	Laboratory string `json:"laboratory"`
}
type registryEntry struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
}
type fixtureBinding struct {
	ID      string `json:"id"`
	Finding string `json:"finding"`
}
type pathPolicy struct {
	NoSymlinks        bool `json:"no_symlinks"`
	SingleLinkOnly    bool `json:"single_link_only"`
	SameDevice        bool `json:"same_device"`
	NoSpecialFiles    bool `json:"no_special_files"`
	MaxDepth          int  `json:"max_depth"`
	MaxComponent      int  `json:"max_component_length"`
	MaxPath           int  `json:"max_path_length"`
	RequireNFC        bool `json:"require_nfc"`
	CaseFoldCollision bool `json:"casefold_collision"`
}
type quotaPolicy struct {
	MaxFiles          int   `json:"max_files"`
	MaxDirectories    int   `json:"max_directories"`
	MaxFileBytes      int64 `json:"max_file_bytes"`
	MaxTotalBytes     int64 `json:"max_total_bytes"`
	MaxArchiveEntries int   `json:"max_archive_entries"`
	MaxExpandedBytes  int64 `json:"max_expanded_bytes"`
	MaxArchiveDepth   int   `json:"max_archive_depth"`
	MaxExpansionRatio int64 `json:"max_expansion_ratio"`
}
type ingestionPolicy struct {
	SchemaVersion     string           `json:"schema_version"`
	Scope             scope            `json:"scope"`
	DefaultClass      string           `json:"default_classification"`
	SourceModes       []string         `json:"source_modes"`
	ExecuteActions    []string         `json:"execute_actions"`
	ExecutableClasses []string         `json:"executable_classes"`
	Paths             pathPolicy       `json:"paths"`
	Quotas            quotaPolicy      `json:"quotas"`
	FindingRegistry   []registryEntry  `json:"finding_registry"`
	FixtureBindings   []fixtureBinding `json:"fixture_bindings"`
}
type resources struct {
	WallSeconds    int   `json:"wall_seconds"`
	CPUSeconds     int   `json:"cpu_seconds"`
	MemoryBytes    int64 `json:"memory_bytes"`
	PIDs           int   `json:"pids"`
	OpenFiles      int   `json:"open_files"`
	OutputBytes    int64 `json:"output_bytes"`
	WorkspaceBytes int64 `json:"workspace_bytes"`
	CacheBytes     int64 `json:"cache_bytes"`
	DiskBytes      int64 `json:"disk_bytes"`
	Inodes         int   `json:"inodes"`
}
type sandboxPolicy struct {
	SchemaVersion           string           `json:"schema_version"`
	Scope                   scope            `json:"scope"`
	Operations              []string         `json:"operations"`
	CanaryIDs               []string         `json:"canary_ids"`
	RequiredCapabilities    []string         `json:"required_capabilities"`
	EnvironmentNames        []string         `json:"environment_names"`
	Secrets                 string           `json:"secrets"`
	Network                 string           `json:"network"`
	Resources               resources        `json:"resources"`
	FindingRegistry         []registryEntry  `json:"finding_registry"`
	AutobahnDisposition     string           `json:"autobahn_disposition"`
	FurtherRerunsAuthorized bool             `json:"further_reruns_authorized"`
	FixtureBindings         []fixtureBinding `json:"fixture_bindings"`
}
type detector struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Finding string `json:"finding"`
}
type releasePolicy struct {
	SchemaVersion            string           `json:"schema_version"`
	Scope                    scope            `json:"scope"`
	AllowedClassifications   []string         `json:"allowed_classifications"`
	IncludedClassifications  []string         `json:"included_classifications"`
	Detectors                []detector       `json:"detectors"`
	ProtectedCheckerRequired bool             `json:"protected_checker_required"`
	PublicationCapability    bool             `json:"publication_capability"`
	FindingRegistry          []registryEntry  `json:"finding_registry"`
	FixtureBindings          []fixtureBinding `json:"fixture_bindings"`
}
type fixtureCatalog struct {
	SchemaVersion            string        `json:"schema_version"`
	Company                  string        `json:"company"`
	Project                  string        `json:"project"`
	Assurance                string        `json:"assurance"`
	IndependentReviewClaimed bool          `json:"independent_review_claimed"`
	Cases                    []fixtureCase `json:"cases"`
}
type fixtureCase struct {
	ID                  string `json:"id"`
	Kind                string `json:"kind"`
	Input               string `json:"input"`
	ExpectedCode        string `json:"expected_code"`
	ExpectedDisposition string `json:"expected_disposition"`
}
type validationEvidence struct {
	SchemaVersion                      string            `json:"schema_version"`
	Story                              string            `json:"story"`
	Company                            string            `json:"company"`
	Project                            string            `json:"project"`
	PolicyDigests                      map[string]string `json:"policy_digests"`
	SchemaDigests                      map[string]string `json:"schema_digests"`
	FixtureCatalogDigest               string            `json:"fixture_catalog_digest"`
	AutobahnBaselineDigest             string            `json:"autobahn_baseline_digest"`
	OriginalReceiptDigests             []string          `json:"original_receipt_digests"`
	RemediationReceiptDigests          []string          `json:"remediation_receipt_digests"`
	ConsumedRemediationAttemptsPerMode int               `json:"consumed_remediation_attempts_per_mode"`
	FurtherRerunsAuthorized            bool              `json:"further_reruns_authorized"`
	RerunsPerformedByUS007             int               `json:"reruns_performed_by_us007"`
	FixtureResults                     []fixtureResult   `json:"fixture_results"`
	MechanicsState                     string            `json:"mechanics_state"`
	Assurance                          string            `json:"assurance"`
	IndependentReviewClaimed           bool              `json:"independent_review_claimed"`
	Production                         bool              `json:"production"`
	Signing                            bool              `json:"signing"`
	Publication                        bool              `json:"publication"`
	SandboxMechanics                   Finding           `json:"sandbox_mechanics"`
	LifecycleIntegration               Finding           `json:"lifecycle_integration"`
	Runtime                            runtimeMetadata   `json:"runtime"`
}
type fixtureResult struct {
	ID                  string `json:"id"`
	Component           string `json:"component"`
	State               string `json:"state"`
	InputDigest         string `json:"input_digest"`
	OutputDigest        string `json:"output_digest"`
	ExpectedCode        string `json:"expected_code"`
	ActualCode          string `json:"actual_code"`
	ExpectedDisposition string `json:"expected_disposition"`
	ActualDisposition   string `json:"actual_disposition"`
	CLIExit             int    `json:"cli_exit"`
	Matched             bool   `json:"matched"`
}
type runtimeMetadata struct {
	Provider                   string `json:"provider"`
	RequestedModel             string `json:"requested_model"`
	RequestedReasoningEffort   string `json:"requested_reasoning_effort"`
	TaskSessionPath            string `json:"task_session_path"`
	ActualDeploymentIdentifier string `json:"actual_deployment_identifier"`
	RuntimeSessionUUID         string `json:"runtime_session_uuid"`
}
type policySnapshot struct {
	root      *os.Root
	ingestion ingestionPolicy
	sandbox   sandboxPolicy
	release   releasePolicy
	catalog   fixtureCatalog
	evidence  validationEvidence
	bytes     map[string][]byte
	digests   map[string]string
	registry  map[string]string
	bindings  map[string]string
	autobahn  autobahnClosure
}

func Verify(ctx context.Context, request Request) (Verdict, error) {
	if err := ctx.Err(); err != nil {
		return Verdict{}, err
	}
	if request.Operation == "" {
		request.Operation = OperationVerify
	}
	if request.Operation != OperationVerify {
		return Verdict{}, fmt.Errorf("operation %q does not match VERIFY", request.Operation)
	}
	snapshot, err := loadPolicies(request.RootPath)
	if err != nil {
		return Verdict{}, err
	}
	defer snapshot.root.Close()
	verdict := baseVerdict(snapshot)
	if request.FixtureID != "" {
		item, ok := catalogCase(snapshot.catalog, request.FixtureID)
		if !ok {
			return Verdict{}, fmt.Errorf("fixture %q is not in the closed catalog", request.FixtureID)
		}
		observation, err := evaluateFixture(snapshot, item)
		if err != nil {
			return Verdict{}, err
		}
		verdict.State = observation.State
		if observation.Code != "" {
			verdict = findingVerdict(verdict, observation.Code, observation.Disposition, "security/fixtures/"+item.ID, "inert fixture produced an observed component finding")
		}
		return verdict, nil
	}
	if findings := verifyRetainedEvidence(snapshot); len(findings) != 0 {
		verdict.State = "BLOCKED"
		verdict.Findings = findings
		return verdict, nil
	}
	verified, verifyErr := assurance.Verify(ctx, assurance.Request{RootPath: request.RootPath, LifecyclePath: "assurance/lifecycle.json", Mode: assurance.ModeVerify})
	replayed, replayErr := assurance.Replay(ctx, assurance.Request{RootPath: request.RootPath, LifecyclePath: "assurance/lifecycle.json", Mode: assurance.ModeReplay})
	if verifyErr != nil || replayErr != nil || verified.SnapshotRoot != replayed.SnapshotRoot || verified.PublicEvidenceRoot != replayed.PublicEvidenceRoot {
		verdict = findingVerdict(verdict, "INVALID_SECURITY_POLICY", "BLOCK", "assurance", "assurance verify/replay adapters disagree")
		return verdict, nil
	}
	verdict = findingVerdict(verdict, "SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.platform_enforcement", "required namespace/profile, resource, mount, network, and cleanup enforcement is not proven; no host-process fallback was used")
	verdict.State = "BLOCKED_SANDBOX_ENFORCEMENT_UNAVAILABLE"
	return verdict, nil
}

func Ingest(ctx context.Context, request Request) (Verdict, error) {
	if err := ctx.Err(); err != nil {
		return Verdict{}, err
	}
	snapshot, err := loadPolicies(request.RootPath)
	if err != nil {
		return Verdict{}, err
	}
	defer snapshot.root.Close()
	verdict := baseVerdict(snapshot)
	if request.Operation != OperationIngest {
		return Verdict{}, errors.New("operation must be INGEST")
	}
	if finding := validateIngestRoots(request.RootPath, request.StorePath, request.fixtureSourcePath); finding != nil {
		return findingVerdict(verdict, finding.Code, finding.Disposition, finding.Path, finding.Message), nil
	}
	if request.fixtureSourcePath == "" && !isSHA256Digest(request.CandidateRoot) {
		return findingVerdict(verdict, "PROMOTION_BINDING_MISMATCH", "QUARANTINE", "$.candidate_root", "authoritative ingest requires one exact accepted content-addressed root"), nil
	}
	sourcePath := request.fixtureSourcePath
	if sourcePath == "" {
		// The inherited adapter verifies the accepted manifest, every object
		// digest, and the root derivation before these bytes enter US-007.
		accepted, loadErr := lab.LoadAcceptedRoot(request.StorePath, request.CandidateRoot)
		if loadErr != nil {
			return findingVerdict(verdict, "PROMOTION_BINDING_MISMATCH", "QUARANTINE", "$.candidate_root", "accepted source root did not verify: "+loadErr.Error()), nil
		}
		manifest, objects, finding := snapshotAcceptedRoot(request.CandidateRoot, accepted, snapshot.ingestion)
		if finding != nil {
			return findingVerdict(verdict, finding.Code, finding.Disposition, finding.Path, finding.Message), nil
		}
		return promoteCandidate(verdict, request.StorePath, manifest, objects, false)
	}
	if request.CandidateRoot != "" {
		return findingVerdict(verdict, "PROMOTION_BINDING_MISMATCH", "QUARANTINE", "$.candidate_root", "fixture and authoritative source modes cannot be combined"), nil
	}
	manifest, objects, finding := snapshotCandidate(sourcePath, snapshot.ingestion)
	if finding != nil {
		verdict.State = "BLOCKED"
		verdict.Findings = []Finding{*finding}
		return verdict, nil
	}
	return promoteCandidate(verdict, request.StorePath, manifest, objects, true)
}

func promoteCandidate(verdict Verdict, storePath string, manifest candidateManifest, objects []intake.Object, synthetic bool) (Verdict, error) {
	manifestBytes, err := intake.CanonicalJSON(manifest)
	if err != nil {
		return Verdict{}, err
	}
	objects = append(objects, intake.Object{ID: "candidate-manifest", Digest: intake.DigestBytes(manifestBytes), Bytes: manifestBytes})
	if storePath == "" {
		return Verdict{}, errors.New("store path is required")
	}
	root, err := intake.PromoteDirectory(storePath, objects)
	if err != nil {
		return findingVerdict(verdict, "PARTIAL_PROMOTION", "QUARANTINE", storePath, err.Error()), nil
	}
	verdict.QuarantineRoot = root
	accepted, err := lab.LoadAcceptedRoot(storePath, root)
	if err != nil {
		return findingVerdict(verdict, "PARTIAL_PROMOTION", "QUARANTINE", storePath, "promoted root did not pass read-back: "+err.Error()), nil
	}
	if retained, ok := accepted.Object("candidate-manifest"); !ok || !bytes.Equal(retained, manifestBytes) {
		return findingVerdict(verdict, "DIGEST_MISMATCH", "QUARANTINE", storePath, "promoted candidate manifest differs from the one-read snapshot"), nil
	}
	if synthetic {
		verdict.State = "PASS_SYNTHETIC_NON_CLAIM"
	} else {
		verdict.State = "PASS_INGESTION_COMPONENT"
	}
	return verdict, nil
}

func validateIngestRoots(projectRoot, storePath, fixtureSource string) *Finding {
	deny := func(path, message string) *Finding {
		return &Finding{Code: "ROOT_CONFINEMENT_FAILED", Disposition: "QUARANTINE", Path: path, Message: message}
	}
	project, err := realDirectoryIdentity(projectRoot)
	if err != nil {
		return deny("$.root", err.Error())
	}
	store, err := realDirectoryIdentity(storePath)
	if err != nil {
		return deny("$.store", err.Error())
	}
	if pathIdentitiesOverlap(project.path, store.path) {
		return deny("$.store", "project and private promotion roots must be disjoint")
	}
	if fixtureSource == "" {
		return nil
	}
	source, err := realDirectoryIdentity(fixtureSource)
	if err != nil {
		return deny("$.fixture_source", err.Error())
	}
	if pathIdentitiesOverlap(project.path, source.path) || pathIdentitiesOverlap(source.path, store.path) {
		return deny("$.fixture_source", "project, fixture source, and private promotion roots must be pairwise disjoint")
	}
	if source.device != store.device {
		return deny("$.store", "fixture staging and promotion roots must remain on one verified device")
	}
	return nil
}

type directoryIdentity struct {
	path   string
	device uint64
}

func realDirectoryIdentity(path string) (directoryIdentity, error) {
	if path == "" {
		return directoryIdentity{}, errors.New("directory path is required")
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return directoryIdentity{}, errors.New("directory must be a specific absolute path")
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return directoryIdentity{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return directoryIdentity{}, errors.New("directory must be a real directory, not a link or special file")
	}
	resolved, err := canonicalDirectoryIdentity(clean)
	if err != nil {
		return directoryIdentity{}, err
	}
	identity, ok := deviceAndLinks(info)
	if !ok {
		return directoryIdentity{}, errors.New("directory device identity is unavailable")
	}
	return directoryIdentity{path: resolved, device: identity.device}, nil
}

func canonicalDirectoryIdentity(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return "", errors.New("path must be a specific absolute directory")
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func pathIdentitiesOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+string(filepath.Separator)) || strings.HasPrefix(right, left+string(filepath.Separator))
}

func VerifySandbox(ctx context.Context, request Request) (Verdict, error) {
	if err := ctx.Err(); err != nil {
		return Verdict{}, err
	}
	snapshot, err := loadPolicies(request.RootPath)
	if err != nil {
		return Verdict{}, err
	}
	defer snapshot.root.Close()
	verdict := baseVerdict(snapshot)
	if request.Operation != OperationVerifySandbox {
		return Verdict{}, errors.New("operation must be VERIFY_SANDBOX")
	}
	planBytes, err := readRelative(snapshot.root, request.PlanPath, 1<<20)
	if err != nil {
		return Verdict{}, err
	}
	receiptBytes, err := readRelative(snapshot.root, request.ReceiptPath, 1<<20)
	if err != nil {
		return Verdict{}, err
	}
	var plan sandboxPlan
	if err := intake.DecodeStrict(planBytes, &plan); err != nil {
		return findingVerdict(verdict, "SANDBOX_RECEIPT_INVALID", "QUARANTINE", request.PlanPath, err.Error()), nil
	}
	var receipt securitySandboxReceipt
	if err := intake.DecodeStrict(receiptBytes, &receipt); err != nil {
		return findingVerdict(verdict, "SANDBOX_RECEIPT_INVALID", "QUARANTINE", request.ReceiptPath, err.Error()), nil
	}
	if finding := validateSandboxReceipt(snapshot, plan, receipt); finding != nil {
		return findingVerdict(verdict, finding.Code, finding.Disposition, finding.Path, finding.Message), nil
	}
	return findingVerdict(verdict, "SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.supervisor_authentication", "external JSON cannot authenticate supervisor-owned enforcement; no ordinary host-process fallback was used"), nil
}

func Project(ctx context.Context, request Request) (Verdict, error) {
	if err := ctx.Err(); err != nil {
		return Verdict{}, err
	}
	snapshot, err := loadPolicies(request.RootPath)
	if err != nil {
		return Verdict{}, err
	}
	defer snapshot.root.Close()
	verdict := baseVerdict(snapshot)
	if request.Operation != OperationProject {
		return Verdict{}, errors.New("operation must be PROJECT")
	}
	if !isSHA256Digest(request.CandidateRoot) {
		return findingVerdict(verdict, "PROMOTION_BINDING_MISMATCH", "QUARANTINE", "$.candidate_root", "projection requires one exact accepted quarantine-root digest"), nil
	}
	projectRoot, rootErr := realDirectoryIdentity(request.RootPath)
	storeRoot, storeErr := realDirectoryIdentity(request.StorePath)
	if rootErr != nil || storeErr != nil || pathIdentitiesOverlap(projectRoot.path, storeRoot.path) {
		return findingVerdict(verdict, "ROOT_CONFINEMENT_FAILED", "QUARANTINE", "$.store", "project and private projection roots must be real and disjoint"), nil
	}
	if request.FixtureID != "" {
		item, ok := catalogCase(snapshot.catalog, request.FixtureID)
		if !ok || item.Kind != "release" {
			return Verdict{}, fmt.Errorf("release fixture %q is not cataloged", request.FixtureID)
		}
		detectedCode, detectorExpected, detectionErr := scanReleaseFixture(snapshot.release, item)
		if detectionErr != nil || detectorExpected && detectedCode != item.ExpectedCode {
			return findingVerdict(verdict, "INVALID_SECURITY_POLICY", "BLOCK", "security/fixtures/"+item.ID, "fixture input does not independently produce its cataloged detector finding"), nil
		}
	}
	accepted, err := lab.LoadAcceptedRoot(request.StorePath, request.CandidateRoot)
	if err != nil {
		return findingVerdict(verdict, "PROMOTION_BINDING_MISMATCH", "QUARANTINE", "$.candidate_root", "accepted quarantine root did not verify: "+err.Error()), nil
	}
	projectionRoot, finding, err := materializeProjection(request.StorePath, request.CandidateRoot, accepted, snapshot.release)
	if err != nil {
		return Verdict{}, err
	}
	if finding != nil {
		return findingVerdict(verdict, finding.Code, finding.Disposition, finding.Path, finding.Message), nil
	}
	verdict.ProjectionRoot = projectionRoot
	if request.FixtureID != "" {
		verdict.State = "PASS_SYNTHETIC_NON_CLAIM"
		return verdict, nil
	}
	return findingVerdict(verdict, "PROTECTED_CLASSIFIER_UNAVAILABLE", "BLOCK", "$.protected_classifier", "the project-owned projection was materialized, reopened, rehashed, and scanned, but no external protected-classifier receipt is available"), nil
}

func scanReleaseFixture(policy releasePolicy, item fixtureCase) (string, bool, error) {
	detectorFindings := map[string]bool{}
	matched := ""
	for _, detector := range policy.Detectors {
		detectorFindings[detector.Finding] = true
		if !strings.Contains(item.Input, detector.Token) {
			continue
		}
		if matched != "" && matched != detector.Finding {
			return "", detectorFindings[item.ExpectedCode], errors.New("fixture input matched more than one release detector")
		}
		matched = detector.Finding
	}
	return matched, detectorFindings[item.ExpectedCode], nil
}

func RunControlledCanary(context.Context, CanaryRequest) (SandboxReceipt, error) {
	return SandboxReceipt{}, errors.New("SANDBOX_ENFORCEMENT_UNAVAILABLE/BLOCK")
}
func baseVerdict(snapshot *policySnapshot) Verdict {
	return Verdict{State: "BLOCKED_SANDBOX_ENFORCEMENT_UNAVAILABLE", SecurityEvidenceRoot: snapshot.digests["evidence/security-validation.json"], Findings: []Finding{}, Assurance: AssuranceOwnerOnly}
}
func findingVerdict(v Verdict, code, disposition, path, message string) Verdict {
	v.State = "BLOCKED"
	v.Findings = []Finding{{Code: code, Disposition: disposition, Path: path, Message: message}}
	return v
}
func catalogCase(c fixtureCatalog, id string) (fixtureCase, bool) {
	i := sort.Search(len(c.Cases), func(i int) bool { return c.Cases[i].ID >= id })
	if i == len(c.Cases) || c.Cases[i].ID != id {
		return fixtureCase{}, false
	}
	return c.Cases[i], true
}

func loadPolicies(rootPath string) (*policySnapshot, error) {
	if rootPath == "" {
		return nil, errors.New("root path is required")
	}
	clean := filepath.Clean(rootPath)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return nil, errors.New("root path must be a specific absolute directory")
	}
	if _, err := realDirectoryIdentity(clean); err != nil {
		return nil, fmt.Errorf("ROOT_CONFINEMENT_FAILED/QUARANTINE: %w", err)
	}
	root, err := os.OpenRoot(clean)
	if err != nil {
		return nil, err
	}
	s := &policySnapshot{root: root, bytes: map[string][]byte{}, digests: map[string]string{}, registry: map[string]string{}, bindings: map[string]string{}}
	paths := append(append([]string{}, policyPaths...), schemaPaths...)
	paths = append(paths, "security/fixtures/cases.json", "evidence/security-validation.json")
	paths = append(paths, baselineEvidencePaths...)
	for _, p := range paths {
		data, err := readRelative(root, p, 8<<20)
		if err != nil {
			root.Close()
			return nil, err
		}
		s.bytes[p] = data
		s.digests[p] = intake.DigestBytes(data)
	}
	if err := intake.DecodeStrict(s.bytes[policyPaths[0]], &s.ingestion); err != nil {
		root.Close()
		return nil, fmt.Errorf("INVALID_SECURITY_POLICY/BLOCK: %w", err)
	}
	if err := intake.DecodeStrict(s.bytes[policyPaths[1]], &s.sandbox); err != nil {
		root.Close()
		return nil, fmt.Errorf("INVALID_SECURITY_POLICY/BLOCK: %w", err)
	}
	if err := intake.DecodeStrict(s.bytes[policyPaths[2]], &s.release); err != nil {
		root.Close()
		return nil, fmt.Errorf("INVALID_SECURITY_POLICY/BLOCK: %w", err)
	}
	if err := intake.DecodeStrict(s.bytes["security/fixtures/cases.json"], &s.catalog); err != nil {
		root.Close()
		return nil, fmt.Errorf("INVALID_SECURITY_POLICY/BLOCK: %w", err)
	}
	if err := intake.DecodeStrict(s.bytes["evidence/security-validation.json"], &s.evidence); err != nil {
		root.Close()
		return nil, fmt.Errorf("INVALID_SECURITY_POLICY/BLOCK: %w", err)
	}
	if err := validateSchemas(s); err != nil {
		root.Close()
		return nil, err
	}
	if err := validatePolicies(s); err != nil {
		root.Close()
		return nil, err
	}
	closure, err := validateAutobahnClosure(s.bytes)
	if err != nil {
		root.Close()
		return nil, err
	}
	s.autobahn = closure
	return s, nil
}

func readRelative(root *os.Root, name string, limit int64) ([]byte, error) {
	if name == "" || filepath.IsAbs(name) || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) {
		return nil, fmt.Errorf("ROOT_CONFINEMENT_FAILED/QUARANTINE: invalid relative path %q", name)
	}
	clean := filepath.ToSlash(filepath.Clean(name))
	if clean != name || clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "//") {
		return nil, fmt.Errorf("ROOT_CONFINEMENT_FAILED/QUARANTINE: noncanonical path %q", name)
	}
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("ROOT_CONFINEMENT_FAILED/QUARANTINE: %s is not a bounded regular file", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("IMMUTABLE_SNAPSHOT_FAILED/QUARANTINE: %s identity changed", name)
	}
	data := make([]byte, info.Size())
	if _, err := file.ReadAt(data, 0); err != nil && len(data) != 0 {
		return nil, err
	}
	after, err := file.Stat()
	final, lerr := root.Lstat(name)
	if err != nil || lerr != nil || !os.SameFile(info, after) || !os.SameFile(info, final) || after.Size() != info.Size() || after.ModTime() != info.ModTime() || final.ModTime() != info.ModTime() {
		return nil, fmt.Errorf("IMMUTABLE_SNAPSHOT_FAILED/QUARANTINE: %s changed during its one read", name)
	}
	return data, nil
}

func validateSchemas(s *policySnapshot) error {
	compiler := jsonschema.NewCompiler()
	for _, p := range schemaPaths {
		var resource any
		if err := json.Unmarshal(s.bytes[p], &resource); err != nil {
			return fmt.Errorf("INVALID_SECURITY_POLICY/BLOCK: %w", err)
		}
		if err := compiler.AddResource("mem:///"+p, resource); err != nil {
			return fmt.Errorf("INVALID_SECURITY_POLICY/BLOCK: %w", err)
		}
	}
	pairs := [][2]string{{schemaPaths[0], policyPaths[0]}, {schemaPaths[1], policyPaths[1]}, {schemaPaths[2], policyPaths[2]}, {schemaPaths[3], "security/fixtures/cases.json"}, {schemaPaths[4], "evidence/security-validation.json"}}
	for _, pair := range pairs {
		schema, err := compiler.Compile("mem:///" + pair[0])
		if err != nil {
			return fmt.Errorf("INVALID_SECURITY_POLICY/BLOCK: %w", err)
		}
		var value any
		if err := json.Unmarshal(s.bytes[pair[1]], &value); err != nil {
			return fmt.Errorf("INVALID_SECURITY_POLICY/BLOCK: %w", err)
		}
		if err := schema.Validate(value); err != nil {
			return fmt.Errorf("INVALID_SECURITY_POLICY/BLOCK: %s: %w", pair[1], err)
		}
	}
	return nil
}

func validatePolicies(s *policySnapshot) error {
	for _, v := range []string{s.ingestion.SchemaVersion, s.sandbox.SchemaVersion, s.release.SchemaVersion, s.catalog.SchemaVersion, s.evidence.SchemaVersion} {
		if v != policyVersion {
			return errors.New("UNSUPPORTED_POLICY_VERSION/BLOCK")
		}
	}
	wantScope := scope{Company: requiredCompany, Project: requiredProject, Laboratory: requiredLaboratory}
	for _, got := range []scope{s.ingestion.Scope, s.sandbox.Scope, s.release.Scope} {
		if got != wantScope {
			return errors.New("INVALID_SECURITY_POLICY/BLOCK: scope mismatch")
		}
	}
	if s.catalog.Company != requiredCompany || s.catalog.Project != requiredProject || s.catalog.Assurance != AssuranceOwnerOnly || s.catalog.IndependentReviewClaimed {
		return errors.New("ASSURANCE_CEILING_EXCEEDED/REVOKE")
	}
	if s.ingestion.DefaultClass != "QUARANTINED" || len(s.ingestion.ExecuteActions) != 0 || !equalSet(s.ingestion.SourceModes, []string{"ACCEPTED_CONTENT_ADDRESSED_ROOT", "DISPOSABLE_FIXTURE_ROOT"}) {
		return errors.New("STATIC_EXECUTION_FORBIDDEN/QUARANTINE")
	}
	wantExecutableClasses := []string{"ARCHIVE_DECODER", "ARCHIVE_DECLARED_EXECUTABLE", "AUTOBAHN_PYTHON_DISTRIBUTION", "AUTOBAHN_PYTHON_RUNTIME", "AUTOBAHN_SCRIPT", "CARGO_BUILD_SCRIPT", "CARGO_RUNNER_OR_WRAPPER", "CONTAINER_COMMAND", "CONTAINER_ENTRYPOINT", "CONTAINER_LAYER", "CONTAINER_RUNTIME_HELPER", "GLANCER_IMPORT", "JDT_LS_IMPORT", "JVM_DEPENDENCY", "LANGUAGE_SERVER_PLUGIN", "MAVEN_ANNOTATION_PROCESSOR", "MAVEN_CORE", "MAVEN_EXTENSION", "MAVEN_PLUGIN", "RUST_ANALYZER_IMPORT", "RUST_DEPENDENCY", "RUST_PROC_MACRO", "RUST_TOOLCHAIN", "SANDBOX_SUPERVISOR", "SECURITYCTL"}
	if !equalSet(s.ingestion.ExecutableClasses, wantExecutableClasses) {
		return errors.New("EXECUTABLE_INVENTORY_INCOMPLETE/QUARANTINE")
	}
	p := s.ingestion.Paths
	q := s.ingestion.Quotas
	if !p.NoSymlinks || !p.SingleLinkOnly || !p.SameDevice || !p.NoSpecialFiles || !p.RequireNFC || !p.CaseFoldCollision || p.MaxDepth <= 0 || p.MaxComponent <= 0 || p.MaxPath <= 0 || q.MaxFiles <= 0 || q.MaxDirectories <= 0 || q.MaxFileBytes <= 0 || q.MaxTotalBytes <= 0 || q.MaxArchiveEntries <= 0 || q.MaxExpandedBytes <= 0 || q.MaxArchiveDepth <= 0 || q.MaxExpansionRatio <= 0 {
		return errors.New("INVALID_SECURITY_POLICY/BLOCK: unsafe ingestion bounds")
	}
	if s.sandbox.Secrets != "none" || s.sandbox.Network != "deny-all" || s.sandbox.FurtherRerunsAuthorized || s.sandbox.AutobahnDisposition != "NO_FURTHER_RERUNS_AUTHORIZED" {
		return errors.New("INVALID_SECURITY_POLICY/BLOCK: sandbox closure widened")
	}
	if s.release.PublicationCapability || !s.release.ProtectedCheckerRequired || !equalSet(s.release.IncludedClassifications, []string{"PUBLIC", "PUBLIC_DERIVED"}) {
		return errors.New("PUBLICATION_NOT_AUTHORIZED/BLOCK")
	}
	for _, entries := range [][]registryEntry{s.ingestion.FindingRegistry, s.sandbox.FindingRegistry, s.release.FindingRegistry} {
		for _, e := range entries {
			if e.Code == "" || !validDisposition(e.Disposition) {
				return errors.New("INVALID_SECURITY_POLICY/BLOCK: invalid registry row")
			}
			if _, ok := s.registry[e.Code]; ok {
				return errors.New("INVALID_SECURITY_POLICY/BLOCK: duplicate registry row")
			}
			s.registry[e.Code] = e.Disposition
		}
	}
	if len(s.registry) < 55 {
		return errors.New("INVALID_SECURITY_POLICY/BLOCK: incomplete finding registry")
	}
	if !sort.SliceIsSorted(s.catalog.Cases, func(i, j int) bool { return s.catalog.Cases[i].ID < s.catalog.Cases[j].ID }) {
		return errors.New("INVALID_SECURITY_POLICY/BLOCK: fixture catalog is not sorted")
	}
	seen := map[string]bool{}
	for _, bindings := range [][]fixtureBinding{s.ingestion.FixtureBindings, s.sandbox.FixtureBindings, s.release.FixtureBindings} {
		for _, binding := range bindings {
			if binding.ID == "" || binding.Finding != "" && s.registry[binding.Finding] == "" {
				return errors.New("INVALID_SECURITY_POLICY/BLOCK: invalid fixture binding")
			}
			if _, exists := s.bindings[binding.ID]; exists {
				return errors.New("INVALID_SECURITY_POLICY/BLOCK: duplicate fixture binding")
			}
			s.bindings[binding.ID] = binding.Finding
		}
	}
	for _, item := range s.catalog.Cases {
		if item.ID == "" || seen[item.ID] {
			return errors.New("INVALID_SECURITY_POLICY/BLOCK: duplicate fixture")
		}
		seen[item.ID] = true
		actual, bound := s.bindings[item.ID]
		if !bound || actual != item.ExpectedCode {
			return errors.New("INVALID_SECURITY_POLICY/BLOCK: fixture catalog and policy binding disagree")
		}
		if item.ExpectedCode == "" {
			if item.ExpectedDisposition != "" {
				return errors.New("INVALID_SECURITY_POLICY/BLOCK: success fixture has disposition")
			}
		} else if s.registry[item.ExpectedCode] != item.ExpectedDisposition {
			return errors.New("INVALID_SECURITY_POLICY/BLOCK: fixture finding not in registry")
		}
	}
	return nil
}

func verifyRetainedEvidence(s *policySnapshot) []Finding {
	e := s.evidence
	add := func(code, disp, path, msg string) []Finding {
		return []Finding{{Code: code, Disposition: disp, Path: path, Message: msg}}
	}
	if e.Story != "US-007" || e.Company != requiredCompany || e.Project != requiredProject || e.MechanicsState != "BLOCKED_SANDBOX_ENFORCEMENT_UNAVAILABLE" || e.Assurance != AssuranceOwnerOnly || e.IndependentReviewClaimed || e.Production || e.Signing || e.Publication {
		return add("ASSURANCE_CEILING_EXCEEDED", "REVOKE", "evidence/security-validation.json", "retained evidence exceeds owner-only mechanics")
	}
	for _, p := range policyPaths {
		if e.PolicyDigests[p] != s.digests[p] {
			return add("POLICY_DIGEST_MISMATCH", "QUARANTINE", p, "retained evidence policy digest differs")
		}
	}
	for _, p := range schemaPaths {
		if e.SchemaDigests[p] != s.digests[p] {
			return add("POLICY_DIGEST_MISMATCH", "QUARANTINE", p, "retained evidence schema digest differs")
		}
	}
	if e.FixtureCatalogDigest != s.digests["security/fixtures/cases.json"] {
		return add("POLICY_DIGEST_MISMATCH", "QUARANTINE", "security/fixtures/cases.json", "fixture catalog digest differs")
	}
	if e.AutobahnBaselineDigest != s.digests["evidence/java/autobahn-baseline.json"] || e.ConsumedRemediationAttemptsPerMode != s.autobahn.ConsumedRemediationAttemptsPerMode || e.FurtherRerunsAuthorized != s.autobahn.FurtherRerunsAuthorized || e.RerunsPerformedByUS007 != 0 || !equalStrings(e.OriginalReceiptDigests, s.autobahn.OriginalReceiptDigests) || !equalStrings(e.RemediationReceiptDigests, s.autobahn.RemediationReceiptDigests) {
		return add("CANONICAL_EVIDENCE_MUTATION", "REVOKE", "evidence/java/autobahn-baseline.json", "Autobahn receipt closure changed")
	}
	if e.SandboxMechanics.Code != "SANDBOX_ENFORCEMENT_UNAVAILABLE" || e.SandboxMechanics.Disposition != "BLOCK" {
		return add("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.sandbox_mechanics", "unsupported platform mechanics must fail closed")
	}
	if e.LifecycleIntegration.Code != "LIFECYCLE_INTEGRATION_UNAVAILABLE" || e.LifecycleIntegration.Disposition != "BLOCK" {
		return add("INVALID_SECURITY_POLICY", "BLOCK", "$.lifecycle_integration", "frozen US-004 lifecycle lacks an authorized US-007 evidence-node adapter")
	}
	if len(e.FixtureResults) != len(s.catalog.Cases) {
		return add("INVALID_SECURITY_POLICY", "BLOCK", "$.fixture_results", "catalog coverage is incomplete")
	}
	for i, item := range s.catalog.Cases {
		r := e.FixtureResults[i]
		observation := fixtureObservation{Component: r.Component, State: r.State, Code: r.ActualCode, Disposition: r.ActualDisposition, Exit: r.CLIExit, InputDigest: r.InputDigest}
		matched := r.ActualCode == item.ExpectedCode && r.ActualDisposition == item.ExpectedDisposition
		if r.ID != item.ID || r.ExpectedCode != item.ExpectedCode || r.ExpectedDisposition != item.ExpectedDisposition || r.InputDigest != intake.DigestBytes([]byte(item.Input)) || r.OutputDigest != fixtureObservationDigest(observation) || r.CLIExit != boolExit(r.ActualCode != "") || r.Matched != matched || r.ActualCode != "" && s.registry[r.ActualCode] != r.ActualDisposition {
			return add("INVALID_SECURITY_POLICY", "BLOCK", "$.fixture_results", "fixture result is not an exact observed component output")
		}
	}
	goodSandbox, ok := catalogCase(s.catalog, "good-sandbox-canaries")
	if !ok {
		return add("INVALID_SECURITY_POLICY", "BLOCK", "$.fixture_results", "controlled-canary fixture is absent")
	}
	index := sort.Search(len(e.FixtureResults), func(i int) bool { return e.FixtureResults[i].ID >= goodSandbox.ID })
	if index == len(e.FixtureResults) || e.FixtureResults[index].ActualCode != "SANDBOX_ENFORCEMENT_UNAVAILABLE" || e.FixtureResults[index].Matched {
		return add("SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.fixture_results", "unsupported controlled canary must be retained as an observed blocker, not a synthetic pass")
	}
	return nil
}

func boolExit(failed bool) int {
	if failed {
		return 1
	}
	return 0
}

func validDisposition(v string) bool {
	return v == "BLOCK" || v == "QUARANTINE" || v == "INVALIDATE" || v == "REVOKE"
}
func equalSet(a, b []string) bool {
	x := append([]string{}, a...)
	y := append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	return equalStrings(x, y)
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}

type sandboxPlan struct {
	SchemaVersion       string    `json:"schema_version"`
	PlanDigest          string    `json:"plan_digest"`
	PolicyDigest        string    `json:"policy_digest"`
	AcceptedRootDigest  string    `json:"accepted_root_digest"`
	InventoryRootDigest string    `json:"inventory_root_digest"`
	PromotionReceipts   []string  `json:"promotion_receipt_digests"`
	SecurityctlDigest   string    `json:"securityctl_digest"`
	SupervisorDigest    string    `json:"supervisor_digest"`
	CanaryID            string    `json:"canary_id"`
	Capabilities        []string  `json:"capabilities"`
	Resources           resources `json:"resources"`
}
type securitySandboxReceipt struct {
	SchemaVersion            string            `json:"schema_version"`
	AttemptID                string            `json:"attempt_id"`
	PriorAttemptID           string            `json:"prior_attempt_id"`
	Company                  string            `json:"company"`
	Project                  string            `json:"project"`
	PlanDigest               string            `json:"plan_digest"`
	PolicyDigest             string            `json:"policy_digest"`
	AcceptedRootDigest       string            `json:"accepted_root_digest"`
	InventoryRootDigest      string            `json:"inventory_root_digest"`
	PromotionReceipts        []string          `json:"promotion_receipt_digests"`
	SecurityctlDigest        string            `json:"securityctl_digest"`
	SupervisorDigest         string            `json:"supervisor_digest"`
	CanaryID                 string            `json:"canary_id"`
	PlatformIdentity         string            `json:"platform_identity"`
	NamespaceIDs             map[string]string `json:"namespace_ids"`
	CgroupID                 string            `json:"cgroup_id"`
	ProfileDigest            string            `json:"seccomp_or_profile_digest"`
	MountTableBeforeDigest   string            `json:"mount_table_before_digest"`
	EnvironmentNames         []string          `json:"environment_names"`
	EnvironmentDigest        string            `json:"environment_digest"`
	InheritedFDCount         int               `json:"inherited_fd_count"`
	StartedAt                string            `json:"started_at"`
	FinishedAt               string            `json:"finished_at"`
	ExitCode                 *int              `json:"exit_code"`
	TerminationReason        string            `json:"termination_reason"`
	SecretValueCount         int               `json:"secret_value_count"`
	AllowedEndpointCount     int               `json:"allowed_endpoint_count"`
	ForbiddenMountCount      int               `json:"forbidden_mount_count"`
	NetworkAttemptsByClass   map[string]int    `json:"network_attempts_by_class"`
	ObservedResources        *resources        `json:"observed_resources"`
	ArtifactCaptureComplete  bool              `json:"artifact_capture_complete"`
	SourceBeforeDigest       string            `json:"source_before_digest"`
	SourceAfterDigest        string            `json:"source_after_digest"`
	CacheBeforeDigest        string            `json:"cache_before_digest"`
	CacheAfterDigest         string            `json:"cache_after_digest"`
	ArtifactManifestDigest   string            `json:"artifact_manifest_digest"`
	LivePIDsAfter            int               `json:"live_pids_after"`
	MountsAfter              int               `json:"mounts_after"`
	InterfacesAfter          int               `json:"interfaces_after"`
	CleanupStartedAt         string            `json:"cleanup_started_at"`
	CleanupFinishedAt        string            `json:"cleanup_finished_at"`
	WritableRootsRemoved     bool              `json:"writable_roots_removed"`
	CleanupComplete          bool              `json:"cleanup_complete"`
	Assurance                string            `json:"assurance"`
	IndependentReviewClaimed bool              `json:"independent_review_claimed"`
}

func validateSandboxReceipt(s *policySnapshot, p sandboxPlan, r securitySandboxReceipt) *Finding {
	deny := func(code, disp, path, msg string) *Finding {
		return &Finding{Code: code, Disposition: disp, Path: path, Message: msg}
	}
	if p.SchemaVersion != policyVersion || r.SchemaVersion != policyVersion || p.PolicyDigest != s.digests[policyPaths[1]] || r.PolicyDigest != p.PolicyDigest || !isSHA256Digest(p.AcceptedRootDigest) || !isSHA256Digest(p.InventoryRootDigest) || r.AcceptedRootDigest != p.AcceptedRootDigest || r.InventoryRootDigest != p.InventoryRootDigest || r.CanaryID != p.CanaryID || !stringInSet(p.CanaryID, s.sandbox.CanaryIDs) || !equalStrings(p.PromotionReceipts, r.PromotionReceipts) || p.SecurityctlDigest != r.SecurityctlDigest || p.SupervisorDigest != r.SupervisorDigest {
		return deny("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$", "receipt does not bind the exact plan, policy, source, inventory, and canary")
	}
	canonicalPlanDigest, err := sandboxPlanDigest(p)
	if err != nil || p.PlanDigest != canonicalPlanDigest || r.PlanDigest != canonicalPlanDigest {
		return deny("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.plan_digest", "plan and receipt do not bind the canonical plan bytes")
	}
	if !equalSet(p.Capabilities, s.sandbox.RequiredCapabilities) || p.Resources != s.sandbox.Resources {
		return deny("SANDBOX_CAPABILITY_MISMATCH", "QUARANTINE", "$.capabilities", "capability envelope differs")
	}
	if finding := validateCompleteSandboxObservation(s, p, r); finding != nil {
		return finding
	}
	validTerminations := []string{"EXITED", "WALL_LIMIT", "CPU_LIMIT", "MEMORY_LIMIT", "PID_LIMIT", "FD_LIMIT", "OUTPUT_LIMIT", "WORKSPACE_LIMIT", "CACHE_LIMIT", "DISK_LIMIT", "INODE_LIMIT", "POLICY_DENIAL", "SUPERVISOR_FAILURE"}
	if !stringInSet(r.TerminationReason, validTerminations) {
		return deny("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.termination_reason", "receipt termination reason is absent or outside the closed registry")
	}
	limitTerminations := map[string]string{
		"CPU_BOUND":       "CPU_LIMIT",
		"MEMORY_BOUND":    "MEMORY_LIMIT",
		"PID_BOUND":       "PID_LIMIT",
		"FD_BOUND":        "FD_LIMIT",
		"OUTPUT_BOUND":    "OUTPUT_LIMIT",
		"WORKSPACE_BOUND": "WORKSPACE_LIMIT",
		"WALL_BOUND":      "WALL_LIMIT",
	}
	if expected := limitTerminations[p.CanaryID]; expected != "" && r.TerminationReason != expected {
		return deny("RESOURCE_TERMINATION_MISSING", "QUARANTINE", "$.termination_reason", "limit canary did not record its exact expected termination")
	}
	if r.SecretValueCount != 0 {
		return deny("SECRET_ACCESS_DENIED", "QUARANTINE", "$.secret_value_count", "sandbox exposed secret values")
	}
	if r.AllowedEndpointCount != 0 {
		return deny("NETWORK_POLICY_VIOLATION", "QUARANTINE", "$.allowed_endpoint_count", "deny-all operation exposed an endpoint")
	}
	if r.ForbiddenMountCount != 0 {
		return deny("FORBIDDEN_MOUNT_EXPOSED", "REVOKE", "$.forbidden_mount_count", "receipt observed a forbidden protected/signing/public/cross-company mount")
	}
	if !r.ArtifactCaptureComplete {
		return deny("ARTIFACT_CAPTURE_INCOMPLETE", "QUARANTINE", "$.artifact_capture_complete", "artifact capture was partial")
	}
	if r.SourceBeforeDigest == "" || r.SourceBeforeDigest != r.SourceAfterDigest {
		return deny("SOURCE_MUTATION_DETECTED", "QUARANTINE", "$.source_after_digest", "source changed")
	}
	if r.CacheBeforeDigest == "" || r.CacheBeforeDigest != r.CacheAfterDigest {
		return deny("CACHE_CLOSURE_MISMATCH", "QUARANTINE", "$.cache_after_digest", "cache changed")
	}
	if r.LivePIDsAfter != 0 || r.MountsAfter != 0 || r.InterfacesAfter != 0 || !r.WritableRootsRemoved || !r.CleanupComplete {
		return deny("SANDBOX_CLEANUP_INCOMPLETE", "REVOKE", "$.cleanup", "cleanup left sandbox residue")
	}
	if r.Assurance != AssuranceOwnerOnly || r.IndependentReviewClaimed {
		return deny("ASSURANCE_CEILING_EXCEEDED", "REVOKE", "$.assurance", "receipt exceeds owner-only ceiling")
	}
	return nil
}

func sandboxPlanDigest(plan sandboxPlan) (string, error) {
	canonical, err := intake.CanonicalJSON(struct {
		SchemaVersion       string    `json:"schema_version"`
		PolicyDigest        string    `json:"policy_digest"`
		AcceptedRootDigest  string    `json:"accepted_root_digest"`
		InventoryRootDigest string    `json:"inventory_root_digest"`
		PromotionReceipts   []string  `json:"promotion_receipt_digests"`
		SecurityctlDigest   string    `json:"securityctl_digest"`
		SupervisorDigest    string    `json:"supervisor_digest"`
		CanaryID            string    `json:"canary_id"`
		Capabilities        []string  `json:"capabilities"`
		Resources           resources `json:"resources"`
	}{
		SchemaVersion:       plan.SchemaVersion,
		PolicyDigest:        plan.PolicyDigest,
		AcceptedRootDigest:  plan.AcceptedRootDigest,
		InventoryRootDigest: plan.InventoryRootDigest,
		PromotionReceipts:   plan.PromotionReceipts,
		SecurityctlDigest:   plan.SecurityctlDigest,
		SupervisorDigest:    plan.SupervisorDigest,
		CanaryID:            plan.CanaryID,
		Capabilities:        plan.Capabilities,
		Resources:           plan.Resources,
	})
	if err != nil {
		return "", err
	}
	return intake.DigestBytes(canonical), nil
}

func validateCompleteSandboxObservation(s *policySnapshot, p sandboxPlan, r securitySandboxReceipt) *Finding {
	invalid := func(path, message string) *Finding {
		return &Finding{Code: "SANDBOX_RECEIPT_INVALID", Disposition: "QUARANTINE", Path: path, Message: message}
	}
	if r.AttemptID == "" || r.Company != requiredCompany || r.Project != requiredProject || len(p.PromotionReceipts) == 0 || !allDigests(p.PromotionReceipts) || !isSHA256Digest(p.SecurityctlDigest) || !isSHA256Digest(p.SupervisorDigest) {
		return invalid("$.identity", "attempt, tenant, executable, and promotion identities must be complete")
	}
	if r.PlatformIdentity == "" || r.CgroupID == "" || !isSHA256Digest(r.ProfileDigest) || !isSHA256Digest(r.MountTableBeforeDigest) || !isSHA256Digest(r.EnvironmentDigest) || !isSHA256Digest(r.ArtifactManifestDigest) {
		return invalid("$.platform_identity", "platform/profile/mount/environment/artifact identities must be complete")
	}
	for _, namespace := range []string{"ipc", "mount", "network", "pid", "user", "uts"} {
		if r.NamespaceIDs[namespace] == "" {
			return invalid("$.namespace_ids", "all disposable namespace identities must be present")
		}
	}
	if len(r.NamespaceIDs) != 6 || !equalSet(r.EnvironmentNames, s.sandbox.EnvironmentNames) || r.InheritedFDCount != 0 || r.ExitCode == nil || r.NetworkAttemptsByClass == nil || r.ObservedResources == nil {
		return invalid("$.observation", "environment, descriptor, exit, network, and resource observations must be explicit")
	}
	for class, count := range r.NetworkAttemptsByClass {
		if class == "" || count < 0 {
			return invalid("$.network_attempts_by_class", "network audit contains an invalid class/count")
		}
	}
	if !resourcesWithin(*r.ObservedResources, p.Resources) {
		return &Finding{Code: "RESOURCE_LIMIT_EXCEEDED", Disposition: "QUARANTINE", Path: "$.observed_resources", Message: "observed resources exceed the canonical plan envelope"}
	}
	started, startErr := time.Parse(time.RFC3339Nano, r.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, r.FinishedAt)
	cleanupStarted, cleanupStartErr := time.Parse(time.RFC3339Nano, r.CleanupStartedAt)
	cleanupFinished, cleanupFinishErr := time.Parse(time.RFC3339Nano, r.CleanupFinishedAt)
	if startErr != nil || finishErr != nil || cleanupStartErr != nil || cleanupFinishErr != nil || finished.Before(started) || cleanupStarted.Before(finished) || cleanupFinished.Before(cleanupStarted) {
		return invalid("$.timestamps", "execution and cleanup timestamps must be complete and ordered")
	}
	return nil
}

func allDigests(values []string) bool {
	for _, value := range values {
		if !isSHA256Digest(value) {
			return false
		}
	}
	return true
}

func resourcesWithin(observed, limit resources) bool {
	return observed.WallSeconds >= 0 && observed.WallSeconds <= limit.WallSeconds &&
		observed.CPUSeconds >= 0 && observed.CPUSeconds <= limit.CPUSeconds &&
		observed.MemoryBytes >= 0 && observed.MemoryBytes <= limit.MemoryBytes &&
		observed.PIDs >= 0 && observed.PIDs <= limit.PIDs &&
		observed.OpenFiles >= 0 && observed.OpenFiles <= limit.OpenFiles &&
		observed.OutputBytes >= 0 && observed.OutputBytes <= limit.OutputBytes &&
		observed.WorkspaceBytes >= 0 && observed.WorkspaceBytes <= limit.WorkspaceBytes &&
		observed.CacheBytes >= 0 && observed.CacheBytes <= limit.CacheBytes &&
		observed.DiskBytes >= 0 && observed.DiskBytes <= limit.DiskBytes &&
		observed.Inodes >= 0 && observed.Inodes <= limit.Inodes
}

func stringInSet(value string, values []string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
