package intake

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
)

var evidenceFiles = []string{
	"source-pins.json",
	"toolchain-pins.json",
	"sbom.json",
	"vulnerability-snapshot.json",
	"promotion-receipts.json",
}

type VerifyReport struct {
	EvidenceRoot string            `json:"evidence_root"`
	FileDigests  map[string]string `json:"file_digests"`
	Blockers     []Finding         `json:"blockers"`
}

// TrustedAuthority is supplied by the protected caller, never loaded from the
// candidate evidence directory.
type TrustedAuthority struct {
	AuthorityMode string
	OwnerActorID  string
	Identities    map[string]Identity
	Snapshots     map[string]Snapshot
	Ledger        NonceLedger
}

type sourceDocument struct {
	SchemaVersion          string             `json:"schema_version"`
	Company                string             `json:"company"`
	Project                string             `json:"project"`
	LaboratoryID           string             `json:"laboratory_id"`
	CatalogID              string             `json:"catalog_id"`
	AcquiredAt             time.Time          `json:"acquired_at"`
	AcquisitionMode        string             `json:"acquisition_mode"`
	PublicationRequested   bool               `json:"publication_requested"`
	DefaultClassification  string             `json:"default_classification"`
	Lifecycle              lifecycle          `json:"lifecycle"`
	Repository             repositoryBinding  `json:"repository"`
	Artifacts              []sourceArtifact   `json:"artifacts"`
	DeferredPlatformInputs []deferredPlatform `json:"deferred_platform_inputs"`
}

type lifecycle struct {
	ExpiresAt  time.Time `json:"expires_at"`
	Rotation   string    `json:"rotation"`
	Revocation string    `json:"revocation"`
}

type repositoryBinding struct {
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	HTTPSURL      string `json:"https_url"`
	BindingCommit string `json:"binding_commit"`
}

type sourceArtifact struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	ImmutableURL string `json:"immutable_url"`
	AssetAPIURL  string `json:"asset_api_url,omitempty"`
	SHA256       string `json:"sha256"`
	SHA512       string `json:"sha512,omitempty"`
	ByteSize     int64  `json:"byte_size"`
	License      string `json:"license"`
	Provenance   string `json:"provenance"`
	Replay       string `json:"replay"`
}

type deferredPlatform struct {
	Platform string `json:"platform"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
}

type toolchainDocument struct {
	SchemaVersion        string               `json:"schema_version"`
	Company              string               `json:"company"`
	Project              string               `json:"project"`
	LaboratoryID         string               `json:"laboratory_id"`
	GeneratedAt          time.Time            `json:"generated_at"`
	ExecutionState       string               `json:"execution_state"`
	QualificationSandbox qualificationSandbox `json:"qualification_sandbox"`
	Executables          []executablePin      `json:"executables"`
	Container            toolchainContainer   `json:"container"`
}

type toolchainContainer struct {
	Reference                string `json:"reference"`
	Platform                 string `json:"platform"`
	ManifestDigest           string `json:"manifest_digest"`
	ConfigDigest             string `json:"config_digest"`
	CompressedLayerBytes     int64  `json:"compressed_layer_bytes"`
	FloatingTagSatisfiesGate bool   `json:"floating_tag_satisfies_gate"`
	Executed                 bool   `json:"executed"`
}

type qualificationSandbox struct {
	RequiredRole    string   `json:"required_role"`
	RequestedAccess []string `json:"requested_access"`
	ForbiddenAccess []string `json:"forbidden_access"`
	Disposable      bool     `json:"disposable"`
	Secrets         string   `json:"secrets"`
	Publication     bool     `json:"publication"`
}

type executablePin struct {
	ArtifactID                 string            `json:"artifact_id"`
	Platform                   string            `json:"platform"`
	Version                    string            `json:"version"`
	BinaryDigests              map[string]string `json:"binary_digests"`
	LockGraph                  []string          `json:"lock_graph"`
	SBOMComponentID            string            `json:"sbom_component_id"`
	VulnerabilityObservationID string            `json:"vulnerability_observation_id"`
	License                    string            `json:"license"`
	Provenance                 string            `json:"provenance"`
	MirrorOrReplay             string            `json:"mirror_or_replay"`
	ExpiresAt                  time.Time         `json:"expires_at"`
	Rotation                   string            `json:"rotation"`
	Revocation                 string            `json:"revocation"`
	AssuranceMode              string            `json:"assurance_mode,omitempty"`
	QualificationStatus        string            `json:"qualification_status,omitempty"`
}

type sbomDocument struct {
	BomFormat      string          `json:"bomFormat"`
	SpecVersion    string          `json:"specVersion"`
	SchemaVersion  string          `json:"schema_version"`
	Company        string          `json:"company"`
	Project        string          `json:"project"`
	LaboratoryID   string          `json:"laboratory_id"`
	GeneratedAt    time.Time       `json:"generated_at"`
	Classification string          `json:"classification"`
	Scanner        json.RawMessage `json:"scanner"`
	Components     []sbomComponent `json:"components"`
	Dependencies   json.RawMessage `json:"dependencies"`
}

type sbomComponent struct {
	Ref                   string   `json:"bom-ref"`
	Type                  string   `json:"type"`
	Name                  string   `json:"name"`
	Version               string   `json:"version"`
	PURL                  string   `json:"purl"`
	Hashes                []string `json:"hashes"`
	Licenses              []string `json:"licenses"`
	ScannerComponentCount int      `json:"scanner_component_count,omitempty"`
}

type vulnerabilityDocument struct {
	SchemaVersion     string                     `json:"schema_version"`
	Company           string                     `json:"company"`
	Project           string                     `json:"project"`
	LaboratoryID      string                     `json:"laboratory_id"`
	GeneratedAt       time.Time                  `json:"generated_at"`
	ExpiresAt         time.Time                  `json:"expires_at"`
	Classification    string                     `json:"classification"`
	Decision          string                     `json:"decision"`
	DecisionReason    string                     `json:"decision_reason"`
	OSVSnapshot       json.RawMessage            `json:"osv_snapshot"`
	ContainerSnapshot containerVulnerabilityScan `json:"container_snapshot"`
	Observations      []vulnerabilityObservation `json:"observations"`
	Rotation          string                     `json:"rotation"`
	Revocation        string                     `json:"revocation"`
}

type containerVulnerabilityScan struct {
	ArtifactID           string         `json:"artifact_id"`
	ImageDigest          string         `json:"image_digest"`
	Scanner              string         `json:"scanner"`
	ScannerBinarySHA256  string         `json:"scanner_binary_sha256"`
	IndexedPackages      int            `json:"indexed_packages"`
	VulnerablePackages   int            `json:"vulnerable_packages"`
	UniqueRules          int            `json:"unique_vulnerability_rules"`
	ResultCount          int            `json:"result_count"`
	SeverityCounts       map[string]int `json:"severity_counts"`
	FixCounts            map[string]int `json:"fix_counts"`
	CriticalIDs          []string       `json:"critical_ids"`
	RawSARIFSHA256       string         `json:"raw_sarif_sha256"`
	RawSARIFBytes        int64          `json:"raw_sarif_bytes"`
	RawGzipSHA256        string         `json:"raw_gzip_sha256"`
	RawGzipBytes         int64          `json:"raw_gzip_bytes"`
	InternalEvidencePath string         `json:"internal_evidence_path"`
	Replay               string         `json:"replay"`
}

type vulnerabilityObservation struct {
	ID         string `json:"id"`
	ArtifactID string `json:"artifact_id"`
	Status     string `json:"status"`
}

type promotionDocument struct {
	SchemaVersion                    string            `json:"schema_version"`
	Company                          string            `json:"company"`
	Project                          string            `json:"project"`
	LaboratoryID                     string            `json:"laboratory_id"`
	AuthorityMode                    string            `json:"authority_mode"`
	PolicyVersion                    string            `json:"policy_version"`
	PolicyDigest                     string            `json:"policy_digest"`
	PolicyAmendmentVersion           string            `json:"policy_amendment_version"`
	PolicyAmendmentDigest            string            `json:"policy_amendment_digest"`
	AssuranceCeiling                 string            `json:"assurance_ceiling"`
	CandidatePayload                 candidatePayload  `json:"candidate_payload"`
	Status                           string            `json:"status"`
	PublicationRequested             bool              `json:"publication_requested"`
	PublicationCount                 int               `json:"publication_count"`
	ProtectedAccessCount             int               `json:"protected_access_count"`
	AcceptedObjectCount              int               `json:"accepted_object_count"`
	PromotionStoreRoot               string            `json:"promotion_store_root,omitempty"`
	SignedActions                    []Action          `json:"signed_actions"`
	AuthoritativeSnapshotProjections []json.RawMessage `json:"authoritative_snapshot_projections"`
	RequiredActions                  []requiredAction  `json:"required_actions"`
	ApprovalPolicy                   approvalPolicy    `json:"approval_policy"`
	BlockingFindings                 []Finding         `json:"blocking_findings"`
	SafeNextAction                   string            `json:"safe_next_action"`
	Claim                            string            `json:"claim"`
}

type approvalPolicy struct {
	AuthorityModel                string `json:"authority_model"`
	OwnerActorID                  string `json:"owner_actor_id"`
	OwnerActionPrincipalsRequired int    `json:"owner_action_principals_required"`
	IndependentApprovalsRequired  int    `json:"independent_approvals_required"`
	IndependentReviewClaimed      bool   `json:"independent_review_claimed"`
	AssuranceCeiling              string `json:"assurance_ceiling"`
	NonceLedger                   string `json:"nonce_ledger"`
	RoleAndRevocationSnapshots    string `json:"role_and_revocation_snapshots"`
}

type candidatePayload struct {
	RootAlgorithm string          `json:"root_algorithm"`
	RootDigest    string          `json:"root_digest"`
	Files         []candidateFile `json:"files"`
}

type candidateFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type requiredAction struct {
	Stage                  string   `json:"stage"`
	Role                   string   `json:"role"`
	RequestedSandboxAccess []string `json:"requested_sandbox_access"`
	PublicationRequested   bool     `json:"publication_requested"`
	Status                 string   `json:"status"`
}

var requiredActionPolicy = []requiredAction{
	{Stage: "acquisition", Role: "method-schema-steward", RequestedSandboxAccess: []string{}, PublicationRequested: false},
	{Stage: "quarantine", Role: "port-implementer", RequestedSandboxAccess: []string{}, PublicationRequested: false},
	{Stage: "qualification", Role: "port-implementer", RequestedSandboxAccess: []string{"quarantined-source"}, PublicationRequested: false},
	{Stage: PromotionStageID, Role: "release-attestor", RequestedSandboxAccess: []string{}, PublicationRequested: false},
}

type expectedArtifact struct {
	URL    string
	Digest string
	Size   int64
}

var expectedArtifacts = map[string]expectedArtifact{
	"java-websocket-source-archive":                   {"https://github.com/TooTallNate/Java-WebSocket/archive/da3cf2a777aed862f2f5b5cf060cae7969958667.tar.gz", "sha256:f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4", 190008},
	"java-websocket-license":                          {"https://raw.githubusercontent.com/TooTallNate/Java-WebSocket/da3cf2a777aed862f2f5b5cf060cae7969958667/LICENSE", "sha256:15101a7cbdaa7f1c161424b760e907e7832e4a1e7f05d03373ca91fbffdb95ee", 1082},
	"java-websocket-source-pom":                       {"https://raw.githubusercontent.com/TooTallNate/Java-WebSocket/da3cf2a777aed862f2f5b5cf060cae7969958667/pom.xml", "sha256:56a83e3452869e9c8e02ef0650fec57148a68820c8a815ab99d9774d5b9dbce9", 13425},
	"java-websocket-runtime-jar":                      {"https://repo1.maven.org/maven2/org/java-websocket/Java-WebSocket/1.6.0/Java-WebSocket-1.6.0.jar", "sha256:eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f", 140686},
	"java-websocket-runtime-pom":                      {"https://repo1.maven.org/maven2/org/java-websocket/Java-WebSocket/1.6.0/Java-WebSocket-1.6.0.pom", "sha256:a8e84d553c34d793e2ea7e4a54b073f44ddb0bb442f4dd6fad0cecd755d1ceac", 13737},
	"rfc6455-text":                                    {"https://www.rfc-editor.org/rfc/rfc6455.txt", "sha256:765775326aee0ecca9b04bde3fd1f52932d498e33e34e428bd61b8a24da0fa3b", 162067},
	"autobahn-source-archive":                         {"https://github.com/crossbario/autobahn-testsuite/archive/6ed6f439dc7ed0d7432fe2cf7481b110905ecc5c.tar.gz", "sha256:c17e0e22b9ca0f6ebd415bb14dc60e7fd7ea57b50fbc4ba12892dd454b98e66b", 1325014},
	"autobahn-license":                                {"https://raw.githubusercontent.com/crossbario/autobahn-testsuite/6ed6f439dc7ed0d7432fe2cf7481b110905ecc5c/LICENSE", "sha256:0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594", 10174},
	"autobahn-case-registry":                          {"https://raw.githubusercontent.com/crossbario/autobahn-testsuite/6ed6f439dc7ed0d7432fe2cf7481b110905ecc5c/autobahntestsuite/autobahntestsuite/case/__init__.py", "sha256:12ce097739b14751daefa1fd1ee4125ca1b95584759100563c00cf796eac7cb4", 10072},
	"autobahn-linux-amd64-image":                      {"docker://docker.io/crossbario/autobahn-testsuite@" + AutobahnManifestDigest, AutobahnManifestDigest, 388892885},
	"openjdk-17.0.19-homebrew-bottle":                 {"https://ghcr.io/v2/homebrew/core/openjdk/17/blobs/sha256:6d51e51e754dc75437c5c552eea568ec2f166e39fc3faa256e668083a8620c17", "sha256:6d51e51e754dc75437c5c552eea568ec2f166e39fc3faa256e668083a8620c17", 186238433},
	"apache-maven-3.9.11":                             {"https://archive.apache.org/dist/maven/maven-3/3.9.11/binaries/apache-maven-3.9.11-bin.tar.gz", "sha256:4b7195b6a4f5c81af4c0212677a32ee8143643401bc6e1e8412e6b06ea82beac", 9160848},
	"rustc-1.95.0-aarch64-apple-darwin":               {"https://static.rust-lang.org/dist/2026-04-16/rustc-1.95.0-aarch64-apple-darwin.tar.xz", "sha256:149e85a285b6eba58eb6c8bdf7deb1b93763890598e62cb635a712e3a8454f04", 67652240},
	"cargo-1.95.0-aarch64-apple-darwin":               {"https://static.rust-lang.org/dist/2026-04-16/cargo-1.95.0-aarch64-apple-darwin.tar.xz", "sha256:6c2ffed8e1ac9cf4dc9e80f282a869a6b237a153e7c55cca039d33de29d80aaf", 8731256},
	"rust-std-1.95.0-aarch64-apple-darwin":            {"https://static.rust-lang.org/dist/2026-04-16/rust-std-1.95.0-aarch64-apple-darwin.tar.xz", "sha256:9b30089b0f767cb91b2190ffec55a9beeb2a21a1405d8da0f664d7e09d08e6d8", 27317176},
	"rust-src-1.95.0":                                 {"https://static.rust-lang.org/dist/2026-04-16/rust-src-1.95.0.tar.xz", "sha256:67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363", 3827368},
	"rust-channel-1.95.0":                             {"https://static.rust-lang.org/dist/2026-04-16/channel-rust-1.95.0.toml", "sha256:821ff14e4c4a1cbe1e8915f35aff0a3fbbdf8d293ad48ab8f31e3b0440c581f9", 848342},
	"eclipse-jdt-ls-1.60.0":                           {"https://download.eclipse.org/jdtls/milestones/1.60.0/jdt-language-server-1.60.0-202606262232.tar.gz", "sha256:e94c303d8198f977930803582738771fd18c52c5492878410bf222b1aa81ef1d", 50925681},
	"rust-analyzer-2026-08-17.4-aarch64-apple-darwin": {"https://github.com/rust-lang/rust-analyzer/releases/download/2026-08-17.4/rust-analyzer-aarch64-apple-darwin.gz", "sha256:ece932daf2f077be87bf745d2eb0a62cbc550f4b1e2e31ca76dfafdd0cc599b3", 13829387},
	"rust-glancer-0.1.1-darwin-arm64":                 {"https://github.com/rust-glancer/rust-glancer/releases/download/v0.1.1/rust-glancer-0.1.1-darwin-arm64.vsix", "sha256:dac95f6a2ad7cef36c552fd14eb5cf475a6eb3093f4589ecc65aaa841a0339a3", 9576452},
	"frozen-laboratory-template":                      {"https://raw.githubusercontent.com/michaellady/verified-java-websocket-port/156b459a1d0cc8d9bc4e624ddbd7a1c7bc9ded62/contracts/laboratory-template.json", "sha256:eb8afd7c9089456c08515b3b43182a57545ef50f40b1953944f85acdae308599", 1000},
	"toolchain-promotion-policy":                      {"https://raw.githubusercontent.com/michaellady/verified-java-websocket-port/156b459a1d0cc8d9bc4e624ddbd7a1c7bc9ded62/contracts/toolchain-promotion.json", "sha256:12a11bc4015ad5fd52e447053b8c3a7a3bc0b9e79389737ec7fc6bac0d465c54", 4947},
	"intake-bundle-schema-1.0.0":                      {"https://raw.githubusercontent.com/michaellady/verified-java-websocket-port/156b459a1d0cc8d9bc4e624ddbd7a1c7bc9ded62/schemas/intake-bundle-1.0.0.schema.json", "sha256:24093e9dc70c64690ac551282ba478d3ca9fe464e22f6ade9f120b5b26b68ff9", 4357},
}

func VerifyEvidenceDir(directory string, now time.Time) (*VerifyReport, error) {
	report := &VerifyReport{FileDigests: make(map[string]string)}
	contents := make(map[string][]byte)
	for _, name := range evidenceFiles {
		data, err := readEvidenceFile(directory, name)
		if err != nil {
			return nil, err
		}
		contents[name] = data
		report.FileDigests[name] = DigestBytes(data)
	}
	report.EvidenceRoot = digestFileMap(report.FileDigests)

	var sources sourceDocument
	if err := DecodeStrict(contents["source-pins.json"], &sources); err != nil {
		return nil, err
	}
	var toolchains toolchainDocument
	if err := DecodeStrict(contents["toolchain-pins.json"], &toolchains); err != nil {
		return nil, err
	}
	var sbom sbomDocument
	if err := DecodeStrict(contents["sbom.json"], &sbom); err != nil {
		return nil, err
	}
	var vulnerabilities vulnerabilityDocument
	if err := DecodeStrict(contents["vulnerability-snapshot.json"], &vulnerabilities); err != nil {
		return nil, err
	}
	var promotions promotionDocument
	if err := DecodeStrict(contents["promotion-receipts.json"], &promotions); err != nil {
		return nil, err
	}

	for _, scope := range []struct {
		name, company, project, laboratory, version string
	}{
		{"source-pins.json", sources.Company, sources.Project, sources.LaboratoryID, sources.SchemaVersion},
		{"toolchain-pins.json", toolchains.Company, toolchains.Project, toolchains.LaboratoryID, toolchains.SchemaVersion},
		{"sbom.json", sbom.Company, sbom.Project, sbom.LaboratoryID, sbom.SchemaVersion},
		{"vulnerability-snapshot.json", vulnerabilities.Company, vulnerabilities.Project, vulnerabilities.LaboratoryID, vulnerabilities.SchemaVersion},
		{"promotion-receipts.json", promotions.Company, promotions.Project, promotions.LaboratoryID, promotions.SchemaVersion},
	} {
		if scope.company != RequiredCompany || scope.project != RequiredProject || scope.laboratory != RequiredLaboratory {
			return nil, deny("CROSS_COMPANY_REFERENCE", scope.name, "evidence scope differs from the child laboratory")
		}
		if scope.version != "1.0.0" {
			return nil, deny("POLICY_VERSION_MISMATCH", scope.name, "evidence schema version is not frozen")
		}
	}

	if sources.PublicationRequested || sources.DefaultClassification != "QUARANTINED" {
		return nil, deny("UNCLASSIFIED_OBJECT", "source-pins.json", "intake bytes must remain explicitly quarantined")
	}
	if sources.Repository.Owner != "michaellady" || sources.Repository.Name != RequiredProject || sources.Repository.HTTPSURL != "https://github.com/michaellady/verified-java-websocket-port" {
		return nil, deny("OWNER_URL_MISMATCH", "source-pins.json.repository", "repository binding differs from the authorized owner and URL")
	}
	if len(sources.DeferredPlatformInputs) != 1 || sources.DeferredPlatformInputs[0].Platform != "x86_64-unknown-linux-gnu" || sources.DeferredPlatformInputs[0].Status != "NOT_YET_AN_INPUT" || sources.DeferredPlatformInputs[0].Reason == "" {
		return nil, deny("MISSING_PROMOTION_REQUIREMENT", "source-pins.json.deferred_platform_inputs", "the external Linux toolchain must remain explicitly unbound until child US-008")
	}
	if !now.Before(sources.Lifecycle.ExpiresAt) {
		report.Blockers = append(report.Blockers, Finding{Code: "PROMOTION_EVIDENCE_EXPIRED", Path: "source-pins.json.lifecycle.expires_at", Message: "input acquisition evidence is stale"})
	}
	seenArtifacts := make(map[string]struct{})
	for _, artifact := range sources.Artifacts {
		expected, exists := expectedArtifacts[artifact.ID]
		if !exists {
			return nil, deny("UNDECLARED_ARTIFACT", "source-pins.json.artifacts", "unexpected artifact "+artifact.ID)
		}
		if _, duplicate := seenArtifacts[artifact.ID]; duplicate {
			return nil, deny("DUPLICATE_ARCHIVE_ENTRY", "source-pins.json.artifacts", "duplicate artifact "+artifact.ID)
		}
		seenArtifacts[artifact.ID] = struct{}{}
		if artifact.ImmutableURL != expected.URL {
			return nil, deny("MUTABLE_SOURCE_REFERENCE", artifact.ID, "immutable URL differs from the frozen catalog")
		}
		if artifact.SHA256 != expected.Digest || artifact.ByteSize != expected.Size {
			return nil, deny("ARTIFACT_DRIFT", artifact.ID, "digest or byte size differs from the frozen catalog")
		}
		if artifact.License == "" || artifact.Provenance == "" || artifact.Replay == "" {
			return nil, deny("MISSING_PROMOTION_REQUIREMENT", artifact.ID, "license, provenance, and replay are mandatory")
		}
	}
	if len(seenArtifacts) != len(expectedArtifacts) {
		return nil, deny("MISSING_PROMOTION_REQUIREMENT", "source-pins.json.artifacts", "closed artifact catalog is incomplete")
	}

	if toolchains.Container.FloatingTagSatisfiesGate || toolchains.Container.Executed || toolchains.Container.CompressedLayerBytes != 388877802 {
		return nil, deny("CONTAINER_DESCRIPTOR_MISMATCH", "toolchain-pins.json.container", "container acquisition state differs from the exact static intake")
	}
	if err := ValidateAutobahnDescriptor(ContainerDescriptor{Reference: toolchains.Container.Reference, Platform: toolchains.Container.Platform, ManifestDigest: toolchains.Container.ManifestDigest, ConfigDigest: toolchains.Container.ConfigDigest}); err != nil {
		return nil, err
	}
	requiredForbiddenAccess := []string{"protected-held-out", "canonical-evidence", "release-signing", "production-credentials", "cross-company-data"}
	if toolchains.ExecutionState != "NO_DOWNLOADED_EXECUTABLE_OR_CONTAINER_WAS_EXECUTED_DURING_INTAKE" || toolchains.QualificationSandbox.RequiredRole != "port-implementer" || !slices.Equal(toolchains.QualificationSandbox.ForbiddenAccess, requiredForbiddenAccess) || !toolchains.QualificationSandbox.Disposable || toolchains.QualificationSandbox.Secrets != "none" || toolchains.QualificationSandbox.Publication {
		return nil, deny("FORBIDDEN_SANDBOX_ACCESS", "toolchain-pins.json.qualification_sandbox", "qualification sandbox contract is incomplete")
	}
	if err := ValidateRoleStage("qualification", toolchains.QualificationSandbox.RequiredRole, toolchains.QualificationSandbox.RequestedAccess, PublicationIntent{Requested: false, Classification: "QUARANTINED"}); err != nil {
		return nil, err
	}

	sbomIDs := make(map[string]struct{})
	for _, component := range sbom.Components {
		if component.Ref == "" || len(component.Hashes) == 0 || len(component.Licenses) == 0 {
			return nil, deny("MISSING_PROMOTION_REQUIREMENT", "sbom.json.components", "component identity, hashes, and licenses are required")
		}
		sbomIDs[component.Ref] = struct{}{}
	}
	vulnerabilityIDs := make(map[string]string)
	for _, observation := range vulnerabilities.Observations {
		if _, exists := vulnerabilityIDs[observation.ID]; exists {
			return nil, deny("DUPLICATE_ARCHIVE_ENTRY", "vulnerability-snapshot.json.observations", "duplicate vulnerability observation")
		}
		vulnerabilityIDs[observation.ID] = observation.ArtifactID
	}
	seenExecutables := make(map[string]struct{})
	for _, executable := range toolchains.Executables {
		if _, exists := seenArtifacts[executable.ArtifactID]; !exists {
			return nil, deny("DANGLING_GRAPH_EDGE", executable.ArtifactID, "executable references an absent source artifact")
		}
		if _, duplicate := seenExecutables[executable.ArtifactID]; duplicate {
			return nil, deny("DUPLICATE_ARCHIVE_ENTRY", "toolchain-pins.json.executables", "duplicate executable record")
		}
		seenExecutables[executable.ArtifactID] = struct{}{}
		if len(executable.BinaryDigests) == 0 || len(executable.LockGraph) == 0 || executable.License == "" || executable.Provenance == "" || executable.MirrorOrReplay == "" || executable.Rotation == "" || executable.Revocation == "" || executable.ExpiresAt.IsZero() {
			return nil, deny("MISSING_PROMOTION_REQUIREMENT", executable.ArtifactID, "executable promotion closure is incomplete")
		}
		for _, digest := range executable.BinaryDigests {
			if !validateDigest(digest) {
				return nil, deny("INVALID_DIGEST", executable.ArtifactID, "executable digest is malformed")
			}
		}
		if _, exists := sbomIDs[executable.SBOMComponentID]; !exists {
			return nil, deny("DANGLING_GRAPH_EDGE", executable.ArtifactID, "SBOM component is absent")
		}
		if artifactID, exists := vulnerabilityIDs[executable.VulnerabilityObservationID]; !exists || artifactID != executable.ArtifactID {
			return nil, deny("DANGLING_GRAPH_EDGE", executable.ArtifactID, "vulnerability observation is absent or points elsewhere")
		}
		if !now.Before(executable.ExpiresAt) {
			report.Blockers = append(report.Blockers, Finding{Code: "PROMOTION_EVIDENCE_EXPIRED", Path: executable.ArtifactID, Message: "executable qualification evidence is stale"})
		}
	}
	if len(seenExecutables) != 7 {
		return nil, deny("MISSING_PROMOTION_REQUIREMENT", "toolchain-pins.json.executables", "expected exactly seven executable input records")
	}

	if vulnerabilities.ContainerSnapshot.ImageDigest != AutobahnManifestDigest || vulnerabilities.ContainerSnapshot.SeverityCounts["critical"] != 12 || vulnerabilities.ContainerSnapshot.SeverityCounts["high"] != 147 || vulnerabilities.ContainerSnapshot.UniqueRules != 740 {
		return nil, deny("VULNERABILITY_SNAPSHOT_STALE", "vulnerability-snapshot.json.container_snapshot", "retained exact-image scan summary differs from the acquired snapshot")
	}
	if !now.Before(vulnerabilities.ExpiresAt) {
		report.Blockers = append(report.Blockers, Finding{Code: "VULNERABILITY_SNAPSHOT_STALE", Path: "vulnerability-snapshot.json.expires_at", Message: "vulnerability snapshot expired"})
	}
	if vulnerabilities.Decision != "OWNER_DISPOSITION_REQUIRED" || vulnerabilities.DecisionReason == "" {
		return nil, deny("VULNERABILITY_SNAPSHOT_STALE", "vulnerability-snapshot.json.decision", "single-owner intake must retain an explicit owner-disposition-required state")
	}
	report.Blockers = append(report.Blockers, Finding{Code: "OWNER_RISK_DISPOSITION_REQUIRED", Path: "vulnerability-snapshot.json.decision", Message: vulnerabilities.DecisionReason})

	if promotions.AuthorityMode != SingleOwnerAuthorityMode || promotions.PolicyVersion != BasePolicyVersion || promotions.PolicyDigest != BasePolicyDigest || promotions.PolicyAmendmentVersion != SingleOwnerAmendmentVersion || promotions.PolicyAmendmentDigest != SingleOwnerAmendmentDigest {
		return nil, deny("POLICY_VERSION_MISMATCH", "promotion-receipts.json", "promotion receipt must bind the frozen base policy and authoritative single-owner amendment")
	}
	if promotions.AssuranceCeiling != "OWNER_ATTESTED_NOT_INDEPENDENT" || promotions.ApprovalPolicy.AuthorityModel != SingleOwnerAuthorityMode || promotions.ApprovalPolicy.OwnerActorID != RequiredOwnerActor || promotions.ApprovalPolicy.OwnerActionPrincipalsRequired != 1 || promotions.ApprovalPolicy.IndependentApprovalsRequired != 0 || promotions.ApprovalPolicy.IndependentReviewClaimed || promotions.ApprovalPolicy.AssuranceCeiling != promotions.AssuranceCeiling || promotions.ApprovalPolicy.NonceLedger == "" || promotions.ApprovalPolicy.RoleAndRevocationSnapshots == "" {
		return nil, deny("POLICY_VERSION_MISMATCH", "promotion-receipts.json.approval_policy", "receipt obscures or widens the single-owner assurance ceiling")
	}
	if promotions.PublicationRequested || promotions.PublicationCount != 0 || promotions.ProtectedAccessCount != 0 {
		return nil, deny("ROLE_ACTION_MISMATCH", "promotion-receipts.json", "US-001 permits neither publication nor protected access")
	}
	if err := validateRequiredActionTrace(promotions.Status, promotions.RequiredActions); err != nil {
		return nil, err
	}
	if err := verifyCandidatePayload(promotions.CandidatePayload, report.FileDigests); err != nil {
		return nil, err
	}
	if promotions.Status == SingleOwnerPromotedStatus && promotions.AcceptedObjectCount == len(expectedArtifacts) && validateDigest(promotions.PromotionStoreRoot) && len(promotions.SignedActions) == 4 {
		report.Blockers = append(report.Blockers, Finding{Code: "PROTECTED_CALLER_REQUIRED", Path: "promotion-receipts.json.signed_actions", Message: "candidate evidence cannot verify its own authoritative identities, snapshots, or nonce ledger"})
	} else if promotions.Status == SingleOwnerAuthorizedStatus && promotions.AcceptedObjectCount == 0 && promotions.PromotionStoreRoot == "" && len(promotions.SignedActions) == 4 {
		report.Blockers = append(report.Blockers, Finding{Code: "PROTECTED_CALLER_REQUIRED", Path: "promotion-receipts.json.signed_actions", Message: "candidate evidence cannot verify its own authoritative identities, snapshots, or nonce ledger"})
	} else if promotions.Status == SingleOwnerBlockedStatus && promotions.AcceptedObjectCount == 0 && len(promotions.SignedActions) == 0 {
		report.Blockers = append(report.Blockers, Finding{Code: "MISSING_PROMOTION_REQUIREMENT", Path: "promotion-receipts.json.signed_actions", Message: "the repository owner's real cryptographic stage actions and protected authority are absent"})
	} else {
		return nil, deny("ACTION_SCOPE_MISMATCH", "promotion-receipts.json.status", "receipt status, action count, and accepted-object count are inconsistent")
	}
	return report, nil
}

// readEvidenceFile rejects links and identity changes before candidate evidence
// is read. Promotion callers must never be able to turn a checked-in evidence
// member into an implicit read of protected authority, nonce, or materialized
// input state.
func readEvidenceFile(directory, name string) ([]byte, error) {
	path := filepath.Join(directory, name)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, deny("MISSING_PROMOTION_REQUIREMENT", name, "evidence file cannot be inspected")
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maxJSONBytes || evidenceLinkCount(before) != 1 {
		return nil, deny("UNSAFE_ARCHIVE_ENTRY", name, "evidence member must be one bounded regular file with no links")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, deny("MISSING_PROMOTION_REQUIREMENT", name, "evidence file cannot be opened")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Size() != before.Size() || evidenceLinkCount(opened) != 1 {
		return nil, deny("UNSAFE_ARCHIVE_ENTRY", name, "evidence member changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxJSONBytes+1))
	if err != nil || len(data) > maxJSONBytes {
		return nil, deny("INPUT_TOO_LARGE", name, "evidence member cannot be read within its bound")
	}
	openedAfter, openErr := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if openErr != nil || pathErr != nil || !os.SameFile(opened, openedAfter) || !os.SameFile(opened, pathAfter) || !pathAfter.Mode().IsRegular() || pathAfter.Mode()&os.ModeSymlink != 0 || pathAfter.Size() != int64(len(data)) || evidenceLinkCount(pathAfter) != 1 {
		return nil, deny("ARTIFACT_DRIFT", name, "evidence member changed while reading")
	}
	return data, nil
}

func evidenceLinkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 0
}

func validateRequiredActionTrace(receiptStatus string, actions []requiredAction) error {
	if len(actions) != len(requiredActionPolicy) {
		return deny("ACTION_SCOPE_MISMATCH", "promotion-receipts.json.required_actions", "required-action trace must contain exactly four policy-ordered stages")
	}
	for index, required := range requiredActionPolicy {
		expectedStatus := ""
		switch receiptStatus {
		case SingleOwnerBlockedStatus:
			expectedStatus = "OWNER_SIGNATURE_REQUIRED"
			if index == len(requiredActionPolicy)-1 {
				expectedStatus = "OWNER_SIGNATURE_AND_SCOPED_RISK_DISPOSITION_REQUIRED"
			}
		case SingleOwnerAuthorizedStatus:
			expectedStatus = "OWNER_SIGNED_PENDING_PROTECTED_VERIFICATION"
		case SingleOwnerPromotedStatus:
			expectedStatus = "OWNER_SIGNED_AND_PROTECTED_VERIFIED"
		default:
			return deny("ACTION_SCOPE_MISMATCH", "promotion-receipts.json.status", "receipt status has no valid required-action trace")
		}
		actual := actions[index]
		if actual.Stage != required.Stage || actual.Role != required.Role || !slices.Equal(actual.RequestedSandboxAccess, required.RequestedSandboxAccess) || actual.PublicationRequested != required.PublicationRequested || actual.Status != expectedStatus {
			return deny("ACTION_SCOPE_MISMATCH", fmt.Sprintf("promotion-receipts.json.required_actions[%d]", index), "required-action stage, role, sandbox, publication, or status differs from policy")
		}
	}
	return nil
}

// VerifyAuthorizedEvidenceDir is the only path that can clear the protected
// caller gate. It verifies the public evidence first, then checks each signed
// stage against authority data supplied out of band.
func VerifyAuthorizedEvidenceDir(directory string, now time.Time, authority TrustedAuthority) (*VerifyReport, error) {
	report, err := VerifyEvidenceDir(directory, now)
	if err != nil {
		return nil, err
	}
	for _, blocker := range report.Blockers {
		if blocker.Code != "OWNER_RISK_DISPOSITION_REQUIRED" && blocker.Code != "PROTECTED_CALLER_REQUIRED" {
			return report, &blocker
		}
	}
	if authority.AuthorityMode != SingleOwnerAuthorityMode || authority.OwnerActorID != RequiredOwnerActor {
		return nil, deny("AUTHORITY_MODE_MISMATCH", "protected-authority", "protected caller did not supply the policy-bound single-owner authority")
	}
	data, err := readEvidenceFile(directory, "promotion-receipts.json")
	if err != nil {
		return nil, deny("MISSING_PROMOTION_REQUIREMENT", "promotion-receipts.json", err.Error())
	}
	var promotions promotionDocument
	if err := DecodeStrict(data, &promotions); err != nil {
		return nil, err
	}
	expected := []struct {
		stage, action, role string
		sandbox             []string
	}{
		{"acquisition", "acquire", "method-schema-steward", nil},
		{"quarantine", "quarantine", "port-implementer", nil},
		{"qualification", "qualify", "port-implementer", []string{"quarantined-source"}},
		{PromotionStageID, "promote", "release-attestor", nil},
	}
	if len(promotions.SignedActions) != len(expected) {
		return nil, deny("MISSING_PROMOTION_REQUIREMENT", "promotion-receipts.json.signed_actions", "exactly four signed stage actions are required")
	}
	claims := make([]NonceClaim, 0, len(expected))
	for index, required := range expected {
		action := promotions.SignedActions[index]
		if action.ObjectID != "java-websocket-us001-inputs-v1" || action.ObjectKind != "artifact-set" || action.Stage != required.stage || action.Action != required.action || action.ActorID != RequiredOwnerActor || action.Role != required.role || action.AuthorityMode != promotions.AuthorityMode || action.ArtifactDigest != promotions.CandidatePayload.RootDigest || action.PolicyVersion != promotions.PolicyVersion || action.PolicyDigest != promotions.PolicyDigest || action.PolicyAmendmentVersion != promotions.PolicyAmendmentVersion || action.PolicyAmendmentDigest != promotions.PolicyAmendmentDigest || !slices.Equal(action.RequestedSandboxAccess, required.sandbox) || action.Publication.Requested || action.Publication.Classification != "QUARANTINED" {
			return nil, deny("ACTION_SCOPE_MISMATCH", fmt.Sprintf("promotion-receipts.json.signed_actions[%d]", index), "signed action does not bind the exact owner, stage, object, roots, policies, sandbox, and non-publication intent")
		}
		if action.Stage == PromotionStageID && (action.RiskDisposition == nil || action.RiskDisposition.VulnerabilitySnapshotDigest != report.FileDigests["vulnerability-snapshot.json"]) {
			return nil, deny("RISK_DISPOSITION_MISMATCH", fmt.Sprintf("promotion-receipts.json.signed_actions[%d].risk_disposition", index), "promotion action does not bind the retained vulnerability snapshot bytes")
		}
		snapshot, exists := authority.Snapshots[action.ActorID]
		if !exists {
			return nil, deny("REVOKED_AUTHORIZATION", fmt.Sprintf("promotion-receipts.json.signed_actions[%d]", index), "authoritative snapshot is absent")
		}
		if err := validateAuthorization(action, authority.Identities, snapshot, now); err != nil {
			return nil, err
		}
		claims = append(claims, NonceClaim{ActorID: action.ActorID, Nonce: action.Nonce})
	}
	ledger, ok := authority.Ledger.(BatchNonceLedger)
	if !ok || !ledger.ConsumeBatch(claims) {
		return nil, deny("REPLAYED_APPROVAL", "promotion-receipts.json.signed_actions", "one or more owner action nonces were already consumed or the protected ledger could not consume the complete batch")
	}
	report.Blockers = nil
	return report, nil
}

func verifyCandidatePayload(payload candidatePayload, fileDigests map[string]string) error {
	if len(payload.Files) != 4 {
		return deny("MISSING_PROMOTION_REQUIREMENT", "promotion-receipts.json.candidate_payload", "candidate payload must bind exactly four pre-receipt evidence files")
	}
	records := make([]string, 0, len(payload.Files))
	for _, file := range payload.Files {
		actual, exists := fileDigests[file.Path]
		if !exists || file.Path == "promotion-receipts.json" || actual != file.SHA256 {
			return deny("DIGEST_MISMATCH", file.Path, "candidate payload file digest differs from retained evidence")
		}
		records = append(records, file.Path+"="+file.SHA256)
	}
	expectedOrder := []string{"source-pins.json", "toolchain-pins.json", "sbom.json", "vulnerability-snapshot.json"}
	for index, path := range expectedOrder {
		if payload.Files[index].Path != path {
			return deny("ACTION_SCOPE_MISMATCH", "promotion-receipts.json.candidate_payload", "candidate payload order differs from the frozen root algorithm")
		}
	}
	root := DigestBytes([]byte(strings.Join(records, "\n") + "\n"))
	if root != payload.RootDigest {
		return deny("DIGEST_MISMATCH", "promotion-receipts.json.candidate_payload.root_digest", "candidate payload root differs")
	}
	return nil
}

func digestFileMap(digests map[string]string) string {
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	sort.Strings(names)
	var buffer bytes.Buffer
	for _, name := range names {
		fmt.Fprintf(&buffer, "%s=%s\n", name, digests[name])
	}
	return DigestBytes(buffer.Bytes())
}
