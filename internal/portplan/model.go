package portplan

// Document file names for the six US-003 intake artifacts, relative to evidence/intake.
const (
	ManifestDocument         = "java-intake-manifest.json"
	SurfaceInventoryDocument = "surface-inventory.json"
	MigrationMapDocument     = "semantic-id-migration-map.json"
	SeamDossierDocument      = "port-seam-dossier.json"
	CompatibilityDocument    = "compatibility-surface.json"
	CutoverDocument          = "cutover-contract.json"
)

// DocumentNames is the full set of documents this story freezes.
var DocumentNames = []string{
	ManifestDocument,
	SurfaceInventoryDocument,
	MigrationMapDocument,
	SeamDossierDocument,
	CompatibilityDocument,
	CutoverDocument,
}

// EvidenceDirectory is the repository-relative home of the intake documents.
const EvidenceDirectory = "evidence/intake"

// Finding codes. Each maps to an acceptance criterion or to the story's honesty constraints.
const (
	FindingTotalsNotReconciled       = "TOTALS_NOT_RECONCILED"
	FindingSurfaceSectionUnsupported = "SURFACE_SECTION_UNSUPPORTED"
	FindingExclusionNotNamed         = "EXCLUSION_NOT_NAMED"
	FindingPartitionIncomplete       = "SURFACE_PARTITION_INCOMPLETE"
	FindingIncompleteMigrationRow    = "INCOMPLETE_MIGRATION_MAP"
	FindingWeakLookupStrength        = "WEAK_LOOKUP_STRENGTH"
	FindingUnverifiableRustIdentity  = "UNVERIFIABLE_RUST_IDENTITY"
	FindingUnresolvedTouchedSurface  = "UNRESOLVED_TOUCHED_SURFACE"
	FindingSeamCategoryMissing       = "SEAM_CATEGORY_MISSING"
	FindingWireBoundaryNotPreserved  = "WIRE_BOUNDARY_NOT_PRESERVED"
	FindingRequiredExclusionMissing  = "REQUIRED_EXCLUSION_MISSING"
	FindingUnresolvedBehavior        = "UNRESOLVED_BEHAVIOR"
	FindingUnknownChildStory         = "UNKNOWN_CHILD_STORY"
	FindingAssurancePosture          = "ASSURANCE_POSTURE_UPGRADED"
	FindingDocumentUnreadable        = "DOCUMENT_UNREADABLE"
	FindingSchemaViolation           = "SCHEMA_VIOLATION"
	FindingStoryCoverageGap          = "STORY_COVERAGE_GAP"
	FindingOracleBindingBroken       = "ORACLE_BINDING_BROKEN"
	FindingPromotedInputUnbound      = "PROMOTED_INPUT_UNBOUND"
)

// OracleEvidenceDocument is the committed compiler-derived identity report the six documents are
// built from. Verify binds the manifest's recorded digest to these exact bytes.
const OracleEvidenceDocument = "semantic-id-oracle.json"

// SLF4JAPIJarSHA256 is the identity of the only non-JDK compile input the oracle run may use.
// It is the exact digest already qualified by US-002 (internal/lab/autobahn_endpoint.go,
// AutobahnSLF4JAPIDigest); the oracle Makefile fails closed when the jar's bytes differ.
const SLF4JAPIJarSHA256 = "sha256:e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9"

// RequiredExclusions are the AC5 surfaces that must stay explicitly out of scope.
var RequiredExclusions = []string{
	"EXCLUDED_TLS_WSS",
	"EXCLUDED_PROXY_SUPPORT",
	"EXCLUDED_RECONNECT",
	"EXCLUDED_ANDROID",
	"EXCLUDED_RFC_7692_PERMESSAGE_DEFLATE",
	"EXCLUDED_JAVA_API_PARITY",
	"EXCLUDED_JAVA_NIO_TOPOLOGY",
	"EXCLUDED_EXTENSION_SUBPROTOCOL_PARITY",
}

// RequiredSeamCategories are the AC4 boundary categories the dossier must inventory.
var RequiredSeamCategories = []string{
	"public_boundaries",
	"internal_boundaries",
	"handshakes",
	"frames",
	"ownership",
	"buffers",
	"queues",
	"threads",
	"callbacks",
	"wire_formats",
	"limits",
	"time_and_randomness",
	"adapter_seams",
}

// ReadinessLadder is the fixed cutover ladder inherited from the parent contract.
var ReadinessLadder = []string{
	"SOURCE_QUALIFIED",
	"SEMANTICALLY_VERIFIED",
	"OPERATIONALLY_VERIFIED",
	"SHADOW_VERIFIED",
	"CANARY_VERIFIED",
	"CUTOVER_READY",
}

// Assurance is the fixed posture every US-003 document carries.
type Assurance struct {
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	Production               bool   `json:"production"`
	Signing                  bool   `json:"signing"`
	Publication              bool   `json:"publication"`
}

// OwnerAttested is the only posture this story may assert.
const OwnerAttested = "OWNER_ATTESTED_NOT_INDEPENDENT"

// FileRecord is one derived source file with its compiler-run digest and physical line count.
type FileRecord struct {
	Path             string `json:"path"`
	Package          string `json:"package"`
	PhysicalLines    int    `json:"physical_lines"`
	SHA256           string `json:"sha256"`
	DeclarationCount int    `json:"declaration_count"`
	ReasonCode       string `json:"reason_code,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

// SurfaceInventory is the AC2 partition of the production tree.
type SurfaceInventory struct {
	SchemaRef     string        `json:"$schema"`
	SchemaVersion string        `json:"schema_version"`
	EntityType    string        `json:"entity_type"`
	InventoryID   string        `json:"inventory_id"`
	Source        SourcePin     `json:"source"`
	SelectionRule SelectionRule `json:"selection_rule"`
	Selected      []FileRecord  `json:"selected"`
	Excluded      []FileRecord  `json:"excluded"`
	TestFiles     []FileRecord  `json:"test_files"`
	Assurance     Assurance     `json:"assurance"`
}

// SelectionRule records the AC2 rule literally so a reviewer can re-derive the partition.
type SelectionRule struct {
	RootFiles []string `json:"root_files"`
	Packages  []string `json:"packages"`
	Recursive bool     `json:"recursive"`
	Statement string   `json:"statement"`
}

// SourcePin binds a document to the digest-pinned upstream release.
type SourcePin struct {
	ArtifactID     string `json:"artifact_id"`
	SHA256         string `json:"sha256"`
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	ProductionRoot string `json:"production_source_root"`
	TestRoot       string `json:"test_source_root"`
}

// TreeCount is a declared file/line total.
type TreeCount struct {
	Files         int `json:"files"`
	PhysicalLines int `json:"physical_lines"`
}

// IntakeManifest is the AC1 JavaIntakeManifest.
type IntakeManifest struct {
	SchemaRef      string           `json:"$schema"`
	SchemaVersion  string           `json:"schema_version"`
	EntityType     string           `json:"entity_type"`
	ManifestID     string           `json:"manifest_id"`
	Source         SourcePin        `json:"source"`
	JDK            JDKRecord        `json:"jdk"`
	Build          BuildRecord      `json:"build"`
	Reconciliation Reconciliation   `json:"reconciliation"`
	PromotedInputs []PromotedInput  `json:"promoted_inputs"`
	Sections       []SurfaceSection `json:"surface_sections"`
	Assurance      Assurance        `json:"assurance"`
	HonestyNotes   []string         `json:"honesty_notes"`
}

// PromotedInput is a versioned non-source input whose identity is enforced, not assumed.
type PromotedInput struct {
	ArtifactID             string `json:"artifact_id"`
	Kind                   string `json:"kind"`
	SHA256                 string `json:"sha256"`
	ImmutableURL           string `json:"immutable_url"`
	QualifiedBy            string `json:"qualified_by"`
	QualificationReference string `json:"qualification_reference"`
	EnforcedBy             string `json:"enforced_by"`
	Role                   string `json:"role"`
}

// JDKRecord is the compiler that produced every semantic identity in this story.
type JDKRecord struct {
	Vendor          string `json:"vendor"`
	Version         string `json:"version"`
	PinnedArtifact  string `json:"pinned_artifact_id"`
	PinnedSHA256    string `json:"pinned_sha256"`
	IdentitySource  string `json:"identity_source"`
	OracleOutputSHA string `json:"oracle_output_sha256"`
	OracleToolSHA   string `json:"oracle_tool_sha256"`
}

// BuildRecord references the authoritative Java build accepted by US-002 rather than re-running
// the quarantined build inside this story.
type BuildRecord struct {
	System              string `json:"system"`
	Version             string `json:"version"`
	Executed            bool   `json:"executed_in_this_story"`
	InheritedEvidence   string `json:"inherited_evidence_path"`
	InheritedRootDigest string `json:"inherited_accepted_root_digest"`
	Rationale           string `json:"rationale"`
}

// Reconciliation carries the derived totals AC1 must reconcile.
type Reconciliation struct {
	ProductionTree    TreeCount         `json:"production_tree"`
	TestTree          TreeCount         `json:"test_tree"`
	StudySurface      TreeCount         `json:"study_surface"`
	DeclarationTotals DeclarationTotals `json:"declaration_totals"`
	Method            string            `json:"method"`
	CountingSemantics string            `json:"counting_semantics"`
}

// DeclarationTotals are compiler-derived declaration counts.
type DeclarationTotals struct {
	ProductionDeclarations int `json:"production_declarations"`
	StudyDeclarations      int `json:"study_surface_declarations"`
	StudyTypes             int `json:"study_surface_types"`
	AnalyzedTopLevelTypes  int `json:"analyzed_top_level_types"`
	CompilerErrorCount     int `json:"compiler_error_count"`
	PackageInfoFiles       int `json:"package_info_files_without_declarations"`
}

// SurfaceSection is one AC1 surface area with an honest observation status.
type SurfaceSection struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	ObservationStatus string   `json:"observation_status"`
	EvidenceRef       string   `json:"evidence_ref"`
	BlockerCode       string   `json:"blocker_code"`
	Items             []string `json:"items"`
}

// MigrationMap is the AC3 versioned semantic identity map.
type MigrationMap struct {
	SchemaRef          string             `json:"$schema"`
	SchemaVersion      string             `json:"schema_version"`
	EntityType         string             `json:"entity_type"`
	MapID              string             `json:"map_id"`
	MapVersion         string             `json:"map_version"`
	JavaIdentityMethod JavaIdentityMethod `json:"java_identity_method"`
	RustIdentityStatus RustIdentityStatus `json:"rust_identity_status"`
	Rows               []MigrationRow     `json:"rows"`
	Assurance          Assurance          `json:"assurance"`
}

// JavaIdentityMethod records exactly how each Java identity was obtained.
type JavaIdentityMethod struct {
	Tool           string `json:"tool"`
	API            string `json:"api"`
	CompilerVendor string `json:"compiler_vendor"`
	CompilerFlags  string `json:"compiler_flags"`
	Strength       string `json:"strength"`
	Statement      string `json:"statement"`
}

// RustIdentityStatus records that no Rust workspace exists yet, so no Rust identity in this
// document is resolver-verified.
type RustIdentityStatus struct {
	WorkspacePresent  bool                           `json:"rust_workspace_present"`
	PlannedResolver   string                         `json:"planned_resolver"`
	BlockerCode       string                         `json:"blocker_code"`
	CreatedByStory    string                         `json:"created_by_story"`
	Statement         string                         `json:"statement"`
	ResolutionReceipt *RustIdentityResolutionReceipt `json:"resolution_receipt,omitempty"`
}

type RustIdentityResolutionReceipt struct {
	StoryID              string                   `json:"story_id"`
	ResolverArtifactID   string                   `json:"resolver_artifact_id"`
	ResolverVersion      string                   `json:"resolver_version"`
	ResolverBinarySHA256 string                   `json:"resolver_binary_sha256"`
	Mode                 string                   `json:"mode"`
	Command              []string                 `json:"command"`
	Network              string                   `json:"network"`
	IndexSHA256          string                   `json:"index_sha256"`
	Resolutions          []RustIdentityResolution `json:"resolutions"`
	UnresolvedScope      string                   `json:"unresolved_scope"`
}

type RustIdentityResolution struct {
	JavaSemanticID string `json:"java_semantic_id"`
	RustSemanticID string `json:"rust_semantic_id"`
	SCIPSymbol     string `json:"scip_symbol"`
}

// SliceBinding binds one behavioral facet of a Java type to the port slice (and child story)
// that implements it. Slice-crossing types carry one binding per touched slice, each naming the
// concrete behavior that slice owns (review B1).
type SliceBinding struct {
	PortSliceID     string   `json:"port_slice_id"`
	ChildStoryID    string   `json:"child_story_id"`
	TouchedBehavior string   `json:"touched_behavior"`
	EvidenceIDs     []string `json:"evidence_ids"`
}

// MigrationRow binds one compiler-derived Java semantic identity to a planned Rust identity.
type MigrationRow struct {
	ID                      string         `json:"id"`
	JavaSemanticID          string         `json:"java_semantic_id"`
	JavaBinaryName          string         `json:"java_binary_name"`
	JavaDescriptor          string         `json:"java_descriptor"`
	JavaSignature           string         `json:"java_signature"`
	JavaKind                string         `json:"java_kind"`
	JavaLookupStrength      string         `json:"java_lookup_strength"`
	JavaMemberCount         int            `json:"java_member_count"`
	RustSemanticID          string         `json:"rust_semantic_id"`
	RustResolver            string         `json:"rust_resolver"`
	RustIdentityVerified    bool           `json:"rust_identity_verified"`
	ApplicabilityConditions []string       `json:"applicability_conditions"`
	KnownNonEquivalentCases []string       `json:"known_non_equivalent_cases"`
	SourceRevision          string         `json:"source_revision"`
	DetectionQuery          string         `json:"detection_query"`
	PortSlices              []SliceBinding `json:"port_slices"`
	TouchedFiles            []string       `json:"touched_files"`
	SpecificationIDs        []string       `json:"specification_ids"`
	ObservedBehaviorIDs     []string       `json:"observed_behavior_ids"`
	OracleIDs               []string       `json:"oracle_ids"`
	VectorIDs               []string       `json:"vector_ids"`
	PropertyClaimIDs        []string       `json:"property_claim_ids"`
	FormalClaimIDs          []string       `json:"formal_claim_ids"`
	EvidenceIDs             []string       `json:"evidence_ids"`
	Status                  string         `json:"status"`
}

// SeamDossier is the AC4 port seam inventory.
type SeamDossier struct {
	SchemaRef             string                 `json:"$schema"`
	SchemaVersion         string                 `json:"schema_version"`
	EntityType            string                 `json:"entity_type"`
	DossierID             string                 `json:"dossier_id"`
	PublicBoundaries      []string               `json:"public_boundaries"`
	InternalBoundaries    []string               `json:"internal_boundaries"`
	Handshakes            []string               `json:"handshakes"`
	Frames                []string               `json:"frames"`
	Ownership             []string               `json:"ownership"`
	Buffers               []string               `json:"buffers"`
	Queues                []string               `json:"queues"`
	Threads               []string               `json:"threads"`
	Callbacks             []string               `json:"callbacks"`
	WireFormats           []string               `json:"wire_formats"`
	Limits                []string               `json:"limits"`
	TimeAndRandomness     []string               `json:"time_and_randomness"`
	AdapterSeams          []string               `json:"adapter_seams"`
	Seams                 []Seam                 `json:"seams"`
	ImplementationStories []ImplementationStory  `json:"implementation_stories"`
	Assurance             Assurance              `json:"assurance"`
	Raw                   map[string]interface{} `json:"-"`
}

// Seam is one resolved port boundary.
type Seam struct {
	SurfaceID             string   `json:"surface_id"`
	SemanticID            string   `json:"semantic_id"`
	Owner                 string   `json:"owner"`
	Category              string   `json:"category"`
	ChildStoryID          string   `json:"child_story_id"`
	TouchedFiles          []string `json:"touched_files"`
	EvidenceObligationIDs []string `json:"evidence_obligation_ids"`
	Status                string   `json:"status"`
}

// ImplementationStory is a child story that must have no unresolved touched surface.
type ImplementationStory struct {
	StoryID string   `json:"story_id"`
	Title   string   `json:"title"`
	SeamIDs []string `json:"seam_ids"`
	Status  string   `json:"status"`
}

// CompatibilitySurface is the AC5 preserved-behavior surface.
type CompatibilitySurface struct {
	SchemaRef         string              `json:"$schema"`
	SchemaVersion     string              `json:"schema_version"`
	EntityType        string              `json:"entity_type"`
	SurfaceID         string              `json:"compatibility_surface_id"`
	PreservedBoundary PreservedBoundary   `json:"preserved_boundary"`
	Items             []CompatibilityItem `json:"items"`
	ExcludedSurfaces  []ExclusionRecord   `json:"excluded_surfaces"`
	Assurance         Assurance           `json:"assurance"`
}

// PreservedBoundary is the RFC 6455 wire boundary that must survive the port.
type PreservedBoundary struct {
	Standard                       string `json:"standard"`
	NormativeArtifactID            string `json:"normative_artifact_id"`
	NormativeArtifactSHA256        string `json:"normative_artifact_sha256"`
	NormalizedCommandEventBehavior bool   `json:"normalized_command_event_behavior"`
	WireOctetEquivalenceRequired   bool   `json:"wire_octet_equivalence_required"`
	Statement                      string `json:"statement"`
}

// CompatibilityItem is one preserved surface with its edge cases and obligations.
type CompatibilityItem struct {
	SurfaceID             string   `json:"surface_id"`
	Kind                  string   `json:"kind"`
	EdgeCases             []string `json:"edge_cases"`
	OracleID              string   `json:"oracle_id"`
	EvidenceObligationIDs []string `json:"evidence_obligation_ids"`
	CutoverObligationID   string   `json:"cutover_obligation_id"`
	ObservationStatus     string   `json:"observation_status"`
	BlockerCode           string   `json:"blocker_code"`
}

// ExclusionRecord names an out-of-scope surface.
type ExclusionRecord struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// CutoverContract is the AC5 cutover boundary.
type CutoverContract struct {
	SchemaRef           string              `json:"$schema"`
	SchemaVersion       string              `json:"schema_version"`
	EntityType          string              `json:"entity_type"`
	ContractID          string              `json:"contract_id"`
	ReplacementBoundary string              `json:"replacement_boundary"`
	PreservedBoundary   PreservedBoundary   `json:"preserved_boundary"`
	ExcludedBehaviors   []ExclusionRecord   `json:"excluded_behaviors"`
	UnresolvedBehaviors []string            `json:"unresolved_behaviors"`
	ReadinessLadder     []string            `json:"readiness_ladder"`
	Obligations         []CutoverObligation `json:"obligations"`
	Assurance           Assurance           `json:"assurance"`
}

// CutoverObligation is a declared, not-yet-satisfied cutover obligation.
type CutoverObligation struct {
	ID           string   `json:"id"`
	SurfaceID    string   `json:"surface_id"`
	ChildStoryID string   `json:"child_story_id"`
	Status       string   `json:"status"`
	EvidenceIDs  []string `json:"evidence_ids"`
}

// CoverageRequirement names one binding (or dossier touched file) an implementation story's
// behavioral surface requires. The validator fails closed when the migration map or the seam
// dossier no longer provides it (review B2).
type CoverageRequirement struct {
	ChildStoryID   string
	JavaBinaryName string // required (binary name, slice) binding when non-empty
	PortSliceID    string
	TouchedFile    string // required dossier seam touched file when non-empty
	Reason         string
}

// RequiredStoryCoverage is the frozen behavioral-surface definition per implementation story.
var RequiredStoryCoverage = []CoverageRequirement{
	{"US-009", "org.java_websocket.WebSocketImpl", "slice.connection-core", "", "connection state machine owner"},
	{"US-009", "org.java_websocket.drafts.Draft", "slice.connection-core", "", "protocol strategy seam"},
	{"US-009", "org.java_websocket.WebSocketListener", "slice.connection-core", "", "callback boundary"},
	{"US-010", "org.java_websocket.drafts.Draft_6455", "slice.client-handshake", "", "client handshake construction and acceptance"},
	{"US-010", "org.java_websocket.WebSocketImpl", "slice.client-handshake", "", "client handshake decode path"},
	{"US-011", "org.java_websocket.drafts.Draft_6455", "slice.server-handshake", "", "server handshake acceptance and response"},
	{"US-012", "org.java_websocket.drafts.Draft_6455", "slice.framing", "", "canonical frame encode/decode"},
	{"US-012", "org.java_websocket.WebSocketImpl", "slice.framing", "", "decodeFrames loop"},
	{"US-013", "org.java_websocket.drafts.Draft_6455", "slice.messages", "", "text/binary frame processing"},
	{"US-013", "org.java_websocket.util.Charsetfunctions", "slice.messages", "", "strict UTF-8 validation"},
	{"US-014", "org.java_websocket.drafts.Draft_6455", "slice.fragmentation", "", "continuation reassembly state and checks"},
	{"US-014", "org.java_websocket.exceptions.LimitExceededException", "slice.fragmentation", "", "reassembly size limit"},
	{"US-015", "org.java_websocket.drafts.Draft_6455", "slice.ping-pong", "", "ping/pong dispatch and automatic pong"},
	{"US-015", "org.java_websocket.WebSocketAdapter", "slice.ping-pong", "", "default automatic-pong callback"},
	{"US-015", "org.java_websocket.WebSocketListener", "slice.ping-pong", "", "ping/pong callback dispatch"},
	{"US-016", "org.java_websocket.drafts.Draft_6455", "slice.close-eof", "", "close frame processing"},
	{"US-016", "org.java_websocket.WebSocketImpl", "slice.close-eof", "", "terminal-state handling"},
	{"US-017", "org.java_websocket.WebSocketImpl", "slice.concurrency", "", "synchronized regions and queues"},
	{"US-018", "org.java_websocket.WebSocketImpl", "slice.tcp-adapter", "", "outgoing-queue drain contract"},
	{"US-018", "org.java_websocket.interfaces.ISSLChannel", "slice.tcp-adapter", "", "capability-excluded TLS accessor context"},
	{"US-018", "", "", "org/java_websocket/WrappedByteChannel.java", "byte-channel adapter surface"},
	{"US-018", "", "", "org/java_websocket/AbstractWrappedByteChannel.java", "byte-channel adapter surface"},
	// Round-2 review additions, each verified against the named Java declarations.
	{"US-014", "org.java_websocket.drafts.Draft", "slice.fragmentation", "", "continuousFrame and continuousFrameType (Draft.java:68,210)"},
	{"US-013", "org.java_websocket.drafts.Draft", "slice.messages", "", "processFrame text/binary dispatch strategy (Draft.java:207)"},
	{"US-015", "org.java_websocket.drafts.Draft", "slice.ping-pong", "", "processFrame control dispatch strategy (Draft.java:207)"},
	{"US-016", "org.java_websocket.drafts.Draft", "slice.close-eof", "", "processFrame close dispatch and getCloseHandshakeType (Draft.java:207,306)"},
	{"US-018", "org.java_websocket.WebSocketListener", "slice.tcp-adapter", "", "onWriteDemand and the transport-facing address accessors (WebSocketListener.java:184,191,199)"},
	{"US-014", "org.java_websocket.WebSocket", "slice.fragmentation", "", "sendFragmentedFrame command surface (WebSocket.java:130)"},
	{"US-010", "org.java_websocket.WebSocketAdapter", "slice.client-handshake", "", "default client handshake callbacks (WebSocketAdapter.java:59,72)"},
	{"US-011", "org.java_websocket.WebSocketAdapter", "slice.server-handshake", "", "default server handshake callback (WebSocketAdapter.java:53)"},
	{"US-010", "org.java_websocket.exceptions.InvalidDataException", "slice.client-handshake", "", "declared handshake rejection type (WebSocketListener.java:73,81)"},
	{"US-011", "org.java_websocket.exceptions.InvalidDataException", "slice.server-handshake", "", "declared handshake rejection type (WebSocketListener.java:60)"},
}

// Finding is one validation failure.
type Finding struct {
	Code     string `json:"code"`
	Document string `json:"document"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

// Report is the verification outcome.
type Report struct {
	OK                     bool                 `json:"ok"`
	Findings               []Finding            `json:"findings"`
	DocumentsChecked       int                  `json:"documents_checked"`
	Totals                 map[string]TreeCount `json:"totals"`
	StudySurfaceFiles      int                  `json:"study_surface_files"`
	StudySurfaceTypes      int                  `json:"study_surface_types"`
	MigrationRows          int                  `json:"migration_rows"`
	RustWorkspacePresent   bool                 `json:"rust_workspace_present"`
	VerifiedRustIdentities int                  `json:"verified_rust_identities"`
	ImplementationStories  []string             `json:"implementation_stories"`
	UnresolvedStories      []string             `json:"unresolved_stories"`
	WireBoundaryPreserved  bool                 `json:"wire_boundary_preserved"`
	DeclaredExclusions     map[string]bool      `json:"declared_exclusions"`
	TraceableSemanticItems int                  `json:"traceable_semantic_items"`
	UnmappedSemanticItems  []string             `json:"unmapped_semantic_items"`
}
