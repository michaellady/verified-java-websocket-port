package foundation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const currentEvidenceSchemaVersion = "1.1.0"

var (
	stableEvidenceID = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)
	semanticVersion  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	productionCodeID = regexp.MustCompile(`^(?:[A-Za-z0-9_][A-Za-z0-9._-]*/)*[A-Za-z0-9_][A-Za-z0-9._-]*#[A-Za-z_][A-Za-z0-9_.:-]*$`)
)

// ValidateEvidence validates one miniature, claim-scoped assurance case.
// It is a deterministic reader and never changes the supplied bytes.
func ValidateEvidence(data []byte) []Failure {
	var value evidenceCase
	if err := decodeStrict(data, &value); err != nil {
		return []Failure{{Code: "INVALID_EVIDENCE_JSON", Path: "$", Message: err.Error()}}
	}
	failures := make([]Failure, 0)
	if value.SchemaVersion != currentEvidenceSchemaVersion || !semanticVersion.MatchString(value.SchemaVersion) {
		failures = append(failures, Failure{Code: "INVALID_EVIDENCE_SCHEMA_VERSION", Path: "$.schema_version", Message: "current evidence cases require semantic schema version 1.1.0"})
	}
	requireEvidenceID(&failures, value.CaseID, "$.case_id", "")
	if strings.TrimSpace(value.Scenario) == "" {
		failures = append(failures, Failure{Code: "MISSING_FIELD", Path: "$.scenario", Message: "miniature scenario is required"})
	}
	if value.Failures == nil {
		failures = append(failures, Failure{Code: "MISSING_EVIDENCE_FIELD", Path: "$.failures", Message: "required failure envelope array is missing"})
	}
	if value.Attempts == nil {
		failures = append(failures, Failure{Code: "MISSING_EVIDENCE_FIELD", Path: "$.attempts", Message: "required attempt array is missing"})
	}
	snapshotTime, err := time.Parse(time.RFC3339, value.SnapshotTime)
	if err != nil {
		failures = append(failures, Failure{Code: "INVALID_TIMESTAMP", Path: "$.snapshot_time", Message: "snapshot_time must be RFC3339"})
	}

	entities, types := validateEntities(&failures, value.Entities)
	profiles := validateAssuranceProfiles(&failures, value.AssuranceProfiles)
	claimsByID := make(map[string]claim, len(value.Claims))
	for index, claimValue := range value.Claims {
		itemPath := fmt.Sprintf("$.claims[%d]", index)
		requireEvidenceID(&failures, claimValue.ID, itemPath+".id", claimValue.ID)
		if _, exists := claimsByID[claimValue.ID]; exists {
			failures = append(failures, claimFailure("DUPLICATE_ID", itemPath+".id", "claim ID must be unique", claimValue.ID))
		}
		claimsByID[claimValue.ID] = claimValue
		validateClaim(&failures, claimValue, itemPath, snapshotTime, entities, types, profiles)
	}
	if len(value.Claims) == 0 {
		failures = append(failures, Failure{Code: "MISSING_FIELD", Path: "$.claims", Message: "at least one scoped claim is required"})
	}

	validateCommonGate(&failures, value.CommonGate, value.Claims, value.Snapshot)
	reviewsByID := validateReviews(&failures, value.Reviews, claimsByID)
	validateMutations(&failures, value.MutationResults, value.SignedMutationDenominatorIDs, reviewsByID, claimsByID, types)
	validateProofObligations(&failures, value.ProofObligations, claimsByID, types)
	validateReplayBundles(&failures, value.ReplayBundles, value.ProofObligations, claimsByID)
	validateMigrationMaps(&failures, value.MigrationMaps, claimsByID)
	validateFailureEnvelopes(&failures, value.Failures, value.Attempts, claimsByID, entities, value.Snapshot)
	validateSnapshot(&failures, value.Snapshot, value.Claims, reviewsByID)
	return failures
}

// ValidateEvolution validates retained schema bytes, a migration artifact,
// dependency staleness, and one ProgramSnapshotManifest transition.
// It is a deterministic reader and never changes the supplied bytes.
func ValidateEvolution(data []byte) []Failure {
	var value evolutionCase
	if err := decodeStrict(data, &value); err != nil {
		return []Failure{{Code: "INVALID_EVOLUTION_JSON", Path: "$", Message: err.Error()}}
	}
	failures := make([]Failure, 0)
	if value.SchemaVersion != currentEvidenceSchemaVersion || !semanticVersion.MatchString(value.SchemaVersion) {
		failures = append(failures, Failure{Code: "INVALID_EVIDENCE_SCHEMA_VERSION", Path: "$.schema_version", Message: "evolution case requires semantic schema version 1.1.0"})
	}
	for _, requiredArray := range []struct {
		path    string
		missing bool
	}{
		{path: "$.nodes", missing: value.Nodes == nil},
		{path: "$.edges", missing: value.Edges == nil},
		{path: "$.changed_inputs", missing: value.ChangedInputs == nil},
		{path: "$.expected_stale_claim_ids", missing: value.ExpectedStaleClaimIDs == nil},
	} {
		if requiredArray.missing {
			failures = append(failures, Failure{Code: "MISSING_EVOLUTION_FIELD", Path: requiredArray.path, Message: "required evolution graph array is missing"})
		}
	}
	if value.HistoricalValidator != "schemas/evidence-model-1.0.0.schema.json" || value.CurrentValidator != "schemas/evidence-model-1.1.0.schema.json" {
		failures = append(failures, Failure{Code: "RETAINED_VALIDATOR_REQUIRED", Path: "$", Message: "historical and current validators must be pinned by versioned path"})
	}
	historical, historicalErr := decodeCanonicalBase64(value.HistoricalBytesBase64)
	migrated, migratedErr := decodeCanonicalBase64(value.MigratedBytesBase64)
	roundTrip, roundTripErr := decodeCanonicalBase64(value.RoundTripBytesBase64)
	if historicalErr != nil || migratedErr != nil || roundTripErr != nil {
		failures = append(failures, Failure{Code: "SCHEMA_MIGRATION_ERROR", Path: "$", Message: "migration byte payloads must be canonical base64"})
	} else {
		if digestBytes(historical) != value.HistoricalRoot || digestBytes(historical) != value.MigrationArtifact.SourceRoot {
			failures = append(failures, Failure{Code: "SCHEMA_MIGRATION_ERROR", Path: "$.historical_root", Message: "historical root does not bind the retained bytes"})
		}
		if digestBytes(migrated) != value.MigratedRoot || digestBytes(migrated) != value.MigrationArtifact.TargetRoot {
			failures = append(failures, Failure{Code: "SCHEMA_MIGRATION_ERROR", Path: "$.migrated_root", Message: "target root does not bind the migrated bytes"})
		}
		if !value.MigrationArtifact.Lossless || !bytes.Equal(historical, roundTrip) {
			failures = append(failures, Failure{Code: "SCHEMA_MIGRATION_ERROR", Path: "$.round_trip_bytes_base64", Message: "lossless migration must reproduce the exact historical bytes"})
		}
		if !isCanonicalJSON(migrated) {
			failures = append(failures, Failure{Code: "SCHEMA_MIGRATION_ERROR", Path: "$.migrated_bytes_base64", Message: "current migrated bytes must use deterministic canonical JSON"})
		}
		if documentVersion(historical) != value.MigrationArtifact.FromVersion || documentVersion(migrated) != value.MigrationArtifact.ToVersion {
			failures = append(failures, Failure{Code: "SCHEMA_MIGRATION_ERROR", Path: "$.migration_artifact", Message: "migration versions do not match the encoded documents"})
		}
		if !retainedHistoricalDocumentValid(historical) || !retainedCurrentDocumentValid(migrated) {
			failures = append(failures, Failure{Code: "SCHEMA_MIGRATION_ERROR", Path: "$.migration_artifact", Message: "migration documents must satisfy their pinned retained validators"})
		}
	}
	if !sha256Pattern.MatchString(value.MigrationArtifact.ContentAddress) {
		failures = append(failures, Failure{Code: "SCHEMA_MIGRATION_ERROR", Path: "$.migration_artifact.content_address", Message: "migration artifact requires a content-addressed SHA-256 identity"})
	} else if value.MigrationArtifact.ContentAddress != migrationArtifactDigest(value.MigrationArtifact) {
		failures = append(failures, Failure{Code: "SCHEMA_MIGRATION_ERROR", Path: "$.migration_artifact.content_address", Message: "migration artifact content address does not bind its canonical fields"})
	}
	if !semanticVersion.MatchString(value.MigrationArtifact.FromVersion) || !semanticVersion.MatchString(value.MigrationArtifact.ToVersion) || value.MigrationArtifact.FromVersion == value.MigrationArtifact.ToVersion {
		failures = append(failures, Failure{Code: "SCHEMA_MIGRATION_ERROR", Path: "$.migration_artifact", Message: "migration must bind distinct semantic versions"})
	}
	if value.MigrationArtifact.FromVersion != "1.0.0" || value.MigrationArtifact.ToVersion != currentEvidenceSchemaVersion {
		failures = append(failures, Failure{Code: "SCHEMA_MIGRATION_ERROR", Path: "$.migration_artifact", Message: "retained validators support only the exact 1.0.0 to 1.1.0 migration"})
	}
	validateEvolutionGraph(&failures, value)
	if !validSnapshotTransition(value.Transition.From, value.Transition.To) {
		failures = append(failures, Failure{Code: "INVALID_SNAPSHOT_TRANSITION", Path: "$.transition", Message: "ProgramSnapshotManifest transition is not allowed"})
	}
	if !value.HistoricalSnapshotReplayable {
		failures = append(failures, Failure{Code: "HISTORICAL_REPLAY_BLOCKED", Path: "$.historical_snapshot_replayable", Message: "retained historical snapshot must remain replayable"})
	}
	if value.FallbackSnapshotID == "" || value.FallbackSnapshotState != "ACCEPTED" {
		failures = append(failures, Failure{Code: "INVALID_FALLBACK", Path: "$.fallback_snapshot_id", Message: "current suspension requires a last accepted fallback snapshot"})
	}
	return failures
}

type evidenceCase struct {
	SchemaVersion                string              `json:"schema_version"`
	CaseID                       string              `json:"case_id"`
	Scenario                     string              `json:"scenario"`
	SnapshotTime                 string              `json:"snapshot_time"`
	Entities                     []evidenceEntity    `json:"entities"`
	AssuranceProfiles            []assuranceProfile  `json:"assurance_profiles"`
	Claims                       []claim             `json:"claims"`
	CommonGate                   commonGate          `json:"common_gate"`
	MutationResults              []mutationResult    `json:"mutation_results"`
	SignedMutationDenominatorIDs []string            `json:"signed_mutation_denominator_ids"`
	Reviews                      []review            `json:"reviews"`
	ProofObligations             []proofObligation   `json:"proof_obligations"`
	ReplayBundles                []claimReplayBundle `json:"replay_bundles"`
	MigrationMaps                []migrationMap      `json:"migration_maps"`
	Failures                     []failureEnvelope   `json:"failures"`
	Attempts                     []attempt           `json:"attempts"`
	Snapshot                     programSnapshot     `json:"snapshot"`
}

type historicalEvidenceCase struct {
	SchemaVersion string                     `json:"schema_version"`
	CaseID        string                     `json:"case_id"`
	Entities      []historicalEvidenceEntity `json:"entities,omitempty"`
	Claims        []historicalClaim          `json:"claims,omitempty"`
}

type historicalEvidenceEntity struct {
	ID    string         `json:"id"`
	Type  string         `json:"type"`
	Edges []evidenceEdge `json:"edges"`
}

type historicalClaim struct {
	ID          string   `json:"id"`
	Assurance   string   `json:"assurance"`
	SubjectID   string   `json:"subject_id"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type evidenceEntity struct {
	ID    string         `json:"id"`
	Type  string         `json:"type"`
	Edges []evidenceEdge `json:"edges"`
}

type evidenceEdge struct {
	Type string `json:"type"`
	To   string `json:"to"`
}

type assuranceProfile struct {
	Label                 string   `json:"label"`
	RequiredArtifactTypes []string `json:"required_artifact_types"`
	TrustedComputingBase  []string `json:"trusted_computing_base"`
	Disclosures           []string `json:"disclosures"`
	ProhibitedInferences  []string `json:"prohibited_inferences"`
	FailureStates         []string `json:"failure_states"`
	ExpiryRule            string   `json:"expiry_rule"`
	FreshnessRule         string   `json:"freshness_rule"`
	ReadinessCeiling      string   `json:"readiness_ceiling"`
}

type claim struct {
	ID            string   `json:"id"`
	Assurance     string   `json:"assurance"`
	RequiredLevel string   `json:"required_level"`
	SubjectID     string   `json:"subject_id"`
	EvidenceIDs   []string `json:"evidence_ids"`
	Status        string   `json:"status"`
	Freshness     string   `json:"freshness"`
	ExpiresAt     string   `json:"expires_at"`
	Readiness     string   `json:"readiness"`
}

type commonGate struct {
	ConformanceAllPass                bool   `json:"conformance_all_pass"`
	UnexplainedDifferentialMismatches *int   `json:"unexplained_differential_mismatches"`
	DeclaredProofsPass                bool   `json:"declared_proofs_pass"`
	BoundedChecksPass                 bool   `json:"bounded_checks_pass"`
	Flakes                            *int   `json:"flakes"`
	FirstPartyUnsafeRust              *int   `json:"first_party_unsafe_rust"`
	PerformanceVsJava                 string `json:"performance_vs_java"`
	MissedEligibleMutations           *int   `json:"missed_eligible_mutations"`
}

type mutationResult struct {
	ID          string   `json:"id"`
	ClaimID     string   `json:"claim_id"`
	SourceTool  string   `json:"source_tool"`
	RawStatus   string   `json:"raw_status"`
	Disposition string   `json:"disposition"`
	Eligible    *bool    `json:"eligible"`
	ReviewIDs   []string `json:"review_ids"`
}

type review struct {
	ID          string `json:"id"`
	ClaimID     string `json:"claim_id"`
	ReviewerID  string `json:"reviewer_id"`
	Role        string `json:"role"`
	Blind       bool   `json:"blind"`
	Disposition string `json:"disposition"`
}

type proofObligation struct {
	ID                    string   `json:"id"`
	ClaimID               string   `json:"claim_id"`
	RequiredOutcome       string   `json:"required_outcome"`
	Outcome               string   `json:"outcome"`
	ModelID               string   `json:"model_id"`
	ProductionCodeIDs     []string `json:"production_code_ids"`
	Bounds                []string `json:"bounds"`
	UnsupportedConstructs []string `json:"unsupported_constructs"`
}

type claimReplayBundle struct {
	ID                        string   `json:"id"`
	ClaimID                   string   `json:"claim_id"`
	SourceRevision            string   `json:"source_revision"`
	SpecificationRevision     string   `json:"specification_revision"`
	JavaRevision              string   `json:"java_revision"`
	RustRevision              string   `json:"rust_revision"`
	JavaSemanticIDs           []string `json:"java_semantic_ids"`
	RustSemanticIDs           []string `json:"rust_semantic_ids"`
	Command                   string   `json:"command"`
	WorkingDirectory          string   `json:"working_directory"`
	ToolHashes                []string `json:"tool_hashes"`
	ContainerHashes           []string `json:"container_hashes"`
	Environment               []string `json:"environment"`
	Seed                      string   `json:"seed"`
	Hardware                  string   `json:"hardware"`
	Assumptions               []string `json:"assumptions"`
	Bounds                    []string `json:"bounds"`
	UnsupportedConstructs     []string `json:"unsupported_constructs"`
	TrustedBase               []string `json:"trusted_base"`
	ExitCount                 *int     `json:"exit_count"`
	ObligationCount           *int     `json:"obligation_count"`
	RawLogIDs                 []string `json:"raw_log_ids"`
	ArtifactIDs               []string `json:"artifact_ids"`
	NormalizedDiffID          string   `json:"normalized_diff_id"`
	CounterexampleOrCorpusIDs []string `json:"counterexample_or_corpus_ids"`
	ReplayCommand             string   `json:"replay_command"`
}

type migrationMap struct {
	ID                      string   `json:"id"`
	JavaSemanticID          string   `json:"java_semantic_id"`
	JavaSignature           string   `json:"java_signature"`
	RustSemanticID          string   `json:"rust_semantic_id"`
	RustResolver            string   `json:"rust_resolver"`
	ApplicabilityConditions []string `json:"applicability_conditions"`
	KnownNonEquivalentCases []string `json:"known_non_equivalent_cases"`
	SourceRevision          string   `json:"source_revision"`
	DetectionQuery          string   `json:"detection_query"`
	PortSliceID             string   `json:"port_slice_id"`
	TouchedFiles            []string `json:"touched_files"`
	SpecificationIDs        []string `json:"specification_ids"`
	ObservedBehaviorIDs     []string `json:"observed_behavior_ids"`
	OracleIDs               []string `json:"oracle_ids"`
	VectorIDs               []string `json:"vector_ids"`
	PropertyClaimIDs        []string `json:"property_claim_ids"`
	FormalClaimIDs          []string `json:"formal_claim_ids"`
	EvidenceIDs             []string `json:"evidence_ids"`
	Status                  string   `json:"status"`
	LookupStrength          string   `json:"lookup_strength"`
}

type failureEnvelope struct {
	FailureID            string   `json:"failure_id"`
	ErrorType            string   `json:"error_type"`
	Phase                string   `json:"phase"`
	Codepath             string   `json:"codepath"`
	Severity             string   `json:"severity"`
	Retryability         string   `json:"retryability"`
	Disposition          string   `json:"disposition"`
	AffectedClaimIDs     []string `json:"affected_claim_ids"`
	AffectedArtifactIDs  []string `json:"affected_artifact_ids"`
	SnapshotID           string   `json:"snapshot_id"`
	ActorID              string   `json:"actor_id"`
	Role                 string   `json:"role"`
	RunID                string   `json:"run_id"`
	AttemptID            string   `json:"attempt_id"`
	CauseChain           []string `json:"cause_chain"`
	SafeUserMessage      string   `json:"safe_user_message"`
	DiagnosticArtifactID string   `json:"diagnostic_artifact_id"`
	Timestamp            string   `json:"timestamp"`
}

type attempt struct {
	ID        string `json:"id"`
	RunID     string `json:"run_id"`
	ActorID   string `json:"actor_id"`
	Role      string `json:"role"`
	ErrorType string `json:"error_type"`
	FailureID string `json:"failure_id"`
}

type programSnapshot struct {
	ID                      string          `json:"id"`
	State                   string          `json:"state"`
	Schemas                 []string        `json:"schemas"`
	Validators              []string        `json:"validators"`
	Policies                []string        `json:"policies"`
	SkillRevision           string          `json:"skill_revision"`
	SourceCommits           []string        `json:"source_commits"`
	PortCommits             []string        `json:"port_commits"`
	Suites                  []string        `json:"suites"`
	ProtectedCaseSetVersion string          `json:"protected_case_set_version"`
	Toolchains              []string        `json:"toolchains"`
	Platforms               []string        `json:"platforms"`
	LSPProfiles             []string        `json:"lsp_profiles"`
	EvidenceRoots           []string        `json:"evidence_roots"`
	ReviewerAttestations    []string        `json:"reviewer_attestations"`
	CutoverProfile          string          `json:"cutover_profile"`
	CutoverPrerequisites    map[string]bool `json:"cutover_prerequisites"`
}

type evolutionCase struct {
	SchemaVersion                string            `json:"schema_version"`
	HistoricalValidator          string            `json:"historical_validator"`
	CurrentValidator             string            `json:"current_validator"`
	HistoricalBytesBase64        string            `json:"historical_bytes_base64"`
	HistoricalRoot               string            `json:"historical_root"`
	MigratedBytesBase64          string            `json:"migrated_bytes_base64"`
	MigratedRoot                 string            `json:"migrated_root"`
	RoundTripBytesBase64         string            `json:"round_trip_bytes_base64"`
	MigrationArtifact            migrationArtifact `json:"migration_artifact"`
	Nodes                        []dependencyNode  `json:"nodes"`
	Edges                        []dependencyEdge  `json:"edges"`
	ChangedInputs                []changedInput    `json:"changed_inputs"`
	ExpectedStaleClaimIDs        []string          `json:"expected_stale_claim_ids"`
	FallbackSnapshotID           string            `json:"fallback_snapshot_id"`
	FallbackSnapshotState        string            `json:"fallback_snapshot_state"`
	HistoricalSnapshotReplayable bool              `json:"historical_snapshot_replayable"`
	Transition                   stateTransition   `json:"transition"`
}

type migrationArtifact struct {
	ID             string `json:"id"`
	FromVersion    string `json:"from_version"`
	ToVersion      string `json:"to_version"`
	SourceRoot     string `json:"source_root"`
	TargetRoot     string `json:"target_root"`
	Lossless       bool   `json:"lossless"`
	ContentAddress string `json:"content_address"`
}

type dependencyNode struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	CorrectnessClaim *bool  `json:"correctness_claim"`
	State            string `json:"state"`
}

type dependencyEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

type changedInput struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type stateTransition struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func validateEntities(failures *[]Failure, values []evidenceEntity) (map[string]evidenceEntity, map[string]string) {
	requiredTypes := evidenceEntityTypeNames
	allowedTypes := stringSet(requiredTypes)
	entities := make(map[string]evidenceEntity, len(values))
	types := make(map[string]string, len(values))
	typeCounts := make(map[string]int, len(requiredTypes))
	for index, value := range values {
		itemPath := fmt.Sprintf("$.entities[%d]", index)
		requireEvidenceID(failures, value.ID, itemPath+".id", "")
		if !allowedTypes[value.Type] {
			*failures = append(*failures, Failure{Code: "UNKNOWN_ENTITY_TYPE", Path: itemPath + ".type", Message: "entity type is not defined by evidence-model@1.1.0"})
		}
		if _, exists := entities[value.ID]; exists {
			*failures = append(*failures, Failure{Code: "DUPLICATE_ID", Path: itemPath + ".id", Message: "stable entity ID must be unique"})
		}
		entities[value.ID] = value
		types[value.ID] = value.Type
		typeCounts[value.Type]++
	}
	for _, entityType := range requiredTypes {
		if typeCounts[entityType] == 0 {
			*failures = append(*failures, Failure{Code: "MISSING_ENTITY_DEFINITION", Path: "$.entities", Message: "miniature case is missing entity type " + entityType})
		}
	}
	allowedEdges := stringSet(evidenceEdgeTypeNames)
	for index, value := range values {
		seenEntityEdges := make(map[string]bool, len(value.Edges))
		for edgeIndex, edge := range value.Edges {
			itemPath := fmt.Sprintf("$.entities[%d].edges[%d]", index, edgeIndex)
			edgeIdentity := edge.Type + "\x00" + edge.To
			if seenEntityEdges[edgeIdentity] {
				*failures = append(*failures, Failure{Code: "DUPLICATE_LINK", Path: itemPath, Message: "typed entity edge must be unique"})
			}
			seenEntityEdges[edgeIdentity] = true
			if !allowedEdges[edge.Type] {
				*failures = append(*failures, Failure{Code: "INVALID_EDGE_TYPE", Path: itemPath + ".type", Message: "relationship must use an explicit evidence edge type"})
			}
			if _, exists := entities[edge.To]; !exists {
				*failures = append(*failures, Failure{Code: "DANGLING_EDGE", Path: itemPath + ".to", Message: "typed relationship target does not resolve"})
			}
		}
	}
	return entities, types
}

func validateAssuranceProfiles(failures *[]Failure, values []assuranceProfile) map[string]assuranceProfile {
	labels := []string{"observed", "differential", "bounded", "proved-model", "proved-production/refinement"}
	ceilings := map[string]string{"observed": "LAB", "differential": "LAB", "bounded": "CANDIDATE", "proved-model": "CANDIDATE", "proved-production/refinement": "PUBLISHED"}
	requiredArtifacts := assuranceArtifactRequirements()
	profiles := make(map[string]assuranceProfile, len(values))
	for index, value := range values {
		itemPath := fmt.Sprintf("$.assurance_profiles[%d]", index)
		if _, exists := profiles[value.Label]; exists {
			*failures = append(*failures, Failure{Code: "DUPLICATE_ASSURANCE_PROFILE", Path: itemPath + ".label", Message: "each assurance label must be defined once"})
		}
		profiles[value.Label] = value
		if ceilings[value.Label] == "" || value.ReadinessCeiling != ceilings[value.Label] {
			*failures = append(*failures, Failure{Code: "INVALID_ASSURANCE_PROFILE", Path: itemPath + ".readiness_ceiling", Message: "assurance label has an invalid production-readiness ceiling"})
		}
		if len(value.RequiredArtifactTypes) == 0 || len(value.TrustedComputingBase) == 0 || len(value.Disclosures) == 0 || len(value.ProhibitedInferences) == 0 || len(value.FailureStates) == 0 || value.ExpiryRule == "" || value.FreshnessRule == "" {
			*failures = append(*failures, Failure{Code: "INCOMPLETE_ASSURANCE_PROFILE", Path: itemPath, Message: "assurance profile must declare artifacts, TCB, disclosures, prohibited inferences, failures, expiry, and freshness"})
		}
		declaredArtifacts := stringSet(value.RequiredArtifactTypes)
		for _, artifactType := range requiredArtifacts[value.Label] {
			if !declaredArtifacts[artifactType] {
				*failures = append(*failures, Failure{Code: "INVALID_ASSURANCE_PROFILE", Path: itemPath + ".required_artifact_types", Message: "assurance profile omits required artifact type " + artifactType})
			}
		}
	}
	for _, label := range labels {
		if _, exists := profiles[label]; !exists {
			*failures = append(*failures, Failure{Code: "MISSING_ASSURANCE_PROFILE", Path: "$.assurance_profiles", Message: "missing claim-scoped assurance label " + label})
		}
	}
	return profiles
}

func validateClaim(failures *[]Failure, value claim, itemPath string, snapshotTime time.Time, entities map[string]evidenceEntity, types map[string]string, profiles map[string]assuranceProfile) {
	profile, validProfile := profiles[value.Assurance]
	assuranceRanks := map[string]int{"observed": 0, "differential": 1, "bounded": 2, "proved-model": 3, "proved-production/refinement": 4}
	if !validProfile {
		*failures = append(*failures, claimFailure("INVALID_ASSURANCE_LABEL", itemPath+".assurance", "claim assurance label is not defined", value.ID))
	}
	if value.RequiredLevel == "" || value.SubjectID == "" || len(value.EvidenceIDs) == 0 {
		*failures = append(*failures, claimFailure("MISSING_REQUIRED_EVIDENCE", itemPath, "claim must bind its subject, required level, and evidence", value.ID))
	}
	requiredRank, requiredOK := assuranceRanks[value.RequiredLevel]
	assuranceRank, assuranceOK := assuranceRanks[value.Assurance]
	if !requiredOK || !assuranceOK || assuranceRank < requiredRank {
		*failures = append(*failures, claimFailure("ASSURANCE_CEILING_EXCEEDED", itemPath+".required_level", "claim assurance is weaker than its predeclared required level", value.ID))
	}
	if _, exists := entities[value.SubjectID]; !exists {
		*failures = append(*failures, claimFailure("MISSING_REQUIRED_EVIDENCE", itemPath+".subject_id", "claim subject does not resolve", value.ID))
	}
	if types[value.ID] != "Claim" {
		*failures = append(*failures, claimFailure("INVALID_CLAIM_ID_BINDING", itemPath+".id", "claim ID must resolve to the corresponding Claim entity", value.ID))
	}
	presentTypes := make(map[string]bool)
	seenEvidenceIDs := make(map[string]bool, len(value.EvidenceIDs))
	lspOnly := len(value.EvidenceIDs) != 0
	for evidenceIndex, evidenceID := range value.EvidenceIDs {
		if seenEvidenceIDs[evidenceID] {
			*failures = append(*failures, claimFailure("DUPLICATE_LINK", fmt.Sprintf("%s.evidence_ids[%d]", itemPath, evidenceIndex), "claim evidence link must be unique", value.ID))
		}
		seenEvidenceIDs[evidenceID] = true
		entityType, exists := types[evidenceID]
		if !exists {
			*failures = append(*failures, claimFailure("MISSING_REQUIRED_EVIDENCE", fmt.Sprintf("%s.evidence_ids[%d]", itemPath, evidenceIndex), "claim evidence does not resolve", value.ID))
			continue
		}
		presentTypes[entityType] = true
		if !entitySupportsClaim(entities[evidenceID], value.ID) {
			*failures = append(*failures, claimFailure("DISCONNECTED_EVIDENCE", fmt.Sprintf("%s.evidence_ids[%d]", itemPath, evidenceIndex), "claim evidence must explicitly support, discharge, or attest the scoped claim", value.ID))
		}
		if entityType != "DeveloperToolRun" {
			lspOnly = false
		}
	}
	if lspOnly {
		*failures = append(*failures, claimFailure("LSP_NON_ASSURANCE", itemPath+".evidence_ids", "LSP developer-tool output is navigational and cannot satisfy or revoke correctness", value.ID))
	}
	for _, artifactType := range uniqueStrings(append(append([]string(nil), profile.RequiredArtifactTypes...), assuranceArtifactRequirements()[value.Assurance]...)) {
		if !presentTypes[artifactType] {
			*failures = append(*failures, claimFailure("MISSING_REQUIRED_EVIDENCE", itemPath+".evidence_ids", "claim is missing required artifact type "+artifactType, value.ID))
		}
	}
	switch value.Status {
	case "SUPPORTED":
	case "CONTRADICTORY":
		*failures = append(*failures, claimFailure("CONTRADICTORY_CLAIM", itemPath+".status", "contradictory evidence blocks the claim", value.ID))
	default:
		*failures = append(*failures, claimFailure("UNSUPPORTED_CLAIM", itemPath+".status", "claim status is not supported", value.ID))
	}
	if value.Freshness != "FRESH" {
		*failures = append(*failures, claimFailure("STALE_CLAIM", itemPath+".freshness", "claim is not fresh for the current snapshot", value.ID))
	}
	if expiresAt, err := time.Parse(time.RFC3339, value.ExpiresAt); err != nil || (!snapshotTime.IsZero() && !expiresAt.After(snapshotTime)) {
		*failures = append(*failures, claimFailure("EXPIRED_CLAIM", itemPath+".expires_at", "claim evidence is expired at snapshot time", value.ID))
	}
	if validProfile && readinessRank(value.Readiness) > readinessRank(profile.ReadinessCeiling) {
		*failures = append(*failures, claimFailure("ASSURANCE_CEILING_EXCEEDED", itemPath+".readiness", "claim readiness exceeds its assurance ceiling", value.ID))
	}
	if readinessRank(value.Readiness) < 0 {
		*failures = append(*failures, claimFailure("INVALID_READINESS", itemPath+".readiness", "claim readiness is not defined", value.ID))
	}
}

func validateCommonGate(failures *[]Failure, gate commonGate, claims []claim, snapshot programSnapshot) {
	if gate.UnexplainedDifferentialMismatches == nil || gate.Flakes == nil || gate.FirstPartyUnsafeRust == nil || gate.MissedEligibleMutations == nil {
		for _, claimValue := range claims {
			*failures = append(*failures, claimFailure("INCOMPLETE_COMMON_GATE", "$.common_gate", "common gate requires every signed zero-valued counter", claimValue.ID))
		}
		return
	}
	gatePasses := gate.ConformanceAllPass && *gate.UnexplainedDifferentialMismatches == 0 && gate.DeclaredProofsPass && gate.BoundedChecksPass && *gate.Flakes == 0 && *gate.FirstPartyUnsafeRust == 0 && (gate.PerformanceVsJava == "match" || gate.PerformanceVsJava == "outperform") && *gate.MissedEligibleMutations == 0 && len(snapshot.Suites) > 0
	if gatePasses {
		return
	}
	for _, claimValue := range claims {
		*failures = append(*failures, claimFailure("COMMON_GATE_FAILED", "$.common_gate", "common gate requires conformance, differential, proof, bounded, flake, unsafe, performance, suite, and mutation success", claimValue.ID))
	}
}

func validateReviews(failures *[]Failure, values []review, claims map[string]claim) map[string]review {
	byID := make(map[string]review, len(values))
	byClaim := make(map[string][]review)
	for index, value := range values {
		itemPath := fmt.Sprintf("$.reviews[%d]", index)
		requireEvidenceID(failures, value.ID, itemPath+".id", value.ClaimID)
		requireEvidenceID(failures, value.ReviewerID, itemPath+".reviewer_id", value.ClaimID)
		if _, exists := byID[value.ID]; exists {
			*failures = append(*failures, claimFailure("DUPLICATE_ID", itemPath+".id", "review ID must be unique", value.ClaimID))
		}
		byID[value.ID] = value
		if stableEvidenceID.MatchString(value.ReviewerID) {
			byClaim[value.ClaimID] = append(byClaim[value.ClaimID], value)
		}
		if _, exists := claims[value.ClaimID]; !exists || value.ReviewerID == "" || value.Role != "independent-reviewer" || !value.Blind || value.Disposition != "APPROVE" {
			*failures = append(*failures, claimFailure("INVALID_REVIEW", itemPath, "review must be blind, independent, approving, and bound to a claim", value.ClaimID))
		}
	}
	claimIDs := sortedClaimIDs(claims)
	for _, claimID := range claimIDs {
		seenReviewers := make(map[string]bool)
		for _, reviewValue := range byClaim[claimID] {
			if seenReviewers[reviewValue.ReviewerID] {
				*failures = append(*failures, claimFailure("REVIEW_ROLE_CONFLICT", "$.reviews", "independent approvals must come from distinct reviewers", claimID))
			}
			seenReviewers[reviewValue.ReviewerID] = true
		}
		if claims[claimID].Assurance == "proved-production/refinement" && len(seenReviewers) < 2 {
			*failures = append(*failures, claimFailure("INDEPENDENT_REVIEW_REQUIRED", "$.reviews", "claim requires two blind independent reviewers", claimID))
		}
	}
	return byID
}

func validateMutations(failures *[]Failure, values []mutationResult, denominator []string, reviews map[string]review, claims map[string]claim, types map[string]string) {
	validDispositions := stringSet([]string{"killed", "survived", "not_executed", "uncovered", "timeout", "tool_failure", "flaky", "equivalent", "technically_unviable"})
	validTools := stringSet([]string{"PIT", "cargo-mutants"})
	actualIDs := make([]string, 0, len(values))
	seenIDs := make(map[string]bool, len(values))
	byClaim := make(map[string]int)
	for index, value := range values {
		itemPath := fmt.Sprintf("$.mutation_results[%d]", index)
		requireEvidenceID(failures, value.ID, itemPath+".id", value.ClaimID)
		if seenIDs[value.ID] {
			*failures = append(*failures, claimFailure("DUPLICATE_ID", itemPath+".id", "mutation result ID must be unique", value.ClaimID))
		}
		seenIDs[value.ID] = true
		actualIDs = append(actualIDs, value.ID)
		if value.RawStatus == "" || value.Eligible == nil {
			*failures = append(*failures, claimFailure("INCOMPLETE_MUTATION_RESULT", itemPath, "mutation result requires raw status and explicit eligibility", value.ClaimID))
		}
		if !validTools[value.SourceTool] {
			*failures = append(*failures, claimFailure("INVALID_MUTATION_TOOL", itemPath+".source_tool", "mutation result must normalize PIT or cargo-mutants output", value.ClaimID))
		}
		if !validDispositions[value.Disposition] {
			*failures = append(*failures, claimFailure("INVALID_MUTATION_DISPOSITION", itemPath+".disposition", "mutation disposition is not normalized", value.ClaimID))
		}
		claimValue, claimExists := claims[value.ClaimID]
		if !claimExists {
			*failures = append(*failures, claimFailure("UNKNOWN_CLAIM", itemPath+".claim_id", "mutation result claim does not resolve", value.ClaimID))
		} else {
			byClaim[value.ClaimID]++
			if types[value.ID] != "MutationResult" || !containsString(claimValue.EvidenceIDs, value.ID) {
				*failures = append(*failures, claimFailure("DISCONNECTED_MUTATION_RESULT", itemPath+".id", "mutation record must bind the claim's MutationResult evidence entity", value.ClaimID))
			}
		}
		if value.Eligible != nil && *value.Eligible && value.Disposition != "killed" && value.Disposition != "equivalent" && value.Disposition != "technically_unviable" {
			*failures = append(*failures, claimFailure("MUTATION_GATE_FAILED", itemPath+".disposition", "eligible non-killed mutation blocks the common gate", value.ClaimID))
		}
		if value.Disposition == "equivalent" || value.Disposition == "technically_unviable" {
			reviewerIDs := make(map[string]bool)
			for _, reviewID := range value.ReviewIDs {
				if reviewValue, exists := reviews[reviewID]; exists && stableEvidenceID.MatchString(reviewValue.ReviewerID) && reviewValue.ClaimID == value.ClaimID && reviewValue.Blind && reviewValue.Role == "independent-reviewer" && reviewValue.Disposition == "APPROVE" {
					reviewerIDs[reviewValue.ReviewerID] = true
				}
			}
			if len(reviewerIDs) < 2 {
				*failures = append(*failures, claimFailure("MUTATION_REVIEW_REQUIRED", itemPath+".review_ids", "equivalent and technically unviable dispositions require dual-blind independent review", value.ClaimID))
			}
		}
	}
	if !sameStringSet(actualIDs, denominator) {
		for _, claimID := range sortedClaimIDs(claims) {
			*failures = append(*failures, claimFailure("MUTATION_DENOMINATOR_MISMATCH", "$.signed_mutation_denominator_ids", "every mutation disposition must remain in the signed denominator", claimID))
		}
	}
	for _, claimID := range sortedClaimIDs(claims) {
		if claims[claimID].Assurance == "proved-production/refinement" && byClaim[claimID] == 0 {
			*failures = append(*failures, claimFailure("MISSING_MUTATION_RESULT", "$.mutation_results", "proved production claim requires a bound mutation result", claimID))
		}
	}
}

func validateProofObligations(failures *[]Failure, values []proofObligation, claims map[string]claim, types map[string]string) {
	lattice := map[string]int{"unsupported": 0, "disconnected": 0, "inconclusive": 1, "stale": 1, "model_observation": 2, "trace_observation": 3, "BoundedCheckPassed": 4, "ProofEstablished": 5}
	byClaim := make(map[string]int)
	seenIDs := make(map[string]bool, len(values))
	for index, value := range values {
		itemPath := fmt.Sprintf("$.proof_obligations[%d]", index)
		requireEvidenceID(failures, value.ID, itemPath+".id", value.ClaimID)
		if seenIDs[value.ID] {
			*failures = append(*failures, claimFailure("DUPLICATE_ID", itemPath+".id", "proof obligation ID must be unique", value.ClaimID))
		}
		seenIDs[value.ID] = true
		claimValue, exists := claims[value.ClaimID]
		if !exists {
			*failures = append(*failures, claimFailure("UNKNOWN_CLAIM", itemPath+".claim_id", "proof obligation claim does not resolve", value.ClaimID))
			continue
		}
		byClaim[value.ClaimID]++
		if types[value.ID] != "ProofObligation" || !containsString(claimValue.EvidenceIDs, value.ID) {
			*failures = append(*failures, claimFailure("DISCONNECTED_PROOF", itemPath+".id", "proof record must bind the claim's ProofObligation evidence entity", value.ClaimID))
		}
		requiredRank, requiredOK := lattice[value.RequiredOutcome]
		outcomeRank, outcomeOK := lattice[value.Outcome]
		if !requiredOK || !outcomeOK || outcomeRank < requiredRank {
			*failures = append(*failures, claimFailure("ASSURANCE_CEILING_EXCEEDED", itemPath+".outcome", "weaker formal evidence lowers or blocks the predeclared claim ceiling", value.ClaimID))
		}
		productionCodeIDsValid := true
		for _, productionCodeID := range value.ProductionCodeIDs {
			productionCodeIDsValid = productionCodeIDsValid && canonicalProductionCodeID(productionCodeID)
		}
		if !productionCodeIDsValid || (claimValue.Assurance == "proved-production/refinement" && len(value.ProductionCodeIDs) == 0) {
			*failures = append(*failures, claimFailure("DISCONNECTED_PROOF", itemPath+".production_code_ids", "production refinement proof must link to production code", value.ClaimID))
		}
		if value.ModelID == "" {
			*failures = append(*failures, claimFailure("INCOMPLETE_PROOF_OBLIGATION", itemPath+".model_id", "proof obligation requires an explicit model", value.ClaimID))
		} else if types[value.ModelID] != "Model" || !containsString(claimValue.EvidenceIDs, value.ModelID) {
			*failures = append(*failures, claimFailure("DISCONNECTED_PROOF", itemPath+".model_id", "proof model must resolve to connected Model evidence", value.ClaimID))
		}
	}
	for _, claimID := range sortedClaimIDs(claims) {
		claimValue := claims[claimID]
		if (claimValue.Assurance == "proved-model" || claimValue.Assurance == "proved-production/refinement") && byClaim[claimID] == 0 {
			*failures = append(*failures, claimFailure("MISSING_PROOF_OBLIGATION", "$.proof_obligations", "proved claim requires a predeclared obligation", claimID))
		}
	}
}

func canonicalProductionCodeID(value string) bool {
	if !productionCodeID.MatchString(value) {
		return false
	}
	file, _, _ := strings.Cut(value, "#")
	return path.Clean(file) == file
}

func validateReplayBundles(failures *[]Failure, values []claimReplayBundle, obligations []proofObligation, claims map[string]claim) {
	byClaim := make(map[string]int)
	obligationsByClaim := make(map[string]int)
	for _, obligation := range obligations {
		obligationsByClaim[obligation.ClaimID]++
	}
	seenIDs := make(map[string]bool, len(values))
	for index, value := range values {
		itemPath := fmt.Sprintf("$.replay_bundles[%d]", index)
		requireEvidenceID(failures, value.ID, itemPath+".id", value.ClaimID)
		if seenIDs[value.ID] {
			*failures = append(*failures, claimFailure("DUPLICATE_ID", itemPath+".id", "ClaimReplayBundle ID must be unique", value.ClaimID))
		}
		seenIDs[value.ID] = true
		byClaim[value.ClaimID]++
		complete := value.ID != "" && value.SourceRevision != "" && value.SpecificationRevision != "" && value.JavaRevision != "" && value.RustRevision != "" && len(value.JavaSemanticIDs) > 0 && len(value.RustSemanticIDs) > 0 && value.Command != "" && value.WorkingDirectory != "" && len(value.ToolHashes) > 0 && len(value.ContainerHashes) > 0 && len(value.Environment) > 0 && value.Seed != "" && value.Hardware != "" && len(value.Assumptions) > 0 && value.Bounds != nil && value.UnsupportedConstructs != nil && len(value.TrustedBase) > 0 && value.ExitCount != nil && *value.ExitCount >= 0 && value.ObligationCount != nil && *value.ObligationCount >= 0 && len(value.RawLogIDs) > 0 && len(value.ArtifactIDs) > 0 && value.NormalizedDiffID != "" && len(value.CounterexampleOrCorpusIDs) > 0 && value.ReplayCommand != ""
		if _, exists := claims[value.ClaimID]; !exists || !complete {
			*failures = append(*failures, claimFailure("INCOMPLETE_REPLAY_BUNDLE", itemPath, "ClaimReplayBundle is missing a deterministic replay binding", value.ClaimID))
		}
		if value.Command != value.ReplayCommand || !safeReplayCommand(value.Command) || !safeReplayWorkingDirectory(value.WorkingDirectory) {
			*failures = append(*failures, claimFailure("UNSAFE_REPLAY_COMMAND", itemPath+".command", "replay command and working directory must be canonical relative paths without shell control syntax", value.ClaimID))
		}
		if value.ObligationCount != nil && *value.ObligationCount != obligationsByClaim[value.ClaimID] {
			*failures = append(*failures, claimFailure("REPLAY_COUNT_MISMATCH", itemPath+".obligation_count", "replay obligation count must equal the claim's declared obligations", value.ClaimID))
		}
	}
	for _, claimID := range sortedClaimIDs(claims) {
		if byClaim[claimID] != 1 {
			*failures = append(*failures, claimFailure("INCOMPLETE_REPLAY_BUNDLE", "$.replay_bundles", "every claim must own exactly one ClaimReplayBundle", claimID))
		}
	}
}

func safeReplayCommand(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\n\r;&|><`\\\"'$*?[]{}()!~#") {
		return false
	}
	fields := strings.Fields(value)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "./") {
		return false
	}
	executable := strings.TrimPrefix(fields[0], "./")
	if executable == "" || strings.HasPrefix(executable, "../") || path.Clean(executable) != executable {
		return false
	}
	for _, argument := range fields[1:] {
		pathValue := argument
		if separator := strings.IndexByte(pathValue, '='); separator >= 0 {
			pathValue = pathValue[separator+1:]
		}
		if pathValue == ".." || strings.HasPrefix(pathValue, "../") || strings.HasPrefix(pathValue, "/") || (strings.ContainsRune(pathValue, '/') && !safeReplayWorkingDirectory(pathValue)) {
			return false
		}
	}
	return true
}

func safeReplayWorkingDirectory(value string) bool {
	return value == "." || (value != "" && !strings.HasPrefix(value, "/") && value != ".." && !strings.HasPrefix(value, "../") && !strings.ContainsRune(value, '\\') && path.Clean(value) == value)
}

func validateMigrationMaps(failures *[]Failure, values []migrationMap, claims map[string]claim) {
	seenIDs := make(map[string]bool, len(values))
	for index, value := range values {
		itemPath := fmt.Sprintf("$.migration_maps[%d]", index)
		requireEvidenceID(failures, value.ID, itemPath+".id", "")
		if seenIDs[value.ID] {
			*failures = append(*failures, Failure{Code: "DUPLICATE_ID", Path: itemPath + ".id", Message: "MigrationMap ID must be unique"})
		}
		seenIDs[value.ID] = true
		complete := value.ID != "" && value.JavaSemanticID != "" && value.JavaSignature != "" && value.RustSemanticID != "" && (value.RustResolver == "rust-analyzer" || value.RustResolver == "reviewed-glancer") && len(value.ApplicabilityConditions) > 0 && len(value.KnownNonEquivalentCases) > 0 && value.SourceRevision != "" && value.DetectionQuery != "" && value.PortSliceID != "" && len(value.TouchedFiles) > 0 && len(value.SpecificationIDs) > 0 && len(value.ObservedBehaviorIDs) > 0 && len(value.OracleIDs) > 0 && len(value.VectorIDs) > 0 && len(value.PropertyClaimIDs) > 0 && len(value.FormalClaimIDs) > 0 && len(value.EvidenceIDs) > 0 && value.Status != ""
		if !complete {
			*failures = append(*failures, Failure{Code: "INCOMPLETE_MIGRATION_MAP", Path: itemPath, Message: "MigrationMap row is missing a required semantic or evidence binding"})
		}
		if value.LookupStrength != "semantic" && value.LookupStrength != "ast-fallback" && value.LookupStrength != "grep-fallback" {
			*failures = append(*failures, Failure{Code: "INVALID_LOOKUP_STRENGTH", Path: itemPath + ".lookup_strength", Message: "lookup must be semantic or an explicitly weaker AST/grep fallback"})
		}
		if value.LookupStrength != "semantic" {
			claimIDs := append(append([]string(nil), value.PropertyClaimIDs...), value.FormalClaimIDs...)
			for _, claimID := range claimIDs {
				if claimValue, exists := claims[claimID]; exists && (claimValue.Assurance == "proved-model" || claimValue.Assurance == "proved-production/refinement") {
					*failures = append(*failures, claimFailure("WEAK_LOOKUP_CEILING", itemPath+".lookup_strength", "AST or grep lookup cannot establish a proved claim", claimID))
				}
			}
		}
		for _, claimID := range append(append([]string(nil), value.PropertyClaimIDs...), value.FormalClaimIDs...) {
			if _, exists := claims[claimID]; !exists {
				*failures = append(*failures, claimFailure("UNKNOWN_CLAIM", itemPath, "MigrationMap claim link does not resolve", claimID))
			}
		}
	}
	if len(values) == 0 {
		*failures = append(*failures, Failure{Code: "INCOMPLETE_MIGRATION_MAP", Path: "$.migration_maps", Message: "at least one complete MigrationMap row is required"})
	}
}

func validateFailureEnvelopes(failures *[]Failure, values []failureEnvelope, attempts []attempt, claims map[string]claim, entities map[string]evidenceEntity, snapshot programSnapshot) {
	validDispositions := stringSet([]string{"RETRY", "DEGRADE_NON_ASSURANCE", "BLOCK", "INVALIDATE", "QUARANTINE", "REVOKE"})
	byID := make(map[string]failureEnvelope, len(values))
	attemptsByID := make(map[string]attempt, len(attempts))
	for _, value := range attempts {
		attemptsByID[value.ID] = value
	}
	for index, value := range values {
		itemPath := fmt.Sprintf("$.failures[%d]", index)
		requireEvidenceID(failures, value.FailureID, itemPath+".failure_id", "")
		if _, exists := byID[value.FailureID]; exists {
			*failures = append(*failures, Failure{Code: "DUPLICATE_ID", Path: itemPath + ".failure_id", Message: "failure ID must be unique"})
		}
		byID[value.FailureID] = value
		complete := value.FailureID != "" && value.ErrorType != "" && value.Phase != "" && value.Codepath != "" && value.Severity != "" && value.Retryability != "" && validDispositions[value.Disposition] && len(value.AffectedClaimIDs) > 0 && len(value.AffectedArtifactIDs) > 0 && value.SnapshotID != "" && value.ActorID != "" && value.Role != "" && value.RunID != "" && value.AttemptID != "" && len(value.CauseChain) > 0 && value.SafeUserMessage != "" && value.DiagnosticArtifactID != ""
		if _, err := time.Parse(time.RFC3339, value.Timestamp); err != nil {
			complete = false
		}
		if !complete {
			*failures = append(*failures, Failure{Code: "INCOMPLETE_FAILURE_ENVELOPE", Path: itemPath, Message: "failure envelope is missing a universal failure field"})
		}
		bindingValid := value.SnapshotID == snapshot.ID
		for _, claimID := range value.AffectedClaimIDs {
			if _, exists := claims[claimID]; !exists {
				bindingValid = false
			}
		}
		for _, artifactID := range value.AffectedArtifactIDs {
			if _, exists := entities[artifactID]; !exists {
				bindingValid = false
			}
		}
		attemptValue, attemptExists := attemptsByID[value.AttemptID]
		if !attemptExists || attemptValue.FailureID != value.FailureID || attemptValue.ErrorType != value.ErrorType || attemptValue.RunID != value.RunID || attemptValue.ActorID != value.ActorID || attemptValue.Role != value.Role {
			bindingValid = false
		}
		if !bindingValid {
			*failures = append(*failures, Failure{Code: "INVALID_FAILURE_BINDING", Path: itemPath, Message: "failure envelope references must resolve and match its snapshot and attempt"})
		}
	}
	seenAttemptIDs := make(map[string]bool, len(attempts))
	for index, value := range attempts {
		itemPath := fmt.Sprintf("$.attempts[%d]", index)
		requireEvidenceID(failures, value.ID, itemPath+".id", "")
		if seenAttemptIDs[value.ID] {
			*failures = append(*failures, Failure{Code: "DUPLICATE_ID", Path: itemPath + ".id", Message: "attempt ID must be unique"})
		}
		seenAttemptIDs[value.ID] = true
		if value.ID == "" || value.RunID == "" || value.ActorID == "" || value.Role == "" || value.ErrorType == "" || value.FailureID == "" {
			*failures = append(*failures, Failure{Code: "INCOMPLETE_ATTEMPT", Path: fmt.Sprintf("$.attempts[%d]", index), Message: "attempt is missing identity or run binding"})
		}
		envelope, exists := byID[value.FailureID]
		if !exists || envelope.ErrorType != value.ErrorType || envelope.AttemptID != value.ID || envelope.RunID != value.RunID || envelope.ActorID != value.ActorID || envelope.Role != value.Role {
			*failures = append(*failures, Failure{Code: "INVALID_FAILURE_BINDING", Path: itemPath, Message: "attempt and failure envelope bindings must agree"})
		}
		if value.ErrorType == "UNKNOWN_CRASH" {
			envelope, exists := byID[value.FailureID]
			if !exists || envelope.Disposition != "BLOCK" || envelope.ErrorType != value.ErrorType || envelope.AttemptID != value.ID || envelope.RunID != value.RunID || envelope.ActorID != value.ActorID || envelope.Role != value.Role {
				for _, claimID := range sortedClaimIDs(claims) {
					*failures = append(*failures, claimFailure("UNKNOWN_CRASH_BLOCK", fmt.Sprintf("$.attempts[%d]", index), "unknown crash is synthesized as a blocking failure", claimID))
				}
			}
		}
	}
}

func validateSnapshot(failures *[]Failure, value programSnapshot, claims []claim, reviews map[string]review) {
	states := stringSet([]string{"PROPOSED", "QUALIFIED", "CANDIDATE", "ACCEPTED", "PUBLISHED", "BLOCKED", "STALE", "SUPERSEDED", "REVOKED"})
	complete := value.ID != "" && states[value.State] && len(value.Schemas) > 0 && len(value.Validators) > 0 && len(value.Policies) > 0 && value.SkillRevision != "" && len(value.SourceCommits) > 0 && len(value.PortCommits) > 0 && len(value.Suites) > 0 && value.ProtectedCaseSetVersion != "" && len(value.Toolchains) > 0 && len(value.Platforms) > 0 && len(value.LSPProfiles) > 0 && len(value.EvidenceRoots) > 0 && len(value.ReviewerAttestations) > 0 && value.CutoverProfile != ""
	if !complete {
		for _, claimValue := range claims {
			*failures = append(*failures, claimFailure("INCOMPLETE_SNAPSHOT", "$.snapshot", "ProgramSnapshotManifest must pin every reproducibility and cutover input", claimValue.ID))
		}
	}
	reviewIDs := make([]string, 0, len(reviews))
	for reviewID := range reviews {
		reviewIDs = append(reviewIDs, reviewID)
	}
	if !sameStringSet(value.ReviewerAttestations, reviewIDs) {
		for _, claimValue := range claims {
			*failures = append(*failures, claimFailure("INVALID_SNAPSHOT_BINDING", "$.snapshot.reviewer_attestations", "snapshot attestations must exactly pin the unique review records", claimValue.ID))
		}
	}
	if len(value.CutoverPrerequisites) == 0 {
		for _, claimValue := range claims {
			*failures = append(*failures, claimFailure("CUTOVER_BLOCKED", "$.snapshot.cutover_prerequisites", "cutover prerequisites must be declared", claimValue.ID))
		}
		return
	}
	prerequisiteNames := make([]string, 0, len(value.CutoverPrerequisites))
	for name := range value.CutoverPrerequisites {
		prerequisiteNames = append(prerequisiteNames, name)
	}
	sort.Strings(prerequisiteNames)
	for _, name := range prerequisiteNames {
		if !value.CutoverPrerequisites[name] {
			for _, claimValue := range claims {
				*failures = append(*failures, claimFailure("CUTOVER_BLOCKED", "$.snapshot.cutover_prerequisites."+name, "every cutover prerequisite must pass", claimValue.ID))
			}
			break
		}
	}
}

func validateEvolutionGraph(failures *[]Failure, value evolutionCase) {
	allowedChangeTypes := stringSet([]string{"source", "suite", "toolchain", "schema", "proof", "security", "lsp", "policy"})
	allowedNodeKinds := stringSet([]string{"source", "suite", "toolchain", "schema", "proof", "security", "lsp", "policy", "evidence", "claim"})
	allowedNodeStates := stringSet([]string{"CURRENT", "STALE"})
	nodes := make(map[string]dependencyNode, len(value.Nodes))
	for index, node := range value.Nodes {
		_, duplicate := nodes[node.ID]
		if duplicate || !stableEvidenceID.MatchString(node.ID) || !allowedNodeKinds[node.Kind] || !allowedNodeStates[node.State] || node.CorrectnessClaim == nil || (node.Kind == "claim") != *node.CorrectnessClaim {
			*failures = append(*failures, Failure{Code: "INVALID_DEPENDENCY_NODE", Path: fmt.Sprintf("$.nodes[%d]", index), Message: "dependency nodes require stable unique IDs, typed kinds, valid states, and coherent claim classification"})
		}
		nodes[node.ID] = node
	}
	adjacency := make(map[string][]dependencyEdge)
	seenEdges := make(map[string]bool, len(value.Edges))
	for index, edge := range value.Edges {
		_, fromExists := nodes[edge.From]
		_, toExists := nodes[edge.To]
		edgeIdentity := edge.From + "\x00" + edge.To
		if !fromExists || !toExists || (!allowedChangeTypes[edge.Type] && edge.Type != "evidence" && edge.Type != "lsp-navigation") || seenEdges[edgeIdentity] {
			*failures = append(*failures, Failure{Code: "INVALID_STALENESS_EDGE", Path: fmt.Sprintf("$.edges[%d]", index), Message: "StalenessEdge must have resolved endpoints and a typed dependency"})
			continue
		}
		seenEdges[edgeIdentity] = true
		adjacency[edge.From] = append(adjacency[edge.From], edge)
	}
	queue := make([]string, 0)
	seen := make(map[string]bool)
	for index, changed := range value.ChangedInputs {
		node, exists := nodes[changed.ID]
		if !allowedChangeTypes[changed.Type] || !exists || node.Kind != changed.Type {
			*failures = append(*failures, Failure{Code: "INVALID_CHANGED_INPUT", Path: fmt.Sprintf("$.changed_inputs[%d]", index), Message: "changed input must resolve and use a supported dependency type"})
			continue
		}
		if changed.Type == "lsp" {
			continue
		}
		queue = append(queue, changed.ID)
		seen[changed.ID] = true
	}
	staleClaims := make([]string, 0)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, edge := range adjacency[current] {
			if edge.Type == "lsp" || edge.Type == "lsp-navigation" || seen[edge.To] {
				continue
			}
			seen[edge.To] = true
			queue = append(queue, edge.To)
			if node := nodes[edge.To]; node.Kind == "claim" && node.CorrectnessClaim != nil && *node.CorrectnessClaim {
				staleClaims = append(staleClaims, edge.To)
			}
		}
	}
	sort.Strings(staleClaims)
	expected := append([]string(nil), value.ExpectedStaleClaimIDs...)
	sort.Strings(expected)
	if !sameOrderedStrings(staleClaims, expected) {
		*failures = append(*failures, Failure{Code: "STALE_CUT_MISMATCH", Path: "$.expected_stale_claim_ids", Message: "declared stale claims are not the minimal dependent graph cut"})
	}
	staleSet := stringSet(staleClaims)
	for _, node := range value.Nodes {
		if node.Kind != "claim" || node.CorrectnessClaim == nil || !*node.CorrectnessClaim {
			continue
		}
		if (staleSet[node.ID] && node.State != "STALE") || (!staleSet[node.ID] && node.State == "STALE") {
			*failures = append(*failures, Failure{Code: "STALE_STATE_MISMATCH", Path: "$.nodes", Message: "current claim states must exactly match the minimal stale cut", ClaimID: node.ID})
		}
	}
}

func validSnapshotTransition(from, to string) bool {
	if from == to || from == "" || to == "" {
		return false
	}
	terminal := stringSet([]string{"BLOCKED", "STALE", "SUPERSEDED", "REVOKED"})
	if terminal[from] || from == "PUBLISHED" {
		return false
	}
	allowed := map[string]string{"PROPOSED": "QUALIFIED", "QUALIFIED": "CANDIDATE", "CANDIDATE": "ACCEPTED", "ACCEPTED": "PUBLISHED"}
	if _, exists := allowed[from]; !exists {
		return false
	}
	if terminal[to] {
		return true
	}
	return allowed[from] == to
}

func isCanonicalJSON(data []byte) bool {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil || ensureJSONEOF(decoder) != nil {
		return false
	}
	canonical, err := json.Marshal(value)
	return err == nil && bytes.Equal(data, canonical)
}

func documentVersion(data []byte) string {
	var value struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return ""
	}
	return value.SchemaVersion
}

func retainedHistoricalDocumentValid(data []byte) bool {
	var value historicalEvidenceCase
	if err := decodeStrict(data, &value); err != nil || value.SchemaVersion != "1.0.0" || !stableEvidenceID.MatchString(value.CaseID) {
		return false
	}
	allowedAssurance := stringSet([]string{"observed", "differential", "bounded", "proved-model"})
	for _, entity := range value.Entities {
		if !stableEvidenceID.MatchString(entity.ID) || entity.Type == "" {
			return false
		}
		for _, edge := range entity.Edges {
			if edge.Type == "" || !stableEvidenceID.MatchString(edge.To) {
				return false
			}
		}
	}
	for _, claimValue := range value.Claims {
		if !stableEvidenceID.MatchString(claimValue.ID) || !allowedAssurance[claimValue.Assurance] || !stableEvidenceID.MatchString(claimValue.SubjectID) {
			return false
		}
		for _, evidenceID := range claimValue.EvidenceIDs {
			if !stableEvidenceID.MatchString(evidenceID) {
				return false
			}
		}
	}
	return true
}

func retainedCurrentDocumentValid(data []byte) bool {
	var value evidenceCase
	if err := decodeStrict(data, &value); err != nil {
		return false
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil || !requiredJSONFieldsPresent(raw, reflect.TypeOf(value)) {
		return false
	}
	return currentEvidenceSchemaValid(value)
}

func requiredJSONFieldsPresent(raw any, target reflect.Type) bool {
	if target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	switch target.Kind() {
	case reflect.Struct:
		object := raw.(map[string]any)
		for index := 0; index < target.NumField(); index++ {
			field := target.Field(index)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			value, exists := object[name]
			if !exists || !requiredJSONFieldsPresent(value, field.Type) {
				return false
			}
		}
	case reflect.Slice:
		values := raw.([]any)
		for _, value := range values {
			if !requiredJSONFieldsPresent(value, target.Elem()) {
				return false
			}
		}
	case reflect.Map:
		_, ok := raw.(map[string]any)
		return ok
	}
	return true
}

func decodeCanonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("base64 payload is not canonical")
	}
	return decoded, nil
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func migrationArtifactDigest(value migrationArtifact) string {
	canonical, _ := json.Marshal(struct {
		FromVersion string `json:"from_version"`
		ID          string `json:"id"`
		Lossless    bool   `json:"lossless"`
		SourceRoot  string `json:"source_root"`
		TargetRoot  string `json:"target_root"`
		ToVersion   string `json:"to_version"`
	}{
		FromVersion: value.FromVersion,
		ID:          value.ID,
		Lossless:    value.Lossless,
		SourceRoot:  value.SourceRoot,
		TargetRoot:  value.TargetRoot,
		ToVersion:   value.ToVersion,
	})
	return digestBytes(canonical)
}

func claimFailure(code, pathValue, message, claimID string) Failure {
	return Failure{Code: code, Path: pathValue, Message: message, ClaimID: claimID}
}

func requireEvidenceID(failures *[]Failure, value, pathValue, claimID string) {
	if !stableEvidenceID.MatchString(value) {
		*failures = append(*failures, claimFailure("INVALID_STABLE_ID", pathValue, "ID must be a stable lowercase dotted or hyphenated identifier", claimID))
	}
}

func readinessRank(value string) int {
	rank, exists := map[string]int{"LAB": 0, "CANDIDATE": 1, "ACCEPTED": 2, "PUBLISHED": 3}[value]
	if !exists {
		return -1
	}
	return rank
}

func assuranceArtifactRequirements() map[string][]string {
	return map[string][]string{
		"observed":                     {"EvidenceRun"},
		"differential":                 {"EvidenceRun", "Trace", "Oracle"},
		"bounded":                      {"EvidenceRun", "ProofObligation", "Model"},
		"proved-model":                 {"EvidenceRun", "ProofObligation", "Model"},
		"proved-production/refinement": {"EvidenceRun", "Trace", "MutationResult", "BenchmarkRun", "ProofObligation", "Review", "Model"},
	}
}

func entitySupportsClaim(entity evidenceEntity, claimID string) bool {
	for _, edge := range entity.Edges {
		if edge.To == claimID && (edge.Type == "supports" || edge.Type == "discharges" || edge.Type == "attests") {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy, rightCopy := append([]string(nil), left...), append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	return sameOrderedStrings(leftCopy, rightCopy)
}

func sameOrderedStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sortedClaimIDs(values map[string]claim) []string {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
