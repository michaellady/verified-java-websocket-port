package foundation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	// MaxInputBytes bounds both validation seams.
	MaxInputBytes         = 1 << 20
	expectedSchemaVersion = "1.0.0"
	expectedPolicyVersion = "foundation-1.0.0"
	expectedCompany       = "open-source-projects"
	expectedProject       = "verified-java-to-rust-port"
)

// Failure is a stable, machine-readable validation denial.
type Failure struct {
	Code       string `json:"code"`
	Path       string `json:"path"`
	Message    string `json:"message"`
	ClaimID    string `json:"claim_id,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	Repository string `json:"repository,omitempty"`
	Obligation string `json:"obligation,omitempty"`
}

type registry struct {
	SchemaVersion string       `json:"schema_version"`
	Company       string       `json:"company"`
	Project       string       `json:"project"`
	Repositories  []repository `json:"repositories"`
	SourcePins    []sourcePin  `json:"source_pins"`
}

type repository struct {
	ID                         string   `json:"id"`
	Name                       string   `json:"name"`
	RepositoryURL              string   `json:"repository_url"`
	Kind                       string   `json:"kind"`
	Status                     string   `json:"status"`
	Visibility                 string   `json:"visibility"`
	License                    string   `json:"license"`
	Owners                     []string `json:"owners"`
	DefaultBranch              string   `json:"default_branch"`
	ProtectionPolicy           string   `json:"protection_policy"`
	ReleasePolicy              string   `json:"release_policy"`
	HQRegistrationPath         string   `json:"hq_registration_path"`
	SourcePinID                string   `json:"source_pin_id,omitempty"`
	SourceLicenseCompatibility string   `json:"source_license_compatibility"`
	NameTrademarkCompatibility string   `json:"name_trademark_compatibility"`
}

type sourcePin struct {
	ID                   string    `json:"id"`
	RepositoryURL        string    `json:"repository_url"`
	ImmutableCommit      string    `json:"immutable_commit"`
	ReleaseOrTag         string    `json:"release_or_tag"`
	License              string    `json:"license"`
	LicensePath          string    `json:"license_path"`
	LicenseSHA256        string    `json:"license_sha256"`
	JavaVersion          string    `json:"java_version"`
	BuildTool            buildTool `json:"build_tool"`
	InspectDirectories   []string  `json:"inspect_directories"`
	TranslateDirectories []string  `json:"translate_directories"`
}

type buildTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type foundationPolicy struct {
	SchemaVersion              string                `json:"schema_version"`
	PolicyVersion              string                `json:"policy_version"`
	Company                    string                `json:"company"`
	Project                    string                `json:"project"`
	AuthorityModel             string                `json:"authority_model"`
	Roles                      []policyRole          `json:"roles"`
	SignedActionRequiredFields []string              `json:"signed_action_required_fields"`
	SignedAction               signedActionPolicy    `json:"signed_action"`
	TrustedInputContract       trustedInputContract  `json:"trusted_input_contract"`
	PromotionStages            []promotionStage      `json:"promotion_stages"`
	ArtifactRequirements       []string              `json:"artifact_requirements"`
	ForbiddenSandboxAccess     []string              `json:"forbidden_sandbox_access"`
	AllowedSandboxAccess       []string              `json:"allowed_sandbox_access"`
	Sandbox                    sandboxPolicy         `json:"sandbox"`
	StorageClassifications     []string              `json:"storage_classifications"`
	PublicationClassifications []string              `json:"publication_classifications"`
	Storage                    storagePolicy         `json:"storage"`
	RepositoryEnforcement      repositoryEnforcement `json:"repository_enforcement"`
}

type policyRole struct {
	ID               string   `json:"id"`
	IncompatibleWith []string `json:"incompatible_with"`
}

type signedActionPolicy struct {
	MaximumLifetimeHours int    `json:"maximum_lifetime_hours"`
	NonceReuse           string `json:"nonce_reuse"`
	ArtifactBinding      string `json:"artifact_binding"`
	Ledger               string `json:"ledger"`
	Revocation           string `json:"revocation"`
	Rotation             string `json:"rotation"`
}

type trustedInputContract struct {
	SignatureVerification  string `json:"signature_verification"`
	RoleSnapshot           string `json:"role_snapshot"`
	NonceSnapshot          string `json:"nonce_snapshot"`
	ArtifactDigestSnapshot string `json:"artifact_digest_snapshot"`
	ClassificationSnapshot string `json:"classification_snapshot"`
	TimeSource             string `json:"time_source"`
}

type promotionStage struct {
	ID           string   `json:"id"`
	Requirements []string `json:"requirements"`
	Executor     string   `json:"executor"`
}

type sandboxPolicy struct {
	ExecutionAllowedOnlyAfterQuarantine bool     `json:"execution_allowed_only_after_quarantine"`
	Disposable                          bool     `json:"disposable"`
	SourceMount                         string   `json:"source_mount"`
	Secrets                             string   `json:"secrets"`
	Network                             string   `json:"network"`
	Caches                              string   `json:"caches"`
	Resources                           string   `json:"resources"`
	HostileExecutables                  []string `json:"hostile_executables"`
}

type storagePolicy struct {
	Git                  []string `json:"git"`
	ImmutablePublicBlobs []string `json:"immutable_public_blobs"`
	ProtectedStore       []string `json:"protected_store"`
	Unclassified         string   `json:"unclassified"`
}

type repositoryEnforcement struct {
	Permissions                 string   `json:"permissions"`
	ProtectedEnvironments       []string `json:"protected_environments"`
	IndependentApprovals        int      `json:"independent_approvals"`
	SignedCommitsOrAttestations bool     `json:"signed_commits_or_attestations"`
	DirectMainPush              bool     `json:"direct_main_push"`
	AutomaticDependencyUpdates  bool     `json:"automatic_dependency_updates"`
}

type policyCandidate struct {
	Company                string       `json:"company"`
	Project                string       `json:"project"`
	ActorID                string       `json:"actor_id"`
	Role                   string       `json:"role"`
	SnapshotRoles          []string     `json:"snapshot_roles"`
	ArtifactDigest         string       `json:"artifact_digest"`
	ExpectedArtifactDigest string       `json:"expected_artifact_digest"`
	PolicyVersion          string       `json:"policy_version"`
	IssuedAt               string       `json:"issued_at"`
	ExpiresAt              string       `json:"expires_at"`
	Nonce                  string       `json:"nonce"`
	PriorNonces            []string     `json:"prior_nonces"`
	RequestedSandboxAccess []string     `json:"requested_sandbox_access"`
	Publication            *publication `json:"publication"`
}

type publication struct {
	Requested      *bool  `json:"requested"`
	Classification string `json:"classification"`
}

var (
	commitPattern = regexp.MustCompile("^[0-9a-f]{40}$")
	sha256Pattern = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
	bareSHA256    = regexp.MustCompile("^[0-9a-f]{64}$")
	noncePattern  = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
	identifier    = regexp.MustCompile("^[a-z0-9][a-z0-9.-]*$")
	githubOwner   = regexp.MustCompile("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
	githubSegment = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]*$")
)

// ValidateRegistry validates the program registry without mutating it.
func ValidateRegistry(data []byte) []Failure {
	var value registry
	if err := decodeStrict(data, &value); err != nil {
		return []Failure{{Code: "INVALID_JSON", Path: "$", Message: err.Error()}}
	}

	failures := make([]Failure, 0)
	require(&failures, value.SchemaVersion, "$.schema_version")
	require(&failures, value.Company, "$.company")
	require(&failures, value.Project, "$.project")
	if value.SchemaVersion != "" && value.SchemaVersion != expectedSchemaVersion {
		failures = append(failures, Failure{Code: "INVALID_SCHEMA_VERSION", Path: "$.schema_version", Message: "registry schema version is not supported"})
	}
	if value.Company != expectedCompany || value.Project != expectedProject {
		failures = append(failures, Failure{Code: "INVALID_SCOPE", Path: "$.company", Message: "registry must remain inside the selected company and project"})
	}
	if len(value.Repositories) == 0 {
		failures = append(failures, Failure{Code: "MISSING_FIELD", Path: "$.repositories", Message: "at least one repository is required"})
	}
	if len(value.SourcePins) == 0 {
		failures = append(failures, Failure{Code: "MISSING_FIELD", Path: "$.source_pins", Message: "at least one source pin is required"})
	}
	if len(value.Repositories) != 7 || len(value.SourcePins) != 4 {
		failures = append(failures, Failure{Code: "INVALID_TOPOLOGY", Path: "$", Message: "registry requires one program, four laboratories, one held-out store, one publication repository, and four source pins"})
	}

	sourceCounts := make(map[string]int, len(value.SourcePins))
	for index, pin := range value.SourcePins {
		itemPath := fmt.Sprintf("$.source_pins[%d]", index)
		requireIdentifier(&failures, pin.ID, itemPath+".id")
		requireURL(&failures, pin.RepositoryURL, itemPath+".repository_url")
		require(&failures, pin.ReleaseOrTag, itemPath+".release_or_tag")
		require(&failures, pin.License, itemPath+".license")
		requireRelativePath(&failures, pin.LicensePath, itemPath+".license_path")
		require(&failures, pin.JavaVersion, itemPath+".java_version")
		require(&failures, pin.BuildTool.Name, itemPath+".build_tool.name")
		require(&failures, pin.BuildTool.Version, itemPath+".build_tool.version")
		requirePathList(&failures, pin.InspectDirectories, itemPath+".inspect_directories")
		requirePathList(&failures, pin.TranslateDirectories, itemPath+".translate_directories")
		if !commitPattern.MatchString(pin.ImmutableCommit) {
			failures = append(failures, Failure{Code: "INVALID_SOURCE_PIN", Path: itemPath + ".immutable_commit", Message: "commit must be a full lowercase 40-character Git object ID"})
		}
		if !bareSHA256.MatchString(pin.LicenseSHA256) {
			failures = append(failures, Failure{Code: "INVALID_LICENSE_HASH", Path: itemPath + ".license_sha256", Message: "license hash must be a lowercase SHA-256"})
		}
		sourceCounts[pin.ID]++
	}
	for id, count := range sourceCounts {
		if id != "" && count > 1 {
			failures = append(failures, Failure{Code: "DUPLICATE_SOURCE_PIN", Path: "$.source_pins", Message: fmt.Sprintf("source pin %q appears %d times", id, count)})
		}
	}

	repositoryIDs := make(map[string]int, len(value.Repositories))
	repositoryNames := make(map[string]int, len(value.Repositories))
	repositoryURLs := make(map[string]int, len(value.Repositories))
	expectedHQPath := "companies/manifest.yaml#companies." + expectedCompany + ".repos"
	validKinds := stringSet([]string{"program", "laboratory", "held-out", "publication"})
	validStatuses := stringSet([]string{"planned", "existing"})
	kindCounts := make(map[string]int, len(validKinds))
	for index, repository := range value.Repositories {
		itemPath := fmt.Sprintf("$.repositories[%d]", index)
		requireIdentifier(&failures, repository.ID, itemPath+".id")
		requireIdentifier(&failures, repository.Name, itemPath+".name")
		requireURL(&failures, repository.RepositoryURL, itemPath+".repository_url")
		if !validKinds[repository.Kind] {
			failures = append(failures, Failure{Code: "INVALID_REPOSITORY_KIND", Path: itemPath + ".kind", Message: "repository kind is not recognized"})
		}
		kindCounts[repository.Kind]++
		if !validStatuses[repository.Status] {
			failures = append(failures, Failure{Code: "INVALID_REPOSITORY_STATUS", Path: itemPath + ".status", Message: "repository status must be planned or existing"})
		}
		require(&failures, repository.License, itemPath+".license")
		require(&failures, repository.DefaultBranch, itemPath+".default_branch")
		require(&failures, repository.ProtectionPolicy, itemPath+".protection_policy")
		require(&failures, repository.ReleasePolicy, itemPath+".release_policy")
		require(&failures, repository.SourceLicenseCompatibility, itemPath+".source_license_compatibility")
		require(&failures, repository.NameTrademarkCompatibility, itemPath+".name_trademark_compatibility")
		if len(repository.Owners) != 1 || strings.TrimSpace(repository.Owners[0]) == "" {
			failures = append(failures, Failure{Code: "AMBIGUOUS_OWNER", Path: itemPath + ".owners", Message: "exactly one non-blank owner is required"})
		} else if !githubOwner.MatchString(repository.Owners[0]) {
			failures = append(failures, Failure{Code: "INVALID_OWNER", Path: itemPath + ".owners[0]", Message: "owner must be a canonical GitHub owner identifier"})
		} else if repositoryOwner, ok := canonicalRepositoryOwner(repository.RepositoryURL); ok && !strings.EqualFold(repository.Owners[0], repositoryOwner) {
			failures = append(failures, Failure{Code: "OWNER_URL_MISMATCH", Path: itemPath + ".owners[0]", Message: "owner must match the repository URL owner segment under GitHub's case-insensitive owner semantics"})
		}
		if repository.Visibility != "PUBLIC" && repository.Visibility != "PRIVATE" {
			failures = append(failures, Failure{Code: "INVALID_VISIBILITY", Path: itemPath + ".visibility", Message: "visibility must be PUBLIC or PRIVATE"})
		}
		if (repository.Kind == "held-out" && repository.Visibility != "PRIVATE") || (repository.Kind != "held-out" && validKinds[repository.Kind] && repository.Visibility != "PUBLIC") {
			failures = append(failures, Failure{Code: "INVALID_VISIBILITY", Path: itemPath + ".visibility", Message: "program, laboratories, and publication are public; held-out storage is private"})
		}
		if repository.HQRegistrationPath != expectedHQPath {
			failures = append(failures, Failure{Code: "INVALID_HQ_REGISTRATION", Path: itemPath + ".hq_registration_path", Message: "registration target must remain inside the selected company"})
		}
		if repository.Kind == "laboratory" {
			if strings.TrimSpace(repository.SourcePinID) == "" {
				failures = append(failures, Failure{Code: "MISSING_SOURCE_PIN", Path: itemPath + ".source_pin_id", Message: "laboratory repositories require exactly one source pin"})
			} else if sourceCounts[repository.SourcePinID] != 1 {
				failures = append(failures, Failure{Code: "INVALID_SOURCE_PIN_REFERENCE", Path: itemPath + ".source_pin_id", Message: "source pin reference must resolve exactly once"})
			}
		} else if strings.TrimSpace(repository.SourcePinID) != "" {
			failures = append(failures, Failure{Code: "UNEXPECTED_SOURCE_PIN", Path: itemPath + ".source_pin_id", Message: "only laboratory repositories may reference a Java source pin"})
		}
		if repository.Kind == "publication" && (repository.Name != "mike-skills" || repository.RepositoryURL != "https://github.com/michaellady/mike-skills" || repository.Status != "existing" || repository.License != "UNLICENSED" || !strings.Contains(repository.ReleasePolicy, "publication-blocked-until-license-adopted")) {
			failures = append(failures, Failure{Code: "PUBLICATION_LICENSE_BLOCK_REQUIRED", Path: itemPath + ".license", Message: "michaellady/mike-skills must remain UNLICENSED and publication-blocked until a license is adopted"})
		}
		repositoryIDs[repository.ID]++
		repositoryNames[repository.Name]++
		repositoryURLs[repository.RepositoryURL]++
	}
	appendDuplicates(&failures, repositoryIDs, "repository id")
	appendDuplicates(&failures, repositoryNames, "repository name")
	appendDuplicates(&failures, repositoryURLs, "repository URL")
	if kindCounts["program"] != 1 || kindCounts["laboratory"] != 4 || kindCounts["held-out"] != 1 || kindCounts["publication"] != 1 {
		failures = append(failures, Failure{Code: "INVALID_TOPOLOGY", Path: "$.repositories", Message: "repository kind cardinality does not match the approved program topology"})
	}

	for id, count := range sourceCounts {
		if id == "" || count != 1 {
			continue
		}
		labReferences := 0
		for _, repository := range value.Repositories {
			if repository.Kind == "laboratory" && repository.SourcePinID == id {
				labReferences++
			}
		}
		if labReferences != 1 {
			failures = append(failures, Failure{Code: "AMBIGUOUS_SOURCE_PIN_OWNERSHIP", Path: "$.source_pins", Message: fmt.Sprintf("source pin %q must be referenced by exactly one laboratory", id)})
		}
	}
	return failures
}

// ValidatePolicy evaluates a candidate action against the foundation policy without mutating either input.
func ValidatePolicy(policyData, candidateData []byte) []Failure {
	return validatePolicyAt(policyData, candidateData, time.Now().UTC())
}

func validatePolicyAt(policyData, candidateData []byte, now time.Time) []Failure {
	var policy foundationPolicy
	if err := decodeStrict(policyData, &policy); err != nil {
		return []Failure{{Code: "INVALID_POLICY", Path: "$", Message: err.Error()}}
	}
	if err := validateFoundationPolicy(policy); err != nil {
		return []Failure{{Code: "INVALID_POLICY", Path: "$", Message: err.Error()}}
	}
	var candidate policyCandidate
	if err := decodeStrict(candidateData, &candidate); err != nil {
		return []Failure{{Code: "INVALID_CANDIDATE", Path: "$", Message: err.Error()}}
	}

	failures := make([]Failure, 0)
	requireSigned(&failures, candidate.Company, "$.company")
	requireSigned(&failures, candidate.Project, "$.project")
	requireSigned(&failures, candidate.ActorID, "$.actor_id")
	requireSigned(&failures, candidate.Role, "$.role")
	requireSigned(&failures, candidate.ArtifactDigest, "$.artifact_digest")
	requireSigned(&failures, candidate.PolicyVersion, "$.policy_version")
	requireSigned(&failures, candidate.IssuedAt, "$.issued_at")
	requireSigned(&failures, candidate.ExpiresAt, "$.expires_at")
	requireSigned(&failures, candidate.Nonce, "$.nonce")
	if candidate.RequestedSandboxAccess == nil {
		failures = append(failures, Failure{Code: "MISSING_SIGNED_FIELD", Path: "$.requested_sandbox_access", Message: "signed sandbox action intent is missing"})
	}
	if candidate.Publication == nil {
		failures = append(failures, Failure{Code: "MISSING_SIGNED_FIELD", Path: "$.publication", Message: "signed publication action intent is missing"})
	} else if candidate.Publication.Requested == nil {
		failures = append(failures, Failure{Code: "MISSING_SIGNED_FIELD", Path: "$.publication.requested", Message: "signed publication requested flag is missing"})
	}
	if strings.TrimSpace(candidate.ExpectedArtifactDigest) == "" {
		failures = append(failures, Failure{Code: "MISSING_FIELD", Path: "$.expected_artifact_digest", Message: "independently approved artifact digest is required"})
	}
	if candidate.PolicyVersion != policy.PolicyVersion {
		failures = append(failures, Failure{Code: "POLICY_VERSION_MISMATCH", Path: "$.policy_version", Message: "candidate policy version does not match the evaluated policy"})
	}
	if candidate.Company != policy.Company || candidate.Project != policy.Project {
		failures = append(failures, Failure{Code: "CROSS_COMPANY_REFERENCE", Path: "$.company", Message: "candidate company and project must match the policy scope"})
	}

	knownRoles := make(map[string]policyRole, len(policy.Roles))
	for _, role := range policy.Roles {
		knownRoles[role.ID] = role
	}
	if _, ok := knownRoles[candidate.Role]; candidate.Role != "" && !ok {
		failures = append(failures, Failure{Code: "UNKNOWN_ROLE", Path: "$.role", Message: "signed role is not defined by the evaluated policy"})
	}
	roleCounts := make(map[string]int, len(candidate.SnapshotRoles))
	for _, role := range candidate.SnapshotRoles {
		roleCounts[role]++
		if _, ok := knownRoles[role]; !ok {
			failures = append(failures, Failure{Code: "UNKNOWN_ROLE", Path: "$.snapshot_roles", Message: "role snapshot contains an undefined role"})
		}
	}
	roleConflict := len(candidate.SnapshotRoles) != 1 || roleCounts[candidate.Role] != 1
	for left, leftCount := range roleCounts {
		if leftCount != 1 {
			roleConflict = true
		}
		for right := range roleCounts {
			if left != right && stringSet(knownRoles[left].IncompatibleWith)[right] {
				roleConflict = true
			}
		}
	}
	if roleConflict {
		failures = append(failures, Failure{Code: "ROLE_CONFLICT", Path: "$.snapshot_roles", Message: "actor must have exactly one compatible artifact-scoped role for the snapshot"})
	}
	publicationRequested := candidate.Publication != nil && candidate.Publication.Requested != nil && *candidate.Publication.Requested
	if publicationRequested && candidate.Role != "release-attestor" {
		failures = append(failures, Failure{Code: "ROLE_ACTION_MISMATCH", Path: "$.role", Message: "publication requests require the release-attestor role"})
	}
	if len(candidate.RequestedSandboxAccess) != 0 && candidate.Role != "port-implementer" {
		failures = append(failures, Failure{Code: "ROLE_ACTION_MISMATCH", Path: "$.role", Message: "sandbox access requests require the port-implementer role"})
	}

	for _, priorNonce := range candidate.PriorNonces {
		if priorNonce == candidate.Nonce {
			failures = append(failures, Failure{Code: "REPLAYED_APPROVAL", Path: "$.nonce", Message: "approval nonce already exists in the supplied protected ledger snapshot"})
			break
		}
	}
	if !noncePattern.MatchString(candidate.Nonce) && candidate.Nonce != "" {
		failures = append(failures, Failure{Code: "INVALID_NONCE", Path: "$.nonce", Message: "nonce must be 8 to 128 unambiguous characters"})
	}
	if !sha256Pattern.MatchString(candidate.ArtifactDigest) {
		failures = append(failures, Failure{Code: "INVALID_ARTIFACT_DIGEST", Path: "$.artifact_digest", Message: "artifact digest must be an explicit lowercase SHA-256"})
	}
	if !sha256Pattern.MatchString(candidate.ExpectedArtifactDigest) {
		failures = append(failures, Failure{Code: "INVALID_ARTIFACT_DIGEST", Path: "$.expected_artifact_digest", Message: "expected digest must be an explicit lowercase SHA-256"})
	}
	if candidate.ArtifactDigest != candidate.ExpectedArtifactDigest {
		failures = append(failures, Failure{Code: "ARTIFACT_DRIFT", Path: "$.artifact_digest", Message: "candidate bytes do not match the independently approved digest"})
	}

	issuedAt, issuedErr := time.Parse(time.RFC3339, candidate.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, candidate.ExpiresAt)
	if issuedErr != nil {
		failures = append(failures, Failure{Code: "INVALID_EXPIRATION", Path: "$.issued_at", Message: "issued_at must be RFC3339"})
	}
	if expiresErr != nil {
		failures = append(failures, Failure{Code: "INVALID_EXPIRATION", Path: "$.expires_at", Message: "expires_at must be RFC3339"})
	}
	if issuedErr == nil && expiresErr == nil {
		maximumLifetime := time.Duration(policy.SignedAction.MaximumLifetimeHours) * time.Hour
		if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > maximumLifetime {
			failures = append(failures, Failure{Code: "INVALID_EXPIRATION", Path: "$.expires_at", Message: "authorization lifetime must be positive and within policy maximum"})
		}
		if issuedAt.After(now.Add(5 * time.Minute)) {
			failures = append(failures, Failure{Code: "INVALID_EXPIRATION", Path: "$.issued_at", Message: "authorization cannot be issued in the future"})
		}
		if !expiresAt.After(now) {
			failures = append(failures, Failure{Code: "EXPIRED_AUTHORIZATION", Path: "$.expires_at", Message: "authorization has expired"})
		}
	}

	allowedAccess := stringSet(policy.AllowedSandboxAccess)
	for _, requestedAccess := range candidate.RequestedSandboxAccess {
		if !allowedAccess[requestedAccess] {
			failures = append(failures, Failure{Code: "FORBIDDEN_SANDBOX_ACCESS", Path: "$.requested_sandbox_access", Message: "sandbox request is not explicitly allowlisted"})
			break
		}
	}
	storageClasses := stringSet(policy.StorageClassifications)
	publicationClassification := ""
	if candidate.Publication != nil {
		publicationClassification = candidate.Publication.Classification
	}
	if candidate.Publication != nil && !storageClasses[publicationClassification] {
		code := "UNCLASSIFIED_OBJECT"
		if publicationRequested {
			code = "UNCLASSIFIED_PUBLICATION"
		}
		failures = append(failures, Failure{Code: code, Path: "$.publication.classification", Message: "every object requires exactly one recognized classification"})
	} else if publicationRequested && !stringSet(policy.PublicationClassifications)[publicationClassification] {
		failures = append(failures, Failure{Code: "UNCLASSIFIED_PUBLICATION", Path: "$.publication.classification", Message: "publication accepts only PUBLIC or PUBLIC_DERIVED"})
	}
	return failures
}

func validateFoundationPolicy(policy foundationPolicy) error {
	if policy.SchemaVersion != expectedSchemaVersion || policy.PolicyVersion != expectedPolicyVersion || policy.Company != expectedCompany || policy.Project != expectedProject {
		return errors.New("foundation policy has an invalid schema version, policy version, or scope")
	}
	if policy.AuthorityModel != "existing-identities-only" {
		return errors.New("authority model must reuse existing identities")
	}
	expectedRoles := []string{"method-schema-steward", "port-implementer", "oracle-held-out-custodian", "release-attestor"}
	if len(policy.Roles) != len(expectedRoles) {
		return errors.New("foundation policy must define exactly four trust roles")
	}
	roles := make(map[string]policyRole, len(policy.Roles))
	for _, role := range policy.Roles {
		if role.ID == "" {
			return errors.New("foundation policy contains a blank role")
		}
		if _, exists := roles[role.ID]; exists {
			return errors.New("foundation policy contains a duplicate role")
		}
		roles[role.ID] = role
	}
	if !setEquals(mapKeys(roles), expectedRoles) {
		return errors.New("foundation policy trust-role set is invalid")
	}
	for _, roleID := range expectedRoles {
		if !setEquals(roles[roleID].IncompatibleWith, without(expectedRoles, roleID)) {
			return fmt.Errorf("role %q must be mutually incompatible with every other role", roleID)
		}
	}
	expectedSignedFields := []string{"actor_id", "role", "company", "project", "artifact_digest", "policy_version", "issued_at", "expires_at", "nonce", "requested_sandbox_access", "publication"}
	if !setEquals(policy.SignedActionRequiredFields, expectedSignedFields) {
		return errors.New("signed action field binding is incomplete")
	}
	if policy.SignedAction.MaximumLifetimeHours != 24 ||
		policy.SignedAction.NonceReuse != "deny" ||
		policy.SignedAction.ArtifactBinding != "sha256" ||
		policy.SignedAction.Ledger != "PROTECTED_HELD_OUT append-only nonce and approval ledger" ||
		policy.SignedAction.Revocation != "any role, identity, artifact, vulnerability, or policy revocation invalidates dependent approvals" ||
		policy.SignedAction.Rotation != "rotate workload credentials and signing material before expiration or immediately after compromise" {
		return errors.New("signed action expiration, replay, digest, ledger, rotation, or revocation policy is invalid")
	}
	if policy.TrustedInputContract.SignatureVerification != "the protected promotion caller verifies every signed required field, including requested_sandbox_access and publication action intent, against the existing identity before invoking validate-policy" ||
		policy.TrustedInputContract.RoleSnapshot != "snapshot_roles is an authoritative artifact-scoped projection from repository permissions and protected environments, never candidate-authored data" ||
		policy.TrustedInputContract.NonceSnapshot != "prior_nonces is an authoritative read from the PROTECTED_HELD_OUT append-only ledger, never candidate-authored data" ||
		policy.TrustedInputContract.ArtifactDigestSnapshot != "expected_artifact_digest is an authoritative independently approved fresh-byte digest supplied by the protected caller, never candidate-authored data" ||
		policy.TrustedInputContract.ClassificationSnapshot != "publication.classification is an authoritative classifier projection supplied by the protected caller, never candidate-authored data" ||
		policy.TrustedInputContract.TimeSource != "expiration is evaluated against the validator host UTC clock; the signed issued_at field is not a verifier clock substitute" {
		return errors.New("trusted signature, role, nonce, digest, classification, and time input contract is incomplete")
	}
	type stageContract struct {
		executor     string
		requirements []string
	}
	expectedStages := map[string]stageContract{
		"acquisition": {
			executor:     "method-schema-steward",
			requirements: []string{"immutable upstream URL and revision", "artifact digest", "license hash", "automatic updates disabled"},
		},
		"quarantine": {
			executor:     "port-implementer",
			requirements: []string{"no scripts", "no secrets", "static inventory only", "read-only source", "classification QUARANTINED"},
		},
		"qualification": {
			executor:     "port-implementer",
			requirements: []string{"dependency lock graph", "SBOM", "vulnerability snapshot", "sandbox evidence", "replay command", "expiration"},
		},
		"independent-promotion": {
			executor:     "release-attestor",
			requirements: []string{"fresh-byte digest match", "independent approval", "unused nonce", "unexpired signature", "revocation check"},
		},
	}
	stageIDs := make([]string, 0, len(policy.PromotionStages))
	for _, stage := range policy.PromotionStages {
		stageIDs = append(stageIDs, stage.ID)
		expected, ok := expectedStages[stage.ID]
		if !ok || stage.Executor != expected.executor || !setEquals(stage.Requirements, expected.requirements) {
			return errors.New("promotion stage has an invalid executor or requirement contract")
		}
	}
	if !setEquals(stageIDs, mapKeysOf(expectedStages)) || !setEquals(policy.ArtifactRequirements, []string{"source provenance", "transitive dependency lock graph", "SBOM", "vulnerability state", "approval", "expiration", "rotation", "revocation", "replayable accepted bytes"}) {
		return errors.New("promotion pipeline or artifact requirements are incomplete")
	}
	if !setEquals(policy.ForbiddenSandboxAccess, []string{"protected-held-out", "canonical-evidence", "release-signing", "production-credentials", "cross-company-data"}) ||
		!setEquals(policy.AllowedSandboxAccess, []string{"quarantined-source"}) {
		return errors.New("sandbox access lists do not match the approved deny and allow boundaries")
	}
	requiredHostile := []string{"Maven plugins", "Gradle plugins", "annotation processors", "build.rs", "proc macros", "LSP imports", "dependencies"}
	if !policy.Sandbox.ExecutionAllowedOnlyAfterQuarantine ||
		!policy.Sandbox.Disposable ||
		policy.Sandbox.SourceMount != "read-only" ||
		policy.Sandbox.Secrets != "none" ||
		policy.Sandbox.Network != "deny-by-default with audited allowlist" ||
		policy.Sandbox.Caches != "isolated and content-addressed" ||
		policy.Sandbox.Resources != "bounded CPU, memory, processes, disk, and wall time" ||
		!setEquals(policy.Sandbox.HostileExecutables, requiredHostile) {
		return errors.New("hostile execution sandbox policy is incomplete")
	}
	if !setEquals(policy.StorageClassifications, []string{"PUBLIC", "PUBLIC_DERIVED", "INTERNAL", "PROTECTED_HELD_OUT", "QUARANTINED"}) ||
		!setEquals(policy.PublicationClassifications, []string{"PUBLIC", "PUBLIC_DERIVED"}) ||
		policy.Storage.Unclassified != "deny" ||
		!setEquals(policy.Storage.Git, []string{"schemas", "small public fixtures", "methodology", "evidence indexes"}) ||
		!setEquals(policy.Storage.ImmutablePublicBlobs, []string{"large replayable public evidence"}) ||
		!setEquals(policy.Storage.ProtectedStore, []string{"held-out cases", "expected outputs", "nonce ledger", "custodian-only evaluator material"}) {
		return errors.New("storage classification or trusted-store policy is incomplete")
	}
	if policy.RepositoryEnforcement.Permissions != "repository teams map existing identities to exactly one artifact-scoped role per snapshot" ||
		!setEquals(policy.RepositoryEnforcement.ProtectedEnvironments, []string{"held-out", "evidence-promotion", "publication"}) ||
		policy.RepositoryEnforcement.IndependentApprovals < 2 ||
		!policy.RepositoryEnforcement.SignedCommitsOrAttestations ||
		policy.RepositoryEnforcement.DirectMainPush ||
		policy.RepositoryEnforcement.AutomaticDependencyUpdates {
		return errors.New("repository identity separation or release enforcement is incomplete")
	}
	return nil
}

func decodeStrict(data []byte, destination any) error {
	if len(data) > MaxInputBytes {
		return fmt.Errorf("input exceeds %d bytes", MaxInputBytes)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, "$"); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func consumeJSONValue(decoder *json.Decoder, currentPath string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil && currentPath != "$.publication.requested" {
		return errors.New("JSON null is not allowed by the strict schema")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter == json.Delim('{') {
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key := keyToken.(string)
			if seen[key] {
				return fmt.Errorf("duplicate JSON field %q at %s", key, currentPath)
			}
			seen[key] = true
			if err := consumeJSONValue(decoder, currentPath+"."+key); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	for index := 0; decoder.More(); index++ {
		if err := consumeJSONValue(decoder, fmt.Sprintf("%s[%d]", currentPath, index)); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func ensureJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func require(failures *[]Failure, value, fieldPath string) {
	if strings.TrimSpace(value) == "" {
		*failures = append(*failures, Failure{Code: "MISSING_FIELD", Path: fieldPath, Message: "required field is blank"})
	}
}

func requireSigned(failures *[]Failure, value, fieldPath string) {
	if strings.TrimSpace(value) == "" {
		*failures = append(*failures, Failure{Code: "MISSING_SIGNED_FIELD", Path: fieldPath, Message: "signed binding field is blank"})
	}
}

func requireIdentifier(failures *[]Failure, value, fieldPath string) {
	if !identifier.MatchString(value) {
		*failures = append(*failures, Failure{Code: "INVALID_IDENTIFIER", Path: fieldPath, Message: "identifier must be a lowercase, path-free slug"})
	}
}

func requireURL(failures *[]Failure, value, fieldPath string) {
	if _, ok := canonicalRepositoryOwner(value); !ok {
		*failures = append(*failures, Failure{Code: "INVALID_REPOSITORY_URL", Path: fieldPath, Message: "repository URL must be a canonical HTTPS GitHub owner/repository URL"})
	}
}

func canonicalRepositoryOwner(value string) (string, bool) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", false
	}
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if parsed.Scheme != "https" ||
		parsed.Host != "github.com" ||
		parsed.User != nil ||
		parsed.Opaque != "" ||
		parsed.RawPath != "" ||
		parsed.RawQuery != "" ||
		parsed.ForceQuery ||
		parsed.Fragment != "" ||
		parsed.String() != value ||
		strings.Contains(value, "%") ||
		strings.HasSuffix(parsed.Path, "/") ||
		path.Clean(parsed.Path) != parsed.Path ||
		len(segments) != 2 ||
		!githubSegment.MatchString(segments[0]) ||
		!githubSegment.MatchString(segments[1]) ||
		strings.HasSuffix(segments[1], ".git") {
		return "", false
	}
	return segments[0], true
}

func requireRelativePath(failures *[]Failure, value, fieldPath string) {
	if strings.TrimSpace(value) == "" {
		*failures = append(*failures, Failure{Code: "MISSING_FIELD", Path: fieldPath, Message: "required path is blank"})
		return
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "../") || value == ".." || strings.ContainsRune(value, rune(92)) || path.Clean(value) != value || value == "." || strings.Contains(value, "//") {
		*failures = append(*failures, Failure{Code: "INVALID_PATH", Path: fieldPath, Message: "path must be a clean relative slash-separated path"})
	}
}

func requirePathList(failures *[]Failure, values []string, fieldPath string) {
	if len(values) == 0 {
		*failures = append(*failures, Failure{Code: "MISSING_FIELD", Path: fieldPath, Message: "at least one path is required"})
		return
	}
	for index, value := range values {
		requireRelativePath(failures, value, fmt.Sprintf("%s[%d]", fieldPath, index))
	}
}

func appendDuplicates(failures *[]Failure, counts map[string]int, label string) {
	for value, count := range counts {
		if value != "" && count > 1 {
			*failures = append(*failures, Failure{Code: "DUPLICATE_REPOSITORY", Path: "$.repositories", Message: fmt.Sprintf("%s %q appears %d times", label, value, count)})
		}
	}
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func setEquals(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftSet := stringSet(left)
	if len(leftSet) != len(left) {
		return false
	}
	for _, value := range right {
		if !leftSet[value] {
			return false
		}
	}
	return true
}

func without(values []string, omitted string) []string {
	result := make([]string, 0, len(values)-1)
	for _, value := range values {
		if value != omitted {
			result = append(result, value)
		}
	}
	return result
}

func mapKeys(values map[string]policyRole) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func mapKeysOf[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
