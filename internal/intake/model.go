package intake

import (
	"fmt"
	"time"
)

const (
	RequiredCompany    = "open-source-projects"
	RequiredProject    = "verified-java-websocket-port"
	RequiredLaboratory = "lab-java-websocket"
	RequiredOwnerActor = "github:michaellady"

	SingleOwnerAuthorityMode    = "single-owner"
	BasePolicyVersion           = "foundation-1.0.0"
	BasePolicyDigest            = "sha256:12a11bc4015ad5fd52e447053b8c3a7a3bc0b9e79389737ec7fc6bac0d465c54"
	SingleOwnerAmendmentVersion = "java-websocket-single-owner-1.0.0"
	SingleOwnerAmendmentDigest  = "sha256:ee247975a3a2cf10e8d93221df85505b8ed882630a5658662e9d716afe617cec"
	PromotionStageID            = "owner-promotion"
	SingleOwnerBlockedStatus    = "BLOCKED_PENDING_OWNER_ACTION_AND_RISK_DISPOSITION"
	SingleOwnerAuthorizedStatus = "OWNER_AUTHORIZED_PENDING_BYTE_COMMIT"
	SingleOwnerPromotedStatus   = "SINGLE_OWNER_PROMOTED_NO_INDEPENDENT_REVIEW"

	AutobahnManifestDigest = "sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
	AutobahnConfigDigest   = "sha256:b0475418d42ae284876bd695f0282fbe6684e00f745d787b095d60e55727a06f"
)

var SingleOwnerActionRoles = []string{"method-schema-steward", "port-implementer", "oracle-held-out-custodian", "release-attestor"}

// Finding is the stable fail-closed interface exposed by the intake verifier.
type Finding struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (f *Finding) Error() string {
	return fmt.Sprintf("%s at %s: %s", f.Code, f.Path, f.Message)
}

func deny(code, path, message string) error {
	return &Finding{Code: code, Path: path, Message: message}
}

type PublicationIntent struct {
	Requested      bool   `json:"requested"`
	Classification string `json:"classification"`
}

// RiskDisposition is part of the signed promotion action. It accepts only the
// retained Autobahn image findings and never grants production or publication
// authority.
type RiskDisposition struct {
	Decision                    string `json:"decision"`
	ArtifactID                  string `json:"artifact_id"`
	ArtifactDigest              string `json:"artifact_digest"`
	VulnerabilitySnapshotDigest string `json:"vulnerability_snapshot_digest"`
	CriticalCount               int    `json:"critical_count"`
	HighCount                   int    `json:"high_count"`
	Scope                       string `json:"scope"`
	ProductionUseAuthorized     bool   `json:"production_use_authorized"`
	PublicationAuthorized       bool   `json:"publication_authorized"`
	Rationale                   string `json:"rationale"`
}

type Action struct {
	ObjectID                 string            `json:"object_id"`
	ObjectKind               string            `json:"object_kind"`
	Stage                    string            `json:"stage"`
	Action                   string            `json:"action"`
	ActorID                  string            `json:"actor_id"`
	Role                     string            `json:"role"`
	KeyID                    string            `json:"key_id"`
	AuthorityMode            string            `json:"authority_mode"`
	Company                  string            `json:"company"`
	Project                  string            `json:"project"`
	LaboratoryID             string            `json:"laboratory_id"`
	ArtifactDigest           string            `json:"artifact_digest"`
	PolicyVersion            string            `json:"policy_version"`
	PolicyDigest             string            `json:"policy_digest"`
	PolicyAmendmentVersion   string            `json:"policy_amendment_version"`
	PolicyAmendmentDigest    string            `json:"policy_amendment_digest"`
	RequestedSandboxAccess   []string          `json:"requested_sandbox_access"`
	Publication              PublicationIntent `json:"publication"`
	RiskDisposition          *RiskDisposition  `json:"risk_disposition,omitempty"`
	IssuedAt                 time.Time         `json:"issued_at"`
	ExpiresAt                time.Time         `json:"expires_at"`
	Nonce                    string            `json:"nonce"`
	RoleSnapshotDigest       string            `json:"role_snapshot_digest"`
	RevocationSnapshotDigest string            `json:"revocation_snapshot_digest"`
	Signature                string            `json:"signature"`
}

type Identity struct {
	ActorID       string   `json:"actor_id"`
	AuthorityMode string   `json:"authority_mode"`
	Role          string   `json:"role,omitempty"`
	AllowedRoles  []string `json:"allowed_roles"`
	KeyID         string   `json:"key_id"`
	PublicKey     string   `json:"public_key_ed25519_hex"`
	Revoked       bool     `json:"revoked"`
}

// OwnerActionRequest contains only public action scope. The caller supplies
// Ed25519 private key bytes separately to BuildAndSignOwnerActions.
type OwnerActionRequest struct {
	ActorID                     string    `json:"actor_id"`
	KeyID                       string    `json:"key_id"`
	ArtifactDigest              string    `json:"artifact_digest"`
	PolicyVersion               string    `json:"policy_version"`
	PolicyDigest                string    `json:"policy_digest"`
	PolicyAmendmentVersion      string    `json:"policy_amendment_version"`
	PolicyAmendmentDigest       string    `json:"policy_amendment_digest"`
	IssuedAt                    time.Time `json:"issued_at"`
	ExpiresAt                   time.Time `json:"expires_at"`
	RoleSnapshotDigest          string    `json:"role_snapshot_digest"`
	RevocationSnapshotDigest    string    `json:"revocation_snapshot_digest"`
	VulnerabilitySnapshotDigest string    `json:"vulnerability_snapshot_digest"`
	Nonces                      []string  `json:"nonces"`
	RiskRationale               string    `json:"risk_rationale"`
}

type Snapshot struct {
	RoleDigest       string `json:"role_digest"`
	RevocationDigest string `json:"revocation_digest"`
}

type ContainerDescriptor struct {
	Reference      string `json:"reference"`
	Platform       string `json:"platform"`
	ManifestDigest string `json:"manifest_digest"`
	ConfigDigest   string `json:"config_digest"`
}

type Object struct {
	ID     string
	Digest string
	Bytes  []byte
}
