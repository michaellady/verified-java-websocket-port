package intake

import (
	"fmt"
	"time"
)

const (
	RequiredCompany    = "open-source-projects"
	RequiredProject    = "verified-java-websocket-port"
	RequiredLaboratory = "lab-java-websocket"

	AutobahnManifestDigest = "sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
)

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

type Action struct {
	ObjectID                 string            `json:"object_id"`
	ObjectKind               string            `json:"object_kind"`
	Stage                    string            `json:"stage"`
	Action                   string            `json:"action"`
	ActorID                  string            `json:"actor_id"`
	Role                     string            `json:"role"`
	KeyID                    string            `json:"key_id"`
	Company                  string            `json:"company"`
	Project                  string            `json:"project"`
	LaboratoryID             string            `json:"laboratory_id"`
	ArtifactDigest           string            `json:"artifact_digest"`
	PolicyVersion            string            `json:"policy_version"`
	PolicyDigest             string            `json:"policy_digest"`
	RequestedSandboxAccess   []string          `json:"requested_sandbox_access"`
	Publication              PublicationIntent `json:"publication"`
	IssuedAt                 time.Time         `json:"issued_at"`
	ExpiresAt                time.Time         `json:"expires_at"`
	Nonce                    string            `json:"nonce"`
	RoleSnapshotDigest       string            `json:"role_snapshot_digest"`
	RevocationSnapshotDigest string            `json:"revocation_snapshot_digest"`
	Signature                string            `json:"signature"`
}

type Identity struct {
	ActorID   string `json:"actor_id"`
	Role      string `json:"role"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key_ed25519_hex"`
	Revoked   bool   `json:"revoked"`
}

type Snapshot struct {
	RoleDigest       string
	RevocationDigest string
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
