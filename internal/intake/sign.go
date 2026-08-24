package intake

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

var ownerStages = []struct {
	stage   string
	action  string
	role    string
	sandbox []string
}{
	{stage: "acquisition", action: "acquire", role: "method-schema-steward"},
	{stage: "quarantine", action: "quarantine", role: "port-implementer"},
	{stage: "qualification", action: "qualify", role: "port-implementer", sandbox: []string{"quarantined-source"}},
	{stage: PromotionStageID, action: "promote", role: "release-attestor"},
}

// BuildAndSignOwnerActions constructs the four exact US-001 stage actions and
// signs them with key material supplied separately by the protected operator.
func BuildAndSignOwnerActions(request OwnerActionRequest, privateKey ed25519.PrivateKey) ([]Action, error) {
	if request.ActorID != RequiredOwnerActor {
		return nil, deny("OWNER_MISMATCH", "$.actor_id", "request actor is not the policy-bound repository owner")
	}
	if request.KeyID == "" {
		return nil, deny("UNKNOWN_IDENTITY", "$.key_id", "owner key id is required")
	}
	if request.PolicyVersion != BasePolicyVersion || request.PolicyDigest != BasePolicyDigest || request.PolicyAmendmentVersion != SingleOwnerAmendmentVersion || request.PolicyAmendmentDigest != SingleOwnerAmendmentDigest {
		return nil, deny("POLICY_VERSION_MISMATCH", "$.policy_amendment_digest", "request must bind the frozen base policy and authoritative single-owner amendment")
	}
	if !validateDigest(request.ArtifactDigest) || !validateDigest(request.RoleSnapshotDigest) || !validateDigest(request.RevocationSnapshotDigest) || !validateDigest(request.VulnerabilitySnapshotDigest) {
		return nil, deny("INVALID_DIGEST", "$.artifact_digest", "request digests must be canonical sha256 values")
	}
	if request.IssuedAt.IsZero() || request.ExpiresAt.IsZero() || !request.ExpiresAt.After(request.IssuedAt) || request.ExpiresAt.Sub(request.IssuedAt) > 24*time.Hour {
		return nil, deny("INVALID_EXPIRATION", "$.expires_at", "authorization lifetime must be positive and at most 24 hours")
	}
	if strings.TrimSpace(request.RiskRationale) == "" {
		return nil, deny("RISK_DISPOSITION_REQUIRED", "$.risk_rationale", "owner risk rationale is required")
	}
	if len(request.Nonces) != len(ownerStages) {
		return nil, deny("INVALID_NONCE", "$.nonces", "exactly four stage nonces are required")
	}
	seenNonces := make(map[string]struct{}, len(request.Nonces))
	for _, nonce := range request.Nonces {
		if !noncePattern.MatchString(nonce) {
			return nil, deny("INVALID_NONCE", "$.nonces", "each nonce must be 16-128 conservative characters")
		}
		if _, exists := seenNonces[nonce]; exists {
			return nil, deny("INVALID_NONCE", "$.nonces", "stage nonces must be unique")
		}
		seenNonces[nonce] = struct{}{}
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, deny("INVALID_IDENTITY_KEY", "private-key", "external key is not an Ed25519 private key")
	}

	actions := make([]Action, 0, len(ownerStages))
	for index, required := range ownerStages {
		action := Action{
			ObjectID: "java-websocket-us001-inputs-v1", ObjectKind: "artifact-set",
			Stage: required.stage, Action: required.action,
			ActorID: request.ActorID, Role: required.role, KeyID: request.KeyID,
			AuthorityMode: SingleOwnerAuthorityMode,
			Company:       RequiredCompany, Project: RequiredProject, LaboratoryID: RequiredLaboratory,
			ArtifactDigest: request.ArtifactDigest,
			PolicyVersion:  request.PolicyVersion, PolicyDigest: request.PolicyDigest,
			PolicyAmendmentVersion: request.PolicyAmendmentVersion, PolicyAmendmentDigest: request.PolicyAmendmentDigest,
			RequestedSandboxAccess: slices.Clone(required.sandbox),
			Publication:            PublicationIntent{Requested: false, Classification: "QUARANTINED"},
			IssuedAt:               request.IssuedAt, ExpiresAt: request.ExpiresAt, Nonce: request.Nonces[index],
			RoleSnapshotDigest: request.RoleSnapshotDigest, RevocationSnapshotDigest: request.RevocationSnapshotDigest,
		}
		if required.stage == PromotionStageID {
			action.RiskDisposition = validRiskDisposition(request.VulnerabilitySnapshotDigest)
			action.RiskDisposition.Rationale = strings.TrimSpace(request.RiskRationale)
		}
		action.Signature = hex.EncodeToString(ed25519.Sign(privateKey, CanonicalAction(action)))
		actions = append(actions, action)
	}
	return actions, nil
}

// ReadExternalPrivateKey reads a hex-encoded Ed25519 private key from a
// protected regular file. The file must not be a symlink or group/world
// accessible. Its contents are never included in errors.
func ReadExternalPrivateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, deny("INVALID_IDENTITY_KEY", "private-key", "external private-key file is required")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, deny("INVALID_IDENTITY_KEY", "private-key", "external private-key file cannot be inspected")
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 || before.Size() <= 0 || before.Size() > 1024 {
		return nil, deny("INVALID_IDENTITY_KEY", "private-key", "private-key path must be a small, owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, deny("INVALID_IDENTITY_KEY", "private-key", "external private-key file cannot be opened")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0o077 != 0 {
		return nil, deny("INVALID_IDENTITY_KEY", "private-key", "private-key file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil || len(data) > 1024 {
		return nil, deny("INVALID_IDENTITY_KEY", "private-key", "private-key file cannot be read safely")
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, deny("INVALID_IDENTITY_KEY", "private-key", fmt.Sprintf("external key must contain exactly %d hex-encoded Ed25519 private-key bytes", ed25519.PrivateKeySize))
	}
	return ed25519.PrivateKey(decoded), nil
}
