package intake

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"
)

var noncePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)

type NonceLedger interface {
	Consume(actorID, nonce string) bool
}

type MemoryLedger struct {
	mu   sync.Mutex
	used map[string]struct{}
}

func NewMemoryLedger() *MemoryLedger { return &MemoryLedger{used: make(map[string]struct{})} }

func (l *MemoryLedger) Consume(actorID, nonce string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := actorID + "\x00" + nonce
	if _, exists := l.used[key]; exists {
		return false
	}
	l.used[key] = struct{}{}
	return true
}

// FileLedger is the protected caller's durable nonce-consumption primitive.
// The filename is a hash of the signed actor/nonce tuple, so candidate text
// cannot escape the ledger directory. O_EXCL makes concurrent reuse fail.
type FileLedger struct {
	Directory string
}

func (l FileLedger) Consume(actorID, nonce string) bool {
	if l.Directory == "" || actorID == "" || !noncePattern.MatchString(nonce) {
		return false
	}
	if err := os.MkdirAll(l.Directory, 0o700); err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(actorID + "\x00" + nonce))
	name := hex.EncodeToString(sum[:]) + ".consumed"
	file, err := os.OpenFile(filepath.Join(l.Directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return false
	}
	if err != nil {
		return false
	}
	if _, err := file.WriteString(DigestBytes(CanonicalAction(Action{ActorID: actorID, Nonce: nonce})) + "\n"); err != nil {
		_ = file.Close()
		return false
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false
	}
	if err := file.Close(); err != nil {
		return false
	}
	return syncDirectory(l.Directory) == nil
}

func ValidateRoleStage(stage, role string, sandbox []string, publication PublicationIntent) error {
	requiredRole := map[string]string{
		"acquisition":           "method-schema-steward",
		"quarantine":            "port-implementer",
		"qualification":         "port-implementer",
		"independent-promotion": "release-attestor",
	}[stage]
	if requiredRole == "" {
		return deny("UNKNOWN_STAGE", "$.stage", "stage is outside the frozen promotion policy")
	}
	if role != requiredRole {
		return deny("ROLE_ACTION_MISMATCH", "$.role", "role cannot execute this stage")
	}
	if stage == "qualification" {
		if !slices.Equal(sandbox, []string{"quarantined-source"}) {
			return deny("ROLE_ACTION_MISMATCH", "$.requested_sandbox_access", "qualification requires only quarantined-source")
		}
	} else if len(sandbox) != 0 {
		return deny("ROLE_ACTION_MISMATCH", "$.requested_sandbox_access", "sandbox access is forbidden for this stage")
	}
	if publication.Requested {
		if role != "release-attestor" {
			return deny("ROLE_ACTION_MISMATCH", "$.publication.requested", "publication requires release-attestor")
		}
		if publication.Classification != "PUBLIC" && publication.Classification != "PUBLIC_DERIVED" {
			return deny("UNCLASSIFIED_PUBLICATION", "$.publication.classification", "only public classifications may be published")
		}
	}
	return nil
}

func Authorize(action Action, identities map[string]Identity, snapshot Snapshot, ledger NonceLedger, now time.Time) error {
	if action.Company != RequiredCompany || action.Project != RequiredProject || action.LaboratoryID != RequiredLaboratory {
		return deny("CROSS_COMPANY_REFERENCE", "$.company", "authorization scope does not match the laboratory")
	}
	if !noncePattern.MatchString(action.Nonce) {
		return deny("INVALID_NONCE", "$.nonce", "nonce must be 16-128 conservative characters")
	}
	if action.IssuedAt.IsZero() || action.ExpiresAt.IsZero() || !action.ExpiresAt.After(action.IssuedAt) || action.ExpiresAt.Sub(action.IssuedAt) > 24*time.Hour || action.IssuedAt.After(now.Add(5*time.Minute)) {
		return deny("INVALID_EXPIRATION", "$.expires_at", "authorization lifetime must be positive, at most 24 hours, and not future-issued")
	}
	if !now.Before(action.ExpiresAt) {
		return deny("EXPIRED_AUTHORIZATION", "$.expires_at", "authorization has expired")
	}
	if err := ValidateRoleStage(action.Stage, action.Role, action.RequestedSandboxAccess, action.Publication); err != nil {
		return err
	}
	identity, ok := identities[action.ActorID]
	if !ok || identity.KeyID != action.KeyID {
		return deny("UNKNOWN_IDENTITY", "$.actor_id", "actor/key is not in the authoritative registry")
	}
	if identity.Role != action.Role {
		return deny("ROLE_CONFLICT", "$.role", "action role differs from authoritative identity role")
	}
	if identity.Revoked {
		return deny("REVOKED_AUTHORIZATION", "$.actor_id", "identity is revoked")
	}
	if snapshot.RoleDigest != action.RoleSnapshotDigest || snapshot.RevocationDigest != action.RevocationSnapshotDigest {
		return deny("REVOKED_AUTHORIZATION", "$.revocation_snapshot_digest", "authoritative snapshots differ from the signed action")
	}
	if !validateDigest(action.ArtifactDigest) || !validateDigest(action.PolicyDigest) || !validateDigest(action.RoleSnapshotDigest) || !validateDigest(action.RevocationSnapshotDigest) {
		return deny("INVALID_DIGEST", "$.artifact_digest", "signed digests must be canonical sha256 values")
	}
	publicKey, err := hex.DecodeString(identity.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || identity.PublicKey == "" {
		return deny("INVALID_IDENTITY_KEY", "$.actor_id", "identity key is not a valid Ed25519 public key")
	}
	signature, err := hex.DecodeString(action.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(publicKey), CanonicalAction(action), signature) {
		return deny("INVALID_SIGNATURE", "$.signature", "signature does not bind the complete action")
	}
	if ledger == nil || !ledger.Consume(action.ActorID, action.Nonce) {
		return deny("REPLAYED_APPROVAL", "$.nonce", "nonce has already been consumed")
	}
	return nil
}
