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
	"strings"
	"sync"
	"time"
)

var noncePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)

type NonceLedger interface {
	Consume(actorID, nonce string) bool
}

type nonceClaim struct {
	actorID string
	nonce   string
}

type batchNonceLedger interface {
	ConsumeBatch(claims []nonceClaim) bool
}

type MemoryLedger struct {
	mu   sync.Mutex
	used map[string]struct{}
}

func NewMemoryLedger() *MemoryLedger { return &MemoryLedger{used: make(map[string]struct{})} }

func (l *MemoryLedger) Consume(actorID, nonce string) bool {
	return l.ConsumeBatch([]nonceClaim{{actorID: actorID, nonce: nonce}})
}

func (l *MemoryLedger) ConsumeBatch(claims []nonceClaim) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	keys := make([]string, 0, len(claims))
	for _, claim := range claims {
		key := claim.actorID + "\x00" + claim.nonce
		if _, exists := l.used[key]; exists || slices.Contains(keys, key) {
			return false
		}
		keys = append(keys, key)
	}
	for _, key := range keys {
		l.used[key] = struct{}{}
	}
	return true
}

// FileLedger is the protected caller's durable nonce-consumption primitive.
// The filename is a hash of the signed actor/nonce tuple, so candidate text
// cannot escape the ledger directory. O_EXCL makes concurrent reuse fail.
type FileLedger struct {
	Directory string
}

func (l FileLedger) Consume(actorID, nonce string) bool {
	return l.ConsumeBatch([]nonceClaim{{actorID: actorID, nonce: nonce}})
}

func (l FileLedger) ConsumeBatch(claims []nonceClaim) bool {
	if l.Directory == "" || len(claims) == 0 {
		return false
	}
	for _, claim := range claims {
		if claim.actorID == "" || !noncePattern.MatchString(claim.nonce) {
			return false
		}
	}
	if err := os.MkdirAll(l.Directory, 0o700); err != nil {
		return false
	}
	lockPath := filepath.Join(l.Directory, ".nonce-batch.lock")
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false
	}
	defer func() {
		_ = lock.Close()
		_ = os.Remove(lockPath)
		_ = syncDirectory(l.Directory)
	}()

	paths := make([]string, 0, len(claims))
	seen := make(map[string]struct{}, len(claims))
	for _, claim := range claims {
		sum := sha256.Sum256([]byte(claim.actorID + "\x00" + claim.nonce))
		path := filepath.Join(l.Directory, hex.EncodeToString(sum[:])+".consumed")
		if _, duplicate := seen[path]; duplicate {
			return false
		}
		seen[path] = struct{}{}
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return false
		}
		paths = append(paths, path)
	}
	created := make([]string, 0, len(paths))
	rollback := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	for index, path := range paths {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			rollback()
			return false
		}
		created = append(created, path)
		claim := claims[index]
		if _, err := file.WriteString(DigestBytes(CanonicalAction(Action{ActorID: claim.actorID, Nonce: claim.nonce})) + "\n"); err != nil {
			_ = file.Close()
			rollback()
			return false
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			rollback()
			return false
		}
		if err := file.Close(); err != nil {
			rollback()
			return false
		}
	}
	if err := syncDirectory(l.Directory); err != nil {
		rollback()
		return false
	}
	return true
}

func ValidateRoleStage(stage, role string, sandbox []string, publication PublicationIntent) error {
	requiredRole := map[string]string{
		"acquisition":    "method-schema-steward",
		"quarantine":     "port-implementer",
		"qualification":  "port-implementer",
		PromotionStageID: "release-attestor",
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
	if err := validateAuthorization(action, identities, snapshot, now); err != nil {
		return err
	}
	if ledger == nil || !ledger.Consume(action.ActorID, action.Nonce) {
		return deny("REPLAYED_APPROVAL", "$.nonce", "nonce has already been consumed")
	}
	return nil
}

func validateAuthorization(action Action, identities map[string]Identity, snapshot Snapshot, now time.Time) error {
	if action.Company != RequiredCompany || action.Project != RequiredProject || action.LaboratoryID != RequiredLaboratory {
		return deny("CROSS_COMPANY_REFERENCE", "$.company", "authorization scope does not match the laboratory")
	}
	if action.AuthorityMode != SingleOwnerAuthorityMode {
		return deny("AUTHORITY_MODE_MISMATCH", "$.authority_mode", "action does not use the policy-bound single-owner authority mode")
	}
	if action.ActorID != RequiredOwnerActor {
		return deny("OWNER_MISMATCH", "$.actor_id", "action actor is not the policy-bound repository owner")
	}
	if action.PolicyVersion != BasePolicyVersion || action.PolicyDigest != BasePolicyDigest || action.PolicyAmendmentVersion != SingleOwnerAmendmentVersion || action.PolicyAmendmentDigest != SingleOwnerAmendmentDigest {
		return deny("POLICY_VERSION_MISMATCH", "$.policy_amendment_digest", "action does not bind the frozen base policy and single-owner amendment")
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
	if err := validateActionRiskDisposition(action); err != nil {
		return err
	}
	identity, ok := identities[action.ActorID]
	if !ok || identity.ActorID != action.ActorID || identity.KeyID != action.KeyID {
		return deny("UNKNOWN_IDENTITY", "$.actor_id", "actor/key is not in the authoritative registry")
	}
	if identity.AuthorityMode != SingleOwnerAuthorityMode {
		return deny("AUTHORITY_MODE_MISMATCH", "$.actor_id", "authoritative identity is not registered for single-owner mode")
	}
	if !slices.Contains(identity.AllowedRoles, action.Role) {
		return deny("ROLE_CONFLICT", "$.role", "action role is not present in the owner's authoritative allowed roles")
	}
	if identity.Revoked {
		return deny("REVOKED_AUTHORIZATION", "$.actor_id", "identity is revoked")
	}
	if snapshot.RoleDigest != action.RoleSnapshotDigest || snapshot.RevocationDigest != action.RevocationSnapshotDigest {
		return deny("REVOKED_AUTHORIZATION", "$.revocation_snapshot_digest", "authoritative snapshots differ from the signed action")
	}
	if !validateDigest(action.ArtifactDigest) || !validateDigest(action.PolicyDigest) || !validateDigest(action.PolicyAmendmentDigest) || !validateDigest(action.RoleSnapshotDigest) || !validateDigest(action.RevocationSnapshotDigest) {
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
	return nil
}

func validateActionRiskDisposition(action Action) error {
	if action.Stage != PromotionStageID {
		if action.RiskDisposition != nil {
			return deny("RISK_DISPOSITION_MISMATCH", "$.risk_disposition", "risk disposition is allowed only on the promotion action")
		}
		return nil
	}
	if action.RiskDisposition == nil {
		return deny("RISK_DISPOSITION_REQUIRED", "$.risk_disposition", "promotion must sign the exact retained Autobahn risk disposition")
	}
	disposition := action.RiskDisposition
	if disposition.Decision != "ACCEPT_RETAINED_FINDINGS_FOR_QUARANTINED_LAB_ONLY" ||
		disposition.ArtifactID != "autobahn-linux-amd64-image" ||
		disposition.ArtifactDigest != AutobahnManifestDigest ||
		!validateDigest(disposition.VulnerabilitySnapshotDigest) ||
		disposition.CriticalCount != 12 || disposition.HighCount != 147 ||
		disposition.Scope != "QUARANTINED_LABORATORY_QUALIFICATION_ONLY" ||
		disposition.ProductionUseAuthorized || disposition.PublicationAuthorized ||
		strings.TrimSpace(disposition.Rationale) == "" {
		return deny("RISK_DISPOSITION_MISMATCH", "$.risk_disposition", "signed risk disposition does not accept only the exact retained 12 critical and 147 high findings for quarantined laboratory qualification")
	}
	return nil
}

func validRiskDisposition(vulnerabilitySnapshotDigest string) *RiskDisposition {
	return &RiskDisposition{
		Decision:                    "ACCEPT_RETAINED_FINDINGS_FOR_QUARANTINED_LAB_ONLY",
		ArtifactID:                  "autobahn-linux-amd64-image",
		ArtifactDigest:              AutobahnManifestDigest,
		VulnerabilitySnapshotDigest: vulnerabilitySnapshotDigest,
		CriticalCount:               12,
		HighCount:                   147,
		Scope:                       "QUARANTINED_LABORATORY_QUALIFICATION_ONLY",
		ProductionUseAuthorized:     false,
		PublicationAuthorized:       false,
		Rationale:                   "Owner accepts the exact retained findings only for quarantined laboratory qualification.",
	}
}
