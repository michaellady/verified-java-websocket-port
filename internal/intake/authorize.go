package intake

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

var noncePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)

type NonceLedger interface {
	Consume(actorID, nonce string) bool
}

type NonceClaim struct {
	ActorID string
	Nonce   string
}

type BatchNonceLedger interface {
	NonceLedger
	ConsumeBatch(claims []NonceClaim) bool
}

type nonceBatchManifest struct {
	SchemaVersion string   `json:"schema_version"`
	Claims        []string `json:"claims"`
}

type MemoryLedger struct {
	mu   sync.Mutex
	used map[string]struct{}
}

func NewMemoryLedger() *MemoryLedger { return &MemoryLedger{used: make(map[string]struct{})} }

func (l *MemoryLedger) Consume(actorID, nonce string) bool {
	return l.ConsumeBatch([]NonceClaim{{ActorID: actorID, Nonce: nonce}})
}

func (l *MemoryLedger) ConsumeBatch(claims []NonceClaim) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	keys := make([]string, 0, len(claims))
	for _, claim := range claims {
		key := claim.ActorID + "\x00" + claim.Nonce
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

// FileLedger commits a nonce batch as one content-addressed manifest under a
// serialized, protected-directory lock. Each claim digest remains individually
// replay-detectable across committed batches.
type FileLedger struct {
	Directory string
}

func (l FileLedger) Consume(actorID, nonce string) bool {
	return l.ConsumeBatch([]NonceClaim{{ActorID: actorID, Nonce: nonce}})
}

func (l FileLedger) ConsumeBatch(claims []NonceClaim) bool {
	if l.Directory == "" || len(claims) == 0 {
		return false
	}
	for _, claim := range claims {
		if claim.ActorID == "" || !noncePattern.MatchString(claim.Nonce) {
			return false
		}
	}
	if err := os.MkdirAll(l.Directory, 0o700); err != nil {
		return false
	}
	directoryInfo, err := os.Lstat(l.Directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm()&0o077 != 0 {
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

	committed, ok := l.readCommittedClaims(lockPath)
	if !ok {
		return false
	}
	claimDigests := make([]string, 0, len(claims))
	batchClaims := make(map[string]struct{}, len(claims))
	for _, claim := range claims {
		digest := nonceClaimDigest(claim)
		if _, duplicate := batchClaims[digest]; duplicate {
			return false
		}
		if _, replayed := committed[digest]; replayed {
			return false
		}
		batchClaims[digest] = struct{}{}
		claimDigests = append(claimDigests, digest)
	}
	sort.Strings(claimDigests)
	manifestBytes, err := CanonicalJSON(nonceBatchManifest{SchemaVersion: "1.0.0", Claims: claimDigests})
	if err != nil {
		return false
	}
	finalPath := filepath.Join(l.Directory, DigestBytes(manifestBytes)[7:]+".batch")
	temporary, err := os.CreateTemp(l.Directory, ".nonce-batch-*.tmp")
	if err != nil {
		return false
	}
	temporaryPath := temporary.Name()
	committedManifest := false
	defer func() {
		_ = temporary.Close()
		if !committedManifest {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false
	}
	if _, err := temporary.Write(manifestBytes); err != nil {
		return false
	}
	if err := temporary.Sync(); err != nil {
		return false
	}
	if err := temporary.Close(); err != nil {
		return false
	}
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return false
	}
	committedManifest = true
	if err := syncDirectory(l.Directory); err != nil {
		return false
	}
	return true
}

func (l FileLedger) readCommittedClaims(lockPath string) (map[string]struct{}, bool) {
	entries, err := os.ReadDir(l.Directory)
	if err != nil {
		return nil, false
	}
	committed := make(map[string]struct{})
	for _, entry := range entries {
		path := filepath.Join(l.Directory, entry.Name())
		if path == lockPath {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".nonce-batch-") && strings.HasSuffix(entry.Name(), ".tmp") {
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || os.Remove(path) != nil {
				return nil, false
			}
			continue
		}
		nameParts := strings.Split(entry.Name(), ".")
		if len(nameParts) != 2 || !isLowerHexDigest(nameParts[0]) {
			return nil, false
		}
		data, ok := readProtectedLedgerFile(path)
		if !ok {
			return nil, false
		}
		switch nameParts[1] {
		case "consumed":
			if !validateDigest(strings.TrimSpace(string(data))) {
				return nil, false
			}
			committed[nameParts[0]] = struct{}{}
		case "batch":
			if DigestBytes(data)[7:] != nameParts[0] {
				return nil, false
			}
			var manifest nonceBatchManifest
			if err := DecodeStrict(data, &manifest); err != nil || manifest.SchemaVersion != "1.0.0" || len(manifest.Claims) == 0 || len(manifest.Claims) > 128 || !sort.StringsAreSorted(manifest.Claims) {
				return nil, false
			}
			for index, claimDigest := range manifest.Claims {
				if !isLowerHexDigest(claimDigest) || (index > 0 && manifest.Claims[index-1] == claimDigest) {
					return nil, false
				}
				if _, duplicate := committed[claimDigest]; duplicate {
					return nil, false
				}
				committed[claimDigest] = struct{}{}
			}
		default:
			return nil, false
		}
	}
	return committed, true
}

func readProtectedLedgerFile(path string) ([]byte, bool) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || !hasSingleLink(before) || before.Mode().Perm()&0o077 != 0 || before.Size() <= 0 || before.Size() > 32<<10 {
		return nil, false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || !hasSingleLink(after) || after.Mode().Perm()&0o077 != 0 {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(file, (32<<10)+1))
	return data, err == nil && len(data) <= 32<<10
}

func hasSingleLink(info os.FileInfo) bool {
	value := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if !value.IsValid() {
		return false
	}
	field := value.FieldByName("Nlink")
	return field.IsValid() && field.CanUint() && field.Uint() == 1
}

func nonceClaimDigest(claim NonceClaim) string {
	sum := sha256.Sum256([]byte(claim.ActorID + "\x00" + claim.Nonce))
	return hex.EncodeToString(sum[:])
}

func isLowerHexDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
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
