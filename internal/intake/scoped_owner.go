package intake

import (
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// ScopedDigestBinding names one retained root that is part of an owner-signed
// subject. Names and digests are sorted and closed by the consuming policy.
type ScopedDigestBinding struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// ScopedOwnerSubject is generic signed intent. It carries no key material and
// makes non-production/non-public/non-independent limits part of the signature.
type ScopedOwnerSubject struct {
	SchemaVersion            string                `json:"schema_version"`
	Kind                     string                `json:"kind"`
	ArtifactDigest           string                `json:"artifact_digest"`
	SubjectRoles             []string              `json:"subject_roles"`
	Operation                string                `json:"operation"`
	Company                  string                `json:"company"`
	Project                  string                `json:"project"`
	LaboratoryID             string                `json:"laboratory_id"`
	PolicyDigest             string                `json:"policy_digest"`
	EvidenceBindings         []ScopedDigestBinding `json:"evidence_bindings"`
	Scope                    string                `json:"scope"`
	HistoricalKeyID          string                `json:"historical_key_id"`
	ProductionUseAuthorized  bool                  `json:"production_use_authorized"`
	PublicationAuthorized    bool                  `json:"publication_authorized"`
	IndependentReviewClaimed bool                  `json:"independent_review_claimed"`
}

// ScopedOwnerStatement records one scoped action. Public keys are intentionally
// absent: verification uses only the caller's TrustedAuthority.
type ScopedOwnerStatement struct {
	SchemaVersion            string    `json:"schema_version"`
	SubjectDigest            string    `json:"subject_digest"`
	Stage                    string    `json:"stage"`
	Action                   string    `json:"action"`
	ActorID                  string    `json:"actor_id"`
	Role                     string    `json:"role"`
	KeyID                    string    `json:"key_id"`
	AuthorityMode            string    `json:"authority_mode"`
	IssuedAt                 time.Time `json:"issued_at"`
	ExpiresAt                time.Time `json:"expires_at"`
	Nonce                    string    `json:"nonce"`
	RoleSnapshotDigest       string    `json:"role_snapshot_digest"`
	RevocationSnapshotDigest string    `json:"revocation_snapshot_digest"`
	Signature                string    `json:"signature_ed25519_hex"`
}

type ScopedStatementRequirement struct {
	Stage      string
	Action     string
	SignerRole string
}

// ScopedOwnerRequirements is security judgment supplied by the consuming
// package. This package provides canonical signature and atomic nonce transport.
type ScopedOwnerRequirements struct {
	OwnerActorID         string
	Kind                 string
	Statements           []ScopedStatementRequirement
	SubjectRoles         []string
	HistoricalKeyID      string
	RequireDurableLedger bool
}

// ScopedOwnerValidation proves only that the supplied statements validate
// against the supplied TrustedAuthority. It does not prove that the caller is
// protected or that the authority originated outside candidate control.
type ScopedOwnerValidation struct {
	subject          ScopedOwnerSubject
	subjectDigest    string
	statementDigests []string
	bindingDigest    string
}

func ScopedOwnerSubjectDigest(subject ScopedOwnerSubject) (string, error) {
	canonical, err := CanonicalJSON(subject)
	if err != nil {
		return "", err
	}
	return DigestBytes(canonical), nil
}

func canonicalScopedOwnerStatement(statement ScopedOwnerStatement) ([]byte, error) {
	statement.Signature = ""
	return CanonicalJSON(statement)
}

// SignScopedOwnerStatement signs fixture/operator-supplied intent without
// loading key material. Protected callers remain responsible for key custody.
func SignScopedOwnerStatement(statement ScopedOwnerStatement, privateKey ed25519.PrivateKey) (ScopedOwnerStatement, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return ScopedOwnerStatement{}, deny("INVALID_IDENTITY_KEY", "private-key", "external key is not an Ed25519 private key")
	}
	canonical, err := canonicalScopedOwnerStatement(statement)
	if err != nil {
		return ScopedOwnerStatement{}, err
	}
	statement.Signature = hex.EncodeToString(ed25519.Sign(privateKey, canonical))
	return statement, nil
}

// VerifyScopedOwnerStatements validates the complete required action sequence
// before atomically consuming any nonce. The caller, not this transport helper,
// is responsible for establishing that TrustedAuthority is protected from the
// candidate.
func VerifyScopedOwnerStatements(subject ScopedOwnerSubject, statements []ScopedOwnerStatement, authority TrustedAuthority, requirements ScopedOwnerRequirements, now time.Time) (ScopedOwnerValidation, error) {
	subjectDigest, err := validateScopedOwnerSubject(subject, requirements)
	if err != nil {
		return ScopedOwnerValidation{}, err
	}
	if authority.AuthorityMode != SingleOwnerAuthorityMode || authority.OwnerActorID != requirements.OwnerActorID {
		return ScopedOwnerValidation{}, deny("OWNER_MISMATCH", "$.authority", "trusted authority does not bind the required owner")
	}
	identity, ok := authority.Identities[requirements.OwnerActorID]
	if !ok || identity.ActorID != requirements.OwnerActorID || identity.KeyID != requirements.HistoricalKeyID {
		return ScopedOwnerValidation{}, deny("UNKNOWN_IDENTITY", "$.authority.identity", "required owner key id is absent from supplied authority")
	}
	if identity.AuthorityMode != SingleOwnerAuthorityMode || identity.Revoked {
		return ScopedOwnerValidation{}, deny("REVOKED_AUTHORIZATION", "$.authority.identity", "owner role or revocation state is not currently authorized")
	}
	for _, statement := range requirements.Statements {
		if !slices.Contains(identity.AllowedRoles, statement.SignerRole) {
			return ScopedOwnerValidation{}, deny("REVOKED_AUTHORIZATION", "$.authority.identity", "a required signer role is not currently authorized")
		}
	}
	publicKey, err := hex.DecodeString(identity.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || hex.EncodeToString(publicKey) != identity.PublicKey {
		return ScopedOwnerValidation{}, deny("INVALID_IDENTITY_KEY", "$.authority.identity", "supplied authority key is not canonical Ed25519")
	}
	snapshot, ok := authority.Snapshots[requirements.OwnerActorID]
	if !ok || !validateDigest(snapshot.RoleDigest) || !validateDigest(snapshot.RevocationDigest) {
		return ScopedOwnerValidation{}, deny("REVOKED_AUTHORIZATION", "$.authority.snapshot", "current role and revocation snapshots are required")
	}
	if len(statements) != len(requirements.Statements) {
		return ScopedOwnerValidation{}, deny("ACTION_SCOPE_MISMATCH", "$.statements", "the exact scoped statement sequence is required")
	}
	statementDigests := make([]string, 0, len(statements))
	claims := make([]NonceClaim, 0, len(statements))
	for index, statement := range statements {
		if err := validateScopedOwnerStatement(statement, requirements.Statements[index], subjectDigest, identity, snapshot, requirements, now, ed25519.PublicKey(publicKey)); err != nil {
			return ScopedOwnerValidation{}, err
		}
		canonical, err := canonicalScopedOwnerStatement(statement)
		if err != nil {
			return ScopedOwnerValidation{}, err
		}
		statementDigests = append(statementDigests, DigestBytes(canonical))
		claims = append(claims, NonceClaim{ActorID: statement.ActorID, Nonce: statement.Nonce})
	}
	ledger, ok := authority.Ledger.(BatchNonceLedger)
	if !ok || ledger == nil {
		return ScopedOwnerValidation{}, deny("REPLAYED_APPROVAL", "$.nonce", "an atomic nonce-batch ledger is required")
	}
	if requirements.RequireDurableLedger {
		fileLedger, durable := durableFileLedger(authority.Ledger)
		if !durable || !filepath.IsAbs(filepath.Clean(fileLedger.Directory)) || filepath.Clean(fileLedger.Directory) == string(filepath.Separator) {
			return ScopedOwnerValidation{}, deny("INVALID_PROMOTION_STORE", "$.authority.ledger", "executable promotion requires a specific absolute durable FileLedger")
		}
	}
	if !ledger.ConsumeBatch(claims) {
		return ScopedOwnerValidation{}, deny("REPLAYED_APPROVAL", "$.nonce", "statement nonce batch was replayed or could not be committed atomically")
	}
	bindingBytes, err := CanonicalJSON(struct {
		SubjectDigest    string   `json:"subject_digest"`
		StatementDigests []string `json:"statement_digests"`
	}{subjectDigest, statementDigests})
	if err != nil {
		return ScopedOwnerValidation{}, err
	}
	return ScopedOwnerValidation{
		subject: subject, subjectDigest: subjectDigest,
		statementDigests: slices.Clone(statementDigests), bindingDigest: DigestBytes(bindingBytes),
	}, nil
}

func validateScopedOwnerSubject(subject ScopedOwnerSubject, requirements ScopedOwnerRequirements) (string, error) {
	if requirements.OwnerActorID == "" || requirements.Kind == "" || requirements.HistoricalKeyID == "" || len(requirements.SubjectRoles) == 0 || len(requirements.Statements) == 0 {
		return "", deny("ACTION_SCOPE_MISMATCH", "$.requirements", "scoped owner requirements are incomplete")
	}
	for _, statement := range requirements.Statements {
		if statement.Stage == "" || statement.Action == "" || statement.SignerRole == "" {
			return "", deny("ACTION_SCOPE_MISMATCH", "$.requirements.statements", "scoped statement requirements are incomplete")
		}
	}
	if subject.SchemaVersion != "1.0.0" || subject.Kind != requirements.Kind || subject.HistoricalKeyID != requirements.HistoricalKeyID || !slices.Equal(subject.SubjectRoles, requirements.SubjectRoles) {
		return "", deny("ACTION_SCOPE_MISMATCH", "$.subject", "subject kind, roles, or required retained key-id binding changed")
	}
	if subject.Company == "" || subject.Project == "" || subject.LaboratoryID == "" || subject.Operation == "" || subject.Scope == "" || !validateDigest(subject.ArtifactDigest) || !validateDigest(subject.PolicyDigest) {
		return "", deny("INVALID_DIGEST", "$.subject", "subject scope and canonical digests are required")
	}
	if subject.ProductionUseAuthorized || subject.PublicationAuthorized || subject.IndependentReviewClaimed {
		return "", deny("ASSURANCE_CEILING_EXCEEDED", "$.subject", "scoped owner statements cannot authorize production, publication, or independent review")
	}
	if len(subject.EvidenceBindings) == 0 || len(subject.EvidenceBindings) > 32 || !sort.SliceIsSorted(subject.EvidenceBindings, func(i, j int) bool { return subject.EvidenceBindings[i].Name < subject.EvidenceBindings[j].Name }) {
		return "", deny("ACTION_SCOPE_MISMATCH", "$.subject.evidence_bindings", "evidence bindings must be nonempty, sorted, and bounded")
	}
	for index, binding := range subject.EvidenceBindings {
		if strings.TrimSpace(binding.Name) == "" || binding.Name != strings.TrimSpace(binding.Name) || !validateDigest(binding.Digest) || index > 0 && subject.EvidenceBindings[index-1].Name == binding.Name {
			return "", deny("ACTION_SCOPE_MISMATCH", "$.subject.evidence_bindings", "evidence binding names and digests must be unique and canonical")
		}
	}
	return ScopedOwnerSubjectDigest(subject)
}

func validateScopedOwnerStatement(statement ScopedOwnerStatement, expected ScopedStatementRequirement, subjectDigest string, identity Identity, snapshot Snapshot, requirements ScopedOwnerRequirements, now time.Time, publicKey ed25519.PublicKey) error {
	if statement.SchemaVersion != "1.0.0" || statement.SubjectDigest != subjectDigest || statement.Stage != expected.Stage || statement.Action != expected.Action || statement.ActorID != requirements.OwnerActorID || statement.Role != expected.SignerRole || statement.KeyID != requirements.HistoricalKeyID || statement.AuthorityMode != SingleOwnerAuthorityMode {
		return deny("ACTION_SCOPE_MISMATCH", "$.statements", "statement signer, stage, action, role, or subject binding changed")
	}
	if identity.ActorID != statement.ActorID || identity.KeyID != statement.KeyID {
		return deny("UNKNOWN_IDENTITY", "$.statements", "statement signer is absent from trusted authority")
	}
	if !noncePattern.MatchString(statement.Nonce) {
		return deny("INVALID_NONCE", "$.statements.nonce", "statement nonce must use the conservative 16-128 character form")
	}
	if statement.IssuedAt.IsZero() || statement.ExpiresAt.IsZero() || !statement.ExpiresAt.After(statement.IssuedAt) || statement.ExpiresAt.Sub(statement.IssuedAt) > 24*time.Hour || statement.IssuedAt.After(now.Add(5*time.Minute)) {
		return deny("INVALID_EXPIRATION", "$.statements.expires_at", "statement lifetime must be positive, at most 24 hours, and not future-issued")
	}
	if !now.Before(statement.ExpiresAt) {
		return deny("EXPIRED_AUTHORIZATION", "$.statements.expires_at", "statement has expired")
	}
	if statement.RoleSnapshotDigest != snapshot.RoleDigest || statement.RevocationSnapshotDigest != snapshot.RevocationDigest {
		return deny("REVOKED_AUTHORIZATION", "$.statements.revocation_snapshot_digest", "statement does not bind current protected snapshots")
	}
	canonical, err := canonicalScopedOwnerStatement(statement)
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(statement.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return deny("INVALID_SIGNATURE", "$.statements.signature_ed25519_hex", "signature does not bind the complete scoped statement")
	}
	return nil
}

func (verified ScopedOwnerValidation) MatchesSubject(subject ScopedOwnerSubject) bool {
	digest, err := ScopedOwnerSubjectDigest(subject)
	if err != nil || digest != verified.subjectDigest || verified.bindingDigest == "" || len(verified.statementDigests) == 0 {
		return false
	}
	bindingBytes, err := CanonicalJSON(struct {
		SubjectDigest    string   `json:"subject_digest"`
		StatementDigests []string `json:"statement_digests"`
	}{verified.subjectDigest, verified.statementDigests})
	return err == nil && DigestBytes(bindingBytes) == verified.bindingDigest
}
