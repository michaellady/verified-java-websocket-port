package securitygate

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	executablePromotionSchemaPath          = "schemas/executable-promotion-record-1.0.0.schema.json"
	executablePromotionKeyID               = "java-websocket-us001-owner-ed25519-2026-08-24"
	retainedUS001AcceptedRoot              = "sha256:5713245496362ece061c769bc4ee8eb909bfcc6d7d319bc3fc9b750f6e0a4ad8"
	retainedUS001PublicEvidenceRoot        = "sha256:d0fcc851c23233c645895a2fe862128ff576676da10d00c409165707ab0b482a"
	executablePromotionKind                = "CONTROLLED_CANARY_EXECUTABLE_PROMOTION"
	executablePromotionOperation           = "CONTROLLED_CANARY"
	executablePromotionQualificationScope  = "QUARANTINED_LABORATORY_QUALIFICATION_ONLY"
	executablePromotionQualificationStage  = "qualification"
	executablePromotionQualificationAction = "authorize-controlled-canary"
	executablePromotionPromotionAction     = "promote-controlled-canary-executable"
)

var executablePromotionNonce = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)

// ExecutablePromotionRecord is candidate transport only. It deliberately
// contains no public key, trust anchor, platform receipt, or launch claim.
type ExecutablePromotionRecord struct {
	SchemaVersion string                        `json:"schema_version"`
	Subject       intake.ScopedOwnerSubject     `json:"subject"`
	Statements    []intake.ScopedOwnerStatement `json:"statements"`
}

// PromotionFinding is the closed fail-before-launch result for this seam.
type PromotionFinding struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
	Path        string `json:"path"`
	Message     string `json:"message"`
}

func (finding *PromotionFinding) Error() string {
	return fmt.Sprintf("%s/%s at %s: %s", finding.Code, finding.Disposition, finding.Path, finding.Message)
}

func promotionFinding(code, disposition, path, message string) error {
	return &PromotionFinding{Code: code, Disposition: disposition, Path: path, Message: message}
}

// ExecutablePromotionOwnerRequirements returns the exact two-action protocol
// a protected caller would pass to intake's atomic transport verifier. The
// retained key ID is only a signed binding; it is not proof of key continuity.
func ExecutablePromotionOwnerRequirements() intake.ScopedOwnerRequirements {
	return intake.ScopedOwnerRequirements{
		OwnerActorID: intake.RequiredOwnerActor,
		Kind:         executablePromotionKind,
		Statements: []intake.ScopedStatementRequirement{
			{Stage: executablePromotionQualificationStage, Action: executablePromotionQualificationAction, SignerRole: "port-implementer"},
			{Stage: intake.PromotionStageID, Action: executablePromotionPromotionAction, SignerRole: "release-attestor"},
		},
		SubjectRoles:         []string{"SANDBOX_SUPERVISOR", "SECURITYCTL"},
		HistoricalKeyID:      executablePromotionKeyID,
		RequireDurableLedger: true,
	}
}

// ExecutablePromotionSubject builds the exact subject from the retained policy
// snapshot. This deterministic construction is not a protected trust decision.
func ExecutablePromotionSubject(rootPath, binaryDigest string) (intake.ScopedOwnerSubject, error) {
	if !isSHA256Digest(binaryDigest) {
		return intake.ScopedOwnerSubject{}, promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.subject.artifact_digest", "exact executable SHA-256 digest is required")
	}
	snapshot, err := loadPolicies(rootPath)
	if err != nil {
		return intake.ScopedOwnerSubject{}, err
	}
	defer snapshot.root.Close()
	if findings := verifyRetainedEvidence(snapshot); len(findings) != 0 {
		return intake.ScopedOwnerSubject{}, promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.subject.evidence_bindings", "current retained security evidence does not verify")
	}
	return intake.ScopedOwnerSubject{
		SchemaVersion:  "1.0.0",
		Kind:           executablePromotionKind,
		ArtifactDigest: binaryDigest,
		SubjectRoles:   []string{"SANDBOX_SUPERVISOR", "SECURITYCTL"},
		Operation:      executablePromotionOperation,
		Company:        intake.RequiredCompany,
		Project:        intake.RequiredProject,
		LaboratoryID:   intake.RequiredLaboratory,
		PolicyDigest:   snapshot.digests["security/sandbox-policy.json"],
		EvidenceBindings: []intake.ScopedDigestBinding{
			{Name: "security-evidence", Digest: snapshot.digests["evidence/security-validation.json"]},
			{Name: "us001-accepted-root", Digest: retainedUS001AcceptedRoot},
			{Name: "us001-public-evidence", Digest: retainedUS001PublicEvidenceRoot},
		},
		Scope:                    executablePromotionQualificationScope,
		HistoricalKeyID:          executablePromotionKeyID,
		ProductionUseAuthorized:  false,
		PublicationAuthorized:    false,
		IndependentReviewClaimed: false,
	}, nil
}

// DecodeExecutablePromotionRecord rejects unknown or duplicate JSON fields.
func DecodeExecutablePromotionRecord(data []byte) (ExecutablePromotionRecord, error) {
	var record ExecutablePromotionRecord
	if err := intake.DecodeStrict(data, &record); err != nil {
		return ExecutablePromotionRecord{}, promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.promotion_record", "record is not strict canonical JSON: "+err.Error())
	}
	return record, nil
}

// ValidateExecutablePromotionRecord validates closed scope and temporal shape,
// but intentionally does not authenticate the caller-supplied authority or
// consume nonces. Only the protected external launcher may do that.
func ValidateExecutablePromotionRecord(rootPath, binaryDigest string, record ExecutablePromotionRecord, now time.Time) error {
	expected, err := ExecutablePromotionSubject(rootPath, binaryDigest)
	if err != nil {
		return err
	}
	if record.SchemaVersion != "1.0.0" || !reflect.DeepEqual(record.Subject, expected) {
		return promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.subject", "promotion subject differs from the exact retained controlled-canary binding")
	}
	subjectDigest, err := intake.ScopedOwnerSubjectDigest(expected)
	if err != nil {
		return err
	}
	requirements := ExecutablePromotionOwnerRequirements()
	if len(record.Statements) != len(requirements.Statements) {
		return promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.statements", "exactly one qualification and one executable-promotion statement are required")
	}
	seenNonces := make(map[string]struct{}, len(record.Statements))
	for index, statement := range record.Statements {
		required := requirements.Statements[index]
		if statement.SchemaVersion != "1.0.0" || statement.SubjectDigest != subjectDigest ||
			statement.Stage != required.Stage || statement.Action != required.Action || statement.ActorID != intake.RequiredOwnerActor ||
			statement.Role != required.SignerRole || statement.KeyID != executablePromotionKeyID || statement.AuthorityMode != intake.SingleOwnerAuthorityMode {
			return promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", fmt.Sprintf("$.statements[%d]", index), "statement signer, stage, action, role, key-id binding, or subject digest changed")
		}
		if !executablePromotionNonce.MatchString(statement.Nonce) {
			return promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", fmt.Sprintf("$.statements[%d].nonce", index), "fresh distinct nonce shape is required")
		}
		if _, duplicate := seenNonces[statement.Nonce]; duplicate {
			return promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.statements", "qualification and promotion require distinct nonces")
		}
		seenNonces[statement.Nonce] = struct{}{}
		if statement.IssuedAt.IsZero() || statement.ExpiresAt.IsZero() || !statement.ExpiresAt.After(statement.IssuedAt) ||
			statement.ExpiresAt.Sub(statement.IssuedAt) > 24*time.Hour || statement.IssuedAt.After(now.Add(5*time.Minute)) || !now.Before(statement.ExpiresAt) {
			return promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", fmt.Sprintf("$.statements[%d].expires_at", index), "statement must be current, future-skew bounded, and valid for at most 24 hours")
		}
		if !isSHA256Digest(statement.RoleSnapshotDigest) || !isSHA256Digest(statement.RevocationSnapshotDigest) {
			return promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", fmt.Sprintf("$.statements[%d]", index), "current role and revocation snapshot bindings are required")
		}
		signature, decodeErr := hex.DecodeString(statement.Signature)
		if decodeErr != nil || len(signature) != 64 || strings.ToLower(statement.Signature) != statement.Signature {
			return promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", fmt.Sprintf("$.statements[%d].signature_ed25519_hex", index), "canonical Ed25519 signature shape is required")
		}
	}
	if record.Statements[0].RoleSnapshotDigest != record.Statements[1].RoleSnapshotDigest ||
		record.Statements[0].RevocationSnapshotDigest != record.Statements[1].RevocationSnapshotDigest {
		return promotionFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.statements", "the action pair must bind one current role/revocation snapshot")
	}
	return nil
}

// PreflightExecutablePromotionCandidate is a non-authorizing candidate-side
// check. It can never authorize launch: even a valid signature set under an
// attacker-supplied authority reaches PROTECTED_CALLER_REQUIRED before nonce
// consumption or execution.
func PreflightExecutablePromotionCandidate(rootPath, binaryDigest string, data []byte, _ intake.TrustedAuthority, now time.Time) error {
	if len(data) == 0 {
		return promotionFinding("UNPROMOTED_EXECUTABLE", "QUARANTINE", "$.promotion_record", "a protected executable-promotion record is absent")
	}
	record, err := DecodeExecutablePromotionRecord(data)
	if err != nil {
		return err
	}
	if err := ValidateExecutablePromotionRecord(rootPath, binaryDigest, record, now); err != nil {
		return err
	}
	return promotionFinding("PROTECTED_CALLER_REQUIRED", "BLOCK", "$.promotion_authority", "repository-local authority and signatures cannot establish protected key custody, historical key continuity, or durable launcher provenance")
}
