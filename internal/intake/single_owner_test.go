package intake

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSingleOwnerModeAcceptsOneOwnerAcrossAllStageRoles(t *testing.T) {
	directory := copyEvidence(t)
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{
		RoleDigest:       DigestBytes([]byte("single-owner-roles:github:michaellady")),
		RevocationDigest: DigestBytes([]byte("single-owner-revocations:github:michaellady")),
	}
	request := ownerRequestForTest(t, directory, now, snapshot)
	actions, err := BuildAndSignOwnerActions(request, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	writePromotedActionsForTest(t, directory, actions)

	report, err := VerifyEvidenceDir(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingCodes(t, report.Blockers, "OWNER_RISK_DISPOSITION_REQUIRED", "PROTECTED_CALLER_REQUIRED")

	authority := TrustedAuthority{
		AuthorityMode: SingleOwnerAuthorityMode,
		OwnerActorID:  RequiredOwnerActor,
		Identities: map[string]Identity{
			RequiredOwnerActor: {
				ActorID: RequiredOwnerActor, AuthorityMode: SingleOwnerAuthorityMode,
				AllowedRoles: append([]string(nil), SingleOwnerActionRoles...),
				KeyID:        request.KeyID, PublicKey: hex.EncodeToString(publicKey),
			},
		},
		Snapshots: map[string]Snapshot{RequiredOwnerActor: snapshot},
		Ledger:    NewMemoryLedger(),
	}
	report, err = VerifyAuthorizedEvidenceDir(directory, now, authority)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Blockers) != 0 {
		t.Fatalf("single-owner authority remained blocked: %+v", report.Blockers)
	}
	for index, action := range actions {
		if action.ActorID != RequiredOwnerActor {
			t.Fatalf("action %d actor=%q", index, action.ActorID)
		}
	}
}

func TestSingleOwnerModeRejectsNonOwnerAndWrongRoleStage(t *testing.T) {
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	action := validSingleOwnerAction(now)
	action.Signature = hex.EncodeToString(ed25519.Sign(privateKey, CanonicalAction(action)))
	snapshot := Snapshot{RoleDigest: action.RoleSnapshotDigest, RevocationDigest: action.RevocationSnapshotDigest}
	identity := Identity{
		ActorID: action.ActorID, AuthorityMode: SingleOwnerAuthorityMode,
		AllowedRoles: append([]string(nil), SingleOwnerActionRoles...),
		KeyID:        action.KeyID, PublicKey: hex.EncodeToString(publicKey),
	}

	nonOwner := action
	nonOwner.ActorID = "github:not-the-owner"
	nonOwner.Nonce = "nonce-single-owner-nonowner-0001"
	nonOwner.Signature = hex.EncodeToString(ed25519.Sign(privateKey, CanonicalAction(nonOwner)))
	err = Authorize(nonOwner, map[string]Identity{nonOwner.ActorID: identity}, snapshot, NewMemoryLedger(), now)
	assertCode(t, err, "OWNER_MISMATCH")

	wrongRole := action
	wrongRole.Role = "release-attestor"
	wrongRole.Nonce = "nonce-single-owner-wrong-role-001"
	wrongRole.Signature = hex.EncodeToString(ed25519.Sign(privateKey, CanonicalAction(wrongRole)))
	err = Authorize(wrongRole, map[string]Identity{action.ActorID: identity}, snapshot, NewMemoryLedger(), now)
	assertCode(t, err, "ROLE_ACTION_MISMATCH")
}

func TestOwnerPromotionRequiresSignedScopedRiskDisposition(t *testing.T) {
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	action := validSingleOwnerAction(now)
	action.Stage = PromotionStageID
	action.Action = "promote"
	action.Role = "release-attestor"
	action.RequestedSandboxAccess = nil
	action.Nonce = "nonce-single-owner-promotion-0001"
	identity := Identity{
		ActorID: action.ActorID, AuthorityMode: SingleOwnerAuthorityMode,
		AllowedRoles: append([]string(nil), SingleOwnerActionRoles...),
		KeyID:        action.KeyID, PublicKey: hex.EncodeToString(publicKey),
	}
	snapshot := Snapshot{RoleDigest: action.RoleSnapshotDigest, RevocationDigest: action.RevocationSnapshotDigest}

	action.Signature = hex.EncodeToString(ed25519.Sign(privateKey, CanonicalAction(action)))
	err = Authorize(action, map[string]Identity{action.ActorID: identity}, snapshot, NewMemoryLedger(), now)
	assertCode(t, err, "RISK_DISPOSITION_REQUIRED")

	action.RiskDisposition = validRiskDisposition("sha256:" + strings.Repeat("d", 64))
	action.Nonce = "nonce-single-owner-promotion-0002"
	action.Signature = hex.EncodeToString(ed25519.Sign(privateKey, CanonicalAction(action)))
	mutated := action
	mutatedDisposition := *action.RiskDisposition
	mutated.RiskDisposition = &mutatedDisposition
	mutated.RiskDisposition.HighCount++
	err = Authorize(mutated, map[string]Identity{action.ActorID: identity}, snapshot, NewMemoryLedger(), now)
	assertCode(t, err, "RISK_DISPOSITION_MISMATCH")

	if err := Authorize(action, map[string]Identity{action.ActorID: identity}, snapshot, NewMemoryLedger(), now); err != nil {
		t.Fatalf("valid scoped risk acceptance denied: %v", err)
	}
	if action.RiskDisposition.ProductionUseAuthorized || action.RiskDisposition.PublicationAuthorized {
		t.Fatal("quarantined laboratory risk disposition widened its scope")
	}
}

func TestSingleOwnerActionsStillRejectReplayExpiryAndPublicAuthority(t *testing.T) {
	directory := copyEvidence(t)
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{RoleDigest: DigestBytes([]byte("roles")), RevocationDigest: DigestBytes([]byte("revocations"))}
	request := ownerRequestForTest(t, directory, now, snapshot)
	actions, err := BuildAndSignOwnerActions(request, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	writePromotedActionsForTest(t, directory, actions)

	publicReport, err := VerifyEvidenceDir(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingCodes(t, publicReport.Blockers, "OWNER_RISK_DISPOSITION_REQUIRED", "PROTECTED_CALLER_REQUIRED")

	identity := Identity{
		ActorID: RequiredOwnerActor, AuthorityMode: SingleOwnerAuthorityMode,
		AllowedRoles: append([]string(nil), SingleOwnerActionRoles...), KeyID: request.KeyID,
		PublicKey: hex.EncodeToString(publicKey),
	}
	authority := TrustedAuthority{
		AuthorityMode: SingleOwnerAuthorityMode, OwnerActorID: RequiredOwnerActor,
		Identities: map[string]Identity{RequiredOwnerActor: identity},
		Snapshots:  map[string]Snapshot{RequiredOwnerActor: snapshot}, Ledger: NewMemoryLedger(),
	}
	if _, err := VerifyAuthorizedEvidenceDir(directory, now, authority); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyAuthorizedEvidenceDir(directory, now, authority)
	assertCode(t, err, "REPLAYED_APPROVAL")

	expiredAuthority := authority
	expiredAuthority.Ledger = NewMemoryLedger()
	_, err = VerifyAuthorizedEvidenceDir(directory, now.Add(25*time.Hour), expiredAuthority)
	assertCode(t, err, "EXPIRED_AUTHORIZATION")
}

func TestOwnerActionBatchDoesNotConsumeNoncesWhenOneActionIsInvalid(t *testing.T) {
	directory := copyEvidence(t)
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{RoleDigest: DigestBytes([]byte("roles")), RevocationDigest: DigestBytes([]byte("revocations"))}
	request := ownerRequestForTest(t, directory, now, snapshot)
	actions, err := BuildAndSignOwnerActions(request, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	invalid := append([]Action(nil), actions...)
	invalid[len(invalid)-1].Signature = strings.Repeat("0", ed25519.SignatureSize*2)
	writePromotedActionsForTest(t, directory, invalid)
	ledger := NewMemoryLedger()
	authority := TrustedAuthority{
		AuthorityMode: SingleOwnerAuthorityMode, OwnerActorID: RequiredOwnerActor,
		Identities: map[string]Identity{RequiredOwnerActor: {
			ActorID: RequiredOwnerActor, AuthorityMode: SingleOwnerAuthorityMode,
			AllowedRoles: append([]string(nil), SingleOwnerActionRoles...), KeyID: request.KeyID,
			PublicKey: hex.EncodeToString(publicKey),
		}},
		Snapshots: map[string]Snapshot{RequiredOwnerActor: snapshot}, Ledger: ledger,
	}
	_, err = VerifyAuthorizedEvidenceDir(directory, now, authority)
	assertCode(t, err, "INVALID_SIGNATURE")

	writePromotedActionsForTest(t, directory, actions)
	if _, err := VerifyAuthorizedEvidenceDir(directory, now, authority); err != nil {
		t.Fatalf("invalid batch consumed an earlier valid nonce: %v", err)
	}
}

func TestOwnerActionSignerReadsExternalPrivateKeyWithoutEchoingIt(t *testing.T) {
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "owner.key")
	encoded := hex.EncodeToString(privateKey)
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadExternalPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	request := OwnerActionRequest{
		ActorID: RequiredOwnerActor, KeyID: "test:owner", ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
		PolicyVersion: BasePolicyVersion, PolicyDigest: BasePolicyDigest,
		PolicyAmendmentVersion: SingleOwnerAmendmentVersion, PolicyAmendmentDigest: SingleOwnerAmendmentDigest,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		RoleSnapshotDigest: "sha256:" + strings.Repeat("b", 64), RevocationSnapshotDigest: "sha256:" + strings.Repeat("c", 64),
		VulnerabilitySnapshotDigest: "sha256:" + strings.Repeat("d", 64),
		Nonces:                      []string{"nonce-owner-stage-0000000001", "nonce-owner-stage-0000000002", "nonce-owner-stage-0000000003", "nonce-owner-stage-0000000004"},
		RiskRationale:               "Owner accepts the exact retained image findings only for quarantined laboratory qualification.",
	}
	actions, err := BuildAndSignOwnerActions(request, loaded)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range actions {
		if action.Signature == "" || strings.Contains(action.Signature, encoded) {
			t.Fatal("signer omitted a signature or exposed private key material")
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ReadExternalPrivateKey(path)
	assertCode(t, err, "INVALID_IDENTITY_KEY")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "owner-link.key")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	_, err = ReadExternalPrivateKey(symlink)
	assertCode(t, err, "INVALID_IDENTITY_KEY")
}

func ownerRequestForTest(t *testing.T, directory string, now time.Time, snapshot Snapshot) OwnerActionRequest {
	t.Helper()
	var promotions promotionDocument
	readStrictTestFile(t, filepath.Join(directory, "promotion-receipts.json"), &promotions)
	vulnerabilityBytes, err := os.ReadFile(filepath.Join(directory, "vulnerability-snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	return OwnerActionRequest{
		ActorID: RequiredOwnerActor, KeyID: "test:single-owner", ArtifactDigest: promotions.CandidatePayload.RootDigest,
		PolicyVersion: BasePolicyVersion, PolicyDigest: BasePolicyDigest,
		PolicyAmendmentVersion: SingleOwnerAmendmentVersion, PolicyAmendmentDigest: SingleOwnerAmendmentDigest,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		RoleSnapshotDigest: snapshot.RoleDigest, RevocationSnapshotDigest: snapshot.RevocationDigest,
		VulnerabilitySnapshotDigest: DigestBytes(vulnerabilityBytes),
		Nonces:                      []string{"nonce-owner-stage-0000000001", "nonce-owner-stage-0000000002", "nonce-owner-stage-0000000003", "nonce-owner-stage-0000000004"},
		RiskRationale:               "Owner accepts the exact retained image findings only for quarantined laboratory qualification.",
	}
}

func writePromotedActionsForTest(t *testing.T, directory string, actions []Action) {
	t.Helper()
	var promotions promotionDocument
	path := filepath.Join(directory, "promotion-receipts.json")
	readStrictTestFile(t, path, &promotions)
	promotions.Status = SingleOwnerPromotedStatus
	promotions.AcceptedObjectCount = len(expectedArtifacts)
	promotions.BlockingFindings = nil
	promotions.SignedActions = actions
	writeJSONTestFile(t, path, promotions)
}

func validSingleOwnerAction(now time.Time) Action {
	return Action{
		ObjectID: "java-websocket-us001-inputs-v1", ObjectKind: "artifact-set", Stage: "qualification", Action: "qualify",
		ActorID: RequiredOwnerActor, Role: "port-implementer", KeyID: "test:single-owner",
		AuthorityMode: SingleOwnerAuthorityMode,
		Company:       RequiredCompany, Project: RequiredProject, LaboratoryID: RequiredLaboratory,
		ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
		PolicyVersion:  BasePolicyVersion, PolicyDigest: BasePolicyDigest,
		PolicyAmendmentVersion: SingleOwnerAmendmentVersion, PolicyAmendmentDigest: SingleOwnerAmendmentDigest,
		RequestedSandboxAccess: []string{"quarantined-source"}, Publication: PublicationIntent{Requested: false, Classification: "QUARANTINED"},
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Nonce: "nonce-single-owner-valid-000001",
		RoleSnapshotDigest: "sha256:" + strings.Repeat("b", 64), RevocationSnapshotDigest: "sha256:" + strings.Repeat("c", 64),
	}
}
