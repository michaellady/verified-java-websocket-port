package intake

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyScopedOwnerStatementsUsesExternalAuthorityAndAtomicBatch(t *testing.T) {
	now := time.Date(2026, 8, 25, 4, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	subject := testScopedSubject()
	requirements := testScopedRequirements(false)
	statements := testScopedStatements(t, subject, privateKey, now)
	authority := testScopedAuthority(privateKey.Public().(ed25519.PublicKey), NewMemoryLedger())

	invalid := append([]ScopedOwnerStatement(nil), statements...)
	invalid[1].Signature = strings.Repeat("0", ed25519.SignatureSize*2)
	if _, err := VerifyScopedOwnerStatements(subject, invalid, authority, requirements, now); err == nil {
		t.Fatal("partially invalid statement batch was accepted")
	}
	verified, err := VerifyScopedOwnerStatements(subject, statements, authority, requirements, now)
	if err != nil {
		t.Fatalf("valid batch after rejected batch: %v", err)
	}
	if !verified.MatchesSubject(subject) {
		t.Fatal("verified authorization lost its exact canonical subject binding")
	}
	if _, err := VerifyScopedOwnerStatements(subject, statements, authority, requirements, now); err == nil || !strings.Contains(err.Error(), "REPLAYED_APPROVAL") {
		t.Fatalf("replayed batch err=%v", err)
	}
}

func TestVerifyScopedOwnerStatementsRejectsHistoryAndForbiddenClaims(t *testing.T) {
	now := time.Date(2026, 8, 25, 4, 0, 0, 0, time.UTC)
	ownerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	baseSubject := testScopedSubject()
	baseRequirements := testScopedRequirements(false)

	tests := []struct {
		name   string
		mutate func(*ScopedOwnerSubject, *[]ScopedOwnerStatement, *TrustedAuthority, *ScopedOwnerRequirements)
	}{
		{"historical-key", func(subject *ScopedOwnerSubject, statements *[]ScopedOwnerStatement, _ *TrustedAuthority, _ *ScopedOwnerRequirements) {
			subject.HistoricalKeyID = "unrelated-history"
			*statements = testScopedStatements(t, *subject, ownerKey, now)
		}},
		{"production", func(subject *ScopedOwnerSubject, statements *[]ScopedOwnerStatement, _ *TrustedAuthority, _ *ScopedOwnerRequirements) {
			subject.ProductionUseAuthorized = true
			*statements = testScopedStatements(t, *subject, ownerKey, now)
		}},
		{"publication", func(subject *ScopedOwnerSubject, statements *[]ScopedOwnerStatement, _ *TrustedAuthority, _ *ScopedOwnerRequirements) {
			subject.PublicationAuthorized = true
			*statements = testScopedStatements(t, *subject, ownerKey, now)
		}},
		{"independence", func(subject *ScopedOwnerSubject, statements *[]ScopedOwnerStatement, _ *TrustedAuthority, _ *ScopedOwnerRequirements) {
			subject.IndependentReviewClaimed = true
			*statements = testScopedStatements(t, *subject, ownerKey, now)
		}},
		{"missing-snapshot", func(_ *ScopedOwnerSubject, _ *[]ScopedOwnerStatement, authority *TrustedAuthority, _ *ScopedOwnerRequirements) {
			authority.Snapshots = nil
		}},
		{"revoked", func(_ *ScopedOwnerSubject, _ *[]ScopedOwnerStatement, authority *TrustedAuthority, _ *ScopedOwnerRequirements) {
			identity := authority.Identities[RequiredOwnerActor]
			identity.Revoked = true
			authority.Identities[RequiredOwnerActor] = identity
		}},
		{"future", func(_ *ScopedOwnerSubject, statements *[]ScopedOwnerStatement, _ *TrustedAuthority, _ *ScopedOwnerRequirements) {
			for index := range *statements {
				(*statements)[index].IssuedAt = now.Add(6 * time.Minute)
				(*statements)[index].ExpiresAt = now.Add(time.Hour)
				(*statements)[index], _ = SignScopedOwnerStatement((*statements)[index], ownerKey)
			}
		}},
		{"expired", func(_ *ScopedOwnerSubject, statements *[]ScopedOwnerStatement, _ *TrustedAuthority, _ *ScopedOwnerRequirements) {
			for index := range *statements {
				(*statements)[index].IssuedAt = now.Add(-2 * time.Hour)
				(*statements)[index].ExpiresAt = now.Add(-time.Hour)
				(*statements)[index], _ = SignScopedOwnerStatement((*statements)[index], ownerKey)
			}
		}},
		{"stage", func(_ *ScopedOwnerSubject, statements *[]ScopedOwnerStatement, _ *TrustedAuthority, _ *ScopedOwnerRequirements) {
			(*statements)[0].Stage = "publication"
			(*statements)[0], _ = SignScopedOwnerStatement((*statements)[0], ownerKey)
		}},
		{"signer-role", func(_ *ScopedOwnerSubject, statements *[]ScopedOwnerStatement, _ *TrustedAuthority, _ *ScopedOwnerRequirements) {
			(*statements)[0].Role = "release-attestor"
			(*statements)[0], _ = SignScopedOwnerStatement((*statements)[0], ownerKey)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subject := baseSubject
			statements := testScopedStatements(t, subject, ownerKey, now)
			authority := testScopedAuthority(ownerKey.Public().(ed25519.PublicKey), NewMemoryLedger())
			requirements := baseRequirements
			test.mutate(&subject, &statements, &authority, &requirements)
			if _, err := VerifyScopedOwnerStatements(subject, statements, authority, requirements, now); err == nil {
				t.Fatal("mutated owner statement was accepted")
			}
		})
	}
}

func TestFileLedgerRejectsSymlinkAndHardlinkState(t *testing.T) {
	claim := NonceClaim{ActorID: RequiredOwnerActor, Nonce: "nonce-scoped-owner-ledger-0001"}
	for _, test := range []struct {
		name  string
		plant func(*testing.T, string)
	}{
		{"symlink", func(t *testing.T, directory string) {
			t.Helper()
			if err := os.Symlink("outside", filepath.Join(directory, strings.Repeat("a", 64)+".consumed")); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, directory string) {
			t.Helper()
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("sha256:"+strings.Repeat("b", 64)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(outside, filepath.Join(directory, strings.Repeat("a", 64)+".consumed")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			test.plant(t, directory)
			if (FileLedger{Directory: directory}).ConsumeBatch([]NonceClaim{claim}) {
				t.Fatal("unsafe ledger state was accepted")
			}
		})
	}
}

func testScopedSubject() ScopedOwnerSubject {
	return ScopedOwnerSubject{
		SchemaVersion: "1.0.0", Kind: "TEST_EXECUTABLE_PROMOTION", ArtifactDigest: DigestBytes([]byte("binary")),
		SubjectRoles: []string{"SANDBOX_SUPERVISOR", "SECURITYCTL"}, Operation: "CONTROLLED_CANARY",
		Company: RequiredCompany, Project: RequiredProject, LaboratoryID: RequiredLaboratory,
		PolicyDigest: DigestBytes([]byte("policy")), EvidenceBindings: []ScopedDigestBinding{{Name: "accepted", Digest: DigestBytes([]byte("accepted"))}},
		Scope: "QUARANTINED_LABORATORY_QUALIFICATION_ONLY", HistoricalKeyID: "historical-owner-key",
	}
}

func testScopedRequirements(durable bool) ScopedOwnerRequirements {
	return ScopedOwnerRequirements{
		OwnerActorID: RequiredOwnerActor, Kind: "TEST_EXECUTABLE_PROMOTION",
		Statements: []ScopedStatementRequirement{
			{Stage: "qualification", Action: "authorize-controlled-canary", SignerRole: "port-implementer"},
			{Stage: PromotionStageID, Action: "promote-controlled-canary-executable", SignerRole: "release-attestor"},
		},
		SubjectRoles: []string{"SANDBOX_SUPERVISOR", "SECURITYCTL"}, HistoricalKeyID: "historical-owner-key",
		RequireDurableLedger: durable,
	}
}

func testScopedStatements(t *testing.T, subject ScopedOwnerSubject, privateKey ed25519.PrivateKey, now time.Time) []ScopedOwnerStatement {
	t.Helper()
	digest, err := ScopedOwnerSubjectDigest(subject)
	if err != nil {
		t.Fatal(err)
	}
	required := testScopedRequirements(false).Statements
	statements := make([]ScopedOwnerStatement, 0, len(required))
	for index, statementRequirement := range required {
		statement := ScopedOwnerStatement{
			SchemaVersion: "1.0.0", SubjectDigest: digest, Stage: statementRequirement.Stage, Action: statementRequirement.Action,
			ActorID: RequiredOwnerActor, Role: statementRequirement.SignerRole, KeyID: "historical-owner-key", AuthorityMode: SingleOwnerAuthorityMode,
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Nonce: "nonce-scoped-owner-0000000" + string(rune('1'+index)),
			RoleSnapshotDigest: DigestBytes([]byte("current roles")), RevocationSnapshotDigest: DigestBytes([]byte("current revocations")),
		}
		statement, err = SignScopedOwnerStatement(statement, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		statements = append(statements, statement)
	}
	return statements
}

func testScopedAuthority(publicKey ed25519.PublicKey, ledger NonceLedger) TrustedAuthority {
	return TrustedAuthority{
		AuthorityMode: SingleOwnerAuthorityMode, OwnerActorID: RequiredOwnerActor,
		Identities: map[string]Identity{RequiredOwnerActor: {
			ActorID: RequiredOwnerActor, AuthorityMode: SingleOwnerAuthorityMode, AllowedRoles: []string{"port-implementer", "release-attestor"},
			KeyID: "historical-owner-key", PublicKey: strings.ToLower(stringHex(publicKey)),
		}},
		Snapshots: map[string]Snapshot{RequiredOwnerActor: {RoleDigest: DigestBytes([]byte("current roles")), RevocationDigest: DigestBytes([]byte("current revocations"))}},
		Ledger:    ledger,
	}
}

func stringHex(data []byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(data)*2)
	for index, value := range data {
		encoded[index*2] = alphabet[value>>4]
		encoded[index*2+1] = alphabet[value&0x0f]
	}
	return string(encoded)
}
