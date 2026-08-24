package intake

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestPromoteAuthorizedOwnerInputsCommitsExactMaterializedBatchAndReceipt(t *testing.T) {
	directory := copyEvidence(t)
	materializationRoot := filepath.Join(t.TempDir(), "materialized")
	manifest, catalog := writeFixtureMaterialization(t, directory, materializationRoot)

	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	actions, authority := signedOwnerPromotionFixture(t, directory, now, FileLedger{Directory: filepath.Join(t.TempDir(), "ledger")})
	promotionStore := filepath.Join(t.TempDir(), "promotion-store")
	result, err := PromoteAuthorizedOwnerInputs(OwnerPromotionInput{
		EvidenceDirectory: directory, MaterializationRoot: materializationRoot,
		PromotionStore: promotionStore, Manifest: manifest, Actions: actions,
		Authority: authority, Now: now,
		testCatalog: catalog,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !validateDigest(result.PromotionRoot) || !validateDigest(result.EvidenceRoot) {
		t.Fatalf("invalid promotion result: %+v", result)
	}
	var receipt promotionDocument
	readStrictTestFile(t, filepath.Join(directory, "promotion-receipts.json"), &receipt)
	if receipt.Status != SingleOwnerPromotedStatus || receipt.AcceptedObjectCount != 23 || receipt.PromotionStoreRoot != result.PromotionRoot || len(receipt.SignedActions) != 4 {
		t.Fatalf("persisted receipt is incomplete: %+v", receipt)
	}
	acceptedManifest := filepath.Join(promotionStore, "accepted", result.PromotionRoot[7:], "manifest.json")
	if _, err := os.Stat(acceptedManifest); err != nil {
		t.Fatalf("promoted batch is absent: %v", err)
	}
	publicReport, err := VerifyEvidenceDir(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingCodes(t, publicReport.Blockers, "OWNER_RISK_DISPOSITION_REQUIRED", "PROTECTED_CALLER_REQUIRED")
}

func TestPromoteAuthorizedOwnerInputsRejectsBadBytesBeforeNonceOrReceiptMutation(t *testing.T) {
	directory := copyEvidence(t)
	initialReceipt, err := os.ReadFile(filepath.Join(directory, "promotion-receipts.json"))
	if err != nil {
		t.Fatal(err)
	}
	materializationRoot := filepath.Join(t.TempDir(), "materialized")
	manifest, catalog := writeFixtureMaterialization(t, directory, materializationRoot)
	badPath := filepath.Join(materializationRoot, filepath.FromSlash(manifest.Objects[7].Path))
	badBytes, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}
	badBytes[0] ^= 1
	if err := os.WriteFile(badPath, badBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	ledgerDirectory := filepath.Join(t.TempDir(), "ledger")
	actions, authority := signedOwnerPromotionFixture(t, directory, now, FileLedger{Directory: ledgerDirectory})
	promotionStore := filepath.Join(t.TempDir(), "promotion-store")
	_, err = PromoteAuthorizedOwnerInputs(OwnerPromotionInput{
		EvidenceDirectory: directory, MaterializationRoot: materializationRoot,
		PromotionStore: promotionStore, Manifest: manifest, Actions: actions,
		Authority: authority, Now: now,
		testCatalog: catalog,
	})
	assertCode(t, err, "DIGEST_MISMATCH")
	if entries, err := os.ReadDir(ledgerDirectory); err == nil && len(entries) != 0 {
		t.Fatalf("bad bytes consumed nonce state: %+v", entries)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	actualReceipt, err := os.ReadFile(filepath.Join(directory, "promotion-receipts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(actualReceipt) != string(initialReceipt) {
		t.Fatal("failed promotion mutated public receipt")
	}
	if _, err := os.Stat(filepath.Join(promotionStore, "accepted")); !os.IsNotExist(err) {
		t.Fatalf("failed promotion exposed accepted state: %v", err)
	}
}

func TestPromoteAuthorizedOwnerInputsRejectsTraversalBeforeNonceConsumption(t *testing.T) {
	directory := copyEvidence(t)
	materializationRoot := filepath.Join(t.TempDir(), "materialized")
	manifest, catalog := writeFixtureMaterialization(t, directory, materializationRoot)
	manifest.Objects[0].Path = "../escape"

	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	ledgerDirectory := filepath.Join(t.TempDir(), "ledger")
	actions, authority := signedOwnerPromotionFixture(t, directory, now, FileLedger{Directory: ledgerDirectory})
	_, err := PromoteAuthorizedOwnerInputs(OwnerPromotionInput{
		EvidenceDirectory: directory, MaterializationRoot: materializationRoot,
		PromotionStore: filepath.Join(t.TempDir(), "promotion-store"),
		Manifest:       manifest, Actions: actions, Authority: authority, Now: now,
		testCatalog: catalog,
	})
	assertCode(t, err, "PATH_TRAVERSAL")
	if _, err := os.Stat(ledgerDirectory); !os.IsNotExist(err) {
		t.Fatalf("traversal reached protected nonce ledger: %v", err)
	}
}

func TestPromoteAuthorizedOwnerInputsLeavesReceiptBlockedWhenStoreCommitFails(t *testing.T) {
	directory := copyEvidence(t)
	initialReceipt, err := os.ReadFile(filepath.Join(directory, "promotion-receipts.json"))
	if err != nil {
		t.Fatal(err)
	}
	materializationRoot := filepath.Join(t.TempDir(), "materialized")
	manifest, catalog := writeFixtureMaterialization(t, directory, materializationRoot)
	promotionStore := filepath.Join(t.TempDir(), "promotion-store-is-a-file")
	if err := os.WriteFile(promotionStore, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	ledgerDirectory := filepath.Join(t.TempDir(), "ledger")
	actions, authority := signedOwnerPromotionFixture(t, directory, now, FileLedger{Directory: ledgerDirectory})
	_, err = PromoteAuthorizedOwnerInputs(OwnerPromotionInput{
		EvidenceDirectory: directory, MaterializationRoot: materializationRoot,
		PromotionStore: promotionStore, Manifest: manifest, Actions: actions,
		Authority: authority, Now: now,
		testCatalog: catalog,
	})
	assertCode(t, err, "PARTIAL_PUBLICATION")
	actualReceipt, err := os.ReadFile(filepath.Join(directory, "promotion-receipts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(actualReceipt) != string(initialReceipt) {
		t.Fatal("failed store commit persisted a promoted receipt")
	}
	entries, err := os.ReadDir(ledgerDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".batch") {
		t.Fatalf("post-authorization failure did not preserve one atomic consumed-nonce batch: %+v", entries)
	}
}

func TestBuildTrustedOwnerAuthorityRejectsNonOwnerAndAmbiguousRoles(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := OwnerAuthorityDocument{
		SchemaVersion: "1.0.0", AuthorityMode: SingleOwnerAuthorityMode,
		OwnerActorID: RequiredOwnerActor,
		Identity: Identity{
			ActorID: RequiredOwnerActor, AuthorityMode: SingleOwnerAuthorityMode,
			AllowedRoles: append([]string(nil), SingleOwnerActionRoles...),
			KeyID:        "owner-test-key", PublicKey: hex.EncodeToString(publicKey),
		},
		Snapshot: Snapshot{RoleDigest: DigestBytes([]byte("roles")), RevocationDigest: DigestBytes([]byte("revocations"))},
	}
	for _, testCase := range []struct {
		name   string
		mutate func(*OwnerAuthorityDocument)
		code   string
	}{
		{"non-owner", func(document *OwnerAuthorityDocument) { document.OwnerActorID = "github:not-the-owner" }, "AUTHORITY_MODE_MISMATCH"},
		{"legacy-role", func(document *OwnerAuthorityDocument) { document.Identity.Role = "release-attestor" }, "UNKNOWN_IDENTITY"},
		{"missing-role", func(document *OwnerAuthorityDocument) {
			document.Identity.AllowedRoles = document.Identity.AllowedRoles[1:]
		}, "ROLE_CONFLICT"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			document := valid
			document.Identity.AllowedRoles = append([]string(nil), valid.Identity.AllowedRoles...)
			testCase.mutate(&document)
			_, err := BuildTrustedOwnerAuthority(document, FileLedger{Directory: filepath.Join(t.TempDir(), "ledger")})
			assertCode(t, err, testCase.code)
		})
	}
}

func TestProductionMaterializationCatalogBindsAutobahnManifestBlobNotArchiveTar(t *testing.T) {
	descriptor := expectedArtifacts["autobahn-linux-amd64-image"]
	if descriptor.Digest != AutobahnManifestDigest {
		t.Fatalf("Autobahn catalog binds %s, want exact manifest %s", descriptor.Digest, AutobahnManifestDigest)
	}
	if descriptor.Size <= maxOCIManifestBytes {
		t.Fatalf("test precondition lost: source catalog size %d no longer distinguishes retained archive size from a manifest blob", descriptor.Size)
	}
}

func writeFixtureMaterialization(t *testing.T, evidenceDirectory, root string) (MaterializationManifest, map[string]expectedArtifact) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(expectedArtifacts))
	for id := range expectedArtifacts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	manifest := MaterializationManifest{
		SchemaVersion: "1.0.0", Company: RequiredCompany, Project: RequiredProject,
		LaboratoryID: RequiredLaboratory,
	}
	var receipt promotionDocument
	readStrictTestFile(t, filepath.Join(evidenceDirectory, "promotion-receipts.json"), &receipt)
	manifest.CandidatePayloadRoot = receipt.CandidatePayload.RootDigest
	catalog := make(map[string]expectedArtifact, len(ids))
	for _, id := range ids {
		data := []byte("fixture bytes for " + id + "\n")
		relativePath := filepath.ToSlash(filepath.Join("objects", id))
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(relativePath)), data, 0o600); err != nil {
			t.Fatal(err)
		}
		kind := MaterializationKindArtifact
		if id == "autobahn-linux-amd64-image" {
			kind = MaterializationKindOCIManifest
		}
		digest := DigestBytes(data)
		manifest.Objects = append(manifest.Objects, MaterializedObject{ID: id, Kind: kind, Path: relativePath, SHA256: digest, ByteSize: int64(len(data))})
		catalog[id] = expectedArtifact{Digest: digest, Size: int64(len(data))}
	}
	return manifest, catalog
}

func signedOwnerPromotionFixture(t *testing.T, directory string, now time.Time, ledger NonceLedger) ([]Action, TrustedAuthority) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{RoleDigest: DigestBytes([]byte("protected roles")), RevocationDigest: DigestBytes([]byte("protected revocations"))}
	request := ownerRequestForTest(t, directory, now, snapshot)
	actions, err := BuildAndSignOwnerActions(request, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	authority := TrustedAuthority{
		AuthorityMode: SingleOwnerAuthorityMode, OwnerActorID: RequiredOwnerActor,
		Identities: map[string]Identity{RequiredOwnerActor: {
			ActorID: RequiredOwnerActor, AuthorityMode: SingleOwnerAuthorityMode,
			AllowedRoles: append([]string(nil), SingleOwnerActionRoles...),
			KeyID:        request.KeyID, PublicKey: hex.EncodeToString(publicKey),
		}},
		Snapshots: map[string]Snapshot{RequiredOwnerActor: snapshot}, Ledger: ledger,
	}
	return actions, authority
}
