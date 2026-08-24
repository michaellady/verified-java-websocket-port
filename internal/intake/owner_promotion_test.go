package intake

import (
	"bytes"
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
	directory := copyBlockedEvidence(t)
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
	if receipt.ApprovalPolicy.RoleAndRevocationSnapshots != "were supplied and validated by the protected caller but remain absent from this public projection" {
		t.Fatalf("persisted receipt misstates protected snapshots: %q", receipt.ApprovalPolicy.RoleAndRevocationSnapshots)
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
	directory := copyBlockedEvidence(t)
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
	directory := copyBlockedEvidence(t)
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

func TestPromoteAuthorizedOwnerInputsRejectsLinkedEvidenceBeforeProtectedState(t *testing.T) {
	directory := copyBlockedEvidence(t)
	receiptPath := filepath.Join(directory, "promotion-receipts.json")
	initialReceipt, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	materializationRoot := filepath.Join(t.TempDir(), "materialized")
	manifest, catalog := writeFixtureMaterialization(t, directory, materializationRoot)
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	ledgerDirectory := filepath.Join(t.TempDir(), "ledger")
	actions, authority := signedOwnerPromotionFixture(t, directory, now, FileLedger{Directory: ledgerDirectory})
	promotionStore := filepath.Join(t.TempDir(), "promotion-store")

	sourcePath := filepath.Join(directory, "source-pins.json")
	outsidePath := filepath.Join(t.TempDir(), "outside-source-pins.json")
	sourceBytes, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsidePath, sourceBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsidePath, sourcePath); err != nil {
		t.Fatal(err)
	}

	_, err = PromoteAuthorizedOwnerInputs(OwnerPromotionInput{
		EvidenceDirectory: directory, MaterializationRoot: materializationRoot,
		PromotionStore: promotionStore, Manifest: manifest, Actions: actions,
		Authority: authority, Now: now,
		testCatalog: catalog,
	})
	assertCode(t, err, "UNSAFE_ARCHIVE_ENTRY")
	if _, err := os.Lstat(ledgerDirectory); !os.IsNotExist(err) {
		t.Fatalf("linked evidence reached protected nonce state: %v", err)
	}
	if _, err := os.Lstat(promotionStore); !os.IsNotExist(err) {
		t.Fatalf("linked evidence reached protected promotion state: %v", err)
	}
	actualReceipt, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualReceipt, initialReceipt) {
		t.Fatal("linked evidence replaced the blocked receipt")
	}
}

func TestPromoteAuthorizedOwnerInputsRejectsProtectedCandidatePathOverlap(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		paths func(string) (string, string, string, string)
	}{
		{"evidence-materialization", func(root string) (string, string, string, string) {
			return filepath.Join(root, "evidence"), filepath.Join(root, "evidence"), filepath.Join(root, "store"), filepath.Join(root, "ledger")
		}},
		{"materialization-promotion", func(root string) (string, string, string, string) {
			return filepath.Join(root, "evidence"), filepath.Join(root, "materialized"), filepath.Join(root, "materialized", "store"), filepath.Join(root, "ledger")
		}},
		{"ledger-evidence", func(root string) (string, string, string, string) {
			return filepath.Join(root, "evidence"), filepath.Join(root, "materialized"), filepath.Join(root, "store"), filepath.Join(root, "evidence", "ledger")
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			evidence, materialized, store, ledger := testCase.paths(root)
			if err := os.MkdirAll(evidence, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(materialized, 0o700); err != nil {
				t.Fatal(err)
			}
			_, err := PromoteAuthorizedOwnerInputs(OwnerPromotionInput{
				EvidenceDirectory: evidence, MaterializationRoot: materialized,
				PromotionStore: store,
				Authority:      TrustedAuthority{Ledger: FileLedger{Directory: ledger}},
			})
			assertCode(t, err, "CROSS_COMPANY_REFERENCE")
			if _, err := os.Lstat(filepath.Join(evidence, ".owner-promotion.lock")); !os.IsNotExist(err) {
				t.Fatalf("overlap validation acquired a promotion lock: %v", err)
			}
		})
	}
}

func TestPromoteAuthorizedOwnerInputsLeavesReceiptBlockedWhenStoreCommitFails(t *testing.T) {
	directory := copyBlockedEvidence(t)
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

func TestPromoteAuthorizedOwnerInputsDeniesConcurrentEvidenceDriftBeforeReceiptReplacement(t *testing.T) {
	directory := copyBlockedEvidence(t)
	receiptPath := filepath.Join(directory, "promotion-receipts.json")
	initialReceipt, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(directory, "source-pins.json")
	initialSource, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	materializationRoot := filepath.Join(t.TempDir(), "materialized")
	manifest, catalog := writeFixtureMaterialization(t, directory, materializationRoot)
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	ledgerDirectory := filepath.Join(t.TempDir(), "ledger")
	actions, authority := signedOwnerPromotionFixture(t, directory, now, FileLedger{Directory: ledgerDirectory})
	promotionStore := filepath.Join(t.TempDir(), "promotion-store")
	hookCalled := false
	_, err = PromoteAuthorizedOwnerInputs(OwnerPromotionInput{
		EvidenceDirectory: directory, MaterializationRoot: materializationRoot,
		PromotionStore: promotionStore, Manifest: manifest, Actions: actions,
		Authority: authority, Now: now,
		testCatalog: catalog,
		testBeforeReceiptPersist: func() {
			hookCalled = true
			if writeErr := os.WriteFile(sourcePath, append(initialSource, '\n'), 0o600); writeErr != nil {
				t.Fatalf("mutate evidence: %v", writeErr)
			}
		},
	})
	assertCode(t, err, "ARTIFACT_DRIFT")
	if !hookCalled {
		t.Fatal("deterministic pre-persistence hook was not reached")
	}
	actualReceipt, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(actualReceipt) != string(initialReceipt) {
		t.Fatal("concurrent non-receipt drift replaced the public receipt")
	}
	ledgerEntries, err := os.ReadDir(ledgerDirectory)
	if err != nil || len(ledgerEntries) != 1 || !strings.HasSuffix(ledgerEntries[0].Name(), ".batch") {
		t.Fatalf("authorized nonce batch was not honestly retained: entries=%+v err=%v", ledgerEntries, err)
	}
	acceptedEntries, err := os.ReadDir(filepath.Join(promotionStore, "accepted"))
	if err != nil || len(acceptedEntries) != 1 {
		t.Fatalf("already-promoted store state was not honestly retained: entries=%+v err=%v", acceptedEntries, err)
	}
}

func TestPromoteAuthorizedOwnerInputsAcceptsSchemaValidMaterializationOrder(t *testing.T) {
	directory := copyBlockedEvidence(t)
	materializationRoot := filepath.Join(t.TempDir(), "materialized")
	manifest, catalog := writeFixtureMaterialization(t, directory, materializationRoot)
	for left, right := 0, len(manifest.Objects)-1; left < right; left, right = left+1, right-1 {
		manifest.Objects[left], manifest.Objects[right] = manifest.Objects[right], manifest.Objects[left]
	}
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	actions, authority := signedOwnerPromotionFixture(t, directory, now, FileLedger{Directory: filepath.Join(t.TempDir(), "ledger")})
	result, err := PromoteAuthorizedOwnerInputs(OwnerPromotionInput{
		EvidenceDirectory: directory, MaterializationRoot: materializationRoot,
		PromotionStore: filepath.Join(t.TempDir(), "promotion-store"),
		Manifest:       manifest, Actions: actions, Authority: authority, Now: now,
		testCatalog: catalog,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ObjectCount != 23 {
		t.Fatalf("promoted %d objects from reordered manifest, want 23", result.ObjectCount)
	}
}

func TestPromoteAuthorizedOwnerInputsRejectsDuplicateMissingAndUnknownMaterializationIDs(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*MaterializationManifest)
		code   string
	}{
		{"duplicate", func(manifest *MaterializationManifest) { manifest.Objects[0] = manifest.Objects[1] }, "DUPLICATE_ARCHIVE_ENTRY"},
		{"missing", func(manifest *MaterializationManifest) { manifest.Objects = manifest.Objects[:len(manifest.Objects)-1] }, "MISSING_PROMOTION_REQUIREMENT"},
		{"unknown", func(manifest *MaterializationManifest) { manifest.Objects[0].ID = "unknown-artifact" }, "ARTIFACT_DRIFT"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			directory := copyBlockedEvidence(t)
			materializationRoot := filepath.Join(t.TempDir(), "materialized")
			manifest, catalog := writeFixtureMaterialization(t, directory, materializationRoot)
			testCase.mutate(&manifest)
			now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
			ledgerDirectory := filepath.Join(t.TempDir(), "ledger")
			actions, authority := signedOwnerPromotionFixture(t, directory, now, FileLedger{Directory: ledgerDirectory})
			_, err := PromoteAuthorizedOwnerInputs(OwnerPromotionInput{
				EvidenceDirectory: directory, MaterializationRoot: materializationRoot,
				PromotionStore: filepath.Join(t.TempDir(), "promotion-store"),
				Manifest:       manifest, Actions: actions, Authority: authority, Now: now,
				testCatalog: catalog,
			})
			assertCode(t, err, testCase.code)
			if _, err := os.Lstat(ledgerDirectory); !os.IsNotExist(err) {
				t.Fatalf("invalid id set reached nonce ledger: %v", err)
			}
		})
	}
}

func TestPromoteAuthorizedOwnerInputsValidatesRequiredActionsBeforeTransition(t *testing.T) {
	directory := copyBlockedEvidence(t)
	receiptPath := filepath.Join(directory, "promotion-receipts.json")
	var receipt promotionDocument
	readStrictTestFile(t, receiptPath, &receipt)
	receipt.RequiredActions[0], receipt.RequiredActions[1] = receipt.RequiredActions[1], receipt.RequiredActions[0]
	writeJSONTestFile(t, receiptPath, receipt)
	corruptReceipt, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	materializationRoot := filepath.Join(t.TempDir(), "materialized")
	manifest, catalog := writeFixtureMaterialization(t, directory, materializationRoot)
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
	assertCode(t, err, "ACTION_SCOPE_MISMATCH")
	actualReceipt, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(actualReceipt) != string(corruptReceipt) {
		t.Fatal("invalid required-action trace was rewritten before validation")
	}
	for _, path := range []string{ledgerDirectory, promotionStore} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("invalid required-action trace mutated protected state at %s: %v", path, err)
		}
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
