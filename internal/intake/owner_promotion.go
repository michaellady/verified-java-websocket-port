package intake

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	MaterializationKindArtifact    = "artifact-bytes"
	MaterializationKindOCIManifest = "oci-manifest-blob"
	maxMaterializedBatchBytes      = int64(1 << 30)
	maxOCIManifestBytes            = int64(4 << 20)
)

type MaterializationManifest struct {
	SchemaVersion        string               `json:"schema_version"`
	Company              string               `json:"company"`
	Project              string               `json:"project"`
	LaboratoryID         string               `json:"laboratory_id"`
	CandidatePayloadRoot string               `json:"candidate_payload_root"`
	Objects              []MaterializedObject `json:"objects"`
}

type MaterializedObject struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	ByteSize int64  `json:"byte_size"`
}

type OwnerPromotionInput struct {
	EvidenceDirectory   string
	MaterializationRoot string
	PromotionStore      string
	Manifest            MaterializationManifest
	Actions             []Action
	Authority           TrustedAuthority
	Now                 time.Time

	testCatalog              map[string]expectedArtifact
	testBeforeReceiptPersist func()
}

type OwnerPromotionResult struct {
	PromotionRoot string `json:"promotion_root"`
	EvidenceRoot  string `json:"evidence_root"`
	ObjectCount   int    `json:"object_count"`
}

type OwnerAuthorityDocument struct {
	SchemaVersion string   `json:"schema_version"`
	AuthorityMode string   `json:"authority_mode"`
	OwnerActorID  string   `json:"owner_actor_id"`
	Identity      Identity `json:"identity"`
	Snapshot      Snapshot `json:"snapshot"`
}

func BuildTrustedOwnerAuthority(document OwnerAuthorityDocument, ledger FileLedger) (TrustedAuthority, error) {
	if document.SchemaVersion != "1.0.0" || document.AuthorityMode != SingleOwnerAuthorityMode || document.OwnerActorID != RequiredOwnerActor {
		return TrustedAuthority{}, deny("AUTHORITY_MODE_MISMATCH", "authority", "external authority document does not bind the single repository owner")
	}
	identity := document.Identity
	if identity.ActorID != RequiredOwnerActor || identity.AuthorityMode != SingleOwnerAuthorityMode || identity.Role != "" || identity.KeyID == "" || identity.Revoked {
		return TrustedAuthority{}, deny("UNKNOWN_IDENTITY", "authority.identity", "external authority identity does not bind the active repository owner key")
	}
	roles := slices.Clone(identity.AllowedRoles)
	wantedRoles := slices.Clone(SingleOwnerActionRoles)
	sort.Strings(roles)
	sort.Strings(wantedRoles)
	if !slices.Equal(roles, wantedRoles) {
		return TrustedAuthority{}, deny("ROLE_CONFLICT", "authority.identity.allowed_roles", "external owner authority must grant exactly the amended action roles")
	}
	publicKey, err := hex.DecodeString(identity.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || hex.EncodeToString(publicKey) != identity.PublicKey {
		return TrustedAuthority{}, deny("INVALID_IDENTITY_KEY", "authority.identity.public_key_ed25519_hex", "external authority public key is not an Ed25519 public key")
	}
	if !validateDigest(document.Snapshot.RoleDigest) || !validateDigest(document.Snapshot.RevocationDigest) {
		return TrustedAuthority{}, deny("REVOKED_AUTHORIZATION", "authority.snapshot", "external role and revocation snapshot digests are required")
	}
	return TrustedAuthority{
		AuthorityMode: SingleOwnerAuthorityMode,
		OwnerActorID:  RequiredOwnerActor,
		Identities:    map[string]Identity{RequiredOwnerActor: identity},
		Snapshots:     map[string]Snapshot{RequiredOwnerActor: document.Snapshot},
		Ledger:        ledger,
	}, nil
}

func PromoteAuthorizedOwnerInputs(input OwnerPromotionInput) (*OwnerPromotionResult, error) {
	evidenceDirectory, materializationRoot, promotionStore, err := validateOwnerPromotionPaths(input)
	if err != nil {
		return nil, err
	}
	ledger, ok := durableFileLedger(input.Authority.Ledger)
	if !ok || !filepath.IsAbs(filepath.Clean(ledger.Directory)) {
		return nil, deny("INVALID_PROMOTION_STORE", "protected-authority.ledger", "owner promotion requires an absolute durable FileLedger directory")
	}
	ledger.Directory, err = canonicalProtectedPath(ledger.Directory)
	if err != nil {
		return nil, err
	}
	input.Authority.Ledger = ledger
	if pathsOverlap(ledger.Directory, evidenceDirectory) || pathsOverlap(ledger.Directory, materializationRoot) || pathsOverlap(ledger.Directory, promotionStore) {
		return nil, deny("CROSS_COMPANY_REFERENCE", "protected-authority.ledger", "nonce ledger must be isolated from evidence, materialization, and promotion storage")
	}
	lock, err := acquirePromotionLock(evidenceDirectory)
	if err != nil {
		return nil, err
	}
	defer lock.release()

	report, err := VerifyEvidenceDir(evidenceDirectory, input.Now)
	if err != nil {
		return nil, err
	}
	if len(report.Blockers) != 2 || report.Blockers[0].Code != "OWNER_RISK_DISPOSITION_REQUIRED" || report.Blockers[1].Code != "MISSING_PROMOTION_REQUIREMENT" {
		return nil, deny("ACTION_SCOPE_MISMATCH", "promotion-receipts.json", "owner promotion must begin from the exact blocked public receipt")
	}

	evidenceSnapshot, err := captureEvidenceSnapshot(evidenceDirectory, report.FileDigests)
	if err != nil {
		return nil, err
	}
	receiptBytes := evidenceSnapshot["promotion-receipts.json"]
	var receipt promotionDocument
	if err := DecodeStrict(receiptBytes, &receipt); err != nil {
		return nil, err
	}
	if input.Manifest.CandidatePayloadRoot != receipt.CandidatePayload.RootDigest {
		return nil, deny("DIGEST_MISMATCH", "materialization.candidate_payload_root", "materialization does not bind the exact candidate evidence root")
	}
	catalog := expectedArtifacts
	enforceProductionDescriptor := true
	if input.testCatalog != nil {
		catalog = input.testCatalog
		enforceProductionDescriptor = false
	}
	objects, err := loadMaterializedObjects(materializationRoot, input.Manifest, catalog, enforceProductionDescriptor)
	if err != nil {
		return nil, err
	}

	pendingReceipt := receipt
	pendingReceipt.Status = SingleOwnerAuthorizedStatus
	pendingReceipt.AcceptedObjectCount = 0
	pendingReceipt.PromotionStoreRoot = ""
	pendingReceipt.SignedActions = append([]Action(nil), input.Actions...)
	pendingReceipt.BlockingFindings = nil
	for index := range pendingReceipt.RequiredActions {
		pendingReceipt.RequiredActions[index].Status = "OWNER_SIGNED_PENDING_PROTECTED_VERIFICATION"
	}
	pendingReceipt.SafeNextAction = "Protected verification and exact-byte promotion are pending; this staged receipt is not a public promotion receipt."
	pendingReceipt.Claim = "Owner actions are staged under OWNER_ATTESTED_NOT_INDEPENDENT; no input byte is accepted until protected promotion commits."

	stagedEvidence, err := stageEvidenceDirectory(evidenceDirectory, pendingReceipt)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stagedEvidence)
	if _, err := VerifyAuthorizedEvidenceDir(stagedEvidence, input.Now, input.Authority); err != nil {
		return nil, err
	}
	promotionRoot, err := PromoteDirectory(promotionStore, objects)
	if err != nil {
		return nil, err
	}

	finalReceipt := pendingReceipt
	finalReceipt.Status = SingleOwnerPromotedStatus
	finalReceipt.AcceptedObjectCount = len(objects)
	finalReceipt.PromotionStoreRoot = promotionRoot
	for index := range finalReceipt.RequiredActions {
		finalReceipt.RequiredActions[index].Status = "OWNER_SIGNED_AND_PROTECTED_VERIFIED"
	}
	finalReceipt.SafeNextAction = "Use the accepted content-addressed inputs only within quarantined laboratory qualification; production use and publication remain unauthorized."
	finalReceipt.Claim = "The exact input bytes were promoted under OWNER_ATTESTED_NOT_INDEPENDENT; this is not independent review and does not authorize production use or publication."
	if input.testBeforeReceiptPersist != nil {
		input.testBeforeReceiptPersist()
	}
	if err := persistReceiptAtomically(evidenceDirectory, evidenceSnapshot, finalReceipt); err != nil {
		return nil, err
	}
	finalReport, err := VerifyEvidenceDir(evidenceDirectory, input.Now)
	if err != nil {
		return nil, err
	}
	return &OwnerPromotionResult{PromotionRoot: promotionRoot, EvidenceRoot: finalReport.EvidenceRoot, ObjectCount: len(objects)}, nil
}

func durableFileLedger(ledger NonceLedger) (FileLedger, bool) {
	switch value := ledger.(type) {
	case FileLedger:
		return value, true
	case *FileLedger:
		if value != nil {
			return *value, true
		}
	}
	return FileLedger{}, false
}

func validateOwnerPromotionPaths(input OwnerPromotionInput) (string, string, string, error) {
	paths := []struct {
		name  string
		value string
	}{
		{"evidence", input.EvidenceDirectory},
		{"materialization", input.MaterializationRoot},
		{"promotion-store", input.PromotionStore},
	}
	cleaned := make([]string, len(paths))
	for index, path := range paths {
		cleaned[index] = filepath.Clean(path.value)
		if !filepath.IsAbs(cleaned[index]) || cleaned[index] == string(filepath.Separator) {
			return "", "", "", deny("INVALID_PROMOTION_STORE", path.name, "protected promotion paths must be specific absolute paths")
		}
		canonical, err := canonicalProtectedPath(cleaned[index])
		if err != nil {
			return "", "", "", err
		}
		cleaned[index] = canonical
	}
	for left := range cleaned {
		for right := left + 1; right < len(cleaned); right++ {
			if pathsOverlap(cleaned[left], cleaned[right]) {
				return "", "", "", deny("CROSS_COMPANY_REFERENCE", paths[left].name, "evidence, materialization, and promotion storage paths must be isolated")
			}
		}
	}
	return cleaned[0], cleaned[1], cleaned[2], nil
}

func loadMaterializedObjects(root string, manifest MaterializationManifest, catalog map[string]expectedArtifact, enforceProductionDescriptor bool) ([]Object, error) {
	if manifest.SchemaVersion != "1.0.0" || manifest.Company != RequiredCompany || manifest.Project != RequiredProject || manifest.LaboratoryID != RequiredLaboratory || !validateDigest(manifest.CandidatePayloadRoot) {
		return nil, deny("CROSS_COMPANY_REFERENCE", "materialization", "materialization scope or schema differs from the protected laboratory")
	}
	if len(manifest.Objects) != 23 || len(catalog) != 23 {
		return nil, deny("MISSING_PROMOTION_REQUIREMENT", "materialization.objects", "exactly 23 materialized input objects are required")
	}
	if enforceProductionDescriptor {
		descriptor, exists := catalog["autobahn-linux-amd64-image"]
		if !exists || descriptor.Digest != AutobahnManifestDigest {
			return nil, deny("CONTAINER_DESCRIPTOR_MISMATCH", "materialization.objects", "Autobahn input must bind the exact linux/amd64 manifest blob digest")
		}
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, deny("MISSING_PROMOTION_REQUIREMENT", "materialization", "materialization root must be an existing non-symlink directory")
	}
	expectedIDs := make([]string, 0, len(catalog))
	for id := range catalog {
		expectedIDs = append(expectedIDs, id)
	}
	sort.Strings(expectedIDs)
	entriesByID := make(map[string]MaterializedObject, len(manifest.Objects))
	entryIndexes := make(map[string]int, len(manifest.Objects))
	for index, entry := range manifest.Objects {
		if _, expected := catalog[entry.ID]; !expected {
			return nil, deny("ARTIFACT_DRIFT", fmt.Sprintf("materialization.objects[%d].id", index), "materialization contains an unknown artifact id")
		}
		if _, duplicate := entriesByID[entry.ID]; duplicate {
			return nil, deny("DUPLICATE_ARCHIVE_ENTRY", fmt.Sprintf("materialization.objects[%d].id", index), "materialization contains a duplicate artifact id")
		}
		entriesByID[entry.ID] = entry
		entryIndexes[entry.ID] = index
	}
	objects := make([]Object, 0, len(expectedIDs))
	var totalBytes int64
	for _, id := range expectedIDs {
		entry, exists := entriesByID[id]
		if !exists {
			return nil, deny("MISSING_PROMOTION_REQUIREMENT", "materialization.objects", "materialization is missing a frozen artifact id")
		}
		index := entryIndexes[id]
		expected := catalog[id]
		if entry.SHA256 != expected.Digest || !validateDigest(entry.SHA256) {
			return nil, deny("DIGEST_MISMATCH", fmt.Sprintf("materialization.objects[%d]", index), "materialized object identity or digest differs from the frozen catalog")
		}
		if id == "autobahn-linux-amd64-image" {
			if entry.Kind != MaterializationKindOCIManifest || entry.ByteSize <= 0 || entry.ByteSize > maxOCIManifestBytes {
				return nil, deny("CONTAINER_DESCRIPTOR_MISMATCH", entry.ID, "Autobahn input must be the exact OCI manifest blob, not an archive tar or expanded image")
			}
		} else if entry.Kind != MaterializationKindArtifact || entry.ByteSize != expected.Size || entry.ByteSize <= 0 {
			return nil, deny("ARTIFACT_DRIFT", entry.ID, "materialized byte size or kind differs from the frozen catalog")
		}
		totalBytes += entry.ByteSize
		if totalBytes > maxMaterializedBatchBytes {
			return nil, deny("INPUT_TOO_LARGE", "materialization.objects", "materialized input batch exceeds 1 GiB")
		}
		data, err := readMaterializedFile(root, entry)
		if err != nil {
			return nil, err
		}
		objects = append(objects, Object{ID: entry.ID, Digest: entry.SHA256, Bytes: data})
	}
	return objects, nil
}

func readMaterializedFile(root string, entry MaterializedObject) ([]byte, error) {
	if entry.Path == "" || strings.Contains(entry.Path, "\\") || filepath.IsAbs(entry.Path) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.Path))) != entry.Path || entry.Path == "." || strings.HasPrefix(entry.Path, "../") {
		return nil, deny("PATH_TRAVERSAL", entry.Path, "materialized object path must be a clean relative slash path")
	}
	path := filepath.Join(root, filepath.FromSlash(entry.Path))
	evaluated, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(evaluated) != filepath.Clean(path) {
		return nil, deny("UNSAFE_ARCHIVE_ENTRY", entry.Path, "materialized object path may not traverse a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, deny("MISSING_PROMOTION_REQUIREMENT", entry.Path, "materialized object cannot be opened")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != entry.ByteSize {
		return nil, deny("ARTIFACT_DRIFT", entry.Path, "materialized object is not a regular file of the declared size")
	}
	data, err := io.ReadAll(io.LimitReader(file, entry.ByteSize+1))
	if err != nil || int64(len(data)) != entry.ByteSize || DigestBytes(data) != entry.SHA256 {
		return nil, deny("DIGEST_MISMATCH", entry.Path, "materialized object bytes differ from the frozen digest")
	}
	return data, nil
}

type promotionLock struct {
	path string
	file *os.File
	dir  string
}

func acquirePromotionLock(evidenceDirectory string) (*promotionLock, error) {
	path := filepath.Join(evidenceDirectory, ".owner-promotion.lock")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, deny("PARTIAL_PUBLICATION", path, "another promotion or stale promotion lock exists")
	}
	return &promotionLock{path: path, file: file, dir: evidenceDirectory}, nil
}

func (l *promotionLock) release() {
	_ = l.file.Close()
	_ = os.Remove(l.path)
	_ = syncDirectory(l.dir)
}

func stageEvidenceDirectory(source string, receipt promotionDocument) (string, error) {
	stage, err := os.MkdirTemp("", "java-websocket-owner-promotion-")
	if err != nil {
		return "", deny("PARTIAL_PUBLICATION", "staged-evidence", err.Error())
	}
	for _, name := range evidenceFiles {
		var data []byte
		if name == "promotion-receipts.json" {
			data, err = marshalIndentedJSON(receipt)
		} else {
			data, err = os.ReadFile(filepath.Join(source, name))
		}
		if err != nil || writeExclusiveSynced(filepath.Join(stage, name), data, 0o600) != nil {
			_ = os.RemoveAll(stage)
			return "", deny("PARTIAL_PUBLICATION", "staged-evidence", "could not construct protected staged evidence")
		}
	}
	if err := syncDirectory(stage); err != nil {
		_ = os.RemoveAll(stage)
		return "", deny("PARTIAL_PUBLICATION", "staged-evidence", err.Error())
	}
	return stage, nil
}

func captureEvidenceSnapshot(directory string, verifiedDigests map[string]string) (map[string][]byte, error) {
	snapshot, err := readEvidenceSnapshot(directory)
	if err != nil {
		return nil, err
	}
	for _, name := range evidenceFiles {
		if DigestBytes(snapshot[name]) != verifiedDigests[name] {
			return nil, deny("ARTIFACT_DRIFT", name, "evidence changed while its immutable promotion snapshot was captured")
		}
	}
	return snapshot, nil
}

func readEvidenceSnapshot(directory string) (map[string][]byte, error) {
	snapshot := make(map[string][]byte, len(evidenceFiles))
	for _, name := range evidenceFiles {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return nil, deny("ARTIFACT_DRIFT", name, "evidence snapshot cannot be read completely")
		}
		snapshot[name] = data
	}
	return snapshot, nil
}

func compareEvidenceSnapshot(directory string, expected map[string][]byte) error {
	actual, err := readEvidenceSnapshot(directory)
	if err != nil {
		return err
	}
	for _, name := range evidenceFiles {
		if expectedBytes, exists := expected[name]; !exists || !bytes.Equal(actual[name], expectedBytes) {
			return deny("ARTIFACT_DRIFT", name, "evidence changed after protected verification and before receipt persistence")
		}
	}
	return nil
}

func persistReceiptAtomically(directory string, expected map[string][]byte, receipt promotionDocument) error {
	path := filepath.Join(directory, "promotion-receipts.json")
	data, err := marshalIndentedJSON(receipt)
	if err != nil {
		return deny("PARTIAL_PUBLICATION", path, err.Error())
	}
	temporary, err := os.CreateTemp(directory, ".promotion-receipts-*.tmp")
	if err != nil {
		return deny("PARTIAL_PUBLICATION", path, err.Error())
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return deny("PARTIAL_PUBLICATION", path, err.Error())
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return deny("PARTIAL_PUBLICATION", path, err.Error())
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return deny("PARTIAL_PUBLICATION", path, err.Error())
	}
	if err := temporary.Close(); err != nil {
		return deny("PARTIAL_PUBLICATION", path, err.Error())
	}
	if err := compareEvidenceSnapshot(directory, expected); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return deny("PARTIAL_PUBLICATION", path, err.Error())
	}
	if err := syncDirectory(directory); err != nil {
		return deny("DURABILITY_UNCERTAIN", path, err.Error())
	}
	return nil
}

func marshalIndentedJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func pathsOverlap(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if left == right {
		return true
	}
	leftRelative, leftErr := filepath.Rel(left, right)
	rightRelative, rightErr := filepath.Rel(right, left)
	return leftErr == nil && leftRelative != ".." && !strings.HasPrefix(leftRelative, ".."+string(filepath.Separator)) ||
		rightErr == nil && rightRelative != ".." && !strings.HasPrefix(rightRelative, ".."+string(filepath.Separator))
}

func canonicalProtectedPath(path string) (string, error) {
	clean := filepath.Clean(path)
	missing := make([]string, 0, 4)
	existing := clean
	for {
		_, err := os.Lstat(existing)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", deny("UNSAFE_ARCHIVE_ENTRY", path, "protected path contains an unreadable component")
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", deny("UNSAFE_ARCHIVE_ENTRY", path, "protected path has no resolvable ancestor")
		}
		missing = append(missing, filepath.Base(existing))
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", deny("UNSAFE_ARCHIVE_ENTRY", path, "protected path contains an unsafe component")
	}
	for index := len(missing) - 1; index >= 0; index-- {
		resolved = filepath.Join(resolved, missing[index])
	}
	return filepath.Clean(resolved), nil
}
