package intake

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStrictJSONRejectsAmbiguity(t *testing.T) {
	t.Parallel()
	var target struct {
		Name string `json:"name"`
	}
	for _, tc := range []struct {
		name string
		data string
		code string
	}{
		{"duplicate", `{"name":"a","name":"b"}`, "DUPLICATE_JSON_FIELD"},
		{"unknown", `{"name":"a","extra":true}`, "UNKNOWN_JSON_FIELD"},
		{"trailing", `{"name":"a"}{}`, "TRAILING_JSON_VALUE"},
		{"null", `null`, "NULL_JSON_DOCUMENT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := DecodeStrict([]byte(tc.data), &target)
			assertCode(t, err, tc.code)
		})
	}
}

func TestValidateActionCryptographicallyBindsScopeAndRoles(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	action := validAction(now)
	action.Signature = hex.EncodeToString(ed25519.Sign(privateKey, CanonicalAction(action)))
	keys := map[string]Identity{
		action.ActorID: {
			ActorID:   action.ActorID,
			Role:      action.Role,
			KeyID:     action.KeyID,
			PublicKey: hex.EncodeToString(publicKey),
		},
	}
	ledger := NewMemoryLedger()
	if err := Authorize(action, keys, Snapshot{RoleDigest: action.RoleSnapshotDigest, RevocationDigest: action.RevocationSnapshotDigest}, ledger, now); err != nil {
		t.Fatalf("valid action denied: %v", err)
	}
	if err := Authorize(action, keys, Snapshot{RoleDigest: action.RoleSnapshotDigest, RevocationDigest: action.RevocationSnapshotDigest}, ledger, now); err == nil {
		t.Fatal("replayed action accepted")
	} else {
		assertCode(t, err, "REPLAYED_APPROVAL")
	}

	mutations := []struct {
		name string
		edit func(*Action)
		code string
	}{
		{"artifact", func(a *Action) { a.ObjectID = "mutated" }, "INVALID_SIGNATURE"},
		{"company", func(a *Action) { a.Company = "other-company" }, "CROSS_COMPANY_REFERENCE"},
		{"publication", func(a *Action) { a.Publication.Requested = true }, "ROLE_ACTION_MISMATCH"},
		{"sandbox", func(a *Action) { a.RequestedSandboxAccess = []string{"protected-store"} }, "ROLE_ACTION_MISMATCH"},
		{"expired", func(a *Action) { a.ExpiresAt = now.Add(-time.Second) }, "EXPIRED_AUTHORIZATION"},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			candidate := action
			candidate.Nonce = "nonce-" + tc.name + "-000000000000"
			tc.edit(&candidate)
			err := Authorize(candidate, keys, Snapshot{RoleDigest: candidate.RoleSnapshotDigest, RevocationDigest: candidate.RevocationSnapshotDigest}, NewMemoryLedger(), now)
			assertCode(t, err, tc.code)
		})
	}
}

func TestRoleStagePolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		stage  string
		role   string
		sbox   []string
		pub    bool
		permit bool
	}{
		{"acquire", "acquisition", "method-schema-steward", nil, false, true},
		{"quarantine", "quarantine", "port-implementer", nil, false, true},
		{"qualification", "qualification", "port-implementer", []string{"quarantined-source"}, false, true},
		{"promotion", "independent-promotion", "release-attestor", nil, false, true},
		{"attestor-sandbox", "qualification", "release-attestor", []string{"quarantined-source"}, false, false},
		{"implementer-publish", "qualification", "port-implementer", []string{"quarantined-source"}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRoleStage(tc.stage, tc.role, tc.sbox, PublicationIntent{Requested: tc.pub, Classification: "PUBLIC"})
			if tc.permit && err != nil {
				t.Fatalf("valid role/stage denied: %v", err)
			}
			if !tc.permit {
				assertCode(t, err, "ROLE_ACTION_MISMATCH")
			}
		})
	}
}

func TestArchiveInspectionFailsClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		header tar.Header
		body   []byte
		code   string
	}{
		{"traversal", tar.Header{Name: "../escape", Mode: 0o644, Typeflag: tar.TypeReg}, []byte("x"), "PATH_TRAVERSAL"},
		{"absolute", tar.Header{Name: "/escape", Mode: 0o644, Typeflag: tar.TypeReg}, []byte("x"), "ABSOLUTE_PATH"},
		{"symlink", tar.Header{Name: "link", Linkname: "target", Mode: 0o777, Typeflag: tar.TypeSymlink}, nil, "UNSAFE_ARCHIVE_ENTRY"},
		{"device", tar.Header{Name: "dev", Mode: 0o600, Typeflag: tar.TypeChar}, nil, "UNSAFE_ARCHIVE_ENTRY"},
		{"undeclared-executable", tar.Header{Name: "bin/tool", Mode: 0o755, Typeflag: tar.TypeReg}, []byte("tool"), "UNDECLARED_EXECUTABLE"},
		{"nested", tar.Header{Name: "payload.bin", Mode: 0o644, Typeflag: tar.TypeReg}, append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0}, 16)...), "NESTED_ARCHIVE_DENIED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := tarBytes(t, []tar.Header{tc.header}, [][]byte{tc.body})
			_, err := InspectTar(bytes.NewReader(archive), ArchivePolicy{DeclaredExecutables: map[string]bool{}, MaxEntries: 16, MaxFileBytes: 1024, MaxTotalBytes: 4096, MaxDepth: 8})
			assertCode(t, err, tc.code)
		})
	}
}

func TestArchiveInspectionRejectsNormalizationCollision(t *testing.T) {
	t.Parallel()
	headers := []tar.Header{
		{Name: "README", Mode: 0o644, Typeflag: tar.TypeReg},
		{Name: "readme", Mode: 0o644, Typeflag: tar.TypeReg},
	}
	archive := tarBytes(t, headers, [][]byte{[]byte("a"), []byte("b")})
	_, err := InspectTar(bytes.NewReader(archive), ArchivePolicy{MaxEntries: 16, MaxFileBytes: 1024, MaxTotalBytes: 4096, MaxDepth: 8})
	assertCode(t, err, "NORMALIZATION_COLLISION")
}

func TestZipInspectionRejectsBombAndUnsafePaths(t *testing.T) {
	t.Parallel()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: "large.txt", Method: zip.Deflate}
	entry, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(bytes.Repeat([]byte("a"), 1<<20)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = InspectZip(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()), ArchivePolicy{MaxEntries: 4, MaxFileBytes: 2 << 20, MaxTotalBytes: 2 << 20, MaxDepth: 4})
	assertCode(t, err, "ARCHIVE_LIMIT_EXCEEDED")
}

func TestFileLedgerConsumesNonceOnceUnderConcurrency(t *testing.T) {
	t.Parallel()
	ledger := FileLedger{Directory: filepath.Join(t.TempDir(), "protected-ledger")}
	const callers = 32
	results := make(chan bool, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- ledger.Consume("github:existing-actor", "nonce-concurrent-0000000001")
		}()
	}
	group.Wait()
	close(results)
	winners := 0
	for result := range results {
		if result {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("got %d successful nonce consumers, want 1", winners)
	}
	entries, err := os.ReadDir(ledger.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d ledger records, want 1", len(entries))
	}
}

func TestPromoteBatchIsAtomicAndIdempotent(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	objects := []Object{{ID: "a", Digest: DigestBytes([]byte("a")), Bytes: []byte("a")}, {ID: "b", Digest: DigestBytes([]byte("b")), Bytes: []byte("b")}}
	store.FailOn("b")
	err := PromoteBatch(store, objects)
	assertCode(t, err, "PARTIAL_PUBLICATION")
	if store.Count() != 0 {
		t.Fatalf("partial batch committed: %d objects", store.Count())
	}
	store.FailOn("")
	if err := PromoteBatch(store, objects); err != nil {
		t.Fatal(err)
	}
	if err := PromoteBatch(store, objects); err != nil {
		t.Fatalf("idempotent replay failed: %v", err)
	}
	if store.Count() != len(objects) {
		t.Fatalf("got %d objects, want %d", store.Count(), len(objects))
	}
}

func TestDurablePromotionIsAtomicAndIdempotent(t *testing.T) {
	t.Parallel()
	base := filepath.Join(t.TempDir(), "protected-promotion-store")
	objects := []Object{{ID: "artifact-a", Digest: DigestBytes([]byte("a")), Bytes: []byte("a")}, {ID: "artifact-b", Digest: DigestBytes([]byte("b")), Bytes: []byte("b")}}
	root, err := PromoteDirectory(base, objects)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := PromoteDirectory(base, objects)
	if err != nil {
		t.Fatal(err)
	}
	if replayed != root {
		t.Fatalf("idempotent root changed: %s != %s", replayed, root)
	}
	accepted, err := os.ReadDir(filepath.Join(base, "accepted"))
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) != 1 {
		t.Fatalf("got %d accepted batches, want 1", len(accepted))
	}
	bad := append([]Object(nil), objects...)
	bad[1].Digest = DigestBytes([]byte("mutated"))
	_, err = PromoteDirectory(base, bad)
	assertCode(t, err, "DIGEST_MISMATCH")
	accepted, err = os.ReadDir(filepath.Join(base, "accepted"))
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) != 1 {
		t.Fatalf("invalid batch changed accepted state: %d", len(accepted))
	}
}

func TestValidateAutobahnDescriptorRejectsFloatingOrWrongPlatform(t *testing.T) {
	t.Parallel()
	valid := ContainerDescriptor{Reference: "docker.io/crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074", Platform: "linux/amd64", ManifestDigest: AutobahnManifestDigest, ConfigDigest: "sha256:b0475418d42ae284876bd695f0282fbe6684e00f745d787b095d60e55727a06f"}
	if err := ValidateAutobahnDescriptor(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ContainerDescriptor){
		func(d *ContainerDescriptor) { d.Reference = "docker.io/crossbario/autobahn-testsuite:25.10.1" },
		func(d *ContainerDescriptor) { d.Platform = "linux/arm64" },
		func(d *ContainerDescriptor) { d.ManifestDigest = "sha256:" + string(bytes.Repeat([]byte("a"), 64)) },
		func(d *ContainerDescriptor) { d.ConfigDigest = "sha256:" + string(bytes.Repeat([]byte("b"), 64)) },
	} {
		candidate := valid
		mutate(&candidate)
		assertCode(t, ValidateAutobahnDescriptor(candidate), "CONTAINER_DESCRIPTOR_MISMATCH")
	}
}

func validAction(now time.Time) Action {
	return Action{
		ObjectID: "object-source-pin-set", ObjectKind: "artifact-set", Stage: "qualification", Action: "qualify",
		ActorID: "github:port-implementer", Role: "port-implementer", KeyID: "ed25519:port-implementer-2026-08",
		Company: RequiredCompany, Project: RequiredProject, LaboratoryID: RequiredLaboratory,
		ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicyVersion:  "toolchain-promotion-1.0.0", PolicyDigest: "sha256:12a11bc4015ad5fd52e447053b8c3a7a3bc0b9e79389737ec7fc6bac0d465c54",
		RequestedSandboxAccess: []string{"quarantined-source"}, Publication: PublicationIntent{Requested: false, Classification: "QUARANTINED"},
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Nonce: "nonce-valid-0000000000000001",
		RoleSnapshotDigest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RevocationSnapshotDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
}

func tarBytes(t *testing.T, headers []tar.Header, bodies [][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	w := tar.NewWriter(&buffer)
	for i := range headers {
		header := headers[i]
		header.Size = int64(len(bodies[i]))
		if err := w.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(bodies[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", code)
	}
	finding, ok := err.(*Finding)
	if !ok {
		t.Fatalf("expected Finding, got %T: %v", err, err)
	}
	if finding.Code != code {
		t.Fatalf("got %s, want %s (%v)", finding.Code, code, err)
	}
}
