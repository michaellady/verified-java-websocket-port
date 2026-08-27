package corpora

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommittedServerHandshakeProjectionReconciles(t *testing.T) {
	projection, err := LoadAndVerifyServerHandshakeProjection(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.FrozenCases) != 39 || len(projection.NonceVectors) != 256 ||
		len(projection.FuzzSeeds) != 17 {
		t.Fatalf("unexpected server inventory: frozen=%d nonce=%d fuzz=%d",
			len(projection.FrozenCases), len(projection.NonceVectors), len(projection.FuzzSeeds))
	}
}

func TestCommittedServerHandshakeEvidenceClosesExactCheckout(t *testing.T) {
	if err := VerifyServerHandshakeEvidence(repoRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func TestServerProjectionRejectsVerdictNonceAndAuthorityDrift(t *testing.T) {
	root := repoRoot(t)
	projection, err := LoadAndVerifyServerHandshakeProjection(root)
	if err != nil {
		t.Fatal(err)
	}
	sourceRaw, err := readUS010Artifact(root, projection.FrozenSource.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	source, err := clientRequestCases(sourceRaw)
	if err != nil {
		t.Fatal(err)
	}

	verdict := projection
	verdict.FrozenCases = append([]ServerHandshakeCase(nil), projection.FrozenCases...)
	verdict.FrozenCases[0].RustExpected = "Rejected"
	if err := verifyFrozenServerProjection(verdict, source); err == nil {
		t.Fatal("frozen Rust verdict drift was accepted")
	}

	nonce := append([]ServerHandshakeNonceVector(nil), projection.NonceVectors...)
	nonce[7].Accept = nonce[8].Accept
	if err := verifyServerNonceVectors(root, nonce); err == nil {
		t.Fatal("nonce accept drift was accepted")
	}

	authority := projection
	authority.Authority.StrictnessRule = "Java observations override RFC strictness"
	if err := verifyServerAuthority(authority.Authority); err == nil {
		t.Fatal("reversed authority was accepted")
	}

	javaDrift := projection
	javaDrift.FrozenCases = append([]ServerHandshakeCase(nil), projection.FrozenCases...)
	javaDrift.FrozenCases[0].Java.Observable = "reject"
	if err := verifyServerJavaMapping(root, source, javaDrift.FrozenCases); err == nil {
		t.Fatal("per-case Java observable drift was accepted")
	}
	var duplicatedKey, duplicatedVersion ServerHandshakeJavaObservation
	for _, item := range projection.FrozenCases {
		switch item.CaseID {
		case "us005.hs.0027":
			duplicatedKey = item.Java
		case "us005.hs.0028":
			duplicatedVersion = item.Java
		}
	}
	if duplicatedKey.Observable != "accept" || !duplicatedKey.Divergent ||
		duplicatedVersion.Observable != "reject" || duplicatedVersion.Divergent ||
		duplicatedVersion.RejectChannel != "not_matched" {
		t.Fatal("duplicate key/version Java outcomes were collapsed")
	}

	fixture, err := readUS010Artifact(root, us011FrozenRustFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	tamperedFixture := bytes.Replace(fixture, []byte("us005.hs.0027"), []byte("us005.hs.0028"), 1)
	if bytes.Equal(tamperedFixture, fixture) {
		t.Fatal("fixture tamper precondition did not modify bytes")
	}
	if err := verifyServerFrozenRustFixtureBytes(tamperedFixture, projection, source); err == nil {
		t.Fatal("executable Rust frozen-fixture tampering was accepted")
	}
	tamperedSource := make(map[string]HandshakeCase, len(source))
	for id, item := range source {
		tamperedSource[id] = item
	}
	item := tamperedSource["us005.hs.0000"]
	item.RawBase64 = tamperedSource["us005.hs.0001"].RawBase64
	tamperedSource["us005.hs.0000"] = item
	if err := verifyServerFrozenRustFixtureBytes(fixture, projection, tamperedSource); err == nil {
		t.Fatal("frozen corpus byte drift away from the executable Rust fixture was accepted")
	}
}

func TestUS011ProjectionAndReceiptRejectNonclaimSubstitutionReorderingAndOmission(t *testing.T) {
	mutations := map[string]func([]string) []string{
		"substituted": func(value []string) []string {
			value[0] = "frames are probably out of scope"
			return value
		},
		"reordered": func(value []string) []string {
			value[0], value[1] = value[1], value[0]
			return value
		},
		"omitted": func(value []string) []string {
			return value[:len(value)-1]
		},
	}
	for name, mutate := range mutations {
		t.Run("projection_"+name, func(t *testing.T) {
			projection := ServerHandshakeProjection{Nonclaims: mutate(append([]string(nil), exactServerNonclaims...))}
			if err := verifyServerProjectionNonclaims(projection); err == nil {
				t.Fatalf("%s projection nonclaims were accepted", name)
			}
		})
		t.Run("receipt_"+name, func(t *testing.T) {
			evidence := serverHandshakeEvidence{Nonclaims: mutate(append([]string(nil), exactServerNonclaims...))}
			if err := verifyServerEvidenceNonclaims(evidence); err == nil {
				t.Fatalf("%s receipt nonclaims were accepted", name)
			}
		})
	}
	if err := verifyServerProjectionNonclaims(ServerHandshakeProjection{Nonclaims: exactServerNonclaims}); err != nil {
		t.Fatalf("canonical projection nonclaims failed: %v", err)
	}
	if err := verifyServerEvidenceNonclaims(serverHandshakeEvidence{Nonclaims: exactServerNonclaims}); err != nil {
		t.Fatalf("canonical receipt nonclaims failed: %v", err)
	}
}

func TestUS011ReceiptPathsAreAClosedAllowlist(t *testing.T) {
	raw, err := readUS010Artifact(repoRoot(t), us011ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var evidence serverHandshakeEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	// The receipt is updated after the implementation commit. Assigning this
	// field keeps the pre-receipt implementation commit independently testable.
	evidence.Corpus.EvidenceSchemaPath = us011EvidenceSchemaPath
	if err := verifyUS011AncillaryPaths(evidence); err != nil {
		t.Fatalf("committed ancillary allowlist failed: %v", err)
	}
	mutations := []func(*serverHandshakeEvidence){
		func(value *serverHandshakeEvidence) { value.Corpus.ProjectionPath = us011JavaMappingPath },
		func(value *serverHandshakeEvidence) { value.Corpus.SchemaPath = us011EvidenceSchemaPath },
		func(value *serverHandshakeEvidence) { value.Corpus.EvidenceSchemaPath = us011CorpusSchemaPath },
		func(value *serverHandshakeEvidence) { value.Symbols.MigrationMapPath = us011CompatibilityPath },
		func(value *serverHandshakeEvidence) { value.Compatibility.JavaMappingPath = us011ProjectionPath },
		func(value *serverHandshakeEvidence) { value.DeltaLedger.Path = us011EvidenceDAGPath },
		func(value *serverHandshakeEvidence) { value.EvidenceDAGPath = us011DeltaLedgerPath },
	}
	for index, mutate := range mutations {
		drift := evidence
		mutate(&drift)
		if err := verifyUS011AncillaryPaths(drift); err == nil {
			t.Fatalf("receipt path substitution %d was accepted", index)
		}
	}
}

func TestUS011CheckoutHeadBindingRejectsDirtyReceiptAndAncillaryArtifacts(t *testing.T) {
	root := t.TempDir()
	runUS010TestGit(t, root, "init", "--quiet")
	runUS010TestGit(t, root, "config", "user.email", "us011@example.invalid")
	runUS010TestGit(t, root, "config", "user.name", "US011 Test")
	if err := os.MkdirAll(filepath.Join(root, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, "evidence", "receipt.json")
	ancillaryPath := filepath.Join(root, "evidence", "ancillary.json")
	receipt := []byte("{\"receipt\":true}\n")
	ancillary := []byte("{\"ancillary\":true}\n")
	if err := os.WriteFile(receiptPath, receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ancillaryPath, ancillary, 0o600); err != nil {
		t.Fatal(err)
	}
	runUS010TestGit(t, root, "add", "evidence/receipt.json", "evidence/ancillary.json")
	runUS010TestGit(t, root, "commit", "--quiet", "-m", "exact evidence")

	if err := verifyUS011CheckoutHeadArtifact(root, "evidence/receipt.json", ""); err != nil {
		t.Fatalf("clean receipt failed: %v", err)
	}
	if err := verifyUS011CheckoutHeadArtifact(root, "evidence/ancillary.json", DigestSHA256(ancillary)); err != nil {
		t.Fatalf("clean ancillary failed: %v", err)
	}
	if err := os.WriteFile(receiptPath, []byte("{\"receipt\":false}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyUS011CheckoutHeadArtifact(root, "evidence/receipt.json", ""); err == nil {
		t.Fatal("dirty receipt was accepted")
	}
	if err := os.WriteFile(receiptPath, receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ancillaryPath, []byte("{\"ancillary\":false}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyUS011CheckoutHeadArtifact(root, "evidence/ancillary.json", DigestSHA256(ancillary)); err == nil {
		t.Fatal("dirty ancillary artifact was accepted")
	}
	if err := os.WriteFile(ancillaryPath, ancillary, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyUS011CheckoutHeadArtifact(root, "evidence/ancillary.json", DigestSHA256([]byte("stale"))); err == nil {
		t.Fatal("stale ancillary digest was accepted")
	}
	if err := verifyUS011CheckoutHeadArtifact(root, "evidence/missing.json", ""); err == nil {
		t.Fatal("missing ancillary artifact was accepted")
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, ancillary, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "evidence", "symlink.json")); err != nil {
		t.Fatal(err)
	}
	if err := verifyUS011CheckoutHeadArtifact(root, "evidence/symlink.json", DigestSHA256(ancillary)); err == nil {
		t.Fatal("symlinked ancillary artifact was accepted")
	}
}

func TestUS011ReusesHardenedReaderForNestedPathsAndRejectsEscapeAndSymlink(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "one", "two")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "artifact.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readUS010Artifact(root, "one/two/artifact.json"); err != nil || string(raw) != "{}" {
		t.Fatalf("safe deeper nesting failed: %q, %v", raw, err)
	}
	out := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(out, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(root, "link.json")); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"../outside.json", out, "one/../../outside.json", "link.json", `one\\two\\artifact.json`} {
		if _, err := readUS010Artifact(root, unsafe); err == nil {
			t.Fatalf("unsafe artifact path was accepted: %q", unsafe)
		}
	}
	if _, err := readUS010Artifact(root, "missing.json"); err == nil {
		t.Fatal("missing artifact was accepted")
	}
}

func TestUS011CheckoutBindingRejectsStaleAndMissingHeadEntries(t *testing.T) {
	root := t.TempDir()
	runUS010TestGit(t, root, "init", "--quiet")
	runUS010TestGit(t, root, "config", "user.email", "us011@example.invalid")
	runUS010TestGit(t, root, "config", "user.name", "US011 Test")
	path := filepath.Join(root, "artifact.txt")
	first := []byte("first committed bytes")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	runUS010TestGit(t, root, "add", "artifact.txt")
	runUS010TestGit(t, root, "commit", "--quiet", "-m", "first")
	firstCommit := strings.TrimSpace(runUS010TestGit(t, root, "rev-parse", "HEAD"))
	firstBlob := runUS010TestGit(t, root, "rev-parse", "HEAD:artifact.txt")
	firstBlob = firstBlob[:len(firstBlob)-1]
	stale := []evidenceArtifact{{Path: "artifact.txt", SHA256: DigestSHA256(first), GitBlob: firstBlob}}
	if err := verifyUS010GitSourceBindingAtCommit(root, firstCommit, stale); err != nil {
		t.Fatalf("exact historical binding failed: %v", err)
	}
	if err := os.WriteFile(path, []byte("second committed bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	runUS010TestGit(t, root, "add", "artifact.txt")
	runUS010TestGit(t, root, "commit", "--quiet", "-m", "second")
	secondCommit := strings.TrimSpace(runUS010TestGit(t, root, "rev-parse", "HEAD"))
	if err := verifyUS010GitSourceBindingAtCommit(root, secondCommit, stale); err == nil {
		t.Fatal("forged later-commit historical blob receipt was accepted")
	}
	missing := []evidenceArtifact{{Path: "missing.txt", SHA256: DigestSHA256(nil), GitBlob: firstBlob}}
	if err := verifyUS010GitSourceBindingAtCommit(root, firstCommit, missing); err == nil {
		t.Fatal("missing checkout entry was accepted")
	}
}
