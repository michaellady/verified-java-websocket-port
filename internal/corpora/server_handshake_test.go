package corpora

import (
	"os"
	"path/filepath"
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
	firstBlob := runUS010TestGit(t, root, "rev-parse", "HEAD:artifact.txt")
	firstBlob = firstBlob[:len(firstBlob)-1]
	stale := []evidenceArtifact{{Path: "artifact.txt", SHA256: DigestSHA256(first), GitBlob: firstBlob}}
	if err := verifyUS010GitSourceBinding(root, stale); err != nil {
		t.Fatalf("fresh checkout binding failed: %v", err)
	}
	if err := os.WriteFile(path, []byte("second committed bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	runUS010TestGit(t, root, "add", "artifact.txt")
	runUS010TestGit(t, root, "commit", "--quiet", "-m", "second")
	if err := verifyUS010GitSourceBinding(root, stale); err == nil {
		t.Fatal("stale checkout blob receipt was accepted")
	}
	missing := []evidenceArtifact{{Path: "missing.txt", SHA256: DigestSHA256(nil), GitBlob: firstBlob}}
	if err := verifyUS010GitSourceBinding(root, missing); err == nil {
		t.Fatal("missing checkout entry was accepted")
	}
}
