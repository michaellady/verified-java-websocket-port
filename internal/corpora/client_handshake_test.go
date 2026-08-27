package corpora

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCommittedClientHandshakeProjectionReconciles(t *testing.T) {
	projection, err := LoadAndVerifyClientHandshakeProjection(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.AdditiveVectors) != 18 || len(projection.Nonclaims) != 6 {
		t.Fatalf("unexpected additive/nonclaim inventory: %d/%d", len(projection.AdditiveVectors), len(projection.Nonclaims))
	}
}

func TestCommittedClientHandshakeEvidenceClosesExactArtifacts(t *testing.T) {
	if err := VerifyClientHandshakeEvidence(repoRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func TestUS010ArtifactReadsFailClosedAtTheRepositoryBoundary(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "regular.json")
	if err := os.WriteFile(regular, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readUS010Artifact(root, "regular.json"); err != nil || string(raw) != "{}" {
		t.Fatalf("regular artifact read = %q, %v", raw, err)
	}

	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "symlink.json")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(root, "hardlink.json")
	if err := os.Link(regular, hardlink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(root, "oversized.json")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(us010MaxArtifactBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"absolute":     outside,
		"parent":       "../outside.json",
		"symlink":      "symlink.json",
		"directory":    ".",
		"special-file": "fifo.json",
		"multi-link":   "hardlink.json",
		"oversized":    "oversized.json",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readUS010Artifact(root, path); err == nil {
				t.Fatalf("unsafe path %q was read", path)
			}
		})
	}
}

func TestUS010ProjectionRejectsFrozenVerdictPropertyAndSeedConfigDrift(t *testing.T) {
	root := repoRoot(t)
	projection, err := LoadAndVerifyClientHandshakeProjection(root)
	if err != nil {
		t.Fatal(err)
	}
	sourceRaw, err := readUS010Artifact(root, projection.FrozenSource.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	sourceCases, err := serverResponseCases(sourceRaw)
	if err != nil {
		t.Fatal(err)
	}

	verdictDrift := projection
	verdictDrift.FrozenCases = append([]ClientHandshakeCase(nil), projection.FrozenCases...)
	verdictDrift.FrozenCases[0].Expected = "AcceptMismatch"
	if err := verifyFrozenClientProjection(verdictDrift, sourceCases); err == nil {
		t.Fatal("frozen expected-verdict drift was accepted")
	}

	propertyDrift := projection
	propertyDrift.Properties.DeterministicProperties = append(
		[]string(nil), projection.Properties.DeterministicProperties...)
	propertyDrift.Properties.DeterministicProperties[0] = "all ASCII case permutations"
	if err := verifyClientPropertyClaims(propertyDrift.Properties); err == nil {
		t.Fatal("unsupported deterministic-property drift was accepted")
	}

	seedDrift := projection
	seedDrift.FuzzSeeds = append([]ClientHandshakeFuzzSeed(nil), projection.FuzzSeeds...)
	seedDrift.FuzzSeeds[0].Expected = "Open"
	if err := verifyClientFuzzProjection(root, seedDrift.FuzzSeeds); err == nil {
		t.Fatal("fuzz expected-verdict drift was accepted")
	}
	seedDrift = projection
	seedDrift.FuzzSeeds = append([]ClientHandshakeFuzzSeed(nil), projection.FuzzSeeds...)
	seedDrift.FuzzSeeds[0].Config.MaxHandshakeBytes++
	if err := verifyClientFuzzProjection(root, seedDrift.FuzzSeeds); err == nil {
		t.Fatal("fuzz execution-config drift was accepted")
	}
}

func TestUS010EvidenceSourceBindingRequiresRealGitObjects(t *testing.T) {
	raw, err := readUS010Artifact(repoRoot(t), "evidence/us010-client-handshake.json")
	if err != nil {
		t.Fatal(err)
	}
	var evidence clientHandshakeEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	if err := verifyUS010GitSourceBinding(repoRoot(t), evidence.Source.Commit, evidence.Source.Tree, evidence.Source.ImplementationFiles); err != nil {
		t.Fatalf("committed source binding failed: %v", err)
	}
	if err := verifyUS010GitSourceBinding(repoRoot(t), "0000000000000000000000000000000000000000", evidence.Source.Tree, evidence.Source.ImplementationFiles); err == nil {
		t.Fatal("hex-shaped nonexistent commit was accepted")
	}
}
