package corpora

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestUS010EvidenceSourceBindingRejectsOversizedHistoricalBlob(t *testing.T) {
	root := t.TempDir()
	runUS010TestGit(t, root, "init", "--quiet")
	runUS010TestGit(t, root, "config", "user.email", "us010@example.invalid")
	runUS010TestGit(t, root, "config", "user.name", "US010 Test")

	const artifactPath = "artifact.bin"
	committed := bytes.Repeat([]byte("x"), int(us010MaxArtifactBytes+1))
	if err := os.WriteFile(filepath.Join(root, artifactPath), committed, 0o600); err != nil {
		t.Fatal(err)
	}
	runUS010TestGit(t, root, "add", artifactPath)
	runUS010TestGit(t, root, "commit", "--quiet", "-m", "oversized historical artifact")
	commit := strings.TrimSpace(runUS010TestGit(t, root, "rev-parse", "HEAD"))
	tree := strings.TrimSpace(runUS010TestGit(t, root, "rev-parse", "HEAD^{tree}"))

	if err := os.WriteFile(filepath.Join(root, artifactPath), []byte("bounded working copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifacts := []evidenceArtifact{{Path: artifactPath, SHA256: DigestSHA256(committed)}}
	if err := verifyUS010GitSourceBinding(root, commit, tree, artifacts); err == nil {
		t.Fatal("oversized historical git blob was accepted")
	}
}

func runUS010TestGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", root}, args...)
	output, err := exec.Command("git", commandArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return string(output)
}
