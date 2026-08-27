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

	"github.com/michaellady/verified-java-websocket-port/internal/provenance"
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

func TestUS010ArtifactReadRejectsInPlaceSameSizeMutation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact.json")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = readUS010ArtifactWithHooks(root, "artifact.json", us010ArtifactReadHooks{
		afterOpen: func() {
			if writeErr := os.WriteFile(path, []byte("tampered"), 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			if timeErr := os.Chtimes(path, original.ModTime(), original.ModTime()); timeErr != nil {
				t.Fatal(timeErr)
			}
		},
	})
	if err == nil {
		t.Fatal("same-inode same-size mutation with restored mtime was accepted")
	}
}

func TestUS010ArtifactReadRejectsParentSymlinkSwap(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	moved := filepath.Join(root, "moved")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "artifact.json"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := readUS010ArtifactWithHooks(root, "parent/artifact.json", us010ArtifactReadHooks{
		beforeOpen: func() {
			if renameErr := os.Rename(parent, moved); renameErr != nil {
				t.Fatal(renameErr)
			}
			if linkErr := os.Symlink("moved", parent); linkErr != nil {
				t.Fatal(linkErr)
			}
		},
	})
	if err == nil {
		t.Fatal("parent-directory symlink swap was accepted")
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

func TestUS010EvidenceSourceBindingRequiresExactGitBlobs(t *testing.T) {
	raw, err := readUS010Artifact(repoRoot(t), "evidence/us010-client-handshake.json")
	if err != nil {
		t.Fatal(err)
	}
	var evidence clientHandshakeEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	rawReceipt, readErr := readUS010Artifact(repoRoot(t), "evidence/us010-client-handshake.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	commit, resolveErr := provenance.ResolveHistoricalArtifactCommit(repoRoot(t), "evidence/us010-client-handshake.json", rawReceipt)
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	if err := verifyUS010GitSourceBindingAtCommit(repoRoot(t), commit, evidence.Source.ImplementationFiles); err != nil {
		t.Fatalf("committed source binding failed: %v", err)
	}
	drift := append([]evidenceArtifact(nil), evidence.Source.ImplementationFiles...)
	drift[0].GitBlob = "0000000000000000000000000000000000000000"
	if err := verifyUS010GitSourceBindingAtCommit(repoRoot(t), commit, drift); err == nil {
		t.Fatal("hex-shaped nonexistent source blob was accepted")
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
	if _, err := readUS010GitBlob(root, commit+":"+artifactPath); err == nil {
		t.Fatal("oversized historical git blob was accepted")
	}
}

func TestUS010EvidenceSourceBindingSupportsDepthOneCheckoutAndRejectsTamper(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	runUS010TestGit(t, source, "init", "--quiet")
	runUS010TestGit(t, source, "config", "user.email", "us010@example.invalid")
	runUS010TestGit(t, source, "config", "user.name", "US010 Test")

	const artifactPath = "artifact.bin"
	committed := []byte("exact implementation bytes")
	if err := os.WriteFile(filepath.Join(source, artifactPath), committed, 0o600); err != nil {
		t.Fatal(err)
	}
	runUS010TestGit(t, source, "add", artifactPath)
	runUS010TestGit(t, source, "commit", "--quiet", "-m", "source implementation")
	commit := strings.TrimSpace(runUS010TestGit(t, source, "rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(source, "receipt.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	runUS010TestGit(t, source, "add", "receipt.json")
	runUS010TestGit(t, source, "commit", "--quiet", "-m", "bind source receipt")
	gitBlob := strings.TrimSpace(runUS010TestGit(t, source, "rev-parse", "HEAD:"+artifactPath))

	checkout := filepath.Join(base, "checkout")
	runUS010TestGit(t, base, "clone", "--quiet", "--depth", "1", "--no-local", source, checkout)
	if err := exec.Command("git", "-C", checkout, "cat-file", "-e", commit+"^{commit}").Run(); err == nil {
		t.Fatal("depth-one fixture unexpectedly contains the historical source commit")
	}
	artifacts := []evidenceArtifact{{Path: artifactPath, SHA256: DigestSHA256(committed), GitBlob: gitBlob}}
	checkoutHead := strings.TrimSpace(runUS010TestGit(t, checkout, "rev-parse", "HEAD"))
	if err := verifyUS010GitSourceBindingAtCommit(checkout, checkoutHead, artifacts); err != nil {
		t.Fatalf("depth-one source binding failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(checkout, artifactPath), []byte("tampered implementation!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyUS010GitSourceBindingAtCommit(checkout, checkoutHead, artifacts); err != nil {
		t.Fatalf("working-tree mutation changed immutable historical validation: %v", err)
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
