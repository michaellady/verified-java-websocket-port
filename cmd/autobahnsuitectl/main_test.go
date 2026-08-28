package main

import (
	"os"
	"path/filepath"
	"testing"
)

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("go.mod not found above the test directory")
	return ""
}

const (
	devTree           = "evidence/autobahn/dev-aarch64-nonauthoritative"
	devDigestManifest = "evidence/autobahn/digest-manifest.json"
)

// TestTheCommittedDigestManifestStillDescribesTheTree is the digest
// manifest's verification consumer.
//
// The manifest pins ~1,500 evidence files by sha256. Before this test it had
// a generator and no reader, so tampering with a pinned report — or deleting
// one — changed no gate outcome and the manifest was inert.
func TestTheCommittedDigestManifestStillDescribesTheTree(t *testing.T) {
	root := repoRoot(t)
	manifest := filepath.Join(root, devDigestManifest)
	if _, err := os.Stat(manifest); err != nil {
		t.Fatalf("load-bearing digest manifest is missing, so this gate would "+
			"otherwise pass while verifying nothing: %v", err)
	}
	status := run([]string{
		"verify-digest-manifest",
		"-root", root,
		"-tree", devTree,
		"-manifest", devDigestManifest,
	})
	if status != exitOK {
		t.Errorf("verify-digest-manifest exited %d, want %d: the committed digests no "+
			"longer describe the evidence tree", status, exitOK)
	}
}

// TestDigestManifestVerificationCatchesTamperAndDeletion proves the consumer
// above can actually fail. It works on a COPY so the committed evidence is
// never touched.
func TestDigestManifestVerificationCatchesTamperAndDeletion(t *testing.T) {
	root := repoRoot(t)

	// A small self-contained tree, pinned and then perturbed.
	stage := t.TempDir()
	treeDir := filepath.Join(stage, "tree")
	if err := os.MkdirAll(treeDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for name, body := range map[string]string{
		"a.json": `{"case":"1.1.1"}`,
		"b.json": `{"case":"1.1.2"}`,
	} {
		if err := os.WriteFile(filepath.Join(treeDir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if status := run([]string{
		"digest-manifest", "-root", stage, "-tree", "tree", "-out", "pinned.json",
	}); status != exitOK {
		t.Fatalf("digest-manifest exited %d", status)
	}
	verify := func() int {
		return run([]string{
			"verify-digest-manifest", "-root", stage, "-tree", "tree", "-manifest", "pinned.json",
		})
	}
	if status := verify(); status != exitOK {
		t.Fatalf("a freshly pinned tree must verify; exited %d", status)
	}

	// TAMPER: change one pinned byte.
	if err := os.WriteFile(filepath.Join(treeDir, "a.json"),
		[]byte(`{"case":"9.9.9"}`), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if status := verify(); status == exitOK {
		t.Error("a tampered pinned file verified clean")
	}

	// DELETE: remove a pinned file entirely.
	if err := os.WriteFile(filepath.Join(treeDir, "a.json"),
		[]byte(`{"case":"1.1.1"}`), 0o600); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if status := verify(); status != exitOK {
		t.Fatalf("restoring the byte should verify again; exited %d", status)
	}
	if err := os.Remove(filepath.Join(treeDir, "b.json")); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if status := verify(); status == exitOK {
		t.Error("a deleted pinned file verified clean")
	}

	// UNPINNED ADDITION: a file the manifest does not know about.
	if err := os.WriteFile(filepath.Join(treeDir, "b.json"),
		[]byte(`{"case":"1.1.2"}`), 0o600); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := os.WriteFile(filepath.Join(treeDir, "smuggled.json"),
		[]byte(`{"case":"smuggled"}`), 0o600); err != nil {
		t.Fatalf("add: %v", err)
	}
	if status := verify(); status == exitOK {
		t.Error("an unpinned extra file verified clean")
	}

	_ = root
}

// TestReconcileRefusesAnUnarmedAntiStaleGate proves the anti-stale binding is
// no longer optional at the command boundary: reconciling without naming the
// agent, or without the per-case reports, is a usage error rather than a
// silently weaker check.
func TestReconcileRefusesAnUnarmedAntiStaleGate(t *testing.T) {
	root := repoRoot(t)
	index := filepath.Join(root, devTree, "fuzzingserver-run1", "index.json")
	cases := filepath.Join(root, devTree, "fuzzingserver-run1", "cases")
	manifest := filepath.Join(root, "autobahn", "case-manifest.json")

	if status := run([]string{
		"reconcile", "-manifest", manifest, "-index", index, "-cases", cases,
	}); status != exitUsage {
		t.Errorf("reconcile without -require-agent exited %d, want usage %d",
			status, exitUsage)
	}
	if status := run([]string{
		"reconcile", "-manifest", manifest, "-index", index,
		"-require-agent", "verified-rust-ws-testee-us019",
	}); status != exitUsage {
		t.Errorf("reconcile without -cases exited %d, want usage %d", status, exitUsage)
	}
}
