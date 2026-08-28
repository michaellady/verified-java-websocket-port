package formalplan

// Polarity coverage for the US-017 results-binding gate (pre-landing review
// round 2, results.json finding). A green run with correct digests proves
// nothing on its own: the finding is that a STALE binding was undetectable,
// so each way of going stale is produced here and the refusal is read.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const crTestRoot = "../.."

// crTestIsolate copies every file the results binding reads into a temp tree,
// so a deliberate staleness never touches the repository.
func crTestIsolate(t *testing.T) string {
	t.Helper()
	isolated := t.TempDir()
	copyIn := func(relative string) {
		content, err := os.ReadFile(filepath.Join(crTestRoot, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		target := filepath.Join(isolated, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", relative, err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatalf("write %s: %v", relative, err)
		}
	}
	copyIn(ConcurrencyResultsDocumentPath)
	copyIn("assurance/concurrency/plan.json")
	copyIn("rust/ws-driver/src/lib.rs")
	copyIn("rust/ws-driver/tests/schedule_exploration.rs")
	seeds, err := os.ReadDir(filepath.Join(crTestRoot, filepath.FromSlash(minimizedSeedDir)))
	if err != nil {
		t.Fatalf("read minimized seeds: %v", err)
	}
	for _, entry := range seeds {
		copyIn(minimizedSeedDir + "/" + entry.Name())
	}
	for _, seed := range []string{
		"rust/ws-driver/fuzz-seeds/us017/regressions/eof-backpressure-livelock.seed",
		"rust/ws-driver/fuzz-seeds/us017/regressions/fatal-halt-suppressed-write-drop.seed",
	} {
		copyIn(seed)
	}
	if findings := ValidateConcurrencyResults(isolated); len(findings) != 0 {
		t.Fatalf("the isolated copy must validate clean before any mutation, got %v", findings)
	}
	return isolated
}

func crTestOverwrite(t *testing.T, root, relative, before, after string) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(relative))
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	if !strings.Contains(string(content), before) {
		t.Fatalf("%s no longer contains %q; the polarity probe is stale", relative, before)
	}
	mutated := strings.Replace(string(content), before, after, 1)
	if err := os.WriteFile(target, []byte(mutated), 0o644); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

func crTestRequireFinding(t *testing.T, root, code, needle string) {
	t.Helper()
	findings := ValidateConcurrencyResults(root)
	for _, finding := range findings {
		if finding.Code == code && strings.Contains(finding.Detail, needle) {
			if finding.Severity != SeverityBlocking {
				t.Fatalf("%s must be blocking, got %q", code, finding.Severity)
			}
			return
		}
	}
	t.Fatalf("expected a blocking %s mentioning %q, got %v", code, needle, findings)
}

// TestCommittedConcurrencyResultsBindTheCommittedTree is the gate: the PASS
// artifact's recorded blobs and digests must describe the tree it ships with.
func TestCommittedConcurrencyResultsBindTheCommittedTree(t *testing.T) {
	if findings := ValidateConcurrencyResults(crTestRoot); len(findings) != 0 {
		t.Fatalf("the committed results artifact does not describe the committed tree: %v", findings)
	}
}

// TestGitBlobIDMatchesGitsOwnObjectIds pins the hash construction itself
// against object ids git produces, so the comparison cannot be vacuous
// because the id was computed a different way than the artifact records it.
func TestGitBlobIDMatchesGitsOwnObjectIds(t *testing.T) {
	for _, vector := range []struct {
		content string
		blob    string
	}{
		// `printf '' | git hash-object --stdin`
		{"", "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"},
		// `printf 'hello\n' | git hash-object --stdin`
		{"hello\n", "ce013625030ba8dba906f756967f9e9ca394464a"},
		// `printf 'what is up, doc?' | git hash-object --stdin`
		{"what is up, doc?", "bd9dbf5aae1a3862dd1526723246b20206e5fc37"},
	} {
		if got := GitBlobID([]byte(vector.content)); got != vector.blob {
			t.Fatalf("GitBlobID(%q) = %s, want git's %s", vector.content, got, vector.blob)
		}
	}
}

// TestAStaleResultsTargetBindingIsRefused is the deletion-equivalent polarity
// for a digest: an artifact whose target names a tree OTHER than the one it
// claims to describe must fail, whichever side went stale. Both directions
// are exercised — the recorded id edited, and the named file edited — because
// the real defect arrived the second way: the driver source was rewritten by
// a fix round and the artifact kept the previous revision's blob id.
func TestAStaleResultsTargetBindingIsRefused(t *testing.T) {
	t.Run("recorded source blob names another revision", func(t *testing.T) {
		isolated := crTestIsolate(t)
		crTestOverwrite(t, isolated, ConcurrencyResultsDocumentPath,
			`"git_blob": "`, `"git_blob": "2dab10459db8a34b44a9d031b3670010f9667fdb`)
		crTestRequireFinding(t, isolated, "RESULTS_TARGET_BLOB_STALE", "target.source")
	})

	t.Run("named driver source changed under the recorded blob", func(t *testing.T) {
		isolated := crTestIsolate(t)
		crTestOverwrite(t, isolated, "rust/ws-driver/src/lib.rs",
			"#![forbid(unsafe_code)]", "#![forbid(unsafe_code)] // a later fix round")
		crTestRequireFinding(t, isolated, "RESULTS_TARGET_BLOB_STALE", "target.source")
	})

	t.Run("named exploration harness changed under the recorded blob", func(t *testing.T) {
		isolated := crTestIsolate(t)
		target := filepath.Join(isolated, filepath.FromSlash("rust/ws-driver/tests/schedule_exploration.rs"))
		content, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read harness: %v", err)
		}
		if err := os.WriteFile(target, append(content, []byte("\n// harness edited\n")...), 0o644); err != nil {
			t.Fatalf("write harness: %v", err)
		}
		crTestRequireFinding(t, isolated, "RESULTS_TARGET_BLOB_STALE", "target.harness")
	})

	t.Run("preregistered plan digest goes stale", func(t *testing.T) {
		isolated := crTestIsolate(t)
		crTestOverwrite(t, isolated, "assurance/concurrency/plan.json",
			`"schema_version"`, `"schema_version_edited"`)
		crTestRequireFinding(t, isolated, "RESULTS_ARTIFACT_DIGEST_STALE", "preregistered_plan")
	})

	t.Run("a pinned minimized artifact is edited", func(t *testing.T) {
		isolated := crTestIsolate(t)
		target := filepath.Join(isolated, filepath.FromSlash(minimizedSeedDir+"/silent-write-drop.seed"))
		content, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read seed: %v", err)
		}
		if err := os.WriteFile(target, append(content, '\n'), 0o644); err != nil {
			t.Fatalf("write seed: %v", err)
		}
		crTestRequireFinding(t, isolated, "RESULTS_ARTIFACT_DIGEST_STALE", "silent-write-drop")
	})

	t.Run("a named file is gone entirely", func(t *testing.T) {
		isolated := crTestIsolate(t)
		if err := os.Remove(filepath.Join(isolated,
			filepath.FromSlash("rust/ws-driver/tests/schedule_exploration.rs"))); err != nil {
			t.Fatalf("remove harness: %v", err)
		}
		crTestRequireFinding(t, isolated, "RESULTS_TARGET_PATH_MISSING", "target.harness")
	})
}
