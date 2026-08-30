package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func TestRunRejectsUnknownDuplicateAndRelativeArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"verify", "--repository-root", ".", "--evidence", "/tmp/evidence.json"},
		{"verify", "--repository-root", "/tmp/repo", "--repository-root", "/tmp/repo"},
	} {
		if code := run(args, &bytes.Buffer{}, &bytes.Buffer{}); code != 64 {
			t.Fatalf("args=%v code=%d", args, code)
		}
	}
}

func TestVerifyUsesExactEvidencePathAndReturnsRealFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "evidence/refinement-replay.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := verify
	t.Cleanup(func() { verify = original })
	verify = func(gotRoot string, raw []byte) error {
		if gotRoot != root || string(raw) != "{}" {
			t.Fatal("verify received the wrong bounded input")
		}
		return errors.New("blocked")
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", "--repository-root", root, "--evidence", path}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestWriteAtomicAnchorsRepositoryAndEvidenceDirectories(t *testing.T) {
	root := privateTempDir(t)
	evidenceDirectory := filepath.Join(root, "evidence")
	if err := os.Mkdir(evidenceDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "evidence/refinement-replay.json")
	if err := writeAtomic(root, path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(root, path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "second" {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
}

func TestWriteAtomicRejectsSymlinkedRepositoryOrEvidenceParent(t *testing.T) {
	container := privateTempDir(t)
	realRoot := filepath.Join(container, "real")
	if err := os.MkdirAll(filepath.Join(realRoot, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(container, "linked")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(linkedRoot, filepath.Join(linkedRoot, "evidence/refinement-replay.json"), []byte("forbidden")); err == nil {
		t.Fatal("accepted symlinked repository root")
	}

	outside := filepath.Join(container, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(realRoot, "evidence")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(realRoot, "evidence")); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(realRoot, filepath.Join(realRoot, "evidence/refinement-replay.json"), []byte("forbidden")); err == nil {
		t.Fatal("accepted symlinked evidence directory")
	}
	if _, err := os.Stat(filepath.Join(outside, "refinement-replay.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside destination changed: %v", err)
	}
}
