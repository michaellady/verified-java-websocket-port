package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
