package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestRunRequiresExactVerifyCommand(t *testing.T) {
	original := verify
	t.Cleanup(func() { verify = original })
	verify = func(root string) error {
		if root != "/tmp/repository" {
			t.Fatalf("root=%q", root)
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", "--repository-root", "/tmp/repository"}, &stdout, &stderr); code != 0 || stdout.String() != "PASS\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunFailsClosed(t *testing.T) {
	original := verify
	t.Cleanup(func() { verify = original })
	verify = func(string) error { return errors.New("drift") }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", "--repository-root", "/tmp/repository"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.String() != "campaign verify failed: drift\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunRejectsMalformedArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", "--repository-root", "relative"}, &stdout, &stderr); code != 64 || stdout.Len() != 0 || stderr.String() != usage {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunPrintsCorpusIdentity(t *testing.T) {
	original := corpusIdentity
	t.Cleanup(func() { corpusIdentity = original })
	corpusIdentity = func(root string, roots []string) (string, uint64, error) {
		if root != "/tmp/repository" || len(roots) != 2 || roots[0] != "a" || roots[1] != "b" {
			t.Fatalf("root=%q roots=%v", root, roots)
		}
		return "sha256:abc", 3, nil
	}
	var stdout, stderr bytes.Buffer
	arguments := []string{"corpus", "--repository-root", "/tmp/repository", "--seed-roots", "a,b"}
	if code := run(arguments, &stdout, &stderr); code != 0 || stdout.String() != "sha256:abc 3\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
