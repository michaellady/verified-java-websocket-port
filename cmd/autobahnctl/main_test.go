package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsAnythingOutsideFixedOperation(t *testing.T) {
	for _, arguments := range [][]string{nil, {"shell"}, {"run", "--accepted-root", "x"}} {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != 2 {
			t.Fatalf("arguments %q returned %d", arguments, code)
		}
	}
}

func TestRustRoutesHaveClosedFlagsAndTypedBlockedOutput(t *testing.T) {
	for _, arguments := range [][]string{
		{"prepare-rust"},
		{"prepare-rust", "--docker", "x"},
		{"verify-rust"},
		{"verify-rust", "--repository-root", "/tmp"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != 2 {
			t.Fatalf("arguments %q returned %d stdout=%s stderr=%s", arguments, code, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify-rust", "--repository-root", "/private/tmp", "--evidence", "/private/tmp/does-not-exist-us019"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), `"status":"BLOCKED_STATIC_READINESS"`) {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestWriteExclusiveSyncedCreatesReadOnlyAndNeverOverwrites(t *testing.T) {
	directory := t.TempDir()
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "receipt.json")
	if err := writeExclusiveSynced(path, []byte("fixed\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	if err := writeExclusiveSynced(path, []byte("changed\n")); err == nil {
		t.Fatal("existing receipt overwritten")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "fixed\n" {
		t.Fatalf("data=%q err=%v", data, err)
	}
}
