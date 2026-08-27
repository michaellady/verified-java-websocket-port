package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestReadRustEvidenceFileRejectsHostileFilesystemObjects(t *testing.T) {
	directory := t.TempDir()
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(directory, "good.json")
	if err := os.WriteFile(good, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readRustEvidenceFile(good)
	if err != nil || string(data) != "{}\n" {
		t.Fatalf("good evidence data=%q err=%v", data, err)
	}

	symlink := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(good, symlink); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(directory, "hardlink.json")
	if err := os.Link(good, hardlink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(directory, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	oversize := filepath.Join(directory, "oversize.json")
	file, err := os.OpenFile(oversize, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate((8 << 20) + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	componentTarget := filepath.Join(directory, "component-target")
	if err := os.Mkdir(componentTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	componentFile := filepath.Join(componentTarget, "receipt.json")
	if err := os.WriteFile(componentFile, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	componentLink := filepath.Join(directory, "component-link")
	if err := os.Symlink(componentTarget, componentLink); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"relative":          "receipt.json",
		"symlink":           symlink,
		"hardlink":          hardlink,
		"fifo":              fifo,
		"directory":         directory,
		"device":            "/dev/null",
		"oversize":          oversize,
		"symlink-component": filepath.Join(componentLink, "receipt.json"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readRustEvidenceFile(path); err == nil {
				t.Fatalf("hostile evidence path accepted: %s", path)
			}
			var stdout, stderr bytes.Buffer
			code := run([]string{"verify-rust", "--repository-root", directory, "--evidence", path}, &stdout, &stderr)
			if code != 1 || !strings.Contains(stdout.String(), `"status":"BLOCKED_STATIC_READINESS"`) {
				t.Fatalf("hostile CLI evidence path code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}
