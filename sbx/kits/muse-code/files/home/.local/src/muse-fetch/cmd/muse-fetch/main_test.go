package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunRequiresAllExplicitInputs(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	if code := run(nil, &stderr); code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--url, --sha256, --size, and --destination are required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunRejectsPositionalArguments(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	code := run([]string{
		"--url", "https://example.invalid/muse",
		"--sha256", strings.Repeat("0", 64),
		"--size", "1",
		"--destination", "/tmp/muse",
		"extra",
	}, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "positional arguments are not accepted") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
