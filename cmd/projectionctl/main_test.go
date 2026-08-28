package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fixtureRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	repository := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		"contracts/laboratory-template.json", "assurance/candidate-manifest.json",
		"assurance/candidate-claims.json", "assurance/formal/obligation-catalog.json",
		"assurance/reviews/human.json", "assurance/reviews/codex.json",
		"assurance/reviews/reality.json", "evidence/cutover.json",
		"security/release-firewall.json",
		"schemas/us027-receipt-1.0.0.schema.json",
		"schemas/us027-independent-replay-1.0.0.schema.json",
		"schemas/us027-public-snapshot-1.0.0.schema.json",
	}
	for _, name := range paths {
		raw, err := os.ReadFile(filepath.Join(repository, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRunCaptureVerifyAndUsage(t *testing.T) {
	root := fixtureRoot(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"capture", "--root", root}, &stdout, &stderr); code != 0 {
		t.Fatalf("capture exit %d: %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"verify", "--root", root}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify exit %d: %s", code, stderr.String())
	}
	if code := run([]string{"unknown"}, &stdout, &stderr); code != 2 {
		t.Fatalf("usage exit = %d", code)
	}
}
