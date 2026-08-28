package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunCaptureThenVerify(t *testing.T) {
	root := cliFixtureRoot(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"capture", "--root", root}, &stdout, &stderr); code != exitOK {
		t.Fatalf("capture exit %d, stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"verify", "--root", root}, &stdout, &stderr); code != exitOK {
		t.Fatalf("verify exit %d, stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"cutover_acceptance":"CUTOVER_BLOCKED"`)) {
		t.Fatalf("verify output = %s", stdout.String())
	}
}

func TestRunRejectsUsageAndMissingEvidence(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"unknown"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("unknown command exit = %d", code)
	}
	root := cliFixtureRoot(t)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"verify", "--root", root}, &stdout, &stderr); code != exitFailure {
		t.Fatalf("missing evidence exit = %d", code)
	}
}

func TestRunRejectsMissingRootAndExtraArguments(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"capture"},
		{"verify", "--root", t.TempDir(), "extra"},
		{"capture", "--unknown"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != exitUsage {
			t.Fatalf("arguments %q exit = %d, stderr=%s", arguments, code, stderr.String())
		}
	}
}

func cliFixtureRoot(t *testing.T) string {
	t.Helper()
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, relative := range []string{
		"evidence/intake/cutover-contract.json",
		"assurance/candidate-manifest.json",
		"evidence/refinement-replay.json",
		"evidence/performance.json",
		"java-oracle/pom.xml",
	} {
		content, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
