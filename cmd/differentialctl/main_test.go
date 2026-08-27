package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/differential"
)

func TestUnknownCommandIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"unknown"}, &stdout, &stderr); code != 64 {
		t.Fatalf("exit = %d, want 64", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("usage error wrote stdout: %q", stdout.String())
	}
}

func TestRepeatedAndTrailingArgumentsAreUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"run", "--repository-root", "/tmp/a", "--repository-root", "/tmp/b"}, {"verify", "--repository-root", "/tmp/a", "trailing"}, {"run", "--repository-root", "relative"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 64 {
			t.Fatalf("args=%v exit=%d stderr=%s", args, code, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("usage wrote stdout for %v", args)
		}
	}
}

func TestRunIsOnlyTransportForFacade(t *testing.T) {
	original := runDifferential
	defer func() { runDifferential = original }()
	called := false
	runDifferential = func(_ context.Context, cfg differential.Config) (differential.Receipt, error) {
		called = true
		if cfg.RepositoryRoot != "/repo" || cfg.ScenarioTimeout <= 0 || cfg.MinimizationBudget.MaxCandidates != 128 {
			return differential.Receipt{}, errors.New("bad config")
		}
		return differential.Receipt{Status: "PASS", ScenarioCount: 74, ProcessReceipts: 296}, nil
	}
	args := []string{"run", "--repository-root", "/repo", "--public-corpus", "/repo/corpus", "--java-executable", "/java", "--java-adapter", "/adapter", "--java-runtime", "/runtime", "--java-support", "/support", "--rust-testee", "/rust", "--migration-inventory", "/repo/migration", "--compatibility-surface", "/repo/compat", "--ledger", "/repo/ledger", "--oracle-hierarchy", "/repo/hierarchy", "--evidence", "/repo/evidence"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !called || !bytes.Contains(stdout.Bytes(), []byte(`"process_receipts":296`)) {
		t.Fatalf("called=%v stdout=%s", called, stdout.String())
	}
}

func TestVerifyReadsOneBoundedEvidenceFile(t *testing.T) {
	original := verifyDifferential
	defer func() { verifyDifferential = original }()
	root := t.TempDir()
	path := filepath.Join(root, "evidence.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	verifyDifferential = func(gotRoot string, raw []byte) error {
		called = true
		if gotRoot != root || string(raw) != "{}\n" {
			return errors.New("wrong input")
		}
		return nil
	}
	args := []string{"verify", "--repository-root", root, "--evidence", path, "--ledger", filepath.Join(root, "evidence/java/behavior-delta-ledger.json"), "--oracle-hierarchy", filepath.Join(root, "evidence/oracle-hierarchy.json")}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !called {
		t.Fatal("verifier not called")
	}
}
