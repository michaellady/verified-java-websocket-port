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

func TestDiagnoseIsBoundedNoWriteTransport(t *testing.T) {
	original := diagnoseDifferential
	defer func() { diagnoseDifferential = original }()
	called := false
	diagnoseDifferential = func(_ context.Context, cfg differential.Config) (differential.DiagnosticReport, error) {
		called = true
		if cfg.RepositoryRoot != "/repo" || cfg.ScenarioTimeout <= 0 {
			return differential.DiagnosticReport{}, errors.New("bad config")
		}
		return differential.DiagnosticReport{
			Status:           "DIAGNOSTIC_ONLY_NO_WRITES",
			ScenarioCount:    74,
			ProcessReceipts:  296,
			AcceptedQuirks:   1,
			BlockingFindings: 3,
			AcceptedFindings: []differential.DiagnosticFinding{{
				ScenarioID:     "us005.pub.0005",
				Pointer:        "/final_state",
				Classification: "java_quirk",
				JavaValue:      `"open"`,
				RustValue:      `"closed"`,
				Detail:         "field-addressed accepted quirk",
			}},
		}, nil
	}
	args := []string{"diagnose", "--repository-root", "/repo", "--public-corpus", "/repo/corpus", "--java-executable", "/java", "--java-adapter", "/adapter", "--java-runtime", "/runtime", "--java-support", "/support", "--rust-testee", "/rust", "--migration-inventory", "/repo/migration", "--compatibility-surface", "/repo/compat", "--ledger", "/repo/ledger", "--oracle-hierarchy", "/repo/hierarchy", "--evidence", "/repo/evidence"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !called || !bytes.Contains(stdout.Bytes(), []byte(`"status":"DIAGNOSTIC_ONLY_NO_WRITES"`)) {
		t.Fatalf("called=%v stdout=%s", called, stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"accepted_findings":[{"scenario_id":"us005.pub.0005"`)) {
		t.Fatalf("accepted findings were not transported: %s", stdout.String())
	}
}

func TestParityIsJavaCompatibilityNoWriteTransport(t *testing.T) {
	original := parityDifferential
	defer func() { parityDifferential = original }()
	called := false
	parityDifferential = func(_ context.Context, cfg differential.Config) (differential.DiagnosticReport, error) {
		called = true
		if cfg.RepositoryRoot != "/repo" || cfg.ScenarioTimeout <= 0 {
			return differential.DiagnosticReport{}, errors.New("bad config")
		}
		return differential.DiagnosticReport{
			Status:          "JAVA_PARITY_DIAGNOSTIC_ONLY_NO_WRITES",
			ScenarioCount:   74,
			ProcessReceipts: 296,
			ExactAgreements: 74,
		}, nil
	}
	args := []string{"parity", "--repository-root", "/repo", "--public-corpus", "/repo/corpus", "--java-executable", "/java", "--java-adapter", "/adapter", "--java-runtime", "/runtime", "--java-support", "/support", "--rust-testee", "/rust", "--migration-inventory", "/repo/migration", "--compatibility-surface", "/repo/compat", "--ledger", "/repo/ledger", "--oracle-hierarchy", "/repo/hierarchy", "--evidence", "/repo/evidence"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !called || !bytes.Contains(stdout.Bytes(), []byte(`"exact_agreements":74`)) {
		t.Fatalf("called=%v stdout=%s", called, stdout.String())
	}
}

func TestVerifyParityReadsPortableSummaryAndCurrentRuntimeConfig(t *testing.T) {
	original := verifyParityDiagnostic
	defer func() { verifyParityDiagnostic = original }()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	summary := filepath.Join(root, "parity.json")
	if err := os.WriteFile(summary, []byte("{\"status\":\"portable\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	verifyParityDiagnostic = func(cfg differential.Config, raw []byte) error {
		called = true
		if cfg.RepositoryRoot != root || cfg.JavaRuntimeJar != filepath.Join(root, "runtime") || string(raw) != "{\"status\":\"portable\"}\n" {
			return errors.New("wrong parity verification input")
		}
		return nil
	}
	args := []string{"verify-parity", "--repository-root", root, "--public-corpus", filepath.Join(root, "corpus"), "--java-executable", filepath.Join(root, "java"), "--java-adapter", filepath.Join(root, "adapter"), "--java-runtime", filepath.Join(root, "runtime"), "--java-support", filepath.Join(root, "support"), "--rust-testee", filepath.Join(root, "rust"), "--migration-inventory", filepath.Join(root, "migration"), "--compatibility-surface", filepath.Join(root, "compat"), "--ledger", filepath.Join(root, "ledger"), "--oracle-hierarchy", filepath.Join(root, "hierarchy"), "--evidence", filepath.Join(root, "evidence"), "--parity-summary", summary}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !called || stdout.String() != "PASS\n" {
		t.Fatalf("called=%v stdout=%q", called, stdout.String())
	}
}

func TestReadParitySummaryRejectsRelativeAndSymlinkPaths(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "parity.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readParitySummary("parity.json"); err == nil {
		t.Fatal("relative parity summary path accepted")
	}
	link := filepath.Join(root, "parity-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readParitySummary(link); err == nil {
		t.Fatal("symlink parity summary path accepted")
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

func TestReproduceIsBoundedTransportForOnePublicWitness(t *testing.T) {
	original := reproduceDifferential
	defer func() { reproduceDifferential = original }()
	root := t.TempDir()
	evidence := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(evidence, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	reproduceDifferential = func(_ context.Context, gotRoot string, raw []byte, id string) (differential.ReproductionReceipt, error) {
		called = true
		if gotRoot != root || string(raw) != "{}\n" || id != "reproducer.us005.pub.0005.0123456789abcdef" {
			return differential.ReproductionReceipt{}, errors.New("wrong reproduction binding")
		}
		return differential.ReproductionReceipt{Status: "PASS_FRESH_DIFFERENCE_REPRODUCED", ReproducerID: id, FreshProcesses: 4, CurrentlyReproduced: true}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"reproduce", "--repository-root", root, "--evidence", evidence, "--reproducer-id", "reproducer.us005.pub.0005.0123456789abcdef"}, &stdout, &stderr)
	if code != 0 || !called || !bytes.Contains(stdout.Bytes(), []byte(`"fresh_processes":4`)) {
		t.Fatalf("code=%d called=%v stdout=%s stderr=%s", code, called, stdout.String(), stderr.String())
	}
}
