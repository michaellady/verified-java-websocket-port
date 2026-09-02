package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

// TestVerifyExitsZeroOnTheRetainedArtifacts is the baseline reading. It also
// pins the exit CODE, not merely the absence of an error, because the freeze
// gate's whole purpose is to be distinguishable by exit code.
func TestVerifyExitsZeroOnTheRetainedArtifacts(t *testing.T) {
	var out bytes.Buffer
	code, err := run([]string{"verify", "-repo", moduleRoot(t)}, &out)
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out.String())
	}
	if code != 0 {
		t.Fatalf("verify exited %d", code)
	}
	if !strings.Contains(out.String(), "correction_proposal_findings=0") {
		t.Fatalf("verify did not report the correction findings:\n%s", out.String())
	}
}

// TestTheFreezeGateExitsTwoWhileAnythingBlocks. Exit 2 is reserved for a
// well-formed report whose verdict is BLOCKED; exit 1 means the tool failed.
// Collapsing them would let a broken tool read as a blocked freeze.
func TestTheFreezeGateExitsTwoWhileAnythingBlocks(t *testing.T) {
	var out bytes.Buffer
	code, err := run([]string{"freeze-gate", "-repo", moduleRoot(t)}, &out)
	if code != exitBlocked {
		t.Fatalf("freeze-gate exited %d, want %d; err=%v\n%s", code, exitBlocked, err, out.String())
	}
	if err == nil {
		t.Fatal("freeze-gate exited BLOCKED without saying why")
	}
	if !strings.Contains(out.String(), "freeze_verdict=BLOCKED") {
		t.Fatalf("freeze-gate did not print its verdict:\n%s", out.String())
	}
}

// TestEveryAxisIsPrintedOnOneScreen: a non-zero attribution number must never
// be printable without the zero coverage numbers beside it. This is the
// discipline javabindctl already uses.
func TestEveryAxisIsPrintedOnOneScreen(t *testing.T) {
	var out bytes.Buffer
	if _, err := run([]string{"verify", "-repo", moduleRoot(t)}, &out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"java_coverage=", "rust_coverage=", "paired_comparable_coverage=",
		"production_linkage_java=", "production_linkage_rust=", "refinement_coverage=",
		"bound_parity=", "counterexample_sensitivity_java=", "counterexample_sensitivity_rust=",
		"aggregate=", "blocking_obligations=", "resolver_ceiling ", "NOT_COVERAGE",
		"obligations_with_no_target=", "targets_with_no_obligation=",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("the one-screen report omits %q:\n%s", want, text)
		}
	}
}

// TestVerifyFailsWhenARetainedArtifactIsEdited is the RED reading for the byte
// comparison: an artifact edited by hand must not verify.
func TestVerifyFailsWhenARetainedArtifactIsEdited(t *testing.T) {
	root := moduleRoot(t)
	for _, relative := range []string{
		"assurance/formal/denominator-reconciliation.json",
		"evidence/formal/us023-coverage-report.json",
		"evidence/formal/us023-coverage-report.md",
	} {
		t.Run(relative, func(t *testing.T) {
			sandboxRoot := t.TempDir()
			mirrorRepo(t, root, sandboxRoot)
			path := filepath.Join(sandboxRoot, filepath.FromSlash(relative))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", relative, err)
			}
			if err := os.WriteFile(path, append(data, []byte("\ntrailing\n")...), 0o644); err != nil {
				t.Fatalf("write %s: %v", relative, err)
			}
			var out bytes.Buffer
			code, err := run([]string{"verify", "-repo", sandboxRoot}, &out)
			if err == nil || code != exitFailure {
				t.Fatalf("verify accepted an edited %s (exit %d)", relative, code)
			}
		})
	}
}

// TestAnUnknownSubcommandExitsOne keeps the two failure modes apart.
func TestAnUnknownSubcommandExitsOne(t *testing.T) {
	var out bytes.Buffer
	code, err := run([]string{"nonsense", "-repo", "."}, &out)
	if code != exitFailure || err == nil {
		t.Fatalf("unknown subcommand exited %d with err %v", code, err)
	}
}

// mirrorRepo copies every input the derivation reads plus the artifacts it
// writes, so a test can edit one without touching the repository.
func mirrorRepo(t *testing.T, src, dst string) {
	t.Helper()
	files := []string{
		"assurance/formal/obligation-catalog.json",
		"assurance/formal/proof-targets.json",
		"assurance/formal/java-binding-spec.json",
		"assurance/formal/catalog-correction-proposal.json",
		"assurance/formal/denominator-reconciliation.json",
		"assurance/developer-tools/port-seam-dossier.json",
		"evidence/java/formal-bindings/coverage-projection.json",
		"evidence/java/formal-bindings/receipt.json",
		"evidence/linkage/rust-identity-verification.json",
		"evidence/intake/compatibility-surface.json",
		"evidence/intake/semantic-id-migration-map.json",
		"evidence/formal/us023-coverage-report.json",
		"evidence/formal/us023-coverage-report.md",
	}
	for _, relative := range files {
		data, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		target := filepath.Join(dst, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", relative, err)
		}
	}
	crates, err := os.ReadDir(filepath.Join(src, "rust"))
	if err != nil {
		t.Fatalf("read rust/: %v", err)
	}
	for _, entry := range crates {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(src, "rust", entry.Name(), "Cargo.toml")); err != nil {
			continue
		}
		dir := filepath.Join(dst, "rust", entry.Name())
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("# mirrored\n"), 0o644); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
	}
}
