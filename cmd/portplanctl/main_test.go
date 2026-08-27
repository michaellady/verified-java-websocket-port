package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestUsageWithoutArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "portplanctl verify") {
		t.Fatalf("usage must name the verify subcommand, got %q", stderr.String())
	}
}

func TestUnknownSubcommandFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"promote"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestVerifyOnTheRepositoryRootSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", "--root", "../.."}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var report struct {
		OK                     bool `json:"ok"`
		DocumentsChecked       int  `json:"documents_checked"`
		MigrationRows          int  `json:"migration_rows"`
		TraceableSemanticItems int  `json:"traceable_semantic_items"`
		VerifiedRustIdentities int  `json:"verified_rust_identities"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("verify must emit a JSON report: %v", err)
	}
	if !report.OK || report.DocumentsChecked != 6 {
		t.Fatalf("report = %+v", report)
	}
	if report.MigrationRows != report.TraceableSemanticItems {
		t.Fatalf("every migration row must be traceable, got %d of %d",
			report.TraceableSemanticItems, report.MigrationRows)
	}
	if report.VerifiedRustIdentities != 3 {
		t.Fatalf("verified Rust identities = %d, want the three receipted US-009 identities", report.VerifiedRustIdentities)
	}
}

func TestDeriveRequiresItsInputs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"derive", "--root", "."}, &stdout, &stderr); code != 2 {
		t.Fatalf("derive without inputs must fail with exit 2, got %d", code)
	}
}
