package main

import (
	"bytes"
	"strings"
	"testing"
)

const repoRoot = "../.."

func TestVerifyOnRealTreeExitsHostBindingPending(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", "--root", repoRoot}, &stdout, &stderr)
	if code != exitHostBindingPending {
		t.Fatalf("exit code %d, want %d (HOST_BINDING_PENDING)\nstdout: %s\nstderr: %s", code, exitHostBindingPending, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, required := range []string{
		"single remaining blocker class: HOST_BINDING_PENDING",
		"US-008 preregistration freeze: VALID (OWNER_ATTESTED_NOT_INDEPENDENT)",
		"Measurement preflight: BLOCKED",
		"schema ok   benchmarks/plan/workloads.json",
		"schema ok   benchmarks/environments/primary-macos.json",
		"schema ok   benchmarks/environments/confirmation.json",
		"plan-spec ok",
		"power-model ok",
		"binding completion meter: 26 field(s) unbound",
		"host_identity.instance_id",
		"host_identity.observed_architecture",
		"host_identity.allocation_evidence",
		"tool_identities.analyzer",
		"preregistration freeze: plan OWNER_ATTESTED_NOT_INDEPENDENT",
		"meter ok",
	} {
		if !strings.Contains(output, required) {
			t.Errorf("verify output missing %q\noutput: %s", required, output)
		}
	}
	// The owner's Tier-1 decision of 2026-08-26 bound these four
	// confirmation identities; they must no longer report as unbound
	// (the only place these paths appear in verify output).
	for _, bound := range []string{
		"host_identity.instance_type",
		"host_identity.region",
		"host_identity.ami_id",
		"host_identity.ami_name",
	} {
		if strings.Contains(output, bound) {
			t.Errorf("verify output still lists owner-bound field %q as unbound\noutput: %s", bound, output)
		}
	}
	if strings.Contains(output, "RESULT: all benchmark documents consistent and every binding field bound") {
		t.Error("verify must not claim full binding while the host binding is owner-gated")
	}
}

func TestOrderPrintsDeterministicOrder(t *testing.T) {
	var first, second, stderr bytes.Buffer
	if code := run([]string{"order", "--workload", "wl-01-handshake-close"}, &first, &stderr); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if code := run([]string{"order", "--workload", "wl-01-handshake-close"}, &second, &stderr); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if first.String() != second.String() {
		t.Fatal("order output must be deterministic")
	}
	if count := strings.Count(first.String(), "pair "); count != 35 {
		t.Fatalf("expected 35 pair lines, got %d", count)
	}
	if !strings.Contains(first.String(), "warmup") || !strings.Contains(first.String(), "measured") {
		t.Fatal("order output must label warmup and measured pairs")
	}
}

func TestOrderAllWorkloads(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"order"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if count := strings.Count(stdout.String(), "pair "); count != 6*35 {
		t.Fatalf("expected %d pair lines, got %d", 6*35, count)
	}
}

func TestUsageErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != exitUsage {
		t.Errorf("no arguments: exit %d, want %d", code, exitUsage)
	}
	if code := run([]string{"analyze"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("unknown subcommand: exit %d, want %d (no analyze mode exists before binding)", code, exitUsage)
	}
	if code := run([]string{"verify"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("verify without --root: exit %d, want %d", code, exitUsage)
	}
	if code := run([]string{"order", "--workload", "wl-99-not-preregistered"}, &stdout, &stderr); code != exitFailures {
		t.Errorf("unknown workload: exit %d, want %d", code, exitFailures)
	}
}
