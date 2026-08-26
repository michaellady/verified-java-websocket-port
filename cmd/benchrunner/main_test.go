package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsageAndValidationExitCodes(t *testing.T) {
	cases := []struct {
		name      string
		arguments []string
		exitCode  int
		fragment  string
	}{
		{"no arguments", nil, exitUsage, "all required"},
		{"help", []string{"--help"}, exitUsage, "usage"},
		{"unknown argument", []string{"--fast"}, exitUsage, "unknown argument"},
		{"missing out", []string{"--mode", "pipeline-smoke", "--pr", "7", "--workspace", "bench-pr-7"}, exitUsage, "all required"},
		{"non-decimal pr", []string{"--mode", "pipeline-smoke", "--pr", "7a", "--workspace", "bench-pr-7a", "--out", "x"}, exitUsage, "decimal PR number"},
		{"workspace mismatch", []string{"--mode", "pipeline-smoke", "--pr", "7", "--workspace", "bench-pr-8", "--out", "x"}, exitUsage, "must equal bench-pr-7"},
	}
	for _, testCase := range cases {
		var stdout, stderr bytes.Buffer
		code := run(testCase.arguments, &stdout, &stderr)
		if code != testCase.exitCode {
			t.Errorf("%s: exit %d, want %d (stderr: %s)", testCase.name, code, testCase.exitCode, stderr.String())
			continue
		}
		if !strings.Contains(strings.ToLower(stderr.String()), strings.ToLower(testCase.fragment)) {
			t.Errorf("%s: stderr missing %q: %s", testCase.name, testCase.fragment, stderr.String())
		}
	}
}

func TestMeasurementImplyingModesAreRefused(t *testing.T) {
	for _, mode := range []string{"measure", "benchmark", "real", "pipeline-smoke2"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"--mode", mode, "--pr", "7", "--workspace", "bench-pr-7", "--out", t.TempDir()}, &stdout, &stderr)
		if code != exitRefused {
			t.Errorf("mode %q: exit %d, want %d (refused)", mode, code, exitRefused)
		}
		if !strings.Contains(stderr.String(), "refused") {
			t.Errorf("mode %q: stderr must state the refusal: %s", mode, stderr.String())
		}
	}
}

func TestPipelineSmokeEmitsSentinelOnlySkeleton(t *testing.T) {
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{"--mode", "pipeline-smoke", "--pr", "42", "--workspace", "bench-pr-42", "--out", out}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "self-check ok") {
		t.Fatalf("stdout must confirm the self-check: %s", stdout.String())
	}
	content, err := os.ReadFile(filepath.Join(out, "pipeline-smoke-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result smokeResult
	if err := json.Unmarshal(content, &result); err != nil {
		t.Fatal(err)
	}
	digestSidecar, err := os.ReadFile(filepath.Join(out, "pipeline-smoke-result.json.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(content))
	if strings.TrimSpace(string(digestSidecar)) != wantDigest {
		t.Fatalf("digest sidecar %q, want %q", strings.TrimSpace(string(digestSidecar)), wantDigest)
	}
	if result.Schema != "vjwp-bench-pipeline-smoke/1" || result.Mode != "pipeline-smoke" {
		t.Fatalf("schema/mode %q/%q unexpected", result.Schema, result.Mode)
	}
	if result.PRNumber != "42" || result.Workspace != "bench-pr-42" {
		t.Fatalf("pr/workspace %q/%q unexpected", result.PRNumber, result.Workspace)
	}
	if !strings.Contains(result.Honesty, "not a benchmark") {
		t.Fatal("honesty statement missing")
	}
	if len(result.Workloads) != 6 {
		t.Fatalf("expected 6 workload skeletons, got %d", len(result.Workloads))
	}
	for _, workload := range result.Workloads {
		for name, value := range map[string]string{
			"samples": workload.Samples, "peak_rss": workload.PeakRSS, "steady_rss": workload.SteadyRSS,
			"cpu_time": workload.CPUTime, "startup_to_ready": workload.StartupToReady,
			"latency_p50": workload.LatencyP50, "latency_p95": workload.LatencyP95, "latency_p99": workload.LatencyP99,
			"allocated_bytes": workload.AllocatedBytes, "allocation_count": workload.AllocationCount,
			"throughput": workload.Throughput,
		} {
			if value != NotMeasured {
				t.Errorf("%s.%s = %q, must be the NOT_MEASURED sentinel", workload.Workload, name, value)
			}
		}
	}
}

func TestSelfCheckRejectsFabricatedNumber(t *testing.T) {
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--mode", "pipeline-smoke", "--pr", "7", "--workspace", "bench-pr-7", "--out", out}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	path := filepath.Join(out, "pipeline-smoke-result.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(content, []byte(`"cpu_time": "NOT_MEASURED"`), []byte(`"cpu_time": 0.93`), 1)
	if bytes.Equal(tampered, content) {
		t.Fatal("tamper did not apply")
	}
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := selfCheck(path); err == nil {
		t.Fatal("self-check must reject a fabricated metric number")
	}
}

func TestProbeOSReleaseParsesPrettyName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte("NAME=\"Amazon Linux\"\nPRETTY_NAME=\"Amazon Linux 2023\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := probeOSRelease(path); got != "Amazon Linux 2023" {
		t.Fatalf("probeOSRelease = %q", got)
	}
	if got := probeOSRelease(filepath.Join(t.TempDir(), "missing")); got != NotMeasured {
		t.Fatalf("missing file must probe as NOT_MEASURED, got %q", got)
	}
}
