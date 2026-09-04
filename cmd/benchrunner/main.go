// benchrunner is the US-008 benchmark-runner STUB (enabling work),
// the Go replacement for the former benchmarks/runner/run-benchmark.sh
// (review fix I6: nontrivial logic lives in a compiled binary, not a
// shell script). It is cross-compiled for the confirmation host
// (GOOS=linux GOARCH=amd64) by .github/workflows/benchmark.yml and
// invoked there via SSM.
//
// The stub does exactly two things:
//  1. validates its arguments (fail-closed), and
//  2. emits the result-schema skeleton with the NOT_MEASURED sentinel
//     in every metric field, plus honestly-captured host identity facts,
//     then re-reads the emitted file and verifies no metric field holds
//     anything but the sentinel.
//
// It performs NO benchmark, produces NO performance number, and REFUSES
// any mode that implies measurement. Real measured runs require: frozen
// + independently attested plan, bound environments (see
// benchmarks/environments/), bound tool identities with digests, and a
// replacement runner that is itself digest-bound in the preregistration.
// Fabricating a number where a NOT_MEASURED sentinel belongs is a
// blocking integrity violation (see benchmarks/README.md).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// NotMeasured is the only honest placeholder for an unmeasured value.
const NotMeasured = "NOT_MEASURED"

// Exit codes mirror the retired shell stub exactly: 2 = usage /
// validation error, 3 = refused measurement-implying mode, 1 = runtime
// failure (including a failed self-check).
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	exitRefused = 3
)

var workloadIDs = []string{
	"wl-01-handshake-close",
	"wl-02-small-text-echo",
	"wl-03-fragmented-64kib-binary-echo",
	"wl-04-control-mix",
	"wl-05-cap-rejection",
	"wl-06-concurrent-pressure",
}

type workloadSkeleton struct {
	Workload        string `json:"workload"`
	Samples         string `json:"samples"`
	PeakRSS         string `json:"peak_rss"`
	SteadyRSS       string `json:"steady_rss"`
	CPUTime         string `json:"cpu_time"`
	StartupToReady  string `json:"startup_to_ready"`
	LatencyP50      string `json:"latency_p50"`
	LatencyP95      string `json:"latency_p95"`
	LatencyP99      string `json:"latency_p99"`
	AllocatedBytes  string `json:"allocated_bytes"`
	AllocationCount string `json:"allocation_count"`
	Throughput      string `json:"throughput"`
}

type hostIdentityProbe struct {
	Note         string `json:"note"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type smokeResult struct {
	Schema            string             `json:"schema"`
	Mode              string             `json:"mode"`
	Honesty           string             `json:"honesty"`
	PRNumber          string             `json:"pr_number"`
	Workspace         string             `json:"workspace"`
	GeneratedAtUTC    string             `json:"generated_at_utc"`
	HostIdentityProbe hostIdentityProbe  `json:"host_identity_probe"`
	Workloads         []workloadSkeleton `json:"workloads"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: benchrunner --mode pipeline-smoke --pr <N> --workspace bench-pr-<N> --out <dir>")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "  --mode       Only 'pipeline-smoke' is accepted. Any measurement-implying")
	fmt.Fprintln(output, "               mode is refused by design.")
	fmt.Fprintln(output, "  --pr         Decimal PR number for this job-scoped run.")
	fmt.Fprintln(output, "  --workspace  Must equal bench-pr-<pr> (the job-scoped workspace contract).")
	fmt.Fprintln(output, "  --out        Writable output directory for the result-schema skeleton.")
}

func run(arguments []string, stdout, stderr io.Writer) int {
	var mode, pr, workspace, out string
	for i := 0; i < len(arguments); i++ {
		argument := arguments[i]
		value := func() string {
			if i+1 < len(arguments) {
				i++
				return arguments[i]
			}
			return ""
		}
		switch argument {
		case "--mode":
			mode = value()
		case "--pr":
			pr = value()
		case "--workspace":
			workspace = value()
		case "--out":
			out = value()
		case "-h", "--help":
			printUsage(stderr)
			return exitUsage
		default:
			fmt.Fprintf(stderr, "error: unknown argument %q\n", argument)
			printUsage(stderr)
			return exitUsage
		}
	}

	if mode == "" || pr == "" || workspace == "" || out == "" {
		fmt.Fprintln(stderr, "error: --mode, --pr, --workspace, and --out are all required")
		printUsage(stderr)
		return exitUsage
	}
	if mode != "pipeline-smoke" {
		fmt.Fprintf(stderr, "error: mode %q refused. This runner is a stub: only 'pipeline-smoke' exists, and no mode may produce measurements until the preregistration binds a real, digest-bound runner.\n", mode)
		return exitRefused
	}
	if !isDecimal(pr) {
		fmt.Fprintf(stderr, "error: --pr must be a decimal PR number (got %q)\n", pr)
		return exitUsage
	}
	if workspace != "bench-pr-"+pr {
		fmt.Fprintf(stderr, "error: --workspace must equal bench-pr-%s (got %q)\n", pr, workspace)
		return exitUsage
	}

	if err := os.MkdirAll(out, 0o755); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitFailure
	}

	result := smokeResult{
		Schema:         "vjwp-bench-pipeline-smoke/1",
		Mode:           "pipeline-smoke",
		Honesty:        "STUB OUTPUT — this is a pipeline plumbing check, not a benchmark. Every metric is the NOT_MEASURED sentinel by design. This artifact is not evidence for US-008 and asserts no performance claim.",
		PRNumber:       pr,
		Workspace:      workspace,
		GeneratedAtUTC: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		HostIdentityProbe: hostIdentityProbe{
			Note:         "Real identity facts from the host this stub ran on (not measurements).",
			Kernel:       probeCommand("uname", "-sr"),
			Architecture: probeCommand("uname", "-m"),
			OS:           probeOSRelease("/etc/os-release"),
		},
	}
	for _, workloadID := range workloadIDs {
		result.Workloads = append(result.Workloads, workloadSkeleton{
			Workload:        workloadID,
			Samples:         NotMeasured,
			PeakRSS:         NotMeasured,
			SteadyRSS:       NotMeasured,
			CPUTime:         NotMeasured,
			StartupToReady:  NotMeasured,
			LatencyP50:      NotMeasured,
			LatencyP95:      NotMeasured,
			LatencyP99:      NotMeasured,
			AllocatedBytes:  NotMeasured,
			AllocationCount: NotMeasured,
			Throughput:      NotMeasured,
		})
	}

	resultPath := filepath.Join(out, "pipeline-smoke-result.json")
	content, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitFailure
	}
	if err := os.WriteFile(resultPath, append(content, '\n'), 0o644); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitFailure
	}

	// Self-check: re-read the emitted artifact and verify it is valid
	// JSON with no metric field holding anything but the sentinel
	// (defense against future edits fabricating numbers). Unlike the
	// retired shell stub's python3 check, this can never be skipped.
	if err := selfCheck(resultPath); err != nil {
		fmt.Fprintf(stderr, "integrity violation: %v\n", err)
		return exitFailure
	}
	fmt.Fprintln(stdout, "self-check ok: valid JSON, all metric fields are NOT_MEASURED sentinels")
	fmt.Fprintf(stdout, "wrote %s\n", resultPath)
	return exitOK
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// probeCommand returns the trimmed output of an identity probe command,
// or the NOT_MEASURED sentinel when the probe is unavailable. These are
// identity facts, not benchmark measurements.
func probeCommand(name string, arguments ...string) string {
	output, err := exec.Command(name, arguments...).Output()
	if err != nil {
		return NotMeasured
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return NotMeasured
	}
	return trimmed
}

// probeOSRelease extracts PRETTY_NAME from an os-release file without
// sourcing it through a shell.
func probeOSRelease(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return NotMeasured
	}
	for _, line := range strings.Split(string(content), "\n") {
		value, found := strings.CutPrefix(strings.TrimSpace(line), "PRETTY_NAME=")
		if !found {
			continue
		}
		value = strings.Trim(value, `"'`)
		if value != "" {
			return value
		}
	}
	return NotMeasured
}

// selfCheck verifies the emitted artifact: valid JSON, all six
// workloads present, and every metric field exactly the NOT_MEASURED
// sentinel.
func selfCheck(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var document struct {
		Workloads []map[string]any `json:"workloads"`
	}
	if err := json.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("emitted artifact is not valid JSON: %w", err)
	}
	if len(document.Workloads) != len(workloadIDs) {
		return fmt.Errorf("emitted artifact has %d workloads, want %d", len(document.Workloads), len(workloadIDs))
	}
	metrics := []string{"samples", "peak_rss", "steady_rss", "cpu_time", "startup_to_ready",
		"latency_p50", "latency_p95", "latency_p99", "allocated_bytes", "allocation_count", "throughput"}
	for _, workload := range document.Workloads {
		for _, metric := range metrics {
			if workload[metric] != NotMeasured {
				return fmt.Errorf("%v.%s is not the NOT_MEASURED sentinel", workload["workload"], metric)
			}
		}
	}
	return nil
}
