// benchplanctl verifies the US-008 benchmark preregistration documents
// and reports the machine-checkable completion meter. It never measures
// anything: the owner-attested preregistration freeze can be valid while
// exit code 0 remains unreachable until the owner binds the confirmation
// host and every measurement/analyzer tool identity.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/michaellady/verified-java-websocket-port/internal/benchplan"
)

// Exit codes: 0 = fully bound and consistent (owner-gated; not
// reachable while host binding is pending), 1 = verification failures,
// 2 = usage error, 3 = documents consistent with the single remaining
// owner-gated blocker class HOST_BINDING_PENDING.
const (
	exitFullyBound          = 0
	exitFailures            = 1
	exitUsage               = 2
	exitHostBindingPending  = 3
	exitInconclusiveBlocked = 4
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return exitUsage
	}
	switch arguments[0] {
	case "verify":
		return runVerify(arguments[1:], stdout, stderr)
	case "order":
		return runOrder(arguments[1:], stdout, stderr)
	case "envelope":
		return runEnvelope(arguments[1:], stdout, stderr)
	case "raw-append":
		return runRawAppend(arguments[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return exitUsage
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  benchplanctl verify --root DIR   validate the preregistration documents and print the binding completion meter")
	fmt.Fprintln(output, "  benchplanctl order [--workload ID]   print the SHA-256-derived Java/Rust pair order (executable seed spec)")
	fmt.Fprintln(output, "  benchplanctl envelope --root DIR   emit the complete two-host resource-envelope decision")
	fmt.Fprintln(output, "  benchplanctl raw-append --root DIR --role ROLE --record-type TYPE --payload FILE   append one future authorized ledger record")
	fmt.Fprintln(output, "exit codes: 0 accepted measurement, 1 verification failures, 2 usage, 3 consistent but HOST_BINDING_PENDING, 4 INCONCLUSIVE_BLOCKED")
}

func runEnvelope(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("envelope", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *root == "" {
		printUsage(stderr)
		return exitUsage
	}
	decision, err := benchplan.DecideResourceEnvelope(*root)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailures
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(decision); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailures
	}
	if decision.MeasurementAcceptance == benchplan.MeasurementInconclusiveBlocked {
		return exitInconclusiveBlocked
	}
	return exitFullyBound
}

func runRawAppend(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("raw-append", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root")
	role := flags.String("role", "", "environment role")
	recordType := flags.String("record-type", "", "ledger record type")
	payloadPath := flags.String("payload", "", "payload JSON file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *root == "" || *role == "" || *recordType == "" || *payloadPath == "" {
		printUsage(stderr)
		return exitUsage
	}
	report, err := benchplan.Verify(*root)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailures
	}
	if !report.FullyBound() {
		if report.HostBindingIsOnlyBlocker() {
			fmt.Fprintln(stderr, "INCONCLUSIVE_BLOCKED: SAMPLES_NOT_AUTHORIZED_OR_COLLECTED; both exact native hosts and all tool identities must be BOUND before raw append")
			return exitInconclusiveBlocked
		}
		fmt.Fprintf(stderr, "benchmark verification blockers: %v\n", report.BlockerClasses)
		return exitFailures
	}
	if *role != benchplan.EnvironmentRolePrimary && *role != benchplan.EnvironmentRoleConfirmation {
		fmt.Fprintln(stderr, "role must be primary or confirmation")
		return exitUsage
	}
	info, err := os.Lstat(*payloadPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 4<<20 {
		fmt.Fprintln(stderr, "payload must be a nonempty regular non-symlink file no larger than 4 MiB")
		return exitFailures
	}
	payload, err := os.ReadFile(*payloadPath)
	if err != nil || int64(len(payload)) != info.Size() {
		fmt.Fprintln(stderr, "payload changed or could not be read")
		return exitFailures
	}
	name := "primary.jsonl"
	if *role == benchplan.EnvironmentRoleConfirmation {
		name = "confirmation.jsonl"
	}
	receipt, err := benchplan.AppendRawLedger(filepath.Join(*root, "benchmarks", "raw", name), *role, *recordType, payload)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailures
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(receipt); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailures
	}
	return exitInconclusiveBlocked
}

func runVerify(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *root == "" {
		printUsage(stderr)
		return exitUsage
	}
	report, err := benchplan.Verify(*root)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailures
	}

	documents := make([]string, 0, len(benchplan.BenchmarkDocuments))
	for document := range benchplan.BenchmarkDocuments {
		documents = append(documents, document)
	}
	sort.Strings(documents)
	for _, document := range documents {
		if failures := report.SchemaFailures[document]; len(failures) > 0 {
			fmt.Fprintf(stdout, "schema FAIL %s\n", document)
			for _, failure := range failures {
				fmt.Fprintf(stdout, "  - %s\n", failure)
			}
		} else {
			fmt.Fprintf(stdout, "schema ok   %s\n", document)
		}
	}
	if len(report.PlanFailures) > 0 {
		fmt.Fprintln(stdout, "plan-spec FAIL (plan disagrees with the frozen executable spec):")
		for _, failure := range report.PlanFailures {
			fmt.Fprintf(stdout, "  - %s\n", failure)
		}
	} else {
		fmt.Fprintln(stdout, "plan-spec ok (six workloads, seed rule, derived orders, statistics constants, thresholds)")
	}
	if len(report.PowerFailures) > 0 {
		fmt.Fprintln(stdout, "power-model FAIL:")
		for _, failure := range report.PowerFailures {
			fmt.Fprintf(stdout, "  - %s\n", failure)
		}
	} else {
		fmt.Fprintln(stdout, "power-model ok (named alternatives detectable at alpha 0.025, power 0.8, max log-SD 0.10, n=30)")
	}

	if len(report.MeterFailures) > 0 {
		fmt.Fprintln(stdout, "meter FAIL (METER_TAMPERED — the completion meter is code+schema truth, not document truth):")
		for _, failure := range report.MeterFailures {
			fmt.Fprintf(stdout, "  - %s\n", failure)
		}
	} else {
		fmt.Fprintln(stdout, "meter ok (declared roles and required_binding_fields match the canonical per-role lists)")
	}
	fmt.Fprintf(stdout, "preregistration freeze: plan %s", report.PlanFreezeState)
	environmentDocuments := make([]string, 0, len(report.EnvironmentBindingStatus))
	for document := range report.EnvironmentBindingStatus {
		environmentDocuments = append(environmentDocuments, document)
	}
	sort.Strings(environmentDocuments)
	for _, document := range environmentDocuments {
		fmt.Fprintf(stdout, "; %s %s", document, report.EnvironmentBindingStatus[document])
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "binding completion meter: %d field(s) unbound, %d runtime-snapshot field(s) deferred to measurement time\n",
		len(report.UnboundFields), len(report.RuntimeSnapshotFields))
	for _, field := range report.UnboundFields {
		fmt.Fprintf(stdout, "  UNBOUND %-22s %s (%s)\n", field.Status, field.Path, field.Document)
	}
	for _, field := range report.RuntimeSnapshotFields {
		fmt.Fprintf(stdout, "  RUNTIME %-22s %s (%s)\n", field.Status, field.Path, field.Document)
	}

	switch {
	case report.FullyBound():
		fmt.Fprintln(stdout, "RESULT: owner-attested preregistration valid and every sample-readiness binding field bound")
		return exitFullyBound
	case report.HostBindingIsOnlyBlocker():
		fmt.Fprintln(stdout, "RESULT: documents consistent; single remaining blocker class: HOST_BINDING_PENDING")
		fmt.Fprintln(stdout, "US-008 preregistration freeze: VALID (OWNER_ATTESTED_NOT_INDEPENDENT). Measurement preflight: BLOCKED. The exact confirmation host and every measurement/analyzer tool identity must bind before any sample, tuning, or performance claim.")
		return exitHostBindingPending
	default:
		fmt.Fprintf(stdout, "RESULT: verification FAILED with blocker classes %v\n", report.BlockerClasses)
		return exitFailures
	}
}

func runOrder(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("order", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workload := flags.String("workload", "", "workload id (default: all six)")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		printUsage(stderr)
		return exitUsage
	}
	workloads := benchplan.WorkloadIDs
	if *workload != "" {
		workloads = []string{*workload}
	}
	for _, workloadID := range workloads {
		order, err := benchplan.PairOrder(workloadID)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitFailures
		}
		fmt.Fprintf(stdout, "%s (seed %q; pairs 0-4 warmup, 5-34 measured):\n", workloadID, benchplan.SeedString(workloadID))
		for i, entry := range order {
			kind := "measured"
			if i < benchplan.WarmupPairs {
				kind = "warmup"
			}
			fmt.Fprintf(stdout, "  pair %02d %-8s %s\n", i, kind, entry)
		}
	}
	return exitFullyBound
}
