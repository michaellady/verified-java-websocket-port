package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/differential"
)

const usage = "usage: differentialctl run --repository-root ABS --public-corpus ABS --java-executable ABS --java-adapter ABS --java-runtime ABS --java-support ABS[,ABS...] --rust-testee ABS --migration-inventory ABS --compatibility-surface ABS --ledger ABS --oracle-hierarchy ABS --evidence ABS\n       differentialctl diagnose (same flags as run; strict RFC profile; writes no ledger/evidence)\n       differentialctl parity (same flags as run; Java-WebSocket 1.6.0 profile; writes no ledger/evidence)\n       differentialctl verify-parity (same flags as run plus --parity-summary ABS; reads only)\n       differentialctl verify --repository-root ABS --evidence ABS --ledger ABS --oracle-hierarchy ABS\n       differentialctl reproduce --repository-root ABS --evidence ABS --reproducer-id ID\n"

var runDifferential = differential.RunPublicDifferential
var diagnoseDifferential = differential.RunPublicDiagnostic
var parityDifferential = differential.RunJavaParityDiagnostic
var verifyParityDiagnostic = differential.VerifyJavaParityDiagnostic
var verifyDifferential = differential.VerifyPublicDifferential
var reproduceDifferential = differential.ReproducePublicDifferential

const maximumParitySummaryBytes int64 = 32 << 20

func parse(args []string, allowed []string) (map[string]string, error) {
	if len(args)%2 != 0 {
		return nil, errors.New("flags require values")
	}
	allow := map[string]bool{}
	for _, name := range allowed {
		allow[name] = true
	}
	values := map[string]string{}
	for index := 0; index < len(args); index += 2 {
		name, value := args[index], args[index+1]
		if !strings.HasPrefix(name, "--") || !allow[name] || value == "" || strings.HasPrefix(value, "--") {
			return nil, errors.New("unknown, positional, or empty argument")
		}
		if _, duplicate := values[name]; duplicate {
			return nil, errors.New("repeated singleton flag")
		}
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return nil, errors.New("all paths must be absolute and clean")
		}
		values[name] = value
	}
	if len(values) != len(allowed) {
		return nil, errors.New("required flag absent")
	}
	return values, nil
}

func runCommand(args []string, stdout, stderr io.Writer) int {
	allowed := []string{"--repository-root", "--public-corpus", "--java-executable", "--java-adapter", "--java-runtime", "--java-support", "--rust-testee", "--migration-inventory", "--compatibility-surface", "--ledger", "--oracle-hierarchy", "--evidence"}
	values, err := parse(args, allowed)
	if err != nil {
		fmt.Fprint(stderr, usage)
		return 64
	}
	support := strings.Split(values["--java-support"], ",")
	for _, path := range support {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			fmt.Fprint(stderr, usage)
			return 64
		}
	}
	cfg := differential.Config{RepositoryRoot: values["--repository-root"], PublicCorpus: values["--public-corpus"], JavaExecutable: values["--java-executable"], JavaAdapterJar: values["--java-adapter"], JavaRuntimeJar: values["--java-runtime"], JavaSupportJars: support, RustTestee: values["--rust-testee"], MigrationInventory: values["--migration-inventory"], CompatibilitySurface: values["--compatibility-surface"], LedgerPath: values["--ledger"], OracleHierarchyPath: values["--oracle-hierarchy"], EvidencePath: values["--evidence"], ScenarioTimeout: 5 * time.Second, SuiteTimeout: 15 * time.Minute, MinimizationBudget: differential.Budget{MaxCandidates: 128, MaxDuration: 10 * time.Minute}}
	receipt, err := runDifferential(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(stderr, "differential run failed: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(receipt); err != nil {
		fmt.Fprintln(stderr, "encode receipt failed")
		return 1
	}
	return 0
}

type diagnosticRunner func(context.Context, differential.Config) (differential.DiagnosticReport, error)

var diagnosticFlags = []string{"--repository-root", "--public-corpus", "--java-executable", "--java-adapter", "--java-runtime", "--java-support", "--rust-testee", "--migration-inventory", "--compatibility-surface", "--ledger", "--oracle-hierarchy", "--evidence"}

func configFromValues(values map[string]string) (differential.Config, bool) {
	support := strings.Split(values["--java-support"], ",")
	for _, path := range support {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return differential.Config{}, false
		}
	}
	return differential.Config{RepositoryRoot: values["--repository-root"], PublicCorpus: values["--public-corpus"], JavaExecutable: values["--java-executable"], JavaAdapterJar: values["--java-adapter"], JavaRuntimeJar: values["--java-runtime"], JavaSupportJars: support, RustTestee: values["--rust-testee"], MigrationInventory: values["--migration-inventory"], CompatibilitySurface: values["--compatibility-surface"], LedgerPath: values["--ledger"], OracleHierarchyPath: values["--oracle-hierarchy"], EvidencePath: values["--evidence"], ScenarioTimeout: 5 * time.Second, SuiteTimeout: 15 * time.Minute, MinimizationBudget: differential.Budget{MaxCandidates: 128, MaxDuration: 10 * time.Minute}}, true
}

func diagnosticCommand(args []string, stdout, stderr io.Writer, runner diagnosticRunner, label string) int {
	values, err := parse(args, diagnosticFlags)
	if err != nil {
		fmt.Fprint(stderr, usage)
		return 64
	}
	cfg, ok := configFromValues(values)
	if !ok {
		fmt.Fprint(stderr, usage)
		return 64
	}
	report, err := runner(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(stderr, "differential %s failed: %v\n", label, err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(stderr, "encode diagnostic report failed")
		return 1
	}
	return 0
}

func diagnoseCommand(args []string, stdout, stderr io.Writer) int {
	return diagnosticCommand(args, stdout, stderr, diagnoseDifferential, "diagnose")
}

func parityCommand(args []string, stdout, stderr io.Writer) int {
	return diagnosticCommand(args, stdout, stderr, parityDifferential, "parity")
}

func readParitySummary(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("parity summary path must be absolute and clean")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, errors.New("parity summary path may not resolve through a symlink")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maximumParitySummaryBytes {
		return nil, errors.New("parity summary must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.New("parity summary changed during open")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumParitySummaryBytes+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximumParitySummaryBytes {
		return nil, errors.New("parity summary read failed")
	}
	return raw, nil
}

func verifyParityCommand(args []string, stdout, stderr io.Writer) int {
	allowed := append(append([]string(nil), diagnosticFlags...), "--parity-summary")
	values, err := parse(args, allowed)
	if err != nil {
		fmt.Fprint(stderr, usage)
		return 64
	}
	summaryPath := values["--parity-summary"]
	delete(values, "--parity-summary")
	cfg, ok := configFromValues(values)
	if !ok {
		fmt.Fprint(stderr, usage)
		return 64
	}
	raw, err := readParitySummary(summaryPath)
	if err != nil {
		fmt.Fprintln(stderr, "parity summary read failed")
		return 1
	}
	if err := verifyParityDiagnostic(cfg, raw); err != nil {
		fmt.Fprintf(stderr, "differential parity verify failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "PASS")
	return 0
}

func verifyCommand(args []string, stdout, stderr io.Writer) int {
	allowed := []string{"--repository-root", "--evidence", "--ledger", "--oracle-hierarchy"}
	values, err := parse(args, allowed)
	if err != nil {
		fmt.Fprint(stderr, usage)
		return 64
	}
	root := values["--repository-root"]
	if values["--ledger"] != filepath.Join(root, "evidence/java/behavior-delta-ledger.json") || values["--oracle-hierarchy"] != filepath.Join(root, "evidence/oracle-hierarchy.json") {
		fmt.Fprint(stderr, usage)
		return 64
	}
	raw, err := os.ReadFile(values["--evidence"])
	if err != nil || len(raw) == 0 || len(raw) > 32<<20 {
		fmt.Fprintln(stderr, "evidence read failed")
		return 1
	}
	if err := verifyDifferential(root, raw); err != nil {
		fmt.Fprintf(stderr, "differential verify failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "PASS")
	return 0
}

func reproduceCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) != 6 || args[0] != "--repository-root" || args[2] != "--evidence" || args[4] != "--reproducer-id" || !filepath.IsAbs(args[1]) || filepath.Clean(args[1]) != args[1] || !filepath.IsAbs(args[3]) || filepath.Clean(args[3]) != args[3] || !strings.HasPrefix(args[5], "reproducer.us005.pub.") || len(args[5]) > 128 {
		fmt.Fprint(stderr, usage)
		return 64
	}
	raw, err := os.ReadFile(args[3])
	if err != nil || len(raw) == 0 || len(raw) > 32<<20 {
		fmt.Fprintln(stderr, "evidence read failed")
		return 1
	}
	receipt, err := reproduceDifferential(context.Background(), args[1], raw, args[5])
	if err != nil {
		fmt.Fprintf(stderr, "differential reproduce failed: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(receipt); err != nil {
		fmt.Fprintln(stderr, "encode reproduction receipt failed")
		return 1
	}
	return 0
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 64
	}
	switch args[0] {
	case "run":
		return runCommand(args[1:], stdout, stderr)
	case "diagnose":
		return diagnoseCommand(args[1:], stdout, stderr)
	case "parity":
		return parityCommand(args[1:], stdout, stderr)
	case "verify-parity":
		return verifyParityCommand(args[1:], stdout, stderr)
	case "verify":
		return verifyCommand(args[1:], stdout, stderr)
	case "reproduce":
		return reproduceCommand(args[1:], stdout, stderr)
	default:
		fmt.Fprint(stderr, usage)
		return 64
	}
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
