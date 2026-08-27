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

const usage = "usage: differentialctl run --repository-root ABS --public-corpus ABS --java-executable ABS --java-adapter ABS --java-runtime ABS --java-support ABS[,ABS...] --rust-testee ABS --migration-inventory ABS --compatibility-surface ABS --ledger ABS --oracle-hierarchy ABS --evidence ABS\n       differentialctl diagnose (same flags as run; writes no ledger/evidence)\n       differentialctl verify --repository-root ABS --evidence ABS --ledger ABS --oracle-hierarchy ABS\n"

var runDifferential = differential.RunPublicDifferential
var diagnoseDifferential = differential.RunPublicDiagnostic
var verifyDifferential = differential.VerifyPublicDifferential

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

func diagnoseCommand(args []string, stdout, stderr io.Writer) int {
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
	report, err := diagnoseDifferential(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(stderr, "differential diagnose failed: %v\n", err)
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
	case "verify":
		return verifyCommand(args[1:], stdout, stderr)
	default:
		fmt.Fprint(stderr, usage)
		return 64
	}
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
