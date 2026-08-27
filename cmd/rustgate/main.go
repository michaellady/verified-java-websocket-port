package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/rustgate"
)

const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
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
		root, options, remaining, ok := parseVerificationFlags("verify", arguments[1:], stderr)
		if !ok || len(remaining) != 0 {
			printUsage(stderr)
			return exitUsage
		}
		return verify(root, options, stdout, stderr)
	case "cargo":
		root, options, cargoArguments, ok := parseVerificationFlags("cargo", arguments[1:], stderr)
		if !ok || len(cargoArguments) == 0 {
			printUsage(stderr)
			return exitUsage
		}
		return runCargo(root, options, cargoArguments, stdout, stderr)
	default:
		printUsage(stderr)
		return exitUsage
	}
}

func parseVerificationFlags(name string, arguments []string, stderr io.Writer) (string, rustgate.Options, []string, bool) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root")
	toolchainBinDir := flags.String("toolchain-bin-dir", "", "selected installed Rust toolchain bin directory")
	validationTimeValue := flags.String("validation-time", "", "explicit RFC3339 receipt-validation timestamp")
	if err := flags.Parse(arguments); err != nil || *root == "" || *toolchainBinDir == "" || *validationTimeValue == "" {
		return "", rustgate.Options{}, nil, false
	}
	validationTime, err := time.Parse(time.RFC3339, *validationTimeValue)
	if err != nil {
		fmt.Fprintln(stderr, "validation-time must be RFC3339:", err)
		return "", rustgate.Options{}, nil, false
	}
	return *root, rustgate.Options{
		ValidationTime:  validationTime,
		ToolchainBinDir: *toolchainBinDir,
	}, flags.Args(), true
}

func verify(root string, options rustgate.Options, stdout, stderr io.Writer) int {
	report := rustgate.Verify(root, options)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFindings
	}
	if !report.OK {
		return exitFindings
	}
	return exitOK
}

func runCargo(root string, options rustgate.Options, arguments []string, stdout, stderr io.Writer) int {
	if code := verify(root, options, stdout, stderr); code != exitOK {
		return code
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFindings
	}
	cargoHome, err := os.MkdirTemp("", "rustgate-cargo-home-")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFindings
	}
	defer func() {
		if err := os.RemoveAll(cargoHome); err != nil {
			fmt.Fprintln(stderr, "remove temporary Cargo home:", err)
		}
	}()

	command := exec.Command(filepath.Join(options.ToolchainBinDir, "cargo"), arguments...)
	command.Dir = filepath.Join(canonicalRoot, "rust")
	command.Env = sanitizedCargoEnvironment(options.ToolchainBinDir, cargoHome, filepath.Join(canonicalRoot, "rust", "target"))
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFindings
	}
	return exitOK
}

func sanitizedCargoEnvironment(toolchainBinDir, cargoHome, targetDir string) []string {
	environment := make([]string, 0, len(os.Environ())+7)
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if !found || rejectsAmbientExecutableOverride(key) {
			continue
		}
		environment = append(environment, entry)
	}
	environment = append(environment,
		"PATH="+toolchainBinDir+":/usr/bin:/bin:/usr/sbin:/sbin",
		"RUSTC="+filepath.Join(toolchainBinDir, "rustc"),
		"RUSTDOC="+filepath.Join(toolchainBinDir, "rustdoc"),
		"CARGO_HOME="+cargoHome,
		"CARGO_TARGET_DIR="+targetDir,
		"CARGO_NET_OFFLINE=true",
		"CARGO_TERM_COLOR=never",
	)
	return environment
}

func rejectsAmbientExecutableOverride(key string) bool {
	if key == "PATH" || strings.HasPrefix(key, "CARGO_") || strings.HasPrefix(key, "RUST") || strings.HasPrefix(key, "DYLD_") {
		return true
	}
	switch key {
	case "AR", "CC", "CPP", "CXX", "LD", "MACOSX_DEPLOYMENT_TARGET":
		return true
	default:
		return false
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: rustgate verify --root DIR --toolchain-bin-dir DIR --validation-time RFC3339")
	fmt.Fprintln(output, "       rustgate cargo --root DIR --toolchain-bin-dir DIR --validation-time RFC3339 -- CARGO_ARGS...")
}
