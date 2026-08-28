// Command currentheadctl executes and materializes the non-networked
// current-source qualification used by later evidence verifiers.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/provenance"
)

const usage = "usage: currentheadctl qualify --repository-root ABS --toolchain-bin-dir ABS --go ABS --validation-time RFC3339\n"

type config struct {
	root, toolchain, goExecutable string
	runHome                       string
	validationTime                time.Time
}

var materialize = provenance.MaterializeCurrentHeadQualification

func run(arguments []string, stdout, stderr io.Writer) int {
	cfg, err := parse(arguments)
	if err != nil {
		fmt.Fprint(stderr, usage)
		return 64
	}
	cfg.runHome, err = os.MkdirTemp("", "currentheadctl-home-")
	if err != nil {
		fmt.Fprintf(stderr, "qualification home creation failed: %v\n", err)
		return 1
	}
	defer os.RemoveAll(cfg.runHome)
	rustc := filepath.Join(cfg.toolchain, "rustc")
	cargo := filepath.Join(cfg.toolchain, "cargo")
	for _, executable := range []string{rustc, cargo, cfg.goExecutable} {
		if !regularExecutable(executable) {
			fmt.Fprintf(stderr, "qualification tool is not a regular executable: %s\n", executable)
			return 1
		}
	}
	rawVersion, err := execute(cfg, cfg.root, rustc, "-vV")
	if err != nil {
		fmt.Fprintf(stderr, "rustc identity failed: %v\n", err)
		return 1
	}
	rustcVersion, host, err := parseRustcIdentity(rawVersion)
	if err != nil {
		fmt.Fprintf(stderr, "rustc identity invalid: %v\n", err)
		return 1
	}
	for _, gate := range qualificationGates(cfg, cargo) {
		if _, err := execute(cfg, gate.directory, gate.executable, gate.arguments...); err != nil {
			fmt.Fprintf(stderr, "qualification gate failed: %s: %v\n", strings.Join(gate.display, " "), err)
			return 1
		}
	}
	if err := materialize(cfg.root, provenance.CurrentHeadMaterialization{
		ValidationTime: cfg.validationTime, Rustc: rustcVersion, Host: host,
	}); err != nil {
		fmt.Fprintf(stderr, "qualification materialization failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "PASS")
	return 0
}

func parse(arguments []string) (config, error) {
	if len(arguments) != 9 || arguments[0] != "qualify" || arguments[1] != "--repository-root" ||
		arguments[3] != "--toolchain-bin-dir" || arguments[5] != "--go" || arguments[7] != "--validation-time" {
		return config{}, fmt.Errorf("invalid arguments")
	}
	for _, path := range []string{arguments[2], arguments[4], arguments[6]} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return config{}, fmt.Errorf("path is not clean and absolute")
		}
	}
	validationTime, err := time.Parse(time.RFC3339, arguments[8])
	if err != nil {
		return config{}, err
	}
	return config{root: arguments[2], toolchain: arguments[4], goExecutable: arguments[6], validationTime: validationTime}, nil
}

type gate struct {
	directory, executable string
	arguments, display    []string
}

func qualificationGates(cfg config, cargo string) []gate {
	rust := filepath.Join(cfg.root, "rust")
	return []gate{
		{rust, cargo, []string{"test", "--locked", "-p", "websocket-core"}, []string{"cargo", "test", "--locked", "-p", "websocket-core"}},
		{rust, cargo, []string{"test", "--locked", "-p", "websocket-driver"}, []string{"cargo", "test", "--locked", "-p", "websocket-driver"}},
		{rust, cargo, []string{"test", "--locked", "-p", "websocket-testee", "--lib"}, []string{"cargo", "test", "--locked", "-p", "websocket-testee", "--lib"}},
		{rust, cargo, []string{"test", "--locked", "-p", "websocket-testee", "--test", "process", "neutral_oracle"}, []string{"cargo", "test", "--locked", "-p", "websocket-testee", "--test", "process", "neutral_oracle"}},
		{rust, cargo, []string{"fmt", "--all", "--", "--check"}, []string{"cargo", "fmt", "--all", "--", "--check"}},
		{rust, cargo, []string{"clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"}, []string{"cargo", "clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"}},
		{cfg.root, cfg.goExecutable, []string{"test", "./cmd/rustgate", "-count=1"}, []string{"go", "test", "./cmd/rustgate", "-count=1"}},
	}
}

func execute(cfg config, directory, executable string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = directory
	command.Env = []string{
		"HOME=" + cfg.runHome,
		"CARGO_HOME=" + filepath.Join(cfg.runHome, ".cargo"),
		"PATH=" + cfg.toolchain + ":/opt/homebrew/bin:/usr/bin:/bin",
		"LANG=C", "LC_ALL=C", "CARGO_NET_OFFLINE=true", "RUST_BACKTRACE=0",
	}
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("timeout")
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, boundedTail(output, 4096))
	}
	return output, nil
}

func parseRustcIdentity(raw []byte) (string, string, error) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "rustc ") {
		return "", "", fmt.Errorf("missing rustc release")
	}
	host := ""
	for _, line := range lines {
		if strings.HasPrefix(line, "host: ") {
			host = strings.TrimPrefix(line, "host: ")
		}
	}
	if host == "" {
		return "", "", fmt.Errorf("missing host")
	}
	return lines[0], host, nil
}

func regularExecutable(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode()&0o111 != 0
}

func boundedTail(raw []byte, maximum int) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) > maximum {
		raw = raw[len(raw)-maximum:]
	}
	return string(raw)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
