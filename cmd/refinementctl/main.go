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
	"syscall"

	"github.com/michaellady/verified-java-websocket-port/internal/refinement"
)

const usage = "usage: refinementctl capture --repository-root ABS --before FULL_COMMIT --after FULL_COMMIT --cargo ABS --evidence ABS\n       refinementctl verify --repository-root ABS --evidence ABS\n"

var capture = refinement.Capture
var verify = refinement.Verify

func parse(args, allowed []string) (map[string]string, error) {
	if len(args) != len(allowed)*2 {
		return nil, errors.New("wrong argument count")
	}
	allow := map[string]bool{}
	for _, flag := range allowed {
		allow[flag] = true
	}
	values := map[string]string{}
	for index := 0; index < len(args); index += 2 {
		flag, value := args[index], args[index+1]
		if !allow[flag] || value == "" || strings.HasPrefix(value, "--") || values[flag] != "" {
			return nil, errors.New("unknown, empty, or duplicate flag")
		}
		values[flag] = value
	}
	return values, nil
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

func writeAtomic(path string, raw []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("evidence destination is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary := filepath.Join(filepath.Dir(path), ".refinement-replay.json.tmp")
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func captureCommand(args []string, stdout, stderr io.Writer) int {
	values, err := parse(args, []string{"--repository-root", "--before", "--after", "--cargo", "--evidence"})
	if err != nil || !cleanAbsolute(values["--repository-root"]) || !cleanAbsolute(values["--cargo"]) || !cleanAbsolute(values["--evidence"]) || values["--evidence"] != filepath.Join(values["--repository-root"], refinement.EvidencePath) {
		fmt.Fprint(stderr, usage)
		return 64
	}
	evidence, err := capture(context.Background(), refinement.CaptureConfig{RepositoryRoot: values["--repository-root"], BeforeCommit: values["--before"], AfterCommit: values["--after"], Cargo: values["--cargo"], EvidencePath: values["--evidence"]})
	if err != nil {
		fmt.Fprintf(stderr, "refinement capture failed: %v\n", err)
		return 1
	}
	raw, err := refinement.Marshal(evidence)
	if err != nil || writeAtomic(values["--evidence"], raw) != nil {
		fmt.Fprintln(stderr, "refinement evidence write failed")
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(map[string]any{"status": evidence.Status, "scenarios": evidence.PublicReplay.Counts.Equal, "local_replays": len(evidence.LocalReplays)}); err != nil {
		fmt.Fprintln(stderr, "refinement receipt encode failed")
		return 1
	}
	return 0
}

func readEvidence(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 16<<20 {
		return nil, errors.New("evidence must be a bounded regular file")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("evidence identity changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (16<<20)+1))
	if err != nil || len(raw) > 16<<20 {
		return nil, errors.New("evidence read exceeded bound")
	}
	return raw, nil
}

func verifyCommand(args []string, stdout, stderr io.Writer) int {
	values, err := parse(args, []string{"--repository-root", "--evidence"})
	if err != nil || !cleanAbsolute(values["--repository-root"]) || !cleanAbsolute(values["--evidence"]) || values["--evidence"] != filepath.Join(values["--repository-root"], refinement.EvidencePath) {
		fmt.Fprint(stderr, usage)
		return 64
	}
	raw, err := readEvidence(values["--evidence"])
	if err != nil {
		fmt.Fprintln(stderr, "refinement evidence read failed")
		return 1
	}
	if err := verify(values["--repository-root"], raw); err != nil {
		fmt.Fprintf(stderr, "refinement verify failed: %v\n", err)
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
	case "capture":
		return captureCommand(args[1:], stdout, stderr)
	case "verify":
		return verifyCommand(args[1:], stdout, stderr)
	default:
		fmt.Fprint(stderr, usage)
		return 64
	}
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
