package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/assurance"
	"github.com/michaellady/verified-java-websocket-port/internal/formal"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now().UTC()))
}

func run(arguments []string, stdout, stderr io.Writer, now time.Time) int {
	_ = now
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "verify":
		return runMode(arguments[1:], stdout, stderr, assurance.ModeVerify)
	case "replay":
		return runMode(arguments[1:], stdout, stderr, assurance.ModeReplay)
	case "candidate-verify":
		return runCandidate(arguments[1:], stdout, stderr, assurance.CandidateVerify)
	case "candidate-replay":
		return runCandidate(arguments[1:], stdout, stderr, assurance.CandidateReplay)
	case "formal-preflight":
		return runFormal(arguments[1:], stdout, stderr, formal.ModePreflight)
	case "formal-replay":
		return runFormal(arguments[1:], stdout, stderr, formal.ModeReplay)
	default:
		printUsage(stderr)
		return 2
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  assurectl verify --root DIR --lifecycle assurance/lifecycle.json")
	fmt.Fprintln(output, "  assurectl replay --root DIR --lifecycle assurance/lifecycle.json")
	fmt.Fprintln(output, "  assurectl formal-preflight --root DIR")
	fmt.Fprintln(output, "  assurectl formal-replay --root DIR")
	fmt.Fprintln(output, "  assurectl candidate-verify --root ABS")
	fmt.Fprintln(output, "  assurectl candidate-replay --root ABS")
}

func runCandidate(arguments []string, stdout, stderr io.Writer, mode assurance.CandidateMode) int {
	if len(arguments) != 2 || arguments[0] != "--root" || arguments[1] == "" {
		printUsage(stderr)
		return 2
	}
	verdict, err := assurance.EvaluateCandidate(context.Background(), assurance.CandidateRequest{RootPath: arguments[1], Mode: mode})
	encoder := json.NewEncoder(stdout)
	if err != nil {
		_ = encoder.Encode(map[string]any{"snapshot_state": "INVALID", "error": err.Error()})
		return 1
	}
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "cannot write candidate verdict")
		return 1
	}
	if verdict.SnapshotState != "FROZEN" || len(verdict.Findings) != 0 {
		return 1
	}
	return 0
}

func runFormal(arguments []string, stdout, stderr io.Writer, mode string) int {
	flags := flag.NewFlagSet(strings.ToLower(mode), flag.ContinueOnError)
	flags.SetOutput(stderr)
	rootPath := flags.String("root", ".", "project root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	verdict, err := formal.Validate(context.Background(), formal.Request{RootPath: *rootPath, Mode: mode})
	encoder := json.NewEncoder(stdout)
	if err != nil {
		_ = encoder.Encode(map[string]any{"state": "ERROR", "error": err.Error()})
		return 1
	}
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "cannot write verdict")
		return 1
	}
	if !verdict.Valid {
		return 1
	}
	return 0
}

func runMode(arguments []string, stdout, stderr io.Writer, mode string) int {
	flags := flag.NewFlagSet(strings.ToLower(mode), flag.ContinueOnError)
	flags.SetOutput(stderr)
	rootPath := flags.String("root", ".", "project root")
	lifecyclePath := flags.String("lifecycle", "assurance/lifecycle.json", "relative lifecycle JSON path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	request := assurance.Request{RootPath: *rootPath, LifecyclePath: *lifecyclePath, Mode: mode}
	var (
		verdict assurance.Verdict
		err     error
	)
	if mode == assurance.ModeVerify {
		verdict, err = assurance.Verify(context.Background(), request)
	} else {
		verdict, err = assurance.Replay(context.Background(), request)
	}
	encoder := json.NewEncoder(stdout)
	if err != nil {
		_ = encoder.Encode(map[string]any{"state": "ERROR", "error": err.Error()})
		return 1
	}
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "cannot write verdict")
		return 1
	}
	if len(verdict.Findings) != 0 {
		return 1
	}
	return 0
}
