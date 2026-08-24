package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "verify":
		verify(os.Args[2:])
	case "sign-owner-actions":
		signOwnerActions(os.Args[2:])
	default:
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  intakectl verify --evidence-dir DIR")
	fmt.Fprintln(output, "  intakectl sign-owner-actions --request FILE --private-key-file FILE")
}

func verify(arguments []string) {
	flags := flag.NewFlagSet("verify", flag.ExitOnError)
	directory := flags.String("evidence-dir", "evidence/intake", "directory containing the five intake evidence files")
	_ = flags.Parse(arguments)
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "verify does not accept positional arguments")
		os.Exit(2)
	}
	report, err := intake.VerifyEvidenceDir(*directory, time.Now().UTC())
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err != nil {
		_ = encoder.Encode(map[string]any{"status": "DENIED", "finding": err})
		os.Exit(1)
	}
	status := "READY"
	if len(report.Blockers) != 0 {
		status = "BLOCKED"
	}
	_ = encoder.Encode(map[string]any{"status": status, "report": report})
	if status != "READY" {
		os.Exit(1)
	}
}

func signOwnerActions(arguments []string) {
	flags := flag.NewFlagSet("sign-owner-actions", flag.ExitOnError)
	requestPath := flags.String("request", "", "public owner-action request JSON")
	privateKeyPath := flags.String("private-key-file", "", "owner-only file containing a hex-encoded Ed25519 private key")
	_ = flags.Parse(arguments)
	if flags.NArg() != 0 || *requestPath == "" || *privateKeyPath == "" {
		fmt.Fprintln(os.Stderr, "sign-owner-actions requires --request and --private-key-file and accepts no positional arguments")
		os.Exit(2)
	}
	requestData, err := readLimited(*requestPath, 1<<20)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read owner-action request")
		os.Exit(1)
	}
	var request intake.OwnerActionRequest
	if err := intake.DecodeStrict(requestData, &request); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	privateKey, err := intake.ReadExternalPrivateKey(*privateKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	actions, err := intake.BuildAndSignOwnerActions(request, privateKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(actions); err != nil {
		fmt.Fprintln(os.Stderr, "cannot write signed actions")
		os.Exit(1)
	}
}

func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("input exceeds limit")
	}
	return data, nil
}
