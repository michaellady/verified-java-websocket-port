package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/securitygate"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "project root")
	accepted := flags.String("accepted-root", "", "accepted root or fixture source")
	store := flags.String("store", "", "private CAS store")
	plan := flags.String("plan", "", "relative sandbox plan")
	receipt := flags.String("receipt", "", "relative sandbox receipt")
	fixture := flags.String("fixture", "", "closed inert fixture ID")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *root == "" {
		usage(stderr)
		return 2
	}
	absoluteRoot, rootErr := filepath.Abs(*root)
	if rootErr != nil {
		_ = json.NewEncoder(stdout).Encode(struct {
			State string `json:"state"`
			Error string `json:"error"`
		}{"ERROR", "cannot resolve project root"})
		return 1
	}
	request := securitygate.Request{RootPath: absoluteRoot, CandidateRoot: *accepted, StorePath: *store, PlanPath: *plan, ReceiptPath: *receipt, FixtureID: *fixture}
	var verdict securitygate.Verdict
	var err error
	switch strings.ToLower(args[0]) {
	case "verify":
		request.Operation = securitygate.OperationVerify
		verdict, err = securitygate.Verify(context.Background(), request)
	case "ingest":
		request.Operation = securitygate.OperationIngest
		verdict, err = securitygate.Ingest(context.Background(), request)
	case "verify-sandbox":
		request.Operation = securitygate.OperationVerifySandbox
		verdict, err = securitygate.VerifySandbox(context.Background(), request)
	case "project":
		request.Operation = securitygate.OperationProject
		verdict, err = securitygate.Project(context.Background(), request)
	default:
		usage(stderr)
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err != nil {
		_ = encoder.Encode(struct {
			State string `json:"state"`
			Error string `json:"error"`
		}{"ERROR", err.Error()})
		return 1
	}
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "cannot write verdict")
		return 1
	}
	if !verdictSucceeded(verdict) {
		return 1
	}
	return 0
}

func verdictSucceeded(verdict securitygate.Verdict) bool {
	if len(verdict.Findings) != 0 {
		return false
	}
	switch verdict.State {
	case "PASS_INGESTION_COMPONENT", "PASS_SYNTHETIC_NON_CLAIM", "PASS_PROJECTION_COMPONENT":
		return true
	default:
		return false
	}
}
func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: securityctl verify|ingest|verify-sandbox|project --root ROOT [closed options]")
}
