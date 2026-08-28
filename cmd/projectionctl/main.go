package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/michaellady/verified-java-websocket-port/internal/projection"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		fmt.Fprintln(stderr, "usage: projectionctl capture|verify --root ABSOLUTE_REPOSITORY_ROOT")
		return exitUsage
	}
	command := arguments[0]
	if command != "capture" && command != "verify" {
		fmt.Fprintf(stderr, "unknown command %q\n", command)
		return exitUsage
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "absolute repository root")
	if err := flags.Parse(arguments[1:]); err != nil || *root == "" || flags.NArg() != 0 {
		return exitUsage
	}
	var (
		summary projection.Summary
		err     error
	)
	if command == "capture" {
		summary, err = projection.Capture(*root)
	} else {
		summary, err = projection.Verify(*root)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	fmt.Fprintln(stdout, string(encoded))
	return exitOK
}
