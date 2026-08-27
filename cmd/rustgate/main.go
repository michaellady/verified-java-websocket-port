package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

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
	if len(arguments) == 0 || arguments[0] != "verify" {
		printUsage(stderr)
		return exitUsage
	}
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *root == "" {
		printUsage(stderr)
		return exitUsage
	}
	report := rustgate.Verify(*root)
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

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: rustgate verify --root DIR")
}
