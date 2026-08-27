package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/michaellady/verified-java-websocket-port/internal/frameformal"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || arguments[0] != "verify" {
		fmt.Fprintln(stderr, "usage: frameformalctl verify --root DIR")
		return 2
	}
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	verdict, err := frameformal.Validate(context.Background(), frameformal.Request{RootPath: *root})
	encoder := json.NewEncoder(stdout)
	if err != nil {
		_ = encoder.Encode(map[string]string{"state": "ERROR", "error": err.Error()})
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
