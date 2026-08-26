package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/portplan"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "study-surface":
		return runStudySurface(arguments[1:], stdout, stderr)
	case "derive":
		return runDerive(arguments[1:], stdout, stderr)
	case "verify":
		return runVerify(arguments[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return 2
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  portplanctl study-surface --source-root DIR --out FILE")
	fmt.Fprintln(output, "  portplanctl derive --root DIR --production-root DIR --test-root DIR --oracle FILE --oracle-tool FILE")
	fmt.Fprintln(output, "  portplanctl verify --root DIR")
}

func runStudySurface(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("study-surface", flag.ContinueOnError)
	flags.SetOutput(stderr)
	sourceRoot := flags.String("source-root", "", "Java production source root")
	outPath := flags.String("out", "", "output list path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *sourceRoot == "" {
		return 2
	}
	paths, err := portplan.ListJavaSources(*sourceRoot)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	selection := portplan.SelectStudySurface(paths)
	body := strings.Join(selection.Selected, "\n") + "\n"
	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(body), 0o644); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	totals, err := portplan.CountTree(*sourceRoot, paths)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	selectedTotals, err := portplan.CountTree(*sourceRoot, selection.Selected)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "production files=%d lines=%d\n", totals.Files, totals.Lines)
	fmt.Fprintf(stdout, "study files=%d lines=%d\n", selectedTotals.Files, selectedTotals.Lines)
	fmt.Fprintf(stdout, "excluded files=%d\n", len(selection.Excluded))
	return 0
}

func runDerive(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("derive", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	productionRoot := flags.String("production-root", "", "Java production source root")
	testRoot := flags.String("test-root", "", "Java test source root")
	oracle := flags.String("oracle", "", "semantic identity oracle output")
	oracleTool := flags.String("oracle-tool", "", "semantic identity oracle source file")
	sourceSHA := flags.String("source-sha256", "", "pinned source archive digest")
	sourceCommit := flags.String("source-commit", "", "pinned upstream commit")
	sourceVersion := flags.String("source-version", "1.6.0", "pinned upstream version")
	rfcSHA := flags.String("rfc6455-sha256", "", "pinned RFC 6455 text digest")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *productionRoot == "" || *testRoot == "" || *oracle == "" || *oracleTool == "" {
		printUsage(stderr)
		return 2
	}
	request := portplan.DeriveRequest{
		Root:                 *root,
		ProductionSourceRoot: *productionRoot,
		TestSourceRoot:       *testRoot,
		OraclePath:           *oracle,
		OracleToolPath:       *oracleTool,
		SourceArtifactID:     "java-websocket-source-archive",
		SourceSHA256:         *sourceSHA,
		SourceVersion:        *sourceVersion,
		SourceCommit:         *sourceCommit,
		RFC6455SHA256:        *rfcSHA,
	}
	if err := portplan.Derive(request); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "derived", len(portplan.DocumentNames), "intake documents")
	return 0
}

func runVerify(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	report, err := portplan.Verify(*root)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !report.OK {
		return 1
	}
	return 0
}
