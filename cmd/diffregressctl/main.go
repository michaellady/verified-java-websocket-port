// Command diffregressctl generates the corpus-invisible differential probe
// requests and compares two oracle transcripts field-by-field.
//
// It never produces a Java-side result: the Java arm is only ever recorded by
// executing the real pinned oracle. This tool emits requests and compares
// recorded transcripts, nothing else.
//
// Usage:
//
//	diffregressctl gen-probes --out probes.jsonl
//	diffregressctl compare --java java.jsonl --rust rust.jsonl [--out summary.json]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/michaellady/verified-java-websocket-port/internal/diffregress"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: diffregressctl <gen-probes|compare> [flags]")
	}
	switch os.Args[1] {
	case "gen-probes":
		genProbes(os.Args[2:])
	case "compare":
		compare(os.Args[2:])
	case "manifest":
		manifest(os.Args[2:])
	default:
		fail("unknown subcommand %q", os.Args[1])
	}
}

func genProbes(args []string) {
	flags := flag.NewFlagSet("gen-probes", flag.ExitOnError)
	out := flags.String("out", "", "destination JSONL path (required)")
	if err := flags.Parse(args); err != nil {
		fail("%v", err)
	}
	if *out == "" {
		fail("--out is required")
	}
	data, err := diffregress.RequestsJSONL()
	if err != nil {
		fail("generate probes: %v", err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fail("write %s: %v", *out, err)
	}
	fmt.Printf("wrote %d probe requests to %s\n", len(diffregress.Catalog()), *out)
}

func compare(args []string) {
	flags := flag.NewFlagSet("compare", flag.ExitOnError)
	javaPath := flags.String("java", "", "recorded Java arm transcript (required)")
	rustPath := flags.String("rust", "", "Rust arm transcript (required)")
	out := flags.String("out", "", "optional JSON summary destination")
	if err := flags.Parse(args); err != nil {
		fail("%v", err)
	}
	if *javaPath == "" || *rustPath == "" {
		fail("--java and --rust are required")
	}
	summary, err := diffregress.CompareTranscripts(*javaPath, *rustPath)
	if err != nil {
		fail("compare: %v", err)
	}
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		fail("encode summary: %v", err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, append(encoded, '\n'), 0o644); err != nil {
			fail("write %s: %v", *out, err)
		}
	}
	fmt.Println(summary.String())
	// A behavioral divergence is a non-zero exit so a caller reading only the
	// exit status still cannot mistake divergence for agreement.
	if summary.Divergent > 0 {
		os.Exit(1)
	}
}

func manifest(args []string) {
	flags := flag.NewFlagSet("manifest", flag.ExitOnError)
	dir := flags.String("dir", "", "directory holding probes.jsonl, java-arm.jsonl, rust-arm.jsonl (required)")
	recordedAt := flags.String("recorded-at", "", "UTC timestamp captured at write time (required)")
	recordedAtSource := flags.String("recorded-at-provenance", "", "how the timestamp was captured (required)")
	head := flags.String("head", "", "repo head the Rust arm was built from (required)")
	provenanceJSON := flags.String("provenance", "{}", "JSON object of provenance strings")
	oracleJSON := flags.String("oracle-identity", "{}", "JSON object of verified oracle identity digests")
	if err := flags.Parse(args); err != nil {
		fail("%v", err)
	}
	for name, value := range map[string]string{
		"--dir": *dir, "--recorded-at": *recordedAt,
		"--recorded-at-provenance": *recordedAtSource, "--head": *head,
	} {
		if value == "" {
			fail("%s is required", name)
		}
	}
	var provenance, oracle map[string]string
	if err := json.Unmarshal([]byte(*provenanceJSON), &provenance); err != nil {
		fail("--provenance: %v", err)
	}
	if err := json.Unmarshal([]byte(*oracleJSON), &oracle); err != nil {
		fail("--oracle-identity: %v", err)
	}
	built, err := diffregress.BuildManifest(*dir, *recordedAt, *recordedAtSource, *head, provenance, oracle)
	if err != nil {
		fail("build manifest: %v", err)
	}
	encoded, err := built.Encode()
	if err != nil {
		fail("encode manifest: %v", err)
	}
	destination := filepath.Join(*dir, diffregress.ManifestFile)
	if err := os.WriteFile(destination, encoded, 0o644); err != nil {
		fail("write %s: %v", destination, err)
	}
	fmt.Printf("wrote %s: %d probes, %d behaviorally divergent\n",
		destination, built.Counts["probes"], built.Counts["behaviorally_divergent"])
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
