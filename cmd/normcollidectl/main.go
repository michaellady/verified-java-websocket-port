// Command normcollidectl decides the normalization-collision catalog by
// running it, and verifies the committed audit document against that run.
//
// It NEVER predicts a verdict. Every probe is answered by executing the real
// ws-oracle-harness binary; the exit code is read from the process and a
// nonzero exit (or any stderr byte) aborts rather than being scored.
//
//	normcollidectl verify --harness <path>   recompute and refuse on drift
//	normcollidectl write  --harness <path>   regenerate the committed document
//	normcollidectl report --harness <path>   human summary, exit 1 if any
//	                                          probe is REFUTED
//
// The --harness flag is mandatory. There is no fallback that scores a run
// that did not happen.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/michaellady/verified-java-websocket-port/internal/normcollide"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	harness := flags.String("harness", os.Getenv("WS_ORACLE_HARNESS"),
		"path to the ws-oracle-harness binary (or set WS_ORACLE_HARNESS)")
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if *harness == "" {
		fmt.Fprintln(os.Stderr, "normcollidectl: --harness is required; this tool never scores a run it did not make")
		os.Exit(2)
	}
	absoluteRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "normcollidectl:", err)
		os.Exit(2)
	}
	digest, err := normcollide.FileDigest(*harness)
	if err != nil {
		fmt.Fprintln(os.Stderr, "normcollidectl: cannot digest the harness:", err)
		os.Exit(2)
	}
	runner := normcollide.HarnessRunner{Binary: filepath.Base(*harness), Digest: digest}
	// Identity() records only the base name plus the digest, so the document
	// does not embed a machine-specific path; the process still runs the
	// absolute binary the operator named.
	absoluteHarness, err := filepath.Abs(*harness)
	if err != nil {
		fmt.Fprintln(os.Stderr, "normcollidectl:", err)
		os.Exit(2)
	}
	runner.Binary = absoluteHarness
	runner.Digest = digest

	switch command {
	case "verify":
		if err := normcollide.Verify(absoluteRoot, identityStableRunner{runner}); err != nil {
			fmt.Fprintln(os.Stderr, "normcollidectl verify:", err)
			os.Exit(1)
		}
		fmt.Println("normcollidectl verify: committed audit document matches a fresh run")
	case "write":
		encoded, err := normcollide.Write(absoluteRoot, identityStableRunner{runner})
		if err != nil {
			fmt.Fprintln(os.Stderr, "normcollidectl write:", err)
			os.Exit(1)
		}
		fmt.Printf("normcollidectl write: %s (%d bytes)\n", normcollide.DocumentPath, len(encoded))
	case "report":
		_, document, err := normcollide.Recompute(absoluteRoot, identityStableRunner{runner})
		if err != nil {
			fmt.Fprintln(os.Stderr, "normcollidectl report:", err)
			os.Exit(1)
		}
		refuted := render(document)
		if refuted > 0 {
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

// identityStableRunner keeps the executed binary absolute while reporting a
// path-independent identity, so the committed document is reproducible on any
// machine. The DIGEST still pins which binary answered.
type identityStableRunner struct {
	inner normcollide.HarnessRunner
}

func (r identityStableRunner) Run(lines []string) ([]string, error) { return r.inner.Run(lines) }

func (r identityStableRunner) Identity() string {
	return "ws-oracle-harness " + r.inner.Digest
}

func render(document *normcollide.Document) int {
	fmt.Printf("normalization surface: %d projections\n", len(document.Surface))
	for _, projection := range document.Surface {
		fmt.Printf("  %-26s drops %d distinction(s), scorer compares %d field(s)\n",
			projection.ID, len(projection.Drops), len(projection.Scores))
	}
	fmt.Printf("\nprobes: %d decided (%d CONFIRMED, %d REFUTED), %d undecided candidates\n",
		document.RecomputedFrom.ProbeCount, document.RecomputedFrom.ConfirmedCount,
		document.RecomputedFrom.RefutedCount, document.RecomputedFrom.CandidateCount)
	refuted := 0
	for _, probe := range document.Probes {
		marker := "  "
		if probe.Result.Verdict == normcollide.Refuted {
			marker = "!!"
			refuted++
		}
		fmt.Printf("%s %-7s %-22s %-9s witness=%s witness_paths=%d collision_paths=%v\n",
			marker, probe.ID, probe.Projection, probe.Result.Verdict,
			probe.Result.WitnessKind, len(probe.Result.WitnessPaths), probe.Result.CollisionPaths)
	}
	fmt.Println("\ncensus:")
	for _, census := range document.Census {
		fmt.Printf("  %s: %d rows -> %d distinct scored observations; %d rows share one; largest class %d\n",
			census.Source, census.Rows, census.DistinctScoredRows,
			census.RowsSharingAnObservation, census.LargestClass)
	}
	fmt.Println("\nbound on 74/74:\n  " + document.Bounds.PublicStatement)
	fmt.Println("\nbound on 49/49:\n  " + document.Bounds.HandshakeStatement)
	fmt.Println("\nclaim: " + document.Bounds.ClaimVocabulary)
	if refuted > 0 {
		fmt.Fprintf(os.Stderr, "\n%d probe(s) REFUTED: the catalog claims a collision the surface does represent\n", refuted)
	}
	return refuted
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: normcollidectl <verify|write|report> --harness <path> [--root <dir>]")
}
