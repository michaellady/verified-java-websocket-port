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
//	                                          probe's verdict disagrees with the
//	                                          one it declared, or any premise
//	                                          of the emptiness argument fails
//
// A REFUTED verdict is NOT a failure when the probe declared it. Two probes in
// the catalog exist to be refuted: they decide candidates by showing the
// observation DOES carry a distinction. What is a failure is disagreement
// between the declaration and the run, in either direction.
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
		unexpected := render(document)
		if unexpected > 0 {
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

// render prints the document and returns the number of DISAGREEMENTS between
// what the catalog declared and what the run produced. It is not "the number
// of refutations": two probes are SUPPOSED to be refuted, and reporting those
// as failures would make the refutation catalog unusable. What counts as a
// failure is a probe whose verdict is not the one it declared, or a premise
// that stopped holding.
func render(document *normcollide.Document) int {
	fmt.Printf("normalization surface: %d projections\n", len(document.Surface))
	for _, projection := range document.Surface {
		fmt.Printf("  %-26s drops %d distinction(s), scorer compares %d field(s)\n",
			projection.ID, len(projection.Drops), len(projection.Scores))
	}
	fmt.Printf("\nprobes: %d decided (%d CONFIRMED, %d REFUTED); candidates: %d decided, %d still undecided (%d at first pass)\n",
		document.RecomputedFrom.ProbeCount, document.RecomputedFrom.ConfirmedCount,
		document.RecomputedFrom.RefutedCount, document.RecomputedFrom.DecidedCandidateCount,
		document.RecomputedFrom.CandidateCount, document.RecomputedFrom.CandidateFirstPassCount)
	unexpected := 0
	fmt.Println("\ncollision probes (expected CONFIRMED):")
	unexpected += renderProbes(document.Probes)
	fmt.Println("\nrefutation probes (expected REFUTED — the observation DOES carry these):")
	unexpected += renderProbes(document.Refutations)

	fmt.Printf("\ncandidate emptiness %s -> %s\n",
		document.Utf8Emptiness.ID, document.Utf8Emptiness.Status)
	for _, premise := range document.Utf8Emptiness.Premises {
		marker := "  "
		if !premise.Holds {
			marker = "!!"
			unexpected++
		}
		fmt.Printf("%s %-24s %-6s holds=%t  %s\n",
			marker, premise.ID, premise.Kind, premise.Holds, clipLine(premise.Evidence))
	}

	fmt.Println("\ndecided candidates:")
	for _, candidate := range document.DecidedCandidates {
		fmt.Printf("   %-16s %-10s decided_by %s\n", candidate.ID, candidate.Status, candidate.DecidedBy)
	}
	fmt.Println("\nstill undecided (HYPOTHESIS):")
	for _, candidate := range document.Candidates {
		fmt.Printf("   %-16s %s\n", candidate.ID, candidate.Status)
	}

	fmt.Println("\ncensus:")
	for _, census := range document.Census {
		fmt.Printf("  %s: %d rows -> %d distinct scored observations; %d rows share one; largest class %d\n",
			census.Source, census.Rows, census.DistinctScoredRows,
			census.RowsSharingAnObservation, census.LargestClass)
	}
	fmt.Println("\nbound on 74/74:\n  " + document.Bounds.PublicStatement)
	fmt.Println("\nbound on 49/49:\n  " + document.Bounds.HandshakeStatement)
	fmt.Println("\nwhat the refutations do to those ceilings:\n  " + document.Bounds.RefutationStatement)
	fmt.Println("\nclaim: " + document.Bounds.ClaimVocabulary)
	if unexpected > 0 {
		fmt.Fprintf(os.Stderr, "\n%d probe(s) or premise(s) did not match what the catalog declared\n", unexpected)
	}
	return unexpected
}

// renderProbes prints one catalog and returns how many members disagreed with
// their own declared expectation.
func renderProbes(probes []normcollide.ProbeDoc) int {
	unexpected := 0
	for _, probe := range probes {
		marker := "  "
		if probe.Result.Verdict != probe.Expect {
			marker = "!!"
			unexpected++
		}
		fmt.Printf("%s %-7s %-22s want=%-9s got=%-9s witness=%s witness_paths=%d collision_paths=%v\n",
			marker, probe.ID, probe.Projection, probe.Expect, probe.Result.Verdict,
			probe.Result.WitnessKind, len(probe.Result.WitnessPaths), probe.Result.CollisionPaths)
	}
	return unexpected
}

func clipLine(text string) string {
	if len(text) > 150 {
		return text[:150] + "..."
	}
	return text
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: normcollidectl <verify|write|report> --harness <path> [--root <dir>]")
}
