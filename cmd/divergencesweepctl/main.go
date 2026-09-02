// Command divergencesweepctl recomputes the Java-versus-port close divergence
// sweep from the committed native x86_64 Autobahn run reports and either
// writes the evidence document (evidence/java/observed-close-divergences.json)
// or verifies the committed one against the reports.
//
// Usage: divergencesweepctl --root <repository-root> [--check]
//
// With --check it writes nothing and exits nonzero when the committed document
// does not equal the recomputation. The committed document is never an input to
// the recomputation, so --check cannot pass by reading itself.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/michaellady/verified-java-websocket-port/internal/divergencesweep"
)

func main() {
	root := flag.String("root", "", "repository root")
	check := flag.Bool("check", false, "verify the committed document instead of writing it")
	flag.Parse()
	if *root == "" {
		fmt.Fprintln(os.Stderr, "divergencesweepctl: --root is required")
		os.Exit(2)
	}
	if *check {
		if err := divergencesweep.Verify(*root); err != nil {
			fmt.Fprintf(os.Stderr, "divergencesweepctl: %v\n", err)
			os.Exit(1)
		}
		_, document, err := divergencesweep.Recompute(*root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "divergencesweepctl: %v\n", err)
			os.Exit(1)
		}
		if err := divergencesweep.VerifyProposals(*root, document); err != nil {
			fmt.Fprintf(os.Stderr, "divergencesweepctl: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("divergencesweepctl: the committed document and every ledger-proposal draft agree with the run reports")
		return
	}
	encoded, err := divergencesweep.Write(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "divergencesweepctl: %v\n", err)
		os.Exit(1)
	}
	_, document, err := divergencesweep.Recompute(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "divergencesweepctl: %v\n", err)
		os.Exit(1)
	}
	drafts, err := divergencesweep.WriteProposals(*root, document)
	if err != nil {
		fmt.Fprintf(os.Stderr, "divergencesweepctl: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("divergencesweepctl: wrote %s (%d bytes) and %d ledger-proposal drafts; %d differences, %d claimed, %d unclaimed, %d classes\n",
		divergencesweep.DocumentPath, len(encoded), len(drafts),
		document.Accounting.TotalDifferences, document.Accounting.ClaimedByAClass,
		document.Accounting.Unclaimed, len(document.Classes))
}
