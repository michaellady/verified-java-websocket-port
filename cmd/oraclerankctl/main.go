// Command oraclerankctl makes US-020 AC2's oracle hierarchy executable over
// this repository's committed evidence.
//
// Usage: oraclerankctl --root <repository-root> [--check]
//
// Without --check it recomputes and writes the adjudication register. With
// --check it writes nothing, recomputes the register from the evidence, refuses
// any difference from the committed bytes, and then checks the adjudication
// rules themselves: that every Java/Rust agreement a higher oracle overrides is
// enrolled, that no enrolled entry is unexhibited, that the guarded parity
// reading refuses on every overridden agreement, and that the pure
// rank-four-against-rank-five family exhibits no override at all.
//
// The committed register is never an input to the recomputation, so --check
// cannot pass by reading itself.
//
// Exit codes: 0 pass, 1 a check failed, 2 usage.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/michaellady/verified-java-websocket-port/internal/oraclerank"
)

func main() {
	root := flag.String("root", "", "repository root")
	check := flag.Bool("check", false, "verify the committed register and the adjudication rules instead of writing")
	flag.Parse()

	if *root == "" {
		fmt.Fprintln(os.Stderr, "oraclerankctl: --root is required")
		os.Exit(2)
	}

	if *check {
		if err := oraclerank.Verify(*root); err != nil {
			fmt.Fprintf(os.Stderr, "oraclerankctl: %v\n", err)
			os.Exit(1)
		}
		if err := oraclerank.VerifyRules(*root); err != nil {
			fmt.Fprintf(os.Stderr, "oraclerankctl: %v\n", err)
			os.Exit(1)
		}
		reg, _, err := oraclerank.Recompute(*root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "oraclerankctl: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("oraclerankctl: %d propositions adjudicated; %d Java/Rust agreements, %d of them overridden by a higher oracle and every one enrolled in %s\n",
			reg.Accounting.Propositions, reg.Accounting.JavaRustConsensus,
			reg.Accounting.JavaRustConsensusOverride, oraclerank.RegisterPath)
		return
	}

	encoded, err := oraclerank.Write(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oraclerankctl: %v\n", err)
		os.Exit(1)
	}
	reg, _, err := oraclerank.Recompute(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oraclerankctl: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("oraclerankctl: wrote %s (%d bytes); %d propositions, %d Java/Rust agreements, %d overridden by a higher oracle\n",
		oraclerank.RegisterPath, len(encoded), reg.Accounting.Propositions,
		reg.Accounting.JavaRustConsensus, reg.Accounting.JavaRustConsensusOverride)
}
