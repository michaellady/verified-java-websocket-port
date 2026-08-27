// Command deltaledgerctl regenerates the committed behavior-delta ledger
// evidence document (evidence/java/behavior-delta-ledger.json) from the
// recorded divergence definitions in internal/deltaledger, appending every
// record through the canonical hash-chained CAS implementation in
// internal/lab. It preserves the committed envelope (accepted root digest and
// status) and is deterministic: rerunning it reproduces the same bytes.
//
// Usage: deltaledgerctl --root <repository-root> [--check]
//
// With --check it writes nothing and exits nonzero when the committed
// document does not equal the regeneration.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/michaellady/verified-java-websocket-port/internal/deltaledger"
)

func main() {
	root := flag.String("root", "", "repository root")
	check := flag.Bool("check", false, "verify the committed ledger instead of writing it")
	flag.Parse()
	if *root == "" {
		fmt.Fprintln(os.Stderr, "deltaledgerctl: --root is required")
		os.Exit(2)
	}
	if err := run(*root, *check); err != nil {
		fmt.Fprintf(os.Stderr, "deltaledgerctl: %v\n", err)
		os.Exit(1)
	}
}

func run(root string, check bool) error {
	committed, err := deltaledger.ReadCommittedLedger(root)
	if err != nil {
		return err
	}
	built, err := deltaledger.BuildLedgerFile(committed)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(built, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	path := filepath.Join(root, filepath.FromSlash(deltaledger.LedgerRelativePath))
	if check {
		existing, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, encoded) {
			return fmt.Errorf("%s does not equal the deterministic regeneration (%d records, head %s)",
				deltaledger.LedgerRelativePath, len(built.Records), built.Head)
		}
		fmt.Printf("ok: %s equals the regeneration (%d records, head %s)\n",
			deltaledger.LedgerRelativePath, len(built.Records), built.Head)
		return nil
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d records, head %s\n", deltaledger.LedgerRelativePath, len(built.Records), built.Head)
	return nil
}
