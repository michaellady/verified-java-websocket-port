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
	regenerateObservations := flag.Bool("regenerate-observations", false,
		"deliberately refreeze evidence/java/observed-disagreements.json from the recorded definitions")
	flag.Parse()
	if *root == "" {
		fmt.Fprintln(os.Stderr, "deltaledgerctl: --root is required")
		os.Exit(2)
	}
	if *regenerateObservations {
		if err := regenerateObservationSet(*root); err != nil {
			fmt.Fprintf(os.Stderr, "deltaledgerctl: %v\n", err)
			os.Exit(1)
		}
	}
	if err := run(*root, *check); err != nil {
		fmt.Fprintf(os.Stderr, "deltaledgerctl: %v\n", err)
		os.Exit(1)
	}
}

// regenerateObservationSet refreezes the committed observed-disagreement set
// from the recorded definitions. It is behind an explicit flag on purpose: the
// gate's whole value is that the committed observations OUTLIVE a record's
// removal, so silently regenerating them would restore the fake-gate behavior
// this artifact exists to prevent.
func regenerateObservationSet(root string) error {
	existing, err := deltaledger.ReadObservations(root)
	if err != nil {
		return err
	}
	built, err := deltaledger.BuildObservationSet(existing)
	if err != nil {
		return err
	}
	encoded, err := deltaledger.EncodeObservations(built)
	if err != nil {
		return err
	}
	path := filepath.Join(root, filepath.FromSlash(deltaledger.ObservationsRelativePath))
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d observations\n", deltaledger.ObservationsRelativePath, len(built.Observed))
	return nil
}

func run(root string, check bool) error {
	committed, err := deltaledger.ReadCommittedLedger(root)
	if err != nil {
		return err
	}
	built, err := deltaledger.BuildLedgerFile(root, committed)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(built, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	path := filepath.Join(root, filepath.FromSlash(deltaledger.LedgerRelativePath))

	supersessions, err := deltaledger.BuildSupersessionsDocument(built.Records)
	if err != nil {
		return err
	}
	encodedSupersessions, err := deltaledger.EncodeSupersessions(supersessions)
	if err != nil {
		return err
	}
	supersessionsPath := filepath.Join(root, filepath.FromSlash(deltaledger.SupersessionsRelativePath))

	if check {
		existing, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, encoded) {
			return fmt.Errorf("%s does not equal the deterministic regeneration (%d records, head %s)",
				deltaledger.LedgerRelativePath, len(built.Records), built.Head)
		}
		existingSupersessions, err := os.ReadFile(supersessionsPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(existingSupersessions, encodedSupersessions) {
			return fmt.Errorf("%s does not equal the supersession map carried by the record chain (%d link(s))",
				deltaledger.SupersessionsRelativePath, len(supersessions.Links))
		}
		// THE INTEGRITY GATE. Until this call existed, every census and
		// observation rule this repository had lived only in `_test.go` files
		// that no release or readiness path ran (review 01a0495e, BLOCKING 3),
		// and `--check` verified only that the ledger equalled its own
		// regeneration — which a wrong-but-consistent pair of artifacts passes.
		if err := deltaledger.VerifyIntegrity(root); err != nil {
			return fmt.Errorf("ledger integrity:\n%w", err)
		}
		checkedDecisions, err := deltaledger.VerifyCitedOwnerDecisions()
		if err != nil {
			return err
		}
		fmt.Printf("ok: %s equals the regeneration (%d records, head %s)\n",
			deltaledger.LedgerRelativePath, len(built.Records), built.Head)
		fmt.Printf("ok: %s equals the chain's supersession map (%d link(s))\n",
			deltaledger.SupersessionsRelativePath, len(supersessions.Links))
		fmt.Printf("ok: ledger integrity verified (frozen prefix through sequence %d, observation provenance, "+
			"handshake mapping census, protocol-rejection class, census evidence and ledger binding, supersessions, "+
			"unledgered_disagreements recomputed = %d)\n",
			deltaledger.FrozenPrefixSequence, built.UnledgeredDisagreements)
		if checkedDecisions == 0 {
			fmt.Printf("note: cited owner-decision digests were NOT recomputed; set %s to the workspace "+
				"orchestrator protected store to recompute them\n", deltaledger.ProtectedStoreEnv)
		} else {
			fmt.Printf("ok: %d cited owner-decision digest(s) recomputed and matched\n", checkedDecisions)
		}
		return nil
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(supersessionsPath, encodedSupersessions, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d records, head %s\n", deltaledger.LedgerRelativePath, len(built.Records), built.Head)
	fmt.Printf("wrote %s: %d link(s)\n", deltaledger.SupersessionsRelativePath, len(supersessions.Links))
	fmt.Printf("unledgered_disagreements = %d\n", built.UnledgeredDisagreements)
	return nil
}
