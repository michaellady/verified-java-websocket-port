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

	// The governance digest mirror is DERIVED from the same record chain and
	// written on the same path, so it cannot become a hand-maintained story
	// beside the digests the records already assert.
	manifest, err := deltaledger.BuildOwnerDecisionManifest(built.Records)
	if err != nil {
		return err
	}
	encodedManifest, err := deltaledger.EncodeOwnerDecisionManifest(manifest)
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(root, filepath.FromSlash(deltaledger.OwnerDecisionManifestRelativePath))

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
		existingManifest, err := os.ReadFile(manifestPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(existingManifest, encodedManifest) {
			return fmt.Errorf("%s does not equal the governance digest mirror derived from the record chain "+
				"(%d decision(s))", deltaledger.OwnerDecisionManifestRelativePath, len(manifest.Decisions))
		}
		// THE INTEGRITY GATE. Until this call existed, every census and
		// observation rule this repository had lived only in `_test.go` files
		// that no release or readiness path ran (review 01a0495e, BLOCKING 3),
		// and `--check` verified only that the ledger equalled its own
		// regeneration — which a wrong-but-consistent pair of artifacts passes.
		if err := deltaledger.VerifyIntegrity(root); err != nil {
			return fmt.Errorf("ledger integrity:\n%w", err)
		}
		verifiedDecisions, err := deltaledger.VerifyGovernance(root, built.Records)
		if err != nil {
			return err
		}
		fmt.Printf("ok: %s equals the regeneration (%d records, head %s, document schema %s)\n",
			deltaledger.LedgerRelativePath, len(built.Records), built.Head, deltaledger.LedgerSchemaVersion)
		fmt.Printf("ok: %s equals the chain's supersession map (%d link(s), also declared in the ledger document)\n",
			deltaledger.SupersessionsRelativePath, len(supersessions.Links))
		// THE HELD-DRAFT POPULATION, PRINTED WHERE THE RESULT IS READ. The
		// summary line below says "held proposal drafts" verified, and for as
		// long as that population was a hardcoded list of seven it said so over
		// four files nobody had classified. A derived population is only as
		// honest as its census, so every .json in the directory is named here
		// with the reason it is in or out, and every declared exemption is named
		// with the owner action that retires it. A number moving with nothing
		// said is the failure this printout exists to prevent.
		draftCensus, err := deltaledger.ClassifyProposalDrafts(root)
		if err != nil {
			return err
		}
		exemptions := deltaledger.HeldDraftExemptions()
		fmt.Printf("ok: held-draft population DERIVED from %s/ (files=%d record_proposals=%d "+
			"not_record_proposals=%d declared_exemptions=%d)\n",
			deltaledger.ProposalDraftsDir, len(draftCensus.Files), len(draftCensus.Proposals()),
			len(draftCensus.Files)-len(draftCensus.Proposals()), len(exemptions))
		for _, file := range draftCensus.Files {
			if file.RecordProposal {
				continue
			}
			fmt.Printf("     held-draft not_a_record_proposal=%s why=%q\n", file.Relative, file.Why)
		}
		for _, exemption := range exemptions {
			fmt.Printf("     held-draft exempted=%s delta_id=%s owner=%q\n",
				exemption.Relative, exemption.DeclaredDeltaID, exemption.Owner)
		}
		legacy, err := deltaledger.ReadLegacyAdjudications(root)
		if err != nil {
			return err
		}
		fmt.Printf("ok: ledger integrity verified (frozen prefix through sequence %d, ledger envelope, evidence document schemas, "+
			"observation provenance, handshake mapping census, protocol-rejection class, census evidence and ledger "+
			"binding, supersessions, adjudication, held proposal drafts, legacy-record adjudications, "+
			"unledgered_disagreements recomputed = %d, records_without_mismatch_class recomputed = %d)\n",
			deltaledger.FrozenPrefixSequence, built.UnledgeredDisagreements, built.RecordsWithoutMismatchClass)
		// TWO COUNTERS, TWO QUESTIONS, BOTH RECOMPUTED. The ledger's own
		// records_without_mismatch_class counts records with no FIELD and stays
		// at 49 because forty-nine sealed digest preimages cannot gain one;
		// records_without_ac3_class counts records that state no US-020 AC3
		// class ANYWHERE. Printing them together is deliberate: reading either
		// one alone misdescribes the chain.
		fmt.Printf("ok: %s adjudicates records 1-%d, each bound to its record by recomputed identity, record "+
			"digest and a unique verbatim rationale quote (records_without_ac3_class recomputed = %d of %d)\n",
			deltaledger.LegacyAdjudicationsRelativePath, deltaledger.PreVocabularySequence,
			legacy.RecordsWithoutAC3Class, len(built.Records))
		fmt.Printf("ok: %s equals the derivation and %d governance record digest(s) recomputed from the protected "+
			"store and matched\n", deltaledger.OwnerDecisionManifestRelativePath, verifiedDecisions)
		return nil
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(supersessionsPath, encodedSupersessions, 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(manifestPath, encodedManifest, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d records, head %s\n", deltaledger.LedgerRelativePath, len(built.Records), built.Head)
	fmt.Printf("wrote %s: %d link(s)\n", deltaledger.SupersessionsRelativePath, len(supersessions.Links))
	fmt.Printf("wrote %s: %d governance record digest(s)\n",
		deltaledger.OwnerDecisionManifestRelativePath, len(manifest.Decisions))
	fmt.Printf("unledgered_disagreements = %d\n", built.UnledgeredDisagreements)
	fmt.Printf("records_without_mismatch_class = %d of %d\n",
		built.RecordsWithoutMismatchClass, len(built.Records))
	return nil
}
