package deltaledger

// THE LEDGER INTEGRITY GATE.
//
// WHY THIS EXISTS (review BLOCKING 3). Every integrity rule this branch added
// lived only in `_test.go` files. Nothing in the release or readiness path ran
// them: rust/Makefile's `gates` target has no `go test` step, the repository has
// no root Makefile, no workflow runs Go tests, `deltaledgerctl --check` only
// compared the ledger to its regeneration, and internal/lab.VerifyBaselineEvidence
// consumed the ledger's integer without reading observations or either census.
// "The census is a gate" was therefore a claim about a test binary a future
// evidence regeneration could simply not run.
//
// VerifyIntegrity is the single entry point that runs every rule, it is
// ordinary production code, and it is called by cmd/deltaledgerctl on BOTH the
// --check and the write path. rust/Makefile's `gates` target now depends on the
// `ledger-gates` target that invokes it. The tests in this package call these
// same exported functions rather than reimplementing them, so a rule cannot be
// strong in the test binary and absent from the gate.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// FrozenPrefixSequence is the last record of the FROZEN ledger prefix, and
// FrozenPrefixHead is its record digest.
//
// The owner ruling at protected/ledger-frozen-prefix-owner-decision-2026-08-28.json
// requires, verbatim: "The frozen prefix through sequence 35 must remain
// byte-identical, verified after the append." Nothing verified it. Because the
// chain is hash-linked, pinning the ONE record digest at sequence 35 pins every
// byte of every record from 1 to 35: any change anywhere in the prefix changes
// this value.
//
// Records after sequence 35 are this branch's own appends and are NOT frozen —
// the same owner decision explicitly contemplates rebuilding them ("BOTH its
// artifacts regenerated before review or merge, since every digest tuple for
// the rebuilt records changes"), which is what licenses correcting the wrong
// RFC and Java preimages in sequences 36-48 in place rather than appending a
// third layer of corrections on top of corrections.
const (
	FrozenPrefixSequence = 35
	FrozenPrefixHead     = "sha256:3fcd461cfea72e049628a0031bfbb90addecea2f2bb6997e62280cad1962656d"
)

// The protected-store binding lives in governance.go. It used to live here as
// an opt-in recomputation that returned success whenever VJWP_PROTECTED_STORE
// was unset; round-2 finding 5 reproduced what that permitted — deleting the
// load-bearing owner decision left `make -C rust ledger-gates` at exit 0 — and
// the owner ruled MIRROR DIGESTS ONLY, with an unreachable store refused rather
// than skipped.

// VerifyFrozenPrefix enforces the owner requirement above.
func VerifyFrozenPrefix(records []lab.BehaviorLedgerRecord) error {
	if len(records) < FrozenPrefixSequence {
		return fmt.Errorf("the chain has %d records; the frozen prefix through sequence %d cannot be verified",
			len(records), FrozenPrefixSequence)
	}
	record := records[FrozenPrefixSequence-1]
	if record.Sequence != FrozenPrefixSequence {
		return fmt.Errorf("record at index %d carries sequence %d, not %d",
			FrozenPrefixSequence-1, record.Sequence, FrozenPrefixSequence)
	}
	if record.RecordDigest != FrozenPrefixHead {
		return fmt.Errorf("THE FROZEN LEDGER PREFIX CHANGED. Sequence %d now digests to %s, but the owner ruling "+
			"protected/ledger-frozen-prefix-owner-decision-2026-08-28.json requires the prefix through sequence %d to "+
			"remain byte-identical at %s. Because the chain is hash-linked, this value pins every byte of records 1-%d, "+
			"so some earlier record was rewritten. Corrections are APPENDED (or, for this branch's own records after "+
			"sequence %d, rebuilt); sealed records are never edited.",
			FrozenPrefixSequence, record.RecordDigest, FrozenPrefixSequence, FrozenPrefixHead,
			FrozenPrefixSequence, FrozenPrefixSequence)
	}
	return nil
}

// VerifyIntegrity runs every ledger integrity rule against the committed
// artifacts at root. It returns a joined error so one run reports every
// problem rather than only the first.
func VerifyIntegrity(root string) error {
	definitions := Definitions()
	committed, err := ReadCommittedLedger(root)
	if err != nil {
		return err
	}

	var failures []error
	add := func(name string, err error) {
		if err != nil {
			failures = append(failures, fmt.Errorf("[%s] %w", name, err))
		}
	}

	add("frozen-prefix", VerifyFrozenPrefix(committed.Records))
	add("evidence-document-schemas", VerifyEvidenceDocumentSchemas(root))
	add("committed-corpora-rederive", VerifyCommittedCorporaReDerive(root))
	add("live-mapping-source-binding", VerifyLiveMappingIsBoundToItsSourceTable(root))
	add("observation-provenance", VerifyObservationProvenance(root, definitions))
	add("handshake-mapping-census", VerifyHandshakeMappingCensus(root, definitions))
	add("protocol-rejection-class", VerifyProtocolRejectionClass(root, definitions))
	add("census-evidence-binding", VerifyCensusRowsMatchEvidence(root))
	add("census-ledger-coverage", VerifyCensusRowsAreLedgered(root, definitions))
	add("supersessions", VerifySupersessions(root, committed.Records))
	add("supersessions-match-definitions", VerifySupersessionsMatchDefinitions(definitions, committed.Records))
	// THE 1.2.0 DISPOSITION VOCABULARY, both halves, in the GATE rather than in
	// a test binary. adjudication.go is the rule that every record states an
	// adjudication in machine-readable form or is grandfathered by content it
	// already carries; proposal_drafts.go is the rule that the seven drafts held
	// for want of that vocabulary actually became the records their own digest
	// preimages produce.
	add("adjudication", VerifyAdjudication(committed.Records, committed.RecordsWithoutMismatchClass))
	add("proposal-drafts-ledgered", VerifyProposalDraftsAreLedgered(root, committed.Records))
	// THE FORTY-NINE THAT COULD NOT CARRY THE FIELD. VerifyAdjudication
	// grandfathers records at or before PreVocabularySequence because their
	// digest preimages cannot gain a byte; it does NOT excuse them the
	// adjudication. legacy_adjudication.go is where those forty-nine
	// attributions live and this is the call that binds each one to the record
	// it is about, by recomputed identity, by record digest, and by a verbatim
	// quote of the record's own hashed rationale.
	add("legacy-record-adjudications", VerifyLegacyAdjudications(root, committed.Records, definitions))

	// The measurement itself: recompute the published count rather than
	// trusting the stored integer, and require it to be zero at rest.
	subjects, demands, err := UnledgeredDisagreements(root, committed.Records, definitions)
	if err != nil {
		add("unledgered-disagreements", err)
	} else {
		count := len(subjects) + len(demands)
		if committed.UnledgeredDisagreements != count {
			add("unledgered-disagreements", fmt.Errorf(
				"the committed ledger publishes unledgered_disagreements=%d but the recomputation over the committed "+
					"evidence says %d", committed.UnledgeredDisagreements, count))
		}
		if count != 0 {
			var named []string
			named = append(named, subjects...)
			for _, demand := range demands {
				named = append(named, demand.String())
			}
			add("unledgered-disagreements", fmt.Errorf(
				"%d observed disagreement(s) have no ledger record:\n    %s", count, strings.Join(named, "\n    ")))
		}
	}

	if _, err := VerifyGovernance(root, committed.Records); err != nil {
		add("governance", err)
	}

	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	return nil
}
