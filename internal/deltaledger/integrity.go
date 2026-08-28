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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// ProtectedStoreEnv names the environment variable that points at the workspace
// orchestrator's immutable protected store. When it is set, VerifyIntegrity
// RECOMPUTES the sha256 of every owner decision the ledger cites, instead of
// merely quoting it.
const ProtectedStoreEnv = "VJWP_PROTECTED_STORE"

// citedOwnerDecisions are the protected-store artifacts whose digests the
// ledger's hashed preimages assert. When the protected store is reachable, each
// is recomputed and must match.
var citedOwnerDecisions = map[string]string{
	"ledger-frozen-prefix-owner-decision-2026-08-28.json":   "bb3cd0da7f4aed014290dab3dc35b2ec87f41d3d7e7a8c7449816159e9d837c7",
	"us010-016-ac-amendment-owner-decision-2026-08-27.json": "26849b5ea74006504d18507ac694c00e882e7fd37d4cd8c8502ea824e96ea974",
}

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

// VerifyCitedOwnerDecisions recomputes the sha256 of each cited owner decision
// when the protected store is reachable.
//
// DISCLOSED RESIDUE: when the store is not reachable — which is the normal case
// in a fresh worktree, since the protected store is deliberately outside this
// repository — the digests are quoted and not recomputed, and deleting the
// external file fails no check on this branch. Closing that gap requires an
// owner ruling on whether governance artifacts may be mirrored into the
// repository; it is escalated rather than decided here.
func VerifyCitedOwnerDecisions() (checked int, err error) {
	store := strings.TrimSpace(os.Getenv(ProtectedStoreEnv))
	if store == "" {
		return 0, nil
	}
	var problems []string
	for name, want := range citedOwnerDecisions {
		path := filepath.Join(store, name)
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			problems = append(problems, fmt.Sprintf("%s: cited by the ledger but not readable in %s=%s: %v",
				name, ProtectedStoreEnv, store, readErr))
			continue
		}
		sum := sha256.Sum256(raw)
		got := hex.EncodeToString(sum[:])
		if got != want {
			problems = append(problems, fmt.Sprintf("%s: the ledger's hashed preimages assert sha256 %s, the file is %s",
				name, want, got))
			continue
		}
		checked++
	}
	if len(problems) != 0 {
		return checked, fmt.Errorf("cited owner decisions (%d problem(s)):\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	return checked, nil
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
	add("observation-provenance", VerifyObservationProvenance(root))
	add("handshake-mapping-census", VerifyHandshakeMappingCensus(root, definitions))
	add("protocol-rejection-class", VerifyProtocolRejectionClass(root))
	add("census-evidence-binding", VerifyCensusRowsMatchEvidence(root))
	add("census-ledger-coverage", VerifyCensusRowsAreLedgered(root, definitions))
	add("supersessions", VerifySupersessions(root, committed.Records))

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

	if _, err := VerifyCitedOwnerDecisions(); err != nil {
		add("owner-decisions", err)
	}

	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	return nil
}
