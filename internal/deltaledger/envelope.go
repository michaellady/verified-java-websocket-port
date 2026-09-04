package deltaledger

// THE TWO ENVELOPE FIELDS THE REGENERATION COPIED FROM THE FILE IT VERIFIES.
//
// ROUND-3 FINDINGS L1 AND L2. `deltaledgerctl --check` builds the ledger
// document with `built := existing` and then overwrites the fields it
// derives: $schema, schema_version, head, records, supersessions,
// unledgered_disagreements, records_without_mismatch_class. Seven fields are
// NOT overwritten and are therefore compared to themselves:
//
//	evidence_kind  normative_authority  append_implementation
//	production     publication          accepted_root_digest  status
//
// The first five are pinned to `const` values by
// schemas/behavior-delta-ledger-1.2.0.schema.json, which
// VerifyEvidenceDocumentSchemas checks, so editing one is refused (flipping
// `production` to true is `at '/production': value must be false`). The last
// two are not:
//
//   - `status` is a two-value enum in the schema, so BLOCKED_PENDING_BASELINE
//     could be rewritten to READY. Every one of the gate's five census lines
//     was byte-identical and it exited 0. The flip is not cosmetic:
//     internal/formalplan/concurrency.go:546 reads this field and only
//     DEMANDS that the plan record the append as blocked while it says
//     BLOCKED_PENDING_BASELINE, so the ledger's self-declaration switches a
//     downstream check off.
//   - `accepted_root_digest` is constrained only to the SHAPE of a digest, so
//     it was rewritten to sixty-four zeroes at exit 0 with the census
//     unmoved, while eight sibling documents under evidence/java/ and two
//     schemas carry the real accepted root as a `const`.
//
// Both are now RE-DERIVED from committed artifacts rather than inherited.
// Neither derivation introduces a constant: the root comes from the sibling
// evidence documents, and the status comes from the Autobahn baseline the
// ledger's own build comment already names as the thing that decides it.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AutobahnBaselineRelativePath is the committed baseline whose status decides
// whether the ledger may declare itself READY.
const AutobahnBaselineRelativePath = "evidence/java/autobahn-baseline.json"

// LedgerStatusBlocked and LedgerStatusReady are the ledger document's two
// legal status values.
const (
	LedgerStatusBlocked = "BLOCKED_PENDING_BASELINE"
	LedgerStatusReady   = "READY"
)

// evidenceEnvelopeFields is the subset of any evidence document this file
// reads. Documents that carry no accepted_root_digest are skipped.
type evidenceEnvelopeFields struct {
	AcceptedRootDigest string `json:"accepted_root_digest"`
	Status             string `json:"status"`
}

// AcceptedRootFromSiblings re-derives the accepted root digest that the
// committed evidence documents under evidence/java/ agree on, EXCLUDING the
// ledger itself so the ledger can never be its own authority. It fails when
// the siblings disagree, because then there is no single accepted root to
// bind the ledger to and picking one would be a choice this gate is not
// entitled to make.
func AcceptedRootFromSiblings(root string) (string, error) {
	dir := filepath.Join(root, "evidence", "java")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", dir, err)
	}
	roots := map[string][]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		rel := "evidence/java/" + entry.Name()
		if rel == LedgerRelativePath {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return "", fmt.Errorf("read %s: %w", rel, err)
		}
		var envelope evidenceEnvelopeFields
		if err := json.Unmarshal(raw, &envelope); err != nil {
			continue // not an envelope-shaped document; not this rule's business
		}
		if envelope.AcceptedRootDigest == "" {
			continue
		}
		roots[envelope.AcceptedRootDigest] = append(roots[envelope.AcceptedRootDigest], rel)
	}
	if len(roots) == 0 {
		return "", fmt.Errorf("no committed document under evidence/java/ other than the ledger carries an accepted_root_digest, so the ledger's own value is bound to nothing")
	}
	if len(roots) > 1 {
		var lines []string
		for digest, docs := range roots {
			sort.Strings(docs)
			lines = append(lines, fmt.Sprintf("%s in %s", digest, strings.Join(docs, ", ")))
		}
		sort.Strings(lines)
		return "", fmt.Errorf("the committed evidence documents under evidence/java/ do not agree on one accepted root: %s", strings.Join(lines, "; "))
	}
	for digest := range roots {
		return digest, nil
	}
	return "", nil
}

// VerifyLedgerEnvelope re-derives the ledger document's two free envelope
// fields.
func VerifyLedgerEnvelope(root string, committed LedgerFile) error {
	var failures []string

	derivedRoot, err := AcceptedRootFromSiblings(root)
	if err != nil {
		failures = append(failures, err.Error())
	} else if committed.AcceptedRootDigest != derivedRoot {
		failures = append(failures, fmt.Sprintf(
			"%s declares accepted_root_digest %s, but every other committed evidence document under evidence/java/ binds %s. "+
				"This field is COPIED into the regeneration, so it equals itself on every run; the sibling documents are what it is bound to",
			LedgerRelativePath, committed.AcceptedRootDigest, derivedRoot))
	}

	baselineRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(AutobahnBaselineRelativePath)))
	if err != nil {
		failures = append(failures, fmt.Sprintf("%s cannot be read, so the ledger's status is bound to nothing: %v", AutobahnBaselineRelativePath, err))
	} else {
		var baseline evidenceEnvelopeFields
		if err := json.Unmarshal(baselineRaw, &baseline); err != nil {
			failures = append(failures, fmt.Sprintf("%s does not decode: %v", AutobahnBaselineRelativePath, err))
		} else {
			want := LedgerStatusBlocked
			if baseline.Status == "PASS" {
				want = LedgerStatusReady
			}
			if committed.Status != want {
				failures = append(failures, fmt.Sprintf(
					"%s declares status %q, but %s is status %q, so the ledger's status must be %q. "+
						"The ledger's aggregate READY gate requires the Autobahn baseline to be PASS; this field is COPIED into the "+
						"regeneration and so cannot be caught by comparing the document to its own rebuild",
					LedgerRelativePath, committed.Status, AutobahnBaselineRelativePath, baseline.Status, want))
			}
		}
	}

	if len(failures) != 0 {
		sort.Strings(failures)
		return fmt.Errorf("ledger envelope (%d problem(s)):\n  %s", len(failures), strings.Join(failures, "\n  "))
	}
	return nil
}
