package deltaledger

// Tests for the ledger integrity gate, the frozen prefix, and supersession.
//
// Every test below either runs a production rule against the committed tree or
// performs the exact attack the corresponding review finding described, and
// requires the rule to refuse it. The rules themselves are in integrity.go,
// evidence_census.go, observations.go and supersede.go — production code that
// cmd/deltaledgerctl runs under --check, so `make -C rust gates` runs it too.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

func TestTheCommittedTreePassesTheIntegrityGate(t *testing.T) {
	if err := VerifyIntegrity(ledgerTestRepoRoot); err != nil {
		t.Fatalf("ledger integrity:\n%v", err)
	}
}

// TestTheFrozenPrefixIsPinned enforces the owner requirement that nothing
// verified before: "The frozen prefix through sequence 35 must remain
// byte-identical, verified after the append."
func TestTheFrozenPrefixIsPinned(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	if err := VerifyFrozenPrefix(committed.Records); err != nil {
		t.Fatalf("frozen prefix: %v", err)
	}
	// Discrimination: a rewritten prefix must fail. Because the chain is
	// hash-linked, sequence 35's record digest covers every byte of records
	// 1-35, so REBUILDING the chain from a tampered first definition is the
	// honest form of this attack: it produces a self-consistent chain that the
	// record-by-record verifier accepts and only this pin refuses.
	tampered := append([]Definition(nil), Definitions()...)
	tampered[0].Rationale += " a byte added to a sealed record"
	rebuilt, _, err := buildLedgerFrom(tampered)
	if err != nil {
		t.Fatalf("rebuild from a tampered definition: %v", err)
	}
	if err := VerifyFrozenPrefix(rebuilt); err == nil {
		t.Fatal("VerifyFrozenPrefix accepted a chain rebuilt from a rewritten sequence-1 record; the frozen prefix " +
			"is not actually pinned")
	}
}

// TestSupersessionIsMachineVisible is the discrimination proof for review
// BLOCKING 8: "supersede" used to be prose, so sequences 14-16 and their
// corrections 45-47 all read `unresolved` and no consumer could tell them apart.
func TestSupersessionIsMachineVisible(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	links, err := ReadSupersessionLinks(committed.Records)
	if err != nil {
		t.Fatalf("read supersession links: %v", err)
	}
	if len(links) != 3 {
		t.Fatalf("the chain carries %d supersession link(s); this branch supersedes sequences 14, 15 and 16",
			len(links))
	}
	wanted := map[uint64]bool{14: true, 15: true, 16: true}
	for _, link := range links {
		if !wanted[link.SupersededSequence] {
			t.Errorf("unexpected superseded sequence %d", link.SupersededSequence)
		}
		delete(wanted, link.SupersededSequence)
		if link.SupersedingSequence <= link.SupersededSequence {
			t.Errorf("sequence %d claims to supersede %d, which is not earlier",
				link.SupersedingSequence, link.SupersededSequence)
		}
	}
	if len(wanted) != 0 {
		t.Errorf("sequences %v are not recorded as superseded", wanted)
	}

	authoritative, err := AuthoritativeSequences(committed.Records)
	if err != nil {
		t.Fatalf("authoritative sequences: %v", err)
	}
	if len(authoritative) != len(committed.Records)-3 {
		t.Fatalf("%d authoritative sequences over %d records; three are superseded",
			len(authoritative), len(committed.Records))
	}
	for _, sequence := range authoritative {
		if sequence == 14 || sequence == 15 || sequence == 16 {
			t.Errorf("superseded sequence %d is still reported authoritative", sequence)
		}
	}

	// The committed sidecar must equal the map the chain itself carries.
	if err := VerifySupersessions(ledgerTestRepoRoot, committed.Records); err != nil {
		t.Fatalf("supersessions sidecar: %v", err)
	}
	// Discrimination: a sidecar that tells a different story must fail.
	root := degradedRoot(t, func(root string) {
		path := filepath.Join(root, filepath.FromSlash(SupersessionsRelativePath))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read supersessions: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode supersessions: %v", err)
		}
		document["links"] = []any{}
		encoded, _ := json.MarshalIndent(document, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write supersessions: %v", err)
		}
	})
	if err := VerifySupersessions(root, committed.Records); err == nil {
		t.Fatal("VerifySupersessions accepted a sidecar that disagrees with the chain")
	}
}

// TestSupersessionLinksMustResolveAgainstTheChain pins the fail-closed half: a
// link naming a sequence that is not there, or naming the wrong delta for the
// sequence it does name, is an error rather than a decorative string.
func TestSupersessionLinksMustResolveAgainstTheChain(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	records := append([]lab.BehaviorLedgerRecord(nil), committed.Records...)
	// Point a real link at the wrong delta for its sequence.
	for index := range records {
		if strings.Contains(records[index].Delta.Rationale, "SUPERSEDES ledger-sequence=14 ") {
			records[index].Delta.Rationale = strings.Replace(records[index].Delta.Rationale,
				records[13].Delta.DeltaID, "delta-"+strings.Repeat("a", 64), 1)
			break
		}
	}
	if _, err := ReadSupersessionLinks(records); err == nil {
		t.Fatal("ReadSupersessionLinks accepted a link naming the wrong delta for the sequence it supersedes")
	}
}

// TestEveryRationaleFitsTheFrozenBound names the offending record when a
// rationale outgrows the frozen 1.0.0 schema's 4096-byte bound, instead of
// leaving a caller to read a generic INVALID_BEHAVIOR_DELTA from the builder.
func TestEveryRationaleFitsTheFrozenBound(t *testing.T) {
	const bound = 4096
	for index, definition := range Definitions() {
		length := len(supersedesPrefix(definition) + definition.Rationale)
		if length > bound {
			t.Errorf("definition %d (%s) renders a %d-byte rationale; the frozen schema bounds it at %d",
				index+1, definition.Subject, length, bound)
		}
	}
}

// TestNewEvidenceDocumentsValidateAgainstTheirSchemas closes the half of review
// BLOCKING 5 that was about a missing contract: the census named a schema that
// did not exist, and nothing validated against it.
//
// ROUND-2 FINDING 4 moved the validation itself into production code. This test
// used to CONTAIN the only JSON-schema validation in the repository, and
// `ledger-gates` runs no Go tests, so an unknown census field passed production
// `--check` — round-1 finding 3 recurring one layer up. It now calls the same
// exported function the gate calls, so the two cannot drift, and it asserts the
// binding list covers the documents this package regenerates.
func TestNewEvidenceDocumentsValidateAgainstTheirSchemas(t *testing.T) {
	if err := VerifyEvidenceDocumentSchemas(ledgerTestRepoRoot); err != nil {
		t.Fatalf("committed evidence documents do not validate: %v", err)
	}
	bound := map[string]bool{}
	for _, binding := range EvidenceSchemaBindings() {
		bound[binding.Document] = true
	}
	for _, document := range []string{
		LedgerRelativePath, CensusRelativePath, SupersessionsRelativePath,
		ObservationsRelativePath, OwnerDecisionManifestRelativePath,
	} {
		if !bound[document] {
			t.Errorf("%s is regenerated by this package but is not schema-validated by the gate", document)
		}
	}
}

// TestTheSchemaGateRefusesAnUnknownField is the discrimination proof: the
// binding above is only worth having if a violation is refused. Reproduced
// before the validation moved into production: adding an unknown field to a
// census row left `deltaledgerctl --check` and `make -C rust ledger-gates` at
// exit 0.
func TestTheSchemaGateRefusesAnUnknownField(t *testing.T) {
	root := degradedRoot(t, func(root string) {
		path := filepath.Join(root, filepath.FromSlash(CensusRelativePath))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read census: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode census: %v", err)
		}
		entries, _ := document["entries"].([]any)
		if len(entries) == 0 {
			t.Fatal("census has no entries")
		}
		row, _ := entries[0].(map[string]any)
		row["an_unknown_field_the_schema_forbids"] = "present"
		encoded, _ := json.MarshalIndent(document, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write census: %v", err)
		}
	})
	err := VerifyEvidenceDocumentSchemas(root)
	if err == nil {
		t.Fatal("the schema gate accepted a census row carrying a field the schema forbids")
	}
	if !strings.Contains(err.Error(), "an_unknown_field_the_schema_forbids") {
		t.Fatalf("refused, but not on the unknown field; got: %v", err)
	}
	if err := VerifyIntegrity(root); err == nil {
		t.Fatal("the integrity gate accepted the same document; the schema rule is not reachable from the gate")
	}
}

// TestTheIntegrityGateRefusesADegradedTree is the wiring proof for review
// BLOCKING 3: the rules are reachable from the gate, and the gate refuses.
func TestTheIntegrityGateRefusesADegradedTree(t *testing.T) {
	root := degradedRoot(t, func(root string) {
		path := filepath.Join(root, filepath.FromSlash(LiveMappingRelativePath))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read live mapping: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode live mapping: %v", err)
		}
		entries, _ := document["entries"].([]any)
		document["entries"] = append(entries, map[string]any{
			"direction":       "server_response",
			"key":             "HS_BARE_LF_NEWLY_OBSERVED",
			"rfc_verdict":     "reject",
			"java_observable": "conditional",
			"divergent":       true,
			"basis":           []any{"an observed divergence with no ledger record"},
		})
		encoded, _ := json.MarshalIndent(document, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write live mapping: %v", err)
		}
	})
	err := VerifyIntegrity(root)
	if err == nil {
		t.Fatal("the integrity gate accepted a tree with a newly observed divergence that no record covers")
	}
	if !strings.Contains(err.Error(), "HS_BARE_LF_NEWLY_OBSERVED") {
		t.Fatalf("the gate refused, but not on the new divergence; got:\n%v", err)
	}
	if !strings.Contains(err.Error(), "unledgered-disagreements") {
		t.Fatalf("the gate refused without the measurement reporting it; got:\n%v", err)
	}
}

// TestTheGovernanceGateDistinguishesAbsentDriftedAndVerified is the
// discrimination proof for round-2 finding 5, and it pins the three outcomes the
// owner ruling requires the gate to tell apart.
//
// THE DEFECT, reproduced by execution before the fix: with VJWP_PROTECTED_STORE
// unset, `rm` of the real
// protected/ledger-frozen-prefix-owner-decision-2026-08-28.json — the ruling
// that authorizes the whole supersede-do-not-rewrite design — left
// `make -C rust ledger-gates` at exit 0. The old check returned success whenever
// the variable was unset, so the governance layer was unbound by anything in the
// repository.
//
// The owner ruled MIRROR DIGESTS ONLY, with the binding note that "a missing
// protected store must not silently pass. Absence of the store is different from
// a matching digest, and the check must distinguish them rather than skipping".
// The three legs below are exactly those three outcomes.
func TestTheGovernanceGateDistinguishesAbsentDriftedAndVerified(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	manifest, err := ReadOwnerDecisionManifest(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read the governance mirror: %v", err)
	}

	t.Run("verified", func(t *testing.T) {
		withProtectedStore(t)
		verified, err := VerifyGovernance(ledgerTestRepoRoot, committed.Records)
		if err != nil {
			t.Fatalf("the governance gate refused the intact tree: %v", err)
		}
		if verified != len(manifest.Decisions) {
			t.Fatalf("the gate verified %d of %d mirrored digests", verified, len(manifest.Decisions))
		}
	})

	t.Run("record absent", func(t *testing.T) {
		store := t.TempDir()
		// Every mirrored record present except one: the deletion the reviewer
		// performed, against a copy rather than the real store.
		source, err := ResolveProtectedStore(ledgerTestRepoRoot)
		if err != nil {
			t.Fatalf("resolve the store: %v", err)
		}
		var omitted string
		for index, decision := range manifest.Decisions {
			if index == 0 {
				omitted = decision.Name
				continue
			}
			raw, err := os.ReadFile(filepath.Join(source.Path, decision.Name))
			if err != nil {
				t.Fatalf("read %s: %v", decision.Name, err)
			}
			if err := os.WriteFile(filepath.Join(store, decision.Name), raw, 0o644); err != nil {
				t.Fatalf("write %s: %v", decision.Name, err)
			}
		}
		t.Setenv(ProtectedStoreEnv, store)
		_, err = VerifyGovernance(ledgerTestRepoRoot, committed.Records)
		if err == nil {
			t.Fatal("the governance gate accepted a store with a deleted owner decision")
		}
		if !strings.Contains(err.Error(), "RECORD_ABSENT "+omitted) {
			t.Fatalf("refused, but not as an absent record; got: %v", err)
		}
	})

	t.Run("record drifted", func(t *testing.T) {
		store := t.TempDir()
		source, err := ResolveProtectedStore(ledgerTestRepoRoot)
		if err != nil {
			t.Fatalf("resolve the store: %v", err)
		}
		for index, decision := range manifest.Decisions {
			raw, err := os.ReadFile(filepath.Join(source.Path, decision.Name))
			if err != nil {
				t.Fatalf("read %s: %v", decision.Name, err)
			}
			if index == 0 {
				// One byte of edit is enough; the point is that ANY edit shows.
				raw = append(raw, '\n')
			}
			if err := os.WriteFile(filepath.Join(store, decision.Name), raw, 0o644); err != nil {
				t.Fatalf("write %s: %v", decision.Name, err)
			}
		}
		t.Setenv(ProtectedStoreEnv, store)
		_, err = VerifyGovernance(ledgerTestRepoRoot, committed.Records)
		if err == nil {
			t.Fatal("the governance gate accepted an edited owner decision")
		}
		if !strings.Contains(err.Error(), "RECORD_DRIFTED "+manifest.Decisions[0].Name) {
			t.Fatalf("refused, but not as a drifted record; got: %v", err)
		}
	})

	t.Run("store unreachable is a refusal and not a skip", func(t *testing.T) {
		// An unset variable with no discoverable store above the root. This is
		// the exact configuration under which deleting a governance record used
		// to leave the branch gate green.
		t.Setenv(ProtectedStoreEnv, "")
		_, err := VerifyGovernance(t.TempDir(), committed.Records)
		if err == nil {
			t.Fatal("the governance gate passed with no reachable protected store. Skipping when the store is " +
				"unset is the exact shape of the defect the owner ruling closes")
		}
		if !strings.Contains(err.Error(), "PROTECTED GOVERNANCE STORE IS NOT REACHABLE") &&
			!strings.Contains(err.Error(), OwnerDecisionManifestRelativePath) {
			t.Fatalf("refused, but not on the unreachable store; got: %v", err)
		}
	})

	t.Run("a misconfigured store is an error, not a fallback", func(t *testing.T) {
		t.Setenv(ProtectedStoreEnv, filepath.Join(t.TempDir(), "no-such-directory"))
		if _, err := ResolveProtectedStore(ledgerTestRepoRoot); err == nil {
			t.Fatal("a store variable pointing at nothing silently fell back to discovery; a typo would then " +
				"produce the same green gate as a correct setting")
		}
	})
}

// TestTheGovernanceMirrorEqualsWhatTheEvidenceAsserts pins the other half: the
// committed mirror is DERIVED from the digests the records themselves assert,
// so it cannot be edited into a separate story.
func TestTheGovernanceMirrorEqualsWhatTheEvidenceAsserts(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	built, err := BuildOwnerDecisionManifest(committed.Records)
	if err != nil {
		t.Fatalf("derive the governance mirror: %v", err)
	}
	if len(built.Decisions) < 2 {
		t.Fatalf("the mirror derived %d decisions; the chain cites at least two", len(built.Decisions))
	}
	// The ruling that mandates the mirror must itself be mirrored, or deleting
	// the authority for the mirror would fail nothing.
	var found bool
	for _, decision := range built.Decisions {
		if strings.HasPrefix(decision.Name, "governance-mirroring-and-record-schema-owner-decision") {
			found = true
		}
	}
	if !found {
		t.Fatal("the governance-mirroring ruling is absent from its own mirror")
	}

	root := degradedRoot(t, func(root string) {
		path := filepath.Join(root, filepath.FromSlash(OwnerDecisionManifestRelativePath))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read the mirror: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode the mirror: %v", err)
		}
		decisions, _ := document["decisions"].([]any)
		if len(decisions) == 0 {
			t.Fatal("the mirror has no decisions to degrade")
		}
		entry, _ := decisions[0].(map[string]any)
		entry["sha256"] = strings.Repeat("a", 64)
		encoded, _ := json.MarshalIndent(document, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write the mirror: %v", err)
		}
	})
	if _, err := VerifyGovernance(root, committed.Records); err == nil {
		t.Fatal("the governance gate accepted a mirror whose digest disagrees with the derivation")
	}
}
