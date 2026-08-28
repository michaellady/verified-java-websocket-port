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
	"github.com/santhosh-tekuri/jsonschema/v6"
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
func TestNewEvidenceDocumentsValidateAgainstTheirSchemas(t *testing.T) {
	for _, pair := range []struct{ document, schema string }{
		{CensusRelativePath, CensusSchemaRelativePath},
		{SupersessionsRelativePath, "schemas/ledger-supersessions-1.0.0.schema.json"},
		{ObservationsRelativePath, "schemas/observed-disagreements-1.0.0.schema.json"},
	} {
		schemaPath := filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(pair.schema))
		schemaRaw, err := os.ReadFile(schemaPath)
		if err != nil {
			t.Errorf("read %s: %v", pair.schema, err)
			continue
		}
		schemaDocument, err := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
		if err != nil {
			t.Errorf("decode %s: %v", pair.schema, err)
			continue
		}
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource(pair.schema, schemaDocument); err != nil {
			t.Errorf("add %s: %v", pair.schema, err)
			continue
		}
		compiled, err := compiler.Compile(pair.schema)
		if err != nil {
			t.Errorf("compile %s: %v", pair.schema, err)
			continue
		}
		documentRaw, err := os.ReadFile(filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(pair.document)))
		if err != nil {
			t.Errorf("read %s: %v", pair.document, err)
			continue
		}
		instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(documentRaw)))
		if err != nil {
			t.Errorf("decode %s: %v", pair.document, err)
			continue
		}
		if err := compiled.Validate(instance); err != nil {
			t.Errorf("%s does not validate against %s: %v", pair.document, pair.schema, err)
		}
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

// TestCitedOwnerDecisionsAreRecomputedWhenTheStoreIsReachable pins that the
// digests the ledger asserts are RECOMPUTED rather than merely quoted, when the
// protected store is reachable, and that a wrong digest is caught.
func TestCitedOwnerDecisionsAreRecomputedWhenTheStoreIsReachable(t *testing.T) {
	store := t.TempDir()
	// A store holding a file whose content does not hash to the cited value.
	for name := range citedOwnerDecisions {
		if err := os.WriteFile(filepath.Join(store, name), []byte("not the owner decision"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	t.Setenv(ProtectedStoreEnv, store)
	if _, err := VerifyCitedOwnerDecisions(); err == nil {
		t.Fatal("VerifyCitedOwnerDecisions accepted a protected store whose files do not hash to the cited digests")
	}
	// And an unset store is a disclosed no-op rather than a silent pass that
	// pretends to have checked.
	t.Setenv(ProtectedStoreEnv, "")
	checked, err := VerifyCitedOwnerDecisions()
	if err != nil {
		t.Fatalf("unset store should be a no-op, got: %v", err)
	}
	if checked != 0 {
		t.Fatalf("unset store reported %d recomputed digests", checked)
	}
}
