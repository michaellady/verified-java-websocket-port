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
	if len(links) != 5 {
		t.Fatalf("the chain carries %d supersession link(s); this branch supersedes sequences 14, 15, 16, 34 and 55",
			len(links))
	}
	// 14-16 are the wrong-RFC-basis budget corrections (45-47). 34 and 55 are
	// the two records whose DESCRIPTION OF THE PORT was made false by later
	// landings — DIV-05's inbound feed policy and DIV-06's response fields —
	// corrected at 57 and 58. The count is spelled out per sequence rather
	// than compared as a number, so adding a supersession fails here with the
	// sequence named instead of with an arithmetic complaint.
	wanted := map[uint64]bool{14: true, 15: true, 16: true, 34: true, 55: true}
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
	if len(authoritative) != len(committed.Records)-5 {
		t.Fatalf("%d authoritative sequences over %d records; five are superseded",
			len(authoritative), len(committed.Records))
	}
	for _, sequence := range authoritative {
		switch sequence {
		case 14, 15, 16, 34, 55:
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

// TestAQuotedSupersedesTokenIsNotAWithdrawal is the discrimination proof for
// round-3 finding 4.
//
// REPRODUCED BEFORE THE FIX, by execution: a disclaimed, explicitly-quoted
// canonical token planted in the class record's rationale withdrew sequence 44
// (the reserved-bit ready-state record). `deltaledgerctl` on the WRITE path
// wrote a sidecar with four links instead of three, and `--check` then exited 0
// — declaration and prose agreeing with each other while the structured
// Definition.Supersedes list claimed nothing at all.
//
// The token is now read as an ANCHORED PREFIX RUN and the canonical marker
// anywhere else is a refusal. Both halves are asserted: the real prefix tokens
// still parse, and a quoted one is refused rather than honoured.
func TestAQuotedSupersedesTokenIsNotAWithdrawal(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	links, err := ReadSupersessionLinks(committed.Records)
	if err != nil {
		t.Fatalf("the committed chain's own anchored tokens no longer parse: %v", err)
	}
	if len(links) != 5 {
		t.Fatalf("the committed chain carries %d supersession links, expected the three prefix corrections plus "+
			"the two stale-port corrections at 57 and 58", len(links))
	}

	// Find a record that supersedes nothing, and have it QUOTE a canonical
	// token that names a real earlier record. It is chosen BY PREDICATE rather
	// than by position: the last record used to supersede nothing and now
	// supersedes sequence 55, and a test whose premise quietly stopped being
	// true is worth less than one that fails when it does.
	target := lab.BehaviorLedgerRecord{}
	for index := len(committed.Records) - 1; index >= 0; index-- {
		if !strings.HasPrefix(committed.Records[index].Delta.Rationale, "SUPERSEDES ledger-sequence=") {
			target = committed.Records[index]
			break
		}
	}
	if target.Sequence == 0 {
		t.Fatal("every record in the chain carries a supersession token; this test needs one that supersedes nothing")
	}
	targetIndex := int(target.Sequence) - 1
	victim := committed.Records[43] // sequence 44, the reserved-bit record.
	if victim.Sequence != 44 {
		t.Fatalf("record index 43 is sequence %d, not 44; this test names the record it withdraws", victim.Sequence)
	}
	quoted := "an earlier draft wrongly asserted 'SUPERSEDES ledger-sequence=44 delta=" + victim.Delta.DeltaID +
		" subject=" + victim.Delta.SubjectRef + " reason=none;'. THAT IS QUOTED, NOT ASSERTED."
	records := append([]lab.BehaviorLedgerRecord(nil), committed.Records...)
	records[targetIndex].Delta.Rationale = target.Delta.Rationale + " " + quoted

	if _, err := ReadSupersessionLinks(records); err == nil {
		t.Fatal("a QUOTED, disclaimed canonical token was accepted as a withdrawal. The marker is reserved: it " +
			"must be parsed as an anchored prefix run, so a token in prose is a refusal rather than a claim")
	} else if !strings.Contains(err.Error(), "OUTSIDE the anchored token run") {
		t.Fatalf("the refusal does not name the reason: %v", err)
	}
}

// TestSupersessionsAreBoundToTheStructuredClaim pins the other half of round-3
// finding 4: the links parsed out of the hashed rationales must equal the links
// the structured Definition.Supersedes lists declare, so generated text cannot
// carry a withdrawal no Definition asked for.
func TestSupersessionsAreBoundToTheStructuredClaim(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	if err := VerifySupersessionsMatchDefinitions(Definitions(), committed.Records); err != nil {
		t.Fatalf("the committed chain's links do not match the structured claims: %v", err)
	}

	// Non-vacuity: drop the structured claim from the definition that makes it,
	// leaving the chain's text unchanged, and the two must disagree.
	definitions := append([]Definition(nil), Definitions()...)
	var stripped bool
	for index := range definitions {
		if len(definitions[index].Supersedes) != 0 {
			definitions[index].Supersedes = nil
			stripped = true
			break
		}
	}
	if !stripped {
		t.Fatal("no Definition declares a supersession; this branch appends three")
	}
	if err := VerifySupersessionsMatchDefinitions(definitions, committed.Records); err == nil {
		t.Fatal("a chain carrying a supersession link that no Definition declares was accepted")
	}
}

// TestGovernanceRecognisesEveryCitedDecision is the discrimination proof for
// round-3 finding 3.
//
// REPRODUCED BEFORE THE FIX, by execution against a scratch copy of the
// protected store with us012-us016-owner-decisions-2026-08-28-formal.json
// removed: the gate reported "3 governance record digest(s) recomputed from the
// protected store and matched" and exited 0. That decision is cited only at
// sequence 35, in the frozen prefix, in a phrasing the old one-wording
// recogniser did not match, so it was never in the mirror to be missed.
func TestGovernanceRecognisesEveryCitedDecision(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	built, err := BuildOwnerDecisionManifest(committed.Records)
	if err != nil {
		t.Fatalf("derive the governance mirror: %v", err)
	}
	mirrored := map[string]bool{}
	for _, decision := range built.Decisions {
		mirrored[decision.Name] = true
	}
	// EVERY decision the chain cites with a digest must be mirrored, and the
	// one the old recogniser omitted is named explicitly so a regression that
	// narrows the parse again fails here rather than silently.
	for _, required := range []string{
		"us012-us016-owner-decisions-2026-08-28-formal.json",
		"us010-016-ac-amendment-owner-decision-2026-08-27.json",
		"ledger-frozen-prefix-owner-decision-2026-08-28.json",
	} {
		if !mirrored[required] {
			t.Fatalf("%s is cited by the record chain with its sha256 but is absent from the governance mirror, so "+
				"deleting it from the protected store would fail nothing", required)
		}
	}

	// The fail-closed arm: a record that NAMES a decision without a digest
	// attributable to it is refused rather than quietly left out.
	records := append([]lab.BehaviorLedgerRecord(nil), committed.Records...)
	last := len(records) - 1
	records[last].Delta.Rationale = records[last].Delta.Rationale +
		" See also protected/a-brand-new-owner-decision-2026-08-29.json for background."
	if _, err := BuildOwnerDecisionManifest(records); err == nil {
		t.Fatal("a governance decision NAMED with no attributable digest was accepted; the mirror would be " +
			"silently incomplete, which is exactly how the gate went green with a deleted ruling")
	}
}

// TestTheLiveMappingIsBoundToItsSourceTable is a finding this branch found in
// its OWN adversarial pass, in the class round 3 named: an evidence input whose
// identity check lived only in a test binary.
//
// REPRODUCED BEFORE THE FIX, by execution: flipping ONE `divergent: true` row of
// evidence/us005-handshake-live-mapping.json to false — client_request
// HS_MISSING_HOST — silently removed a demand from the measurement's universe
// and left `deltaledgerctl --check` at exit 0. Only the six server_response rows
// are claimed by the literal `mapping-row` token, so the fail-closed "cites a
// row the evidence does not record as divergent" arm never fires for the
// thirteen client_request rows.
func TestTheLiveMappingIsBoundToItsSourceTable(t *testing.T) {
	if err := VerifyLiveMappingIsBoundToItsSourceTable(ledgerTestRepoRoot); err != nil {
		t.Fatalf("the committed live mapping does not equal its source table: %v", err)
	}
	root := degradedRoot(t, func(root string) {
		path := filepath.Join(root, filepath.FromSlash(LiveMappingRelativePath))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read the live mapping: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode the live mapping: %v", err)
		}
		entries, _ := document["entries"].([]any)
		var flipped bool
		for _, one := range entries {
			entry, _ := one.(map[string]any)
			if entry["divergent"] == true && entry["direction"] == "client_request" {
				entry["divergent"] = false
				flipped = true
				break
			}
		}
		if !flipped {
			t.Fatal("no client_request divergent row to switch off; this test's premise has moved")
		}
		encoded, _ := json.MarshalIndent(document, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write the live mapping: %v", err)
		}
	})
	if err := VerifyLiveMappingIsBoundToItsSourceTable(root); err == nil {
		t.Fatal("a divergent row was switched off in the committed evidence document and the gate accepted it; " +
			"the measurement's universe can be shrunk by editing its own input")
	}
}

// TestTheCommittedCorporaAreBoundInsideTheGate is the same class again, for the
// two corpus files. Round 3 said of the public one that "the production gate
// does not rederive the public corpus; that identity check remains test-only";
// the handshake corpus had the same gap, and it is the file that decides the
// family slug a record must carry to count as covering a mapping row.
func TestTheCommittedCorporaAreBoundInsideTheGate(t *testing.T) {
	if err := VerifyCommittedCorporaReDerive(ledgerTestRepoRoot); err != nil {
		t.Fatalf("the committed corpora do not re-derive from the committed seed: %v", err)
	}
	for _, relative := range []string{PublicCorpusRelativePath, HandshakeCorpusRelativePath} {
		root := degradedRoot(t, func(root string) {
			path := filepath.Join(root, filepath.FromSlash(relative))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", relative, err)
			}
			lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
			if len(lines) < 2 {
				t.Fatalf("%s has %d lines", relative, len(lines))
			}
			trimmed := strings.Join(lines[:len(lines)-1], "\n") + "\n"
			if err := os.WriteFile(path, []byte(trimmed), 0o644); err != nil {
				t.Fatalf("write %s: %v", relative, err)
			}
		})
		if err := VerifyCommittedCorporaReDerive(root); err == nil {
			t.Fatalf("%s lost a line and the production gate accepted it", relative)
		}
	}
}

// TestTheClassRecordCannotAnswerForANonMember pins the exclusion this branch
// added in its own adversarial pass. The locally-caused escape hatch is "an
// authoritative record names it", and the CLASS record names non-members in the
// sentence that says why they are excluded. Letting that count would make the
// class's own exclusion note the authority for the excluded scenario.
func TestTheClassRecordCannotAnswerForANonMember(t *testing.T) {
	definitions := Definitions()
	deltas, err := buildDeltasFrom(definitions)
	if err != nil {
		t.Fatalf("build deltas: %v", err)
	}
	var classDelta string
	for index, definition := range definitions {
		if strings.Contains(definition.Subject, "protocol-rejection-readystate-class") {
			classDelta = deltas[index].DeltaID
			if !strings.Contains(definitionText(definition), "us005.pub.0000") {
				t.Fatal("the class record no longer names us005.pub.0000; the exclusion this test pins has nothing " +
					"to exclude and the test's premise has moved")
			}
		}
	}
	if classDelta == "" {
		t.Fatal("the protocol-rejection class record is missing")
	}

	// With the class record excluded, us005.pub.0000 is still answered for —
	// by sequence 35, which is the record that is genuinely about it.
	named, err := scenariosNamedByAuthoritativeRecords(definitions, map[string]bool{classDelta: true})
	if err != nil {
		t.Fatalf("collect authoritative scenario names: %v", err)
	}
	if !named["us005.pub.0000"] {
		t.Fatal("us005.pub.0000 has no authoritative record naming it once the class record is excluded; " +
			"sequence 35 is supposed to be that record")
	}

	// Non-vacuity for the EXCLUSION MECHANISM itself: exclude every record that
	// names us005.pub.0000 and the escape hatch must close. Without this the
	// assertion above could pass with the exclusion doing nothing at all.
	excludeAll := map[string]bool{}
	for index, definition := range definitions {
		if strings.Contains(definitionText(definition), "us005.pub.0000") {
			excludeAll[deltas[index].DeltaID] = true
		}
	}
	if len(excludeAll) < 2 {
		t.Fatalf("only %d record(s) name us005.pub.0000; the committed chain has several", len(excludeAll))
	}
	named, err = scenariosNamedByAuthoritativeRecords(definitions, excludeAll)
	if err != nil {
		t.Fatalf("collect authoritative scenario names: %v", err)
	}
	if named["us005.pub.0000"] {
		t.Fatal("us005.pub.0000 is still named after every record that names it is excluded, so the exclusion " +
			"argument is being ignored and the escape hatch cannot be narrowed at all")
	}
}

// TestAnInRepositoryPathIsNotAGovernanceCitation pins the path constraint on
// the convention-independent citation parse. The recogniser keys on an asserted
// sha256 rather than on a file-name convention, so it has to be told what a
// PROTECTED-STORE record looks like: a bare name, or one explicitly under
// protected/, and nothing under any other directory. Without that, a record
// citing an in-repository evidence file with a digest would be mirrored and
// then fail as RECORD_ABSENT, turning a correct citation into a gate failure.
func TestAnInRepositoryPathIsNotAGovernanceCitation(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	baseline, err := BuildOwnerDecisionManifest(committed.Records)
	if err != nil {
		t.Fatalf("derive the governance mirror: %v", err)
	}

	withInRepo := append([]lab.BehaviorLedgerRecord(nil), committed.Records...)
	last := len(withInRepo) - 1
	withInRepo[last].Delta.Rationale = withInRepo[last].Delta.Rationale +
		" Context: evidence/us005-public-rfc-divergence-census.json (sha256 " + strings.Repeat("0", 64) + ")."
	inRepo, err := BuildOwnerDecisionManifest(withInRepo)
	if err != nil {
		t.Fatalf("an in-repository citation was treated as a governance citation: %v", err)
	}
	if len(inRepo.Decisions) != len(baseline.Decisions) {
		t.Fatalf("an in-repository path asserting a digest was mirrored as a protected-store record (%d -> %d)",
			len(baseline.Decisions), len(inRepo.Decisions))
	}

	// The other direction, so the constraint is a discriminator: an explicitly
	// protected/ record asserting a digest IS mirrored.
	withProtected := append([]lab.BehaviorLedgerRecord(nil), committed.Records...)
	withProtected[last].Delta.Rationale = withProtected[last].Delta.Rationale +
		" Context: protected/some-new-owner-decision-2026-08-29.json (sha256 " + strings.Repeat("1", 64) + ")."
	protectedManifest, err := BuildOwnerDecisionManifest(withProtected)
	if err != nil {
		t.Fatalf("derive the mirror with a protected-store citation: %v", err)
	}
	if len(protectedManifest.Decisions) != len(baseline.Decisions)+1 {
		t.Fatalf("a protected/ record asserting a digest was NOT mirrored (%d -> %d); the recogniser is keying on "+
			"something other than the asserted digest", len(baseline.Decisions), len(protectedManifest.Decisions))
	}
}

// TestASupersededRecordCoversNothing closes the last two places a WITHDRAWN
// record still counted as coverage, both found in this branch's own adversarial
// pass. coveringDefinitionsForRow already excluded superseded records on the
// handshake arm; the public-corpus demand arm and the census-coverage rule did
// not, so the round-2 finding about supersession being invisible to a consumer
// had survived in two consumers.
func TestASupersededRecordCoversNothing(t *testing.T) {
	definitions := Definitions()
	superseded := supersededSubjects(definitions)
	if len(superseded) == 0 {
		t.Fatal("no Definition is superseded; this branch supersedes three")
	}

	// Take a superseded definition and make it the ONLY record naming a
	// public-corpus scenario, then require the demand to stay unanswered.
	withdrawn := -1
	for index, definition := range definitions {
		if superseded[definition.Subject] {
			withdrawn = index
			break
		}
	}
	if withdrawn < 0 {
		t.Fatal("no superseded definition found")
	}

	// The census-coverage half: point a class row at the withdrawn record and
	// require a refusal that names supersession, not merely a missing mention.
	deltas, err := buildDeltasFrom(definitions)
	if err != nil {
		t.Fatalf("build deltas: %v", err)
	}
	withdrawnDelta := deltas[withdrawn].DeltaID
	root := degradedRoot(t, func(root string) {
		path := filepath.Join(root, filepath.FromSlash(CensusRelativePath))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read the census: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode the census: %v", err)
		}
		entries, _ := document["entries"].([]any)
		if len(entries) == 0 {
			t.Fatal("the census has no rows to repoint")
		}
		entry, _ := entries[0].(map[string]any)
		entry["ledger_delta_id"] = withdrawnDelta
		encoded, _ := json.MarshalIndent(document, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write the census: %v", err)
		}
	})
	err = VerifyCensusRowsAreLedgered(root, definitions)
	if err == nil {
		t.Fatal("a census row was answered by a record the chain records as SUPERSEDED")
	}
	if !strings.Contains(err.Error(), "SUPERSEDED") {
		t.Fatalf("the refusal does not name supersession as the reason: %v", err)
	}
}
