package deltaledger

// Evidence-side census for the behavior-delta ledger: the TESTS.
//
// The RULES now live in evidence_census.go as ordinary production code, because
// review 01a0495e (BLOCKING 3) established that a rule which exists only in a
// `_test.go` file is not a gate — nothing in the release or readiness path ran
// these. cmd/deltaledgerctl calls the same functions, and rust/Makefile's
// `gates` target depends on it. What remains here is (a) running the rule
// against the committed tree and (b) DISCRIMINATION tests: each one performs
// the exact attack that the previous version of the rule was reproduced to
// accept, and requires the current rule to refuse it.
//
// WHY THE RULE IS SHAPED THE WAY IT IS. The source-side census in ledger_test.go
// (TestEveryShippedQuirkWithAnRFCCounterpartIsLedgered) drives coverage from the
// Q-series quirk tokens written into rust/ws-core/src. That is necessary but NOT
// sufficient, and the acceptance audit found the hole it leaves: a whole
// DIRECTION of recorded divergence went unledgered while the source-side census
// stayed green, because the source need not carry a Q-token for it at all —
// client.rs's only Q-tokens, Q9 and Q28, are both allowlisted. The rule here
// inverts the direction of the census: it reads the committed live handshake
// evidence and requires every `divergent: true` row to be covered by a ledger
// record that is demonstrably about it.

import (
	"strings"
	"testing"
)

func TestEveryDivergentLiveMappingRowIsLedgered(t *testing.T) {
	if err := VerifyHandshakeMappingCensus(ledgerTestRepoRoot, Definitions()); err != nil {
		t.Fatalf("handshake mapping census: %v", err)
	}
}

// TestMappingRowCoverageRefusesACitationTokenInAnUnrelatedRecord is the
// discrimination proof for review BLOCKING 6.
//
// THE ATTACK, reproduced against the previous rule and READ PASSING before the
// fix: delete the six meaningful client-handshake records and paste their six
// `mapping-row direction=… key=…` citation tokens into an unrelated record's
// free prose. Under the old token-grep rule the census stayed green, because
// coverage meant "this literal string appears somewhere in some definition".
//
// The rule now additionally requires the covering record's SUBJECT to name the
// endpoint role that parses the row's direction and to carry the corpus family
// slug for the row's reject code, so an unrelated record cannot claim the row
// however its prose is written.
func TestMappingRowCoverageRefusesACitationTokenInAnUnrelatedRecord(t *testing.T) {
	rows, err := ReadDivergentMappingRows(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read divergent rows: %v", err)
	}
	var serverResponseRows []MappingRow
	for _, row := range rows {
		if row.Direction == "server_response" {
			serverResponseRows = append(serverResponseRows, row)
		}
	}
	if len(serverResponseRows) == 0 {
		t.Fatal("the attack needs at least one server_response divergent row")
	}

	// Delete every client-handshake record (the ones that legitimately cover
	// the server_response rows) and paste their citation tokens into a record
	// that is about something else entirely.
	var mutated []Definition
	victim := -1
	for _, definition := range Definitions() {
		if strings.Contains(definition.Subject, ".client-handshake.") {
			continue
		}
		if victim < 0 && strings.Contains(definition.Subject, ".framing.") {
			victim = len(mutated)
		}
		mutated = append(mutated, definition)
	}
	if victim < 0 {
		t.Fatal("no unrelated record available to carry the pasted tokens")
	}
	var tokens []string
	for _, row := range serverResponseRows {
		tokens = append(tokens, row.CitationToken())
	}
	mutated[victim].Rationale += " ATTACK TOKENS: " + strings.Join(tokens, " ") + "."

	err = VerifyHandshakeMappingCensus(ledgerTestRepoRoot, mutated)
	if err == nil {
		t.Fatal("the census accepted an unrelated record claiming six mapping rows by pasting their citation " +
			"tokens into its prose; coverage is back to being a token grep")
	}
	for _, row := range serverResponseRows {
		if !strings.Contains(err.Error(), row.String()) {
			t.Errorf("the census refused, but did not name the uncovered row %s; got: %v", row, err)
		}
	}
}

// TestASupersededRecordDoesNotCoverAnything joins review BLOCKING 6 to review
// BLOCKING 8: a divergent row whose only claimant is a WITHDRAWN record is an
// uncovered row, and the census can say so only because supersession is now
// machine-visible rather than prose.
//
// The three server-side handshake budget rows are the live instance: sequences
// 14-16 claim them and are superseded by 45-47. Deleting the corrections must
// leave those rows uncovered, not silently covered by the records whose RFC
// basis was withdrawn.
func TestASupersededRecordDoesNotCoverAnything(t *testing.T) {
	superseded := supersededSubjects(Definitions())
	if len(superseded) == 0 {
		t.Fatal("no definition supersedes another; this branch appends corrections for sequences 14-16")
	}

	// Strip the CITATIONS out of the superseding corrections while keeping
	// their Supersedes links, so sequences 14-16 stay withdrawn and are the
	// only remaining claimants of their rows. The rows must then read as
	// uncovered: a withdrawn record is not coverage.
	mutated := append([]Definition(nil), Definitions()...)
	stripped := 0
	for index := range mutated {
		if len(mutated[index].Supersedes) == 0 {
			continue
		}
		mutated[index].JavaObservation = "citations removed by this test"
		mutated[index].Rationale = "citations removed by this test"
		stripped++
	}
	if stripped != 5 {
		t.Fatalf("stripped %d superseding records, expected the three budget corrections plus the two stale-port "+
			"corrections at sequences 57 and 58", stripped)
	}

	err := VerifyHandshakeMappingCensus(ledgerTestRepoRoot, mutated)
	if err == nil {
		t.Fatal("the census left the three server-side budget rows covered when their only remaining claimants were " +
			"the WITHDRAWN sequences 14-16; a superseded record is still being accepted as coverage")
	}
	for _, key := range []string{"HS_LIMIT_TOTAL_BYTES", "HS_LIMIT_HEADER_COUNT", "HS_LIMIT_HEADER_LINE_BYTES"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("the census refused, but did not report %s as uncovered; got: %v", key, err)
		}
	}
}

// TestExplicitMappingRowCitationsResolve is the fail-closed other half: a
// record may not claim a mapping row the committed evidence does not record as
// divergent, so the census cannot be satisfied with an invented token.
func TestExplicitMappingRowCitationsResolve(t *testing.T) {
	mutated := append([]Definition(nil), Definitions()...)
	mutated[0].Rationale += " mapping-row direction=server_response key=HS_NOT_A_DIVERGENT_ROW."
	err := VerifyHandshakeMappingCensus(ledgerTestRepoRoot, mutated)
	if err == nil {
		t.Fatal("the census accepted a citation of a row that is not `divergent: true` in the committed evidence")
	}
	if !strings.Contains(err.Error(), "HS_NOT_A_DIVERGENT_ROW") {
		t.Fatalf("refused, but not on the invented citation; got: %v", err)
	}
}

// TestTheFamilySlugMapIsDerivedFromTheCorpus pins that the subject-slug binding
// comes from committed evidence rather than from a hand table that could drift
// away from it, and that it is non-vacuous.
func TestTheFamilySlugMapIsDerivedFromTheCorpus(t *testing.T) {
	cases, err := ReadHandshakeCorpusCases(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read handshake corpus: %v", err)
	}
	rows, err := ReadDivergentMappingRows(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read divergent rows: %v", err)
	}
	for _, row := range rows {
		family, err := FamilyForRow(cases, row)
		if err != nil {
			t.Errorf("divergent row %s: %v", row, err)
			continue
		}
		if family == "" {
			t.Errorf("divergent row %s resolved to an empty family slug", row)
		}
	}

	// Direction sensitivity is load-bearing: the corpus maps HS_MISSING_UPGRADE
	// to different families on the two sides of the handshake, and picking the
	// wrong one would silently weaken the coverage rule.
	client, err := FamilyForRow(cases, MappingRow{Direction: "client_request", Key: "HS_MISSING_UPGRADE"})
	if err != nil {
		t.Fatalf("client_request HS_MISSING_UPGRADE: %v", err)
	}
	server, err := FamilyForRow(cases, MappingRow{Direction: "server_response", Key: "HS_MISSING_UPGRADE"})
	if err != nil {
		t.Fatalf("server_response HS_MISSING_UPGRADE: %v", err)
	}
	if client == server {
		t.Fatalf("both directions resolve HS_MISSING_UPGRADE to %q; the direction-first resolution has stopped "+
			"discriminating", client)
	}

	// Non-vacuity: an unknown reject code must be an error rather than a
	// fallback to a token-only match.
	if _, err := FamilyForRow(cases, MappingRow{Direction: "client_request", Key: "HS_NO_SUCH_CODE"}); err == nil {
		t.Fatal("FamilyForRow invented a family for a reject code the corpus does not carry")
	}

	// Non-vacuity: an ambiguity WITHIN one direction must be an error rather
	// than a silently chosen winner. HS_KEY_NOT_BASE64 carries two
	// client_request cases (us005.hs.0019 and us005.hs.0020), so giving them
	// different families is a real in-direction conflict.
	ambiguous := MappingRow{Direction: "client_request", Key: "HS_KEY_NOT_BASE64"}
	conflicting := append([]HandshakeCase(nil), cases...)
	seen := 0
	for index := range conflicting {
		if conflicting[index].Expected.RejectCode == ambiguous.Key &&
			conflicting[index].Direction == ambiguous.Direction {
			conflicting[index].Family = "attack-family-" + conflicting[index].CaseID
			seen++
		}
	}
	if seen < 2 {
		t.Fatalf("%s has %d case(s) in its direction; the in-direction ambiguity check needs at least two",
			ambiguous, seen)
	}
	if _, err := FamilyForRow(conflicting, ambiguous); err == nil {
		t.Fatalf("FamilyForRow accepted a corpus mapping %s to many families in one direction", ambiguous)
	}
}
