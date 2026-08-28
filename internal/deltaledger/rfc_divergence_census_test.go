package deltaledger

// The public-corpus RFC-divergence census: the TESTS.
//
// The rules live in evidence_census.go and run inside cmd/deltaledgerctl, for
// the reason given at the top of mapping_census_test.go. What is here is the
// run against the committed tree, plus a discrimination test for each defect
// review 01a0495e found and this branch reproduced by execution.
//
// WHY THE CENSUS EXISTS. The reserved-bit ready-state divergence (us005.pub.0005
// /final_state) was found by a cross-plane audit reading another plane's
// manifest by hand. No gate on this plane would have found it. Worse, once
// found, sweeping the corpus for the same cause showed it was not one scenario
// but eighteen — so the hand-audit found roughly five percent of the class it
// had stumbled into.
//
// IT IS DELIBERATELY SOURCED FROM OUR EVIDENCE ONLY. The Codex plane holds a
// comparable artifact, and making our gate read it would couple the planes and
// let their normative choices silently become ours. The two planes disagree at
// this exact pointer on purpose; that disagreement has to stay separately
// auditable.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtocolRejectionClassIsEnumeratedCompletely(t *testing.T) {
	if err := VerifyProtocolRejectionClass(ledgerTestRepoRoot); err != nil {
		t.Fatalf("protocol-rejection class: %v", err)
	}
}

func TestCensusRowsMatchTheCommittedEvidence(t *testing.T) {
	if err := VerifyCensusRowsMatchEvidence(ledgerTestRepoRoot); err != nil {
		t.Fatalf("census versus evidence: %v", err)
	}
}

func TestEveryCensusRowIsLedgered(t *testing.T) {
	if err := VerifyCensusRowsAreLedgered(ledgerTestRepoRoot, Definitions()); err != nil {
		t.Fatalf("census ledger coverage: %v", err)
	}
}

// TestTheClassPredicateSelectsByCauseAndNotByCloseCode is the discrimination
// proof for review BLOCKING 4.
//
// The previous predicate was `outcome==error AND final_state==open AND
// close_code in {1002,1007,1009}` — a result shape. It enrolled us005.pub.0000,
// a locally initiated `send_close(999)` with input_bytes 0 and consumed_bytes 0.
// RFC 6455 section 7.1.7 requires closing only where another algorithm or
// provision requires _Fail the WebSocket Connection_, and an invalid local API
// call is not such a provision, so the census's claim that the RFC-strict state
// there was `closed` was wrong. That false positive is what proves
// {1002,1007,1009} was never a principled cause boundary.
func TestTheClassPredicateSelectsByCauseAndNotByCloseCode(t *testing.T) {
	scenarios, err := ReadPublicScenarios(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read public corpus: %v", err)
	}
	byID := map[string]PublicScenario{}
	for _, scenario := range scenarios {
		byID[scenario.ScenarioID] = scenario
	}

	local, exists := byID["us005.pub.0000"]
	if !exists {
		t.Fatal("us005.pub.0000 is missing from the public corpus; this test pins its exclusion")
	}
	if local.Expected.Error == nil || local.Expected.Error.CloseCode != 1002 {
		t.Fatal("us005.pub.0000 no longer carries close code 1002; the discrimination this test proves has moved")
	}
	if local.Expected.Counts.InputBytes != 0 {
		t.Fatalf("us005.pub.0000 now reports %d input bytes; it was the zero-inbound local-action case",
			local.Expected.Counts.InputBytes)
	}
	if InProtocolRejectionClass(local) {
		t.Fatal("the class predicate still enrolls us005.pub.0000, a locally initiated send_close(999) with no " +
			"inbound decode; it is selecting by result shape rather than by cause")
	}

	inbound, exists := byID["us005.pub.0005"]
	if !exists {
		t.Fatal("us005.pub.0005 is missing from the public corpus")
	}
	if !InProtocolRejectionClass(inbound) {
		t.Fatal("the class predicate no longer enrolls us005.pub.0005, the founding member of the class")
	}

	// Non-vacuity in the other direction: a member's close code is an asserted
	// consistency property, not a filter, so a hypothetical member carrying
	// 1008 is still IN the class and must be dealt with rather than dropped.
	odd := inbound
	odd.ScenarioID = "us005.pub.9999"
	odd.Expected.Error = &struct {
		Code      string `json:"code"`
		CloseCode int    `json:"close_code"`
	}{Code: "JAVA_INVALID_DATA", CloseCode: 1008}
	if !InProtocolRejectionClass(odd) {
		t.Fatal("a decoder rejection carrying close code 1008 is excluded from the class; the close-code set is " +
			"acting as a membership filter again, which is exactly the defect")
	}
}

// TestCensusCoverageRefusesAnUnrelatedLedgerRecord is the discrimination proof
// for review BLOCKING 5.
//
// THE ATTACK, reproduced against the previous rule and READ PASSING before the
// fix: repoint every census row's `ledger_delta_id` at the unrelated sequence-1
// record (a server-handshake missing-Host divergence). The old rule performed
// set membership on delta ids, so it stayed green. The rule now requires the
// named record's own hashed preimages to MENTION the scenario.
func TestCensusCoverageRefusesAnUnrelatedLedgerRecord(t *testing.T) {
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
		committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
		if err != nil {
			t.Fatalf("read committed ledger: %v", err)
		}
		unrelated := committed.Records[0].Delta.DeltaID
		entries, _ := document["entries"].([]any)
		if len(entries) == 0 {
			t.Fatal("census has no entries to repoint")
		}
		for _, entry := range entries {
			row, _ := entry.(map[string]any)
			row["ledger_delta_id"] = unrelated
		}
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			t.Fatalf("encode census: %v", err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write census: %v", err)
		}
	})
	err := VerifyCensusRowsAreLedgered(root, Definitions())
	if err == nil {
		t.Fatal("census coverage accepted every row pointing at an unrelated record; it is checking that SOMETHING " +
			"exists rather than that it is the RIGHT something")
	}
	if !strings.Contains(err.Error(), "never mention") {
		t.Fatalf("refused, but not on the semantic binding; got: %v", err)
	}
}

// TestTheCensusNamesASchemaThatExists pins review BLOCKING 5's second half: the
// census pointed at schemas/public-rfc-divergence-census-1.0.0.schema.json while
// no such file existed, and the decoder ignored both `$schema` and `census_id`,
// so the missing contract was undetectable.
func TestTheCensusNamesASchemaThatExists(t *testing.T) {
	document, err := ReadCensus(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read census: %v", err)
	}
	if document.CensusID == "" || document.Schema == "" {
		t.Fatal("the census envelope no longer carries census_id and $schema")
	}
	if _, err := os.Stat(filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(CensusSchemaRelativePath))); err != nil {
		t.Fatalf("the census names a schema that does not exist: %v", err)
	}
	// Discrimination: a drifted pointer must fail rather than pass.
	root := degradedRoot(t, func(root string) {
		path := filepath.Join(root, filepath.FromSlash(CensusRelativePath))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read census: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("decode census: %v", err)
		}
		decoded["$schema"] = "../schemas/a-contract-that-does-not-exist.schema.json"
		encoded, _ := json.MarshalIndent(decoded, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write census: %v", err)
		}
	})
	if _, err := ReadCensus(root); err == nil {
		t.Fatal("ReadCensus accepted a census naming a schema pointer that drifted")
	}
}
