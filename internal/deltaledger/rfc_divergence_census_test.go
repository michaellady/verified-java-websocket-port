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
	if member, err := InProtocolRejectionClass(local); err != nil || member {
		t.Fatalf("the class predicate still enrolls us005.pub.0000, a locally initiated send_close(999) with no "+
			"inbound decode; it is selecting by result shape rather than by cause (member=%v err=%v)", member, err)
	}

	inbound, exists := byID["us005.pub.0005"]
	if !exists {
		t.Fatal("us005.pub.0005 is missing from the public corpus")
	}
	if member, err := InProtocolRejectionClass(inbound); err != nil || !member {
		t.Fatalf("the class predicate no longer enrolls us005.pub.0005, the founding member of the class "+
			"(member=%v err=%v)", member, err)
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
	if member, err := InProtocolRejectionClass(odd); err != nil || !member {
		t.Fatalf("a decoder rejection carrying close code 1008 is excluded from the class; the close-code set is "+
			"acting as a membership filter again, which is exactly the defect (member=%v err=%v)", member, err)
	}
}

// TestTheClassPredicateDiscriminatesAMixedStepScenario IS THE ROUND-2
// DISCRIMINATOR, and it is the leg the round-1 test set did not have.
//
// Round one replaced the close-code shape with `counts.input_bytes > 0`. Review
// round 2 found that this is an AGGREGATE over the whole scenario rather than a
// fact about the step that failed, so a VALID inbound frame followed by a local
// `send_close(999)` satisfied every conjunct while its error is locally caused.
// The round-1 test only ever covered the zero-input local case (us005.pub.0000),
// which the aggregate happens to exclude for the wrong reason.
//
// REPRODUCED BEFORE THE FIX, by execution, not by reading: exactly this scenario
// was appended to corpora/public/scenarios.jsonl as us005.pub.0074, enrolled in
// the census, and named by the class record; `deltaledgerctl --check` then
// returned exit 0 with all nineteen rows green, certifying a locally caused
// close as an inbound protocol-decode rejection.
//
// Both directions are asserted. Removing the failing-step binding from
// InProtocolRejectionClass makes the first half fail; weakening it into
// "no action steps anywhere" makes the second half fail.
func TestTheClassPredicateDiscriminatesAMixedStepScenario(t *testing.T) {
	scenarios, err := ReadPublicScenarios(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read public corpus: %v", err)
	}
	byID := map[string]PublicScenario{}
	for _, scenario := range scenarios {
		byID[scenario.ScenarioID] = scenario
	}
	inbound, exists := byID["us005.pub.0005"]
	if !exists {
		t.Fatal("us005.pub.0005 is missing from the public corpus")
	}

	// A valid inbound frame, THEN a local send_close(999) that is what fails.
	// Aggregate input_bytes is nine, so the round-1 predicate enrolled it.
	mixed := inbound
	mixed.ScenarioID = "us005.pub.9001"
	mixed.Steps = append(append([]ScenarioStep(nil), inbound.Steps...),
		ScenarioStep{Kind: "action", Action: "send_close"})
	mixed.Expected.Counts.Actions = 1
	if mixed.Expected.Counts.InputBytes <= 0 {
		t.Fatal("the mixed scenario must carry inbound bytes, or it does not reproduce the finding")
	}
	member, err := InProtocolRejectionClass(mixed)
	if err != nil {
		t.Fatalf("classify the mixed-step scenario: %v", err)
	}
	if member {
		t.Fatal("the class predicate enrolls a scenario whose run STOPPED ON A LOCAL ACTION after a valid inbound " +
			"frame. counts.input_bytes is an aggregate over the whole scenario and cannot say which step failed; " +
			"membership must bind to the failing step")
	}
	index, step, err := FailingStep(mixed)
	if err != nil {
		t.Fatalf("derive the failing step: %v", err)
	}
	if index != 1 || step.Kind != "action" {
		t.Fatalf("the failing step derived as index %d kind %q, expected index 1 kind \"action\"", index, step.Kind)
	}

	// The other direction, so the fix is a DISCRIMINATOR and not a blanket
	// refusal of every scenario that contains an action: a local action that
	// SUCCEEDS before the inbound bytes that fail is still a class member.
	actionFirst := inbound
	actionFirst.ScenarioID = "us005.pub.9002"
	actionFirst.Steps = append([]ScenarioStep{{Kind: "action", Action: "send_text"}}, inbound.Steps...)
	actionFirst.Expected.Counts.Actions = 1
	member, err = InProtocolRejectionClass(actionFirst)
	if err != nil {
		t.Fatalf("classify the action-then-bytes scenario: %v", err)
	}
	if !member {
		t.Fatal("a scenario whose run stopped on INBOUND BYTES after a successful local action is excluded; the " +
			"predicate is refusing action steps rather than binding to the failing step")
	}

	// And the whole gate reports the excluded shape rather than filtering it
	// away silently, which is the round-1 lesson applied to the round-2 fix.
	locally, err := LocallyCausedRejections([]PublicScenario{mixed})
	if err != nil {
		t.Fatalf("report locally caused rejections: %v", err)
	}
	if len(locally) != 1 || !strings.Contains(locally[0], "us005.pub.9001") {
		t.Fatalf("the locally caused rejection is not reported: %v", locally)
	}
}

// TestTheFailingStepDerivationIsUniqueOverTheCommittedCorpus pins that the
// derivation the class predicate depends on actually resolves for every
// committed scenario. If a future corpus change makes a scenario ambiguous, the
// gate refuses it — and this test says so first, with the scenario named.
func TestTheFailingStepDerivationIsUniqueOverTheCommittedCorpus(t *testing.T) {
	scenarios, err := ReadPublicScenarios(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read public corpus: %v", err)
	}
	for _, scenario := range scenarios {
		if _, _, err := FailingStep(scenario); err != nil {
			t.Errorf("%s: %v", scenario.ScenarioID, err)
		}
	}
}

// TestTheCensusRequiresTheExactProposition is the discrimination proof for
// round-2 finding 2.
//
// THE ATTACK, reproduced against the previous rule and READ PASSING before the
// fix: the observable comparison was guarded by `entry.Pointer == "/final_state"`
// and nothing required that pointer, so rewriting one row's pointer to
// `/counts/wire_buffered_bytes` and its recorded_observable to a sentence that
// matches nothing skipped the comparison entirely. `deltaledgerctl --check`
// returned exit 0, with enrollment and ledger coverage still passing by
// scenario id.
func TestTheCensusRequiresTheExactProposition(t *testing.T) {
	for _, attack := range []struct {
		name      string
		pointer   string
		value     string
		mustMatch string
	}{
		{
			name:      "an unrelated but syntactically valid pointer",
			pointer:   "/counts/wire_buffered_bytes",
			value:     "this value is asserted of nothing the gate can resolve",
			mustMatch: "enrols in the protocol-rejection-readystate class but points at",
		},
		{
			name:      "a pointer that does not resolve at all",
			pointer:   "/a/pointer/that/is/not/there",
			value:     "open",
			mustMatch: "does not resolve against the recorded expectation",
		},
		{
			name:      "the right pointer with the wrong value",
			pointer:   "/final_state",
			value:     "closed",
			mustMatch: "census records \"closed\" but the corpus expectation is \"open\"",
		},
	} {
		t.Run(attack.name, func(t *testing.T) {
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
					t.Fatal("census has no entries to attack")
				}
				row, _ := entries[0].(map[string]any)
				row["pointer"] = attack.pointer
				row["recorded_observable"] = attack.value
				encoded, err := json.MarshalIndent(document, "", "  ")
				if err != nil {
					t.Fatalf("encode census: %v", err)
				}
				if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
					t.Fatalf("write census: %v", err)
				}
			})
			err := VerifyCensusRowsMatchEvidence(root)
			if err == nil {
				t.Fatal("the census accepted a row whose proposition it never checked; requiring the exact " +
					"pointer AND value is the whole point")
			}
			if !strings.Contains(err.Error(), attack.mustMatch) {
				t.Fatalf("refused, but not on the substituted proposition; got: %v", err)
			}
		})
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
