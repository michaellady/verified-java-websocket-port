package lab

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const evidenceTestRoot = "sha256:5713245496362ece061c769bc4ee8eb909bfcc6d7d319bc3fc9b750f6e0a4ad8"

func evidenceDocument(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "evidence", "java", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func blockedEvidenceDocuments(t *testing.T) BaselineEvidenceDocuments {
	t.Helper()
	return BaselineEvidenceDocuments{
		Build: evidenceDocument(t, "build.json"), Adapter: evidenceDocument(t, "adapter-baseline.json"),
		Tests: evidenceDocument(t, "test-manifest.json"), Autobahn: evidenceDocument(t, "autobahn-baseline.json"),
		Ledger: evidenceDocument(t, "behavior-delta-ledger.json"),
	}
}

// unclassedForTest is the residual a synthetic chain must publish. Synthetic
// deltas carry no mismatch class, so it is simply their count; it is written as
// a helper rather than a literal so a fixture that grows a record cannot drift.
func unclassedForTest(records []BehaviorLedgerRecord) int {
	count := 0
	for _, record := range records {
		if record.Delta.MismatchClass == "" {
			count++
		}
	}
	return count
}

func canonicalEvidence(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := intake.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func readyEvidenceDocuments(t *testing.T) BaselineEvidenceDocuments {
	t.Helper()
	documents := blockedEvidenceDocuments(t)
	var build buildEvidence
	var adapter adapterEvidence
	var tests testEvidence
	var autobahn autobahnEvidence
	var ledger ledgerEvidence
	for _, item := range []struct {
		raw []byte
		out any
	}{{documents.Build, &build}, {documents.Adapter, &adapter}, {documents.Tests, &tests}, {documents.Autobahn, &autobahn}, {documents.Ledger, &ledger}} {
		if err := intake.DecodeStrict(item.raw, item.out); err != nil {
			t.Fatal(err)
		}
	}
	zero := 0
	build.Status = "PASS"
	build.Cache.ClosureFrozen = true
	build.Cache.OfflineAuthoritativeRun = true
	build.Cache.Qualification = "QUALIFIED_NOT_PROMOTED"
	build.Sandbox.EnforcementStatus = "VERIFIED"
	build.Build.Executed = true
	build.Build.ExitCode = &zero
	build.Build.TestsExecuted = true
	build.Blockers = []EvidenceFinding{}
	adapter.Status = "PASS"
	adapter.AuthoritativeSandboxRun = true
	tests.Status = "PASS"
	tests.InventoryStatus = "RECONCILED"
	tests.Blocker = nil
	autobahn.Status = "PASS"
	autobahn.Registry.StaticExpansionComplete = true
	autobahn.Blocker = nil
	caseIDs := []string{"1.1", "2.1", "3.1", "4.1", "5.1", "6.1.1", "7.1", "10.1"}
	for index := len(caseIDs); index < AutobahnSelectedCaseCount; index++ {
		caseIDs = append(caseIDs, fmt.Sprintf("6.99.%d", index))
	}
	autobahn.Client = readyAutobahnEvidenceRun(t, "client", caseIDs)
	autobahn.Server = readyAutobahnEvidenceRun(t, "server", caseIDs)
	ledger.Status = "READY"
	documents.Build = canonicalEvidence(t, build)
	documents.Adapter = canonicalEvidence(t, adapter)
	documents.Tests = canonicalEvidence(t, tests)
	documents.Autobahn = canonicalEvidence(t, autobahn)
	documents.Ledger = canonicalEvidence(t, ledger)
	return documents
}

func readyAutobahnEvidenceRun(t *testing.T, mode string, ids []string) autobahnEvidenceRun {
	t.Helper()
	count := len(ids)
	originalBlocker := EvidenceFinding{Code: "ORIGINAL_ATTEMPT_BLOCKED", Detail: "the original attempt was retained before the authorized remediation"}
	originalReceipt := intake.DigestBytes([]byte("original-receipt:" + mode))
	run := autobahnEvidenceRun{
		Attempted: true, AttemptCount: 2, Completed: true, Executed: true, FirstCaseID: "1.1.1",
		SelectedCount: count, CompletedCount: count, ResultCount: count,
		AttemptStateDigest: intake.DigestBytes([]byte("attempt:" + mode)), AttemptReceiptDigest: originalReceipt, AttemptReceiptBytes: 1,
		ConfigurationDigest: intake.DigestBytes([]byte("configuration:" + mode)), ConfigurationBytes: 1,
		Attempts: []autobahnEvidenceAttempt{
			{Sequence: 1, Classification: "ORIGINAL_AUTHORITATIVE", PlanDigest: intake.DigestBytes([]byte("original-plan:" + mode)), ReceiptDigest: originalReceipt, ReceiptBytes: 1, Blocker: &originalBlocker},
			{Sequence: 2, Classification: "OWNER_AUTHORIZED_REMEDIATION", PlanDigest: intake.DigestBytes([]byte("remediated-plan:" + mode)), ReceiptDigest: intake.DigestBytes([]byte("remediated-receipt:" + mode)), ReceiptBytes: 1, Completed: true, Executed: true, CompletedCount: count, ResultCount: count},
		},
	}
	for _, id := range ids {
		result := AutobahnResult{CaseID: id, Status: "OK", ResultDigest: intake.DigestBytes([]byte("result:" + id)), ObservationDigest: intake.DigestBytes([]byte("observation:" + id))}
		var err error
		result.BindingDigest, err = AutobahnResultBindingDigest(mode, result)
		if err != nil {
			t.Fatal(err)
		}
		run.Results = append(run.Results, result)
	}
	return run
}

func TestVerifyBaselineEvidenceAcceptsHonestBlockedAndExactReadySets(t *testing.T) {
	blocked, err := VerifyBaselineEvidence(evidenceTestRoot, blockedEvidenceDocuments(t))
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Status != "BLOCKED" || len(blocked.Blockers) < 2 {
		t.Fatalf("blocked report = %+v", blocked)
	}
	ready, err := VerifyBaselineEvidence(evidenceTestRoot, readyEvidenceDocuments(t))
	if err != nil {
		t.Fatal(err)
	}
	if ready.Status != "READY" || len(ready.Blockers) != 0 {
		t.Fatalf("ready report = %+v", ready)
	}
}

func TestCommittedAutobahnEvidenceRetainsBothAttemptsAndClosesReruns(t *testing.T) {
	raw := evidenceDocument(t, "autobahn-baseline.json")
	if strings.Contains(string(raw), "/private/") {
		t.Fatal("committed Autobahn evidence contains a runtime-private absolute path")
	}
	var value struct {
		Status string `json:"status"`
		Client struct {
			AttemptCount int `json:"attempt_count"`
			Attempts     []struct {
				Sequence       int              `json:"sequence"`
				Classification string           `json:"classification"`
				PlanDigest     string           `json:"plan_digest"`
				ReceiptDigest  string           `json:"receipt_digest"`
				ReceiptBytes   int              `json:"receipt_bytes"`
				Executed       bool             `json:"executed"`
				CompletedCount int              `json:"completed_count"`
				ResultCount    int              `json:"result_count"`
				Blocker        *EvidenceFinding `json:"blocker"`
			} `json:"attempts"`
		} `json:"client"`
		Server struct {
			AttemptCount int `json:"attempt_count"`
			Attempts     []struct {
				Sequence       int              `json:"sequence"`
				Classification string           `json:"classification"`
				PlanDigest     string           `json:"plan_digest"`
				ReceiptDigest  string           `json:"receipt_digest"`
				ReceiptBytes   int              `json:"receipt_bytes"`
				Executed       bool             `json:"executed"`
				CompletedCount int              `json:"completed_count"`
				ResultCount    int              `json:"result_count"`
				Blocker        *EvidenceFinding `json:"blocker"`
			} `json:"attempts"`
		} `json:"server"`
		RerunDisposition struct {
			AuthorizedRemediationAttemptsPerMode int    `json:"authorized_remediation_attempts_per_mode"`
			ConsumedRemediationAttemptsPerMode   int    `json:"consumed_remediation_attempts_per_mode"`
			OriginalReceiptRetained              bool   `json:"original_receipt_retained"`
			FurtherRerunsAuthorized              bool   `json:"further_reruns_authorized"`
			Disposition                          string `json:"disposition"`
		} `json:"rerun_disposition"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	const originalPlan = "sha256:53a10ae09a728b63471e5298be777c5e86a5b2f525b43ce247787df9e2139173"
	const originalReceipt = "sha256:ca942585442eb4be74a62533fa2b44a985970612ce6f69d5c13df8ede83c6cff"
	const remediatedPlan = "sha256:a94500dee3959f14941a749e04fe53b4679dd84041449e45a22572fb296a56f5"
	const remediatedReceipt = "sha256:ebb5157aa8ba6c7998dfce303acfbd5c4af166a8d377441e0709b481c26e44b2"
	for mode, run := range map[string]struct {
		count    int
		attempts []struct {
			Sequence       int              `json:"sequence"`
			Classification string           `json:"classification"`
			PlanDigest     string           `json:"plan_digest"`
			ReceiptDigest  string           `json:"receipt_digest"`
			ReceiptBytes   int              `json:"receipt_bytes"`
			Executed       bool             `json:"executed"`
			CompletedCount int              `json:"completed_count"`
			ResultCount    int              `json:"result_count"`
			Blocker        *EvidenceFinding `json:"blocker"`
		}
	}{"client": {value.Client.AttemptCount, value.Client.Attempts}, "server": {value.Server.AttemptCount, value.Server.Attempts}} {
		if run.count != 2 || len(run.attempts) != 2 {
			t.Fatalf("%s attempt history = count %d entries %d, want exactly two", mode, run.count, len(run.attempts))
		}
		original, remediated := run.attempts[0], run.attempts[1]
		if original.Sequence != 1 || original.Classification != "ORIGINAL_AUTHORITATIVE" || original.PlanDigest != originalPlan || original.ReceiptDigest != originalReceipt || original.ReceiptBytes != 18920 || original.Executed || original.CompletedCount != 0 || original.ResultCount != 0 || original.Blocker == nil {
			t.Fatalf("%s original attempt was not retained exactly: %+v", mode, original)
		}
		if remediated.Sequence != 2 || remediated.Classification != "OWNER_AUTHORIZED_REMEDIATION" || remediated.PlanDigest != remediatedPlan || remediated.ReceiptDigest != remediatedReceipt || remediated.ReceiptBytes != 20123 || remediated.Executed || remediated.CompletedCount != 0 || remediated.ResultCount != 0 || remediated.Blocker == nil {
			t.Fatalf("%s remediated attempt was not retained exactly: %+v", mode, remediated)
		}
	}
	disposition := value.RerunDisposition
	if value.Status != "BLOCKED" || disposition.AuthorizedRemediationAttemptsPerMode != 1 || disposition.ConsumedRemediationAttemptsPerMode != 1 || !disposition.OriginalReceiptRetained || disposition.FurtherRerunsAuthorized || disposition.Disposition != "NO_FURTHER_RERUNS_AUTHORIZED" {
		t.Fatalf("invalid terminal rerun disposition: status=%s disposition=%+v", value.Status, disposition)
	}
	readiness, err := VerifyBaselineEvidence(evidenceTestRoot, blockedEvidenceDocuments(t))
	if err != nil {
		t.Fatal(err)
	}
	if readiness.Status != "BLOCKED" {
		t.Fatalf("aggregate readiness = %s, want BLOCKED", readiness.Status)
	}
}

func TestVerifyBaselineEvidenceRejectsContradictoryAndHostileClaims(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *BaselineEvidenceDocuments){
		"wrong root": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value buildEvidence
			mustDecodeEvidence(t, documents.Build, &value)
			value.AcceptedRootDigest = intake.DigestBytes([]byte("wrong root"))
			documents.Build = canonicalEvidence(t, value)
		},
		"unavailable enforcement": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value buildEvidence
			mustDecodeEvidence(t, documents.Build, &value)
			value.Sandbox.EnforcementStatus = "UNAVAILABLE"
			documents.Build = canonicalEvidence(t, value)
		},
		"unfrozen Maven closure": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value buildEvidence
			mustDecodeEvidence(t, documents.Build, &value)
			value.Cache.ClosureFrozen = false
			documents.Build = canonicalEvidence(t, value)
		},
		"online Maven authority": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value buildEvidence
			mustDecodeEvidence(t, documents.Build, &value)
			value.Cache.OfflineAuthoritativeRun = false
			documents.Build = canonicalEvidence(t, value)
		},
		"blocking PASS": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value buildEvidence
			mustDecodeEvidence(t, documents.Build, &value)
			value.Blockers = []EvidenceFinding{{Code: "STILL_BLOCKED", Detail: "blocking condition remains"}}
			documents.Build = canonicalEvidence(t, value)
		},
		"false independent-review claim": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value buildEvidence
			mustDecodeEvidence(t, documents.Build, &value)
			value.IndependentReviewClaimed = true
			documents.Build = canonicalEvidence(t, value)
		},
		"mismatched tests": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value testEvidence
			mustDecodeEvidence(t, documents.Tests, &value)
			value.Counts.Executed--
			documents.Tests = canonicalEvidence(t, value)
		},
		"skipped tests": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value testEvidence
			mustDecodeEvidence(t, documents.Tests, &value)
			value.Counts.Skipped = 1
			documents.Tests = canonicalEvidence(t, value)
		},
		"unexecuted Autobahn": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value autobahnEvidence
			mustDecodeEvidence(t, documents.Autobahn, &value)
			value.Client.Executed = false
			documents.Autobahn = canonicalEvidence(t, value)
		},
		"Autobahn independent-review claim": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value autobahnEvidence
			mustDecodeEvidence(t, documents.Autobahn, &value)
			value.IndependentReviewClaimed = true
			documents.Autobahn = canonicalEvidence(t, value)
		},
		"replayed Autobahn attempt": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value autobahnEvidence
			mustDecodeEvidence(t, documents.Autobahn, &value)
			value.Client.AttemptCount = 3
			documents.Autobahn = canonicalEvidence(t, value)
		},
		"removed authorized remediation history": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value autobahnEvidence
			mustDecodeEvidence(t, documents.Autobahn, &value)
			value.Client.Attempts = value.Client.Attempts[:1]
			documents.Autobahn = canonicalEvidence(t, value)
		},
		"mutated authorized remediation receipt": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value autobahnEvidence
			mustDecodeEvidence(t, documents.Autobahn, &value)
			value.Client.Attempts[1].ReceiptDigest = "sha256:mutated"
			documents.Autobahn = canonicalEvidence(t, value)
		},
		"further Autobahn rerun authorized": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value autobahnEvidence
			mustDecodeEvidence(t, documents.Autobahn, &value)
			value.RerunDisposition.FurtherRerunsAuthorized = true
			documents.Autobahn = canonicalEvidence(t, value)
		},
		"mutated Autobahn attempt receipt": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value autobahnEvidence
			mustDecodeEvidence(t, documents.Autobahn, &value)
			value.Client.AttemptReceiptDigest = "sha256:mutated"
			documents.Autobahn = canonicalEvidence(t, value)
		},
		"nonterminal Autobahn": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value autobahnEvidence
			mustDecodeEvidence(t, documents.Autobahn, &value)
			value.Client.Results[0].Status = "NOT_RUN"
			documents.Autobahn = canonicalEvidence(t, value)
		},
		"unledgered terminal disagreement": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value autobahnEvidence
			mustDecodeEvidence(t, documents.Autobahn, &value)
			value.Client.Results[0].Status = "FAILED"
			binding, err := AutobahnResultBindingDigest("client", value.Client.Results[0])
			if err != nil {
				t.Fatal(err)
			}
			value.Client.Results[0].BindingDigest = binding
			documents.Autobahn = canonicalEvidence(t, value)
		},
		"unledgered disagreement": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			var value ledgerEvidence
			mustDecodeEvidence(t, documents.Ledger, &value)
			value.UnledgeredDisagreements = 1
			documents.Ledger = canonicalEvidence(t, value)
		},
		"premature ledger ready": func(t *testing.T, documents *BaselineEvidenceDocuments) {
			blocked := blockedEvidenceDocuments(t)
			var value ledgerEvidence
			mustDecodeEvidence(t, blocked.Ledger, &value)
			value.Status = "READY"
			documents.Build, documents.Adapter, documents.Tests, documents.Autobahn = blocked.Build, blocked.Adapter, blocked.Tests, blocked.Autobahn
			documents.Ledger = canonicalEvidence(t, value)
		},
	} {
		t.Run(name, func(t *testing.T) {
			documents := readyEvidenceDocuments(t)
			mutate(t, &documents)
			if _, err := VerifyBaselineEvidence(evidenceTestRoot, documents); err == nil {
				t.Fatal("hostile or contradictory evidence accepted")
			}
		})
	}
}

func TestVerifyBaselineEvidenceStrictlyRejectsUnknownFields(t *testing.T) {
	documents := blockedEvidenceDocuments(t)
	documents.Build = append(documents.Build[:len(documents.Build)-2], []byte(`,"unknown":true}`)...)
	_, err := VerifyBaselineEvidence(evidenceTestRoot, documents)
	if err == nil {
		t.Fatal("unknown evidence field accepted")
	}
	var findingValue *intake.Finding
	if !errors.As(err, &findingValue) {
		t.Fatalf("error does not preserve typed finding: %T %v", err, err)
	}
}

func TestJavaTestEvidenceBindsExactInventoryDefaultPolicyAndOverlay(t *testing.T) {
	defaultPolicy := evidenceDocument(t, "default-policy-behavior.json")
	if _, err := DecodeDefaultPolicyEvidence(defaultPolicy); err != nil {
		t.Fatal(err)
	}
	inventory := evidenceDocument(t, "test-inventory.json")
	if _, err := DecodeTestInventory(inventory); err != nil {
		t.Fatal(err)
	}
	overlay := evidenceDocument(t, mavenTestSecurityOverlayName)
	if string(overlay) != mavenTestSecurityOverlay || intake.DigestBytes(overlay) != mavenTestSecurityOverlayDigest {
		t.Fatal("committed overlay differs from its exact compiled pin")
	}
	var manifest testEvidence
	mustDecodeEvidence(t, evidenceDocument(t, "test-manifest.json"), &manifest)
	if manifest.Inventory.Digest != intake.DigestBytes(inventory) || manifest.TestPolicy.DefaultPolicyEvidenceDigest != intake.DigestBytes(defaultPolicy) {
		t.Fatal("test manifest does not content-bind inventory and default-policy evidence")
	}
	if _, err := DecodeDefaultPolicyEvidence(append(defaultPolicy[:len(defaultPolicy)-2], []byte(`,"unknown":true}`)...)); err == nil {
		t.Fatal("unknown default-policy evidence field accepted")
	}
}

func mustDecodeEvidence(t *testing.T, raw []byte, out any) {
	t.Helper()
	if err := intake.DecodeStrict(raw, out); err != nil {
		t.Fatal(err)
	}
}

// TestReadinessRefusesAWithdrawnRecordAsCoverage IS THE DISCRIMINATION PROOF FOR
// ROUND-2 FINDING 6, and it is about the one consumer whose opinion decides
// release readiness.
//
// THE GAP, reproduced by execution before the fix: internal/deltaledger made
// supersession machine-visible — a structured Supersedes list, a canonical
// SUPERSEDES token inside each correcting record's hashed rationale, a committed
// sidecar, and AuthoritativeSequences — but validateAggregateDisagreementLedger
// built its Autobahn coverage map from `ledger.Records`, every record, withdrawn
// or not. So a WITHDRAWN record went on covering a live non-OK Autobahn
// behaviour and this gate returned READY. With the coverage map reverted to
// `ledger.Records` this test reads:
//
//	readiness accepted a non-OK Autobahn result whose only covering record is
//	SUPERSEDED (status=READY)
//
// The chain below is synthesised rather than borrowed from the committed
// evidence, because the committed chain's superseded records bind the
// non-execution Autobahn markers and could not exhibit the failure.
func TestReadinessRefusesAWithdrawnRecordAsCoverage(t *testing.T) {
	documents := readyEvidenceDocuments(t)
	var autobahn autobahnEvidence
	var ledger ledgerEvidence
	mustDecodeEvidence(t, documents.Autobahn, &autobahn)
	mustDecodeEvidence(t, documents.Ledger, &ledger)

	// One live, non-OK terminal Autobahn behaviour.
	failing := &autobahn.Client.Results[0]
	failing.Status = "FAILED"
	binding, err := AutobahnResultBindingDigest("client", *failing)
	if err != nil {
		t.Fatal(err)
	}
	failing.BindingDigest = binding

	// A two-record chain: the first binds that behaviour, the second supersedes
	// the first. The first is therefore WITHDRAWN and covers nothing.
	withdrawn := syntheticDelta(t, "org.java-websocket.test.withdrawn-coverage", binding, "", nil)
	correction := syntheticDelta(t, "org.java-websocket.test.correcting-record",
		DigestBytesForTest("no executed autobahn observation"), "", &withdrawn)

	directory := filepath.Join(t.TempDir(), "ledger")
	head := GenesisLedgerHead
	for _, delta := range []BehaviorDelta{withdrawn, correction} {
		head, err = AppendBehaviorDelta(directory, head, delta)
		if err != nil {
			t.Fatalf("append %s: %v", delta.SubjectRef, err)
		}
	}
	records, verifiedHead, err := ReadBehaviorLedger(directory)
	if err != nil {
		t.Fatalf("read the synthetic chain: %v", err)
	}
	links, err := ReadSupersessionLinks(records)
	if err != nil {
		t.Fatalf("read the synthetic chain's supersessions: %v", err)
	}
	if len(links) != 1 || links[0].SupersededSequence != 1 {
		t.Fatalf("the synthetic chain does not record record 1 as superseded: %+v", links)
	}
	ledger.Records = records
	ledger.Head = verifiedHead
	ledger.Supersessions = links
	// The synthetic chain replaces the committed one, so the 1.2.0 residual has
	// to be recomputed for it. Leaving the committed document's number here
	// would make the readiness gate refuse on THAT mismatch instead of on the
	// withdrawn record, and this test would then pass for the wrong reason.
	ledger.RecordsWithoutMismatchClass = unclassedForTest(records)
	documents.Autobahn = canonicalEvidence(t, autobahn)
	documents.Ledger = canonicalEvidence(t, ledger)

	readiness, err := VerifyBaselineEvidence(evidenceTestRoot, documents)
	if err == nil {
		t.Fatalf("readiness accepted a non-OK Autobahn result whose only covering record is SUPERSEDED (status=%s). "+
			"A withdrawn record must not be authoritative to the consumer that decides release readiness; that is the "+
			"whole point of making supersession machine-visible", readiness.Status)
	}
	if !strings.Contains(err.Error(), "UNLEDGERED_BEHAVIOR_DISAGREEMENT") {
		t.Fatalf("readiness refused, but not on the unledgered behaviour; got: %v", err)
	}

	// The other direction, so this is a DISCRIMINATOR and not a blanket refusal:
	// the same chain with the supersession removed DOES cover the behaviour.
	authoritative := syntheticDelta(t, "org.java-websocket.test.correcting-record",
		DigestBytesForTest("no executed autobahn observation"), "", nil)
	plainDirectory := filepath.Join(t.TempDir(), "ledger")
	plainHead := GenesisLedgerHead
	for _, delta := range []BehaviorDelta{withdrawn, authoritative} {
		plainHead, err = AppendBehaviorDelta(plainDirectory, plainHead, delta)
		if err != nil {
			t.Fatalf("append %s: %v", delta.SubjectRef, err)
		}
	}
	plainRecords, plainVerified, err := ReadBehaviorLedger(plainDirectory)
	if err != nil {
		t.Fatalf("read the un-superseded chain: %v", err)
	}
	ledger.Records = plainRecords
	ledger.Head = plainVerified
	ledger.Supersessions = []SupersessionLink{}
	ledger.RecordsWithoutMismatchClass = unclassedForTest(plainRecords)
	documents.Ledger = canonicalEvidence(t, ledger)
	readiness, err = VerifyBaselineEvidence(evidenceTestRoot, documents)
	if err != nil {
		t.Fatalf("readiness refused a non-OK Autobahn result that an AUTHORITATIVE record covers: %v", err)
	}
	if readiness.Status != "READY" {
		t.Fatalf("readiness returned %s where the covering record is authoritative", readiness.Status)
	}
}

// TestReadinessRefusesADeclaredSupersessionArrayThatTheRecordsDoNotCarry pins
// the other half of the 1.1.0 addition: the declared array is checked against
// the links the hashed rationales carry, so the gate cannot be TOLD that
// nothing is superseded.
func TestReadinessRefusesADeclaredSupersessionArrayThatTheRecordsDoNotCarry(t *testing.T) {
	documents := readyEvidenceDocuments(t)
	var ledger ledgerEvidence
	mustDecodeEvidence(t, documents.Ledger, &ledger)
	if len(ledger.Supersessions) == 0 {
		t.Fatal("the committed ledger declares no supersessions; this test needs at least one to remove")
	}
	ledger.Supersessions = []SupersessionLink{}
	documents.Ledger = canonicalEvidence(t, ledger)
	if _, err := VerifyBaselineEvidence(evidenceTestRoot, documents); err == nil {
		t.Fatal("readiness accepted a ledger document declaring no supersessions while its records carry them")
	} else if !strings.Contains(err.Error(), "BEHAVIOR_LEDGER_SUPERSESSION_MISMATCH") {
		t.Fatalf("readiness refused, but not on the supersession mismatch; got: %v", err)
	}
}

// TestReadinessRefusesAnUnderstatedMismatchClassResidual pins the 1.2.0
// addition. The residual is deliberately NOT required to be zero — forty-nine
// records were sealed before the mismatch-class axis existed and their digest
// preimages cannot be altered to carry one — so the only thing standing between
// "the residual is published" and "the residual is a number nobody checks" is
// that the readiness gate RECOMPUTES it. Without this test, deleting that
// recomputation would leave every suite green.
func TestReadinessRefusesAnUnderstatedMismatchClassResidual(t *testing.T) {
	documents := readyEvidenceDocuments(t)
	var ledger ledgerEvidence
	mustDecodeEvidence(t, documents.Ledger, &ledger)
	if ledger.RecordsWithoutMismatchClass == 0 {
		t.Fatal("the committed ledger publishes a zero residual; this test needs a nonzero one to understate")
	}
	ledger.RecordsWithoutMismatchClass = 0
	documents.Ledger = canonicalEvidence(t, ledger)
	if _, err := VerifyBaselineEvidence(evidenceTestRoot, documents); err == nil {
		t.Fatal("readiness accepted a ledger document publishing records_without_mismatch_class=0 over a chain " +
			"whose records carry no class. A residual the gate does not recompute can be set to anything, which is " +
			"the fake-gate shape unledgered_disagreements already had once")
	} else if !strings.Contains(err.Error(), "records_without_mismatch_class") {
		t.Fatalf("readiness refused, but not on the residual; got: %v", err)
	}

	// The other direction, so this is a discriminator rather than a blanket
	// refusal of the field: the honest number is accepted.
	ledger.RecordsWithoutMismatchClass = unclassedForTest(ledger.Records)
	documents.Ledger = canonicalEvidence(t, ledger)
	if _, err := VerifyBaselineEvidence(evidenceTestRoot, documents); err != nil {
		t.Fatalf("readiness refused the recomputed residual: %v", err)
	}
}

// DigestBytesForTest is a thin alias so the synthetic deltas above read clearly.
func DigestBytesForTest(value string) string { return intake.DigestBytes([]byte(value)) }

// syntheticDelta builds a valid BehaviorDelta for the readiness proofs. When
// supersedes is non-nil the rationale carries the canonical SUPERSEDES token, in
// exactly the form internal/deltaledger emits it.
func syntheticDelta(t *testing.T, subject, autobahnResultDigest string, _ string, supersedes *BehaviorDelta) BehaviorDelta {
	t.Helper()
	rationale := "SYNTHETIC readiness-gate proof record for " + subject + "."
	if supersedes != nil {
		rationale = "SUPERSEDES ledger-sequence=1 delta=" + supersedes.DeltaID + " subject=" + supersedes.SubjectRef +
			" reason=synthetic; " + rationale
	}
	disagreement := ObservedDisagreement{
		SubjectRef:            "semantic:" + subject + ":provisional-v1",
		RFCRefs:               []string{"rfc6455#section-5.2"},
		RFCExpectationDigest:  DigestBytesForTest("rfc expectation " + subject),
		RFCValueDigest:        DigestBytesForTest("rfc value " + subject),
		JavaRef:               "java-v1.6.0:org.java_websocket.WebSocketImpl:decodeFrames",
		JavaObservationDigest: DigestBytesForTest("java observation " + subject),
		JavaValueDigest:       DigestBytesForTest("java value " + subject),
		AutobahnRefs:          []string{"autobahn-v25.10.1:1.1"},
		AutobahnResultDigest:  autobahnResultDigest,
		AutobahnValueDigest:   DigestBytesForTest("autobahn value " + subject),
	}
	digest, err := disagreement.Digest()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := BehaviorDeltaID(digest)
	if err != nil {
		t.Fatal(err)
	}
	delta := BehaviorDelta{
		SchemaVersion: "1.0.0", DeltaID: identity, SubjectRef: disagreement.SubjectRef,
		RFCRefs: disagreement.RFCRefs, RFCExpectationDigest: disagreement.RFCExpectationDigest,
		RFCValueDigest: disagreement.RFCValueDigest, JavaRef: disagreement.JavaRef,
		JavaObservationDigest: disagreement.JavaObservationDigest, JavaValueDigest: disagreement.JavaValueDigest,
		AutobahnRefs: disagreement.AutobahnRefs, AutobahnResultDigest: disagreement.AutobahnResultDigest,
		AutobahnValueDigest: disagreement.AutobahnValueDigest, DisagreementDigest: digest,
		NormativeAuthority: "rfc6455", Disposition: "unresolved", Rationale: rationale,
	}
	if err := delta.Validate(); err != nil {
		t.Fatalf("synthetic delta for %s does not validate: %v", subject, err)
	}
	return delta
}
