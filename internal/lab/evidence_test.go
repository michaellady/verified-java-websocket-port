package lab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	run := autobahnEvidenceRun{
		Attempted: true, AttemptCount: 1, Completed: true, Executed: true, FirstCaseID: "1.1.1",
		SelectedCount: count, CompletedCount: count, ResultCount: count,
		AttemptStateDigest: intake.DigestBytes([]byte("attempt:" + mode)), AttemptReceiptDigest: intake.DigestBytes([]byte("receipt")), AttemptReceiptBytes: 1,
		ConfigurationDigest: intake.DigestBytes([]byte("configuration:" + mode)), ConfigurationBytes: 1,
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
			value.Client.AttemptCount = 2
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
