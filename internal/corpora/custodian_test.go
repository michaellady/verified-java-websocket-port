package corpora

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestLedger(t *testing.T) *Ledger {
	t.Helper()
	ledger, err := NewLedger(DefaultCustodianPolicy(), 1)
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}
	return ledger
}

// Query and diagnostic budgets only decrease; exhaustion denies further use.
func TestLedgerBudgetsAreMonotonic(t *testing.T) {
	policy := DefaultCustodianPolicy()
	policy.QueryBudget = 2
	policy.DiagnosticBudget = 1
	ledger, err := NewLedger(policy, 1)
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}
	if err := ledger.RecordQuery("us005.hid.0001", "q1"); err != nil {
		t.Fatalf("query 1: %v", err)
	}
	if err := ledger.RecordQuery("us005.hid.0002", "q2"); err != nil {
		t.Fatalf("query 2: %v", err)
	}
	if err := ledger.RecordQuery("us005.hid.0003", "q3"); err == nil {
		t.Fatal("exhausted query budget must deny")
	}
	if err := ledger.RecordDiagnostic("us005.hid.0001", "d1"); err != nil {
		t.Fatalf("diagnostic 1: %v", err)
	}
	if err := ledger.RecordDiagnostic("us005.hid.0002", "d2"); err == nil {
		t.Fatal("exhausted diagnostic budget must deny")
	}
	remaining := ledger.Remaining()
	if remaining.Query != 0 || remaining.Diagnostic != 0 {
		t.Fatalf("remaining = %+v", remaining)
	}
}

// The ledger is a hash chain: serialization round-trips and tampering with
// any entry breaks verification.
func TestLedgerHashChainDetectsTamper(t *testing.T) {
	ledger := newTestLedger(t)
	for i := 0; i < 5; i++ {
		if err := ledger.RecordQuery("us005.hid.000"+string(rune('1'+i)), "q"+string(rune('a'+i))); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	serialized, err := ledger.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	restored, err := LoadLedger(serialized)
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	if err := restored.VerifyChain(); err != nil {
		t.Fatalf("fresh chain must verify: %v", err)
	}
	tampered := strings.Replace(string(serialized), `"op":"query"`, `"op":"diagnostic"`, 1)
	if tampered == string(serialized) {
		t.Fatal("tamper probe found nothing")
	}
	if _, err := LoadLedger([]byte(tampered)); err == nil {
		t.Fatal("tampered ledger must fail to load")
	}
}

// Probing: repeated near-identical queries trip detection and lock the
// custodian until rotation.
func TestLedgerProbingDetectionLocksUntilRotation(t *testing.T) {
	policy := DefaultCustodianPolicy()
	policy.RepeatThreshold = 3
	ledger, err := NewLedger(policy, 1)
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}
	if err := ledger.RecordQuery("us005.hid.0001", "same-shape"); err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordQuery("us005.hid.0001", "same-shape"); err != nil {
		t.Fatal(err)
	}
	err = ledger.RecordQuery("us005.hid.0001", "same-shape")
	if err == nil || !strings.Contains(err.Error(), "PROBING") {
		t.Fatalf("third identical query must trip probing detection, got %v", err)
	}
	if !ledger.ProbingDetected() {
		t.Fatal("probing flag must latch")
	}
	if err := ledger.RecordQuery("us005.hid.0002", "different"); err == nil {
		t.Fatal("locked custodian must deny all queries until rotation")
	}
	if err := ledger.Rotate(2); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if ledger.Epoch() != 2 {
		t.Fatalf("epoch = %d", ledger.Epoch())
	}
	if err := ledger.RecordQuery("us005.hid.0002", "different"); err != nil {
		t.Fatalf("rotation must restore service: %v", err)
	}
}

// Canary leak detection: any public artifact containing a canary token is a
// held-out leak finding.
func TestDetectCanaryLeak(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	clean := [][]byte{[]byte("ordinary public artifact"), []byte("nothing to see")}
	if findings := DetectCanaryLeak(clean, generated.CanaryTokens); len(findings) != 0 {
		t.Fatalf("clean artifacts flagged: %v", findings)
	}
	var anyToken string
	for _, token := range generated.CanaryTokens {
		anyToken = token
		break
	}
	leaky := [][]byte{[]byte("prefix " + anyToken + " suffix")}
	findings := DetectCanaryLeak(leaky, generated.CanaryTokens)
	if len(findings) != 1 {
		t.Fatalf("leak not detected: %v", findings)
	}
}

// The policy document serializes deterministically and carries the budgets,
// rotation, probing, and canary mechanics plus honest assurance labels.
func TestCustodianPolicyDocument(t *testing.T) {
	first, err := CustodianPolicyDocument(DefaultCustodianPolicy(), 1)
	if err != nil {
		t.Fatalf("CustodianPolicyDocument: %v", err)
	}
	second, err := CustodianPolicyDocument(DefaultCustodianPolicy(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("policy document must serialize deterministically")
	}
	text := string(first)
	for _, needle := range []string{"query_budget", "diagnostic_budget", "rotation",
		"probing", "canaries", "OWNER_ATTESTED_NOT_INDEPENDENT",
		"\"independent_review_claimed\":false"} {
		if !strings.Contains(text, needle) {
			t.Fatalf("policy document lacks %s", needle)
		}
	}
}

// Every rejected attempt appends a hash-chained denial entry so post-lockout
// probing stays auditable: reason, digest, scenario ref, actor, and time.
func TestLedgerPersistsDenialEntries(t *testing.T) {
	policy := DefaultCustodianPolicy()
	policy.QueryBudget = 1
	policy.DiagnosticBudget = 1
	ledger, err := NewLedger(policy, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordQuery("us005.hid.0001", "q1"); err != nil {
		t.Fatal(err)
	}
	entriesBefore := len(ledger.Entries())
	if err := ledger.RecordQuery("us005.hid.0002", "q2"); err == nil {
		t.Fatal("exhausted budget must deny")
	}
	entries := ledger.Entries()
	if len(entries) != entriesBefore+1 {
		t.Fatalf("denied query must append an entry: %d -> %d", entriesBefore, len(entries))
	}
	denial := entries[len(entries)-1]
	if denial.Op != "query_denied" || denial.Reason != "QUERY_BUDGET_EXHAUSTED" ||
		denial.QueryDigest != "q2" || denial.ScenarioRef != "us005.hid.0002" ||
		denial.At == "" || denial.Actor == "" {
		t.Fatalf("denial entry = %+v", denial)
	}
	if err := ledger.RecordDiagnostic("us005.hid.0001", "d1"); err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordDiagnostic("us005.hid.0001", "d2"); err == nil {
		t.Fatal("exhausted diagnostic budget must deny")
	}
	entries = ledger.Entries()
	if entries[len(entries)-1].Op != "diagnostic_denied" ||
		entries[len(entries)-1].Reason != "DIAGNOSTIC_BUDGET_EXHAUSTED" {
		t.Fatalf("diagnostic denial entry = %+v", entries[len(entries)-1])
	}
	// The chain including denial entries round-trips and verifies.
	serialized, err := ledger.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := LoadLedger(serialized)
	if err != nil {
		t.Fatalf("denial-bearing ledger must load and chain-verify: %v", err)
	}
	if restored.Remaining().Query != 0 || restored.Remaining().Diagnostic != 0 {
		t.Fatalf("remaining = %+v", restored.Remaining())
	}
}

// The query that TRIGGERS probing detection is itself denied, and its own
// ledger entry must be a hash-chained denial record — reason, digest,
// scenario ref, actor, RFC3339 time, latch set — never a success entry.
func TestLedgerProbingTriggerRecordsDenial(t *testing.T) {
	policy := DefaultCustodianPolicy()
	policy.RepeatThreshold = 3
	ledger, err := NewLedger(policy, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordQuery("us005.hid.0001", "same-shape"); err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordQuery("us005.hid.0001", "same-shape"); err != nil {
		t.Fatal(err)
	}
	remainingBefore := ledger.Remaining()
	err = ledger.RecordQuery("us005.hid.0001", "same-shape")
	if err == nil || !strings.Contains(err.Error(), "PROBING_DETECTED") {
		t.Fatalf("triggering query must be denied with PROBING_DETECTED, got %v", err)
	}
	entries := ledger.Entries()
	trigger := entries[len(entries)-1]
	if trigger.Op != "query_denied" {
		t.Fatalf("triggering request must record a denial entry, not %q: %+v",
			trigger.Op, trigger)
	}
	if trigger.Reason != "PROBING_DETECTED" || trigger.QueryDigest != "same-shape" ||
		trigger.ScenarioRef != "us005.hid.0001" || trigger.Actor == "" ||
		!trigger.ProbingDetected {
		t.Fatalf("trigger denial entry incomplete: %+v", trigger)
	}
	if _, err := time.Parse(time.RFC3339, trigger.At); err != nil {
		t.Fatalf("trigger denial time must be RFC3339, got %q: %v", trigger.At, err)
	}
	if ledger.Remaining().Query != remainingBefore.Query {
		t.Fatalf("a denied trigger must not spend budget: %d -> %d",
			remainingBefore.Query, ledger.Remaining().Query)
	}
	// Latch semantics are unchanged: subsequent requests stay denied.
	if err := ledger.RecordQuery("us005.hid.0002", "different"); err == nil ||
		!strings.Contains(err.Error(), "CUSTODIAN_LOCKED") {
		t.Fatalf("post-trigger request must deny CUSTODIAN_LOCKED, got %v", err)
	}
	// The chain including the trigger denial round-trips and verifies.
	serialized, err := ledger.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := LoadLedger(serialized)
	if err != nil {
		t.Fatalf("trigger-denial ledger must load and chain-verify: %v", err)
	}
	if !restored.ProbingDetected() {
		t.Fatal("latch must survive reload through the trigger denial entry")
	}
}

// Denials while probing-locked persist the latch and the lock reason.
func TestLedgerPersistsLockedDenials(t *testing.T) {
	policy := DefaultCustodianPolicy()
	policy.RepeatThreshold = 2
	ledger, err := NewLedger(policy, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordQuery("probe", "same"); err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordQuery("probe", "same"); err == nil {
		t.Fatal("second identical query must latch")
	}
	if err := ledger.RecordQuery("other", "different"); err == nil {
		t.Fatal("locked custodian must deny")
	}
	entries := ledger.Entries()
	last := entries[len(entries)-1]
	if last.Op != "query_denied" || last.Reason != "CUSTODIAN_LOCKED" ||
		!last.ProbingDetected {
		t.Fatalf("locked denial must persist the latch: %+v", last)
	}
	serialized, err := ledger.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := LoadLedger(serialized)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.ProbingDetected() {
		t.Fatal("latch must survive reload through denial entries")
	}
}

// SpendCustodian is atomic: concurrent spends serialize through the file
// lock, every spend lands in the ledger, and none is lost to a race.
func TestSpendCustodianIsAtomic(t *testing.T) {
	protectedRoot := t.TempDir()
	policy := DefaultCustodianPolicy()
	policy.QueryBudget = 10
	ledger, err := NewLedger(policy, 1)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := ledger.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	path := ProtectedLedgerPath(protectedRoot)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, serialized, 0o644); err != nil {
		t.Fatal(err)
	}
	const spends = 8
	errs := make(chan error, spends)
	for i := 0; i < spends; i++ {
		go func(n int) {
			errs <- SpendCustodian(protectedRoot, func(l *Ledger) error {
				return l.RecordQuery("race", fmt.Sprintf("digest-%d", n))
			})
		}(i)
	}
	for i := 0; i < spends; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("spend %d failed: %v", i, err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	final, err := LoadLedger(raw)
	if err != nil {
		t.Fatalf("post-race ledger must verify: %v", err)
	}
	if final.Remaining().Query != policy.QueryBudget-spends {
		t.Fatalf("lost spends: remaining=%d want %d",
			final.Remaining().Query, policy.QueryBudget-spends)
	}
	if len(final.Entries()) != 1+spends {
		t.Fatalf("entries=%d want %d", len(final.Entries()), 1+spends)
	}
}
