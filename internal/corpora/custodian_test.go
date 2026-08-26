package corpora

import (
	"strings"
	"testing"
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
	policy.NearMissThreshold = 3
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
