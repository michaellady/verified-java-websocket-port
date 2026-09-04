package deltaledger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEnvelopeFixture builds a minimal evidence/java tree: the ledger
// document plus one sibling that carries the accepted root, and the Autobahn
// baseline whose status decides the ledger's.
func writeEnvelopeFixture(t *testing.T, ledgerRoot, ledgerStatus, siblingRoot, baselineStatus string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "evidence", "java")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, value any) {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("build.json", map[string]any{"accepted_root_digest": siblingRoot, "status": "PASS"})
	write("autobahn-baseline.json", map[string]any{"accepted_root_digest": siblingRoot, "status": baselineStatus})
	write("behavior-delta-ledger.json", map[string]any{"accepted_root_digest": ledgerRoot, "status": ledgerStatus})
	return root
}

const (
	fixtureRoot  = "sha256:5713245496362ece061c769bc4ee8eb909bfcc6d7d319bc3fc9b750f6e0a4ad8"
	fixtureOther = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

// TestLedgerEnvelopeAcceptedRootIsBoundToItsSiblings is ROUND 3 FINDING L2.
func TestLedgerEnvelopeAcceptedRootIsBoundToItsSiblings(t *testing.T) {
	root := writeEnvelopeFixture(t, fixtureRoot, LedgerStatusBlocked, fixtureRoot, "BLOCKED")
	if err := VerifyLedgerEnvelope(root, LedgerFile{AcceptedRootDigest: fixtureRoot, Status: LedgerStatusBlocked}); err != nil {
		t.Fatalf("the agreeing tree must pass: %v", err)
	}
	root = writeEnvelopeFixture(t, fixtureOther, LedgerStatusBlocked, fixtureRoot, "BLOCKED")
	err := VerifyLedgerEnvelope(root, LedgerFile{AcceptedRootDigest: fixtureOther, Status: LedgerStatusBlocked})
	if err == nil {
		t.Fatal("L2: a ledger whose accepted_root_digest differs from every sibling document must be refused")
	}
	if !strings.Contains(err.Error(), "accepted_root_digest") {
		t.Fatalf("the finding must name the field, got %v", err)
	}
}

// TestLedgerEnvelopeStatusIsBoundToTheAutobahnBaseline is ROUND 3 FINDING L1.
func TestLedgerEnvelopeStatusIsBoundToTheAutobahnBaseline(t *testing.T) {
	// BLOCKED baseline: the ledger must say BLOCKED_PENDING_BASELINE.
	root := writeEnvelopeFixture(t, fixtureRoot, LedgerStatusReady, fixtureRoot, "BLOCKED")
	err := VerifyLedgerEnvelope(root, LedgerFile{AcceptedRootDigest: fixtureRoot, Status: LedgerStatusReady})
	if err == nil {
		t.Fatal("L1: the ledger may not declare itself READY while the Autobahn baseline is BLOCKED")
	}
	if !strings.Contains(err.Error(), "autobahn-baseline.json") {
		t.Fatalf("the finding must name the artifact the status is bound to, got %v", err)
	}
	// The OTHER polarity, so this is a derivation and not a constant: a PASS
	// baseline REQUIRES READY, and BLOCKED_PENDING_BASELINE is then wrong.
	root = writeEnvelopeFixture(t, fixtureRoot, LedgerStatusBlocked, fixtureRoot, "PASS")
	if err := VerifyLedgerEnvelope(root, LedgerFile{AcceptedRootDigest: fixtureRoot, Status: LedgerStatusBlocked}); err == nil {
		t.Fatal("with a PASS baseline the ledger must not still say BLOCKED_PENDING_BASELINE; the status is derived, not pinned to one value")
	}
	root = writeEnvelopeFixture(t, fixtureRoot, LedgerStatusReady, fixtureRoot, "PASS")
	if err := VerifyLedgerEnvelope(root, LedgerFile{AcceptedRootDigest: fixtureRoot, Status: LedgerStatusReady}); err != nil {
		t.Fatalf("a PASS baseline with a READY ledger must pass: %v", err)
	}
}

// TestLedgerEnvelopeRefusesWhenNothingBindsIt: a tree with no sibling
// carrying an accepted root, and a missing baseline, must FAIL rather than
// pass vacuously — an unbound field is what both findings were made of.
func TestLedgerEnvelopeRefusesWhenNothingBindsIt(t *testing.T) {
	// The baseline IS present, so the status arm is satisfied and the only
	// question is the accepted root. No sibling carries one. The refusal must
	// say the field is UNBOUND -- not merely that it differs from the empty
	// string, which is what falling through to the comparison would report
	// and which reads as a value mismatch rather than as a missing anchor.
	root := t.TempDir()
	dir := filepath.Join(root, "evidence", "java")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.MarshalIndent(map[string]any{"status": "BLOCKED"}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "autobahn-baseline.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptedRootFromSiblings(root); err == nil {
		t.Fatal("AcceptedRootFromSiblings must REFUSE when no sibling carries an accepted root; returning the empty string makes an unbound field look like a mismatched one")
	} else if !strings.Contains(err.Error(), "bound to nothing") {
		t.Fatalf("the refusal must say the ledger's value is bound to nothing, got %v", err)
	}
	err := VerifyLedgerEnvelope(root, LedgerFile{AcceptedRootDigest: fixtureRoot, Status: LedgerStatusBlocked})
	if err == nil {
		t.Fatal("a tree with nothing to bind the accepted root must be refused, not passed")
	}
	if !strings.Contains(err.Error(), "bound to nothing") {
		t.Fatalf("the refusal must say the field is unbound, got %v", err)
	}
}

// TestLedgerEnvelopeRefusesDisagreeingSiblings: if the sibling documents do
// not agree on one accepted root, picking one is not this gate's decision.
func TestLedgerEnvelopeRefusesDisagreeingSiblings(t *testing.T) {
	root := writeEnvelopeFixture(t, fixtureRoot, LedgerStatusBlocked, fixtureRoot, "BLOCKED")
	raw, _ := json.MarshalIndent(map[string]any{"accepted_root_digest": fixtureOther, "status": "PASS"}, "", "  ")
	if err := os.WriteFile(filepath.Join(root, "evidence", "java", "adapter-baseline.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptedRootFromSiblings(root); err == nil {
		t.Fatal("siblings that disagree on the accepted root must be refused rather than resolved by majority")
	}
}

// TestLedgerEnvelopeIsRunByTheGate: the rule must be reachable from
// VerifyIntegrity, not only from this test binary — the defect this whole
// package's integrity gate exists to prevent.
func TestLedgerEnvelopeIsRunByTheGate(t *testing.T) {
	raw, err := os.ReadFile("integrity.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "VerifyLedgerEnvelope(root, committed)") {
		t.Fatal("VerifyIntegrity must call VerifyLedgerEnvelope; a rule that lives only in a test binary is the fake gate this package was rebuilt to remove")
	}
}
