package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
)

func repoSchemas(t *testing.T) string {
	t.Helper()
	absolute, err := filepath.Abs("../../schemas")
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

func runCLI(t *testing.T, arguments ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(arguments, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestGenerateVerifyCalibrateEndToEnd(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()

	code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot)
	if code != 0 {
		t.Fatalf("generate exit %d: %s", code, stderr)
	}
	for _, path := range []string{
		"corpora/public/manifest.json", "corpora/handshake/manifest.json",
		"corpora/hidden/manifest.json", "corpora/sealed/manifest.json"} {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatalf("generate did not write %s", path)
		}
	}

	code, stdout, stderr := runCLI(t, "verify",
		"--root", root, "--protected-root", protectedRoot,
		"--schemas", repoSchemas(t))
	if code != 0 {
		t.Fatalf("verify exit %d: %s / %s", code, stdout, stderr)
	}
	var verifyResult map[string]any
	if err := json.Unmarshal([]byte(stdout), &verifyResult); err != nil {
		t.Fatalf("verify output not JSON: %v", err)
	}
	if verifyResult["ok"] != true {
		t.Fatalf("verify not ok: %s", stdout)
	}

	code, stdout, stderr = runCLI(t, "calibrate",
		"--root", root, "--protected-root", protectedRoot,
		"--schemas", repoSchemas(t))
	if code != 0 {
		t.Fatalf("calibrate exit %d: %s / %s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "evidence/corpus-calibration.json")); err != nil {
		t.Fatal("calibrate did not write the evidence document")
	}
	if !strings.Contains(stdout, "OFFLINE_CALIBRATED_PENDING_LIVE_EXECUTION") {
		t.Fatalf("calibrate status not reported: %s", stdout)
	}

	// A second generate run must be byte-identical (rerun reconciliation).
	before, err := os.ReadFile(filepath.Join(root, "corpora/public/scenarios.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot)
	if code != 0 {
		t.Fatalf("regenerate exit %d: %s", code, stderr)
	}
	after, err := os.ReadFile(filepath.Join(root, "corpora/public/scenarios.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("regeneration must be byte-identical")
	}
}

func TestOracleRequestsEmitsJSONL(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()
	if code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot); code != 0 {
		t.Fatalf("generate failed: %s", stderr)
	}
	code, stdout, stderr := runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot, "--tier", "public")
	if code != 0 {
		t.Fatalf("oracle-requests exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) < 40 {
		t.Fatalf("too few request lines: %d", len(lines))
	}
	var request map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &request); err != nil {
		t.Fatalf("request line not JSON: %v", err)
	}
	if request["protocol"] != "java-websocket-oracle" || request["request_digest"] == nil {
		t.Fatalf("request line malformed: %s", lines[0])
	}
}

func TestEvaluateFailsClosedOnEmptyTranscript(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()
	if code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot); code != 0 {
		t.Fatalf("generate failed: %s", stderr)
	}
	transcript := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(transcript, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runCLI(t, "evaluate",
		"--root", root, "--protected-root", protectedRoot,
		"--tier", "public", "--transcript", transcript)
	if code == 0 {
		t.Fatal("empty transcript must not reconcile")
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("evaluate output not JSON: %v", err)
	}
	if int(report["missing"].(float64)) == 0 {
		t.Fatalf("missing count not reported: %s", stdout)
	}
}

func TestUsageOnUnknownCommand(t *testing.T) {
	code, _, stderr := runCLI(t, "warp")
	if code != 2 || !strings.Contains(stderr, "usage") {
		t.Fatalf("unknown command: code=%d stderr=%s", code, stderr)
	}
}

func writeCustodianLedger(t *testing.T, protectedRoot string,
	build func(*corpora.Ledger)) {
	t.Helper()
	policy := corpora.CustodianPolicy{QueryBudget: 1, DiagnosticBudget: 1, RepeatThreshold: 2,
		CanariesPerTier: 3}
	ledger, err := corpora.NewLedger(policy, 1)
	if err != nil {
		t.Fatal(err)
	}
	build(ledger)
	serialized, err := ledger.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corpora.ProtectedLedgerPath(protectedRoot),
		serialized, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Held-out access goes through the custodian ledger: a budget-exhausted or
// probing-locked custodian blocks oracle-requests and evaluate for hidden
// and sealed tiers, while the public tier stays available.
func TestCustodianEnforcementOnLiveCommands(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()
	if code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot); code != 0 {
		t.Fatalf("generate failed: %s", stderr)
	}

	// Exhausted query budget.
	writeCustodianLedger(t, protectedRoot, func(ledger *corpora.Ledger) {
		if err := ledger.RecordQuery("setup", "spend-the-only-query"); err != nil {
			t.Fatal(err)
		}
	})
	code, _, stderr := runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot, "--tier", "hidden")
	if code == 0 {
		t.Fatal("exhausted custodian must block held-out oracle-requests")
	}
	if !strings.Contains(stderr, "QUERY_BUDGET_EXHAUSTED") {
		t.Fatalf("denial reason not surfaced: %s", stderr)
	}
	transcript := filepath.Join(t.TempDir(), "t.jsonl")
	if err := os.WriteFile(transcript, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCLI(t, "evaluate",
		"--root", root, "--protected-root", protectedRoot,
		"--tier", "sealed", "--transcript", transcript)
	if code == 0 {
		t.Fatal("exhausted custodian must block held-out evaluate")
	}
	if !strings.Contains(stderr, "QUERY_BUDGET_EXHAUSTED") {
		t.Fatalf("denial reason not surfaced: %s", stderr)
	}
	// Public tier requires no custodian spend.
	if code, _, stderr := runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot, "--tier", "public"); code != 0 {
		t.Fatalf("public tier must stay available: %s", stderr)
	}

	// Probing-locked custodian.
	writeCustodianLedger(t, protectedRoot, func(ledger *corpora.Ledger) {
		policyLedgerLock(t, ledger)
	})
	code, _, stderr = runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot, "--tier", "hidden")
	if code == 0 || !strings.Contains(stderr, "CUSTODIAN_LOCKED") {
		t.Fatalf("locked custodian must block: code=%d %s", code, stderr)
	}
}

func policyLedgerLock(t *testing.T, ledger *corpora.Ledger) {
	t.Helper()
	// RepeatThreshold 2 with QueryBudget 1 cannot latch; rebuild wider.
	policy := corpora.CustodianPolicy{QueryBudget: 10, DiagnosticBudget: 1,
		RepeatThreshold: 2, CanariesPerTier: 3}
	locked, err := corpora.NewLedger(policy, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := locked.RecordQuery("probe", "same"); err != nil {
		t.Fatal(err)
	}
	if err := locked.RecordQuery("probe", "same"); err == nil {
		t.Fatal("second identical query must latch probing at threshold 2")
	}
	*ledger = *locked
}

// A successful held-out run spends exactly one query and persists the spend.
func TestCustodianSpendIsPersisted(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()
	if code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot); code != 0 {
		t.Fatalf("generate failed: %s", stderr)
	}
	before, err := os.ReadFile(corpora.ProtectedLedgerPath(protectedRoot))
	if err != nil {
		t.Fatal(err)
	}
	beforeLedger, err := corpora.LoadLedger(before)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot, "--tier", "hidden"); code != 0 {
		t.Fatalf("held-out oracle-requests failed: %s", stderr)
	}
	after, err := os.ReadFile(corpora.ProtectedLedgerPath(protectedRoot))
	if err != nil {
		t.Fatal(err)
	}
	afterLedger, err := corpora.LoadLedger(after)
	if err != nil {
		t.Fatal(err)
	}
	if afterLedger.Remaining().Query != beforeLedger.Remaining().Query-1 {
		t.Fatalf("query spend not persisted: before=%d after=%d",
			beforeLedger.Remaining().Query, afterLedger.Remaining().Query)
	}
}

// The handshake corpus is executable through the CLI: requests emit the raw
// cases without expectations, and evaluate scores a transcript fail-closed.
func TestHandshakeTierRequestsAndEvaluate(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()
	if code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot); code != 0 {
		t.Fatalf("generate failed: %s", stderr)
	}
	code, stdout, stderr := runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot, "--tier", "handshake")
	if code != 0 {
		t.Fatalf("handshake requests exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) < 30 {
		t.Fatalf("too few handshake request lines: %d", len(lines))
	}
	var request map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &request); err != nil {
		t.Fatalf("handshake request not JSON: %v", err)
	}
	if request["raw_base64"] == nil || request["expected"] != nil {
		t.Fatalf("handshake request malformed: %s", lines[0])
	}

	transcript := filepath.Join(t.TempDir(), "hs.jsonl")
	if err := os.WriteFile(transcript, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = runCLI(t, "evaluate",
		"--root", root, "--protected-root", protectedRoot,
		"--tier", "handshake", "--transcript", transcript)
	if code == 0 {
		t.Fatal("empty handshake transcript must not reconcile")
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("evaluate output not JSON: %v", err)
	}
	if int(report["missing"].(float64)) == 0 {
		t.Fatalf("missing handshake responses not reported: %s", stdout)
	}
}

// The handshake live adapter is drivable end to end from the CLI: --wire
// emits digest-bound java-oracle handshake protocol requests, and
// evaluate --live scores a java-runtime observable transcript fail-closed.
// Both flags are handshake-tier-only.
func TestHandshakeWireRequestsAndLiveEvaluate(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()
	if code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot); code != 0 {
		t.Fatalf("generate failed: %s", stderr)
	}
	code, stdout, stderr := runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot,
		"--tier", "handshake", "--wire")
	if code != 0 {
		t.Fatalf("wire requests exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) < 30 {
		t.Fatalf("too few wire request lines: %d", len(lines))
	}
	var request map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &request); err != nil {
		t.Fatalf("wire request not JSON: %v", err)
	}
	if request["protocol"] != "java-websocket-handshake-oracle" ||
		request["request_digest"] == nil || request["raw_base64"] == nil {
		t.Fatalf("wire request malformed: %s", lines[0])
	}
	if _, present := request["expected"]; present {
		t.Fatal("wire request must not leak the expected verdict")
	}

	// --wire is handshake-tier-only.
	if code, _, _ := runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot,
		"--tier", "public", "--wire"); code != 2 {
		t.Fatalf("--wire on a behavior tier must be a usage error, got %d", code)
	}

	// An empty live transcript must not reconcile.
	transcript := filepath.Join(t.TempDir(), "live.jsonl")
	if err := os.WriteFile(transcript, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = runCLI(t, "evaluate",
		"--root", root, "--protected-root", protectedRoot,
		"--tier", "handshake", "--transcript", transcript, "--live")
	if code == 0 {
		t.Fatal("empty live transcript must not reconcile")
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("evaluate output not JSON: %v", err)
	}
	if int(report["missing"].(float64)) == 0 {
		t.Fatalf("missing live responses not reported: %s", stdout)
	}
	if _, present := report["divergences"]; !present {
		t.Fatalf("live evaluation must report the divergences field: %s", stdout)
	}

	// --live is handshake-tier-only: behavior tiers must never route through
	// the handshake observable evaluator.
	if code, _, _ := runCLI(t, "evaluate",
		"--root", root, "--protected-root", protectedRoot,
		"--tier", "public", "--transcript", transcript, "--live"); code != 2 {
		t.Fatalf("--live on a behavior tier must be a usage error, got %d", code)
	}
}

// The CLI invocation that TRIGGERS probing detection persists the trigger's
// own hash-chained denial entry (op query_denied, reason PROBING_DETECTED,
// latch set) on that same denied invocation — not a success entry.
func TestProbingTriggerCLIPersistsDenialEntry(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()
	if code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot); code != 0 {
		t.Fatalf("generate failed: %s", stderr)
	}
	// Generation is deterministic, so repeated held-out oracle-requests
	// invocations spend byte-identical query digests; the default policy's
	// RepeatThreshold (3) trips on the third.
	for i := 0; i < 2; i++ {
		if code, _, stderr := runCLI(t, "oracle-requests",
			"--root", root, "--protected-root", protectedRoot, "--tier", "hidden"); code != 0 {
			t.Fatalf("invocation %d must succeed: %s", i+1, stderr)
		}
	}
	code, _, stderr := runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot, "--tier", "hidden")
	if code == 0 || !strings.Contains(stderr, "PROBING_DETECTED") {
		t.Fatalf("third identical invocation must deny with PROBING_DETECTED: code=%d %s",
			code, stderr)
	}
	raw, err := os.ReadFile(corpora.ProtectedLedgerPath(protectedRoot))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := corpora.LoadLedger(raw)
	if err != nil {
		t.Fatalf("trigger-denial ledger must chain-verify: %v", err)
	}
	entries := ledger.Entries()
	last := entries[len(entries)-1]
	if last.Op != "query_denied" || last.Reason != "PROBING_DETECTED" ||
		!last.ProbingDetected || last.Actor == "" || last.At == "" {
		t.Fatalf("denied trigger invocation must persist its own denial entry: %+v", last)
	}
	// The latch persists on disk: the next invocation denies CUSTODIAN_LOCKED.
	code, _, stderr = runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot, "--tier", "hidden")
	if code == 0 || !strings.Contains(stderr, "CUSTODIAN_LOCKED") {
		t.Fatalf("post-trigger invocation must deny CUSTODIAN_LOCKED: code=%d %s",
			code, stderr)
	}
}

// A denied CLI invocation persists the hash-chained denial entry.
func TestDeniedInvocationPersistsDenialEntry(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()
	if code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot); code != 0 {
		t.Fatalf("generate failed: %s", stderr)
	}
	writeCustodianLedger(t, protectedRoot, func(ledger *corpora.Ledger) {
		if err := ledger.RecordQuery("setup", "spend-the-only-query"); err != nil {
			t.Fatal(err)
		}
	})
	if code, _, _ := runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot, "--tier", "hidden"); code == 0 {
		t.Fatal("exhausted custodian must block")
	}
	raw, err := os.ReadFile(corpora.ProtectedLedgerPath(protectedRoot))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := corpora.LoadLedger(raw)
	if err != nil {
		t.Fatalf("denial-bearing ledger must verify: %v", err)
	}
	entries := ledger.Entries()
	last := entries[len(entries)-1]
	if last.Op != "query_denied" || last.Reason != "QUERY_BUDGET_EXHAUSTED" {
		t.Fatalf("denied CLI attempt must persist a denial entry: %+v", last)
	}
}
