package differential

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

func publicScenarios(t *testing.T) []corpora.Scenario {
	t.Helper()
	public, _, _, err := corpora.GeneratePublic("us005-public-calibration-seed-v1")
	if err != nil {
		t.Fatalf("GeneratePublic: %v", err)
	}
	if len(public) != 74 {
		t.Fatalf("public count = %d", len(public))
	}
	return public
}

func minimalValidManifestForTest(t *testing.T) Manifest {
	t.Helper()
	manifest := Manifest{Schema: "../schemas/differential-evidence-1.0.0.schema.json", SchemaVersion: "1.0.0", EvidenceID: "evidence.us-020-public-differential", StoryID: "US-020", Status: "PASS", Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT", ParityScope: "RUNTIME_COMMON_AGGREGATE", RepositoryAnchor: strings.Repeat("a", 40), Counts: CountsReceipt{Scenarios: 74, JavaPrimary: 74, JavaReplay: 74, RustPrimary: 74, RustReplay: 74, Processes: 296}, Controls: ControlsReceipt{Total: 7, Killed: 7, Results: make([]ControlResult, 7)}, Coverage: CoverageReceipt{Summary: CoverageSummary{MigrationRows: 47, CompatibilityItems: 14}, Migration: make([]CoverageRow, 47), Compatibility: make([]CoverageRow, 14)}, Ledger: LedgerBinding{PreHead: "sha256:" + strings.Repeat("0", 64), PostHead: "sha256:" + strings.Repeat("0", 64)}, Nonclaims: []string{"no per-step Java counter parity"}}
	for index := 0; index < 74; index++ {
		id := fmt.Sprintf("us005.pub.%04d", index)
		manifest.Scenarios = append(manifest.Scenarios, ScenarioResult{ScenarioID: id, Stable: true})
		for _, runtimeName := range []string{"java", "rust"} {
			for _, attempt := range []string{"primary", "replay"} {
				manifest.Processes = append(manifest.Processes, ProcessReceipt{ScenarioID: id, Runtime: runtimeName, Attempt: attempt, PID: 1000 + len(manifest.Processes), ExecutableSHA256: digest([]byte(runtimeName)), ExitCode: 0, NormalizedSHA256: digest([]byte(id + runtimeName + attempt))})
			}
		}
	}
	return manifest
}

// TestFacadeRejectsUnboundedConfiguration is the first public-seam RED.  The
// facade must reject paths before it starts either runtime.
func TestFacadeRejectsUnboundedConfiguration(t *testing.T) {
	root := t.TempDir()
	_, err := RunPublicDifferential(context.Background(), Config{
		RepositoryRoot:  root,
		PublicCorpus:    filepath.Join(root, "corpora/public/scenarios.jsonl"),
		ScenarioTimeout: 0,
		SuiteTimeout:    time.Minute,
	})
	if err == nil {
		t.Fatal("zero scenario timeout must fail closed")
	}
}

func TestPublicCorpusRederivesExactCommittedBytes(t *testing.T) {
	root := repositoryRoot(t)
	scenarios, raw, err := loadPublicCorpus(root, filepath.Join(root, "corpora/public/scenarios.jsonl"))
	if err != nil {
		t.Fatalf("loadPublicCorpus: %v", err)
	}
	if len(scenarios) != 74 {
		t.Fatalf("scenarios = %d", len(scenarios))
	}
	committed, err := os.ReadFile(filepath.Join(root, "corpora/public/scenarios.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, committed) {
		t.Fatal("rederived public bytes differ")
	}
}

func TestNeutralRequestUsesFrozenNDRV1Envelope(t *testing.T) {
	sc := publicScenarios(t)[0]
	raw, err := encodeNeutralRequest(sc)
	if err != nil {
		t.Fatalf("encodeNeutralRequest: %v", err)
	}
	if got := int(binary.BigEndian.Uint32(raw[:4])); got != len(raw)-4 {
		t.Fatalf("length=%d body=%d", got, len(raw)-4)
	}
	if string(raw[4:9]) != "NDRV1" {
		t.Fatalf("magic=%q", raw[4:9])
	}
	if !bytes.Contains(raw, []byte(sc.ScenarioID)) {
		t.Fatal("scenario id absent")
	}
	second, err := encodeNeutralRequest(sc)
	if err != nil || !bytes.Equal(raw, second) {
		t.Fatal("request is not deterministic")
	}
}

func TestNeutralResponseRejectsTrailingAndOutOfOrderTLVs(t *testing.T) {
	if _, err := decodeNeutralResponse([]byte{0, 0, 0, 5, 'N', 'O', 'B', 'S', '1', 0}); err == nil {
		t.Fatal("trailing byte accepted")
	}
	body := []byte("NOBS1")
	body = append(body, 2, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 'x')
	framed := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(framed, uint32(len(body)))
	copy(framed[4:], body)
	if _, err := decodeNeutralResponse(framed); err == nil {
		t.Fatal("out-of-order tags accepted")
	}
}

func TestCappedProcessOutputFailsAtBound(t *testing.T) {
	buffer := &cappedBuffer{maximum: 3}
	if n, err := buffer.Write([]byte("four")); err == nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestOracleHierarchyCoversEveryExpectedLeaf(t *testing.T) {
	scenarios := publicScenarios(t)
	hierarchy, err := BuildOracleHierarchy(scenarios)
	if err != nil {
		t.Fatalf("BuildOracleHierarchy: %v", err)
	}
	if hierarchy.ScenarioCount != 74 || hierarchy.CellCount != len(hierarchy.Cells) || hierarchy.CellCount <= 74 {
		t.Fatalf("hierarchy counts = scenarios:%d cells:%d/%d", hierarchy.ScenarioCount, hierarchy.CellCount, len(hierarchy.Cells))
	}
	seen := map[string]bool{}
	for _, cell := range hierarchy.Cells {
		key := cell.ScenarioID + cell.Pointer
		if seen[key] {
			t.Fatalf("duplicate cell %s", key)
		}
		seen[key] = true
		if cell.Rank != 1 && cell.Rank != 3 {
			t.Fatalf("unreviewed rank %d", cell.Rank)
		}
		if !strings.HasPrefix(cell.ExpectedSHA256, "sha256:") {
			t.Fatalf("bad digest %s", cell.ExpectedSHA256)
		}
	}
	if err := ValidateOracleHierarchy(scenarios, hierarchy); err != nil {
		t.Fatalf("ValidateOracleHierarchy: %v", err)
	}
	bad := hierarchy
	bad.Cells = append([]OracleCell(nil), hierarchy.Cells[1:]...)
	bad.CellCount--
	if err := ValidateOracleHierarchy(scenarios, bad); err == nil {
		t.Fatal("missing cell accepted")
	}
}

func TestCommittedOracleHierarchyMatchesExactPublicCorpus(t *testing.T) {
	root := repositoryRoot(t)
	path := filepath.Join(root, "evidence/oracle-hierarchy.json")
	if os.Getenv("UPDATE_US020_ORACLE_HIERARCHY") == "1" {
		if err := PreparePublicOracleHierarchy(root, path); err != nil {
			t.Fatalf("prepare hierarchy: %v", err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed hierarchy: %v", err)
	}
	var hierarchy OracleHierarchy
	if err := decodeStrict(raw, &hierarchy); err != nil {
		t.Fatalf("decode hierarchy: %v", err)
	}
	if err := ValidateOracleHierarchy(publicScenarios(t), hierarchy); err != nil {
		t.Fatalf("validate hierarchy: %v", err)
	}
	if err := compileAndValidateSchema(filepath.Join(root, "schemas/oracle-hierarchy-1.0.0.schema.json"), raw); err != nil {
		t.Fatalf("hierarchy schema: %v", err)
	}
}

func TestLedgerMigrationChainAndCAS(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "evidence/java/behavior-delta-ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := migrateLedger(raw)
	if err != nil {
		t.Fatalf("migrateLedger: %v", err)
	}
	if ledger.SchemaVersion != "1.1.0" || len(ledger.Records) != 0 {
		t.Fatalf("migration = %#v", ledger)
	}
	migrated, err := marshalIndented(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := compileAndValidateSchema(filepath.Join(root, "schemas/behavior-delta-ledger-1.1.0.schema.json"), migrated); err != nil {
		t.Fatalf("ledger schema: %v", err)
	}
	cell := OracleCell{ScenarioID: "us005.pub.0000", Pointer: "/error/class", Authority: "neutral", Rank: 3, ExpectedSHA256: digest([]byte("x")), Evidence: []OracleEvidence{{Kind: "neutral", ID: "us005.pub.0000", SHA256: digest([]byte("x"))}}}
	record := LedgerRecord{DeltaID: "delta.us005.pub.0000.error", ScenarioID: "us005.pub.0000", Pointer: "/error/class", Classification: "rust_defect", JavaObservation: digest([]byte("j")), RustObservation: digest([]byte("r")), ReproducerSHA256: digest([]byte("p")), Decision: cell, Resolution: "remediated", FindingRunAnchor: strings.Repeat("a", 40), ClosingRunAnchor: strings.Repeat("b", 40), ClosingJavaObservation: digest([]byte("closing")), ClosingRustObservation: digest([]byte("closing"))}
	head := ledger.Head
	if err := appendLedgerRecord(&ledger, head, record); err != nil {
		t.Fatalf("append: %v", err)
	}
	if ledger.Head == head || len(ledger.Records) != 1 {
		t.Fatal("append did not advance chain")
	}
	if err := validateLedger(ledger); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := appendLedgerRecord(&ledger, head, record); err == nil {
		t.Fatal("stale CAS accepted")
	}
	bad := ledger
	bad.Records = append([]LedgerRecord(nil), ledger.Records...)
	bad.Records[0].PreviousDigest = digest([]byte("wrong"))
	if err := validateLedger(bad); err == nil {
		t.Fatal("broken chain accepted")
	}
}

func TestObservedRustDefectRemainsVisibleAfterClosingRun(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "evidence/java/behavior-delta-ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := migrateLedger(raw)
	if err != nil {
		t.Fatal(err)
	}
	scenarios := publicScenarios(t)
	hierarchy, err := BuildOracleHierarchy(scenarios)
	if err != nil {
		t.Fatal(err)
	}
	java, err := neutralObservation(scenarios[5])
	if err != nil {
		t.Fatal(err)
	}
	rust := java
	rust.FinalState = "closed"
	closingJava, closingRust := digest([]byte("closing-java")), digest([]byte("closing-rust"))
	if err := appendObservedRemediation(&ledger, hierarchy, scenarios[5], java, rust, closingJava, closingRust, strings.Repeat("c", 40)); err != nil {
		t.Fatalf("appendObservedRemediation: %v", err)
	}
	if len(ledger.Records) != 1 || ledger.Records[0].Classification != "rust_defect" || ledger.Records[0].Resolution != "remediated" || ledger.Records[0].ClosingJavaObservation != closingJava || ledger.Records[0].ClosingRustObservation != closingRust {
		t.Fatalf("retained record=%#v", ledger.Records)
	}
	document, err := marshalIndented(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := compileAndValidateSchema(filepath.Join(repositoryRoot(t), "schemas/behavior-delta-ledger-1.1.0.schema.json"), document); err != nil {
		t.Fatalf("closed ledger schema: %v", err)
	}
}

func TestFieldLevelAdjudicationSeparatesRFCJavaQuirkFromCounterDefect(t *testing.T) {
	scenarios := publicScenarios(t)
	scenario := scenarios[5]
	hierarchy, err := BuildOracleHierarchy(scenarios)
	if err != nil {
		t.Fatal(err)
	}
	java, err := neutralObservation(scenario)
	if err != nil {
		t.Fatal(err)
	}
	rust := java
	rust.FinalState = "closed"
	classification, findings, err := adjudicateScenario(scenario, hierarchy, java, rust)
	if err != nil {
		t.Fatalf("RFC-aligned Rust state rejected: %v", err)
	}
	if classification != "java_quirk" || len(findings) != 1 || findings[0].Pointer != "/final_state" || findings[0].Classification != "java_quirk" {
		t.Fatalf("classification=%s findings=%#v", classification, findings)
	}
	ledger := Ledger{Schema: "../../schemas/behavior-delta-ledger-1.1.0.schema.json", SchemaVersion: ledgerSchemaVersion, EvidenceKind: "behavior-delta-ledger", AcceptedRootDigest: digest([]byte("root")), Status: "PASS_NO_CURRENT_DELTAS", NormativeAuthority: "field-addressed-oracle-hierarchy", Head: "sha256:" + strings.Repeat("0", 64), Records: []LedgerRecord{}, AppendImplementation: "hash-chained-cas"}
	if err := appendJavaQuirk(&ledger, scenario, findings[0], digest([]byte("java")), digest([]byte("rust")), strings.Repeat("d", 40)); err != nil {
		t.Fatalf("append Java quirk: %v", err)
	}
	if len(ledger.Records) != 1 || ledger.Records[0].Resolution != "retained_java_quirk" || ledger.Records[0].ClosingRunAnchor != "" {
		t.Fatalf("Java quirk lifecycle=%#v", ledger.Records)
	}
	rust.Counts.ConsumedBytes = 2
	if _, _, err := adjudicateScenario(scenario, hierarchy, java, rust); err == nil || !strings.Contains(err.Error(), "rust_defect") {
		t.Fatalf("counter defect accepted: %v", err)
	}
}

func TestCoverageReconciles47MigrationAnd14CompatibilityItems(t *testing.T) {
	root := repositoryRoot(t)
	receipt, err := buildCoverage(root, publicScenarios(t))
	if err != nil {
		t.Fatalf("buildCoverage: %v", err)
	}
	if len(receipt.Migration) != 47 || len(receipt.Compatibility) != 14 {
		t.Fatalf("coverage rows=%d items=%d", len(receipt.Migration), len(receipt.Compatibility))
	}
	if receipt.Summary.UnresolvedRows != 0 {
		t.Fatalf("unresolved=%d", receipt.Summary.UnresolvedRows)
	}
	for _, row := range append(append([]CoverageRow{}, receipt.Migration...), receipt.Compatibility...) {
		if row.FreshUS020 && (len(row.ScenarioIDs) == 0 || len(row.FieldPointers) == 0) {
			t.Fatalf("fresh zero-vector row %s", row.ID)
		}
		if !row.FreshUS020 && len(row.PredecessorPaths) == 0 && row.ExcludedReason == "" {
			t.Fatalf("unreconciled row %s", row.ID)
		}
	}
}

func TestAllSevenControlsKillExactDetectors(t *testing.T) {
	controls, err := runSeededControls()
	if err != nil {
		t.Fatalf("runSeededControls: %v", err)
	}
	if controls.Total != 7 || controls.Killed != 7 || len(controls.Results) != 7 {
		t.Fatalf("controls=%#v", controls)
	}
	for _, result := range controls.Results {
		if result.ExpectedCode != result.DetectedCode || !result.BaselinePassed || !result.LedgerUnchanged {
			t.Fatalf("control failed: %#v", result)
		}
	}
}

func TestDeterministicMinimizerPreservesSignatureAndBounds(t *testing.T) {
	steps := []string{"irrelevant-a", "keep", "irrelevant-b"}
	predicate := func(candidate []string) (string, bool) {
		for _, step := range candidate {
			if step == "keep" {
				return "/error/class:rust_defect", true
			}
		}
		return "", false
	}
	first, attempts, err := minimizeStrings(steps, Budget{MaxCandidates: 8, MaxDuration: time.Second}, predicate)
	if err != nil {
		t.Fatalf("minimizeStrings: %v", err)
	}
	second, attempts2, err := minimizeStrings(steps, Budget{MaxCandidates: 8, MaxDuration: time.Second}, predicate)
	if err != nil || strings.Join(first, "|") != "keep" || !bytes.Equal([]byte(strings.Join(first, "|")), []byte(strings.Join(second, "|"))) || attempts != attempts2 {
		t.Fatalf("non-deterministic result first=%v second=%v attempts=%d/%d err=%v", first, second, attempts, attempts2, err)
	}
}

func TestVerifierRejectsPerStepJavaParityOverclaimAndCountMutation(t *testing.T) {
	manifest := minimalValidManifestForTest(t)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyManifestValue(repositoryRoot(t), raw); err != nil {
		t.Fatalf("valid: %v", err)
	}
	manifest.ParityScope = "PER_STEP_JAVA_COUNTER_PARITY"
	raw, _ = json.Marshal(manifest)
	if err := verifyManifestValue(repositoryRoot(t), raw); err == nil {
		t.Fatal("per-step parity overclaim accepted")
	}
	manifest.ParityScope = "RUNTIME_COMMON_AGGREGATE"
	manifest.Counts.Processes--
	raw, _ = json.Marshal(manifest)
	if err := verifyManifestValue(repositoryRoot(t), raw); err == nil {
		t.Fatal("process count mutation accepted")
	}
}

func TestFakeExecutorRejectsMalformedAndUnstableOutput(t *testing.T) {
	original := executeChild
	defer func() { executeChild = original }()
	calls := 0
	executeChild = func(context.Context, childRequest) (childResult, error) {
		calls++
		if calls == 1 {
			return childResult{PID: 101, Stdout: []byte("first"), ExitCode: 0, Started: time.Unix(1, 0)}, nil
		}
		return childResult{PID: 102, Stdout: []byte("different"), ExitCode: 0, Started: time.Unix(2, 0)}, nil
	}
	if err := requireStablePair(context.Background(), childRequest{Timeout: time.Second}, func(raw []byte) (string, error) { return digest(raw), nil }); err == nil {
		t.Fatal("unstable fake executor accepted")
	}
	executeChild = func(context.Context, childRequest) (childResult, error) {
		return childResult{PID: 1, Stdout: []byte("bad")}, errors.New("malformed output")
	}
	if err := requireStablePair(context.Background(), childRequest{Timeout: time.Second}, func(raw []byte) (string, error) { return digest(raw), nil }); err == nil {
		t.Fatal("malformed fake executor accepted")
	}
}

func TestSemanticDetectorsAreFieldAddressed(t *testing.T) {
	baseline := SemanticObservation{
		Events:        []string{"input", "text"},
		ErrorClass:    "none",
		CloseOrigin:   "none",
		ConsumedBytes: 7,
	}
	controls := []struct {
		name   string
		mutate func(*SemanticObservation)
		want   string
	}{
		{"event-order", func(v *SemanticObservation) { v.Events[0], v.Events[1] = v.Events[1], v.Events[0] }, "EVENT_ORDER_MISMATCH"},
		{"error-class", func(v *SemanticObservation) { v.ErrorClass = "protocol" }, "ERROR_CLASS_MISMATCH"},
		{"close-origin", func(v *SemanticObservation) { v.CloseOrigin = "remote" }, "CLOSE_ORIGIN_MISMATCH"},
		{"consumed-byte", func(v *SemanticObservation) { v.ConsumedBytes++ }, "CONSUMED_BYTES_MISMATCH"},
	}
	for _, control := range controls {
		t.Run(control.name, func(t *testing.T) {
			candidate := baseline.Clone()
			control.mutate(&candidate)
			if got := DetectSemanticDifference(baseline, candidate); got.Code != control.want {
				t.Fatalf("detector code = %q, want %q", got.Code, control.want)
			}
		})
	}
}

func TestRustErrorMapIsClosedAndUnknownIsInfrastructureFailure(t *testing.T) {
	for _, input := range []string{"FRAME_RESERVED_BITS", "UTF8_TRUNCATED", "FRAGMENT_DATA_WHILE_ACTIVE", "CLOSE_INVALID_CODE"} {
		got, err := normalizeRustErrorClass(input)
		if err != nil || got != "PROTOCOL_REJECTION" {
			t.Fatalf("%s => %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"LIMIT_FRAME_BYTES", "LIMIT_TOTAL_BUFFERED_BYTES"} {
		got, err := normalizeRustErrorClass(input)
		if err != nil || got != "LIMIT_EXCEEDED" {
			t.Fatalf("%s => %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"FRAME_UNKNOWN", "UTF8_UNKNOWN", "FRAGMENT_UNKNOWN", "CLOSE_UNKNOWN", "invented"} {
		if got, err := normalizeRustErrorClass(input); err == nil {
			t.Fatalf("unmapped %s accepted as %q", input, got)
		}
	}
}
