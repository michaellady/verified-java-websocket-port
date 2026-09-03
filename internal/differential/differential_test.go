package differential

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
)

func committedManifestForTest(t *testing.T) ([]byte, Manifest) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "evidence/differential/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := decodeStrict(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return raw, manifest
}

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

func emptyMigratedLedgerForTest(t *testing.T) Ledger {
	t.Helper()
	raw, err := json.Marshal(LegacyLedger{Schema: "../../schemas/behavior-delta-ledger-1.0.0.schema.json", SchemaVersion: "1.0.0", EvidenceKind: "behavior-delta-ledger", AcceptedRootDigest: digest([]byte("accepted-root")), Status: "BLOCKED_PENDING_BASELINE", NormativeAuthority: "rfc6455", Head: "sha256:" + strings.Repeat("0", 64), Records: []LegacyLedgerRecord{}, AppendImplementation: "hash-chained-cas"})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := migrateLedger(raw)
	if err != nil {
		t.Fatalf("migrate empty v1.0 ledger: %v", err)
	}
	return ledger
}

func legacyDeltaForTest() LegacyDelta {
	return LegacyDelta{
		SchemaVersion: "1.0.0", DeltaID: "delta-" + strings.Repeat("a", 64), SubjectRef: "semantic:test:provisional-v1",
		RFCRefs: []string{"rfc6455#section-5.2"}, RFCExpectationDigest: digest([]byte("expectation")), RFCValueDigest: digest([]byte("rfc")),
		JavaRef: "java-v1.6.0:test", JavaObservationDigest: digest([]byte("java-observation")), JavaValueDigest: digest([]byte("java-value")),
		AutobahnRefs: []string{"autobahn-v25.10.1:1.1"}, AutobahnResultDigest: digest([]byte("autobahn-result")), AutobahnValueDigest: digest([]byte("autobahn-value")),
		DisagreementDigest: digest([]byte("difference")), NormativeAuthority: "rfc6455", Disposition: "rfc-governs", Rationale: "RFC controls the retained legacy disagreement.",
	}
}

func minimalValidManifestForTest(t *testing.T) Manifest {
	t.Helper()
	manifest := Manifest{Schema: "../schemas/differential-evidence-1.1.0.schema.json", SchemaVersion: evidenceSchemaVersion, EvidenceID: "evidence.us-020-public-differential", StoryID: "US-020", Status: "PASS", Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT", ParityScope: "RUNTIME_COMMON_AGGREGATE", RepositoryAnchor: strings.Repeat("a", 40), Counts: CountsReceipt{Scenarios: 74, JavaPrimary: 74, JavaReplay: 74, RustPrimary: 74, RustReplay: 74, Processes: 296}, Controls: ControlsReceipt{Total: 7, Killed: 7, Results: make([]ControlResult, 7)}, Coverage: CoverageReceipt{Summary: CoverageSummary{MigrationRows: 47, CompatibilityItems: 14}, Migration: make([]CoverageRow, 47), Compatibility: make([]CoverageRow, 14)}, Ledger: LedgerBinding{PreHead: "sha256:" + strings.Repeat("0", 64), PostHead: "sha256:" + strings.Repeat("0", 64)}, Reproducers: make([]PublicReproducer, 103), Nonclaims: []string{"no per-step Java counter parity", rustInputDerivationNote}}
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

func TestRustPublicReplayRejectsUnboundedConfiguration(t *testing.T) {
	_, err := ReplayRustPublic(context.Background(), RustReplayConfig{
		RepositoryRoot:  repositoryRoot(t),
		Executable:      os.Args[0],
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

func TestNeutralStepCanonicalizesZeroObservationsAsArray(t *testing.T) {
	record := &bytes.Buffer{}
	_ = binary.Write(record, binary.BigEndian, uint16(0))
	record.Write([]byte{1, 3, 3})
	for range 3 {
		_ = binary.Write(record, binary.BigEndian, uint64(0))
	}
	_ = binary.Write(record, binary.BigEndian, uint16(0))
	step, err := decodeRustStep(record.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if step.Observations == nil {
		t.Fatal("zero observations decoded as nil")
	}
	raw, err := json.Marshal(step)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"observations":[]`)) {
		t.Fatalf("step JSON = %s", raw)
	}
}

func TestCloseCodecAcceptsOnlyClosedTransportOriginExtension(t *testing.T) {
	body := []byte{0, 0, 0, 0, 0, 0, 5}
	close, err := decodeCloseBody(body)
	if err != nil || close.Origin != "transport" {
		t.Fatalf("transport origin=%#v err=%v", close, err)
	}
	body[len(body)-1] = 6
	if _, err := decodeCloseBody(body); err == nil {
		t.Fatal("unknown extended close origin accepted")
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
	var invalidWireClose *OracleCell
	for index := range hierarchy.Cells {
		cell := &hierarchy.Cells[index]
		if cell.ScenarioID == "us005.pub.0019" && cell.Pointer == "/final_state" {
			invalidWireClose = cell
			break
		}
	}
	if invalidWireClose == nil || invalidWireClose.Authority != "rfc6455.section-7-4" || invalidWireClose.Rank != 1 {
		t.Fatalf("invalid wire close authority=%#v", invalidWireClose)
	}
	wantOverrides := map[string]string{
		"us005.pub.0021|/frames/0/payload_base64": "rfc6455.section-5-5-1",
		"us005.pub.0035|/outcome":                 "rfc6455.section-7-4",
		"us005.pub.0046|/close/code":              "rfc6455.section-5-5-1",
	}
	for _, cell := range hierarchy.Cells {
		key := cell.ScenarioID + "|" + cell.Pointer
		if authority, ok := wantOverrides[key]; ok && cell.Authority == authority && cell.Rank == 1 {
			delete(wantOverrides, key)
		}
	}
	if len(wantOverrides) != 0 {
		t.Fatalf("RFC close overrides absent: %v", wantOverrides)
	}
	bad := hierarchy
	bad.Cells = append([]OracleCell(nil), hierarchy.Cells[1:]...)
	bad.CellCount--
	if err := ValidateOracleHierarchy(scenarios, bad); err == nil {
		t.Fatal("missing cell accepted")
	}
}

func TestOracleHierarchySelectsLosslessFailureAndCloseSurfaces(t *testing.T) {
	scenarios := publicScenarios(t)
	hierarchy, err := BuildOracleHierarchy(scenarios)
	if err != nil {
		t.Fatalf("BuildOracleHierarchy: %v", err)
	}
	find := func(scenarioID, pointer string) OracleCell {
		t.Helper()
		for _, cell := range hierarchy.Cells {
			if cell.ScenarioID == scenarioID && cell.Pointer == pointer {
				return cell
			}
		}
		t.Fatalf("missing cell %s%s", scenarioID, pointer)
		return OracleCell{}
	}
	wantDigest := func(value any) string {
		t.Helper()
		raw, err := canonicalOracleValue(value)
		if err != nil {
			t.Fatalf("canonical: %v", err)
		}
		return digest(raw)
	}

	transition := find("us005.pub.0005", "/transitions")
	wantTransition := []commonTransition{{Step: 0, From: "open", To: "closed"}}
	if transition.Authority != "rfc6455.section-7-1-7" || transition.Rank != 1 || transition.ExpectedSHA256 != wantDigest(wantTransition) {
		t.Fatalf("terminal transition cell = %#v", transition)
	}

	rejected := find("us005.pub.0039", "/frames")
	wantRejected := []commonFrame{{Step: 0, Direction: "inbound", Fin: true, Opcode: "continuous", Masked: true, PayloadB64: "4m6L", WireLength: 9}}
	if rejected.Authority != "neutral" || rejected.Rank != 3 || rejected.ExpectedSHA256 != wantDigest(wantRejected) {
		t.Fatalf("rejected frame cell = %#v", rejected)
	}

	restart := find("us005.pub.0042", "/frames")
	wantRestart := []commonFrame{
		{Step: 0, Direction: "inbound", Fin: false, Opcode: "text", Masked: true, PayloadB64: "V309", WireLength: 9},
		{Step: 1, Direction: "inbound", Fin: true, Opcode: "binary", Masked: true, PayloadB64: "X6Tr", WireLength: 9},
	}
	if restart.Authority != "neutral" || restart.Rank != 3 || restart.ExpectedSHA256 != wantDigest(wantRestart) {
		t.Fatalf("fragment restart frames cell = %#v", restart)
	}

	actionLimit := find("us005.pub.0030", "/frames")
	wantActionLimit := []commonFrame{{Step: 0, Direction: "outbound", Fin: true, Opcode: "text", Masked: true, PayloadB64: "YQ==", WireLength: 7}}
	if actionLimit.Authority != "neutral" || actionLimit.Rank != 3 || actionLimit.ExpectedSHA256 != wantDigest(wantActionLimit) {
		t.Fatalf("action limit frames cell = %#v", actionLimit)
	}

	frameLimit := find("us005.pub.0032", "/frames")
	wantFrameLimit := []commonFrame{{Step: 0, Direction: "inbound", Fin: true, Opcode: "text", Masked: true, PayloadB64: "d0c=", WireLength: 8}}
	if frameLimit.Authority != "neutral" || frameLimit.Rank != 3 || frameLimit.ExpectedSHA256 != wantDigest(wantFrameLimit) {
		t.Fatalf("frame limit frames cell = %#v", frameLimit)
	}

	actionRejection := find("us005.pub.0000", "/transitions")
	if actionRejection.Authority != "neutral" || actionRejection.Rank != 3 || actionRejection.ExpectedSHA256 != wantDigest([]commonTransition{}) {
		t.Fatalf("action rejection transition cell = %#v", actionRejection)
	}

	localClosePayload := find("us005.pub.0034", "/frames/0/payload_base64")
	if localClosePayload.Authority != "neutral" || localClosePayload.Rank != 3 || localClosePayload.ExpectedSHA256 != wantDigest("A/NLWGlkbg==") {
		t.Fatalf("local close payload cell = %#v", localClosePayload)
	}

	closePayload := find("us005.pub.0050", "/frames/1/payload_base64")
	if closePayload.Authority != "rfc6455.section-5-5-1" || closePayload.Rank != 1 || closePayload.ExpectedSHA256 != wantDigest("A+h4cGg6") {
		t.Fatalf("close echo payload cell = %#v", closePayload)
	}
	closeWire := find("us005.pub.0050", "/frames/1/wire_length")
	if closeWire.Authority != "rfc6455.section-5-5-1" || closeWire.Rank != 1 || closeWire.ExpectedSHA256 != wantDigest(float64(8)) {
		t.Fatalf("close echo wire cell = %#v", closeWire)
	}
}

func TestMinimizerCandidateHierarchyDerivesBoundedPrefixesFromPublicBytes(t *testing.T) {
	scenarios := publicScenarios(t)
	byFamily := map[string]corpora.Scenario{}
	for _, scenario := range scenarios {
		byFamily[scenario.Family] = scenario
	}
	frameLimit := byFamily["frame-limit"]
	decoded, err := decodePublicInboundFrames(frameLimit)
	if err != nil || len(decoded) != 2 {
		t.Fatalf("public frame-limit bytes decode=%d err=%v", len(decoded), err)
	}
	selected, ok, err := selectedRejectedFrames(frameLimit)
	if err != nil || !ok || len(selected) != 1 || !canonicalEqual(selected[0], decoded[0]) {
		t.Fatalf("selected public frame prefix=%#v ok=%v err=%v", selected, ok, err)
	}
	for name, candidate := range map[string]corpora.Scenario{
		"frame-limit-zero-input": func() corpora.Scenario {
			value := frameLimit
			value.Core.Steps = []corpora.Step{}
			return value
		}(),
		"action-limit-zero-action": func() corpora.Scenario {
			value := byFamily["action-limit"]
			value.Core.Steps = []corpora.Step{}
			return value
		}(),
		"input-limit-zero-input": func() corpora.Scenario {
			value := byFamily["input-limit"]
			value.Core.Steps = []corpora.Step{}
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			hierarchy, err := hierarchyForCandidate(scenarios, candidate)
			if err != nil {
				t.Fatalf("candidate hierarchy: %v", err)
			}
			for _, cell := range hierarchy.Cells {
				if cell.ScenarioID == candidate.ScenarioID && cell.Pointer == "/frames" && cell.ExpectedSHA256 != digest([]byte("[]")) {
					t.Fatalf("zero-step selected frame prefix digest=%s", cell.ExpectedSHA256)
				}
			}
		})
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
	committed, err := migrateLedger(raw)
	if err != nil {
		t.Fatalf("migrateLedger: %v", err)
	}
	if committed.SchemaVersion != "1.1.0" || len(committed.Records) == 0 {
		t.Fatalf("committed ledger = %#v", committed)
	}
	migrated, err := marshalIndented(committed)
	if err != nil {
		t.Fatal(err)
	}
	if err := compileAndValidateSchema(filepath.Join(root, "schemas/behavior-delta-ledger-1.1.0.schema.json"), migrated); err != nil {
		t.Fatalf("ledger schema: %v", err)
	}
	ledger := emptyMigratedLedgerForTest(t)
	if ledger.SchemaVersion != "1.1.0" || len(ledger.Records) != 0 {
		t.Fatalf("migration = %#v", ledger)
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

func TestVerifyBehaviorDeltaLedgerIsStrictAndClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "evidence/java/behavior-delta-ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := VerifyBehaviorDeltaLedger(raw)
	if err != nil {
		t.Fatalf("committed ledger: %v", err)
	}
	if summary.SchemaVersion != "1.1.0" || summary.Status != "PASS_WITH_CLOSED_HISTORY" || summary.RecordCount != 112 || !summary.CurrentDeltasResolved || summary.Production || summary.Publication {
		t.Fatalf("summary=%#v", summary)
	}

	mutate := func(t *testing.T, change func(map[string]any)) []byte {
		t.Helper()
		var candidate map[string]any
		if err := json.Unmarshal(raw, &candidate); err != nil {
			t.Fatal(err)
		}
		change(candidate)
		encoded, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	for name, candidate := range map[string][]byte{
		"unsupported-version": mutate(t, func(v map[string]any) { v["schema_version"] = "9.9.9" }),
		"unknown-top":         mutate(t, func(v map[string]any) { v["unknown"] = true }),
		"unknown-record": mutate(t, func(v map[string]any) {
			v["records"].([]any)[0].(map[string]any)["unknown"] = true
		}),
		"broken-previous": mutate(t, func(v map[string]any) {
			v["records"].([]any)[1].(map[string]any)["previous_digest"] = digest([]byte("wrong"))
		}),
		"broken-head": mutate(t, func(v map[string]any) { v["head"] = digest([]byte("wrong")) }),
		"broken-hash": mutate(t, func(v map[string]any) {
			v["records"].([]any)[0].(map[string]any)["record_digest"] = digest([]byte("wrong"))
		}),
		"unresolved":  mutate(t, func(v map[string]any) { v["status"] = "BLOCKED_UNRESOLVED_CURRENT_DELTAS" }),
		"production":  mutate(t, func(v map[string]any) { v["production"] = true }),
		"publication": mutate(t, func(v map[string]any) { v["publication"] = true }),
	} {
		t.Run(name, func(t *testing.T) {
			if summary, err := VerifyBehaviorDeltaLedger(candidate); err == nil {
				t.Fatalf("hostile ledger accepted: %#v", summary)
			}
		})
	}
	duplicate := bytes.Replace(raw, []byte(`"schema_version": "1.1.0",`), []byte(`"schema_version": "1.1.0", "schema_version": "1.1.0",`), 1)
	if summary, err := VerifyBehaviorDeltaLedger(duplicate); err == nil {
		t.Fatalf("duplicate schema version accepted: %#v", summary)
	}
}

func TestObservedRustDefectRemainsVisibleAfterClosingRun(t *testing.T) {
	ledger := emptyMigratedLedgerForTest(t)
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
	if err := appendObservedRemediations(&ledger, hierarchy, scenarios[5], java, rust, closingJava, closingRust, strings.Repeat("c", 40)); err != nil {
		t.Fatalf("appendObservedRemediations: %v", err)
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
	closedJava, err := neutralObservation(scenarios[15])
	if err != nil {
		t.Fatal(err)
	}
	if err := appendObservedRemediations(&ledger, hierarchy, scenarios[15], closedJava, closedJava, digest([]byte("closed-java")), digest([]byte("closed-rust")), strings.Repeat("e", 40)); err != nil {
		t.Fatalf("append closed-state remediations: %v", err)
	}
	if len(ledger.Records) != 3 || ledger.Records[1].Pointer != "/counts/consumed_bytes" || ledger.Records[2].Pointer != "/counts/input_bytes" {
		t.Fatalf("retained field records=%#v", ledger.Records)
	}
	closedNoop, err := neutralObservation(scenarios[17])
	if err != nil {
		t.Fatal(err)
	}
	if err := appendObservedRemediations(&ledger, hierarchy, scenarios[17], closedNoop, closedNoop, digest([]byte("noop-java")), digest([]byte("noop-rust")), strings.Repeat("f", 40)); err != nil {
		t.Fatalf("append zero-chunk remediations: %v", err)
	}
	if len(ledger.Records) != 5 || ledger.Records[3].Pointer != "/error" || ledger.Records[4].Pointer != "/outcome" {
		t.Fatalf("retained zero-chunk records=%#v", ledger.Records)
	}
}

func TestLocaleHarnessArtifactIsRetractedWithoutRewritingHistory(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "evidence/java/behavior-delta-ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := migrateLedger(raw)
	if err != nil {
		t.Fatal(err)
	}
	uncorrected := make([]LedgerRecord, 0, len(ledger.Records))
	for _, record := range ledger.Records {
		if record.Classification != "harness_artifact_correction" {
			uncorrected = append(uncorrected, record)
		}
	}
	ledger.Records = uncorrected
	ledger.Head = ledger.Records[len(ledger.Records)-1].RecordDigest
	scenarios := publicScenarios(t)
	hierarchy, err := BuildOracleHierarchy(scenarios)
	if err != nil {
		t.Fatal(err)
	}
	var scenario corpora.Scenario
	for _, candidate := range scenarios {
		if candidate.ScenarioID == "us005.pub.0006" {
			scenario = candidate
			break
		}
	}
	if scenario.ScenarioID == "" {
		t.Fatal("fixture scenario absent")
	}
	aligned, err := neutralObservation(scenario)
	if err != nil {
		t.Fatal(err)
	}
	before := len(ledger.Records)
	closingJava := digest([]byte("utf8-java"))
	closingRust := digest([]byte("utf8-rust"))
	anchor := strings.Repeat("9", 40)
	if err := appendObservedHarnessCorrections(&ledger, hierarchy, scenario, aligned, aligned, closingJava, closingRust, anchor); err != nil {
		t.Fatalf("append harness correction: %v", err)
	}
	if len(ledger.Records) != before+1 {
		t.Fatalf("correction count=%d want=%d", len(ledger.Records), before+1)
	}
	correction := ledger.Records[len(ledger.Records)-1]
	originalDeltaID := deltaIDFor(scenario.ScenarioID, "/events/0/text")
	if correction.DeltaID != harnessCorrectionDeltaID(originalDeltaID) || correction.SupersedesDeltaID != originalDeltaID || correction.Classification != "harness_artifact_correction" || correction.Resolution != "retracted_harness_artifact" || correction.CorrectionReason != localeProtocolEncodingCorrection || correction.ClosingJavaObservation != closingJava || correction.ClosingRustObservation != closingRust {
		t.Fatalf("correction=%#v", correction)
	}
	if err := appendObservedHarnessCorrections(&ledger, hierarchy, scenario, aligned, aligned, closingJava, closingRust, anchor); err != nil {
		t.Fatalf("idempotent correction: %v", err)
	}
	if len(ledger.Records) != before+1 {
		t.Fatalf("duplicate correction appended: %d", len(ledger.Records))
	}
	document, err := marshalIndented(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := compileAndValidateSchema(filepath.Join(repositoryRoot(t), "schemas/behavior-delta-ledger-1.1.0.schema.json"), document); err != nil {
		t.Fatalf("corrected ledger schema: %v", err)
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
	rust.Transitions = []commonTransition{{Step: 0, From: "open", To: "closed"}}
	classification, findings, err := adjudicateScenario(scenario, hierarchy, java, rust)
	if err != nil {
		t.Fatalf("RFC-aligned Rust state rejected: %v", err)
	}
	if classification != "java_quirk" || len(findings) != 2 || findings[0].Pointer != "/final_state" || findings[0].Classification != "java_quirk" || findings[1].Pointer != "/transitions" || findings[1].Classification != "java_quirk" {
		t.Fatalf("classification=%s findings=%#v", classification, findings)
	}
	ledger := Ledger{Schema: "../../schemas/behavior-delta-ledger-1.1.0.schema.json", SchemaVersion: ledgerSchemaVersion, EvidenceKind: "behavior-delta-ledger", AcceptedRootDigest: digest([]byte("root")), Status: "PASS_NO_CURRENT_DELTAS", NormativeAuthority: "field-addressed-oracle-hierarchy", Head: "sha256:" + strings.Repeat("0", 64), Records: []LedgerRecord{}, AppendImplementation: "hash-chained-cas"}
	line, _ := scenario.CanonicalLine()
	if err := appendJavaQuirk(&ledger, scenario, findings[0], digest([]byte("java")), digest([]byte("rust")), strings.Repeat("d", 40), digest(line)); err != nil {
		t.Fatalf("append Java quirk: %v", err)
	}
	if len(ledger.Records) != 1 || ledger.Records[0].Resolution != "retained_java_quirk" || ledger.Records[0].ClosingRunAnchor != "" {
		t.Fatalf("Java quirk lifecycle=%#v", ledger.Records)
	}
	rust.Counts.ConsumedBytes = 2
	rust.Counts.InputBytes = 2
	_, findings, err = adjudicateScenario(scenario, hierarchy, java, rust)
	defectPointers := []string{}
	for _, finding := range findings {
		if finding.Classification == "rust_defect" {
			defectPointers = append(defectPointers, finding.Pointer)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "rust_defect") || len(defectPointers) != 2 || defectPointers[0] != "/counts/consumed_bytes" || defectPointers[1] != "/counts/input_bytes" {
		t.Fatalf("counter defect accepted: %v", err)
	}
}

func TestFieldAdjudicationClassifiesMissingStructuralValues(t *testing.T) {
	scenarios := publicScenarios(t)
	hierarchy, err := BuildOracleHierarchy(scenarios)
	if err != nil {
		t.Fatal(err)
	}
	java, err := neutralObservation(scenarios[22])
	if err != nil {
		t.Fatal(err)
	}
	rust := java
	rust.Events = []commonEvent{}
	_, findings, err := adjudicateScenario(scenarios[22], hierarchy, java, rust)
	if err == nil || !strings.Contains(err.Error(), "rust_defect") || len(findings) == 0 {
		t.Fatalf("missing structural values not classified: findings=%#v err=%v", findings, err)
	}
}

func TestRustAcceptedInputExcludesClosedStateRejection(t *testing.T) {
	source := corpora.Step{Kind: "bytes", DataBase64: "XYcK"}
	closed := rustStep{PreState: "closed", Consumed: 0, Observations: []rustItem{{Error: &commonError{Class: "INVALID_STATE"}}}}
	if got, err := acceptedRustInputBytes(source, closed); err != nil || got != 0 {
		t.Fatalf("closed rejected input = %d, %v", got, err)
	}
	open := rustStep{PreState: "open", Consumed: 3, Observations: []rustItem{{Error: &commonError{Class: "FRAME_RESERVED_BITS"}}}}
	if got, err := acceptedRustInputBytes(source, open); err != nil || got != 3 {
		t.Fatalf("open accepted input = %d, %v", got, err)
	}
	empty := corpora.Step{Kind: "bytes", DataBase64: ""}
	closedNoop := rustStep{PreState: "closed", Consumed: 0}
	if got, err := acceptedRustInputBytes(empty, closedNoop); err != nil || got != 0 {
		t.Fatalf("closed zero-chunk no-op = %d, %v", got, err)
	}
	inputLimit := rustStep{PreState: "open", Consumed: 0, Observations: []rustItem{{Error: &commonError{Class: "INPUT_LIMIT_EXCEEDED"}}}}
	if got, err := acceptedRustInputBytes(source, inputLimit); err != nil || got != 0 {
		t.Fatalf("input-limit rejected input = %d, %v", got, err)
	}
	inputLimit.Consumed = 1
	if _, err := acceptedRustInputBytes(source, inputLimit); err == nil {
		t.Fatal("input-limit rejection with consumed bytes accepted")
	}
}

func TestCommonErrorNormalizationKeepsTypedBufferLimit(t *testing.T) {
	scenario := publicScenarios(t)[31]
	observation, err := neutralObservation(scenario)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Error == nil || observation.Error.Class != "LIMIT_EXCEEDED" {
		t.Fatalf("buffer limit class=%#v", observation.Error)
	}
}

func TestVerifierRejectsInvalidClosedStepAndDerivedCounterOverclaim(t *testing.T) {
	scenario := publicScenarios(t)[15]
	result := ScenarioResult{
		ScenarioID:             scenario.ScenarioID,
		RustObservation:        commonObservation{Counts: commonCounts{InputBytes: 0, ConsumedBytes: 0}},
		RustStepDiagnostics:    []rustStep{{InputKind: 1, PreState: "closed", Consumed: 0, Observations: []rustItem{{Error: &commonError{Class: "INVALID_STATE"}}}}},
		RustNormalizationNotes: []string{rustInputDerivationNote},
	}
	if err := validateRustDerivedCounters(scenario, result); err != nil {
		t.Fatalf("valid derived counters: %v", err)
	}
	result.RustStepDiagnostics[0].Consumed = 3
	result.RustObservation.Counts.ConsumedBytes = 3
	if err := validateRustDerivedCounters(scenario, result); err == nil {
		t.Fatal("nonzero Closed-state consumption accepted")
	}
	result.RustStepDiagnostics[0].Consumed = 0
	result.RustObservation.Counts.ConsumedBytes = 0
	result.RustStepDiagnostics[0].Observations = nil
	if err := validateRustDerivedCounters(scenario, result); err == nil {
		t.Fatal("Closed byte step without typed INVALID_STATE accepted")
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
	manifest.Counts.Processes++
	manifest.Reproducers = manifest.Reproducers[:102]
	raw, _ = json.Marshal(manifest)
	if err := verifyManifestValue(repositoryRoot(t), raw); err == nil || !strings.Contains(err.Error(), "exactly 103") {
		t.Fatalf("non-exact reproducer set accepted: %v", err)
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
	for _, input := range []string{"LIMIT_FRAME_BYTES", "LIMIT_TOTAL_BUFFERED_BYTES", "ACTION_LIMIT_EXCEEDED", "FRAME_LIMIT_EXCEEDED", "INPUT_LIMIT_EXCEEDED"} {
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

func TestDiagnosticValueReportsExactFieldWithoutWritingEvidence(t *testing.T) {
	observation := commonObservation{Frames: []commonFrame{{Step: 2, Direction: "inbound", Fin: true, Opcode: "text", PayloadB64: "YQ==", WireLength: 3}}}
	got, err := diagnosticValue(observation, "/frames")
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"direction":"inbound","fin":true,"masked":false,"opcode":"text","payload_base64":"YQ==","step":2,"wire_length":3}]`
	if got != want {
		t.Fatalf("diagnostic value = %s", got)
	}
}

func TestObservationDifferencesReportsEveryDeterministicLeaf(t *testing.T) {
	left := commonObservation{
		FinalState: "open",
		Frames: []commonFrame{{
			Direction:  "inbound",
			PayloadB64: "YQ==",
			WireLength: 3,
		}},
	}
	right := commonObservation{
		FinalState: "closed",
		Frames: []commonFrame{{
			Direction:  "inbound",
			PayloadB64: "Yg==",
			WireLength: 4,
		}},
	}
	got, err := observationDifferences(left, right)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/final_state", "/frames/0/payload_base64", "/frames/0/wire_length"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("differences = %v, want %v", got, want)
	}
	first, err := firstDifference(left, right)
	if err != nil || first != want[0] {
		t.Fatalf("first = %q, %v, want %q", first, err, want[0])
	}
}

func TestPortableParityDiagnosticSchemaHasNoHostPaths(t *testing.T) {
	ids := make([]string, 0, 74)
	for index := 1; index <= 74; index++ {
		ids = append(ids, fmt.Sprintf("us005.pub.%04d", index))
	}
	inputs := make([]PortableArtifactIdentity, 0, 10)
	for index := 0; index < 10; index++ {
		inputs = append(inputs, PortableArtifactIdentity{
			Kind:   fmt.Sprintf("input-%02d", index),
			SHA256: digest([]byte(fmt.Sprintf("input-%02d", index))),
			Bytes:  int64(index + 1),
		})
	}
	report := DiagnosticReport{
		Schema:                   "../../schemas/differential-diagnostic-1.0.0.schema.json",
		SchemaVersion:            "1.0.0",
		EvidenceID:               "evidence.us-020-java-parity-diagnostic",
		StoryID:                  "US-020",
		Status:                   "JAVA_PARITY_DIAGNOSTIC_ONLY_NO_WRITES",
		BehaviorProfile:          "java-websocket-1.6.0",
		Assurance:                "OWNER_ATTESTED_NOT_INDEPENDENT",
		IndependentReviewClaimed: false,
		Production:               false,
		Publication:              false,
		RepositoryAnchor:         strings.Repeat("a", 40),
		Inputs:                   inputs,
		ScenarioCount:            74,
		ProcessReceipts:          296,
		StableScenarios:          74,
		ExactAgreements:          74,
		ExactScenarioIDs:         ids,
		MismatchScenarioIDs:      []string{},
		Findings:                 []DiagnosticFinding{},
		AcceptedFindings:         []DiagnosticFinding{},
		Nonclaims: []string{
			"portable summary omits raw process receipts and normalization traces",
			"canonical strict differential manifest remains the raw replay evidence",
			"no hidden sealed Autobahn performance production publication signing or independent review claim",
		},
	}
	raw, err := marshalIndented(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("/Users/")) {
		t.Fatalf("portable diagnostic contains a host path: %s", raw)
	}
	schemaPath := filepath.Join(repositoryRoot(t), "schemas/differential-diagnostic-1.0.0.schema.json")
	if err := compileAndValidateSchema(schemaPath, raw); err != nil {
		t.Fatalf("valid portable diagnostic rejected: %v", err)
	}
	report.Inputs[0].SHA256 = "not-a-digest"
	tampered, err := marshalIndented(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := compileAndValidateSchema(schemaPath, tampered); err == nil {
		t.Fatal("schema accepted a malformed artifact digest")
	}
}

func TestJavaParityProjectionOmitsPartialFailureDetailsButKeepsCounts(t *testing.T) {
	var scenario corpora.Scenario
	for _, candidate := range publicScenarios(t) {
		if candidate.ScenarioID == "us005.pub.0030" {
			scenario = candidate
			break
		}
	}
	if scenario.ScenarioID == "" {
		t.Fatal("public action-limit scenario absent")
	}
	frame := commonFrame{
		Step:       0,
		Direction:  "outbound",
		Fin:        true,
		Opcode:     "text",
		Masked:     true,
		PayloadB64: "YQ==",
		WireLength: 7,
	}
	raw := testEncodeRustObservation(rustObservation{
		ScenarioID: scenario.ScenarioID,
		Role:       scenario.Core.Role,
		Initial:    scenario.Core.InitialState,
		Final:      "open",
		Steps: []rustStep{
			{Index: 0, InputKind: 16, PreState: "open", PostState: "open", Observations: []rustItem{{Kind: 2, Frame: &frame}}},
			{Index: 1, InputKind: 16, PreState: "open", PostState: "open", Observations: []rustItem{{Kind: 5, Error: &commonError{Class: "ACTION_LIMIT_EXCEEDED"}}}},
		},
	})
	strict, _, err := normalizeRust(scenario, raw)
	if err != nil {
		t.Fatal(err)
	}
	java, _, err := normalizeRustWithProfile(scenario, raw, rustBehaviorJavaWebSocketV1_6_0)
	if err != nil {
		t.Fatal(err)
	}
	if len(strict.Frames) != 1 || len(java.Frames) != 0 {
		t.Fatalf("strict frames=%d Java frames=%d", len(strict.Frames), len(java.Frames))
	}
	if strict.Counts.Frames != 1 || java.Counts.Frames != 1 || java.Error == nil || java.Outcome != "error" {
		t.Fatalf("strict=%+v Java=%+v", strict.Counts, java)
	}
}

func TestVerifierRederivesEveryBoundIdentityAndLink(t *testing.T) {
	root := repositoryRoot(t)
	raw, baseline := committedManifestForTest(t)
	if len(baseline.Reproducers) != 103 {
		if err := VerifyPublicDifferential(root, raw); err == nil {
			t.Fatal("pre-remediation receipt without 103 reproducers was accepted")
		}
		t.Log("pre-remediation receipt is correctly rejected until the authorized replacement run")
		return
	}
	if err := VerifyPublicDifferential(root, raw); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	mutations := map[string]func(*Manifest){
		"input-identity":        func(v *Manifest) { v.Inputs[0].SHA256 = digest([]byte("forged-input")) },
		"scenario-process-link": func(v *Manifest) { v.Scenarios[0].JavaPrimary = digest([]byte("forged-normalized")) },
		"process-source-link":   func(v *Manifest) { v.Processes[0].StdinSHA256 = digest([]byte("forged-stdin")) },
		"observation-link":      func(v *Manifest) { v.Scenarios[0].JavaObservation.FinalState = "closed" },
		"control-set":           func(v *Manifest) { v.Controls.Results[0].ControlID = "forged-control" },
		"coverage-source":       func(v *Manifest) { v.Coverage.Migration[0].SourceSHA256 = digest([]byte("forged-row")) },
		"ledger-pre-head":       func(v *Manifest) { v.Ledger.PreHead = digest([]byte("forged-head")) },
		"execution-anchor":      func(v *Manifest) { v.RepositoryAnchor = strings.Repeat("a", 40) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := baseline
			candidate.Inputs = append([]ArtifactIdentity(nil), baseline.Inputs...)
			candidate.Scenarios = append([]ScenarioResult(nil), baseline.Scenarios...)
			candidate.Processes = append([]ProcessReceipt(nil), baseline.Processes...)
			candidate.Controls.Results = append([]ControlResult(nil), baseline.Controls.Results...)
			candidate.Coverage.Migration = append([]CoverageRow(nil), baseline.Coverage.Migration...)
			mutate(&candidate)
			encoded, err := marshalIndented(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyPublicDifferential(root, encoded); err == nil {
				t.Fatal("forged evidence accepted")
			}
		})
	}
}

func TestCoverageUsesClosedReviewedMapAndExactPredecessorIdentities(t *testing.T) {
	root := repositoryRoot(t)
	receipt, err := buildCoverage(root, publicScenarios(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(reviewedCoverageMap) != 61 {
		t.Fatalf("reviewed mappings=%d", len(reviewedCoverageMap))
	}
	for _, row := range append(append([]CoverageRow{}, receipt.Migration...), receipt.Compatibility...) {
		mapping, ok := reviewedCoverageMap[row.ID]
		if !ok {
			t.Fatalf("unreviewed row %s", row.ID)
		}
		if mapping.Fresh != row.FreshUS020 || strings.Join(mapping.ScenarioIDs, ",") != strings.Join(row.ScenarioIDs, ",") {
			t.Fatalf("mapping drift for %s", row.ID)
		}
		if !row.FreshUS020 && row.ExcludedReason == "" {
			if len(row.PredecessorIdentities) != len(row.PredecessorPaths) || len(row.PredecessorIdentities) == 0 {
				t.Fatalf("predecessor identity absent for %s", row.ID)
			}
			for index, identity := range row.PredecessorIdentities {
				if identity.Path != row.PredecessorPaths[index] || !validLedgerDigest(identity.SHA256) || identity.Bytes <= 0 {
					t.Fatalf("predecessor identity invalid for %s: %#v", row.ID, identity)
				}
			}
		}
	}
}

func TestUnknownJavaEventsFailClosedAndCollisionControlUsesAudit(t *testing.T) {
	unknown := map[string]any{"type": "brand_new_callback", "step": float64(0)}
	if _, _, err := normalizeJavaEvent(unknown); err == nil {
		t.Fatal("unknown Java event was silently erased")
	}
	allowed := map[string]any{"type": "input_chunk", "step": float64(0), "bytes": float64(1)}
	if _, keep, err := normalizeJavaEvent(allowed); err != nil || keep {
		t.Fatalf("reviewed adapter-only event not allowlisted: keep=%v err=%v", keep, err)
	}
	code, err := auditReplayNormalization(
		NormalizationTrace{RawSHA256: digest([]byte("raw-a")), NormalizedSHA256: digest([]byte("same"))},
		NormalizationTrace{RawSHA256: digest([]byte("raw-b")), NormalizedSHA256: digest([]byte("same"))},
	)
	if err == nil || code != "NORMALIZATION_COLLISION" {
		t.Fatalf("collision audit code=%q err=%v", code, err)
	}
	controls, err := runSeededControls()
	if err != nil {
		t.Fatal(err)
	}
	for _, control := range controls.Results {
		if control.ControlID == "normalization-collision" && control.DetectedCode != code {
			t.Fatalf("planted collision bypassed audit: %#v", control)
		}
	}
}

func TestStrictCompleteV10MigrationRetainsRecords(t *testing.T) {
	zero := "sha256:" + strings.Repeat("0", 64)
	delta := legacyDeltaForTest()
	record := LegacyLedgerRecord{SchemaVersion: "1.0.0", Sequence: 1, PreviousDigest: zero, Delta: delta}
	want, err := legacyRecordDigest(record)
	if err != nil {
		t.Fatal(err)
	}
	record.RecordDigest = want
	old := LegacyLedger{Schema: "../../schemas/behavior-delta-ledger-1.0.0.schema.json", SchemaVersion: "1.0.0", EvidenceKind: "behavior-delta-ledger", AcceptedRootDigest: digest([]byte("root")), Status: "READY", NormativeAuthority: "rfc6455", Head: want, Records: []LegacyLedgerRecord{record}, AppendImplementation: "hash-chained-cas", UnledgeredDisagreements: 0}
	raw, _ := json.Marshal(old)
	migrated, err := migrateLedger(raw)
	if err != nil {
		t.Fatalf("complete v1 migration: %v", err)
	}
	if len(migrated.MigratedV1Records) != 1 || migrated.MigrationSourceHead != want || migrated.Head != want {
		t.Fatalf("migration lost history: %#v", migrated)
	}
	document, err := marshalIndented(migrated)
	if err != nil {
		t.Fatal(err)
	}
	if err := compileAndValidateSchema(filepath.Join(repositoryRoot(t), "schemas/behavior-delta-ledger-1.1.0.schema.json"), document); err != nil {
		t.Fatalf("migrated v1.1 document schema: %v", err)
	}
	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	object["unknown"] = true
	hostile, _ := json.Marshal(object)
	if _, err := migrateLedger(hostile); err == nil {
		t.Fatal("unknown v1 field accepted")
	}
}

func TestPersistentLedgerAppendIsRerunnable(t *testing.T) {
	ledger := emptyMigratedLedgerForTest(t)
	cell := OracleCell{ScenarioID: "us005.pub.0000", Pointer: "/error/class", Authority: "neutral", Rank: 3, ExpectedSHA256: digest([]byte("x")), Evidence: []OracleEvidence{{Kind: "neutral", ID: "us005.pub.0000", SHA256: digest([]byte("x"))}}}
	record := LedgerRecord{DeltaID: "delta.us005.pub.0000.error", ScenarioID: "us005.pub.0000", Pointer: "/error/class", Classification: "java_quirk", JavaObservation: digest([]byte("j")), RustObservation: digest([]byte("r")), ReproducerSHA256: digest([]byte("p")), Decision: cell, Resolution: "retained_java_quirk", FindingRunAnchor: strings.Repeat("a", 40)}
	if err := appendLedgerRecord(&ledger, ledger.Head, record); err != nil {
		t.Fatal(err)
	}
	head := ledger.Head
	record.FindingRunAnchor = strings.Repeat("b", 40)
	if err := appendLedgerRecord(&ledger, ledger.Head, record); err != nil {
		t.Fatalf("rerun should preserve first finding: %v", err)
	}
	if len(ledger.Records) != 1 || ledger.Head != head || ledger.Records[0].FindingRunAnchor != strings.Repeat("a", 40) {
		t.Fatal("rerun changed persistent history")
	}
}

func TestOnDiskLockAndJournaledPairRecovery(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	lock, err := acquireEvidenceLock(dir, ledgerPath, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if within(dir, lock.path) {
		t.Fatalf("coordination file is inside repository: %s", lock.path)
	}
	if _, err := acquireEvidenceLock(dir, ledgerPath, manifestPath); err == nil {
		t.Fatal("concurrent on-disk writer accepted")
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(lock.path); err != nil {
		t.Fatalf("stable coordination file absent after release: %v", err)
	}
	reacquired, err := acquireEvidenceLock(dir, ledgerPath, manifestPath)
	if err != nil {
		t.Fatalf("crash/stale coordination file was not reusable: %v", err)
	}
	coordinationPath := reacquired.path
	defer func() {
		if err := reacquired.Release(); err != nil {
			t.Error(err)
		}
		_ = os.Remove(coordinationPath)
	}()
	if err := recoverEvidencePair(nil, ledgerPath, manifestPath); err == nil {
		t.Fatal("journal recovery without exclusive coordination was accepted")
	}
	if err := commitEvidencePair(reacquired, ledgerPath, []byte("ledger\n"), manifestPath, []byte("manifest\n")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(ledgerPath); string(got) != "ledger\n" {
		t.Fatalf("ledger=%q", got)
	}
	if got, _ := os.ReadFile(manifestPath); string(got) != "manifest\n" {
		t.Fatalf("manifest=%q", got)
	}
	ledgerStage, err := stageDocument(ledgerPath, []byte("ledger-recovered\n"))
	if err != nil {
		t.Fatal(err)
	}
	manifestStage, err := stageDocument(manifestPath, []byte("manifest-recovered\n"))
	if err != nil {
		t.Fatal(err)
	}
	journal := pairJournal{SchemaVersion: "1.0.0", LedgerPath: ledgerPath, LedgerStage: ledgerStage, LedgerSHA256: digest([]byte("ledger-recovered\n")), ManifestPath: manifestPath, ManifestStage: manifestStage, ManifestSHA256: digest([]byte("manifest-recovered\n"))}
	if err := writeJSONAtomic(ledgerPath+".us020-journal", journal); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ledgerStage, ledgerPath); err != nil {
		t.Fatal(err)
	}
	if err := recoverEvidencePair(reacquired, ledgerPath, manifestPath); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(ledgerPath); string(got) != "ledger-recovered\n" {
		t.Fatalf("recovered ledger=%q", got)
	}
	if got, _ := os.ReadFile(manifestPath); string(got) != "manifest-recovered\n" {
		t.Fatalf("recovered manifest=%q", got)
	}
}

func TestEvidenceCoordinationPathIsStableAcrossProcessTempEnvironment(t *testing.T) {
	dir, err := makeRealTemporaryDirectory("us020-coordination-key-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	ledgerPath := filepath.Join(dir, "ledger.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	firstTemp, err := makeRealTemporaryDirectory("us020-temp-a-")
	if err != nil {
		t.Fatal(err)
	}
	secondTemp, err := makeRealTemporaryDirectory("us020-temp-b-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(firstTemp)
	defer os.RemoveAll(secondTemp)
	for _, path := range []string{firstTemp, secondTemp} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TMPDIR", firstTemp)
	first, err := evidenceCoordinationPath(dir, ledgerPath, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", secondTemp)
	second, err := evidenceCoordinationPath(dir, ledgerPath, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("coordination path changed across process temp environments: %s != %s", first, second)
	}
}

func TestEvidenceCrashWriterHelper(t *testing.T) {
	if os.Getenv("US020_CRASH_WRITER") != "1" {
		return
	}
	repositoryRoot := os.Getenv("US020_CRASH_REPOSITORY")
	ledgerPath := os.Getenv("US020_CRASH_LEDGER")
	manifestPath := os.Getenv("US020_CRASH_MANIFEST")
	ledgerRaw, err := os.ReadFile(os.Getenv("US020_CRASH_NEW_LEDGER"))
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile(os.Getenv("US020_CRASH_NEW_MANIFEST"))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := acquireEvidenceLock(repositoryRoot, ledgerPath, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = lock // Deliberately abandoned through os.Exit to simulate a process crash.
	ledgerStage, err := stageDocument(ledgerPath, ledgerRaw)
	if err != nil {
		t.Fatal(err)
	}
	manifestStage, err := stageDocument(manifestPath, manifestRaw)
	if err != nil {
		t.Fatal(err)
	}
	journal := pairJournal{SchemaVersion: "1.0.0", LedgerPath: ledgerPath, LedgerStage: ledgerStage, LedgerSHA256: digest(ledgerRaw), ManifestPath: manifestPath, ManifestStage: manifestStage, ManifestSHA256: digest(manifestRaw)}
	if err := writeJSONAtomic(ledgerPath+".us020-journal", journal); err != nil {
		t.Fatal(err)
	}
	switch os.Getenv("US020_CRASH_DIRECTION") {
	case "ledger-installed":
		if err := os.Rename(ledgerStage, ledgerPath); err != nil {
			t.Fatal(err)
		}
	case "manifest-installed":
		if err := os.Rename(manifestStage, manifestPath); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown crash direction")
	}
	os.Exit(86)
}

func crashLedgerDocument(t *testing.T, label string) ([]byte, Ledger) {
	t.Helper()
	ledger := emptyMigratedLedgerForTest(t)
	ledger.AcceptedRootDigest = digest([]byte(label))
	raw, err := marshalIndented(ledger)
	if err != nil {
		t.Fatal(err)
	}
	return raw, ledger
}

func TestCrashReleasedCoordinationRecoversHalfInstalledPairAndCAS(t *testing.T) {
	for _, direction := range []string{"ledger-installed", "manifest-installed"} {
		t.Run(direction, func(t *testing.T) {
			dir, err := makeRealTemporaryDirectory("us020-crash-recovery-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			ledgerPath := filepath.Join(dir, "ledger.json")
			manifestPath := filepath.Join(dir, "manifest.json")
			oldLedger, _ := crashLedgerDocument(t, "old-"+direction)
			newLedger, newLedgerValue := crashLedgerDocument(t, "new-"+direction)
			oldManifest := []byte("old manifest\n")
			newManifest := []byte("new manifest " + direction + "\n")
			newLedgerSource := filepath.Join(dir, "new-ledger.source")
			newManifestSource := filepath.Join(dir, "new-manifest.source")
			for path, raw := range map[string][]byte{ledgerPath: oldLedger, manifestPath: oldManifest, newLedgerSource: newLedger, newManifestSource: newManifest} {
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			childTemp := filepath.Join(dir, "child-temp")
			if err := os.Mkdir(childTemp, 0o700); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestEvidenceCrashWriterHelper$", "-test.count=1")
			command.Env = append(os.Environ(),
				"TMPDIR="+childTemp,
				"US020_CRASH_WRITER=1",
				"US020_CRASH_REPOSITORY="+dir,
				"US020_CRASH_LEDGER="+ledgerPath,
				"US020_CRASH_MANIFEST="+manifestPath,
				"US020_CRASH_NEW_LEDGER="+newLedgerSource,
				"US020_CRASH_NEW_MANIFEST="+newManifestSource,
				"US020_CRASH_DIRECTION="+direction,
			)
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() != 86 {
				t.Fatalf("crash helper err=%v output=%q", err, output)
			}
			if _, err := os.Lstat(ledgerPath + ".us020-journal"); err != nil {
				t.Fatalf("crash journal absent: %v", err)
			}
			lock, err := acquireEvidenceLock(dir, ledgerPath, manifestPath)
			if err != nil {
				t.Fatalf("OS did not release crashed coordination: %v", err)
			}
			coordinationPath := lock.path
			if err := recoverEvidencePair(lock, ledgerPath, manifestPath); err != nil {
				lock.Release()
				t.Fatalf("recover half-installed pair: %v", err)
			}
			if got, _ := os.ReadFile(ledgerPath); !bytes.Equal(got, newLedger) {
				lock.Release()
				t.Fatal("recovered ledger drift")
			}
			if got, _ := os.ReadFile(manifestPath); !bytes.Equal(got, newManifest) {
				lock.Release()
				t.Fatal("recovered manifest drift")
			}
			if err := recheckLedgerCAS(ledgerPath, digest(newLedger), newLedgerValue.Head); err != nil {
				lock.Release()
				t.Fatalf("post-recovery CAS: %v", err)
			}
			if err := commitEvidencePair(lock, ledgerPath, newLedger, manifestPath, newManifest); err != nil {
				lock.Release()
				t.Fatalf("idempotent completion: %v", err)
			}
			if err := recheckLedgerCAS(ledgerPath, digest(newLedger), newLedgerValue.Head); err != nil {
				lock.Release()
				t.Fatalf("post-idempotent CAS: %v", err)
			}
			if err := lock.Release(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(coordinationPath, []byte("pid=999999 token=irrelevant stale=1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			stale, err := acquireEvidenceLock(dir, ledgerPath, manifestPath)
			if err != nil {
				t.Fatalf("stale PID/token content affected advisory acquisition: %v", err)
			}
			if err := stale.Release(); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(coordinationPath)
			for _, residue := range []string{ledgerPath + ".us020-journal", ledgerPath + ".us020.lock", manifestPath + ".us020.lock"} {
				if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("repository transaction residue %s: %v", residue, err)
				}
			}
			stages, err := filepath.Glob(filepath.Join(dir, ".us020-pair-*.stage"))
			if err != nil || len(stages) != 0 {
				t.Fatalf("stage residue=%v err=%v", stages, err)
			}
		})
	}
}

func TestRecoveryRejectsCorruptAndMismatchedJournalWhileHeld(t *testing.T) {
	dir, err := makeRealTemporaryDirectory("us020-hostile-journal-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	ledgerPath := filepath.Join(dir, "ledger.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	oldLedger, _ := crashLedgerDocument(t, "hostile-old")
	oldManifest := []byte("hostile old manifest\n")
	if err := os.WriteFile(ledgerPath, oldLedger, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, oldManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireEvidenceLock(dir, ledgerPath, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	coordinationPath := lock.path
	defer func() {
		_ = lock.Release()
		_ = os.Remove(coordinationPath)
	}()
	journalPath := ledgerPath + ".us020-journal"
	if err := os.WriteFile(journalPath, []byte(`{"schema_version":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverEvidencePair(lock, ledgerPath, manifestPath); err == nil {
		t.Fatal("corrupt journal accepted")
	}
	if got, _ := os.ReadFile(ledgerPath); !bytes.Equal(got, oldLedger) {
		t.Fatal("corrupt journal changed ledger")
	}
	if got, _ := os.ReadFile(manifestPath); !bytes.Equal(got, oldManifest) {
		t.Fatal("corrupt journal changed manifest")
	}
	if err := os.Remove(journalPath); err != nil {
		t.Fatal(err)
	}
	ledgerStage, err := stageDocument(ledgerPath, []byte("hostile ledger\n"))
	if err != nil {
		t.Fatal(err)
	}
	manifestStage, err := stageDocument(manifestPath, []byte("hostile manifest\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(ledgerStage)
	defer os.Remove(manifestStage)
	mismatched := pairJournal{SchemaVersion: "1.0.0", LedgerPath: ledgerPath, LedgerStage: ledgerStage, LedgerSHA256: digest([]byte("hostile ledger\n")), ManifestPath: filepath.Join(dir, "other-manifest.json"), ManifestStage: manifestStage, ManifestSHA256: digest([]byte("hostile manifest\n"))}
	if err := writeJSONAtomic(journalPath, mismatched); err != nil {
		t.Fatal(err)
	}
	if err := recoverEvidencePair(lock, ledgerPath, manifestPath); err == nil {
		t.Fatal("path-mismatched journal accepted")
	}
	if got, _ := os.ReadFile(ledgerPath); !bytes.Equal(got, oldLedger) {
		t.Fatal("mismatched journal changed ledger")
	}
	if got, _ := os.ReadFile(manifestPath); !bytes.Equal(got, oldManifest) {
		t.Fatal("mismatched journal changed manifest")
	}
	if err := os.Remove(journalPath); err != nil {
		t.Fatal(err)
	}
	digestMismatched := pairJournal{SchemaVersion: "1.0.0", LedgerPath: ledgerPath, LedgerStage: ledgerStage, LedgerSHA256: digest([]byte("different ledger\n")), ManifestPath: manifestPath, ManifestStage: manifestStage, ManifestSHA256: digest([]byte("hostile manifest\n"))}
	if err := writeJSONAtomic(journalPath, digestMismatched); err != nil {
		t.Fatal(err)
	}
	if err := recoverEvidencePair(lock, ledgerPath, manifestPath); err == nil {
		t.Fatal("digest-mismatched journal accepted")
	}
	if got, _ := os.ReadFile(ledgerPath); !bytes.Equal(got, oldLedger) {
		t.Fatal("digest-mismatched journal changed ledger")
	}
	if got, _ := os.ReadFile(manifestPath); !bytes.Equal(got, oldManifest) {
		t.Fatal("digest-mismatched journal changed manifest")
	}
}

func TestOnDiskLedgerCASRejectsSameHeadDocumentReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.json")
	ledger := emptyMigratedLedgerForTest(t)
	raw, _ := marshalIndented(ledger)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recheckLedgerCAS(path, digest(raw), ledger.Head); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["accepted_root_digest"] = digest([]byte("replacement"))
	replacement, _ := json.Marshal(object)
	if err := os.WriteFile(path, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recheckLedgerCAS(path, digest(raw), ledger.Head); err == nil {
		t.Fatal("same-head document replacement accepted")
	}
}

func TestLaunchBundleUsesImmutableContentAddressedBytes(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "runtime")
	jar := filepath.Join(dir, "adapter.jar")
	if err := os.WriteFile(executable, []byte("runtime-v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jar, []byte("jar-v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, err := materializeLaunchInputs(filepath.Join(dir, "store"), []launchSource{{Role: "runtime", Path: executable, Executable: true}, {Role: "adapter", Path: jar}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("runtime-v2"), 0o700); err != nil {
		t.Fatal(err)
	}
	launched, err := os.ReadFile(bundle.ByRole["runtime"].Path)
	if err != nil || string(launched) != "runtime-v1" {
		t.Fatalf("launched bytes=%q err=%v", launched, err)
	}
	if bundle.ByRole["runtime"].SHA256 != digest(launched) || !strings.Contains(bundle.ByRole["runtime"].Path, strings.TrimPrefix(digest(launched), "sha256:")) {
		t.Fatalf("launch object not content addressed: %#v", bundle.ByRole["runtime"])
	}
}

func fakeJavaRuntime(t *testing.T, complete bool) string {
	t.Helper()
	base, err := makeRealTemporaryDirectory("us020-fake-jdk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	root := filepath.Join(base, "jdk")
	for _, directory := range []string{"bin", "lib", "legal/java.base", "legal/java.test"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	java := filepath.Join(root, "bin/java")
	if err := os.WriteFile(java, []byte("synthetic-java-launcher"), 0o700); err != nil {
		t.Fatal(err)
	}
	if complete {
		if err := os.WriteFile(filepath.Join(root, "lib/modules"), []byte("synthetic-modules"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "legal/java.base/LICENSE"), []byte("license"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../java.base/LICENSE", filepath.Join(root, "legal/java.test/LICENSE")); err != nil {
		t.Fatal(err)
	}
	return java
}

func TestJavaRuntimeImageIsContentAddressedCompleteAndImmutable(t *testing.T) {
	java := fakeJavaRuntime(t, true)
	identity, err := javaRuntimeImageIdentity(java)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := materializeJavaRuntimeImage(filepath.Join(t.TempDir(), "images"), java, identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = removeImmutableTree(materialized.Root) })
	if !canonicalEqual(materialized.Identity, identity) || !strings.Contains(materialized.Root, strings.TrimPrefix(identity.SHA256, "sha256:")) || filepath.Base(materialized.Executable) != "java" {
		t.Fatalf("materialized=%#v identity=%#v", materialized, identity)
	}
	licenseInfo, err := os.Lstat(filepath.Join(materialized.Root, "legal/java.test/LICENSE"))
	if err != nil || !licenseInfo.Mode().IsRegular() {
		t.Fatalf("internal symlink was not normalized to immutable regular bytes: %v %#v", err, licenseInfo)
	}
	if err := verifyMaterializedJavaRuntimeImage(materialized.Root, identity); err != nil {
		t.Fatalf("verify materialized image: %v", err)
	}
	if err := os.Chmod(filepath.Join(materialized.Root, "lib/modules"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(materialized.Root, "lib/modules"), []byte("mutated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyMaterializedJavaRuntimeImage(materialized.Root, identity); err == nil {
		t.Fatal("post-materialization mutation accepted")
	}
}

func TestMaterializeConfiguredLaunchResolvesPortableJavaRuntimeIdentity(t *testing.T) {
	java := fakeJavaRuntime(t, true)
	javaRoot := filepath.Dir(filepath.Dir(java))
	repositoryRoot := filepath.Dir(javaRoot)
	writeInput := func(name string, body []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(repositoryRoot, name)
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	adapter := writeInput("adapter.jar", []byte("adapter"), 0o600)
	runtime := writeInput("runtime.jar", []byte("runtime"), 0o600)
	support := writeInput("support.jar", []byte("support"), 0o600)
	rust := writeInput("rust-testee", []byte("rust"), 0o700)
	cfg := Config{RepositoryRoot: repositoryRoot, JavaExecutable: java, JavaAdapterJar: adapter, JavaRuntimeJar: runtime, JavaSupportJars: []string{support}, RustTestee: rust}

	javaIdentity, err := artifact(java)
	if err != nil {
		t.Fatal(err)
	}
	javaIdentity.Kind = "java-executable"
	javaIdentity.Path = filepath.ToSlash(filepath.Join("jdk", "bin", "java"))
	imageIdentity, err := javaRuntimeImageIdentity(java)
	if err != nil {
		t.Fatal(err)
	}
	imageIdentity.Path = "jdk"
	imageIdentity.ReproductionCommand = javaReproductionCommand()
	inputIdentity := func(kind, path string) ArtifactIdentity {
		t.Helper()
		identity, identityErr := artifact(path)
		if identityErr != nil {
			t.Fatal(identityErr)
		}
		identity.Kind = kind
		identity.Path = filepath.ToSlash(filepath.Base(path))
		return identity
	}
	inputs := []ArtifactIdentity{
		javaIdentity,
		imageIdentity,
		inputIdentity("java-adapter-jar", adapter),
		inputIdentity("java-runtime-jar", runtime),
		inputIdentity("java-support-jar-00", support),
		inputIdentity("rust-testee", rust),
	}
	suite := filepath.Join(repositoryRoot, "suite")
	if err := os.Mkdir(suite, 0o700); err != nil {
		t.Fatal(err)
	}
	launched, err := materializeConfiguredLaunch(cfg, suite, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if info, statErr := os.Stat(launched.JavaExecutable); statErr != nil || !info.Mode().IsRegular() {
		t.Fatalf("portable Java runtime was not materialized: %v", statErr)
	}

	inputs[1].Path = "wrong-jdk"
	badSuite := filepath.Join(repositoryRoot, "bad-suite")
	if err := os.Mkdir(badSuite, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := materializeConfiguredLaunch(cfg, badSuite, inputs); err == nil || !strings.Contains(err.Error(), "tree path invalid") {
		t.Fatalf("mismatched portable Java runtime path accepted: %v", err)
	}
}

func TestJavaRuntimeImageRejectsIncompleteEscapingAndNonregularTrees(t *testing.T) {
	if _, err := javaRuntimeImageIdentity(fakeJavaRuntime(t, false)); err == nil {
		t.Fatal("incomplete runtime image accepted")
	}
	escapingJava := fakeJavaRuntime(t, true)
	escapingRoot := filepath.Dir(filepath.Dir(escapingJava))
	if err := os.Symlink("../../../../outside", filepath.Join(escapingRoot, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := javaRuntimeImageIdentity(escapingJava); err == nil {
		t.Fatal("escaping runtime symlink accepted")
	}
	nonregularJava := fakeJavaRuntime(t, true)
	nonregularRoot := filepath.Dir(filepath.Dir(nonregularJava))
	if err := syscall.Mkfifo(filepath.Join(nonregularRoot, "runtime.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := javaRuntimeImageIdentity(nonregularJava); err == nil {
		t.Fatal("nonregular runtime entry accepted")
	}
}

func TestJavaRuntimeImageRejectsSourceReplacementDuringCopy(t *testing.T) {
	java := fakeJavaRuntime(t, true)
	root := filepath.Dir(filepath.Dir(java))
	identity, err := javaRuntimeImageIdentity(java)
	if err != nil {
		t.Fatal(err)
	}
	originalHook := javaRuntimeImageCopyHook
	defer func() { javaRuntimeImageCopyHook = originalHook }()
	mutated := false
	javaRuntimeImageCopyHook = func(relative string) {
		if !mutated && relative == "bin/java" {
			mutated = true
			_ = os.WriteFile(filepath.Join(root, "lib/modules"), []byte("replaced-during-copy"), 0o600)
		}
	}
	if _, err := materializeJavaRuntimeImage(filepath.Join(t.TempDir(), "images"), java, identity); err == nil {
		t.Fatal("source replacement during runtime snapshot accepted")
	}
}

func TestJavaRuntimeImageLaunchesRealPinnedJDK(t *testing.T) {
	java := os.Getenv("US020_JAVA_RUNTIME_SMOKE")
	if java == "" {
		t.Skip("set US020_JAVA_RUNTIME_SMOKE to the real pinned JDK bin/java")
	}
	identity, err := javaRuntimeImageIdentity(java)
	if err != nil {
		t.Fatal(err)
	}
	store, err := makeRealTemporaryDirectory("us020-jdk-image-smoke-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = removeImmutableTree(store) })
	materialized, err := materializeJavaRuntimeImage(filepath.Join(store, "images"), java, identity)
	if err != nil {
		t.Fatal(err)
	}
	entries, total, err := scanJavaRuntimeImage(materialized.Root, "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := executeBoundedChild(context.Background(), childRequest{Executable: materialized.Executable, Args: []string{"-version"}, Home: store, Timeout: 5 * time.Second})
	if err != nil || result.ExitCode != 0 || !bytes.Contains(result.Stderr, []byte("openjdk version")) {
		t.Fatalf("materialized JDK launch failed: exit=%d stderr=%q err=%v", result.ExitCode, result.Stderr, err)
	}
	t.Logf("materialized Java runtime image: files=%d bytes=%d tree=%s", len(entries), total, identity.SHA256)
}

func TestScenarioMinimizerUsesFreshProcessesAndProvesIrreducible(t *testing.T) {
	scenario := publicScenarios(t)[0]
	scenario.Core.Steps = append([]corpora.Step{{Kind: "bytes", DataBase64: ""}}, scenario.Core.Steps...)
	pids := 0
	reproducer, err := minimizeScenarioFresh(scenario, Budget{MaxCandidates: 16, MaxDuration: time.Second}, func(candidate corpora.Scenario) (mismatchSignature, []ProcessReceipt, error) {
		pids += 2
		receipts := []ProcessReceipt{{PID: pids - 1}, {PID: pids}}
		if len(candidate.Core.Steps) == 0 {
			return mismatchSignature{}, receipts, nil
		}
		return mismatchSignature{Pointer: "/final_state", Classification: "java_quirk"}, receipts, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(reproducer.Scenario.Core.Steps) != 1 || !reproducer.Irreducible || reproducer.CandidateAttempts == 0 || len(reproducer.Processes) < 4 {
		t.Fatalf("minimized reproducer=%#v", reproducer)
	}
}

func TestEvidenceScenarioRoundTripsFlattenedPublicAndZeroStepCandidates(t *testing.T) {
	scenario := publicScenarios(t)[0]
	for name, candidate := range map[string]corpora.Scenario{
		"public": scenario,
		"zero-step": func() corpora.Scenario {
			value := scenario
			value.Core.Steps = []corpora.Step{}
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			reproducer := PublicReproducer{Scenario: candidate}
			raw, err := json.Marshal(reproducer)
			if err != nil {
				t.Fatal(err)
			}
			var decoded PublicReproducer
			if err := decodeStrict(raw, &decoded); err != nil {
				t.Fatalf("decode flattened scenario: %v", err)
			}
			if !canonicalEqual(decoded.Scenario, candidate) {
				t.Fatalf("scenario round-trip drift")
			}
		})
	}
}

func TestEvidenceScenarioRestoresOnlyBoundedIntegerValues(t *testing.T) {
	value := map[string]any{"integer": float64(3), "nested": []any{float64(4), map[string]any{"integer": float64(5)}}, "text": "retained"}
	if err := restoreEvidenceIntegers(value); err != nil {
		t.Fatal(err)
	}
	if value["integer"] != 3 || value["nested"].([]any)[0] != 4 || value["nested"].([]any)[1].(map[string]any)["integer"] != 5 {
		t.Fatalf("integer restoration drift: %#v", value)
	}
	for name, hostile := range map[string]any{"object": map[string]any{"bad": 1.5}, "array": []any{1.5}} {
		t.Run(name, func(t *testing.T) {
			if err := restoreEvidenceIntegers(hostile); err == nil {
				t.Fatal("fractional evidence value accepted")
			}
		})
	}
	if err := restoreEvidenceIntegers(nil); err != nil {
		t.Fatal(err)
	}
}

func TestReproducerCommandIsExactReviewedArgv(t *testing.T) {
	id := "reproducer.us005.pub.0000.0123456789abcdef"
	command := canonicalReproducerCommand(id)
	if len(command) != 8 || command[3] != "." || command[5] != "evidence/differential/manifest.json" || validateReproducerCommand(command, id) != nil {
		t.Fatalf("canonical command=%q", command)
	}
	mutations := map[string][]string{
		"missing":    append([]string(nil), command[:7]...),
		"extra":      append(append([]string(nil), command...), "extra"),
		"reordered":  {command[0], command[1], command[4], command[5], command[2], command[3], command[6], command[7]},
		"executable": append([]string{"other"}, command[1:]...),
	}
	for name, candidate := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := validateReproducerCommand(candidate, id); err == nil {
				t.Fatal("noncanonical argv accepted")
			}
		})
	}
}

func TestPortableEvidenceInputsUseRelativePathsAndReproductionCommands(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "rust", "target", "release", "websocket-testee")
	inputs := []ArtifactIdentity{
		{Kind: "public-corpus", Path: filepath.Join(root, "corpora", "public", "scenarios.jsonl"), SHA256: digest([]byte("corpus")), Bytes: 6},
		{Kind: "rust-testee", Path: inside, SHA256: digest([]byte("rust")), Bytes: 4},
		{Kind: "java-executable", Path: filepath.Join(t.TempDir(), "bin", "java"), SHA256: digest([]byte("java")), Bytes: 4},
	}
	portable, err := portableEvidenceInputs(root, inputs, true)
	if err != nil {
		t.Fatal(err)
	}
	if portable[0].Path != "corpora/public/scenarios.jsonl" || len(portable[0].ReproductionCommand) != 0 {
		t.Fatalf("repository input=%#v", portable[0])
	}
	if portable[1].Path != "rust/target/release/websocket-testee" || !canonicalEqual(portable[1].ReproductionCommand, rustReproductionCommand()) {
		t.Fatalf("Rust input=%#v", portable[1])
	}
	if portable[2].Path != ".reproduction/runtime/java-executable" || !canonicalEqual(portable[2].ReproductionCommand, javaReproductionCommand()) {
		t.Fatalf("external Java input=%#v", portable[2])
	}
	for _, input := range portable {
		if filepath.IsAbs(input.Path) || !validPortablePath(input.Path) {
			t.Fatalf("nonportable path persisted: %#v", input)
		}
	}
}

func TestPortableEvidenceInputsRejectRepositoryInputOutsideRoot(t *testing.T) {
	root := t.TempDir()
	_, err := portableEvidenceInputs(root, []ArtifactIdentity{{Kind: "public-corpus", Path: filepath.Join(t.TempDir(), "scenarios.jsonl"), SHA256: digest([]byte("x")), Bytes: 1}}, false)
	if err == nil || !strings.Contains(err.Error(), "repository input") {
		t.Fatalf("external repository input accepted: %v", err)
	}
	_, err = portableEvidenceInputs(root, []ArtifactIdentity{{Kind: "rust-testee", Path: filepath.Join(t.TempDir(), "websocket-testee"), SHA256: digest([]byte("x")), Bytes: 1}}, false)
	if err == nil || !strings.Contains(err.Error(), "runtime input") {
		t.Fatalf("external runtime input accepted: %v", err)
	}
}

func TestLargeDifferentialDocumentStrictDecodeRetainsHostileChecks(t *testing.T) {
	type document struct {
		Padding string `json:"padding"`
	}
	padding := strings.Repeat("a", (8<<20)+1)
	valid, err := json.Marshal(document{Padding: padding})
	if err != nil {
		t.Fatal(err)
	}
	var decoded document
	if err := decodeStrict(valid, &decoded); err != nil || decoded.Padding != padding {
		t.Fatalf("bounded large document rejected: %v", err)
	}
	duplicate := append([]byte(`{"padding":"`+padding+`","padding":"x"}`), '\n')
	if err := decodeStrict(duplicate, &decoded); err == nil {
		t.Fatal("duplicate field in large document accepted")
	}
	unknown := append([]byte(`{"padding":"`+padding+`","unknown":true}`), '\n')
	if err := decodeStrict(unknown, &decoded); err == nil {
		t.Fatal("unknown field in large document accepted")
	}
	trailing := append(append([]byte(nil), valid...), []byte(` {}`)...)
	if err := decodeStrict(trailing, &decoded); err == nil {
		t.Fatal("trailing value in large document accepted")
	}
	tooLarge := make([]byte, maximumDocumentBytes+1)
	if err := decodeStrict(tooLarge, &decoded); err == nil {
		t.Fatal("document beyond differential evidence bound accepted")
	}
}

func testStateByte(state string) byte {
	return map[string]byte{"open": 1, "closing": 2, "closed": 3}[state]
}

func testWriteBytes(buffer *bytes.Buffer, raw []byte) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(raw)))
	buffer.Write(raw)
}

func testCloseBody(close *commonClose) []byte {
	buffer := &bytes.Buffer{}
	if close.Code == nil {
		buffer.WriteByte(0)
	} else {
		buffer.WriteByte(1)
		_ = binary.Write(buffer, binary.BigEndian, *close.Code)
	}
	testWriteBytes(buffer, []byte(close.Reason))
	if close.Clean {
		buffer.WriteByte(1)
	} else {
		buffer.WriteByte(0)
	}
	buffer.WriteByte(map[string]byte{"local": 1, "remote": 2, "unknown_before_scenario": 3, "none": 4, "transport": 5}[close.Origin])
	return buffer.Bytes()
}

func testRustItem(item rustItem) []byte {
	buffer := &bytes.Buffer{}
	buffer.WriteByte(item.Kind)
	switch item.Kind {
	case 1:
		event := item.Event
		kind := map[string]byte{"text": 1, "binary": 2, "ping": 3, "pong": 4, "close": 5, "client_handshake_opened": 6, "server_handshake_opened": 7}[event.Kind]
		buffer.WriteByte(kind)
		switch event.Kind {
		case "text":
			testWriteBytes(buffer, []byte(event.Text))
		case "binary", "ping", "pong":
			payload, _ := base64.StdEncoding.DecodeString(event.PayloadB64)
			testWriteBytes(buffer, payload)
		case "close":
			buffer.Write(testCloseBody(event.Close))
		}
	case 2:
		frame := item.Frame
		buffer.WriteByte(map[string]byte{"inbound": 1, "outbound": 2}[frame.Direction])
		if frame.Fin {
			buffer.WriteByte(1)
		} else {
			buffer.WriteByte(0)
		}
		buffer.WriteByte(map[string]byte{"continuous": 0, "text": 1, "binary": 2, "closing": 8, "ping": 9, "pong": 10}[frame.Opcode])
		if frame.Masked {
			buffer.WriteByte(1)
		} else {
			buffer.WriteByte(0)
		}
		payload, _ := base64.StdEncoding.DecodeString(frame.PayloadB64)
		testWriteBytes(buffer, payload)
		_ = binary.Write(buffer, binary.BigEndian, frame.WireLength)
	case 3:
		buffer.WriteByte(testStateByte(item.Transition.From))
		buffer.WriteByte(testStateByte(item.Transition.To))
	case 4:
		buffer.Write(testCloseBody(item.Close))
	case 5:
		if item.Error.Terminal {
			buffer.WriteByte(1)
		} else {
			buffer.WriteByte(0)
		}
		_ = binary.Write(buffer, binary.BigEndian, uint16(len(item.Error.Class)))
		buffer.WriteString(item.Error.Class)
	case 6:
		buffer.WriteByte(1)
		testWriteBytes(buffer, item.Transport)
	}
	return buffer.Bytes()
}

func testEncodeRustObservation(observation rustObservation) []byte {
	body := &bytes.Buffer{}
	body.WriteString("NOBS1")
	appendTLV(body, 1, []byte(observation.ScenarioID))
	appendTLV(body, 2, []byte{map[string]byte{"client": 1, "server": 2}[observation.Role]})
	appendTLV(body, 3, []byte{testStateByte(observation.Initial)})
	bootstrap := &bytes.Buffer{}
	bootstrap.WriteByte(map[string]byte{"client": 1, "server": 2}[observation.Role])
	bootstrap.WriteByte(testStateByte(observation.Initial))
	bootstrap.WriteByte(testStateByte(observation.Initial))
	_ = binary.Write(bootstrap, binary.BigEndian, uint16(0))
	appendTLV(body, 4, bootstrap.Bytes())
	steps := &bytes.Buffer{}
	_ = binary.Write(steps, binary.BigEndian, uint16(len(observation.Steps)))
	for _, step := range observation.Steps {
		record := &bytes.Buffer{}
		_ = binary.Write(record, binary.BigEndian, step.Index)
		record.WriteByte(step.InputKind)
		record.WriteByte(testStateByte(step.PreState))
		record.WriteByte(testStateByte(step.PostState))
		_ = binary.Write(record, binary.BigEndian, step.Consumed)
		_ = binary.Write(record, binary.BigEndian, step.WireBuffered)
		_ = binary.Write(record, binary.BigEndian, step.MessageBuffered)
		_ = binary.Write(record, binary.BigEndian, uint16(len(step.Observations)))
		for _, item := range step.Observations {
			testWriteBytes(record, testRustItem(item))
		}
		testWriteBytes(steps, record.Bytes())
	}
	appendTLV(body, 5, steps.Bytes())
	appendTLV(body, 6, []byte{testStateByte(observation.Final)})
	if observation.Close == nil {
		appendTLV(body, 7, []byte{0})
	} else {
		appendTLV(body, 7, append([]byte{1}, testCloseBody(observation.Close)...))
	}
	framed := &bytes.Buffer{}
	_ = binary.Write(framed, binary.BigEndian, uint32(body.Len()))
	framed.Write(body.Bytes())
	return framed.Bytes()
}

func testSimpleRustObservation(sc corpora.Scenario) rustObservation {
	steps := make([]rustStep, 0, len(sc.Core.Steps))
	for index, source := range sc.Core.Steps {
		kind := byte(1)
		consumed := uint64(0)
		observations := []rustItem{}
		if source.Kind == "bytes" {
			payload, _ := base64.StdEncoding.DecodeString(source.DataBase64)
			if sc.Core.InitialState == "closed" && len(payload) != 0 {
				observations = append(observations, rustItem{Kind: 5, Error: &commonError{Class: "INVALID_STATE"}})
			} else {
				consumed = uint64(len(payload))
			}
		} else {
			kind = map[string]byte{"eof": 2, "send_text": 16, "send_binary": 17, "send_fragment": 18, "send_ping": 19, "send_pong": 20, "send_close": 21}[source.Action]
		}
		steps = append(steps, rustStep{Index: uint16(index), InputKind: kind, PreState: sc.Core.InitialState, PostState: sc.Core.InitialState, Consumed: consumed, Observations: observations})
	}
	return rustObservation{ScenarioID: sc.ScenarioID, Role: sc.Core.Role, Initial: sc.Core.InitialState, Steps: steps, Final: sc.Core.InitialState}
}

func testJavaClose(close *commonClose) any {
	if close == nil {
		return nil
	}
	return map[string]any{"code": *close.Code, "reason": close.Reason, "handshake_complete": close.Clean, "origin": close.Origin, "remote": close.Origin == "remote"}
}

func testJavaObservation(sc corpora.Scenario, observation commonObservation) ([]byte, error) {
	request, err := corpora.OracleRequest(sc)
	if err != nil {
		return nil, err
	}
	object := map[string]any{"request_id": sc.ScenarioID, "protocol": "java-websocket-oracle", "version": "1.0.0", "request_digest": request["request_digest"], "runtime": map[string]any{"kind": "deterministic-fake"}, "outcome": observation.Outcome, "final_state": observation.FinalState, "counts": observation.Counts}
	if observation.Outcome == "error" {
		code := map[string]string{"PROTOCOL_REJECTION": "JAVA_INVALID_DATA", "INVALID_STATE": "STATE_VIOLATION", "LIMIT_EXCEEDED": "FRAME_LIMIT_EXCEEDED"}[observation.Error.Class]
		if code == "" {
			code = observation.Error.Class
		}
		object["error"] = map[string]any{"code": code, "detail": "deterministic fake observation"}
	} else {
		object["initial_state"], object["role"], object["close"] = sc.Core.InitialState, sc.Core.Role, testJavaClose(observation.Close)
		events := []any{}
		for _, event := range observation.Events {
			value := map[string]any{"type": event.Kind, "step": event.Step}
			switch event.Kind {
			case "text":
				value["text"], value["utf8_bytes"] = event.Text, len([]byte(event.Text))
			case "binary", "ping", "pong":
				payload, _ := base64.StdEncoding.DecodeString(event.PayloadB64)
				value["data_base64"], value["bytes"] = event.PayloadB64, len(payload)
			case "close":
				close := testJavaClose(event.Close).(map[string]any)
				for key, item := range close {
					value[key] = item
				}
			}
			events = append(events, value)
		}
		frames := []any{}
		for _, frame := range observation.Frames {
			payload, _ := base64.StdEncoding.DecodeString(frame.PayloadB64)
			frames = append(frames, map[string]any{"direction": frame.Direction, "fin": frame.Fin, "masked": frame.Masked, "opcode": frame.Opcode, "payload_base64": frame.PayloadB64, "payload_bytes": len(payload), "rsv1": false, "rsv2": false, "rsv3": false, "step": frame.Step, "wire_bytes": frame.WireLength})
		}
		transitions := []any{}
		for _, transition := range observation.Transitions {
			transitions = append(transitions, map[string]any{"cause": "deterministic-fake", "from": transition.From, "step": transition.Step, "to": transition.To})
		}
		object["events"], object["frames"], object["transitions"] = events, frames, transitions
	}
	raw, err := canonical(object)
	return append(raw, '\n'), err
}

func testScenarioFromJavaRequest(originals map[string]corpora.Scenario, raw []byte) (corpora.Scenario, error) {
	var request struct {
		RequestID    string         `json:"request_id"`
		Role         string         `json:"role"`
		InitialState string         `json:"initial_state"`
		Limits       corpora.Limits `json:"limits"`
		Steps        []corpora.Step `json:"steps"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &request); err != nil {
		return corpora.Scenario{}, err
	}
	scenario, ok := originals[request.RequestID]
	if !ok {
		return corpora.Scenario{}, fmt.Errorf("unknown fake Java request %q", request.RequestID)
	}
	scenario.Core = corpora.ScenarioCore{Role: request.Role, InitialState: request.InitialState, Limits: request.Limits, Steps: request.Steps}
	return scenario, nil
}

func testScenarioIDFromNeutralRequest(raw []byte) (string, error) {
	if len(raw) < 14 || int(binary.BigEndian.Uint32(raw[:4])) != len(raw)-4 || string(raw[4:9]) != "NDRV1" || raw[9] != 1 {
		return "", errors.New("invalid fake NDRV1 request")
	}
	length := int(binary.BigEndian.Uint32(raw[10:14]))
	if length <= 0 || 14+length > len(raw) {
		return "", errors.New("invalid fake NDRV1 scenario id")
	}
	return string(raw[14 : 14+length]), nil
}

func TestRealGeneratorProducesExact103SchemaValidReproducers(t *testing.T) {
	root := repositoryRoot(t)
	committedManifestRaw, committedManifest := committedManifestForTest(t)
	committedLedgerRaw, err := os.ReadFile(filepath.Join(root, "evidence/java/behavior-delta-ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(committedManifest.Scenarios) != 74 {
		t.Fatalf("committed scenario templates=%d", len(committedManifest.Scenarios))
	}

	originals := map[string]corpora.Scenario{}
	templates := map[string]ScenarioResult{}
	for _, scenario := range publicScenarios(t) {
		originals[scenario.ScenarioID] = scenario
	}
	for _, result := range committedManifest.Scenarios {
		templates[result.ScenarioID] = result
		scenario := originals[result.ScenarioID]
		javaRaw, encodeErr := testJavaObservation(scenario, result.JavaObservation)
		if encodeErr != nil {
			t.Fatalf("encode Java template %s: %v", result.ScenarioID, encodeErr)
		}
		java, _, normalizeErr := normalizeJava(scenario, javaRaw)
		if normalizeErr != nil || !canonicalEqual(java, result.JavaObservation) {
			t.Fatalf("Java template drift %s: %v", result.ScenarioID, normalizeErr)
		}
		rustRaw := testEncodeRustObservation(rustObservation{ScenarioID: result.ScenarioID, Role: scenario.Core.Role, Initial: scenario.Core.InitialState, Steps: result.RustStepDiagnostics, Final: result.RustObservation.FinalState, Close: result.RustObservation.Close})
		rust, diagnostics, normalizeErr := normalizeRust(scenario, rustRaw)
		if normalizeErr != nil || !canonicalEqual(rust, result.RustObservation) || !canonicalEqual(diagnostics.Steps, result.RustStepDiagnostics) {
			t.Fatalf("Rust template drift %s: %v", result.ScenarioID, normalizeErr)
		}
	}

	work, err := makeRealTemporaryDirectory("us020-real-generator-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	writeInput := func(name, value string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(work, name)
		if err := os.WriteFile(path, []byte(value), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	java := fakeJavaRuntime(t, true)
	adapter := writeInput("java-adapter.jar", "deterministic-adapter", 0o600)
	runtimeJar := writeInput("java-runtime.jar", "deterministic-runtime", 0o600)
	support := writeInput("java-support.jar", "deterministic-support", 0o600)
	rustTestee := writeInput("rust-testee", "deterministic-rust", 0o700)
	tempLedger := filepath.Join(work, "transaction", "ledger.json")
	tempManifest := filepath.Join(work, "transaction", "manifest.json")
	if err := os.MkdirAll(filepath.Dir(tempLedger), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tempLedger, committedLedgerRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tempManifest, committedManifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	oldExecute := executeChild
	oldCommit := commitEvidenceDocuments
	oldReadManifest := readCommittedEvidence
	oldReadLedger := readVerificationLedger
	t.Cleanup(func() {
		executeChild = oldExecute
		commitEvidenceDocuments = oldCommit
		readCommittedEvidence = oldReadManifest
		readVerificationLedger = oldReadLedger
	})
	candidates := map[string]corpora.Scenario{}
	pid := 4000
	executeChild = func(_ context.Context, request childRequest) (childResult, error) {
		pid++
		var raw []byte
		if len(bytes.TrimSpace(request.Input)) > 0 && bytes.TrimSpace(request.Input)[0] == '{' {
			if len(request.Args) != 5 || request.Args[0] != "-Dfile.encoding=UTF-8" || request.Args[1] != "-Dslf4j.internal.verbosity=ERROR" || request.Args[2] != "-cp" || request.Args[4] != "OracleMain" {
				return childResult{}, fmt.Errorf("fake Java launch argv drift: %q", request.Args)
			}
			scenario, parseErr := testScenarioFromJavaRequest(originals, request.Input)
			if parseErr != nil {
				return childResult{}, parseErr
			}
			candidates[scenario.ScenarioID] = scenario
			line, _ := scenario.CanonicalLine()
			originalLine, _ := originals[scenario.ScenarioID].CanonicalLine()
			observation := templates[scenario.ScenarioID].JavaObservation
			if !bytes.Equal(line, originalLine) {
				rustRaw := testEncodeRustObservation(testSimpleRustObservation(scenario))
				observation, _, parseErr = normalizeRust(scenario, rustRaw)
				if parseErr != nil {
					return childResult{}, parseErr
				}
			}
			raw, parseErr = testJavaObservation(scenario, observation)
			if parseErr != nil {
				return childResult{}, parseErr
			}
		} else {
			if !canonicalEqual(request.Args, []string{"neutral-oracle", "--protocol", "NDRV1"}) {
				return childResult{}, fmt.Errorf("fake Rust launch argv drift: %q", request.Args)
			}
			scenarioID, parseErr := testScenarioIDFromNeutralRequest(request.Input)
			if parseErr != nil {
				return childResult{}, parseErr
			}
			scenario, ok := candidates[scenarioID]
			if !ok {
				return childResult{}, fmt.Errorf("fake Rust request without Java candidate %q", scenarioID)
			}
			line, _ := scenario.CanonicalLine()
			originalLine, _ := originals[scenarioID].CanonicalLine()
			if bytes.Equal(line, originalLine) {
				template := templates[scenarioID]
				raw = testEncodeRustObservation(rustObservation{ScenarioID: scenarioID, Role: scenario.Core.Role, Initial: scenario.Core.InitialState, Steps: template.RustStepDiagnostics, Final: template.RustObservation.FinalState, Close: template.RustObservation.Close})
			} else {
				raw = testEncodeRustObservation(testSimpleRustObservation(scenario))
			}
		}
		return childResult{PID: pid, Stdout: raw, Stderr: []byte{}, ExitCode: 0, Started: time.Unix(1700000000, int64(pid)), Duration: time.Millisecond}, nil
	}

	var generatedLedger, generatedManifest []byte
	commitEvidenceDocuments = func(_ *evidenceLock, ledgerPath string, ledgerRaw []byte, manifestPath string, manifestRaw []byte) error {
		if ledgerPath != filepath.Join(root, "evidence/java/behavior-delta-ledger.json") || manifestPath != filepath.Join(root, "evidence/differential/manifest.json") {
			return errors.New("generator output path drift")
		}
		generatedLedger = append([]byte(nil), ledgerRaw...)
		generatedManifest = append([]byte(nil), manifestRaw...)
		tempLock, err := acquireEvidenceLock(root, tempLedger, tempManifest)
		if err != nil {
			return err
		}
		coordinationPath := tempLock.path
		defer func() {
			_ = tempLock.Release()
			_ = os.Remove(coordinationPath)
		}()
		return commitEvidencePair(tempLock, tempLedger, generatedLedger, tempManifest, generatedManifest)
	}
	readCommittedEvidence = func(path string, maximum int64) ([]byte, error) {
		if path == filepath.Join(root, "evidence/differential/manifest.json") && len(generatedManifest) != 0 {
			return append([]byte(nil), generatedManifest...), nil
		}
		return readRegularBounded(path, maximum)
	}
	readVerificationLedger = func(path string, maximum int64) ([]byte, error) {
		if path == filepath.Join(root, "evidence/java/behavior-delta-ledger.json") && len(generatedLedger) != 0 {
			return append([]byte(nil), generatedLedger...), nil
		}
		return readRegularBounded(path, maximum)
	}

	cfg := Config{
		RepositoryRoot: root, PublicCorpus: filepath.Join(root, "corpora/public/scenarios.jsonl"),
		JavaExecutable: java, JavaAdapterJar: adapter, JavaRuntimeJar: runtimeJar, JavaSupportJars: []string{support}, RustTestee: rustTestee,
		MigrationInventory: filepath.Join(root, "evidence/intake/semantic-id-migration-map.json"), CompatibilitySurface: filepath.Join(root, "evidence/intake/compatibility-surface.json"),
		LedgerPath: filepath.Join(root, "evidence/java/behavior-delta-ledger.json"), EvidencePath: filepath.Join(root, "evidence/differential/manifest.json"), OracleHierarchyPath: filepath.Join(root, "evidence/oracle-hierarchy.json"),
		ScenarioTimeout: time.Second, SuiteTimeout: 5 * time.Minute, MinimizationBudget: Budget{MaxCandidates: 128, MaxDuration: time.Minute},
		allowExternalRuntime: true,
	}
	receipt, err := RunPublicDifferential(context.Background(), cfg)
	if err != nil {
		t.Fatalf("real generator with deterministic observations: %v", err)
	}
	if receipt.Status != StatusPass || receipt.ScenarioCount != 74 || receipt.ProcessReceipts != 296 || receipt.DeltaCount != 112 || receipt.EvidenceSHA256 != digest(generatedManifest) {
		t.Fatalf("receipt=%#v", receipt)
	}
	if err := verifyPublicDifferential(root, generatedManifest, &cfg); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	for _, schema := range []struct {
		path string
		raw  []byte
	}{{filepath.Join(root, "schemas/differential-evidence-1.1.0.schema.json"), generatedManifest}, {filepath.Join(root, "schemas/behavior-delta-ledger-1.1.0.schema.json"), generatedLedger}} {
		if err := compileAndValidateSchema(schema.path, schema.raw); err != nil {
			t.Fatalf("schema %s: %v", filepath.Base(schema.path), err)
		}
	}
	var manifest Manifest
	var ledger Ledger
	if err := decodeStrict(generatedManifest, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := decodeStrict(generatedLedger, &ledger); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != evidenceSchemaVersion || manifest.Schema != "../../schemas/differential-evidence-1.1.0.schema.json" {
		t.Fatalf("portable schema identity drift: %s %s", manifest.SchemaVersion, manifest.Schema)
	}
	for _, input := range manifest.Inputs {
		if !validPortablePath(input.Path) || filepath.IsAbs(input.Path) {
			t.Fatalf("nonportable manifest input: %#v", input)
		}
		if repositoryInputKind(input.Kind) && len(input.ReproductionCommand) != 0 {
			t.Fatalf("repository input has reproduction command: %#v", input)
		}
		if !repositoryInputKind(input.Kind) && !canonicalEqual(input.ReproductionCommand, runtimeReproductionCommand(input.Kind)) {
			t.Fatalf("runtime reproduction command drift: %#v", input)
		}
	}
	for _, process := range manifest.Processes {
		for _, input := range process.LaunchedInputs {
			if !validPortablePath(input.SourcePath) || filepath.IsAbs(input.SourcePath) {
				t.Fatalf("nonportable launch identity: %#v", input)
			}
		}
	}
	if !validPortablePath(manifest.Coverage.CurrentHeadQualification.Path) {
		t.Fatalf("nonportable qualification identity: %#v", manifest.Coverage.CurrentHeadQualification)
	}
	classifications := map[string]int{}
	for _, record := range ledger.Records {
		classifications[record.Classification]++
	}
	modes := map[string]int{}
	for _, reproducer := range manifest.Reproducers {
		modes[reproducer.Mode]++
		if len(reproducer.Command) != 8 || validateReproducerCommand(reproducer.Command, reproducer.ReproducerID) != nil {
			t.Fatalf("noncanonical reproducer command %s: %q", reproducer.ReproducerID, reproducer.Command)
		}
		for _, attempt := range reproducer.Attempts {
			if attempt.Audits == nil {
				t.Fatalf("null normalization audits in %s", reproducer.ReproducerID)
			}
		}
	}
	if len(manifest.Reproducers) != 103 || len(ledger.Records) != 112 || classifications["java_quirk"] != 98 || classifications["rust_defect"] != 5 || classifications["harness_artifact_correction"] != 9 || modes["FRESH_BOUNDED_MINIMIZATION"] != 89 || modes["HISTORICAL_CLOSED_IDENTITY_WITNESS"] != 14 {
		t.Fatalf("closure reproducers=%d records=%d classes=%v modes=%v", len(manifest.Reproducers), len(ledger.Records), classifications, modes)
	}
	command := append([]string(nil), manifest.Reproducers[0].Command...)
	commandMutations := map[string][]string{
		"missing":    append([]string(nil), command[:7]...),
		"extra":      append(append([]string(nil), command...), "extra"),
		"reordered":  {command[0], command[1], command[4], command[5], command[2], command[3], command[6], command[7]},
		"executable": append([]string{"other"}, command[1:]...),
	}
	for name, mutated := range commandMutations {
		candidate := manifest
		candidate.Reproducers = append([]PublicReproducer(nil), manifest.Reproducers...)
		candidate.Reproducers[0].Command = mutated
		raw, err := marshalIndented(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := compileAndValidateSchema(filepath.Join(root, "schemas/differential-evidence-1.1.0.schema.json"), raw); err == nil {
			t.Fatalf("schema accepted %s reproducer argv", name)
		}
	}
	if bytes.Contains(generatedManifest, []byte(`"normalization_audits": null`)) || bytes.Contains(generatedManifest, []byte(`"normalization_audits":null`)) {
		t.Fatal("generated manifest contains null normalization_audits")
	}
	if manifest.Controls.Total != 7 || manifest.Controls.Killed != 7 || len(manifest.Coverage.Migration) != 47 || len(manifest.Coverage.Compatibility) != 14 || manifest.Counts.Flakes != 0 || manifest.Counts.NormalizationCollisions != 0 || manifest.Counts.UnresolvedDifferences != 0 {
		t.Fatalf("derived closure drift controls=%#v coverage=%#v counts=%#v", manifest.Controls, manifest.Coverage.Summary, manifest.Counts)
	}
	if got, _ := os.ReadFile(tempLedger); !bytes.Equal(got, generatedLedger) {
		t.Fatal("transaction ledger commit drift")
	}
	if got, _ := os.ReadFile(tempManifest); !bytes.Equal(got, generatedManifest) {
		t.Fatal("transaction manifest commit drift")
	}
	for _, path := range []string{tempLedger + ".us020-journal", tempLedger + ".us020-lock", cfg.LedgerPath + ".us020-journal", cfg.LedgerPath + ".us020-lock"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("transaction artifact retained %s: %v", path, err)
		}
	}
	if actual, _ := os.ReadFile(cfg.LedgerPath); !bytes.Equal(actual, committedLedgerRaw) {
		t.Fatal("test mutated committed ledger")
	}
	if actual, _ := os.ReadFile(cfg.EvidencePath); !bytes.Equal(actual, committedManifestRaw) {
		t.Fatal("test mutated committed manifest")
	}
	t.Logf("generated manifest=%s bytes=%d ledger=%s processes=%d reproducers=%d", digest(generatedManifest), len(generatedManifest), digest(generatedLedger), len(manifest.Processes), len(manifest.Reproducers))
}
