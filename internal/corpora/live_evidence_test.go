package corpora

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func findingCodes(findings []Finding) map[string]int {
	out := map[string]int{}
	for _, finding := range findings {
		out[finding.Code]++
	}
	return out
}

// recordLiveExecution writes a faithful public-tier live execution: a
// synthesized transcript and evaluation report in the protected live store,
// and a manifest updated to LIVE_EXECUTED with reconciled digests.
func recordLiveExecution(t *testing.T, root, protectedRoot string,
	generated *GeneratedCorpora) (manifestPath string, transcriptPath string) {
	t.Helper()
	var transcript bytes.Buffer
	for _, sc := range generated.Public {
		response, err := synthesizeResponse(sc)
		if err != nil {
			t.Fatal(err)
		}
		transcript.Write(response)
		transcript.WriteByte('\n')
	}
	report, err := EvaluateTranscript(generated.Public, transcript.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Reconciled() {
		t.Fatalf("synthesized transcript must reconcile: %+v", report)
	}
	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	liveDir := filepath.Join(protectedRoot, ProtectedDirName, "live", "public")
	if err := os.MkdirAll(liveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	transcriptPath = filepath.Join(liveDir, "transcript.jsonl")
	if err := os.WriteFile(transcriptPath, transcript.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(liveDir, "report.json")
	if err := os.WriteFile(reportPath, reportBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	manifestPath = filepath.Join(root, "corpora/public/manifest.json")
	manifest, err := readManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest["execution_status"] = "LIVE_EXECUTED"
	manifest["execution_evidence"] = map[string]any{
		"transcript_sha256": DigestSHA256(transcript.Bytes()),
		"report_sha256":     DigestSHA256(reportBytes),
		"evaluator":         "corporactl evaluate",
	}
	counts := manifest["counts"].(map[string]any)
	selected := int(counts["selected"].(float64))
	counts["executed"] = selected
	counts["passed"] = selected
	if err := writeJSONFile(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	refreshCalibrationManifestPins(t, root)
	return manifestPath, transcriptPath
}

// refreshCalibrationManifestPins mirrors the real recording contract: any
// change to a corpus manifest must be followed by re-pinning its digest in
// the calibration document (the binding check blocks stale pins). No-op when
// no calibration document has been written yet.
func refreshCalibrationManifestPins(t *testing.T, root string) {
	t.Helper()
	calibrationPath := filepath.Join(root, "evidence/corpus-calibration.json")
	raw, err := os.ReadFile(calibrationPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	corpora, _ := doc["corpora"].(map[string]any)
	for _, rawEntry := range corpora {
		entry, _ := rawEntry.(map[string]any)
		manifestPath, _ := entry["manifest_path"].(string)
		bytesRead, err := os.ReadFile(filepath.Join(root, manifestPath))
		if err != nil {
			t.Fatal(err)
		}
		entry["manifest_sha256"] = DigestSHA256(bytesRead)
	}
	if err := writeJSONFile(calibrationPath, doc); err != nil {
		t.Fatal(err)
	}
}

// A pending corpus has no live findings; a faithfully recorded execution
// reconciles end to end, including through VerifyAll.
func TestVerifyLiveEvidenceCleanPaths(t *testing.T) {
	root, protectedRoot, generated := writeAllToTemp(t)
	findings, err := VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatalf("VerifyLiveEvidence: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("pending state must have no live findings: %v", findings)
	}

	recordLiveExecution(t, root, protectedRoot, generated)
	findings, err = VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("faithful live record must verify: %v", findings)
	}
	all, err := VerifyAll(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Fatalf("VerifyAll must accept the recorded execution: %v", all)
	}
}

// Zero-execution claims, inconsistent counters, dangling digests, and edited
// artifacts are all typed blocks.
func TestVerifyLiveEvidenceTamperCases(t *testing.T) {
	root, protectedRoot, generated := writeAllToTemp(t)
	manifestPath, transcriptPath := recordLiveExecution(t, root, protectedRoot, generated)

	mutate := func(change func(manifest map[string]any)) []Finding {
		t.Helper()
		manifest, err := readManifest(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		change(manifest)
		if err := writeJSONFile(manifestPath, manifest); err != nil {
			t.Fatal(err)
		}
		findings, err := VerifyLiveEvidence(root, protectedRoot)
		if err != nil {
			t.Fatal(err)
		}
		return findings
	}
	restore := func() {
		recordLiveExecution(t, root, protectedRoot, generated)
	}

	codes := findingCodes(mutate(func(manifest map[string]any) {
		counts := manifest["counts"].(map[string]any)
		counts["executed"] = 0
		counts["passed"] = 0
	}))
	if codes["LIVE_EXECUTION_EMPTY"] == 0 {
		t.Fatalf("zero-execution claim must block: %v", codes)
	}
	restore()

	codes = findingCodes(mutate(func(manifest map[string]any) {
		counts := manifest["counts"].(map[string]any)
		counts["passed"] = int(counts["passed"].(float64)) - 1
	}))
	if codes["COUNTER_INCONSISTENT"] == 0 {
		t.Fatalf("inconsistent counters must block: %v", codes)
	}
	restore()

	// Edited transcript: recorded digest no longer matches the artifact.
	raw, err := os.ReadFile(transcriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(transcriptPath, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if findingCodes(findings)["TRANSCRIPT_DIGEST_MISMATCH"] == 0 {
		t.Fatalf("edited transcript must block: %v", findings)
	}

	// Dangling digests: the artifacts are gone entirely.
	if err := os.RemoveAll(filepath.Join(protectedRoot, ProtectedDirName, "live")); err != nil {
		t.Fatal(err)
	}
	findings, err = VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	codes = findingCodes(findings)
	if codes["TRANSCRIPT_UNRESOLVED"] == 0 || codes["REPORT_UNRESOLVED"] == 0 {
		t.Fatalf("dangling digests must be typed unresolved blocks: %v", findings)
	}
}

// A PASS gate must record measured work: executed >= 1, and every recorded
// counter must be a genuine integer. Zero-execution PASS claims and
// missing/mistyped counters are distinct typed blocks — never silently zero.
func TestVerifyLiveEvidenceGateExecutionRigor(t *testing.T) {
	root, protectedRoot, generated := writeAllToTemp(t)
	document, err := BuildCalibration(root, protectedRoot, generated)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteCalibration(root, document); err != nil {
		t.Fatal(err)
	}
	_, transcriptPath := recordLiveExecution(t, root, protectedRoot, generated)
	transcriptRaw, err := os.ReadFile(transcriptPath)
	if err != nil {
		t.Fatal(err)
	}
	transcriptDigest := DigestSHA256(transcriptRaw)
	calibrationPath := filepath.Join(root, "evidence/corpus-calibration.json")

	behaviorTotal := len(generated.Public) + len(generated.Hidden) + len(generated.Sealed)
	writeGatesNamed := func(mutate func(gates map[string]any)) []Finding {
		t.Helper()
		raw, err := os.ReadFile(calibrationPath)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		gates := doc["live_gates"].(map[string]any)
		for _, name := range []string{"java_oracle_pass_rate", "empty_rust_target_fails",
			"planted_java_rust_mutants_killed", "execution_rerun_reconciliation",
			"sealed_network_denial"} {
			gate := gates[name].(map[string]any)
			gate["status"] = "PASS"
			// Per-gate faithful shapes: the pass-rate gate covers every
			// behavior scenario with zero failures; the candidate-kill
			// gates PASS precisely because executions failed.
			executed, passed, failed := len(generated.Public), len(generated.Public), 0
			switch name {
			case "java_oracle_pass_rate":
				executed, passed, failed = behaviorTotal, behaviorTotal, 0
			case "empty_rust_target_fails", "planted_java_rust_mutants_killed":
				executed, passed, failed = len(generated.Public), 0, len(generated.Public)
			}
			gate["result"] = map[string]any{
				"transcript_sha256s": []any{transcriptDigest},
				"executed":           executed,
				"passed":             passed,
				"failed":             failed,
			}
		}
		mutate(gates)
		doc["status"] = "LIVE_CALIBRATED"
		if err := writeJSONFile(calibrationPath, doc); err != nil {
			t.Fatal(err)
		}
		findings, err := VerifyLiveEvidence(root, protectedRoot)
		if err != nil {
			t.Fatal(err)
		}
		return findings
	}
	writeGates := func(mutate func(result map[string]any)) []Finding {
		t.Helper()
		return writeGatesNamed(func(gates map[string]any) {
			mutate(gates["java_oracle_pass_rate"].(map[string]any)["result"].(map[string]any))
		})
	}

	// Baseline: faithful nonzero PASS results stay clean.
	if findings := writeGates(func(result map[string]any) {}); len(findings) != 0 {
		t.Fatalf("faithful nonzero PASS gates must verify: %v", findings)
	}

	// A PASS gate claiming executed=passed=failed=0 must block, typed.
	codes := findingCodes(writeGates(func(result map[string]any) {
		result["executed"] = 0
		result["passed"] = 0
		result["failed"] = 0
	}))
	if codes["GATE_ZERO_EXECUTION"] == 0 {
		t.Fatalf("zero-execution PASS gate under LIVE_CALIBRATED must block: %v", codes)
	}

	// A missing counter is its own typed finding, never silently zero.
	codes = findingCodes(writeGates(func(result map[string]any) {
		delete(result, "executed")
	}))
	if codes["GATE_COUNTER_MISSING"] == 0 {
		t.Fatalf("missing gate counter must block with GATE_COUNTER_MISSING: %v", codes)
	}

	// A mistyped counter is the same typed finding.
	codes = findingCodes(writeGates(func(result map[string]any) {
		result["executed"] = "12"
	}))
	if codes["GATE_COUNTER_MISSING"] == 0 {
		t.Fatalf("mistyped gate counter must block with GATE_COUNTER_MISSING: %v", codes)
	}

	// A fractional counter cannot be read as an integer count either.
	codes = findingCodes(writeGates(func(result map[string]any) {
		result["executed"] = 11.5
	}))
	if codes["GATE_COUNTER_MISSING"] == 0 {
		t.Fatalf("fractional gate counter must block with GATE_COUNTER_MISSING: %v", codes)
	}

	// Round-5 regression: a 100%-pass-rate gate claiming PASS while its own
	// counters record failures must block, even though passed+failed==executed.
	codes = findingCodes(writeGates(func(result map[string]any) {
		result["passed"] = 0
		result["failed"] = behaviorTotal
	}))
	if codes["GATE_RESULT_SEMANTICS"] == 0 {
		t.Fatalf("PASS with recorded failures must block with GATE_RESULT_SEMANTICS: %v", codes)
	}

	// Round-5 regression: PASS covering fewer executions than the behavior
	// corpora select is a coverage overclaim.
	codes = findingCodes(writeGates(func(result map[string]any) {
		result["executed"] = behaviorTotal - 1
		result["passed"] = behaviorTotal - 1
	}))
	if codes["GATE_RESULT_SEMANTICS"] == 0 {
		t.Fatalf("PASS under-covering the behavior corpora must block with GATE_RESULT_SEMANTICS: %v", codes)
	}

	// Round-5 regression: a candidate-kill gate whose PASS records zero
	// failing executions has a vacuous kill condition.
	codes = findingCodes(writeGatesNamed(func(gates map[string]any) {
		result := gates["empty_rust_target_fails"].(map[string]any)["result"].(map[string]any)
		result["passed"] = len(generated.Public)
		result["failed"] = 0
	}))
	if codes["GATE_RESULT_SEMANTICS"] == 0 {
		t.Fatalf("kill gate PASS with zero failures must block with GATE_RESULT_SEMANTICS: %v", codes)
	}
}

// Calibration live gates: LIVE_CALIBRATED is only reachable with every gate
// PASS; failed gates force a blocked status; recorded results must carry
// internally consistent counters and resolvable transcript digests.
// Reality-check regression: the calibration document's corpora
// manifest_sha256 bindings must reconcile against the actual manifest files
// — "any mismatch blocks" (AC5) has to hold end to end, not just at the
// per-manifest schema layer.
func TestVerifyLiveEvidenceCalibrationManifestBindings(t *testing.T) {
	root, protectedRoot, generated := writeAllToTemp(t)
	document, err := BuildCalibration(root, protectedRoot, generated)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteCalibration(root, document); err != nil {
		t.Fatal(err)
	}

	// Faithful bindings verify clean.
	findings, err := VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("faithful calibration manifest bindings must verify: %v", findings)
	}

	calibrationPath := filepath.Join(root, "evidence/corpus-calibration.json")
	mutate := func(change func(corpora map[string]any)) []Finding {
		t.Helper()
		raw, err := os.ReadFile(calibrationPath)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		change(doc["corpora"].(map[string]any))
		if err := writeJSONFile(calibrationPath, doc); err != nil {
			t.Fatal(err)
		}
		found, err := VerifyLiveEvidence(root, protectedRoot)
		if err != nil {
			t.Fatal(err)
		}
		// Restore the faithful document for the next case.
		if err := os.WriteFile(calibrationPath, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		return found
	}

	// A stale manifest digest must block, typed.
	codes := findingCodes(mutate(func(corpora map[string]any) {
		entry := corpora["handshake"].(map[string]any)
		entry["manifest_sha256"] = "sha256:" + strings.Repeat("ab", 32)
	}))
	if codes["CALIBRATION_MANIFEST_DIGEST_MISMATCH"] == 0 {
		t.Fatalf("stale calibration manifest digest must block: %v", codes)
	}

	// An unreadable manifest path is its own typed finding, never silent.
	codes = findingCodes(mutate(func(corpora map[string]any) {
		entry := corpora["hidden"].(map[string]any)
		entry["manifest_path"] = "corpora/hidden/does-not-exist.json"
	}))
	if codes["CALIBRATION_MANIFEST_UNREADABLE"] == 0 {
		t.Fatalf("unreadable calibration manifest path must block: %v", codes)
	}

	// A missing/mistyped digest field is unreadable-typed too.
	codes = findingCodes(mutate(func(corpora map[string]any) {
		entry := corpora["sealed"].(map[string]any)
		delete(entry, "manifest_sha256")
	}))
	if codes["CALIBRATION_MANIFEST_UNREADABLE"] == 0 {
		t.Fatalf("missing calibration manifest digest must block: %v", codes)
	}
}

func TestVerifyLiveEvidenceCalibrationGateConsistency(t *testing.T) {
	root, protectedRoot, generated := writeAllToTemp(t)
	document, err := BuildCalibration(root, protectedRoot, generated)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteCalibration(root, document); err != nil {
		t.Fatal(err)
	}
	// Pending gates with pending status: clean.
	findings, err := VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("pending calibration must have no live findings: %v", findings)
	}

	_, transcriptPath := recordLiveExecution(t, root, protectedRoot, generated)
	transcriptRaw, err := os.ReadFile(transcriptPath)
	if err != nil {
		t.Fatal(err)
	}
	transcriptDigest := DigestSHA256(transcriptRaw)

	calibrationPath := filepath.Join(root, "evidence/corpus-calibration.json")
	setGates := func(status string, gateStatus map[string]string) {
		t.Helper()
		raw, err := os.ReadFile(calibrationPath)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		gates := doc["live_gates"].(map[string]any)
		for name, s := range gateStatus {
			gate := gates[name].(map[string]any)
			gate["status"] = s
			if s == "PASS" || s == "FAIL" {
				// Per-gate faithful PASS shapes (round-5 semantics): the
				// pass-rate gate covers every behavior scenario with zero
				// failures; the candidate-kill gates PASS because
				// executions failed.
				behaviorTotal := len(generated.Public) + len(generated.Hidden) + len(generated.Sealed)
				executed, passed, failed := len(generated.Public), len(generated.Public), 0
				switch name {
				case "java_oracle_pass_rate":
					executed, passed, failed = behaviorTotal, behaviorTotal, 0
				case "empty_rust_target_fails", "planted_java_rust_mutants_killed":
					executed, passed, failed = len(generated.Public), 0, len(generated.Public)
				}
				if s == "FAIL" {
					executed, passed, failed = len(generated.Public), len(generated.Public)-1, 1
				}
				gate["result"] = map[string]any{
					"transcript_sha256s": []any{transcriptDigest},
					"executed":           executed,
					"passed":             passed,
					"failed":             failed,
				}
			} else {
				delete(gate, "result")
			}
		}
		doc["status"] = status
		if err := writeJSONFile(calibrationPath, doc); err != nil {
			t.Fatal(err)
		}
	}
	allGates := []string{"java_oracle_pass_rate", "empty_rust_target_fails",
		"planted_java_rust_mutants_killed", "execution_rerun_reconciliation",
		"sealed_network_denial"}
	allPass := map[string]string{}
	for _, gate := range allGates {
		allPass[gate] = "PASS"
	}

	// Every gate PASS with LIVE_CALIBRATED: clean.
	setGates("LIVE_CALIBRATED", allPass)
	findings, err = VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("all-pass live calibration must verify: %v", findings)
	}

	// A FAIL gate under LIVE_CALIBRATED is inconsistent.
	withFail := map[string]string{}
	for gate, s := range allPass {
		withFail[gate] = s
	}
	withFail["sealed_network_denial"] = "FAIL"
	setGates("LIVE_CALIBRATED", withFail)
	findings, err = VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if findingCodes(findings)["LIVE_STATUS_INCONSISTENT"] == 0 {
		t.Fatalf("failed gate under LIVE_CALIBRATED must block: %v", findings)
	}

	// A FAIL gate with LIVE_BLOCKED is consistent.
	setGates("LIVE_BLOCKED", withFail)
	findings, err = VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("failed gate under LIVE_BLOCKED must verify: %v", findings)
	}

	// All gates PASS but a pending status understates the outcome.
	setGates("OFFLINE_CALIBRATED_PENDING_LIVE_EXECUTION", allPass)
	findings, err = VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if findingCodes(findings)["LIVE_STATUS_INCONSISTENT"] == 0 {
		t.Fatalf("all-pass gates with pending status must block: %v", findings)
	}

	// Gate result counters must be internally consistent.
	setGates("LIVE_CALIBRATED", allPass)
	raw, err := os.ReadFile(calibrationPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	gate := doc["live_gates"].(map[string]any)["java_oracle_pass_rate"].(map[string]any)
	result := gate["result"].(map[string]any)
	result["passed"] = int(result["passed"].(float64)) - 1
	if err := writeJSONFile(calibrationPath, doc); err != nil {
		t.Fatal(err)
	}
	findings, err = VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if findingCodes(findings)["GATE_COUNTER_INCONSISTENT"] == 0 {
		t.Fatalf("inconsistent gate counters must block: %v", findings)
	}

	// A gate transcript digest that resolves to no live artifact blocks.
	result["passed"] = int(result["executed"].(float64))
	result["transcript_sha256s"] = []any{DigestSHA256([]byte("never-written"))}
	if err := writeJSONFile(calibrationPath, doc); err != nil {
		t.Fatal(err)
	}
	findings, err = VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if findingCodes(findings)["TRANSCRIPT_UNRESOLVED"] == 0 {
		t.Fatalf("dangling gate transcript digest must block: %v", findings)
	}
}
