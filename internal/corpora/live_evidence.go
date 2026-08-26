package corpora

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

// liveArtifactDir is the protected-store location for live execution
// artifacts: live/<tier>/transcript.jsonl and live/<tier>/report.json for
// manifests, and any files under live/ for calibration gate transcripts.
func liveArtifactDir(protectedRoot string) string {
	return filepath.Join(protectedRoot, ProtectedDirName, "live")
}

var liveGateNames = []string{
	"java_oracle_pass_rate",
	"empty_rust_target_fails",
	"planted_java_rust_mutants_killed",
	"execution_rerun_reconciliation",
	"sealed_network_denial",
}

// VerifyLiveEvidence enforces the semantic half of the live-evidence
// contract: recorded executions must be nonempty and internally consistent,
// their digests must reconcile against the protected live artifacts (typed
// unresolved findings when artifacts are absent — fail closed, not silent),
// and the calibration status must agree with the recorded gate outcomes.
func VerifyLiveEvidence(root, protectedRoot string) ([]Finding, error) {
	var findings []Finding
	fail := func(code, path, detail string) {
		findings = append(findings, Finding{Code: code, Path: path, Detail: detail})
	}

	input, err := LoadGenerationInput(root, protectedRoot)
	if err != nil {
		return nil, fmt.Errorf("live evidence generation input: %w", err)
	}
	generated, err := GenerateAll(input)
	if err != nil {
		return nil, fmt.Errorf("live evidence regeneration: %w", err)
	}

	for _, tier := range []string{"public", "handshake", "hidden", "sealed"} {
		manifestPath := filepath.Join(root, repoCorporaDir, tier, "manifest.json")
		manifest, err := readManifest(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("%s manifest: %w", tier, err)
		}
		if manifest["execution_status"] != "LIVE_EXECUTED" {
			continue
		}
		verifyManifestExecution(tier, manifestPath, manifest, protectedRoot, generated, fail)
	}

	calibrationPath := filepath.Join(root, "evidence/corpus-calibration.json")
	if _, err := os.Stat(calibrationPath); err == nil {
		document, err := readManifest(calibrationPath)
		if err != nil {
			return nil, fmt.Errorf("calibration document: %w", err)
		}
		verifyCalibrationCorpusReferences(root, calibrationPath, document, fail)
		verifyCalibrationLiveGates(calibrationPath, document, protectedRoot, fail)
	}
	return findings, nil
}

// gateCounter reads one recorded gate-result counter strictly: a missing or
// non-integer value reports false and is never silently read as zero.
func gateCounter(result map[string]any, field string) (int, bool) {
	value, ok := result[field].(float64)
	maxInt := float64(int(^uint(0) >> 1))
	if !ok || value != math.Trunc(value) || value < 0 || value > maxInt {
		return 0, false
	}
	return int(value), true
}

func verifyManifestExecution(tier, path string, manifest map[string]any,
	protectedRoot string, generated *GeneratedCorpora,
	fail func(code, path, detail string)) {
	counts, _ := manifest["counts"].(map[string]any)
	if counts == nil {
		fail("COUNTER_INCONSISTENT", path, "LIVE_EXECUTED manifest lacks counts")
		return
	}
	values := map[string]int{}
	for _, field := range []string{"executed", "passed", "failed", "skipped", "timed_out", "selected"} {
		value, ok := gateCounter(counts, field)
		if !ok {
			fail("COUNTER_INCONSISTENT", path,
				"LIVE_EXECUTED manifest counter "+field+" is missing or non-integral")
			return
		}
		values[field] = value
	}
	executed := values["executed"]
	passed := values["passed"]
	failed := values["failed"]
	skipped := values["skipped"]
	timedOut := values["timed_out"]
	selected := values["selected"]
	if executed < 1 {
		fail("LIVE_EXECUTION_EMPTY", path,
			"LIVE_EXECUTED requires at least one executed scenario")
	}
	if passed+failed != executed {
		fail("COUNTER_INCONSISTENT", path, fmt.Sprintf(
			"passed(%d)+failed(%d) != executed(%d)", passed, failed, executed))
	}
	if executed+skipped+timedOut != selected {
		fail("COUNTER_INCONSISTENT", path, fmt.Sprintf(
			"executed(%d)+skipped(%d)+timed_out(%d) != selected(%d)",
			executed, skipped, timedOut, selected))
	}

	evidence, _ := manifest["execution_evidence"].(map[string]any)
	if evidence == nil {
		fail("TRANSCRIPT_UNRESOLVED", path, "LIVE_EXECUTED without execution_evidence")
		return
	}
	transcript, transcriptOK := verifyNamedArtifact(evidence, "transcript_sha256",
		filepath.Join(liveArtifactDir(protectedRoot), tier, "transcript.jsonl"),
		"TRANSCRIPT", path, fail)
	reportRaw, reportOK := verifyNamedArtifact(evidence, "report_sha256",
		filepath.Join(liveArtifactDir(protectedRoot), tier, "report.json"),
		"REPORT", path, fail)
	if !transcriptOK || !reportOK {
		return
	}

	if tier == "handshake" {
		replayed, err := EvaluateHandshakeLiveTranscript(generated.Handshake, transcript)
		if err != nil {
			fail("TRANSCRIPT_SEMANTIC_MISMATCH", path,
				"protected transcript cannot be replayed: "+err.Error())
			return
		}
		if !replayed.Reconciled() {
			fail("TRANSCRIPT_SEMANTIC_MISMATCH", path,
				fmt.Sprintf("replayed transcript does not reconcile: %+v", replayed.TranscriptReport))
		}
		var recorded HandshakeLiveReport
		if err := decodeStrictJSON(reportRaw, &recorded); err != nil {
			fail("REPORT_SEMANTIC_MISMATCH", path,
				"protected report is not strict JSON: "+err.Error())
			return
		}
		if !reportsEquivalent(recorded, replayed) {
			fail("REPORT_SEMANTIC_MISMATCH", path,
				"protected report does not equal transcript replay")
		}
		reconcileManifestReplay(path, counts, replayed.TranscriptReport, fail)
		return
	}

	var scenarios []Scenario
	switch tier {
	case "public":
		scenarios = generated.Public
	case "hidden":
		scenarios = generated.Hidden
	case "sealed":
		scenarios = generated.Sealed
	default:
		fail("TRANSCRIPT_SEMANTIC_MISMATCH", path, "unsupported live tier "+tier)
		return
	}
	replayed, err := EvaluateTranscript(scenarios, transcript)
	if err != nil {
		fail("TRANSCRIPT_SEMANTIC_MISMATCH", path,
			"protected transcript cannot be replayed: "+err.Error())
		return
	}
	if !replayed.Reconciled() {
		fail("TRANSCRIPT_SEMANTIC_MISMATCH", path,
			fmt.Sprintf("replayed transcript does not reconcile: %+v", replayed))
	}
	var recorded TranscriptReport
	if err := decodeStrictJSON(reportRaw, &recorded); err != nil {
		fail("REPORT_SEMANTIC_MISMATCH", path,
			"protected report is not strict JSON: "+err.Error())
		return
	}
	if !reportsEquivalent(recorded, replayed) {
		fail("REPORT_SEMANTIC_MISMATCH", path,
			"protected report does not equal transcript replay")
	}
	reconcileManifestReplay(path, counts, replayed, fail)
}

func reportsEquivalent(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func verifyNamedArtifact(evidence map[string]any, field, artifactPath, kind,
	manifestPath string, fail func(code, path, detail string)) ([]byte, bool) {
	recorded, _ := evidence[field].(string)
	if recorded == "" {
		fail(kind+"_UNRESOLVED", manifestPath, field+" is missing")
		return nil, false
	}
	raw, err := os.ReadFile(artifactPath)
	if err != nil {
		fail(kind+"_UNRESOLVED", manifestPath,
			"recorded "+field+" has no protected artifact at "+artifactPath)
		return nil, false
	}
	if DigestSHA256(raw) != recorded {
		fail(kind+"_DIGEST_MISMATCH", manifestPath,
			"protected artifact "+artifactPath+" does not match the recorded "+field)
		return raw, false
	}
	return raw, true
}

func reconcileManifestReplay(path string, counts map[string]any,
	replayed TranscriptReport, fail func(code, path, detail string)) {
	for field, want := range map[string]int{
		"executed": replayed.Executed,
		"passed":   replayed.Passed,
		"failed":   replayed.Failed,
	} {
		got, ok := gateCounter(counts, field)
		if !ok || got != want {
			fail("MANIFEST_REPORT_MISMATCH", path, fmt.Sprintf(
				"manifest %s=%v but transcript replay reports %d", field, counts[field], want))
		}
	}
}

func verifyCalibrationCorpusReferences(root, calibrationPath string,
	document map[string]any, fail func(code, path, detail string)) {
	entries, _ := document["corpora"].(map[string]any)
	if entries == nil {
		fail("CALIBRATION_MANIFEST_REFERENCE_MISSING", calibrationPath,
			"calibration corpora references are absent")
		return
	}
	if len(entries) != 4 {
		fail("CALIBRATION_MANIFEST_REFERENCE_UNEXPECTED", calibrationPath,
			"calibration corpora must contain exactly the four generated tiers")
	}
	for tier := range entries {
		if tier != "public" && tier != "handshake" && tier != "hidden" && tier != "sealed" {
			fail("CALIBRATION_MANIFEST_REFERENCE_UNEXPECTED", calibrationPath,
				"calibration contains unexpected corpus reference "+tier)
		}
	}
	for _, tier := range []string{"public", "handshake", "hidden", "sealed"} {
		entry, _ := entries[tier].(map[string]any)
		if entry == nil {
			fail("CALIBRATION_MANIFEST_REFERENCE_MISSING", calibrationPath,
				"calibration reference for "+tier+" is absent")
			continue
		}
		expectedPath := filepath.ToSlash(filepath.Join(repoCorporaDir, tier, "manifest.json"))
		recordedPath, _ := entry["manifest_path"].(string)
		if recordedPath != expectedPath {
			fail("CALIBRATION_MANIFEST_PATH_MISMATCH", calibrationPath, fmt.Sprintf(
				"%s manifest_path=%q, expected %q", tier, recordedPath, expectedPath))
			continue
		}
		manifestPath := filepath.Join(root, filepath.FromSlash(expectedPath))
		raw, err := os.ReadFile(manifestPath)
		if err != nil {
			fail("CALIBRATION_MANIFEST_UNREADABLE", calibrationPath,
				"referenced manifest "+manifestPath+" is unreadable: "+err.Error())
			continue
		}
		recordedDigest, _ := entry["manifest_sha256"].(string)
		if recordedDigest == "" || recordedDigest == "sha256:"+zero64() {
			fail("CALIBRATION_MANIFEST_DIGEST_INVALID", calibrationPath,
				tier+" manifest digest is missing or all-zero")
		} else if recordedDigest != DigestSHA256(raw) {
			fail("CALIBRATION_MANIFEST_DIGEST_MISMATCH", calibrationPath,
				tier+" manifest digest does not match reopened bytes")
		}
		manifest, err := readManifest(manifestPath)
		if err != nil {
			fail("CALIBRATION_MANIFEST_UNREADABLE", calibrationPath, err.Error())
			continue
		}
		counts, _ := manifest["counts"].(map[string]any)
		for _, field := range []string{"expected", "selected", "filtered"} {
			recorded, recordedOK := gateCounter(entry, field)
			manifestCount, manifestOK := gateCounter(counts, field)
			if !recordedOK || !manifestOK || recorded != manifestCount {
				fail("CALIBRATION_MANIFEST_COUNT_MISMATCH", calibrationPath, fmt.Sprintf(
					"%s %s=%v, referenced manifest records %v",
					tier, field, entry[field], counts[field]))
			}
		}
	}
}

// liveDigestSet digests every file under the protected live store.
func liveDigestSet(protectedRoot string) map[string]bool {
	digests := map[string]bool{}
	_ = filepath.WalkDir(liveArtifactDir(protectedRoot),
		func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !entry.Type().IsRegular() {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			digests[DigestSHA256(raw)] = true
			return nil
		})
	return digests
}

// behaviorSelectedTotal sums the selected counts of the behavior tiers
// (public, hidden, sealed — handshake is scored by its own tier flow) from
// the calibration document's corpora section. A missing or mistyped count
// returns ok=false so callers surface a typed finding instead of silently
// weakening the coverage check.
func behaviorSelectedTotal(document map[string]any) (int, bool) {
	corpora, _ := document["corpora"].(map[string]any)
	if corpora == nil {
		return 0, false
	}
	total := 0
	for _, tier := range []string{"public", "hidden", "sealed"} {
		entry, _ := corpora[tier].(map[string]any)
		if entry == nil {
			return 0, false
		}
		selected, ok := gateCounter(entry, "selected")
		if !ok {
			return 0, false
		}
		total += selected
	}
	return total, true
}

func verifyCalibrationLiveGates(path string, document map[string]any,
	protectedRoot string, fail func(code, path, detail string)) {
	gates, _ := document["live_gates"].(map[string]any)
	if gates == nil {
		return
	}
	status, _ := document["status"].(string)
	digests := liveDigestSet(protectedRoot)

	allPass := true
	anyFail := false
	for _, name := range liveGateNames {
		gate, _ := gates[name].(map[string]any)
		if gate == nil {
			fail("LIVE_RESULT_MISSING", path, "live gate "+name+" is absent")
			allPass = false
			continue
		}
		gateStatus, _ := gate["status"].(string)
		switch gateStatus {
		case "PASS", "FAIL":
			if gateStatus == "FAIL" {
				anyFail = true
				allPass = false
			}
			result, _ := gate["result"].(map[string]any)
			if result == nil {
				fail("LIVE_RESULT_MISSING", path,
					"live gate "+name+" records "+gateStatus+" without a result")
				continue
			}
			executed, executedOK := gateCounter(result, "executed")
			passed, passedOK := gateCounter(result, "passed")
			failed, failedOK := gateCounter(result, "failed")
			if !executedOK || !passedOK || !failedOK {
				fail("GATE_COUNTER_MISSING", path, fmt.Sprintf(
					"gate %s result counters must be recorded integers "+
						"(executed=%v passed=%v failed=%v)", name,
					result["executed"], result["passed"], result["failed"]))
			} else {
				if passed+failed != executed {
					fail("GATE_COUNTER_INCONSISTENT", path, fmt.Sprintf(
						"gate %s: passed(%d)+failed(%d) != executed(%d)",
						name, passed, failed, executed))
				}
				if gateStatus == "PASS" && executed < 1 {
					fail("GATE_ZERO_EXECUTION", path,
						"gate "+name+" claims PASS with zero executed scenarios")
				}
				// Per-gate PASS semantics: counter identities alone still
				// admit dishonest states (e.g. a 100%-pass-rate gate
				// recording PASS with executed=258 passed=0 failed=258).
				switch name {
				case "java_oracle_pass_rate":
					if gateStatus == "PASS" {
						if failed != 0 || passed != executed {
							fail("GATE_RESULT_SEMANTICS", path, fmt.Sprintf(
								"gate %s claims PASS with non-perfect results "+
									"(executed=%d passed=%d failed=%d); the 100%% "+
									"pass-rate requirement needs failed=0 and passed=executed",
								name, executed, passed, failed))
						}
						if want, ok := behaviorSelectedTotal(document); !ok {
							fail("GATE_COUNTER_MISSING", path,
								"behavior corpora selected counts are unreadable; "+
									"cannot check "+name+" coverage")
						} else if executed != want {
							fail("GATE_RESULT_SEMANTICS", path, fmt.Sprintf(
								"gate %s claims PASS over %d executions but the "+
									"behavior corpora select %d scenarios",
								name, executed, want))
						}
					}
				case "empty_rust_target_fails", "planted_java_rust_mutants_killed":
					if gateStatus == "PASS" && failed < 1 {
						fail("GATE_RESULT_SEMANTICS", path, fmt.Sprintf(
							"gate %s claims PASS with zero failing executions; its "+
								"kill condition requires at least one scenario to fail "+
								"the candidate", name))
					}
				}
			}
			transcripts, _ := result["transcript_sha256s"].([]any)
			if len(transcripts) == 0 {
				fail("TRANSCRIPT_UNRESOLVED", path,
					"gate "+name+" result carries no transcript digests")
			}
			for _, digest := range transcripts {
				digestString, _ := digest.(string)
				if !digests[digestString] {
					fail("TRANSCRIPT_UNRESOLVED", path,
						"gate "+name+" transcript digest resolves to no protected live artifact")
				}
			}
		default:
			allPass = false
		}
	}

	if status == "LIVE_CALIBRATED" && !allPass {
		fail("LIVE_STATUS_INCONSISTENT", path,
			"LIVE_CALIBRATED requires every live gate to record PASS")
	}
	if anyFail && status != "LIVE_BLOCKED" && status != "BLOCKED" {
		fail("LIVE_STATUS_INCONSISTENT", path,
			"a failed live gate requires status LIVE_BLOCKED or BLOCKED")
	}
	if allPass && status != "LIVE_CALIBRATED" {
		fail("LIVE_STATUS_INCONSISTENT", path,
			"all live gates PASS requires status LIVE_CALIBRATED")
	}
}
