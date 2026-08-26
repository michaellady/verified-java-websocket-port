package corpora

import (
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

	for _, tier := range []string{"public", "handshake", "hidden", "sealed"} {
		manifestPath := filepath.Join(root, repoCorporaDir, tier, "manifest.json")
		manifest, err := readManifest(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("%s manifest: %w", tier, err)
		}
		if manifest["execution_status"] != "LIVE_EXECUTED" {
			continue
		}
		verifyManifestExecution(tier, manifestPath, manifest, protectedRoot, fail)
	}

	calibrationPath := filepath.Join(root, "evidence/corpus-calibration.json")
	if _, err := os.Stat(calibrationPath); err == nil {
		document, err := readManifest(calibrationPath)
		if err != nil {
			return nil, fmt.Errorf("calibration document: %w", err)
		}
		verifyCalibrationLiveGates(calibrationPath, document, protectedRoot, fail)
	}
	return findings, nil
}

func intCount(container map[string]any, field string) int {
	value, _ := container[field].(float64)
	return int(value)
}

// gateCounter reads one recorded gate-result counter strictly: a missing or
// non-integer value reports false and is never silently read as zero.
func gateCounter(result map[string]any, field string) (int, bool) {
	value, ok := result[field].(float64)
	if !ok || value != math.Trunc(value) {
		return 0, false
	}
	return int(value), true
}

func verifyManifestExecution(tier, path string, manifest map[string]any,
	protectedRoot string, fail func(code, path, detail string)) {
	counts, _ := manifest["counts"].(map[string]any)
	if counts == nil {
		fail("COUNTER_INCONSISTENT", path, "LIVE_EXECUTED manifest lacks counts")
		return
	}
	executed := intCount(counts, "executed")
	passed := intCount(counts, "passed")
	failed := intCount(counts, "failed")
	skipped := intCount(counts, "skipped")
	timedOut := intCount(counts, "timed_out")
	selected := intCount(counts, "selected")
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
	verifyNamedArtifact(evidence, "transcript_sha256",
		filepath.Join(liveArtifactDir(protectedRoot), tier, "transcript.jsonl"),
		"TRANSCRIPT", path, fail)
	verifyNamedArtifact(evidence, "report_sha256",
		filepath.Join(liveArtifactDir(protectedRoot), tier, "report.json"),
		"REPORT", path, fail)
}

func verifyNamedArtifact(evidence map[string]any, field, artifactPath, kind,
	manifestPath string, fail func(code, path, detail string)) {
	recorded, _ := evidence[field].(string)
	if recorded == "" {
		fail(kind+"_UNRESOLVED", manifestPath, field+" is missing")
		return
	}
	raw, err := os.ReadFile(artifactPath)
	if err != nil {
		fail(kind+"_UNRESOLVED", manifestPath,
			"recorded "+field+" has no protected artifact at "+artifactPath)
		return
	}
	if DigestSHA256(raw) != recorded {
		fail(kind+"_DIGEST_MISMATCH", manifestPath,
			"protected artifact "+artifactPath+" does not match the recorded "+field)
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
