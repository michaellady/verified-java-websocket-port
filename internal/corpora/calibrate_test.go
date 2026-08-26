package corpora

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every built-in reference mutant must be killed by the corpus with a
// nonzero killing inventory; the analysis numbers are derived, never typed.
func TestMutationAnalysisKillsAllBuiltinMutants(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	mutants := BuiltinMutants()
	if len(mutants) < 12 {
		t.Fatalf("builtin mutant inventory too small: %d", len(mutants))
	}
	report, err := RunMutationAnalysis(generated, mutants)
	if err != nil {
		t.Fatalf("RunMutationAnalysis: %v", err)
	}
	if report.Surviving != 0 || report.Killed != len(mutants) {
		t.Fatalf("report = killed %d surviving %d of %d",
			report.Killed, report.Surviving, len(mutants))
	}
	var behavior, handshake int
	for _, result := range report.Mutants {
		if !result.Killed || result.TotalKilling == 0 {
			t.Fatalf("mutant %s not killed (total=%d)", result.MutantID, result.TotalKilling)
		}
		switch result.Kind {
		case "behavior":
			behavior++
		case "handshake":
			handshake++
		default:
			t.Fatalf("mutant %s kind %q", result.MutantID, result.Kind)
		}
	}
	if behavior == 0 || handshake == 0 {
		t.Fatalf("mutant kinds behavior=%d handshake=%d", behavior, handshake)
	}
}

// A mutant identical to the reference must be reported as surviving, and a
// surviving mutant must block the calibration gate.
func TestMutationAnalysisFailsClosedOnSurvivor(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	identity := Mutant{
		MutantID: "mut-identity-probe",
		Kind:     "behavior",
		Operator: "no-op: identical to the reference model",
		Behavior: func() Behavior { return ReferenceBehavior() },
	}
	report, err := RunMutationAnalysis(generated, []Mutant{identity})
	if err != nil {
		t.Fatalf("RunMutationAnalysis: %v", err)
	}
	if report.Surviving != 1 {
		t.Fatalf("identity mutant must survive, report = %+v", report)
	}
}

// The stub-target analysis is a negative control of the evaluator: an empty
// adapter that reports no behavior must pass zero scenarios.
func TestStubTargetPassesZeroScenarios(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	report := EvaluateStubTarget(generated)
	if report.Total == 0 || report.Passes != 0 || report.Failures != report.Total {
		t.Fatalf("stub report = %+v", report)
	}
}

// Two full generation reruns must reconcile exactly.
func TestGenerationRerunsReconcile(t *testing.T) {
	report, err := RunGenerationReruns(testInput(), 2)
	if err != nil {
		t.Fatalf("RunGenerationReruns: %v", err)
	}
	if report.Runs != 2 || !report.Reconciled || len(report.Digests) != 2 ||
		report.Digests[0] != report.Digests[1] {
		t.Fatalf("rerun report = %+v", report)
	}
}

// No protected evidence may rescue a public failure.
func TestRejectProtectedRescue(t *testing.T) {
	publicIDs := map[string]bool{"us005.pub.0001": true, "us005.pub.0002": true}
	if findings := RejectProtectedRescue(publicIDs, nil); len(findings) != 0 {
		t.Fatalf("no overrides must produce no findings: %v", findings)
	}
	overrides := []ProtectedOverride{{
		ScenarioID: "us005.pub.0002",
		Source:     "protected/us005-corpora/hidden/scenarios.jsonl",
		Claim:      "diagnostic shows the public failure is a harness artifact",
	}}
	findings := RejectProtectedRescue(publicIDs, overrides)
	if len(findings) != 1 || findings[0].Code != "PROTECTED_RESCUE_BLOCKED" {
		t.Fatalf("protected rescue must block: %v", findings)
	}
}

// The calibration document derives every number, reports offline gates from
// computed reports, and keeps all live gates fail-closed with the exact
// runtime constraints.
func TestBuildAndWriteCalibrationDocument(t *testing.T) {
	root, protectedRoot, generated := writeAllToTemp(t)
	doc, err := BuildCalibration(root, protectedRoot, generated)
	if err != nil {
		t.Fatalf("BuildCalibration: %v", err)
	}
	if err := WriteCalibration(root, doc); err != nil {
		t.Fatalf("WriteCalibration: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "evidence/corpus-calibration.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("calibration document is not JSON: %v", err)
	}

	offline := parsed["offline_gates"].(map[string]any)
	for _, gate := range []string{"generation_determinism", "manifest_reconciliation",
		"reference_mutation_analysis", "stub_target_analysis", "protected_rescue_rule"} {
		entry, present := offline[gate].(map[string]any)
		if !present {
			t.Fatalf("offline gate %s missing", gate)
		}
		status := entry["status"].(string)
		if status != "PASS" && status != "ENFORCED" {
			t.Fatalf("offline gate %s status %s", gate, status)
		}
	}
	mutation := offline["reference_mutation_analysis"].(map[string]any)
	if int(mutation["surviving"].(float64)) != 0 ||
		int(mutation["total_mutants"].(float64)) < 12 {
		t.Fatalf("mutation gate = %v", mutation)
	}
	if !strings.Contains(mutation["model"].(string), "not Java or Rust") {
		t.Fatal("mutation gate must state it measured the reference model, not Java or Rust binaries")
	}

	live := parsed["live_gates"].(map[string]any)
	for _, gate := range []string{"java_oracle_pass_rate", "empty_rust_target_fails",
		"planted_java_rust_mutants_killed", "execution_rerun_reconciliation",
		"sealed_network_denial"} {
		entry, present := live[gate].(map[string]any)
		if !present {
			t.Fatalf("live gate %s missing", gate)
		}
		if entry["status"] != "BLOCKED_PENDING_LIVE_EXECUTION" {
			t.Fatalf("live gate %s status %v", gate, entry["status"])
		}
		if entry["constraint"] == nil || entry["constraint"] == "" {
			t.Fatalf("live gate %s lacks its constraint", gate)
		}
	}
	if parsed["status"] != "OFFLINE_CALIBRATED_PENDING_LIVE_EXECUTION" {
		t.Fatalf("document status = %v", parsed["status"])
	}
	if parsed["assurance"] != "OWNER_ATTESTED_NOT_INDEPENDENT" ||
		parsed["independent_review_claimed"] != false {
		t.Fatal("calibration document assurance labels wrong")
	}
	steps, _ := parsed["live_steps"].([]any)
	if len(steps) == 0 {
		t.Fatal("calibration document must hand the parent the live steps")
	}
	var stepsText strings.Builder
	for _, step := range steps {
		text, _ := step.(string)
		stepsText.WriteString(text)
		stepsText.WriteByte('\n')
	}
	// The operator-facing steps must state the load-bearing protected
	// live-artifact layout, not leave it to an internal code comment.
	for _, needle := range []string{
		"us005-corpora/live/<tier>/transcript.jsonl",
		"us005-corpora/live/<tier>/report.json",
		"us005-corpora/live/**",
	} {
		if !strings.Contains(stepsText.String(), needle) {
			t.Fatalf("live steps must state the protected live-artifact layout (missing %q)", needle)
		}
	}

	// The document itself must be deterministic.
	second, err := BuildCalibration(root, protectedRoot, generated)
	if err != nil {
		t.Fatal(err)
	}
	left, err := canonicalizeJSONValue(doc)
	if err != nil {
		t.Fatal(err)
	}
	right, err := canonicalizeJSONValue(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatal("calibration document must build deterministically")
	}
}
