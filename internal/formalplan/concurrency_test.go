package formalplan

// Lane B (US-006) tests for the concurrency-plan validator. Helper names are
// lane-scoped (mpTest* / cpTest*) to avoid collisions with Lane A files.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	cpTestPlanPath   = "../../assurance/concurrency/plan.json"
	cpTestSchemaPath = "../../schemas/concurrency-plan-1.0.0.schema.json"
	cpTestLedgerPath = "../../evidence/java/behavior-delta-ledger.json"
)

func cpTestInputs(t *testing.T) ConcurrencyPlanInputs {
	t.Helper()
	return ConcurrencyPlanInputs{
		PlanPath:           cpTestPlanPath,
		SchemaPath:         cpTestSchemaPath,
		TLAPath:            mpTestTLAPath,
		CfgPath:            mpTestCfgPath,
		LedgerPath:         cpTestLedgerPath,
		ReceiptRoot:        "../..",
		QuarantineJavaRoot: mpTestJavaRootIfPresent(t),
	}
}

func cpTestDecodePlan(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(cpTestPlanPath)
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	return value
}

func cpTestWritePlan(t *testing.T, value map[string]any) string {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("encode plan: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	return path
}

func cpTestSection(t *testing.T, plan map[string]any, key string) []any {
	t.Helper()
	section, ok := plan[key].([]any)
	if !ok {
		t.Fatalf("plan section %q missing or not an array", key)
	}
	return section
}

func cpTestObject(t *testing.T, plan map[string]any, key string) map[string]any {
	t.Helper()
	object, ok := plan[key].(map[string]any)
	if !ok {
		t.Fatalf("plan section %q missing or not an object", key)
	}
	return object
}

func TestConcurrencyPlanArtifactValidates(t *testing.T) {
	inputs := cpTestInputs(t)
	findings := ValidateConcurrencyPlan(inputs)
	if blocking := mpTestBlocking(findings); len(blocking) != 0 {
		t.Fatalf("shipped concurrency plan has blocking findings: %+v", blocking)
	}
	if inputs.QuarantineJavaRoot != "" && len(findings) != 0 {
		t.Fatalf("shipped concurrency plan has findings with quarantine present: %+v", findings)
	}
}

func TestConcurrencyPlanEncodesFullSeamCensus(t *testing.T) {
	plan := cpTestDecodePlan(t)
	census := cpTestObject(t, plan, "seam_census")
	seams, ok := census["seams"].([]any)
	if !ok || len(seams) != 33 {
		t.Fatalf("expected the 33-seam census, got %d entries", len(seams))
	}
}

func TestConcurrencyPlanSchemaRejectsUnknownField(t *testing.T) {
	plan := cpTestDecodePlan(t)
	plan["unexpected_field"] = true
	inputs := cpTestInputs(t)
	inputs.PlanPath = cpTestWritePlan(t, plan)
	findings := ValidateConcurrencyPlan(inputs)
	if !mpTestHasFinding(findings, "PLAN_SCHEMA_INVALID") {
		t.Fatalf("expected PLAN_SCHEMA_INVALID, got %+v", findings)
	}
}

func TestConcurrencyPlanValidatorRejectsSemanticDefects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, map[string]any)
		expect string
	}{
		{
			name: "seam removed from census",
			mutate: func(t *testing.T, plan map[string]any) {
				census := cpTestObject(t, plan, "seam_census")
				seams := census["seams"].([]any)
				census["seams"] = seams[:len(seams)-1]
			},
			expect: "PLAN_SEAM_CENSUS_INCOMPLETE",
		},
		{
			name: "duplicate seam id",
			mutate: func(t *testing.T, plan map[string]any) {
				census := cpTestObject(t, plan, "seam_census")
				seams := census["seams"].([]any)
				first := seams[0].(map[string]any)
				second := seams[1].(map[string]any)
				second["seam_id"] = first["seam_id"]
			},
			expect: "PLAN_SEAM_CENSUS_INCOMPLETE",
		},
		{
			name: "malformed citation range order",
			mutate: func(t *testing.T, plan map[string]any) {
				census := cpTestObject(t, plan, "seam_census")
				seam := census["seams"].([]any)[0].(map[string]any)
				seam["citations"] = []any{"WebSocketImpl.java:10-5"}
			},
			expect: "PLAN_CITATION_MALFORMED",
		},
		{
			name: "action references unknown seam",
			mutate: func(t *testing.T, plan map[string]any) {
				action := cpTestSection(t, plan, "actions")[0].(map[string]any)
				action["java_seams"] = []any{"Z9"}
			},
			expect: "PLAN_ACTION_SEAM_UNKNOWN",
		},
		{
			name: "required action family missing",
			mutate: func(t *testing.T, plan map[string]any) {
				actions := cpTestSection(t, plan, "actions")
				var kept []any
				for _, entry := range actions {
					if entry.(map[string]any)["action_id"] != "action.outbound_flush" {
						kept = append(kept, entry)
					}
				}
				if len(kept) == len(actions) {
					t.Fatalf("action.outbound_flush not present; update test")
				}
				plan["actions"] = kept
			},
			expect: "PLAN_ACTION_FAMILY_MISSING",
		},
		{
			name: "second owner task",
			mutate: func(t *testing.T, plan map[string]any) {
				bounds := cpTestObject(t, plan, "bounds")
				bounds["owner_tasks_per_connection"] = 2
			},
			expect: "PLAN_BOUNDS_INCONSISTENT",
		},
		{
			name: "preemption bound exceeds schedule budget",
			mutate: func(t *testing.T, plan map[string]any) {
				bounds := cpTestObject(t, plan, "bounds")
				bounds["preemption_bound"] = bounds["schedule_count_max"]
			},
			expect: "PLAN_BOUNDS_INCONSISTENT",
		},
		{
			name: "producer fairness absence undeclared",
			mutate: func(t *testing.T, plan map[string]any) {
				fairness := cpTestSection(t, plan, "fairness")
				var kept []any
				for _, entry := range fairness {
					if entry.(map[string]any)["fairness_id"] != "PRODUCER_ADMISSION_FAIRNESS_ABSENT" {
						kept = append(kept, entry)
					}
				}
				if len(kept) == len(fairness) {
					t.Fatalf("PRODUCER_ADMISSION_FAIRNESS_ABSENT not present; update test")
				}
				plan["fairness"] = kept
			},
			expect: "PLAN_FAIRNESS_ABSENCE_UNDECLARED",
		},
		{
			name: "required race family missing",
			mutate: func(t *testing.T, plan map[string]any) {
				races := cpTestSection(t, plan, "races_not_corpus_encodable")
				var kept []any
				for _, entry := range races {
					if entry.(map[string]any)["race_id"] != "race.send_vs_close" {
						kept = append(kept, entry)
					}
				}
				if len(kept) == len(races) {
					t.Fatalf("race.send_vs_close not present; update test")
				}
				plan["races_not_corpus_encodable"] = kept
			},
			expect: "PLAN_RACE_FAMILY_MISSING",
		},
		{
			// Round-1 review, IMPORTANT finding: seam R4's census note calls
			// tmpHandshakeBytes a genuine Java race window, so its absence
			// from races_not_corpus_encodable must be a blocking finding.
			name: "required handshake-buffer race missing",
			mutate: func(t *testing.T, plan map[string]any) {
				races := cpTestSection(t, plan, "races_not_corpus_encodable")
				var kept []any
				for _, entry := range races {
					if entry.(map[string]any)["race_id"] != "race.handshake_buffer_vs_close" {
						kept = append(kept, entry)
					}
				}
				if len(kept) == len(races) {
					t.Fatalf("race.handshake_buffer_vs_close not present; update test")
				}
				plan["races_not_corpus_encodable"] = kept
			},
			expect: "PLAN_RACE_FAMILY_MISSING",
		},
		{
			name: "seeded defect targets unknown property",
			mutate: func(t *testing.T, plan map[string]any) {
				defect := cpTestSection(t, plan, "seeded_defects")[0].(map[string]any)
				defect["target_property"] = "NoSuchProperty"
			},
			expect: "PLAN_SEEDED_DEFECT_UNBOUND",
		},
		{
			name: "property loses falsification coverage",
			mutate: func(t *testing.T, plan map[string]any) {
				defects := cpTestSection(t, plan, "seeded_defects")
				plan["seeded_defects"] = defects[1:]
			},
			expect: "PLAN_PROPERTY_UNFALSIFIED",
		},
		{
			name: "ledger binding drifts",
			mutate: func(t *testing.T, plan map[string]any) {
				ledger := cpTestObject(t, plan, "behavior_delta_ledger")
				ledger["observed_record_count"] = 7
			},
			expect: "PLAN_LEDGER_BINDING_MISMATCH",
		},
		{
			name: "model check claims execution while tool unavailable",
			mutate: func(t *testing.T, plan map[string]any) {
				check := cpTestObject(t, plan, "model_check")
				check["state"] = "EXECUTED"
				check["available"] = false
			},
			expect: "PLAN_MODEL_CHECK_INCONSISTENT",
		},
		{
			// The executed record is only as honest as its receipts: every
			// recorded receipt digest must re-hash against the actual bytes
			// in the tree, and a drifted receipt blocks.
			name: "executed model check receipt digest drifts",
			mutate: func(t *testing.T, plan map[string]any) {
				check := cpTestObject(t, plan, "model_check")
				run, ok := check["executed_run"].(map[string]any)
				if !ok {
					t.Fatalf("model_check.executed_run not present; update test")
				}
				receipts := run["receipts"].([]any)
				receipts[0].(map[string]any)["sha256"] = "sha256:" + strings.Repeat("0", 64)
			},
			expect: "PLAN_MODEL_CHECK_RECEIPT_MISMATCH",
		},
		{
			// Paired states: a defect may claim EXECUTED only when the
			// executed run itself names that defect (no defect rides along on
			// another defect's execution).
			name: "executed defect unbound from the executed run",
			mutate: func(t *testing.T, plan map[string]any) {
				defects := cpTestSection(t, plan, "seeded_defects")
				mutated := false
				for _, entry := range defects {
					defect := entry.(map[string]any)
					if defect["defect_id"] == "defect.model.type-domain-escape" {
						defect["execution_state"] = "EXECUTED"
						mutated = true
					}
				}
				if !mutated {
					t.Fatalf("defect.model.type-domain-escape not present; update test")
				}
			},
			expect: "PLAN_DEFECT_EXECUTION_UNBOUND",
		},
		{
			// The reverse pairing: an executed-run defect entry naming a
			// defect whose table state is still pending blocks.
			name: "executed run names defect not marked executed",
			mutate: func(t *testing.T, plan map[string]any) {
				check := cpTestObject(t, plan, "model_check")
				run, ok := check["executed_run"].(map[string]any)
				if !ok {
					t.Fatalf("model_check.executed_run not present; update test")
				}
				executed := run["executed_defects"].([]any)
				executed[0].(map[string]any)["defect_id"] = "defect.model.type-domain-escape"
			},
			expect: "PLAN_DEFECT_EXECUTION_UNBOUND",
		},
		{
			name: "claim scope inflated to proof",
			mutate: func(t *testing.T, plan map[string]any) {
				assurance := cpTestObject(t, plan, "assurance")
				assurance["claim_scope"] = "PROOF"
			},
			expect: "PLAN_SCHEMA_INVALID",
		},
		{
			name: "assurance label inflated",
			mutate: func(t *testing.T, plan map[string]any) {
				assurance := cpTestObject(t, plan, "assurance")
				assurance["label"] = "proved-model"
			},
			expect: "PLAN_SCHEMA_INVALID",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			plan := cpTestDecodePlan(t)
			testCase.mutate(t, plan)
			inputs := cpTestInputs(t)
			inputs.PlanPath = cpTestWritePlan(t, plan)
			findings := ValidateConcurrencyPlan(inputs)
			if !mpTestHasFinding(findings, testCase.expect) {
				t.Fatalf("expected finding %s, got %+v", testCase.expect, findings)
			}
		})
	}
}

func TestConcurrencyPlanCitationResolution(t *testing.T) {
	plan := cpTestDecodePlan(t)
	census := cpTestObject(t, plan, "seam_census")
	seam := census["seams"].([]any)[0].(map[string]any)
	seam["citations"] = []any{"WebSocketImpl.java:900000"}
	inputs := cpTestInputs(t)
	inputs.PlanPath = cpTestWritePlan(t, plan)
	findings := ValidateConcurrencyPlan(inputs)
	if inputs.QuarantineJavaRoot != "" {
		if !mpTestHasFinding(findings, "PLAN_CITATION_UNRESOLVED") {
			t.Fatalf("expected PLAN_CITATION_UNRESOLVED with quarantine present, got %+v", findings)
		}
	} else if !mpTestHasFinding(findings, "PLAN_CITATION_UNVERIFIED") {
		t.Fatalf("expected advisory PLAN_CITATION_UNVERIFIED without quarantine, got %+v", findings)
	}
}

func TestConcurrencyPlanValidatorRejectsMissingFiles(t *testing.T) {
	inputs := cpTestInputs(t)
	inputs.PlanPath = "does-not-exist.json"
	findings := ValidateConcurrencyPlan(inputs)
	if !mpTestHasFinding(findings, "PLAN_FILE_UNREADABLE") {
		t.Fatalf("expected PLAN_FILE_UNREADABLE, got %+v", findings)
	}
}

// Without a receipt root the executed run's receipt digests cannot be
// re-hashed; the validator must say so out loud (advisory, still fail-closed
// in the preflight) instead of passing silently.
func TestConcurrencyPlanReceiptsUnverifiedWithoutRoot(t *testing.T) {
	inputs := cpTestInputs(t)
	inputs.ReceiptRoot = ""
	findings := ValidateConcurrencyPlan(inputs)
	if !mpTestHasFinding(findings, "PLAN_MODEL_CHECK_RECEIPT_UNVERIFIED") {
		t.Fatalf("expected advisory PLAN_MODEL_CHECK_RECEIPT_UNVERIFIED without a receipt root, got %+v", findings)
	}
	for _, finding := range findings {
		if finding.Code == "PLAN_MODEL_CHECK_RECEIPT_UNVERIFIED" && finding.Severity != SeverityAdvisory {
			t.Fatalf("receipt-root absence must be advisory, got %+v", finding)
		}
	}
}
