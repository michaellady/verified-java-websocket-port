package benchplan

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const repoRoot = "../.."

func TestVerifyRealTreeReportsOnlyHostBindingPending(t *testing.T) {
	report, err := Verify(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SchemaFailures) > 0 {
		t.Fatalf("benchmark documents must conform to their schemas, got: %v", report.SchemaFailures)
	}
	if len(report.PlanFailures) > 0 {
		t.Fatalf("plan must agree with the frozen executable spec, got: %v", report.PlanFailures)
	}
	if len(report.PowerFailures) > 0 {
		t.Fatalf("frozen power model must hold, got: %v", report.PowerFailures)
	}
	if report.FullyBound() {
		t.Fatal("the tree cannot be fully bound: the confirmation host and tool identities are owner-gated")
	}
	if !report.HostBindingIsOnlyBlocker() {
		t.Fatalf("expected HOST_BINDING_PENDING as the single blocker class, got %v", report.BlockerClasses)
	}
	// Completion meter: 7 unbound tool-identity fields on primary plus
	// all 23 confirmation fields (15 host including instance_id /
	// observed_architecture / allocation_evidence, 8 tools); 5
	// runtime-snapshot fields on primary.
	if len(report.UnboundFields) != 30 {
		t.Errorf("expected exactly 30 unbound binding fields, got %d: %v", len(report.UnboundFields), report.UnboundFields)
	}
	if report.PlanAttestationState != "UNATTESTED" {
		t.Errorf("plan attestation state %q, want UNATTESTED", report.PlanAttestationState)
	}
	for document, bindingStatus := range report.EnvironmentBindingStatus {
		if bindingStatus != "UNBOUND" {
			t.Errorf("%s binding_status %q, want UNBOUND", document, bindingStatus)
		}
	}
	if len(report.RuntimeSnapshotFields) != 5 {
		t.Errorf("expected exactly 5 runtime-snapshot fields, got %d: %v", len(report.RuntimeSnapshotFields), report.RuntimeSnapshotFields)
	}
	for _, field := range report.UnboundFields {
		if !strings.HasPrefix(field.Path, "host_identity.") && !strings.HasPrefix(field.Path, "tool_identities.") {
			t.Errorf("unbound field %q is outside host/tool identity: the only permitted pending class is host/tool binding", field.Path)
		}
		if field.Status != "OWNER_DECISION_PENDING" && field.Status != "NOT_MEASURED" {
			t.Errorf("unbound field %q has status %q, want OWNER_DECISION_PENDING or NOT_MEASURED", field.Path, field.Status)
		}
	}
}

func TestVerifyDetectsReRolledPairOrder(t *testing.T) {
	root := copyBenchmarkTree(t)
	mutatePlan(t, root, func(plan map[string]any) {
		workloads := plan["workloads"].([]any)
		first := workloads[0].(map[string]any)
		order := first["derived_pair_order"].([]any)
		if order[0] == "JAVA_FIRST" {
			order[0] = "RUST_FIRST"
		} else {
			order[0] = "JAVA_FIRST"
		}
	})
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.PlanFailures) == 0 {
		t.Fatal("a re-rolled derived_pair_order must be detected against the SHA-256 rule")
	}
	if !containsClass(report.BlockerClasses, BlockerPlanInconsistent) {
		t.Fatalf("expected %s, got %v", BlockerPlanInconsistent, report.BlockerClasses)
	}
}

func TestVerifyDetectsLoosenedThreshold(t *testing.T) {
	root := copyBenchmarkTree(t)
	mutatePlan(t, root, func(plan map[string]any) {
		thresholds := plan["ci_thresholds"].(map[string]any)
		thresholds["peak_rss"] = map[string]any{"bound": "upper", "value": 0.95}
	})
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SchemaFailures) == 0 {
		t.Fatal("the schema consts must reject a loosened threshold")
	}
	if len(report.PlanFailures) == 0 {
		t.Fatal("the spec cross-check must reject a loosened threshold")
	}
}

func TestVerifyRejectsResultsSmuggledIntoPlan(t *testing.T) {
	root := copyBenchmarkTree(t)
	mutatePlan(t, root, func(plan map[string]any) {
		plan["results"] = map[string]any{"wl-01-handshake-close": map[string]any{"cpu_time": 0.93}}
	})
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SchemaFailures) == 0 {
		t.Fatal("the schema must reject a results field added to the plan")
	}
	if !containsClass(report.BlockerClasses, BlockerSchemaInvalid) {
		t.Fatalf("expected %s, got %v", BlockerSchemaInvalid, report.BlockerClasses)
	}
}

func TestVerifyRejectsValueSmuggledIntoPendingField(t *testing.T) {
	root := copyBenchmarkTree(t)
	path := filepath.Join(root, "benchmarks", "environments", "confirmation.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var environment map[string]any
	if err := json.Unmarshal(content, &environment); err != nil {
		t.Fatal(err)
	}
	host := environment["host_identity"].(map[string]any)
	instance := host["instance_type"].(map[string]any)
	instance["value"] = "c5n.metal"
	writeJSON(t, path, environment)
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SchemaFailures) == 0 {
		t.Fatal("an OWNER_DECISION_PENDING field carrying a value must fail schema validation")
	}
}

func TestFixturesConformToRawSampleSchema(t *testing.T) {
	conforming := []string{"synthetic-valid.json", "synthetic-underpowered.json", "synthetic-reordered.json", "synthetic-run-validity-violation.json"}
	for _, name := range conforming {
		failures, err := ValidateSampleSetDocument(repoRoot, "internal/benchplan/testdata/"+name)
		if err != nil {
			t.Fatal(err)
		}
		if len(failures) > 0 {
			t.Errorf("%s must conform to the raw-sample schema, got: %v", name, failures)
		}
	}
	// The nonfinite and missing-pair fixtures are schema-invalid by
	// design: the canonical schema itself rejects nonpositive values
	// and wrong pair counts (defense in depth above the engine).
	for _, name := range []string{"synthetic-nonfinite.json", "synthetic-missing-pair.json"} {
		failures, err := ValidateSampleSetDocument(repoRoot, "internal/benchplan/testdata/"+name)
		if err != nil {
			t.Fatal(err)
		}
		if len(failures) == 0 {
			t.Errorf("%s must be rejected by the raw-sample schema", name)
		}
	}
}

// bindAllPendingFields rewrites every OWNER_DECISION_PENDING and
// NOT_MEASURED required binding field in both environment documents to
// a BOUND record with an obviously-synthetic test value (review fix I5
// scenarios). It does NOT touch binding_status or attestation_state.
func bindAllPendingFields(t *testing.T, root string) {
	t.Helper()
	for _, name := range []string{"primary-macos.json", "confirmation.json"} {
		path := filepath.Join(root, "benchmarks", "environments", name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var environment map[string]any
		if err := json.Unmarshal(content, &environment); err != nil {
			t.Fatal(err)
		}
		required := environment["required_binding_fields"].([]any)
		for _, entry := range required {
			parts := strings.SplitN(entry.(string), ".", 2)
			section := environment[parts[0]].(map[string]any)
			record := section[parts[1]].(map[string]any)
			status := record["status"].(string)
			if status != "OWNER_DECISION_PENDING" && status != "NOT_MEASURED" {
				continue
			}
			record["status"] = "BOUND"
			if parts[1] == "observed_architecture" {
				record["value"] = "x86_64"
			} else {
				record["value"] = "bound-for-test-scenario-not-a-real-identity"
			}
		}
		writeJSON(t, path, environment)
	}
}

func setBindingStatuses(t *testing.T, root, environmentStatus, attestationState string) {
	t.Helper()
	for _, name := range []string{"primary-macos.json", "confirmation.json"} {
		path := filepath.Join(root, "benchmarks", "environments", name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var environment map[string]any
		if err := json.Unmarshal(content, &environment); err != nil {
			t.Fatal(err)
		}
		environment["binding_status"] = environmentStatus
		writeJSON(t, path, environment)
	}
	mutatePlan(t, root, func(plan map[string]any) {
		plan["attestation_state"] = attestationState
		if attestationState == "INDEPENDENTLY_ATTESTED" {
			plan["status"] = "PREREGISTERED_INDEPENDENTLY_ATTESTED - test scenario: every field bound and the plan attested (synthetic verification-path exercise, not a real attestation)"
		}
	})
}

// Review fix I5, negative direction: syntactic completeness with
// UNBOUND/UNATTESTED status must NOT read as fully bound.
func TestVerifySyntacticCompletenessWithUnboundStatusIsStillPending(t *testing.T) {
	root := copyBenchmarkTree(t)
	bindAllPendingFields(t, root)
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SchemaFailures) > 0 || len(report.PlanFailures) > 0 {
		t.Fatalf("bound-field scenario must stay schema/spec clean, got %v / %v", report.SchemaFailures, report.PlanFailures)
	}
	if len(report.UnboundFields) != 0 {
		t.Fatalf("every field was bound, yet %d remain: %v", len(report.UnboundFields), report.UnboundFields)
	}
	if report.FullyBound() {
		t.Fatal("UNBOUND binding_status and UNATTESTED plan must never verify as fully bound")
	}
	if !report.HostBindingIsOnlyBlocker() {
		t.Fatalf("expected HOST_BINDING_PENDING (attestation pending), got %v", report.BlockerClasses)
	}
}

// Review fix I5, positive direction: with every field bound, both
// environments BOUND, and the plan attested, verification reports fully
// bound.
func TestVerifyFullyBoundAndAttestedTreeVerifies(t *testing.T) {
	root := copyBenchmarkTree(t)
	bindAllPendingFields(t, root)
	setBindingStatuses(t, root, "BOUND", "INDEPENDENTLY_ATTESTED")
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SchemaFailures) > 0 || len(report.PlanFailures) > 0 {
		t.Fatalf("fully bound scenario must be schema/spec clean, got %v / %v", report.SchemaFailures, report.PlanFailures)
	}
	if !report.FullyBound() {
		t.Fatalf("expected fully bound, got blockers %v", report.BlockerClasses)
	}
}

// A document claiming BOUND while its fields are still pending is an
// inconsistency, never progress.
func TestVerifyBoundStatusWithPendingFieldsIsInconsistent(t *testing.T) {
	root := copyBenchmarkTree(t)
	setBindingStatuses(t, root, "BOUND", "INDEPENDENTLY_ATTESTED")
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.PlanFailures) == 0 {
		t.Fatal("binding_status BOUND with pending fields must be reported as inconsistent")
	}
	if report.FullyBound() {
		t.Fatal("an inconsistent tree must never verify as fully bound")
	}
	if !containsClass(report.BlockerClasses, BlockerPlanInconsistent) {
		t.Fatalf("expected %s, got %v", BlockerPlanInconsistent, report.BlockerClasses)
	}
}

func TestVerifyDetectsMaskSpecDrift(t *testing.T) {
	root := copyBenchmarkTree(t)
	mutatePlan(t, root, func(plan map[string]any) {
		shared := plan["shared_definitions"].(map[string]any)
		shared["mask_spec_version"] = "vjwp-us008-mask|v2"
	})
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SchemaFailures) == 0 {
		t.Fatal("the schema const must reject a re-versioned mask spec")
	}
	if len(report.PlanFailures) == 0 {
		t.Fatal("the spec cross-check must reject a re-versioned mask spec")
	}
}

func TestVerifyDetectsDriftProcedureMutation(t *testing.T) {
	root := copyBenchmarkTree(t)
	mutatePlan(t, root, func(plan map[string]any) {
		statistics := plan["statistics"].(map[string]any)
		procedure := statistics["reference_drift_procedure"].(map[string]any)
		procedure["envelope_percent"] = 10
	})
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SchemaFailures) == 0 {
		t.Fatal("the schema const must reject a widened drift envelope")
	}
	if len(report.PlanFailures) == 0 {
		t.Fatal("the spec cross-check must reject a widened drift envelope")
	}
}

func containsClass(classes []string, class string) bool {
	for _, candidate := range classes {
		if candidate == class {
			return true
		}
	}
	return false
}

// copyBenchmarkTree copies benchmarks/ and schemas/ into a temp root so
// mutation tests never touch the real preregistration.
func copyBenchmarkTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"benchmarks", "schemas"} {
		source := filepath.Join(repoRoot, directory)
		err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			target := filepath.Join(root, directory, relative)
			if entry.IsDir() {
				return os.MkdirAll(target, 0o755)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, content, 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func mutatePlan(t *testing.T, root string, mutate func(map[string]any)) {
	t.Helper()
	path := filepath.Join(root, "benchmarks", "plan", "workloads.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(content, &plan); err != nil {
		t.Fatal(err)
	}
	mutate(plan)
	writeJSON(t, path, plan)
}

func writeJSON(t *testing.T, path string, document any) {
	t.Helper()
	content, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}
