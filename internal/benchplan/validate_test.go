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
	// all 20 confirmation fields; 5 runtime-snapshot fields on primary.
	if len(report.UnboundFields) != 27 {
		t.Errorf("expected exactly 27 unbound binding fields, got %d: %v", len(report.UnboundFields), report.UnboundFields)
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
	conforming := []string{"synthetic-valid.json", "synthetic-underpowered.json", "synthetic-reordered.json"}
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
