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
	// 19 of the 23 confirmation fields; the owner's Tier-1 decision of
	// 2026-08-26 bound instance_type / region / ami_id / ami_name, and
	// everything else (including instance_id / observed_architecture /
	// allocation_evidence and all 8 tools) stays honestly pending. 5
	// runtime-snapshot fields on primary.
	if len(report.UnboundFields) != 26 {
		t.Errorf("expected exactly 26 unbound binding fields, got %d: %v", len(report.UnboundFields), report.UnboundFields)
	}
	tier1Bound := map[string]bool{
		"host_identity.instance_type": true,
		"host_identity.region":        true,
		"host_identity.ami_id":        true,
		"host_identity.ami_name":      true,
	}
	for _, field := range report.UnboundFields {
		if strings.Contains(field.Document, "confirmation") && tier1Bound[field.Path] {
			t.Errorf("field %q is owner-bound (Tier-1 decision 2026-08-26) and must not report as unbound", field.Path)
		}
	}
	if report.PlanAttestationState != "UNATTESTED" {
		t.Errorf("plan attestation state %q, want UNATTESTED", report.PlanAttestationState)
	}
	if len(report.MeterFailures) != 0 {
		t.Errorf("canonical tree must have zero meter failures, got %v", report.MeterFailures)
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

// TestConfirmationDocumentRecordsOwnerTier1Binding pins the owner's
// Tier-1 confirmation-host decision of 2026-08-26 (decision record:
// workspace protected root us008-owner-pinning-tier1.json) exactly as
// recorded, and guards that nothing pending was silently promoted:
// booted-host facts stay NOT_MEASURED sentinels, open owner decisions
// stay OWNER_DECISION_PENDING, and Tier-2 is explicitly deferred.
func TestConfirmationDocumentRecordsOwnerTier1Binding(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "benchmarks", "environments", "confirmation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var environment map[string]any
	if err := json.Unmarshal(raw, &environment); err != nil {
		t.Fatal(err)
	}
	if environment["binding_status"] != "UNBOUND" {
		t.Errorf("binding_status %v, want UNBOUND: a partial Tier-1 binding must never claim document-level BOUND", environment["binding_status"])
	}
	host := environment["host_identity"].(map[string]any)
	tools := environment["tool_identities"].(map[string]any)

	record := func(section map[string]any, name string) map[string]any {
		t.Helper()
		value, present := section[name]
		if !present {
			t.Fatalf("field record %q is missing", name)
		}
		return value.(map[string]any)
	}
	expectBound := func(section map[string]any, name, want string) {
		t.Helper()
		field := record(section, name)
		if field["status"] != "BOUND" {
			t.Errorf("%s status %v, want BOUND", name, field["status"])
		}
		if field["value"] != want {
			t.Errorf("%s value %v, want %q", name, field["value"], want)
		}
	}
	expectPending := func(section map[string]any, name, wantStatus string) {
		t.Helper()
		field := record(section, name)
		if field["status"] != wantStatus {
			t.Errorf("%s status %v, want %s", name, field["status"], wantStatus)
		}
		if _, smuggled := field["value"]; smuggled {
			t.Errorf("%s is %s and must not carry a value", name, wantStatus)
		}
	}

	// The four owner-bound Tier-1 identities, exactly as decided.
	expectBound(host, "instance_type", "c7i.xlarge")
	expectBound(host, "region", "us-east-1")
	expectBound(host, "ami_id", "ami-02b3d83d84b07786d")
	expectBound(host, "ami_name", "al2023-ami-2023.12.20260817.0-kernel-6.1-x86_64")

	// Booted-host facts stay NOT_MEASURED until the bound host boots.
	for _, name := range []string{"instance_id", "observed_architecture", "availability_zone", "os_identity", "kernel_identity", "cpu_model", "memory_total_bytes", "numa_topology", "clocksource"} {
		expectPending(host, name, "NOT_MEASURED")
	}
	// Open owner decisions stay pending.
	expectPending(host, "allocation_evidence", "OWNER_DECISION_PENDING")
	expectPending(host, "cpu_frequency_policy", "OWNER_DECISION_PENDING")
	for _, name := range []string{"java_runtime", "rust_toolchain", "load_driver", "measurement_tools", "analyzer", "runner"} {
		expectPending(tools, name, "OWNER_DECISION_PENDING")
	}
	// No executables exist to digest; the sentinels stay.
	expectPending(tools, "java_executable_digest", "NOT_MEASURED")
	expectPending(tools, "rust_executable_digest", "NOT_MEASURED")

	// Pipeline tool identities recorded by the same owner decision.
	for _, name := range []string{"terraform", "go_toolchain", "runner_build_flags", "yq"} {
		field := record(tools, name)
		if field["status"] != "BOUND" {
			t.Errorf("tool_identities.%s status %v, want BOUND", name, field["status"])
		}
		if value, _ := field["value"].(string); value == "" {
			t.Errorf("tool_identities.%s must carry a non-empty value", name)
		}
	}
	// The Go record carries both the resolved toolchain and the go.mod
	// directive (owner decision: record the resolved version alongside
	// the directive).
	goValue, _ := record(tools, "go_toolchain")["value"].(string)
	if !strings.Contains(goValue, "go1.25") || !strings.Contains(goValue, "go 1.25") {
		t.Errorf("go_toolchain value %q must record the resolved go1.25.x toolchain alongside the go.mod 'go 1.25' directive", goValue)
	}

	// Tier-2 deferral and the decision-record provenance are explicit.
	if !strings.Contains(string(raw), "DEFERRED_BY_OWNER") {
		t.Error("the document must record Tier-2 (METAL_MEASURED) as explicitly DEFERRED_BY_OWNER")
	}
	provenance := environment["provenance"].(map[string]any)
	rationale, _ := provenance["rationale"].(string)
	if !strings.Contains(rationale, "us008-owner-pinning-tier1.json") {
		t.Error("provenance.rationale must reference the owner decision record us008-owner-pinning-tier1.json")
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
	// instance_type is legitimately BOUND since the owner's Tier-1
	// decision of 2026-08-26; instance_id remains a NOT_MEASURED
	// sentinel, so it is the smuggling target.
	instance := host["instance_id"].(map[string]any)
	instance["value"] = "i-0fabricated0000000"
	writeJSON(t, path, environment)
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SchemaFailures) == 0 {
		t.Fatal("a NOT_MEASURED field carrying a value must fail schema validation")
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

func mutateEnvironment(t *testing.T, root, name string, mutate func(map[string]any)) {
	t.Helper()
	path := filepath.Join(root, "benchmarks", "environments", name)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var environment map[string]any
	if err := json.Unmarshal(content, &environment); err != nil {
		t.Fatal(err)
	}
	mutate(environment)
	writeJSON(t, path, environment)
}

// BLOCKING review fix round 2: a document that shrinks its own
// required_binding_fields list must be caught against the canonical
// list — the meter is code+schema truth, not document truth.
func TestVerifyShrunkenMeterIsMeterTampered(t *testing.T) {
	root := copyBenchmarkTree(t)
	mutateEnvironment(t, root, "confirmation.json", func(environment map[string]any) {
		environment["required_binding_fields"] = []any{"host_identity.instance_type"}
		environment["binding_status"] = "BOUND"
	})
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.MeterFailures) == 0 {
		t.Fatal("a shrunken required_binding_fields list must be METER_TAMPERED")
	}
	if !containsClass(report.BlockerClasses, BlockerMeterTampered) {
		t.Fatalf("expected %s, got %v", BlockerMeterTampered, report.BlockerClasses)
	}
	if len(report.SchemaFailures) == 0 {
		t.Fatal("the per-role schema const must also reject the shrunken list")
	}
	if report.FullyBound() {
		t.Fatal("a tampered meter must never verify as fully bound")
	}
	// The canonical meter still counts every genuinely pending
	// confirmation field as unbound, regardless of what the document
	// declares: 19 of 23 remain pending after the owner's Tier-1
	// decision bound instance_type / region / ami_id / ami_name.
	confirmationUnbound := 0
	for _, field := range report.UnboundFields {
		if strings.Contains(field.Document, "confirmation") {
			confirmationUnbound++
		}
	}
	if confirmationUnbound != 19 {
		t.Fatalf("canonical meter must still count 19 unbound confirmation fields, got %d", confirmationUnbound)
	}
}

func TestVerifyWrongRoleForFilenameIsMeterTampered(t *testing.T) {
	root := copyBenchmarkTree(t)
	mutateEnvironment(t, root, "confirmation.json", func(environment map[string]any) {
		environment["role"] = "primary"
	})
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if !containsClass(report.BlockerClasses, BlockerMeterTampered) {
		t.Fatalf("confirmation.json declaring role primary must be %s, got %v", BlockerMeterTampered, report.BlockerClasses)
	}
	found := false
	for _, failure := range report.MeterFailures {
		if strings.Contains(failure, "filename contract") {
			found = true
		}
	}
	if !found {
		t.Fatalf("meter failures must name the filename-to-role contract, got %v", report.MeterFailures)
	}
}

func TestVerifyRemovedCanonicalFieldRecordIsMeterTampered(t *testing.T) {
	root := copyBenchmarkTree(t)
	mutateEnvironment(t, root, "confirmation.json", func(environment map[string]any) {
		host := environment["host_identity"].(map[string]any)
		delete(host, "allocation_evidence")
	})
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if !containsClass(report.BlockerClasses, BlockerMeterTampered) {
		t.Fatalf("a removed canonical field record must be %s, got %v", BlockerMeterTampered, report.BlockerClasses)
	}
	// Note: required_binding_fields still lists it, so the document list
	// itself matches canon; the record-existence walk catches the hole.
	found := false
	for _, failure := range report.MeterFailures {
		if strings.Contains(failure, "allocation_evidence") && strings.Contains(failure, "no field record") {
			found = true
		}
	}
	if !found {
		t.Fatalf("meter failures must name the missing record, got %v", report.MeterFailures)
	}
}

func TestCanonicalBindingFieldListsAreTheFrozenShapes(t *testing.T) {
	if len(CanonicalBindingFields["primary"]) != 20 {
		t.Errorf("canonical primary list has %d entries, want 20", len(CanonicalBindingFields["primary"]))
	}
	if len(CanonicalBindingFields["confirmation"]) != 23 {
		t.Errorf("canonical confirmation list has %d entries, want 23", len(CanonicalBindingFields["confirmation"]))
	}
	if EnvironmentRoleByDocument["benchmarks/environments/primary-macos.json"] != "primary" ||
		EnvironmentRoleByDocument["benchmarks/environments/confirmation.json"] != "confirmation" {
		t.Error("filename-to-role contract must map primary-macos.json to primary and confirmation.json to confirmation")
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
