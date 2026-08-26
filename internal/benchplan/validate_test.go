package benchplan

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const repoRoot = "../.."

// The exact recorded pipeline tool identities of the owner's Tier-1
// decision (2026-08-26). Review round 1 (session 01a03f9c, BLOCKING-2/3):
// every BOUND tool value is regression-pinned by FULL equality here, and
// cross-checked against the pipeline source files it describes, so silent
// drift in either the document or the pipeline can never stay green.
const (
	pinnedTerraformVersion = "1.9.8"
	pinnedGoToolchain      = "go1.25.5 (go.mod directive 'go 1.25.5')"
	pinnedRunnerBuildFlags = "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/benchrunner ./cmd/benchrunner"
	pinnedYqVersion        = "4.44.3"
)

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
	if report.PlanFreezeState != PlanFreezeOwnerAttested {
		t.Errorf("plan freeze state %q, want %s", report.PlanFreezeState, PlanFreezeOwnerAttested)
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

	// Pipeline tool identities recorded by the same owner decision,
	// pinned by FULL equality (review round 1 BLOCKING-2: a substring or
	// non-empty check lets a drifted recorded value stay green).
	expectBound(tools, "terraform", pinnedTerraformVersion)
	expectBound(tools, "go_toolchain", pinnedGoToolchain)
	expectBound(tools, "runner_build_flags", pinnedRunnerBuildFlags)
	expectBound(tools, "yq", pinnedYqVersion)

	// Tier-2 deferral and the decision-record provenance are explicit.
	if !strings.Contains(string(raw), "DEFERRED_BY_OWNER") {
		t.Error("the document must record Tier-2 (METAL_MEASURED) as explicitly DEFERRED_BY_OWNER")
	}
	provenance := environment["provenance"].(map[string]any)
	rationale, _ := provenance["rationale"].(string)
	if !strings.Contains(rationale, "us008-owner-pinning-tier1.json") {
		t.Error("provenance.rationale must reference the owner decision record us008-owner-pinning-tier1.json")
	}
	// Review round 1 finding 1: the original decision record's decided_at
	// was a too-late estimate; the authoritative chronology lives in the
	// timestamp-correction sidecar, and the provenance must cite BOTH.
	if !strings.Contains(rationale, "us008-owner-pinning-tier1-timestamp-correction.json") {
		t.Error("provenance.rationale must reference the timestamp-correction sidecar us008-owner-pinning-tier1-timestamp-correction.json alongside the original decision record")
	}
}

// TestBoundPipelineToolClaimsMatchPipelineSources guards each BOUND
// pipeline-tool claim in confirmation.json against the pipeline file it
// describes (review round 1 BLOCKING-3): the recorded runner build
// command must appear verbatim in .github/workflows/benchmark.yml, and
// the dialed-setup composite action must pin the recorded Terraform
// version and ENFORCE the recorded yq version (install-exact on
// mismatch, fail if the pinned version does not resolve) rather than
// silently accepting whatever yq is preinstalled.
func TestBoundPipelineToolClaimsMatchPipelineSources(t *testing.T) {
	workflowRaw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "benchmark.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(workflowRaw), pinnedRunnerBuildFlags) {
		t.Errorf("benchmark.yml no longer contains the recorded runner build literal %q; the confirmation.json runner_build_flags claim would be false", pinnedRunnerBuildFlags)
	}

	actionRaw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "actions", "dialed-setup", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	action := string(actionRaw)
	if !strings.Contains(action, "terraform_version: \""+pinnedTerraformVersion+"\"") {
		t.Errorf("dialed-setup action.yml no longer enforces terraform_version %q", pinnedTerraformVersion)
	}
	if !strings.Contains(action, "yq_pin=\""+pinnedYqVersion+"\"") {
		t.Errorf("dialed-setup action.yml no longer pins yq_pin=%q", pinnedYqVersion)
	}
	if !strings.Contains(action, "refusing to run with an unpinned yq") {
		t.Error("dialed-setup action.yml must fail closed when the pinned yq version does not resolve (enforcement, not a best-effort download)")
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

func TestVerifyDetectsEveryFrozenWorkloadFieldFamilyMutation(t *testing.T) {
	tests := []struct {
		name     string
		workload int
		field    string
		mutation any
	}{
		{"definition", 0, "definition", "mutated generator definition"},
		{"rate", 0, "rate", float64(999999)},
		{"concurrency", 1, "concurrency", float64(999999)},
		{"operations", 2, "operations", float64(999999)},
		{"nominal duration", 3, "nominal_duration_seconds", float64(999999)},
		{"hard timeout", 4, "hard_timeout_seconds", float64(999999)},
		{"inputs", 5, "inputs", "mutated input generator"},
		{"outputs", 0, "outputs", "mutated output oracle"},
		{"server configuration", 4, "server_configuration", "mutated cap"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := copyBenchmarkTree(t)
			mutatePlan(t, root, func(plan map[string]any) {
				workload := plan["workloads"].([]any)[testCase.workload].(map[string]any)
				if testCase.field == "definition" {
					workload["definition"] = testCase.mutation
					return
				}
				parameters := workload["fixed_parameters"].(map[string]any)
				record := parameters[testCase.field].(map[string]any)
				if _, present := record["value"]; present {
					record["value"] = testCase.mutation
				} else {
					record["definition"] = testCase.mutation
				}
			})
			report, err := Verify(root)
			if err != nil {
				t.Fatal(err)
			}
			if !containsClass(report.BlockerClasses, BlockerPlanInconsistent) || !strings.Contains(strings.Join(report.PlanFailures, "\n"), "canonical projection digest") {
				t.Fatalf("mutation was not caught by full workload projection: failures=%v blockers=%v", report.PlanFailures, report.BlockerClasses)
			}
		})
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

func TestSemanticBindingMeterRejectsPlaceholderBoundIdentities(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value any
	}{
		{"wrong instance class", "instance_type", "c7i.large"},
		{"placeholder instance id", "instance_id", "i-placeholder"},
		{"wrong architecture", "observed_architecture", "arm64"},
		{"zero memory", "memory_total_bytes", float64(0)},
		{"placeholder clocksource", "clocksource", "not a clock"},
		{"tool without provenance digest", "runner", "runner-v1"},
		{"tool on wrong role platform", "runner", map[string]any{"kind": "runner", "identity": "runner 1.0.0 aarch64-apple-darwin", "platform": "aarch64-apple-darwin", "digest": syntheticDigest("runner-wrong-platform"), "provenance": "unit-test receipt fixture"}},
		{"zero executable digest", "java_executable_digest", "sha256:" + strings.Repeat("0", 64)},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := copyBenchmarkTree(t)
			mutateEnvironment(t, root, "confirmation.json", func(environment map[string]any) {
				sectionName := "host_identity"
				if testCase.field == "runner" || testCase.field == "java_executable_digest" {
					sectionName = "tool_identities"
				}
				record := environment[sectionName].(map[string]any)[testCase.field].(map[string]any)
				record["status"] = "BOUND"
				record["value"] = testCase.value
				attachTestReceipt(t, root, environment, sectionName+"."+testCase.field, record, nil)
			})
			report, err := verify(root, true)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.MeterFailures) == 0 || !containsClass(report.BlockerClasses, BlockerMeterTampered) {
				t.Fatalf("placeholder BOUND identity passed semantic meter: failures=%v blockers=%v", report.MeterFailures, report.BlockerClasses)
			}
		})
	}
}

func TestSemanticBindingReceiptRejectsHostileEvidence(t *testing.T) {
	tests := []struct {
		name          string
		field         string
		value         any
		receiptMutate func(map[string]any)
		recordMutate  func(*testing.T, string, map[string]any)
		missing       bool
	}{
		{name: "missing", field: "instance_id", value: "i-0123456789abcdef0", missing: true},
		{name: "wrong role", field: "instance_id", value: "i-0123456789abcdef0", receiptMutate: func(receipt map[string]any) {
			receipt["environment"].(map[string]any)["role"] = "primary"
		}},
		{name: "wrong value", field: "instance_id", value: "i-0123456789abcdef0", receiptMutate: func(receipt map[string]any) {
			receipt["field"].(map[string]any)["value"] = "i-0fedcba9876543210"
		}},
		{name: "wrong environment", field: "instance_id", value: "i-0123456789abcdef0", receiptMutate: func(receipt map[string]any) {
			receipt["environment"].(map[string]any)["id"] = "primary-macos"
		}},
		{name: "wrong evidence type", field: "instance_id", value: "i-0123456789abcdef0", receiptMutate: func(receipt map[string]any) {
			receipt["evidence_type"] = "TOOL_PROVENANCE"
			receipt["source"].(map[string]any)["kind"] = "TOOL_PROVENANCE"
		}},
		{name: "wrong digest", field: "instance_id", value: "i-0123456789abcdef0", recordMutate: func(t *testing.T, _ string, record map[string]any) {
			digest := syntheticDigest("wrong-receipt-digest")
			record["evidence_digest"] = digest
			record["evidence_receipt"].(map[string]any)["digest"] = digest
		}},
		{name: "path substitution", field: "instance_id", value: "i-0123456789abcdef0", recordMutate: func(t *testing.T, root string, record map[string]any) {
			reference := record["evidence_receipt"].(map[string]any)
			canonical := reference["path"].(string)
			content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(canonical)))
			if err != nil {
				t.Fatal(err)
			}
			substitute := "benchmarks/evidence/receipts/confirmation/host_identity.instance_id_substitute.json"
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(substitute)), content, 0o644); err != nil {
				t.Fatal(err)
			}
			reference["path"] = substitute
		}},
		{name: "placeholder", field: "os_identity", value: "placeholder host identity"},
		{name: "unknown receipt property", field: "instance_id", value: "i-0123456789abcdef0", receiptMutate: func(receipt map[string]any) {
			receipt["unexpected"] = true
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := copyBenchmarkTree(t)
			mutateEnvironment(t, root, "confirmation.json", func(environment map[string]any) {
				record := environment["host_identity"].(map[string]any)[testCase.field].(map[string]any)
				record["status"] = "BOUND"
				record["value"] = testCase.value
				if testCase.missing {
					record["evidence_digest"] = syntheticDigest("unattached-digest")
				} else {
					attachTestReceipt(t, root, environment, "host_identity."+testCase.field, record, testCase.receiptMutate)
				}
				if testCase.recordMutate != nil {
					testCase.recordMutate(t, root, record)
				}
			})
			report, err := verify(root, true)
			if err != nil {
				t.Fatal(err)
			}
			if report.FullyBound() || len(report.MeterFailures) == 0 || !containsClass(report.BlockerClasses, BlockerMeterTampered) {
				t.Fatalf("hostile receipt passed: failures=%v blockers=%v", report.MeterFailures, report.BlockerClasses)
			}
		})
	}
}

func TestSemanticBindingReceiptCoversSupplementalBoundTools(t *testing.T) {
	root := copyBenchmarkTree(t)
	mutateEnvironment(t, root, "confirmation.json", func(environment map[string]any) {
		terraform := environment["tool_identities"].(map[string]any)["terraform"].(map[string]any)
		delete(terraform, "evidence_receipt")
	})
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.MeterFailures) == 0 || !containsClass(report.BlockerClasses, BlockerMeterTampered) {
		t.Fatalf("a supplemental BOUND tool without its receipt escaped the meter: failures=%v blockers=%v", report.MeterFailures, report.BlockerClasses)
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
// a BOUND record backed by a structurally authentic TEST_ONLY receipt in
// the temporary root. It does NOT touch document-level binding_status.
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
			bindingPath := entry.(string)
			parts := strings.SplitN(bindingPath, ".", 2)
			section := environment[parts[0]].(map[string]any)
			record := section[parts[1]].(map[string]any)
			status := record["status"].(string)
			if status != "OWNER_DECISION_PENDING" && status != "NOT_MEASURED" {
				continue
			}
			record["status"] = "BOUND"
			record["value"] = testOnlyBoundValue(name, bindingPath)
			attachTestReceipt(t, root, environment, bindingPath, record, nil)
		}
		writeJSON(t, path, environment)
	}
}

func testOnlyBoundValue(document, path string) any {
	if strings.HasPrefix(path, "tool_identities.") {
		name := strings.TrimPrefix(path, "tool_identities.")
		if name == "java_executable_digest" || name == "rust_executable_digest" {
			return syntheticDigest(path)
		}
		architecture := "aarch64-apple-darwin"
		if document == "confirmation.json" {
			architecture = "x86_64-unknown-linux-gnu"
		}
		return map[string]any{
			"kind":       name,
			"identity":   name + " 1.0.0 " + architecture,
			"platform":   architecture,
			"digest":     syntheticDigest(path),
			"provenance": "unit-test receipt fixture generated in an isolated temporary root",
		}
	}
	switch path {
	case "host_identity.instance_id":
		return "i-0123456789abcdef0"
	case "host_identity.observed_architecture":
		return "x86_64"
	case "host_identity.allocation_evidence":
		return map[string]any{"method": "DescribeInstances tenancy plus job allocation record", "observed_value": "exclusive", "observed_at_utc": "2026-08-26T00:00:00Z"}
	case "host_identity.availability_zone":
		return "us-east-1a"
	case "host_identity.memory_total_bytes":
		return 8589934592
	case "host_identity.clocksource":
		return "tsc"
	case "host_identity.os_identity":
		return "Amazon Linux 2023.12.20260817"
	case "host_identity.kernel_identity":
		return "6.1.180-225.360.amzn2023.x86_64"
	case "host_identity.cpu_model":
		return "Intel Xeon Platinum 8488C"
	case "host_identity.cpu_frequency_policy":
		return "performance governor; turbo enabled; SMT enabled"
	case "host_identity.numa_topology":
		return "1 node; CPUs 0-3"
	default:
		return "recorded identity value"
	}
}

func attachTestReceipt(t *testing.T, root string, environment map[string]any, bindingPath string, record map[string]any, mutate func(map[string]any)) {
	t.Helper()
	role := environment["role"].(string)
	document := "benchmarks/environments/primary-macos.json"
	if role == "confirmation" {
		document = "benchmarks/environments/confirmation.json"
	}
	receipt := map[string]any{
		"schema":        bindingReceiptSchema,
		"evidence_type": "TEST_ONLY",
		"environment": map[string]any{
			"id":       environment["environment_id"],
			"role":     role,
			"document": document,
		},
		"field": map[string]any{
			"path":  bindingPath,
			"value": record["value"],
		},
		"captured_at": "2026-08-26T00:00:00Z",
		"source": map[string]any{
			"kind":    "TEST_FIXTURE",
			"locator": "inert unit-test receipt generated in an isolated temporary root",
			"digest":  syntheticDigest("receipt-source|" + role + "|" + bindingPath),
		},
	}
	if mutate != nil {
		mutate(receipt)
	}
	relative := fmt.Sprintf("benchmarks/evidence/receipts/%s/%s.json", role, bindingPath)
	absolute := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, absolute, receipt)
	content, err := os.ReadFile(absolute)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(content))
	record["evidence_digest"] = digest
	record["evidence_receipt"] = map[string]any{"path": relative, "digest": digest}
}

func setBindingStatuses(t *testing.T, root, environmentStatus string) {
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
}

// Review fix I5, negative direction: syntactic completeness with
// UNBOUND document status must NOT read as sample-ready even with a valid
// owner-attested freeze.
func TestVerifySyntacticCompletenessWithUnboundStatusIsStillPending(t *testing.T) {
	root := copyBenchmarkTree(t)
	bindAllPendingFields(t, root)
	report, err := verify(root, true)
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
		t.Fatal("UNBOUND binding_status must never verify as sample-ready")
	}
	if !report.HostBindingIsOnlyBlocker() {
		t.Fatalf("expected HOST_BINDING_PENDING (document binding status pending), got %v; meter failures: %v", report.BlockerClasses, report.MeterFailures)
	}
}

// Review fix I5, positive direction: with every field bound, both
// environments BOUND, the owner-attested plan verifies as sample-ready.
func TestVerifyFullyBoundOwnerAttestedTreeVerifies(t *testing.T) {
	root := copyBenchmarkTree(t)
	bindAllPendingFields(t, root)
	setBindingStatuses(t, root, "BOUND")
	productionReport, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if productionReport.FullyBound() || !containsClass(productionReport.BlockerClasses, BlockerMeterTampered) {
		t.Fatalf("production verification must reject TEST_ONLY receipts, got blockers %v", productionReport.BlockerClasses)
	}
	report, err := verify(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SchemaFailures) > 0 || len(report.PlanFailures) > 0 {
		t.Fatalf("fully bound scenario must be schema/spec clean, got %v / %v", report.SchemaFailures, report.PlanFailures)
	}
	if !report.FullyBound() {
		t.Fatalf("expected fully bound, got blockers %v; meter failures: %v", report.BlockerClasses, report.MeterFailures)
	}
}

func TestVerifyFullyBoundRejectsGenericValueAndUnattachedDigest(t *testing.T) {
	root := copyBenchmarkTree(t)
	bindAllPendingFields(t, root)
	setBindingStatuses(t, root, "BOUND")
	mutateEnvironment(t, root, "confirmation.json", func(environment map[string]any) {
		runner := environment["tool_identities"].(map[string]any)["runner"].(map[string]any)
		runner["value"] = "arbitrary runner string"
		runner["evidence_digest"] = syntheticDigest("unattached-runner")
		delete(runner, "evidence_receipt")
	})
	report, err := verify(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.FullyBound() || !containsClass(report.BlockerClasses, BlockerMeterTampered) {
		t.Fatalf("an arbitrary value plus unattached digest must not become FullyBound: blockers=%v failures=%v", report.BlockerClasses, report.MeterFailures)
	}
}

// A document claiming BOUND while its fields are still pending is an
// inconsistency, never progress.
func TestVerifyBoundStatusWithPendingFieldsIsInconsistent(t *testing.T) {
	root := copyBenchmarkTree(t)
	setBindingStatuses(t, root, "BOUND")
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
