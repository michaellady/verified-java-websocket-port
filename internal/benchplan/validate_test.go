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

// The exact recorded pipeline tool identities of the owner's Tier-1
// decision (2026-08-26). Review round 1 (session 01a03f9c, BLOCKING-2/3):
// every BOUND tool value is regression-pinned by FULL equality here, and
// cross-checked against the pipeline source files it describes, so silent
// drift in either the document or the pipeline can never stay green.
const (
	pinnedTerraformVersion = "1.9.8"
	pinnedGoToolchain      = "go1.25.5 (go.mod directive 'go 1.25')"
	pinnedRunnerBuildFlags = "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/benchrunner ./cmd/benchrunner"
	pinnedYqVersion        = "4.44.3"
)

// Round-2 owner decisions (2026-08-27, decision record
// us009-us008-owner-decisions-2026-08-27.json in the workspace protected
// root), regression-pinned by FULL equality per the round-1 standing rule.
//
// us008_cpu_frequency_policy = DOCUMENT_DEFAULTS_RECORD_OBSERVED binds the
// confirmation host's cpu_frequency_policy field exactly as decided.
//
// us008_allocation_evidence = BUILTIN_ACCOUNTING_PER_RUN decides the
// allocation-ACCOUNTING evidence method (JVM GC/NMT statistics; Rust
// counting allocator; recorded per run) — that is a measurement-tool
// method, recorded as the measurement_tools candidate in BOTH
// environments. It does NOT designate the host-tenancy observation
// procedure that confirmation.json's host_identity.allocation_evidence
// field requires (review fix B3: dedicated/exclusive tenancy
// observation): binding it with the accounting decision would have been
// a false binding under a name collision. The tenancy field stayed
// OWNER_DECISION_PENDING until the round-3 record below designated its
// own procedure.
const (
	pinnedCPUFrequencyPolicy = "DOCUMENT_DEFAULTS_RECORD_OBSERVED: no frequency tuning and no tuning claims — no governor, turbo, or SMT setting is mutated on the bound host; the booted host's default scaling facts (cpufreq driver and governor presence or absence, turbo/boost visibility, SMT state) are recorded at provision alongside the other booted-host facts, and the observed CPU clock is recorded per measured run"
	pinnedAllocationAccountingCandidate = "allocation samplers decided BUILTIN_ACCOUNTING_PER_RUN (owner decision 2026-08-27): Java allocation evidence from the JVM's own accounting (GC/NMT statistics), Rust from a counting allocator, both recorded per run; exact sampler identities and digests remain pending"
)

// Round-3 owner acts (2026-08-27, decision record
// us008-owner-attestation-2026-08-27.json in the workspace protected
// root, decided_at 2026-08-27T03:52:36Z captured from date -u),
// regression-pinned by FULL equality per the round-1 standing rule.
//
// us008_tenancy_allocation_evidence_procedure = STANDARD_CLOUD_CHECKS
// binds host_identity.allocation_evidence — the dedicated/exclusive
// TENANCY observation procedure of review fix B3 — resolving the
// round-2 name collision. It binds the PROCEDURE only: the per-run
// tenancy observations exist only when a measured run exists.
//
// us008_plan_attestation = ATTESTED_BY_OWNER freezes the plan as of its
// content at mainline 51257ac and is digest-bound to those exact bytes.
// The attestation is owner-only (OWNER_ATTESTED_NOT_INDEPENDENT,
// independent_review_claimed false): attestation_state becomes
// OWNER_ATTESTED, never INDEPENDENTLY_ATTESTED, and the exit-0
// full-binding gate stays unsatisfied.
const (
	pinnedTenancyProcedure      = "STANDARD_CLOUD_CHECKS: per-run DescribeInstances tenancy-attribute query + exact instance-type confirmation + a job-scoped exclusive-reservation record covering the run's duration"
	pinnedPlanContentSHA256     = "5fb3fea8b5f1213b7ae5039ce7574c23bf720f543b0bd8c568abe596eef86993"
	pinnedFrozenPlanCommit      = "51257acfd7e645f671b346e6b103819497a34f4c"
	pinnedAttestationRecordPath = "/Users/mikelady/hq/workspace/orchestrator/verified-java-websocket-port-claude/protected/us008-owner-attestation-2026-08-27.json"
	pinnedAttestedAt            = "2026-08-27T03:52:36Z"
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
	// 17 of the 23 confirmation fields; the owner's Tier-1 decision of
	// 2026-08-26 bound instance_type / region / ami_id / ami_name, the
	// round-2 decision of 2026-08-27 bound cpu_frequency_policy, the
	// round-3 decision of 2026-08-27 bound allocation_evidence (the
	// tenancy procedure), and everything else (including instance_id /
	// observed_architecture and all 8 tools) stays honestly pending. 5
	// runtime-snapshot fields on primary.
	if len(report.UnboundFields) != 24 {
		t.Errorf("expected exactly 24 unbound binding fields, got %d: %v", len(report.UnboundFields), report.UnboundFields)
	}
	ownerBound := map[string]bool{
		"host_identity.instance_type":        true,
		"host_identity.region":               true,
		"host_identity.ami_id":               true,
		"host_identity.ami_name":             true,
		"host_identity.cpu_frequency_policy": true,
		"host_identity.allocation_evidence":  true,
	}
	for _, field := range report.UnboundFields {
		if strings.Contains(field.Document, "confirmation") && ownerBound[field.Path] {
			t.Errorf("field %q is owner-bound (Tier-1 decision 2026-08-26 / round-2 and round-3 decisions 2026-08-27) and must not report as unbound", field.Path)
		}
	}
	// The owner's round-3 attestation is OWNER-ONLY: the state must be
	// OWNER_ATTESTED, never promoted to INDEPENDENTLY_ATTESTED (no
	// independent attestor exists and none is claimed).
	if report.PlanAttestationState != "OWNER_ATTESTED" {
		t.Errorf("plan attestation state %q, want OWNER_ATTESTED", report.PlanAttestationState)
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
	// The round-2 owner decision of 2026-08-27 binds the CPU-frequency
	// POLICY (document defaults, record observed; never tune), pinned by
	// full equality like every other bound value.
	expectBound(host, "cpu_frequency_policy", pinnedCPUFrequencyPolicy)
	// The round-3 owner decision of 2026-08-27 binds the dedicated/
	// exclusive TENANCY observation PROCEDURE (review fix B3), pinned by
	// full equality; the per-run observations stay honestly pending.
	expectBound(host, "allocation_evidence", pinnedTenancyProcedure)

	// Booted-host facts stay NOT_MEASURED until the bound host boots.
	for _, name := range []string{"instance_id", "observed_architecture", "availability_zone", "os_identity", "kernel_identity", "cpu_model", "memory_total_bytes", "numa_topology", "clocksource"} {
		expectPending(host, name, "NOT_MEASURED")
	}
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
	// Round 2 (2026-08-27): the provenance must also cite the round-2
	// owner decision record that bound cpu_frequency_policy and decided
	// the allocation-accounting method.
	if !strings.Contains(rationale, "us009-us008-owner-decisions-2026-08-27.json") {
		t.Error("provenance.rationale must reference the round-2 owner decision record us009-us008-owner-decisions-2026-08-27.json")
	}
	// Round 3 (2026-08-27): the provenance must also cite the round-3
	// owner decision record that bound the tenancy observation procedure
	// and attested the plan.
	if !strings.Contains(rationale, "us008-owner-attestation-2026-08-27.json") {
		t.Error("provenance.rationale must reference the round-3 owner decision record us008-owner-attestation-2026-08-27.json")
	}
}

// TestRound2OwnerDecisionsRecordedHonestly pins the round-2 owner
// decisions of 2026-08-27 exactly where they genuinely land, and guards
// against the name-collision false binding:
//
//   - us008_cpu_frequency_policy binds host_identity.cpu_frequency_policy
//     (verified by full equality in the Tier-1 test above and cited to
//     the decision record here);
//   - us008_allocation_evidence (BUILTIN_ACCOUNTING_PER_RUN — JVM GC/NMT
//     statistics; Rust counting allocator; recorded per run) is an
//     allocation-ACCOUNTING method: it is recorded as the
//     measurement_tools candidate in BOTH environments (still
//     OWNER_DECISION_PENDING — exact sampler identities and digests are
//     undecided), and host_identity.allocation_evidence — the
//     dedicated/exclusive TENANCY observation procedure of review fix
//     B3 — was NEVER bound by it. That field is now BOUND, but only by
//     the round-3 record's own tenancy designation
//     (us008_tenancy_allocation_evidence_procedure =
//     STANDARD_CLOUD_CHECKS): its bound value must be the tenancy
//     procedure, never the accounting method, and its notes must keep
//     the collision's resolution on the record.
func TestRound2OwnerDecisionsRecordedHonestly(t *testing.T) {
	loadEnvironment := func(name string) map[string]any {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(repoRoot, "benchmarks", "environments", name))
		if err != nil {
			t.Fatal(err)
		}
		var environment map[string]any
		if err := json.Unmarshal(raw, &environment); err != nil {
			t.Fatal(err)
		}
		return environment
	}

	confirmation := loadEnvironment("confirmation.json")
	host := confirmation["host_identity"].(map[string]any)

	frequency := host["cpu_frequency_policy"].(map[string]any)
	if frequency["status"] != "BOUND" {
		t.Errorf("cpu_frequency_policy status %v, want BOUND", frequency["status"])
	}
	if frequency["value"] != pinnedCPUFrequencyPolicy {
		t.Errorf("cpu_frequency_policy value %v, want the pinned policy string", frequency["value"])
	}
	frequencyRationale, _ := frequency["rationale"].(string)
	if !strings.Contains(frequencyRationale, "us009-us008-owner-decisions-2026-08-27.json") {
		t.Error("cpu_frequency_policy rationale must cite the round-2 owner decision record us009-us008-owner-decisions-2026-08-27.json")
	}
	if !strings.Contains(frequencyRationale, "DOCUMENT_DEFAULTS_RECORD_OBSERVED") {
		t.Error("cpu_frequency_policy rationale must name the owner's choice DOCUMENT_DEFAULTS_RECORD_OBSERVED")
	}

	allocation := host["allocation_evidence"].(map[string]any)
	if allocation["status"] != "BOUND" {
		t.Errorf("allocation_evidence status %v, want BOUND (round-3 owner decision us008_tenancy_allocation_evidence_procedure)", allocation["status"])
	}
	// The false-binding guard survives the binding: the bound value must
	// be the round-3 TENANCY procedure, never the round-2 accounting
	// method that shared the name.
	if allocation["value"] != pinnedTenancyProcedure {
		t.Errorf("allocation_evidence value %v, want the pinned STANDARD_CLOUD_CHECKS tenancy procedure", allocation["value"])
	}
	if value, _ := allocation["value"].(string); strings.Contains(value, "BUILTIN_ACCOUNTING_PER_RUN") || strings.Contains(value, "GC/NMT") {
		t.Error("allocation_evidence must never be bound with the allocation-ACCOUNTING method (name-collision false binding)")
	}
	allocationRationale, _ := allocation["rationale"].(string)
	if !strings.Contains(allocationRationale, "us008-owner-attestation-2026-08-27.json") {
		t.Error("allocation_evidence rationale must cite the round-3 owner decision record us008-owner-attestation-2026-08-27.json")
	}
	if !strings.Contains(allocationRationale, "STANDARD_CLOUD_CHECKS") {
		t.Error("allocation_evidence rationale must name the owner's choice STANDARD_CLOUD_CHECKS")
	}
	allocationNotes, _ := allocation["notes"].(string)
	if !strings.Contains(allocationNotes, "us009-us008-owner-decisions-2026-08-27.json") {
		t.Error("allocation_evidence notes must record that the round-2 decision record never bound this field (collision resolution)")
	}
	if !strings.Contains(allocationNotes, "tenancy") {
		t.Error("allocation_evidence notes must keep the dedicated/exclusive tenancy scope explicit")
	}
	if !strings.Contains(allocationNotes, "none exists yet") && !strings.Contains(allocationNotes, "recorded per run") {
		t.Error("allocation_evidence notes must keep the per-run observations honestly pending (the binding covers the procedure only)")
	}

	// The decided allocation-accounting method is recorded as the
	// measurement_tools candidate in BOTH environments, by full equality,
	// while the field itself stays honestly pending.
	for _, name := range []string{"confirmation.json", "primary-macos.json"} {
		environment := loadEnvironment(name)
		tools := environment["tool_identities"].(map[string]any)
		measurement := tools["measurement_tools"].(map[string]any)
		if measurement["status"] != "OWNER_DECISION_PENDING" {
			t.Errorf("%s measurement_tools status %v, want OWNER_DECISION_PENDING (identities and digests are undecided)", name, measurement["status"])
		}
		if _, smuggled := measurement["value"]; smuggled {
			t.Errorf("%s measurement_tools must not carry a value while pending", name)
		}
		if measurement["candidate"] != pinnedAllocationAccountingCandidate {
			t.Errorf("%s measurement_tools candidate %v, want the pinned BUILTIN_ACCOUNTING_PER_RUN candidate", name, measurement["candidate"])
		}
		measurementNotes, _ := measurement["notes"].(string)
		if !strings.Contains(measurementNotes, "us009-us008-owner-decisions-2026-08-27.json") {
			t.Errorf("%s measurement_tools notes must cite the round-2 owner decision record", name)
		}
	}
}

// TestRound3PlanAttestationRecordedHonestly pins the owner's round-3
// plan attestation (us008_plan_attestation = ATTESTED_BY_OWNER, record
// us008-owner-attestation-2026-08-27.json) exactly as recorded: the
// plan's attestation_state is OWNER_ATTESTED — never promoted to
// INDEPENDENTLY_ATTESTED, because the attestation is owner-only — and
// the in-repo attestation_record digest-binds the attestation to the
// exact frozen plan bytes at mainline 51257ac, by full equality on
// every recorded field.
func TestRound3PlanAttestationRecordedHonestly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "benchmarks", "plan", "workloads.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	if plan["attestation_state"] != "OWNER_ATTESTED" {
		t.Fatalf("attestation_state %v, want OWNER_ATTESTED (owner-only attestation; INDEPENDENTLY_ATTESTED is neither true nor claimed)", plan["attestation_state"])
	}
	status, _ := plan["status"].(string)
	if !strings.HasPrefix(status, "PREREGISTERED_OWNER_ATTESTED") {
		t.Errorf("status %q must declare the paired PREREGISTERED_OWNER_ATTESTED state", status)
	}
	record, present := plan["attestation_record"].(map[string]any)
	if !present {
		t.Fatal("an attested plan must carry the digest-binding attestation_record")
	}
	expectations := map[string]any{
		"plan_content_sha256":        pinnedPlanContentSHA256,
		"frozen_plan_git_commit":     pinnedFrozenPlanCommit,
		"frozen_plan_path":           "benchmarks/plan/workloads.json",
		"decision_record":            pinnedAttestationRecordPath,
		"attested_at":                pinnedAttestedAt,
		"assurance":                  "OWNER_ATTESTED_NOT_INDEPENDENT",
		"independent_review_claimed": false,
	}
	for field, want := range expectations {
		if record[field] != want {
			t.Errorf("attestation_record.%s = %v, want %v", field, record[field], want)
		}
	}
	scope, _ := record["digest_scope"].(string)
	if !strings.Contains(scope, pinnedFrozenPlanCommit[:7]) {
		t.Errorf("digest_scope must name the frozen commit %s, got %q", pinnedFrozenPlanCommit[:7], scope)
	}
}

// TestPlanAttestationPairedStates exercises the paired-state discipline
// of the attestation extension on a copied tree: an attested state
// without its digest-binding record, a record smuggled under
// UNATTESTED, an unpaired status string, a malformed digest, and a
// promoted assurance label must each fail BOTH the schema and the spec
// cross-check — and OWNER_ATTESTED must never satisfy the exit-0
// full-binding gate (never loosening: only INDEPENDENTLY_ATTESTED can).
func TestPlanAttestationPairedStates(t *testing.T) {
	scenarios := []struct {
		name   string
		mutate func(plan map[string]any)
	}{
		{"attested state without attestation_record", func(plan map[string]any) {
			delete(plan, "attestation_record")
		}},
		{"attestation_record smuggled under UNATTESTED", func(plan map[string]any) {
			plan["attestation_state"] = "UNATTESTED"
			plan["status"] = "PREREGISTERED_BY_DRIVER_UNATTESTED - test scenario: state reverted with the record left behind"
		}},
		{"status not paired with OWNER_ATTESTED", func(plan map[string]any) {
			plan["status"] = "PREREGISTERED_BY_DRIVER_UNATTESTED - test scenario: unpaired status"
		}},
		{"malformed plan digest", func(plan map[string]any) {
			record := plan["attestation_record"].(map[string]any)
			record["plan_content_sha256"] = "not-a-digest"
		}},
		{"promoted assurance label", func(plan map[string]any) {
			record := plan["attestation_record"].(map[string]any)
			record["assurance"] = "INDEPENDENTLY_REVIEWED"
		}},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			root := copyBenchmarkTree(t)
			mutatePlan(t, root, scenario.mutate)
			report, err := Verify(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.SchemaFailures["benchmarks/plan/workloads.json"]) == 0 {
				t.Error("the schema must reject the unpaired attestation state")
			}
			if len(report.PlanFailures) == 0 {
				t.Error("the spec cross-check must reject the unpaired attestation state")
			}
		})
	}
}

// OWNER_ATTESTED is honest progress, not the finish line: even with
// every field bound and both environments BOUND, an owner-only
// attestation must never verify as fully bound (the exit-0 gate keeps
// requiring INDEPENDENTLY_ATTESTED — never loosened).
func TestVerifyOwnerAttestedIsNotFullyBound(t *testing.T) {
	root := copyBenchmarkTree(t)
	bindAllPendingFields(t, root)
	setBindingStatuses(t, root, "BOUND", "OWNER_ATTESTED")
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SchemaFailures) > 0 || len(report.PlanFailures) > 0 {
		t.Fatalf("owner-attested scenario must stay schema/spec clean, got %v / %v", report.SchemaFailures, report.PlanFailures)
	}
	if report.FullyBound() {
		t.Fatal("an owner-only attestation must never verify as fully bound")
	}
	if !report.HostBindingIsOnlyBlocker() {
		t.Fatalf("expected HOST_BINDING_PENDING (independent attestation still pending), got %v", report.BlockerClasses)
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
	if !strings.Contains(action, "default: \""+pinnedTerraformVersion+"\"") {
		t.Errorf("dialed-setup action.yml no longer defaults terraform_version to the recorded %q", pinnedTerraformVersion)
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
	// declares: 17 of 23 remain pending after the owner's Tier-1
	// decision bound instance_type / region / ami_id / ami_name, the
	// round-2 decision of 2026-08-27 bound cpu_frequency_policy, and the
	// round-3 decision of 2026-08-27 bound allocation_evidence.
	confirmationUnbound := 0
	for _, field := range report.UnboundFields {
		if strings.Contains(field.Document, "confirmation") {
			confirmationUnbound++
		}
	}
	if confirmationUnbound != 17 {
		t.Fatalf("canonical meter must still count 17 unbound confirmation fields, got %d", confirmationUnbound)
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
