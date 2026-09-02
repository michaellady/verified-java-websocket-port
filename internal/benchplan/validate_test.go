package benchplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp/syntax"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
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
	pinnedCPUFrequencyPolicy            = "DOCUMENT_DEFAULTS_RECORD_OBSERVED: no frequency tuning and no tuning claims — no governor, turbo, or SMT setting is mutated on the bound host; the booted host's default scaling facts (cpufreq driver and governor presence or absence, turbo/boost visibility, SMT state) are recorded at provision alongside the other booted-host facts, and the observed CPU clock is recorded per measured run"
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
		// Re-review round 1 (session 01a04165, BLOCKING): relabeling the
		// owner-only record to INDEPENDENTLY_ATTESTED — a state/status
		// string edit with no independent evidence — must fail BOTH the
		// schema (the independent record variant requires evidence an
		// owner-only record structurally cannot provide) and the spec
		// cross-check (typed finding).
		{"owner record relabeled to INDEPENDENTLY_ATTESTED", func(plan map[string]any) {
			plan["attestation_state"] = "INDEPENDENTLY_ATTESTED"
			plan["status"] = "PREREGISTERED_INDEPENDENTLY_ATTESTED - test scenario: relabel-only promotion of the owner record"
		}},
		{"relabel plus promoted top-level labels, still no independent evidence", func(plan map[string]any) {
			plan["attestation_state"] = "INDEPENDENTLY_ATTESTED"
			plan["status"] = "PREREGISTERED_INDEPENDENTLY_ATTESTED - test scenario: relabel with promoted document labels"
			plan["assurance"] = "INDEPENDENTLY_ATTESTED"
			plan["independent_review_claimed"] = true
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
	setEnvironmentBindingStatuses(t, root, "BOUND")
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

// Defense in depth above the engine: the canonical schema itself must
// require the per-run observed-CPU-clock record on MEASURED documents
// (owner-bound policy DOCUMENT_DEFAULTS_RECORD_OBSERVED) and must accept
// a well-formed one. SYNTHETIC documents are unaffected — the
// requirement lives in the MEASURED-only "then" branch, which is why the
// existing synthetic fixtures above still conform.
func TestSchemaRequiresObservedClockOnMeasuredOnly(t *testing.T) {
	base := map[string]any{}
	content, err := os.ReadFile(filepath.Join(repoRoot, "internal", "benchplan", "testdata", "synthetic-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &base); err != nil {
		t.Fatal(err)
	}
	// Promote the fixture to MEASURED with a complete synthetic binding
	// closure so the only remaining question is the clock record.
	base["provenance_label"] = "MEASURED"
	bindings := map[string]any{}
	for _, name := range RequiredSampleBindings {
		bindings[name] = syntheticDigest(name)
	}
	base["bindings"] = bindings
	observations := map[string]any{
		"background_cpu_percent_max_observed": 1.5,
		"thermal_throttle_events":             0,
		"power_state_anomalies":               0,
		"identity_checks_passed":              true,
		"invalid_samples":                     0,
		"reference_drift": map[string]any{
			"baseline_statistic":    100.0,
			"subsequent_statistics": []float64{100, 100, 100, 100, 100, 100, 100},
		},
	}
	base["run_validity_observations"] = observations

	write := func(t *testing.T, document map[string]any) string {
		t.Helper()
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "sample.json"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	// The schema resource lives under root/schemas, so validate with the
	// repo as root and an absolute-from-root document path is not
	// possible; copy the schema dir reference by validating through a
	// symlinked temp root instead.
	validate := func(t *testing.T, document map[string]any) []string {
		t.Helper()
		dir := write(t, document)
		if err := os.Symlink(mustAbs(t, filepath.Join(repoRoot, "schemas")), filepath.Join(dir, "schemas")); err != nil {
			t.Fatal(err)
		}
		failures, err := ValidateSampleSetDocument(dir, "sample.json")
		if err != nil {
			t.Fatal(err)
		}
		return failures
	}

	if failures := validate(t, base); len(failures) == 0 {
		t.Error("a MEASURED document without observed_cpu_clock must be rejected by the schema")
	}

	observations["observed_cpu_clock"] = map[string]any{
		"source":      "SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT",
		"samples_mhz": []float64{3200, 3200},
	}
	if failures := validate(t, base); len(failures) > 0 {
		t.Errorf("a MEASURED document with a well-formed observed_cpu_clock must conform, got: %v", failures)
	}

	// A nonpositive reading is schema-invalid.
	observations["observed_cpu_clock"] = map[string]any{
		"source":      "SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT",
		"samples_mhz": []float64{0},
	}
	if failures := validate(t, base); len(failures) == 0 {
		t.Error("a nonpositive observed clock reading must be rejected by the schema")
	}
}

// measuredSchemaDocument builds a schema-valid MEASURED raw-sample
// document with a complete synthetic binding closure and a well-formed
// observed clock, and returns the document plus its nested
// run_validity_observations and observed_cpu_clock maps so a test can
// mutate exactly one nested rule at a time. Every digest is synthetic
// and labeled as such; this is not a measurement.
func measuredSchemaDocument(t *testing.T) (document, observations, clock map[string]any) {
	t.Helper()
	document = map[string]any{}
	content, err := os.ReadFile(filepath.Join(repoRoot, "internal", "benchplan", "testdata", "synthetic-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	document["provenance_label"] = "MEASURED"
	bindings := map[string]any{}
	for _, name := range RequiredSampleBindings {
		bindings[name] = syntheticDigest(name)
	}
	document["bindings"] = bindings
	clock = map[string]any{
		"source":      "SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT",
		"samples_mhz": []float64{3200, 3200},
	}
	observations = map[string]any{
		"background_cpu_percent_max_observed": 1.5,
		"thermal_throttle_events":             0,
		"power_state_anomalies":               0,
		"identity_checks_passed":              true,
		"invalid_samples":                     0,
		"reference_drift": map[string]any{
			"baseline_statistic":    100.0,
			"subsequent_statistics": []float64{100, 100, 100, 100, 100, 100, 100},
		},
		"observed_cpu_clock": clock,
	}
	document["run_validity_observations"] = observations
	return document, observations, clock
}

// validateRawSampleDocument runs the canonical raw-sample schema over an
// in-memory document via a temp root that symlinks the real schemas dir.
func validateRawSampleDocument(t *testing.T, document map[string]any) []string {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sample.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(mustAbs(t, filepath.Join(repoRoot, "schemas")), filepath.Join(dir, "schemas")); err != nil {
		t.Fatal(err)
	}
	failures, err := ValidateSampleSetDocument(dir, "sample.json")
	if err != nil {
		t.Fatal(err)
	}
	return failures
}

// The nested observed_cpu_clock shape rules previously had no negative
// tests: the reviewer's deletion-sensitivity matrix showed that missing
// source/samples, an empty readings array, and additionalProperties
// could all be deleted from the schema with every test still passing.
// Each rule now has a concrete failing input.
func TestSchemaObservedClockShapeRulesAreEnforced(t *testing.T) {
	// Control: the unmutated document must conform, so every failure
	// below is attributable to the single mutation and not to a broken
	// base document.
	if failures := func() []string {
		document, _, _ := measuredSchemaDocument(t)
		return validateRawSampleDocument(t, document)
	}(); len(failures) > 0 {
		t.Fatalf("control MEASURED document must conform, got: %v", failures)
	}

	for name, mutate := range map[string]func(observations, clock map[string]any){
		"blank source": func(_, clock map[string]any) {
			clock["source"] = "   "
		},
		"missing source": func(_, clock map[string]any) {
			delete(clock, "source")
		},
		"missing samples": func(_, clock map[string]any) {
			delete(clock, "samples_mhz")
		},
		"empty samples": func(_, clock map[string]any) {
			clock["samples_mhz"] = []float64{}
		},
		"additional property on clock": func(_, clock map[string]any) {
			clock["governor"] = "performance"
		},
		"additional property on observations": func(observations, _ map[string]any) {
			observations["observed_cpu_mhz"] = 3200
		},
	} {
		t.Run(name, func(t *testing.T) {
			document, observations, clock := measuredSchemaDocument(t)
			mutate(observations, clock)
			if failures := validateRawSampleDocument(t, document); len(failures) == 0 {
				t.Fatalf("%s: schema accepted the document; a nested clock shape rule is missing", name)
			}
		})
	}
}

// unicodeSpaceCodePoints returns the COMPLETE current unicode.IsSpace set,
// derived from Go's own Unicode tables rather than transcribed by hand.
//
// Review round 2 found the previous revision of the differential test below
// unable to fail. It drove itself from 17 literal strings covering only 15 of
// this set's 25 code points, omitting ten members of U+2000-U+200A, so a
// schema pattern narrowed to just the 15 exercised code points passed while
// genuinely disagreeing with Go on the other ten. That was reproduced by
// mutation before this fix was written, and the same mutation is now caught.
// Enumerating the set makes such an omission impossible to reintroduce and
// keeps the vectors correct as Go's Unicode tables are updated.
func unicodeSpaceCodePoints() []rune {
	var spaces []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.IsSpace(r) {
			spaces = append(spaces, r)
		}
	}
	return spaces
}

// The canonical schema and the Go contract must agree on what counts as
// an attributed source. They previously disagreed: the schema's
// minLength:1 accepted "   " while ObservedCPUClock.validate rejects any
// string that strings.TrimSpace empties. This test drives BOTH REAL SEAMS
// -- the compiled canonical schema through ValidateSampleSetDocument, and
// EnforceRunValidity -- over every code point in unicode.IsSpace,
// enumerated rather than sampled, in both directions.
//
// SCOPE, stated precisely because review round 3 found the previous
// wording of this comment ("cannot reopen the gap in either direction",
// "every input") false as written. What this test covers exhaustively is
// the REJECTION side: every unicode.IsSpace code point, alone and in
// whitespace-only composites. Its ACCEPTANCE side is a finite sample --
// each IsSpace code point wrapped around "x", plus five realistic
// sources.
//
// Every accepted vector CONTAINS at least one non-space rune, and every
// non-space rune in every one of them is printable ASCII (U+0021-U+007E).
// Review round 4 found the previous wording of this sentence -- "every one
// of those accepted vectors is printable ASCII" -- false: most of them are
// a non-ASCII Unicode space wrapped around "x" (the attributed/U+XXXX
// vectors below), so the vectors themselves are not ASCII at all. It is
// the QUALIFYING rune that is. assertBothAccept now checks that property
// on each vector it is given, so this paragraph is executed rather than
// asserted.
//
// That property is exactly why this test cannot carry the every-rune
// guarantee. PROBE: narrowing the schema pattern to [!-~], which rejects
// the Go-valid source "Ω" (U+03A9) but matches every one of the
// qualifying runes above, left this test AND the whole suite at exit 0
// (28 ok, 0 FAIL). The every-rune guarantee is carried by
// TestSchemaAndGoAgreeOnClockSourceForEveryRune below, which closes
// exactly that half and does fail on that mutation.
func TestSchemaAndGoAgreeOnClockSourceAttribution(t *testing.T) {
	spaces := unicodeSpaceCodePoints()

	// The derivation is the entire basis of this test's coverage, so the
	// derivation itself is checked. A floor rather than an exact count: a
	// future Unicode update may ADD members, which the enumeration picks up
	// automatically, but a derivation that silently collapsed to a handful of
	// code points would make every vector below vacuous without failing.
	if len(spaces) < 25 {
		t.Fatalf("unicode.IsSpace enumeration yielded %d code points, want >= 25: the derivation is broken and every vector below would be vacuous", len(spaces))
	}
	derived := make(map[rune]bool, len(spaces))
	for _, r := range spaces {
		derived[r] = true
	}
	// Regression anchor on the exact historical gap: these ten members of
	// U+2000-U+200A are the ones the hand-written list omitted.
	for r := rune(0x2000); r <= 0x200A; r++ {
		if !derived[r] {
			t.Fatalf("U+%04X missing from the derived unicode.IsSpace set: this is the exact gap review round 2 found, and the enumeration must cover it", r)
		}
	}
	t.Logf("differential vectors derived from unicode.IsSpace: %d code points", len(spaces))

	// assertBothReject and assertBothAccept evaluate the two seams on
	// identical input, so any disagreement is attributable to the seams and
	// not to differently-constructed vectors.
	assertBothReject := func(t *testing.T, source string) {
		t.Helper()
		document, _, clock := measuredSchemaDocument(t)
		clock["source"] = source
		schemaFailures := validateRawSampleDocument(t, document)

		observations := cleanObservations()
		observations.ObservedCPUClock = &ObservedCPUClock{Source: source, SamplesMHz: []float64{3200}}
		_, goErr := EnforceRunValidity(observations)

		if len(schemaFailures) == 0 || goErr == nil {
			t.Errorf("source %q: schema rejected=%t go rejected=%t -- the schema and the Go contract must both reject an unattributed source",
				source, len(schemaFailures) > 0, goErr != nil)
		}
	}
	assertBothAccept := func(t *testing.T, source string) {
		t.Helper()

		// The SCOPE note's claim about this test's accepted vectors,
		// executed on each vector rather than asserted in prose.
		qualifying := 0
		for _, r := range source {
			if unicode.IsSpace(r) {
				continue
			}
			qualifying++
			if r < 0x21 || r > 0x7E {
				t.Errorf("accepted vector %q carries the non-space rune U+%04X, which is not printable ASCII: the SCOPE note above says every qualifying rune in this test's accepted vectors is, and it is the reason this test cannot carry the every-rune guarantee", source, r)
			}
		}
		if qualifying == 0 {
			t.Errorf("accepted vector %q has no non-space rune: it cannot be an attributed source and does not belong on the accept side", source)
		}

		document, _, clock := measuredSchemaDocument(t)
		clock["source"] = source
		schemaFailures := validateRawSampleDocument(t, document)

		observations := cleanObservations()
		observations.ObservedCPUClock = &ObservedCPUClock{Source: source, SamplesMHz: []float64{3200}}
		_, goErr := EnforceRunValidity(observations)

		if len(schemaFailures) > 0 || goErr != nil {
			t.Errorf("source %q: schema failures=%v go err=%v -- both seams must accept an attributed source",
				source, schemaFailures, goErr)
		}
	}

	// Every enumerated whitespace code point, in both directions: alone it is
	// unattributed and must be rejected; wrapped around a non-whitespace
	// character it is attributed and must be accepted. The accept half stops
	// the rejection rule from being satisfied by an over-broad pattern that
	// simply rejects every source containing any whitespace.
	for _, r := range spaces {
		source := string(r)
		t.Run(fmt.Sprintf("unattributed/U+%04X", r), func(t *testing.T) {
			assertBothReject(t, source)
		})
		t.Run(fmt.Sprintf("attributed/U+%04X", r), func(t *testing.T) {
			assertBothAccept(t, source+"x"+source)
		})
	}

	// Multi-code-point whitespace-only vectors, including one built from the
	// entire enumerated set at once.
	var everySpace strings.Builder
	for _, r := range spaces {
		everySpace.WriteRune(r)
	}
	for _, vector := range []struct{ name, source string }{
		{"ascii run", "   "},
		{"crlf", "\r\n"},
		{"mixed", " \t\n 　 "},
		{"every code point", everySpace.String()},
		{"empty", ""},
	} {
		t.Run("unattributed/"+vector.name, func(t *testing.T) {
			assertBothReject(t, vector.source)
		})
	}

	// Realistic attributed sources, including padded ones.
	for _, source := range []string{
		"/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
		"lscpu --json",
		" turbostat ", // padded but attributed
		"a",
		" x ", // non-whitespace between whitespace
	} {
		t.Run("attributed/"+source, func(t *testing.T) {
			assertBothAccept(t, source)
		})
	}
}

// rawSampleSchemaNode reads the canonical raw-sample schema as plain JSON
// and returns the object at the given key path. EXTRACTED, never
// transcribed: a transcribed copy could drift from the schema it claims to
// characterise, which is precisely the class of silent disagreement this
// file exists to prevent.
func rawSampleSchemaNode(t *testing.T, path ...string) map[string]any {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot, "schemas", "benchmark-raw-sample-1.0.0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var node map[string]any
	if err := json.Unmarshal(content, &node); err != nil {
		t.Fatal(err)
	}
	for i, key := range path {
		child, ok := node[key]
		if !ok {
			t.Fatalf("schema path %v: key %q (element %d) is absent -- the clock-source subschema moved or was deleted", path, key, i)
		}
		object, ok := child.(map[string]any)
		if !ok {
			t.Fatalf("schema path %v: element %d (%q) is %T, want an object", path, i, key, child)
		}
		node = object
	}
	return node
}

// clockSourceSchemaPath is the key path from the raw-sample schema root to
// the subschema that governs the clock-source string.
var clockSourceSchemaPath = []string{
	"properties", "run_validity_observations",
	"properties", "observed_cpu_clock",
	"properties", "source",
}

// censusKeywords are the keywords whose PRESENCE anywhere in the raw-sample
// schema document is frozen by rawSampleConstraintCensus.
//
// The set is deliberately NOT "every applicator". The round-4 fix introduced
// a guard that enumerated the ROUTES from the document root down to the clock
// source -- the root's applicator keywords, then run_validity_observations',
// then observed_cpu_clock's, plus a special case for the root if/then pair.
// Review round 5 defeated it with a `then.allOf` that re-descends to source
// from a branch the route list did not walk. Enumerating routes is the wrong
// shape, because there are unboundedly many of them. What IS bounded is the
// set of keywords that can actually change a string's verdict, so the census
// walks the WHOLE document and records every occurrence of one, wherever it
// sits, with no notion of route at all.
//
// Two groups:
//
//   - stringConstrainingKeywords are the assertions that can, on their own,
//     accept or reject a string. A new constraint on the clock source is
//     necessarily one of these, at some pointer, and the census records it
//     whether it hangs off properties, allOf, then, dependentSchemas, or
//     anything else.
//   - composingKeywords cannot constrain a string by themselves, but can
//     pull in a subschema whose own constraints are NOT visible in this
//     document -- $ref/$dynamicRef to another resource being the only real
//     route out. They are censused so that such a route cannot be opened
//     silently; $ref entries carry their target, so a retarget is a census
//     change too.
//
// Container keywords that neither assert nor import (properties, items,
// prefixItems, contains, additionalProperties, required, ...) are NOT
// censused: whatever they contain is itself censused if it can constrain a
// string, so listing the containers would only make the frozen list longer
// and noisier without widening what it catches. `type` is likewise not
// censused, because it occurs on nearly every node: the clock source's own
// `type` is pinned BY VALUE a few lines below in
// TestSchemaAndGoAgreeOnClockSourceForEveryRune, and a `type` introduced
// anywhere else can only reach the source through a composing keyword,
// which is censused.
//
// WHAT THE CENSUS IS AND IS NOT. It is complete over keyword occurrences
// ADDED to or REMOVED from this document: a new constraint on the clock
// source, reached by any route whatsoever, necessarily adds at least one
// entry. It is BLIND to a change in the VALUE of a keyword already present.
// The value-change routes that can reach the clock source are exactly the
// three keywords on its own subschema -- type, minLength and pattern -- of
// which type and minLength are pinned by value below, and pattern is the
// thing both differential sweeps exercise. It is also blind to $id and
// $anchor, and to the CONTENT of any external resource a $ref were
// repointed at (the repoint itself is caught, since $ref entries carry
// their target; today every $ref target is same-document).
var stringConstrainingKeywords = map[string]bool{
	"const": true, "enum": true, "format": true,
	"maxLength": true, "minLength": true, "pattern": true,
	"contentEncoding": true, "contentMediaType": true, "contentSchema": true,
}

var composingKeywords = map[string]bool{
	"$ref": true, "$dynamicRef": true,
	"allOf": true, "anyOf": true, "oneOf": true, "not": true,
	"if": true, "then": true, "else": true,
	"dependentSchemas": true, "propertyNames": true, "patternProperties": true,
	"unevaluatedProperties": true, "unevaluatedItems": true,
}

// frozenRawSampleConstraintCensus is the complete census of the canonical
// raw-sample schema as frozen by this preregistration. Entries are JSON
// pointers to the keyword occurrence, sorted; $ref entries append their
// target.
//
// This list is EXTRACTED, not transcribed: it was produced by running
// rawSampleConstraintCensus over the schema and pasted verbatim, so it
// describes the schema rather than someone's reading of it.
var frozenRawSampleConstraintCensus = []string{
	"/$defs/digest/pattern",
	"/if",
	"/if/properties/provenance_label/const",
	"/properties/bindings/properties/adapter_digest/$ref -> #/$defs/digest",
	"/properties/bindings/properties/analyzer_digest/$ref -> #/$defs/digest",
	"/properties/bindings/properties/confirmation_environment_digest/$ref -> #/$defs/digest",
	"/properties/bindings/properties/java_executable_digest/$ref -> #/$defs/digest",
	"/properties/bindings/properties/java_source_digest/$ref -> #/$defs/digest",
	"/properties/bindings/properties/plan_digest/$ref -> #/$defs/digest",
	"/properties/bindings/properties/primary_environment_digest/$ref -> #/$defs/digest",
	"/properties/bindings/properties/rust_executable_digest/$ref -> #/$defs/digest",
	"/properties/bindings/properties/rust_source_digest/$ref -> #/$defs/digest",
	"/properties/bindings/properties/tool_identity_digest/$ref -> #/$defs/digest",
	"/properties/environment_role/enum",
	"/properties/measured_pairs/items/$ref -> #/$defs/pair",
	"/properties/metric/enum",
	"/properties/order/items/enum",
	"/properties/provenance_label/enum",
	"/properties/run_validity_observations/properties/observed_cpu_clock/properties/source/minLength",
	"/properties/run_validity_observations/properties/observed_cpu_clock/properties/source/pattern",
	"/properties/schema/const",
	"/properties/warmup_pairs/items/$ref -> #/$defs/pair",
	"/properties/workload_id/enum",
	"/then",
}

// rawSampleConstraintCensus walks the whole raw-sample schema document and
// returns the sorted census described on censusKeywords above.
func rawSampleConstraintCensus(t *testing.T) []string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot, "schemas", "benchmark-raw-sample-1.0.0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	var census []string
	var walk func(node any, pointer string)
	walk = func(node any, pointer string) {
		switch typed := node.(type) {
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				child := typed[key]
				childPointer := pointer + "/" + escapeJSONPointerToken(key)
				if stringConstrainingKeywords[key] || composingKeywords[key] {
					entry := childPointer
					if key == "$ref" || key == "$dynamicRef" {
						if target, ok := child.(string); ok {
							entry += " -> " + target
						}
					}
					census = append(census, entry)
				}
				walk(child, childPointer)
			}
		case []any:
			for i, child := range typed {
				walk(child, pointer+"/"+strconv.Itoa(i))
			}
		}
	}
	walk(document, "")
	sort.Strings(census)
	return census
}

func escapeJSONPointerToken(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// TestSchemaAndGoAgreeOnClockSourceForEveryRune closes the half that
// TestSchemaAndGoAgreeOnClockSourceAttribution samples. That test accepts
// only vectors whose qualifying non-space rune is printable ASCII, so a
// pattern narrowed to [!-~] passed it while rejecting the Go-valid source
// "Ω" (U+03A9) -- executed and read at exit 0 before this test was
// written. Here the two accepted SETS are compared over the whole rune
// domain, in both directions: for every rune, schema-rejects must equal
// Go-rejects.
//
// NO PROXIES. Review round 4 found the previous revision of this test
// sampling its own join: it pinned an extracted-pattern proxy and a
// strings.TrimSpace proxy against the real seams on 40 witness runes and
// then swept only the PROXIES, so a schema constraint rejecting an
// unwitnessed rune left it green. That was reproduced by mutation before
// this fix was written -- adding {"not": {"const": "ሴ"}} to the
// source subschema left the previous test AND the whole suite at exit 0
// (28 ok, 0 FAIL) -- and the same mutation is now caught by name.
//
// Both sides of the sweep are now the real seams:
//
//   - The schema side compiles the canonical schema with the production
//     compileCanonicalSchema and reads its verdict through the production
//     validateDecodedValue -- the same two functions ValidateSampleSetDocument
//     itself calls -- applying the WHOLE schema to a WHOLE document. What
//     is elided is only the per-rune re-read and re-compile of the schema
//     FILE. That elision is why the sweep is affordable at all: a
//     temporary timing probe measured the full ValidateSampleSetDocument
//     path at 0.94-1.20ms per document, which over 1,112,064 runes is
//     17-22 minutes, against roughly 32s wall for this sweep on a
//     14-core host.
//   - The Go side calls EnforceRunValidity directly, with no stand-in at
//     all: the same probe measured it at 39-48ns per rune, so the whole
//     domain costs about 50ms.
//
// The one shortcut is that the decoded document is built once per worker
// and only its source leaf is reassigned, rather than re-encoding the
// document per rune. That is sound exactly when JSON round-tripping the
// source string is the identity, since every other leaf is held fixed at a
// value that came from that same round trip -- so the sweep VERIFIES the
// round trip per rune, through jsonschema's own decoder, rather than
// assuming it.
func TestSchemaAndGoAgreeOnClockSourceForEveryRune(t *testing.T) {
	// STEP 1 -- the sweep over the real seams. Surrogates are skipped:
	// they are not valid runes, cannot survive JSON decoding, and
	// string(r) would silently turn each into U+FFFD, so including them
	// would compare U+FFFD to itself 2,048 times rather than adding
	// coverage.
	const everyValidRune = 1114112 - 2048

	document, _, _ := measuredSchemaDocument(t)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	workers := runtime.NumCPU()
	type shard struct {
		compared      int
		disagreements []rune
		roundTripBad  []rune
		err           error
	}
	shards := make([]shard, workers)
	var waiting sync.WaitGroup
	for w := 0; w < workers; w++ {
		waiting.Add(1)
		go func(w int) {
			defer waiting.Done()
			out := &shards[w]

			// Each worker owns a private compiled schema and a private
			// decoded document, so the sweep shares no mutable state and
			// makes no assumption about the validator's concurrency.
			schema, err := compileCanonicalSchema(repoRoot, "benchmark-raw-sample-1.0.0.schema.json")
			if err != nil {
				out.err = err
				return
			}
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
			if err != nil {
				out.err = err
				return
			}
			root, ok := value.(map[string]any)
			if !ok {
				out.err = fmt.Errorf("decoded document is %T, want an object", value)
				return
			}
			leaf, ok := root["run_validity_observations"].(map[string]any)["observed_cpu_clock"].(map[string]any)
			if !ok {
				out.err = fmt.Errorf("decoded document has no observed_cpu_clock object")
				return
			}
			observations := cleanObservations()
			clock := &ObservedCPUClock{SamplesMHz: []float64{3200}}
			observations.ObservedCPUClock = clock

			for r := rune(w); r <= unicode.MaxRune; r += rune(workers) {
				if !utf8.ValidRune(r) {
					continue
				}
				out.compared++
				source := string(r)

				// The leaf-reassignment shortcut is only sound if this
				// string survives JSON encode/decode unchanged, decoded by
				// the same jsonschema decoder the real seam uses.
				sourceJSON, err := json.Marshal(source)
				if err != nil {
					out.err = err
					return
				}
				decoded, err := jsonschema.UnmarshalJSON(bytes.NewReader(sourceJSON))
				if err != nil {
					out.err = err
					return
				}
				if decoded != any(source) {
					out.roundTripBad = append(out.roundTripBad, r)
					continue
				}

				leaf["source"] = source
				schemaAccepts := len(validateDecodedValue(schema, value)) == 0

				clock.Source = source
				_, goErr := EnforceRunValidity(observations)

				if schemaAccepts != (goErr == nil) {
					out.disagreements = append(out.disagreements, r)
				}
			}
		}(w)
	}
	waiting.Wait()

	compared := 0
	var disagreements, roundTripBad []rune
	for w := range shards {
		if shards[w].err != nil {
			t.Fatalf("sweep worker %d failed: %v", w, shards[w].err)
		}
		compared += shards[w].compared
		disagreements = append(disagreements, shards[w].disagreements...)
		roundTripBad = append(roundTripBad, shards[w].roundTripBad...)
	}
	if len(roundTripBad) > 0 {
		t.Fatalf("%d runes do not survive a JSON round trip through jsonschema's decoder (first: U+%04X); the leaf-reassignment shortcut is unsound and the sweep result means nothing",
			len(roundTripBad), roundTripBad[0])
	}
	if compared != everyValidRune {
		t.Fatalf("swept %d runes, want exactly %d: the sweep is not exhaustive and its result means nothing", compared, everyValidRune)
	}
	t.Logf("compared the canonical schema against EnforceRunValidity on all %d valid runes across %d workers", compared, workers)

	if len(disagreements) > 0 {
		sort.Slice(disagreements, func(i, j int) bool { return disagreements[i] < disagreements[j] })
		disagreed := make(map[rune]bool, len(disagreements))
		for _, r := range disagreements {
			disagreed[r] = true
		}
		shown := disagreements
		if len(shown) > 10 {
			shown = shown[:10]
		}
		var detail []string
		for _, r := range shown {
			detail = append(detail, fmt.Sprintf("U+%04X", r))
		}
		var namedWitnesses []string
		for _, r := range []rune{0x03A9, 0x1234, 0x20AC, 0x65E5, 0x1F600} {
			if disagreed[r] {
				namedWitnesses = append(namedWitnesses, fmt.Sprintf("U+%04X %q", r, r))
			}
		}
		t.Fatalf("the canonical raw-sample schema and Go's unicode.IsSpace contract disagree on %d of %d runes; first %d: %s; named witnesses among them: %v",
			len(disagreements), compared, len(shown), strings.Join(detail, ", "), namedWitnesses)
	}

	// STEP 2 -- the STRUCTURAL ASSUMPTIONS behind reading step 1 as
	// evidence about longer strings.
	//
	// SCOPE, stated first because five review rounds have now found a
	// stated property not to be the property that actually holds. Step 1
	// compares SINGLE-RUNE sources and nothing else. It is NOT a proof
	// about every string, and the checks below are NOT a proof that it
	// lifts to one. Review round 5 defeated the previous revision of this
	// guard with a `then.allOf` that re-descends to source carrying a
	// large `maxLength`: that route was not on the hand-enumerated chain,
	// so the guard passed, and a length constraint is invisible to any
	// single-rune probe by construction. Enumerating routes was the wrong
	// shape. The every-input property is now tested DIRECTLY, on strings,
	// by TestSchemaAndGoAgreeOnClockSourceForGeneratedStrings below --
	// which catches that same `then.allOf` construction by observing the
	// disagreement itself rather than by anticipating its shape.
	//
	// What remains here is two things worth checking cheaply and one that
	// is genuinely complete for its own narrow claim:
	//
	//   - the clock-source subschema's own keyword set, so a constraint
	//     added at the obvious place is named at the obvious place;
	//   - the pattern's parse shape, which is WHY single-rune exhaustion
	//     is evidence about longer strings at all rather than an
	//     unrelated fact;
	//   - the whole-document constraint census, which is complete over
	//     keyword OCCURRENCES in this document (see censusKeywords) and
	//     therefore does catch the round-5 construction -- but is blind to
	//     changes in the VALUE of a keyword already present, and to the
	//     content of any resource a $ref target might be repointed at.
	//
	// Together these narrow, but do not close, the space of schema changes
	// the two sweeps cannot see. The residual is recorded in
	// docs/us008-attestation-package.md rather than argued away.
	//
	// Go side, true by inspection of ObservedCPUClock.validate and
	// unaffected by anything in the schema: strings.TrimSpace empties a
	// string iff every rune satisfies unicode.IsSpace, so Go accepts iff at
	// least one rune is not a space -- "some rune qualifies" over a
	// per-rune predicate.
	//
	// Schema side, checked below: the source value is constrained by
	// exactly type/minLength/pattern, the pattern parses to a single
	// character class, and no constraint keyword occurs anywhere else in
	// the document than the census records. A bare character class has no
	// anchors and every match is exactly one rune, so an unanchored search
	// accepts a string iff at least one of its runes is in the class --
	// the same shape.
	//
	// Under those assumptions both sides are "some rune qualifies", and
	// agreement on every rune would give agreement on every non-empty
	// string. The assumptions are checked, not proven exhaustive, which is
	// exactly why the generated-string leg exists as well. The empty
	// string is the one input with no runes: minLength:1 rejects it and
	// TrimSpace empties it, and both
	// TestSchemaAndGoAgreeOnClockSourceAttribution and the generated
	// corpus cover that case directly.
	source := rawSampleSchemaNode(t, clockSourceSchemaPath...)
	var sourceKeys []string
	for key := range source {
		sourceKeys = append(sourceKeys, key)
	}
	sort.Strings(sourceKeys)
	if want := []string{"description", "minLength", "pattern", "type"}; !equalStrings(sourceKeys, want) {
		t.Fatalf("clock-source subschema declares keys %v, want exactly %v: an added keyword could constrain the source string outside the pattern, and the per-rune sweep would no longer be evidence about longer inputs", sourceKeys, want)
	}
	if source["type"] != "string" {
		t.Errorf("clock-source type is %v, want \"string\"", source["type"])
	}
	if source["minLength"] != float64(1) {
		t.Errorf("clock-source minLength is %v, want 1: the empty-string case the lift defers to the differential test depends on it", source["minLength"])
	}
	pattern, ok := source["pattern"].(string)
	if !ok {
		t.Fatalf("clock-source pattern is %T, want string", source["pattern"])
	}
	// The parse below only characterises the pattern the validator
	// actually ran in step 1 if the validator compiled it with Go's own
	// regexp package. It does: santhosh-tekuri/jsonschema/v6 defaults
	// roots.regexpEngine to goRegexpCompile, which is regexp.Compile
	// (roots.go:25 and compiler.go:330 at v6.0.3), and UseRegexpEngine --
	// the only way to change it -- is never CALLED in this repository,
	// checked by repo-wide search across every .go file rather than by
	// reading this package alone. (The round-4 wording said the identifier
	// "appears nowhere in this repository"; that is now false of this
	// sentence itself, which is the only place the identifier occurs.)
	// regexp.Compile parses with syntax.Perl, so that is the flag set used
	// here. Nothing pins this: see residual R5 in
	// docs/us008-attestation-package.md.
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("clock-source pattern %q does not parse with the validator's regexp syntax: %v", pattern, err)
	}
	if parsed.Op != syntax.OpCharClass {
		t.Fatalf("clock-source pattern %q parses to %v, want a single character class (OpCharClass): only then is every match exactly one rune with no anchors, which is what makes the per-rune sweep evidence about longer inputs", pattern, parsed.Op)
	}
	t.Logf("clock-source pattern %q parses to a single character class", pattern)

	// The whole-document constraint census. This REPLACES the route
	// enumeration that rounds 4 and 5 each defeated: instead of listing the
	// ways a constraint could reach the source, it lists every place a
	// constraint occurs at all.
	census := rawSampleConstraintCensus(t)
	if !equalStrings(census, frozenRawSampleConstraintCensus) {
		frozen := make(map[string]bool, len(frozenRawSampleConstraintCensus))
		for _, entry := range frozenRawSampleConstraintCensus {
			frozen[entry] = true
		}
		present := make(map[string]bool, len(census))
		var added []string
		for _, entry := range census {
			present[entry] = true
			if !frozen[entry] {
				added = append(added, entry)
			}
		}
		var removed []string
		for _, entry := range frozenRawSampleConstraintCensus {
			if !present[entry] {
				removed = append(removed, entry)
			}
		}
		t.Errorf("the raw-sample schema's constraint census changed: %d added %v, %d removed %v; every constraint on the clock source is one of these occurrences, so an unrecorded entry means the frozen preregistration now constrains a string differently than it did when the sweeps were run",
			len(added), added, len(removed), removed)
	} else {
		t.Logf("raw-sample schema constraint census matches the frozen %d entries", len(frozenRawSampleConstraintCensus))
	}
}

// Sizes of the generated-string corpus. Every one of these appears in the
// claim recorded in docs/us008-attestation-package.md, because the claim is
// bounded by them and a bounded claim that does not state its bound is not
// checkable.
const (
	// clockSourceDenseMaxRunes is the largest length covered by the DENSE
	// ladder. Four independent properties are required of the corpus at
	// every value n from 1 to this one, and each is checked against the
	// real Go seam rather than assumed:
	//
	//	1. some source of RUNE length n that Go ACCEPTS
	//	2. some source of BYTE length n that Go ACCEPTS
	//	3. some source of rune length n that Go ACCEPTS and that contains
	//	   no printable-ASCII rune (U+0021-U+007E) anywhere
	//	4. some source of rune length n that Go REJECTS
	//
	// (1) and (2) are what make a maxLength or minLength counting either
	// runes or bytes impossible to hide in the range; (3) is what makes a
	// character class narrowed to printable ASCII impossible to hide at
	// any length rather than only at length 1; (4) keeps the rejection
	// half of the property covered at every length too.
	clockSourceDenseMaxRunes = 256

	// clockSourceRandomStrings is the size of the random battery drawn on
	// top of the ladder.
	clockSourceRandomStrings = 200000
)

// clockSourceLongRuneLengths extends the ladder geometrically past the dense
// range, so a length constraint far above it is still caught, at four
// documents per length rather than at the cost of a dense sweep.
var clockSourceLongRuneLengths = []int{512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}

// clockSourceCorpusSeed pins the corpus. math/rand/v2's PCG is seeded from
// these two constants and from nothing else -- no clock, no address, no
// environment -- so the corpus is a pure function of this file for a GIVEN
// Go toolchain, and a failure reproduces on any host running that toolchain.
// Not across toolchains: math/rand/v2 fixes the PCG bit stream but not the
// mapping from it to IntN results, so a future Go release may generate a
// different corpus. Nothing this test proves depends on that -- the four
// coverage properties above are recomputed from whatever corpus is built --
// which is why the corpus digest is logged and never asserted. Recorded as
// residual R4 in docs/us008-attestation-package.md.
const (
	clockSourceCorpusSeedHi uint64 = 0x5553303038524553 // "US008RES"
	clockSourceCorpusSeedLo uint64 = 0x5452544553524f54 // "TRTESROT"
)

// clockSourceRunePools returns the rune pools the corpus is built from,
// PARTITIONED BY unicode.IsSpace at run time rather than by transcription. A
// curated candidate Go classifies as a space (U+00A0, U+0085, U+2028 and
// U+3000 all are) joins the space pool instead of silently corrupting the
// attributed strata, and a future Unicode table update re-partitions them
// automatically.
func clockSourceRunePools(t *testing.T) (spaces, nonSpaces []rune) {
	t.Helper()
	seen := make(map[rune]bool)
	for _, r := range unicodeSpaceCodePoints() {
		spaces = append(spaces, r)
		seen[r] = true
	}
	var candidates []rune
	for r := rune(0x21); r <= 0x7E; r++ {
		candidates = append(candidates, r) // printable ASCII
	}
	// Candidates are curated for INTEREST, not for classification: which
	// side of unicode.IsSpace each lands on is decided below, not here.
	// Several of these are spaces (U+0085, U+00A0, U+2028, U+2029, U+3000)
	// and are included precisely so the partition, rather than a comment,
	// decides that.
	candidates = append(candidates,
		0x00, 0x01, 0x07, 0x08, 0x0E, 0x1B, 0x1F, 0x7F, // C0/C1 controls and DEL
		0x0085, 0x00A0, 0x00B7, 0x00E9, 0x00FF, // NEL, NBSP, and Latin-1 letters
		0x0301, 0x03A9, 0x0416, 0x05D0, 0x0627, 0x0915, // a combining mark and non-Latin letters
		0x1234, 0x180E, 0x200B, 0x2028, 0x2029, 0x20AC, // the round-4 witness U+1234, and space lookalikes
		0x3000, 0x65E5, 0xD55C, 0xFEFF, 0xFFFD, // ideographic space, CJK, Hangul, BOM, replacement
		0x10000, 0x1F600, 0xE0001, 0x10FFFF, // astral planes, including the last valid rune
	)
	for _, r := range candidates {
		if unicode.IsSpace(r) {
			if !seen[r] {
				spaces = append(spaces, r)
				seen[r] = true
			}
			continue
		}
		nonSpaces = append(nonSpaces, r)
	}
	// The pools are the entire basis of this test's discriminating power,
	// so the pools themselves are checked. A collapsed pool would make
	// every stratum below vacuous without failing anything.
	if len(spaces) < 25 {
		t.Fatalf("space pool holds %d runes, want >= 25: the corpus strata that must be REJECTED would be vacuous", len(spaces))
	}
	if len(nonSpaces) < 100 {
		t.Fatalf("non-space pool holds %d runes, want >= 100: the corpus strata that must be ACCEPTED would be vacuous", len(nonSpaces))
	}
	member := make(map[rune]bool, len(nonSpaces))
	for _, r := range nonSpaces {
		member[r] = true
	}
	// Named witnesses that must be on the non-space side for the strata to
	// mean what the comments say. U+1234 is the round-4 mutation witness;
	// U+200B and U+FEFF are the two runes most often mistaken for spaces.
	for _, r := range []rune{0x03A9, 0x1234, 0x20AC, 0x65E5, 0x1F600, 0x200B, 0xFEFF, 0x10FFFF} {
		if !member[r] {
			t.Fatalf("U+%04X is not in the non-space pool: Go now classifies it as a space, and the attributed strata built from it would be whitespace-only", r)
		}
	}
	return spaces, nonSpaces
}

// clockSourceCorpus builds the generated multi-rune corpus, deterministically
// and single-threaded, so that sharding it across workers cannot perturb it.
func clockSourceCorpus(t *testing.T) []string {
	t.Helper()
	spaces, nonSpaces := clockSourceRunePools(t)

	// Two derived pools, split at U+007E, each giving one stratum below
	// exactly the property that stratum needs:
	//
	//   - singleByteNonSpace: every member encodes to ONE UTF-8 byte, so a
	//     string built from it has byte length equal to rune length. That
	//     is what supplies coverage property (2).
	//   - unprintableNonSpace: no member lies in U+0021-U+007E, so a
	//     string built from it contains no printable-ASCII rune at all.
	//     That is what supplies coverage property (3). U+007F is
	//     single-byte too, but it belongs here: for these strata what
	//     matters about it is that it is not printable ASCII.
	//
	// Neither pool is asserted to be exhaustive of its property; each is
	// asserted, by the coverage checks in the test itself, to be big
	// enough to realise it at every length.
	var singleByteNonSpace, unprintableNonSpace []rune
	for _, r := range nonSpaces {
		if r <= 0x7E {
			singleByteNonSpace = append(singleByteNonSpace, r)
		} else {
			unprintableNonSpace = append(unprintableNonSpace, r)
		}
	}

	prng := rand.New(rand.NewPCG(clockSourceCorpusSeedHi, clockSourceCorpusSeedLo))
	pick := func(pool []rune) rune { return pool[prng.IntN(len(pool))] }
	build := func(n int, at func(i int) rune) string {
		var out strings.Builder
		for i := 0; i < n; i++ {
			out.WriteRune(at(i))
		}
		return out.String()
	}
	randomValidRune := func() rune {
		for {
			r := rune(prng.IntN(unicode.MaxRune + 1))
			if utf8.ValidRune(r) {
				return r
			}
		}
	}

	var corpus []string
	add := func(source string) { corpus = append(corpus, source) }

	// (A) The empty string: the one input with no runes at all.
	add("")

	// (B) The dense ladder. Seven shapes at every length from 1 to
	// clockSourceDenseMaxRunes, chosen so that the four coverage
	// properties named on clockSourceDenseMaxRunes hold at every length:
	// the whitespace-only shape supplies (4); the singleByteNonSpace shape
	// supplies (2) because its byte length equals its rune length; the
	// unprintableNonSpace shape supplies (3); any of the attributed shapes
	// supplies (1). The three single-qualifier shapes additionally put the
	// one non-space rune at the start, the end and the middle of a
	// whitespace run, so a constraint sensitive to WHERE the qualifying
	// rune sits is exercised rather than only one sensitive to whether one
	// exists. At n = 1 those three coincide, which is harmless.
	for n := 1; n <= clockSourceDenseMaxRunes; n++ {
		add(build(n, func(int) rune { return pick(spaces) }))
		add(build(n, func(int) rune { return pick(singleByteNonSpace) }))
		add(build(n, func(int) rune { return pick(unprintableNonSpace) }))
		for _, position := range []int{0, n - 1, n / 2} {
			qualifierAt := position
			add(build(n, func(i int) rune {
				if i == qualifierAt {
					return pick(unprintableNonSpace)
				}
				return pick(spaces)
			}))
		}
		add(build(n, func(int) rune {
			if prng.IntN(2) == 0 {
				return pick(spaces)
			}
			return pick(nonSpaces)
		}))
	}

	// (C) The long ladder, four shapes per length.
	for _, n := range clockSourceLongRuneLengths {
		length := n
		add(build(length, func(int) rune { return pick(spaces) }))
		add(build(length, func(int) rune { return pick(singleByteNonSpace) }))
		add(build(length, func(i int) rune {
			if i == 0 {
				return pick(unprintableNonSpace)
			}
			return pick(spaces)
		}))
		add(build(length, func(i int) rune {
			if i == length-1 {
				return pick(unprintableNonSpace)
			}
			return pick(spaces)
		}))
	}

	// (D) The random battery. Lengths are drawn from a mixture weighted
	// towards short strings, because that is where boundary behaviour
	// lives, while still reaching the dense maximum.
	for i := 0; i < clockSourceRandomStrings; i++ {
		var n int
		switch prng.IntN(4) {
		case 0:
			n = prng.IntN(9)
		case 1:
			n = prng.IntN(33)
		case 2:
			n = prng.IntN(65)
		default:
			n = prng.IntN(clockSourceDenseMaxRunes + 1)
		}
		switch prng.IntN(5) {
		case 0:
			add(build(n, func(int) rune { return pick(spaces) }))
		case 1:
			add(build(n, func(int) rune { return pick(nonSpaces) }))
		case 2:
			add(build(n, func(int) rune {
				if prng.IntN(2) == 0 {
					return pick(spaces)
				}
				return pick(nonSpaces)
			}))
		case 3:
			// Drawn from the WHOLE rune domain rather than the curated
			// pools, so the battery is not confined to runes someone
			// thought to list.
			add(build(n, func(int) rune { return randomValidRune() }))
		default:
			if n == 0 {
				add("")
				continue
			}
			at := prng.IntN(n)
			add(build(n, func(i int) rune {
				if i == at {
					return pick(nonSpaces)
				}
				return pick(spaces)
			}))
		}
	}

	// (E) Realistic sources and regression witnesses, including lengths
	// just past the dense ladder.
	for _, source := range []string{
		"/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
		"SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT",
		"lscpu --json", " turbostat ", "a", " x ",
		"   ", "\r\n", " \t\n 　 ",
		"Ω", "ሴ", "日", "\U0001f600", " Ω ", "  ሴ\t",
		strings.Repeat("Ω", 300),
		strings.Repeat(" ", 300),
		strings.Repeat(" ", 299) + "Ω",
	} {
		add(source)
	}
	return corpus
}

// TestSchemaAndGoAgreeOnClockSourceForGeneratedStrings tests the property
// that actually matters -- for a source string s, schema-accepts(s) equals
// Go-accepts(s) -- DIRECTLY, on strings, rather than on single runes plus a
// structural argument that the single-rune result lifts.
//
// WHY THIS EXISTS. The every-rune sweep proves a fact about single runes.
// Everything beyond that was carried by a guard asserting the schema was
// shaped so the single-rune fact generalised, and that guard is what review
// round 5 broke, with a `then.allOf` carrying a large maxLength. (Rounds 3
// and 4 found the sweep itself sampling proxies rather than driving the real
// seams; that is a different defect, fixed at fcca87c, and the sweep here
// drives the same real seams for the same reason.) A length constraint is the
// clean counterexample class for the single-rune approach, because no
// single-rune probe can see one at all: every one-rune source has length 1,
// so maxLength: 64 changes no single-rune verdict and leaves the whole sweep
// green while rejecting Go-valid sources.
//
// REPRODUCED BEFORE THIS TEST WAS WRITTEN, exactly as the finding described
// it. Adding to the schema root's `then`:
//
//	"allOf": [{"properties": {"run_validity_observations": {"properties":
//	  {"observed_cpu_clock": {"properties": {"source": {"maxLength": 64}}}}}}}]
//
// makes the schema reject a 65-character Go-valid source -- read directly at
// the seam: "at '/run_validity_observations/observed_cpu_clock/source':
// maxLength: got 65, want 64" -- and yet `go test -count=1 ./...` at fcca87c
// stayed at exit 0, 28 ok, 3 no-test, 0 FAIL. The same mutation now fails
// this test.
//
// The two seams are the same two the every-rune sweep drives, for the same
// reasons: the schema side compiles the canonical schema with the production
// compileCanonicalSchema and reads its verdict through the production
// validateDecodedValue, and the Go side calls EnforceRunValidity with no
// stand-in. The same leaf-reassignment shortcut is used, and is verified per
// string rather than assumed: every source is round-tripped through
// jsonschema's own decoder and the sweep fails if any does not come back
// identical.
//
// WHAT THIS TEST DOES NOT DO. It is a bounded battery, not a proof. It does
// not establish agreement on every string; it establishes agreement on the
// generated corpus, whose bounds are stated on clockSourceDenseMaxRunes,
// clockSourceRandomStrings and clockSourceLongRuneLengths and are logged on
// every run. A constraint sensitive only to a length above the largest one
// swept, or to a rune combination no generated string realises, would pass
// it. That residual is recorded in docs/us008-attestation-package.md.
func TestSchemaAndGoAgreeOnClockSourceForGeneratedStrings(t *testing.T) {
	corpus := clockSourceCorpus(t)

	// NON-VACUITY, computed on the real Go seam and checked BEFORE the
	// expensive sweep so a corpus that lost its discriminating power fails
	// fast and loudly. Each map is keyed by the length at which the
	// property holds, because "the corpus has some accepted strings" is
	// not enough: a maxLength at length n is only visible if the corpus
	// holds a Go-ACCEPTED string of exactly that length.
	acceptedByRunes := map[int]int{}
	acceptedByBytes := map[int]int{}
	acceptedWithoutASCII := map[int]int{}
	rejectedByRunes := map[int]int{}
	goAccepted, goRejected, longestRunes, longestBytes := 0, 0, 0, 0
	for _, source := range corpus {
		runes := utf8.RuneCountInString(source)
		if runes > longestRunes {
			longestRunes = runes
		}
		if len(source) > longestBytes {
			longestBytes = len(source)
		}
		observations := cleanObservations()
		observations.ObservedCPUClock = &ObservedCPUClock{Source: source, SamplesMHz: []float64{3200}}
		if _, err := EnforceRunValidity(observations); err != nil {
			goRejected++
			rejectedByRunes[runes]++
			continue
		}
		goAccepted++
		acceptedByRunes[runes]++
		acceptedByBytes[len(source)]++
		printableASCII := false
		for _, r := range source {
			if r >= 0x21 && r <= 0x7E {
				printableASCII = true
				break
			}
		}
		if !printableASCII {
			acceptedWithoutASCII[runes]++
		}
	}
	if acceptedByRunes[0] != 0 {
		t.Fatalf("the Go seam accepted %d zero-length sources: the empty string must be rejected and the corpus census is measuring the wrong thing", acceptedByRunes[0])
	}
	if rejectedByRunes[0] == 0 {
		t.Fatal("the corpus holds no empty source: the one input with no runes is not covered")
	}
	for n := 1; n <= clockSourceDenseMaxRunes; n++ {
		if acceptedByRunes[n] == 0 {
			t.Fatalf("the corpus holds no Go-ACCEPTED source of rune length %d: a maxLength or minLength at that length would be invisible to this test", n)
		}
		if acceptedByBytes[n] == 0 {
			t.Fatalf("the corpus holds no Go-ACCEPTED source of BYTE length %d: a length constraint counting bytes rather than runes would be invisible to this test", n)
		}
		if acceptedWithoutASCII[n] == 0 {
			t.Fatalf("the corpus holds no Go-ACCEPTED source of rune length %d free of printable ASCII: a pattern narrowed to [!-~] would be invisible at that length", n)
		}
		if rejectedByRunes[n] == 0 {
			t.Fatalf("the corpus holds no Go-REJECTED source of rune length %d: the rejection half of the property is not covered at that length", n)
		}
	}
	for _, n := range clockSourceLongRuneLengths {
		if acceptedByRunes[n] == 0 {
			t.Fatalf("the corpus holds no Go-ACCEPTED source of rune length %d: a maxLength at that length would be invisible to this test", n)
		}
		if rejectedByRunes[n] == 0 {
			t.Fatalf("the corpus holds no Go-REJECTED source of rune length %d", n)
		}
	}
	// The corpus digest is LOGGED, never asserted. Logged so that two runs
	// can be compared and "seeded deterministically" is observable rather
	// than claimed; never asserted because math/rand/v2 guarantees the PCG
	// bit stream but NOT the mapping from that stream to IntN results
	// across Go releases, so pinning the digest would turn a toolchain
	// upgrade into a spurious failure. Nothing this test proves depends on
	// the digest: every coverage property it relies on is recomputed from
	// the corpus above on every run.
	digest := sha256.New()
	for _, source := range corpus {
		fmt.Fprintf(digest, "%d:%s\n", len(source), source)
	}
	t.Logf("generated corpus: %d sources, %d Go-accepted / %d Go-rejected, dense rune lengths 0-%d, long lengths %v, longest %d runes / %d bytes, PCG seed %#016x/%#016x, corpus sha256 %x (logged, not asserted; %s)",
		len(corpus), goAccepted, goRejected, clockSourceDenseMaxRunes, clockSourceLongRuneLengths, longestRunes, longestBytes,
		clockSourceCorpusSeedHi, clockSourceCorpusSeedLo, digest.Sum(nil), runtime.Version())

	document, _, _ := measuredSchemaDocument(t)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	workers := runtime.NumCPU()
	type shard struct {
		compared      int
		disagreements []int
		roundTripBad  []int
		err           error
	}
	shards := make([]shard, workers)
	var waiting sync.WaitGroup
	for w := 0; w < workers; w++ {
		waiting.Add(1)
		go func(w int) {
			defer waiting.Done()
			out := &shards[w]

			schema, err := compileCanonicalSchema(repoRoot, "benchmark-raw-sample-1.0.0.schema.json")
			if err != nil {
				out.err = err
				return
			}
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
			if err != nil {
				out.err = err
				return
			}
			root, ok := value.(map[string]any)
			if !ok {
				out.err = fmt.Errorf("decoded document is %T, want an object", value)
				return
			}
			leaf, ok := root["run_validity_observations"].(map[string]any)["observed_cpu_clock"].(map[string]any)
			if !ok {
				out.err = fmt.Errorf("decoded document has no observed_cpu_clock object")
				return
			}
			observations := cleanObservations()
			clock := &ObservedCPUClock{SamplesMHz: []float64{3200}}
			observations.ObservedCPUClock = clock

			for i := w; i < len(corpus); i += workers {
				out.compared++
				source := corpus[i]

				sourceJSON, err := json.Marshal(source)
				if err != nil {
					out.err = err
					return
				}
				decoded, err := jsonschema.UnmarshalJSON(bytes.NewReader(sourceJSON))
				if err != nil {
					out.err = err
					return
				}
				if decoded != any(source) {
					out.roundTripBad = append(out.roundTripBad, i)
					continue
				}

				leaf["source"] = source
				schemaAccepts := len(validateDecodedValue(schema, value)) == 0

				clock.Source = source
				_, goErr := EnforceRunValidity(observations)

				if schemaAccepts != (goErr == nil) {
					out.disagreements = append(out.disagreements, i)
				}
			}
		}(w)
	}
	waiting.Wait()

	compared := 0
	var disagreements, roundTripBad []int
	for w := range shards {
		if shards[w].err != nil {
			t.Fatalf("sweep worker %d failed: %v", w, shards[w].err)
		}
		compared += shards[w].compared
		disagreements = append(disagreements, shards[w].disagreements...)
		roundTripBad = append(roundTripBad, shards[w].roundTripBad...)
	}
	if len(roundTripBad) > 0 {
		sort.Ints(roundTripBad)
		t.Fatalf("%d generated sources do not survive a JSON round trip through jsonschema's decoder (first at corpus index %d); the leaf-reassignment shortcut is unsound and the sweep result means nothing",
			len(roundTripBad), roundTripBad[0])
	}
	if compared != len(corpus) {
		t.Fatalf("swept %d sources, want exactly %d: the sweep did not cover the corpus and its result means nothing", compared, len(corpus))
	}
	t.Logf("compared the canonical schema against EnforceRunValidity on all %d generated sources across %d workers", compared, workers)

	if len(disagreements) > 0 {
		sort.Ints(disagreements)
		shown := disagreements
		if len(shown) > 10 {
			shown = shown[:10]
		}
		var detail []string
		for _, i := range shown {
			detail = append(detail, describeClockSource(corpus[i]))
		}
		t.Fatalf("the canonical raw-sample schema and Go's unicode.IsSpace contract disagree on %d of %d generated sources; first %d: %s",
			len(disagreements), compared, len(shown), strings.Join(detail, "; "))
	}
}

// describeClockSource renders a corpus witness compactly enough to read in a
// failure message and precisely enough to reconstruct: both lengths, and a
// quoted prefix truncated on a RUNE boundary so the quoting never shows a
// split code point.
func describeClockSource(source string) string {
	prefix := source
	if utf8.RuneCountInString(prefix) > 24 {
		count := 0
		for i := range prefix {
			if count == 24 {
				prefix = prefix[:i]
				break
			}
			count++
		}
	}
	suffix := ""
	if prefix != source {
		suffix = "..."
	}
	return fmt.Sprintf("%d runes / %d bytes %q%s", utf8.RuneCountInString(source), len(source), prefix, suffix)
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return absolute
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

func setEnvironmentBindingStatuses(t *testing.T, root, environmentStatus string) {
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

// syntheticIndependentAttestor is the clearly-labeled SYNTHETIC attestor
// identity used only to exercise the verification path. It is not a real
// attestation, no independent review happened, and the real document
// never carries it (the real plan stays OWNER_ATTESTED).
const syntheticIndependentAttestor = "synthetic-independent-attestor (SYNTHETIC_TEST_FIXTURE_NOT_A_REAL_ATTESTATION)"

// attestIndependentlyForTest installs a well-formed but SYNTHETIC
// independent attestation on a copied tree: the state/status/label
// pairing plus the independent-specific evidence the schema and the
// validator require (attestor identity distinct from the owner,
// record-level independent_review_claimed true, attestor record digest
// and date). Test-only shape exercise — not a real attestation.
func attestIndependentlyForTest(t *testing.T, root string) {
	t.Helper()
	mutatePlan(t, root, func(plan map[string]any) {
		plan["attestation_state"] = "INDEPENDENTLY_ATTESTED"
		plan["status"] = "PREREGISTERED_INDEPENDENTLY_ATTESTED - test scenario: synthetic independent attestation (verification-path exercise only, not a real attestation)"
		plan["assurance"] = "INDEPENDENTLY_ATTESTED"
		plan["independent_review_claimed"] = true
		record := plan["attestation_record"].(map[string]any)
		record["assurance"] = "INDEPENDENTLY_ATTESTED"
		record["independent_review_claimed"] = true
		record["independent_attestor_identity"] = syntheticIndependentAttestor
		record["independent_attestation_record_sha256"] = strings.Repeat("ab", 32)
		record["independent_attested_at"] = "2026-08-27T00:00:00Z"
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

// Review fix I5, positive direction (re-review round 1: independent
// evidence required): with every field bound, both environments BOUND,
// and a well-formed SYNTHETIC independent attestation record installed
// (clearly labeled synthetic; not a real attestation), verification
// reports fully bound — proving the independent record SHAPE is
// satisfiable while a relabeled owner record never is.
func TestVerifyFullyBoundAndAttestedTreeVerifies(t *testing.T) {
	root := copyBenchmarkTree(t)
	bindAllPendingFields(t, root)
	setEnvironmentBindingStatuses(t, root, "BOUND")
	attestIndependentlyForTest(t, root)
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
	if report.PlanAttestationState != "INDEPENDENTLY_ATTESTED" {
		t.Errorf("plan attestation state %q, want INDEPENDENTLY_ATTESTED", report.PlanAttestationState)
	}
}

// Re-review round 1 (session 01a04165, BLOCKING): FullyBound with the
// owner-only record merely RELABELED to INDEPENDENTLY_ATTESTED must
// never be reachable — not by a state/status edit alone, and not even
// with the top-level document labels promoted too. The independent
// state demands independent-specific evidence the owner-only record
// structurally cannot provide.
func TestVerifyRelabeledOwnerRecordNeverFullyBound(t *testing.T) {
	relabels := []struct {
		name   string
		mutate func(plan map[string]any)
	}{
		{"state and status strings only", func(plan map[string]any) {
			plan["attestation_state"] = "INDEPENDENTLY_ATTESTED"
			plan["status"] = "PREREGISTERED_INDEPENDENTLY_ATTESTED - test scenario: relabel-only promotion"
		}},
		{"state, status, and top-level labels", func(plan map[string]any) {
			plan["attestation_state"] = "INDEPENDENTLY_ATTESTED"
			plan["status"] = "PREREGISTERED_INDEPENDENTLY_ATTESTED - test scenario: relabel with promoted labels"
			plan["assurance"] = "INDEPENDENTLY_ATTESTED"
			plan["independent_review_claimed"] = true
		}},
	}
	for _, relabel := range relabels {
		t.Run(relabel.name, func(t *testing.T) {
			root := copyBenchmarkTree(t)
			bindAllPendingFields(t, root)
			setEnvironmentBindingStatuses(t, root, "BOUND")
			mutatePlan(t, root, relabel.mutate)
			report, err := Verify(root)
			if err != nil {
				t.Fatal(err)
			}
			if report.FullyBound() {
				t.Fatal("a relabeled owner-only record must NEVER verify as fully bound (exit 0 unreachable by a string edit)")
			}
			if len(report.SchemaFailures["benchmarks/plan/workloads.json"]) == 0 {
				t.Error("the schema must reject an INDEPENDENTLY_ATTESTED state carried by an owner-only record")
			}
			if len(report.PlanFailures) == 0 {
				t.Error("the spec cross-check must reject an INDEPENDENTLY_ATTESTED state carried by an owner-only record with a typed finding")
			}
		})
	}
}

// The independent attestor can never be the owner: a synthetic record
// that is otherwise well-formed but names the owner identity as the
// independent attestor must fail the validator (self-attestation is
// owner-only by definition), and the tree must not verify fully bound.
func TestVerifyIndependentSelfAttestationRejected(t *testing.T) {
	root := copyBenchmarkTree(t)
	bindAllPendingFields(t, root)
	setEnvironmentBindingStatuses(t, root, "BOUND")
	attestIndependentlyForTest(t, root)
	mutatePlan(t, root, func(plan map[string]any) {
		record := plan["attestation_record"].(map[string]any)
		record["independent_attestor_identity"] = OwnerIdentity
	})
	report, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.FullyBound() {
		t.Fatal("an owner self-attestation labeled independent must never verify as fully bound")
	}
	found := false
	for _, failure := range report.PlanFailures {
		if strings.Contains(failure, "owner identity") {
			found = true
		}
	}
	if !found {
		t.Fatalf("plan failures must name the owner-identity conflict, got %v", report.PlanFailures)
	}
}

// A document claiming BOUND while its fields are still pending is an
// inconsistency, never progress.
func TestVerifyBoundStatusWithPendingFieldsIsInconsistent(t *testing.T) {
	root := copyBenchmarkTree(t)
	setEnvironmentBindingStatuses(t, root, "BOUND")
	attestIndependentlyForTest(t, root)
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
