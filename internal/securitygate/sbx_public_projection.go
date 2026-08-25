package securitygate

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

type ProtectedCPUCounters struct {
	UsageUsec  int64 `json:"usage_usec"`
	UserUsec   int64 `json:"user_usec"`
	SystemUsec int64 `json:"system_usec"`
}

type ProtectedMemoryEvents struct {
	Low     int64 `json:"low"`
	High    int64 `json:"high"`
	Max     int64 `json:"max"`
	OOM     int64 `json:"oom"`
	OOMKill int64 `json:"oom_kill"`
}

type ProtectedCgroupReadback struct {
	MemoryMax     int64                 `json:"memory_max"`
	MemorySwapMax int64                 `json:"memory_swap_max"`
	MemoryOOM     int64                 `json:"memory_oom_group"`
	PIDsMax       int64                 `json:"pids_max"`
	CPU           ProtectedCPUCounters  `json:"cpu_stat"`
	MemoryEvents  ProtectedMemoryEvents `json:"memory_events"`
	MemoryCurrent int64                 `json:"memory_current"`
	MemoryPeak    int64                 `json:"memory_peak"`
	PIDsCurrent   int64                 `json:"pids_current"`
	PIDsEventsMax int64                 `json:"pids_events_max"`
	Populated     int64                 `json:"populated"`
	Frozen        int64                 `json:"frozen"`
	Procs         string                `json:"cgroup_procs"`
}

type ProtectedDescriptorObservation struct {
	SchemaVersion            string                         `json:"schema_version"`
	DescriptorID             string                         `json:"descriptor_id"`
	DescriptorDigest         string                         `json:"descriptor_digest"`
	SupervisorDigest         string                         `json:"supervisor_digest"`
	SupervisorDigestReopened string                         `json:"supervisor_digest_reopened"`
	RuntimeIdentity          string                         `json:"runtime_identity"`
	SBXIdentity              string                         `json:"sbx_identity"`
	SourceCommit             string                         `json:"source_commit"`
	SourceTree               string                         `json:"source_tree"`
	Preflight                SupervisorCapabilityPreflight  `json:"capability_preflight"`
	Envelope                 resources                      `json:"compiled_envelope"`
	Mechanics                SupervisorEnforcementMechanics `json:"enforcement_mechanics"`
	CgroupInitial            ProtectedCgroupReadback        `json:"cgroup_initial"`
	CgroupFinal              ProtectedCgroupReadback        `json:"cgroup_final"`
	RLimits                  SupervisorRLimitObservation    `json:"rlimits_reopened"`
	Identity                 SupervisorIdentityObservation  `json:"identity_reopened"`
	Mounts                   []SupervisorMountObservation   `json:"mounts_reopened"`
	RootMountInfo            string                         `json:"root_mountinfo_reopened"`
	SourceMountInfo          string                         `json:"source_mountinfo_reopened"`
	CompleteMountInfo        string                         `json:"complete_mountinfo_reopened"`
	CompleteMountInfoDigest  string                         `json:"complete_mountinfo_digest"`
	Peaks                    SupervisorPeakObservation      `json:"peaks"`
	StdoutDigest             string                         `json:"stdout_digest"`
	StderrDigest             string                         `json:"stderr_digest"`
	Termination              string                         `json:"termination"`
	ParentWaitStatus         string                         `json:"parent_wait_status"`
	ExitCode                 *int                           `json:"exit_code"`
	Signal                   string                         `json:"signal"`
	WallDurationNanos        int64                          `json:"wall_duration_nanos"`
	Cleanup                  SupervisorCleanupObservation   `json:"cleanup"`
	Artifact                 SupervisorArtifactObservation  `json:"artifact"`
	Assurance                string                         `json:"assurance"`
	IndependentReviewClaimed bool                           `json:"independent_review_claimed"`
	AutobahnReruns           int                            `json:"autobahn_reruns"`
}

type ProtectedProjectionRequest struct {
	AttemptID                string `json:"attempt_id"`
	TargetCommit             string `json:"target_commit"`
	SourceTree               string `json:"source_tree"`
	FixedPlanDigest          string `json:"fixed_plan_digest"`
	ProfileDigest            string `json:"profile_digest"`
	PolicyDigest             string `json:"policy_digest"`
	AcceptedRootDigest       string `json:"accepted_root_digest"`
	InventoryRootDigest      string `json:"inventory_root_digest"`
	InputRoot                string `json:"input_root"`
	OutputRoot               string `json:"output_root"`
	PrivilegedExecArgvDigest string `json:"privileged_exec_argv_digest"`
}

type ProtectedProjectionRuntime struct {
	CLIPath                string `json:"cli_path"`
	CLIBinaryDigest        string `json:"cli_binary_digest"`
	CLIVersionOutputDigest string `json:"cli_version_output_digest"`
	CLIVersion             string `json:"cli_version"`
	CLICommit              string `json:"cli_commit"`
	DaemonStatusDigest     string `json:"daemon_status_digest"`
	DaemonVersion          string `json:"daemon_version"`
	DaemonCommit           string `json:"daemon_commit"`
	Template               string `json:"template"`
	SandboxName            string `json:"sandbox_name"`
	PrivilegeLifecycle     string `json:"privilege_lifecycle"`
}

type ProtectedProjectionArtifact struct {
	Digest string `json:"digest"`
	Bytes  int64  `json:"bytes"`
	Path   string `json:"path"`
}
type ProtectedProjectionOutput struct {
	SupervisorReceiptsDigest  string `json:"supervisor_receipts_digest"`
	InspectDigest             string `json:"inspect_digest"`
	PolicyListDigest          string `json:"policy_list_digest"`
	ExamplePolicyCheckDigest  string `json:"example_policy_check_digest"`
	ProviderPolicyCheckDigest string `json:"provider_policy_check_digest"`
}
type ProtectedProjectionCleanup struct {
	RemoveDigest  string `json:"remove_digest"`
	AbsenceDigest string `json:"absence_digest"`
	SandboxAbsent bool   `json:"sandbox_absent"`
}

type ProtectedPublicProjection struct {
	SchemaVersion            string                           `json:"schema_version"`
	Request                  ProtectedProjectionRequest       `json:"request"`
	Runtime                  ProtectedProjectionRuntime       `json:"runtime"`
	StartedAt                string                           `json:"started_at"`
	FinishedAt               string                           `json:"finished_at"`
	Artifact                 ProtectedProjectionArtifact      `json:"artifact"`
	Output                   ProtectedProjectionOutput        `json:"output"`
	Cleanup                  ProtectedProjectionCleanup       `json:"cleanup"`
	DescriptorObservations   []ProtectedDescriptorObservation `json:"descriptor_observations"`
	Assurance                string                           `json:"assurance"`
	IndependentReviewClaimed bool                             `json:"independent_review_claimed"`
	AutobahnReruns           int                              `json:"autobahn_reruns"`
}

type ProtectedPublicProjectionEnvelope struct {
	Projection      ProtectedPublicProjection `json:"projection"`
	CanonicalDigest string                    `json:"canonical_digest"`
}

func DecodeProtectedPublicProjection(data []byte) (ProtectedPublicProjectionEnvelope, error) {
	var envelope ProtectedPublicProjectionEnvelope
	if err := intake.DecodeStrict(data, &envelope); err != nil {
		return ProtectedPublicProjectionEnvelope{}, fmt.Errorf("PUBLIC_PROJECTION_INVALID/QUARANTINE: %w", err)
	}
	canonical, err := intake.CanonicalJSON(envelope.Projection)
	if err != nil || envelope.CanonicalDigest != intake.DigestBytes(canonical) {
		return ProtectedPublicProjectionEnvelope{}, errors.New("PUBLIC_PROJECTION_DIGEST_DRIFT/QUARANTINE")
	}
	if err := validateProtectedPublicProjection(envelope.Projection); err != nil {
		return ProtectedPublicProjectionEnvelope{}, err
	}
	return envelope, nil
}

func validateProtectedPublicProjection(projection ProtectedPublicProjection) error {
	request, runtime := projection.Request, projection.Runtime
	if projection.SchemaVersion != policyVersion || request.AttemptID != "us007-sbx-output-live-0012" || !sbxGitObjectPattern.MatchString(request.TargetCommit) || !sbxGitObjectPattern.MatchString(request.SourceTree) || request.FixedPlanDigest != protectedFixedPlanDigest() || !isSHA256Digest(request.ProfileDigest) || !isSHA256Digest(request.PolicyDigest) || !isSHA256Digest(request.AcceptedRootDigest) || !isSHA256Digest(request.InventoryRootDigest) || request.InputRoot != "/Users/mikelady/hq/workspace/worktrees/verified-java-websocket-port/us007-resource-supervisor" || request.OutputRoot != "/Users/mikelady/hq/workspace/orchestrator/verified-java-websocket-port/protected/us007-sbx-output-live-0012" || request.PrivilegedExecArgvDigest != protectedPrivilegedExecDigest() {
		return errors.New("PUBLIC_PROJECTION_REQUEST_INVALID/QUARANTINE")
	}
	if runtime.CLIPath != "/opt/homebrew/Caskroom/sbx/0.39.0/bin/sbx" || runtime.CLIBinaryDigest != "sha256:f2a9e83f41a1cc20292d1f0e40974c495065f59a933aaec98f0619c286ddbeaf" || !isSHA256Digest(runtime.CLIVersionOutputDigest) || runtime.CLIVersion != "v0.39.0" || runtime.CLICommit != "def8cb0523a77e757bdd6ef52b459fe374f3783e" || !isSHA256Digest(runtime.DaemonStatusDigest) || runtime.DaemonVersion != "v0.39.0" || runtime.DaemonCommit != runtime.CLICommit || runtime.Template != "docker.io/docker/sandbox-templates:shell@sha256:1e642f7fadebcbff3d8de67114e9b42a5971ba9b4287ebffa1d05662f5a0f5ec" || runtime.SandboxName != "us007-resource-envelope-0012" || runtime.PrivilegeLifecycle == "" {
		return errors.New("PUBLIC_PROJECTION_RUNTIME_INVALID/QUARANTINE")
	}
	started, e1 := time.Parse(time.RFC3339Nano, projection.StartedAt)
	finished, e2 := time.Parse(time.RFC3339Nano, projection.FinishedAt)
	if e1 != nil || e2 != nil || finished.Before(started) || !isSHA256Digest(projection.Artifact.Digest) || projection.Artifact.Bytes <= 0 || projection.Artifact.Path == "" || !isSHA256Digest(projection.Output.SupervisorReceiptsDigest) || !isSHA256Digest(projection.Output.InspectDigest) || !isSHA256Digest(projection.Output.PolicyListDigest) || !isSHA256Digest(projection.Output.ExamplePolicyCheckDigest) || !isSHA256Digest(projection.Output.ProviderPolicyCheckDigest) || !isSHA256Digest(projection.Cleanup.RemoveDigest) || !isSHA256Digest(projection.Cleanup.AbsenceDigest) || !projection.Cleanup.SandboxAbsent || projection.Assurance != AssuranceOwnerOnly || projection.IndependentReviewClaimed || projection.AutobahnReruns != 0 {
		return errors.New("PUBLIC_PROJECTION_OBSERVATION_INVALID/QUARANTINE")
	}
	plan := protectedFixedPlan()
	if len(projection.DescriptorObservations) != len(plan) {
		return errors.New("PUBLIC_PROJECTION_DESCRIPTOR_COUNT_INVALID/QUARANTINE")
	}
	limits := exactProtectedEnvelope()
	for index, observation := range projection.DescriptorObservations {
		digest, expectation, err := sbxDescriptorContract(plan[index])
		if err != nil || observation.SchemaVersion != policyVersion || observation.DescriptorID != plan[index] || observation.DescriptorDigest != digest || observation.SupervisorDigest != observation.SupervisorDigestReopened || !isSHA256Digest(observation.SupervisorDigest) || observation.SourceCommit != request.TargetCommit || observation.SourceTree != request.SourceTree || observation.Envelope != limits || observation.Assurance != AssuranceOwnerOnly || observation.IndependentReviewClaimed || observation.AutobahnReruns != 0 {
			return errors.New("PUBLIC_PROJECTION_DESCRIPTOR_BINDING_INVALID/QUARANTINE")
		}
		converted := protectedObservationToSupervisor(observation)
		if err := validateProjectedObservationMechanics(converted, limits); err != nil {
			return err
		}
		if err := validateSBXDescriptorOutcome(observation.DescriptorID, expectation, converted, limits); err != nil {
			return err
		}
	}
	benign := projection.DescriptorObservations[len(plan)-1].Artifact
	if projection.Artifact.Digest != benign.ParentDigest || projection.Artifact.Bytes != benign.Bytes {
		return errors.New("PUBLIC_PROJECTION_ARTIFACT_DRIFT/QUARANTINE")
	}
	return nil
}

func exactProtectedEnvelope() resources {
	return resources{WallSeconds: 120, CPUSeconds: 60, MemoryBytes: 536870912, PIDs: 64, OpenFiles: 256, OutputBytes: 8388608, WorkspaceBytes: 67108864, CacheBytes: 67108864, DiskBytes: 134217728, Inodes: 8192}
}

func protectedFixedPlan() []string {
	return []string{"CACHE_WRITE_DENIED", "CLEAN_EXIT", "CPU_BOUND", "ENV_SENTINEL_ABSENT", "FD_BOUND", "MEMORY_BOUND", "NETWORK_SOCKET_DENIED", "OUTPUT_BOUND", "PID_BOUND", "PROTECTED_SENTINEL_DENIED", "SOURCE_WRITE_DENIED", "WALL_BOUND", "WORKSPACE_BOUND", "BENIGN_OPERATION"}
}

func protectedFixedPlanDigest() string {
	type descriptor struct {
		ID              string `json:"id"`
		ProgramKey      string `json:"program_key"`
		ExpectedOutcome string `json:"expected_outcome"`
	}
	items := make([]descriptor, 0, len(protectedFixedPlan()))
	for _, id := range protectedFixedPlan() {
		digest, expectation, _ := sbxDescriptorContract(id)
		_ = digest
		keys := map[string]string{"CACHE_WRITE_DENIED": "cache", "CLEAN_EXIT": "clean", "CPU_BOUND": "cpu", "ENV_SENTINEL_ABSENT": "secret", "FD_BOUND": "fd", "MEMORY_BOUND": "memory", "NETWORK_SOCKET_DENIED": "network", "OUTPUT_BOUND": "output", "PID_BOUND": "pid", "PROTECTED_SENTINEL_DENIED": "protected", "SOURCE_WRITE_DENIED": "source", "WALL_BOUND": "wall", "WORKSPACE_BOUND": "workspace", "BENIGN_OPERATION": "benign"}
		items = append(items, descriptor{id, keys[id], expectation})
	}
	data, _ := json.Marshal(items)
	return intake.DigestBytes(data)
}

func protectedPrivilegedExecDigest() string {
	data, _ := json.Marshal([]string{"/opt/homebrew/Caskroom/sbx/0.39.0/bin/sbx", "exec", "--privileged", "-u", "root", "us007-resource-envelope-0012", "/tmp/us007-resource-supervisor"})
	return intake.DigestBytes(data)
}

func protectedObservationToSupervisor(value ProtectedDescriptorObservation) SupervisorObservation {
	flatten := func(c ProtectedCgroupReadback) SupervisorCgroupObservation {
		return SupervisorCgroupObservation{MemoryMaxBytes: c.MemoryMax, MemorySwapMax: c.MemorySwapMax, MemoryOOMGroup: c.MemoryOOM, PIDsMax: c.PIDsMax, CPUUsageUsec: c.CPU.UsageUsec, CPUUserUsec: c.CPU.UserUsec, CPUSystemUsec: c.CPU.SystemUsec, MemoryEventsMax: c.MemoryEvents.Max, MemoryEventsOOM: c.MemoryEvents.OOM, MemoryEventsKill: c.MemoryEvents.OOMKill, MemoryCurrent: c.MemoryCurrent, MemoryPeak: c.MemoryPeak, PIDsCurrent: c.PIDsCurrent, PIDsEventsMax: c.PIDsEventsMax}
	}
	return SupervisorObservation{DescriptorDigest: value.DescriptorDigest, SupervisorDigestReopened: value.SupervisorDigestReopened, RuntimeIdentity: value.RuntimeIdentity, SBXIdentity: value.SBXIdentity, SourceCommit: value.SourceCommit, SourceTree: value.SourceTree, CapabilityPreflight: value.Preflight, EnforcementMechanics: value.Mechanics, CgroupInitial: flatten(value.CgroupInitial), CgroupFinal: flatten(value.CgroupFinal), RLimits: value.RLimits, Identity: value.Identity, Mounts: value.Mounts, RootMountInfo: value.RootMountInfo, SourceMountInfo: value.SourceMountInfo, CompleteMountInfo: value.CompleteMountInfo, CompleteMountInfoDigest: value.CompleteMountInfoDigest, Peaks: value.Peaks, StdoutDigest: value.StdoutDigest, StderrDigest: value.StderrDigest, Termination: value.Termination, ParentWaitStatus: value.ParentWaitStatus, ParentExitCode: value.ExitCode, ParentSignal: value.Signal, WallDurationNanos: value.WallDurationNanos, Cleanup: value.Cleanup, Artifact: value.Artifact, Assurance: value.Assurance, IndependentReviewClaimed: value.IndependentReviewClaimed, AutobahnReruns: value.AutobahnReruns}
}

func validateProjectedObservationMechanics(observation SupervisorObservation, limits resources) error {
	if observation.EnforcementMechanics != (SupervisorEnforcementMechanics{RLimitFSizeBytes: 134217728, CPUKillThresholdUsec: 58000000, WallKillThresholdNS: 119000000000, CgroupPIDsMax: 56}) || observation.CgroupInitial.MemoryMaxBytes != limits.MemoryBytes || observation.CgroupInitial.MemorySwapMax != 0 || observation.CgroupInitial.MemoryOOMGroup != 1 || observation.CgroupInitial.PIDsMax != 56 || observation.CgroupFinal.PIDsMax != 56 || observation.CgroupFinal.CPUUsageUsec < observation.CgroupInitial.CPUUsageUsec || observation.CgroupFinal.MemoryEventsMax < observation.CgroupInitial.MemoryEventsMax || observation.CgroupFinal.PIDsEventsMax < observation.CgroupInitial.PIDsEventsMax || observation.Identity.UID == 0 || observation.Identity.GID == 0 || observation.Identity.NoNewPrivs != 1 || observation.Identity.Seccomp == 0 || observation.Cleanup.CgroupProcsReopened != "<empty>" || observation.Cleanup.CgroupRemoval != "REMOVE_SUCCEEDED" || observation.CompleteMountInfoDigest != intake.DigestBytes([]byte(observation.CompleteMountInfo)) || validateSBXWritableMountClosure(observation.CompleteMountInfo) != nil {
		return errors.New("PUBLIC_PROJECTION_DESCRIPTOR_OBSERVATION_INVALID/QUARANTINE")
	}
	return nil
}
