package securitygate

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

// ProtectedDescriptorObservation intentionally aliases the candidate-side
// strict receipt shape. This prevents the public classifier and protected
// supervisor from drifting into parallel cgroup-era schemas.
type ProtectedDescriptorObservation = SupervisorObservation

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
	SupervisorDigest       string `json:"supervisor_digest"`
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
	expectedInputRoot := "/Users/mikelady/hq/workspace/orchestrator/verified-java-websocket-port/protected/us007-source-clone-" + request.TargetCommit
	expectedOutputRoot := "/Users/mikelady/hq/workspace/orchestrator/verified-java-websocket-port/protected/us007-sbx-output-live-0018"
	profileBytes, _ := json.Marshal(exactProtectedEnvelope())
	expectedProfileDigest := intake.DigestBytes(profileBytes)
	expectedAcceptedRoot := intake.DigestBytes([]byte("accepted-git-tree:" + request.SourceTree))
	expectedInventoryRoot := intake.DigestBytes([]byte("inventory-git-tree:" + request.SourceTree))
	if projection.SchemaVersion != policyVersion || request.AttemptID != "us007-sbx-output-live-0018" || !sbxGitObjectPattern.MatchString(request.TargetCommit) || !sbxGitObjectPattern.MatchString(request.SourceTree) || request.FixedPlanDigest != protectedFixedPlanDigest() || request.ProfileDigest != expectedProfileDigest || !isSHA256Digest(request.PolicyDigest) || request.PolicyDigest != projection.Output.PolicyListDigest || request.AcceptedRootDigest != expectedAcceptedRoot || request.InventoryRootDigest != expectedInventoryRoot || request.InputRoot != expectedInputRoot || request.OutputRoot != expectedOutputRoot || request.PrivilegedExecArgvDigest != protectedPrivilegedExecDigest() {
		return errors.New("PUBLIC_PROJECTION_REQUEST_INVALID/QUARANTINE")
	}
	if runtime.CLIPath != "/opt/homebrew/Caskroom/sbx/0.39.0/bin/sbx" || runtime.CLIBinaryDigest != "sha256:f2a9e83f41a1cc20292d1f0e40974c495065f59a933aaec98f0619c286ddbeaf" || !isSHA256Digest(runtime.CLIVersionOutputDigest) || runtime.CLIVersion != "v0.39.0" || runtime.CLICommit != "def8cb0523a77e757bdd6ef52b459fe374f3783e" || !isSHA256Digest(runtime.DaemonStatusDigest) || runtime.DaemonVersion != "v0.39.0" || runtime.DaemonCommit != runtime.CLICommit || runtime.Template != "docker.io/docker/sandbox-templates:shell@sha256:1e642f7fadebcbff3d8de67114e9b42a5971ba9b4287ebffa1d05662f5a0f5ec" || runtime.SandboxName != "us007-resource-envelope-0018" || !isSHA256Digest(runtime.SupervisorDigest) || runtime.PrivilegeLifecycle != "sbx exec privilege is fixed to the trusted supervisor; stage-2 drops UID/GID/capabilities, sets no_new_privs/seccomp, and is reopened before workload release" {
		return errors.New("PUBLIC_PROJECTION_RUNTIME_INVALID/QUARANTINE")
	}
	started, e1 := time.Parse(time.RFC3339Nano, projection.StartedAt)
	finished, e2 := time.Parse(time.RFC3339Nano, projection.FinishedAt)
	if e1 != nil || e2 != nil || finished.Before(started) || !isSHA256Digest(projection.Artifact.Digest) || projection.Artifact.Bytes <= 0 || projection.Artifact.Path != expectedOutputRoot+"/resource-envelope-artifact" || !isSHA256Digest(projection.Output.SupervisorReceiptsDigest) || !isSHA256Digest(projection.Output.InspectDigest) || !isSHA256Digest(projection.Output.PolicyListDigest) || !isSHA256Digest(projection.Output.ExamplePolicyCheckDigest) || !isSHA256Digest(projection.Output.ProviderPolicyCheckDigest) || !isSHA256Digest(projection.Cleanup.RemoveDigest) || !isSHA256Digest(projection.Cleanup.AbsenceDigest) || !projection.Cleanup.SandboxAbsent || projection.Assurance != AssuranceOwnerOnly || projection.IndependentReviewClaimed || projection.AutobahnReruns != 0 {
		return errors.New("PUBLIC_PROJECTION_OBSERVATION_INVALID/QUARANTINE")
	}
	plan := protectedFixedPlan()
	if len(projection.DescriptorObservations) != len(plan) {
		return errors.New("PUBLIC_PROJECTION_DESCRIPTOR_COUNT_INVALID/QUARANTINE")
	}
	limits := exactProtectedEnvelope()
	for index, observation := range projection.DescriptorObservations {
		digest, expectation, err := sbxDescriptorContract(plan[index])
		if err != nil || observation.SchemaVersion != policyVersion || observation.DescriptorID != plan[index] || observation.DescriptorDigest != digest || observation.SupervisorDigest != runtime.SupervisorDigest || observation.SupervisorDigest != observation.SupervisorDigestReopened || !isSHA256Digest(observation.SupervisorDigest) || observation.SourceCommit != request.TargetCommit || observation.SourceTree != request.SourceTree || observation.Envelope != limits || observation.Assurance != AssuranceOwnerOnly || observation.IndependentReviewClaimed || observation.AutobahnReruns != 0 {
			return errors.New("PUBLIC_PROJECTION_DESCRIPTOR_BINDING_INVALID/QUARANTINE")
		}
		_ = expectation
		candidateRequest := SbxExecutionRequest{CanaryID: observation.DescriptorID, SupervisorDigest: observation.SupervisorDigest, InputRoot: request.InputRoot}
		if err := validateSupervisorObservation(sbxExecutionProfile{SupervisorLimits: limits}, candidateRequest, observation); err != nil {
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
	return resources{WallSeconds: 60, CPUSeconds: 60, MemoryBytes: 1073741824, PIDs: 64, OpenFiles: 256, OutputBytes: 8388608, WorkspaceBytes: 67108864, CacheBytes: 67108864, DiskBytes: 67108864, Inodes: 16384}
}

func protectedFixedPlan() []string {
	return []string{"CACHE_WRITE_DENIED", "CLEAN_EXIT", "CPU_BOUND", "ENV_SENTINEL_ABSENT", "FD_BOUND", "MEMORY_BOUND", "NETWORK_SOCKET_DENIED", "OUTPUT_BOUND", "PID_BOUND", "PROTECTED_SENTINEL_DENIED", "SESSION_ESCAPE_CLEANUP", "SOURCE_WRITE_DENIED", "WALL_BOUND", "WORKSPACE_BOUND", "BENIGN_OPERATION"}
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
		keys := map[string]string{"CACHE_WRITE_DENIED": "cache", "CLEAN_EXIT": "clean", "CPU_BOUND": "cpu", "ENV_SENTINEL_ABSENT": "secret", "FD_BOUND": "fd", "MEMORY_BOUND": "memory", "NETWORK_SOCKET_DENIED": "network", "OUTPUT_BOUND": "output", "PID_BOUND": "pid", "PROTECTED_SENTINEL_DENIED": "protected", "SESSION_ESCAPE_CLEANUP": "session", "SOURCE_WRITE_DENIED": "source", "WALL_BOUND": "wall", "WORKSPACE_BOUND": "workspace", "BENIGN_OPERATION": "benign"}
		items = append(items, descriptor{id, keys[id], expectation})
	}
	data, _ := json.Marshal(items)
	return intake.DigestBytes(data)
}

func protectedPrivilegedExecDigest() string {
	data, _ := json.Marshal([]string{"/opt/homebrew/Caskroom/sbx/0.39.0/bin/sbx", "exec", "--privileged", "-u", "root", "us007-resource-envelope-0018", "/tmp/us007-resource-supervisor"})
	return intake.DigestBytes(data)
}
