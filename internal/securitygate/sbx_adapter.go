package securitygate

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	sbxExecutionProfilePath = "security/sbx-template.json"
	sbxLaunchKind           = "DOCKER_SBX_CONTROLLED_CANARY_LAUNCH"
	sbxLaunchScope          = "QUARANTINED_LABORATORY_QUALIFICATION_ONLY"
)

var (
	sbxAttemptPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{15,127}$`)
	sbxNamePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,62}$`)
	sbxGitObjectPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// SandboxAdapterFinding is a fail-closed result at the protected sbx seam.
type SandboxAdapterFinding struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
	Path        string `json:"path"`
	Message     string `json:"message"`
}

func (finding *SandboxAdapterFinding) Error() string {
	return fmt.Sprintf("%s/%s at %s: %s", finding.Code, finding.Disposition, finding.Path, finding.Message)
}

func sbxFinding(code, disposition, path, message string) error {
	return &SandboxAdapterFinding{Code: code, Disposition: disposition, Path: path, Message: message}
}

type sbxRuntimeProfile struct {
	CLIPath                string `json:"cli_path"`
	CLIVersion             string `json:"cli_version"`
	CLICommit              string `json:"cli_commit"`
	CLIBinaryDigest        string `json:"cli_binary_digest"`
	DaemonVersion          string `json:"daemon_version"`
	Agent                  string `json:"agent"`
	TemplateReference      string `json:"template_reference"`
	TemplateIndexDigest    string `json:"template_index_digest"`
	TemplatePlatform       string `json:"template_platform"`
	TemplateManifestDigest string `json:"template_manifest_digest"`
}

type sbxNetworkPolicy struct {
	PolicyID                string   `json:"policy_id"`
	RuleID                  string   `json:"rule_id"`
	ResourceType            string   `json:"resource_type"`
	Decision                string   `json:"decision"`
	Resources               []string `json:"resources"`
	Origin                  string   `json:"origin"`
	Status                  string   `json:"status"`
	CanonicalDigest         string   `json:"canonical_digest"`
	PerSandboxDenyResources []string `json:"per_sandbox_deny_resources"`
}

type sbxIsolationProfile struct {
	WorkspaceMode            string           `json:"workspace_mode"`
	CPUs                     int              `json:"cpus"`
	Memory                   string           `json:"memory"`
	MemoryBytes              int64            `json:"memory_bytes"`
	EnvironmentImport        string           `json:"environment_import"`
	SecretImport             string           `json:"secret_import"`
	PlatformControlSecret    string           `json:"platform_control_secret"`
	MCPGatewayInfrastructure bool             `json:"mcp_gateway_infrastructure"`
	CloneGitBridgeRequired   bool             `json:"clone_git_bridge_required"`
	HostDockerSocket         bool             `json:"host_docker_socket"`
	SharedSkills             bool             `json:"shared_skills"`
	LocalMCP                 bool             `json:"local_mcp"`
	StaticMCPServers         []string         `json:"static_mcp_servers"`
	Kits                     []string         `json:"kits"`
	PublishedPorts           []string         `json:"published_ports"`
	NetworkPolicy            sbxNetworkPolicy `json:"network_policy"`
}

type sbxCleanupProfile struct {
	RemoveMode       string `json:"remove_mode"`
	PostRemovalCheck string `json:"post_removal_check"`
	AbsenceRequired  bool   `json:"absence_required"`
}

type sbxExecutionProfile struct {
	SchemaVersion            string              `json:"schema_version"`
	Scope                    scope               `json:"scope"`
	Runtime                  sbxRuntimeProfile   `json:"runtime"`
	Isolation                sbxIsolationProfile `json:"isolation"`
	SandboxPolicyDigest      string              `json:"sandbox_policy_digest"`
	SupervisorLimits         resources           `json:"supervisor_limits"`
	Cleanup                  sbxCleanupProfile   `json:"cleanup"`
	Assurance                string              `json:"assurance"`
	IndependentReviewClaimed bool                `json:"independent_review_claimed"`
	Production               bool                `json:"production"`
	Signing                  bool                `json:"signing"`
	Publication              bool                `json:"publication"`
	digest                   string
}

// SbxExecutionParameters contains identities and roots selected by the
// protected parent. It contains no command or environment injection seam.
type SbxExecutionParameters struct {
	AttemptID             string
	SandboxName           string
	CanaryID              string
	PlanDigest            string
	AcceptedRootDigest    string
	InventoryRootDigest   string
	PromotionRecordDigest string
	SecurityctlDigest     string
	SupervisorDigest      string
	InputRoot             string
	OutputRoot            string
}

// SbxExecutionRequest is the exact, canonical transport passed to a protected
// launcher. Commands are derived from the retained profile, never caller argv.
type SbxExecutionRequest struct {
	SchemaVersion            string   `json:"schema_version"`
	Company                  string   `json:"company"`
	Project                  string   `json:"project"`
	Laboratory               string   `json:"laboratory"`
	AttemptID                string   `json:"attempt_id"`
	SandboxName              string   `json:"sandbox_name"`
	CanaryID                 string   `json:"canary_id"`
	PlanDigest               string   `json:"plan_digest"`
	ProfileDigest            string   `json:"profile_digest"`
	SandboxPolicyDigest      string   `json:"sandbox_policy_digest"`
	AcceptedRootDigest       string   `json:"accepted_root_digest"`
	InventoryRootDigest      string   `json:"inventory_root_digest"`
	PromotionRecordDigest    string   `json:"promotion_record_digest"`
	SecurityctlDigest        string   `json:"securityctl_digest"`
	SupervisorDigest         string   `json:"supervisor_digest"`
	InputRoot                string   `json:"input_root"`
	OutputRoot               string   `json:"output_root"`
	CreateCommand            []string `json:"create_command"`
	RemoveCommand            []string `json:"remove_command"`
	AbsenceCommand           []string `json:"absence_command"`
	Assurance                string   `json:"assurance"`
	IndependentReviewClaimed bool     `json:"independent_review_claimed"`
	Production               bool     `json:"production"`
	Signing                  bool     `json:"signing"`
	Publication              bool     `json:"publication"`
}

// SbxExecutionReceipt is emitted by the protected launcher after execution,
// sbx rm, and an independent post-removal absence query.
type SbxExecutionReceipt struct {
	SchemaVersion              string                `json:"schema_version"`
	RequestDigest              string                `json:"request_digest"`
	AttemptID                  string                `json:"attempt_id"`
	SandboxName                string                `json:"sandbox_name"`
	CanaryID                   string                `json:"canary_id"`
	ProfileDigest              string                `json:"profile_digest"`
	SandboxPolicyDigest        string                `json:"sandbox_policy_digest"`
	CLIVersion                 string                `json:"cli_version"`
	CLICommit                  string                `json:"cli_commit"`
	CLIBinaryDigest            string                `json:"cli_binary_digest"`
	DaemonVersion              string                `json:"daemon_version"`
	Agent                      string                `json:"agent"`
	TemplateReference          string                `json:"template_reference"`
	TemplateIndexDigest        string                `json:"template_index_digest"`
	TemplatePlatform           string                `json:"template_platform"`
	TemplateManifestDigest     string                `json:"template_manifest_digest"`
	WorkspaceMode              string                `json:"workspace_mode"`
	CloneSourceReadOnly        bool                  `json:"clone_source_read_only"`
	CPUCount                   int                   `json:"cpu_count"`
	MemoryBytes                int64                 `json:"memory_bytes"`
	CompiledSupervisorEnvelope resources             `json:"compiled_supervisor_envelope"`
	SupervisorObservation      SupervisorObservation `json:"supervisor_observation"`
	NetworkPolicyDigest        string                `json:"network_policy_digest"`
	NetworkPolicyState         string                `json:"network_policy_state"`
	EnvironmentImportCount     int                   `json:"environment_import_count"`
	SecretImportCount          int                   `json:"secret_import_count"`
	PlatformControlSecretCount int                   `json:"platform_control_secret_count"`
	MCPGatewayInfrastructure   bool                  `json:"mcp_gateway_infrastructure"`
	CloneGitBridgePortCount    int                   `json:"clone_git_bridge_port_count"`
	PublishedPortCount         int                   `json:"published_port_count"`
	StaticMCPCount             int                   `json:"static_mcp_count"`
	KitCount                   int                   `json:"kit_count"`
	HostDockerSocketMounted    bool                  `json:"host_docker_socket_mounted"`
	SharedSkillsEnabled        bool                  `json:"shared_skills_enabled"`
	LocalMCPEnabled            bool                  `json:"local_mcp_enabled"`
	InputRoot                  string                `json:"input_root"`
	OutputRoot                 string                `json:"output_root"`
	AcceptedRootDigest         string                `json:"accepted_root_digest"`
	InventoryRootDigest        string                `json:"inventory_root_digest"`
	SourceBeforeDigest         string                `json:"source_before_digest"`
	SourceAfterDigest          string                `json:"source_after_digest"`
	OutputRootDigest           string                `json:"output_root_digest"`
	CanaryObservationCount     int                   `json:"canary_observation_count"`
	ArtifactManifestDigest     string                `json:"artifact_manifest_digest"`
	ExitCode                   *int                  `json:"exit_code"`
	TerminationReason          string                `json:"termination_reason"`
	StartedAt                  string                `json:"started_at"`
	FinishedAt                 string                `json:"finished_at"`
	RemovalStartedAt           string                `json:"removal_started_at"`
	RemovalFinishedAt          string                `json:"removal_finished_at"`
	RemoveInvoked              bool                  `json:"remove_invoked"`
	RemoveExitCode             *int                  `json:"remove_exit_code"`
	SandboxPresentAfterRemoval bool                  `json:"sandbox_present_after_removal"`
	CleanupComplete            bool                  `json:"cleanup_complete"`
	Assurance                  string                `json:"assurance"`
	IndependentReviewClaimed   bool                  `json:"independent_review_claimed"`
	Production                 bool                  `json:"production"`
	Signing                    bool                  `json:"signing"`
	Publication                bool                  `json:"publication"`
}

// SupervisorCapabilityPreflight is a set of raw protected-parent observations.
// Empty values block; candidate declarations are never substituted.
type SupervisorCapabilityPreflight struct {
	Setrlimit         string `json:"setrlimit"`
	RunTmpfs          string `json:"run_tmpfs"`
	NoNewPrivs        string `json:"no_new_privs"`
	Stage2Containment string `json:"stage2_containment"`
	OuterCPU          string `json:"outer_cpu"`
	InnerCgroup       string `json:"inner_cgroup"`
	UIDIsolation      string `json:"uid_isolation"`
}

type SupervisorEnforcementMechanics struct {
	RLimitFSizeBytes     int64 `json:"rlimit_fsize_bytes"`
	CPUCorroborationUsec int64 `json:"cpu_corroboration_usec"`
	WallKillThresholdNS  int64 `json:"wall_kill_threshold_nanos"`
	MemoryKillBytes      int64 `json:"aggregate_memory_kill_bytes"`
	AggregateOpenFiles   int64 `json:"aggregate_open_files"`
	DescriptorUIDPIDs    int64 `json:"descriptor_uid_pids"`
	OuterCPUs            int   `json:"outer_cpus"`
	OuterMemoryBytes     int64 `json:"outer_memory_bytes"`
	RunTmpfsBytes        int64 `json:"run_tmpfs_bytes"`
}

type SupervisorRusageObservation struct {
	UTimeUsec    int64 `json:"utime_usec"`
	STimeUsec    int64 `json:"stime_usec"`
	CPUUsageUsec int64 `json:"cpu_usage_usec"`
	MaxRSSBytes  int64 `json:"maxrss_bytes"`
}

type SupervisorRLimitObservation struct {
	CPUCur    uint64 `json:"cpu_cur"`
	CPUMax    uint64 `json:"cpu_max"`
	ASCur     uint64 `json:"as_cur"`
	ASMax     uint64 `json:"as_max"`
	NProcCur  uint64 `json:"nproc_cur"`
	NProcMax  uint64 `json:"nproc_max"`
	NOFileCur uint64 `json:"nofile_cur"`
	NOFileMax uint64 `json:"nofile_max"`
	FSizeCur  uint64 `json:"fsize_cur"`
	FSizeMax  uint64 `json:"fsize_max"`
	CoreCur   uint64 `json:"core_cur"`
	CoreMax   uint64 `json:"core_max"`
}

type SupervisorIdentityObservation struct {
	UID         int    `json:"uid"`
	GID         int    `json:"gid"`
	CapEff      string `json:"cap_eff"`
	NoNewPrivs  int    `json:"no_new_privs"`
	Seccomp     int    `json:"seccomp"`
	OpenFDs     int64  `json:"open_fds"`
	FDSemantics string `json:"fd_semantics"`
}

type SupervisorMountObservation struct {
	Name        string `json:"name"`
	MountInfo   string `json:"mountinfo"`
	FSType      int64  `json:"fstatfs_type"`
	BytesTotal  int64  `json:"bytes_total"`
	BytesFree   int64  `json:"bytes_free"`
	InodesTotal int64  `json:"inodes_total"`
	InodesFree  int64  `json:"inodes_free"`
}

type SupervisorPeakObservation struct {
	CPUUsageUsec   int64 `json:"cpu_usage_usec"`
	MemoryBytes    int64 `json:"memory_bytes"`
	PIDs           int64 `json:"descriptor_uid_pids"`
	OpenFiles      int64 `json:"descriptor_uid_open_files"`
	OutputBytes    int64 `json:"output_bytes"`
	WorkspaceBytes int64 `json:"workspace_bytes"`
	CacheBytes     int64 `json:"cache_bytes"`
	DiskBytes      int64 `json:"aggregate_writable_bytes"`
	Inodes         int64 `json:"aggregate_writable_inodes"`
}

type SupervisorCleanupObservation struct {
	ProcessGroupKill string `json:"process_group_kill"`
	UIDKill          string `json:"descriptor_uid_kill"`
	ChildWait        string `json:"child_wait"`
	UIDProcesses     string `json:"descriptor_uid_processes_reopened"`
	WorkspacePurge   string `json:"workspace_tmpfs_purge"`
	FDClosure        string `json:"fd_closure"`
}

type SupervisorArtifactObservation struct {
	ToolPath       string `json:"tool_path"`
	ToolVersion    string `json:"tool_version"`
	Target         string `json:"target"`
	SourceCommit   string `json:"source_commit"`
	NamespacePath  string `json:"namespace_path"`
	CapturePath    string `json:"capture_path"`
	CaptureChannel string `json:"capture_channel"`
	WorkloadDigest string `json:"workload_digest"`
	ParentDigest   string `json:"parent_digest"`
	Bytes          int64  `json:"bytes"`
}

// SupervisorObservation is enforcement evidence from the protected external
// supervisor. It intentionally has no limits-applied or passed boolean.
type SupervisorObservation struct {
	SchemaVersion            string                         `json:"schema_version"`
	DescriptorID             string                         `json:"descriptor_id"`
	DescriptorDigest         string                         `json:"descriptor_digest"`
	SupervisorDigest         string                         `json:"supervisor_digest"`
	SupervisorDigestReopened string                         `json:"supervisor_digest_reopened"`
	RuntimeIdentity          string                         `json:"runtime_identity"`
	SBXIdentity              string                         `json:"sbx_identity"`
	SourceCommit             string                         `json:"source_commit"`
	SourceTree               string                         `json:"source_tree"`
	CapabilityPreflight      SupervisorCapabilityPreflight  `json:"capability_preflight"`
	Envelope                 resources                      `json:"compiled_envelope"`
	EnforcementMechanics     SupervisorEnforcementMechanics `json:"enforcement_mechanics"`
	Rusage                   SupervisorRusageObservation    `json:"rusage_reaped"`
	RLimits                  SupervisorRLimitObservation    `json:"rlimits_reopened"`
	Identity                 SupervisorIdentityObservation  `json:"identity_reopened"`
	RunTmpfs                 SupervisorMountObservation     `json:"run_tmpfs_reopened"`
	CompleteMountInfo        string                         `json:"complete_mountinfo_reopened"`
	CompleteMountInfoDigest  string                         `json:"complete_mountinfo_digest"`
	Peaks                    SupervisorPeakObservation      `json:"peaks"`
	StdoutDigest             string                         `json:"stdout_digest"`
	StderrDigest             string                         `json:"stderr_digest"`
	Termination              string                         `json:"termination"`
	ParentWaitStatus         string                         `json:"parent_wait_status"`
	ParentExitCode           *int                           `json:"exit_code"`
	ParentSignal             string                         `json:"signal"`
	WorkloadSignal           int                            `json:"workload_signal"`
	WorkloadUID              uint32                         `json:"workload_uid"`
	WritablePaths            []string                       `json:"writable_paths_reopened"`
	WallDurationNanos        int64                          `json:"wall_duration_nanos"`
	Cleanup                  SupervisorCleanupObservation   `json:"cleanup"`
	Artifact                 SupervisorArtifactObservation  `json:"artifact"`
	Assurance                string                         `json:"assurance"`
	IndependentReviewClaimed bool                           `json:"independent_review_claimed"`
	AutobahnReruns           int                            `json:"autobahn_reruns"`
}

// SbxLaunchAuthorizationRecord contains public owner intent only. It carries
// no key, trust anchor, protected snapshot source, or launcher implementation.
type SbxLaunchAuthorizationRecord struct {
	SchemaVersion string                        `json:"schema_version"`
	Subject       intake.ScopedOwnerSubject     `json:"subject"`
	Statements    []intake.ScopedOwnerStatement `json:"statements"`
}

type SbxLaunchSigningRequest struct {
	Execution                SbxExecutionRequest `json:"execution"`
	IssuedAt                 time.Time           `json:"issued_at"`
	ExpiresAt                time.Time           `json:"expires_at"`
	RoleSnapshotDigest       string              `json:"role_snapshot_digest"`
	RevocationSnapshotDigest string              `json:"revocation_snapshot_digest"`
	Nonces                   []string            `json:"nonces"`
}

func loadSbxExecutionProfile(rootPath string) (sbxExecutionProfile, error) {
	identity, err := realDirectoryIdentity(rootPath)
	if err != nil {
		return sbxExecutionProfile{}, fmt.Errorf("ROOT_CONFINEMENT_FAILED/QUARANTINE: %w", err)
	}
	root, err := os.OpenRoot(identity.path)
	if err != nil {
		return sbxExecutionProfile{}, err
	}
	defer root.Close()
	data, err := readRelative(root, sbxExecutionProfilePath, 1<<20)
	if err != nil {
		return sbxExecutionProfile{}, err
	}
	policyBytes, err := readRelative(root, policyPaths[1], 1<<20)
	if err != nil {
		return sbxExecutionProfile{}, err
	}
	var retainedSandbox sandboxPolicy
	if err := intake.DecodeStrict(policyBytes, &retainedSandbox); err != nil {
		return sbxExecutionProfile{}, sbxFinding("INVALID_SECURITY_POLICY", "BLOCK", policyPaths[1], err.Error())
	}
	var profile sbxExecutionProfile
	if err := intake.DecodeStrict(data, &profile); err != nil {
		return sbxExecutionProfile{}, sbxFinding("INVALID_SECURITY_POLICY", "BLOCK", sbxExecutionProfilePath, err.Error())
	}
	profile.digest = intake.DigestBytes(data)
	wantScope := scope{Company: requiredCompany, Project: requiredProject, Laboratory: requiredLaboratory}
	runtime := profile.Runtime
	isolation := profile.Isolation
	network := isolation.NetworkPolicy
	if profile.SchemaVersion != policyVersion || profile.Scope != wantScope ||
		runtime.CLIPath != "/opt/homebrew/Caskroom/sbx/0.39.0/bin/sbx" || runtime.CLIVersion != "v0.39.0" || runtime.CLICommit != "def8cb0523a77e757bdd6ef52b459fe374f3783e" ||
		runtime.CLIDaemonInvalid() || runtime.Agent != "shell" || runtime.TemplateReference != "docker.io/docker/sandbox-templates:shell@sha256:1e642f7fadebcbff3d8de67114e9b42a5971ba9b4287ebffa1d05662f5a0f5ec" ||
		runtime.TemplateIndexDigest != "sha256:c183a8ba03cdb30011c73f555c773c5712b84c6ea066f18409253dcab2cfe799" || runtime.TemplatePlatform != "linux/arm64" || runtime.TemplateManifestDigest != "sha256:1e642f7fadebcbff3d8de67114e9b42a5971ba9b4287ebffa1d05662f5a0f5ec" ||
		isolation.WorkspaceMode != "clone" || isolation.CPUs != 1 || isolation.Memory != "1g" || isolation.MemoryBytes != 1073741824 || isolation.EnvironmentImport != "none" || isolation.SecretImport != "none" || isolation.PlatformControlSecret != "mcpgateway" || !isolation.MCPGatewayInfrastructure || !isolation.CloneGitBridgeRequired ||
		isolation.HostDockerSocket || isolation.SharedSkills || isolation.LocalMCP || len(isolation.StaticMCPServers) != 0 || len(isolation.Kits) != 0 || len(isolation.PublishedPorts) != 0 ||
		network.PolicyID != "default-deny-all" || network.RuleID != "default-deny-all" || network.ResourceType != "network" || network.Decision != "deny" || !slices.Equal(network.Resources, []string{"**"}) || !slices.Equal(network.PerSandboxDenyResources, []string{"**"}) || network.Origin != "local" || network.Status != "active" || !isSHA256Digest(network.CanonicalDigest) ||
		profile.SandboxPolicyDigest != intake.DigestBytes(policyBytes) || profile.SupervisorLimits != retainedSandbox.Resources || profile.SupervisorLimits.MemoryBytes > isolation.MemoryBytes ||
		profile.Cleanup.RemoveMode != "sbx-rm-force" || profile.Cleanup.PostRemovalCheck != "sbx-ls-absence" || !profile.Cleanup.AbsenceRequired ||
		profile.Assurance != AssuranceOwnerOnly || profile.IndependentReviewClaimed || profile.Production || profile.Signing || profile.Publication {
		return sbxExecutionProfile{}, sbxFinding("INVALID_SECURITY_POLICY", "BLOCK", sbxExecutionProfilePath, "Docker sbx execution profile differs from the exact protected contract")
	}
	return profile, nil
}

func (runtime sbxRuntimeProfile) CLIDaemonInvalid() bool {
	return runtime.DaemonVersion != "v0.39.0" || !isSHA256Digest(runtime.CLIBinaryDigest)
}

func BuildSbxExecutionRequest(rootPath string, parameters SbxExecutionParameters) (SbxExecutionRequest, error) {
	profile, err := loadSbxExecutionProfile(rootPath)
	if err != nil {
		return SbxExecutionRequest{}, err
	}
	snapshot, err := loadPolicies(rootPath)
	if err != nil {
		return SbxExecutionRequest{}, err
	}
	defer snapshot.root.Close()
	if strings.HasPrefix(parameters.CanaryID, "AUTOBAHN_") {
		return SbxExecutionRequest{}, sbxFinding("AUTOBAHN_RERUN_FORBIDDEN", "BLOCK", "$.canary_id", "US-007 may run only generic non-Autobahn canaries")
	}
	if !stringInSet(parameters.CanaryID, snapshot.sandbox.CanaryIDs) {
		return SbxExecutionRequest{}, sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.canary_id", "canary is outside the closed policy registry")
	}
	if !sbxAttemptPattern.MatchString(parameters.AttemptID) || !sbxNamePattern.MatchString(parameters.SandboxName) || parameters.SandboxName == "default" {
		return SbxExecutionRequest{}, sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.identity", "attempt and sandbox names are not canonical")
	}
	for _, digest := range []string{parameters.PlanDigest, parameters.AcceptedRootDigest, parameters.InventoryRootDigest, parameters.PromotionRecordDigest, parameters.SecurityctlDigest, parameters.SupervisorDigest} {
		if !isSHA256Digest(digest) {
			return SbxExecutionRequest{}, sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.digests", "every execution identity must be an exact SHA-256 digest")
		}
	}
	project, err := realDirectoryIdentity(rootPath)
	if err != nil {
		return SbxExecutionRequest{}, sbxFinding("ROOT_CONFINEMENT_FAILED", "QUARANTINE", "$.root", err.Error())
	}
	input, err := realDirectoryIdentity(parameters.InputRoot)
	if err != nil || input.path != project.path {
		return SbxExecutionRequest{}, sbxFinding("ROOT_CONFINEMENT_FAILED", "QUARANTINE", "$.input_root", "clone input must be the exact retained project repository")
	}
	output, err := realDirectoryIdentity(parameters.OutputRoot)
	if err != nil || pathIdentitiesOverlap(input.path, output.path) {
		return SbxExecutionRequest{}, sbxFinding("ROOT_CONFINEMENT_FAILED", "QUARANTINE", "$.output_root", "output must be a specific existing root disjoint from clone input")
	}
	create := []string{profile.Runtime.CLIPath, "create", "--clone", "--cpus", strconv.Itoa(profile.Isolation.CPUs), "--memory", profile.Isolation.Memory, "--deny-network", "**", "--name", parameters.SandboxName, "--template", profile.Runtime.TemplateReference, profile.Runtime.Agent, input.path}
	return SbxExecutionRequest{
		SchemaVersion: policyVersion, Company: requiredCompany, Project: requiredProject, Laboratory: requiredLaboratory,
		AttemptID: parameters.AttemptID, SandboxName: parameters.SandboxName, CanaryID: parameters.CanaryID, PlanDigest: parameters.PlanDigest,
		ProfileDigest: profile.digest, SandboxPolicyDigest: profile.SandboxPolicyDigest,
		AcceptedRootDigest: parameters.AcceptedRootDigest, InventoryRootDigest: parameters.InventoryRootDigest, PromotionRecordDigest: parameters.PromotionRecordDigest,
		SecurityctlDigest: parameters.SecurityctlDigest, SupervisorDigest: parameters.SupervisorDigest,
		InputRoot: input.path, OutputRoot: output.path, CreateCommand: create,
		RemoveCommand: []string{profile.Runtime.CLIPath, "rm", "--force", parameters.SandboxName}, AbsenceCommand: []string{profile.Runtime.CLIPath, "ls", "--json"},
		Assurance: AssuranceOwnerOnly,
	}, nil
}

func SbxExecutionRequestDigest(request SbxExecutionRequest) (string, error) {
	canonical, err := intake.CanonicalJSON(request)
	if err != nil {
		return "", err
	}
	return intake.DigestBytes(canonical), nil
}

func validateSbxExecutionRequest(rootPath string, request SbxExecutionRequest) error {
	want, err := BuildSbxExecutionRequest(rootPath, SbxExecutionParameters{
		AttemptID: request.AttemptID, SandboxName: request.SandboxName, CanaryID: request.CanaryID, PlanDigest: request.PlanDigest,
		AcceptedRootDigest: request.AcceptedRootDigest, InventoryRootDigest: request.InventoryRootDigest, PromotionRecordDigest: request.PromotionRecordDigest,
		SecurityctlDigest: request.SecurityctlDigest, SupervisorDigest: request.SupervisorDigest, InputRoot: request.InputRoot, OutputRoot: request.OutputRoot,
	})
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(request, want) {
		return sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.execution", "request differs from the exact retained sbx profile")
	}
	return nil
}

func SbxLaunchOwnerRequirements() intake.ScopedOwnerRequirements {
	return intake.ScopedOwnerRequirements{
		OwnerActorID: intake.RequiredOwnerActor, Kind: sbxLaunchKind,
		Statements: []intake.ScopedStatementRequirement{
			{Stage: "qualification", Action: "authorize-docker-sbx-canary", SignerRole: "port-implementer"},
			{Stage: intake.PromotionStageID, Action: "confirm-promoted-sbx-launcher", SignerRole: "release-attestor"},
		},
		SubjectRoles: []string{"PROTECTED_SBX_LAUNCHER"}, HistoricalKeyID: executablePromotionKeyID, RequireDurableLedger: true,
	}
}

func SbxLaunchSubject(rootPath string, request SbxExecutionRequest) (intake.ScopedOwnerSubject, error) {
	if err := validateSbxExecutionRequest(rootPath, request); err != nil {
		return intake.ScopedOwnerSubject{}, err
	}
	snapshot, err := loadPolicies(rootPath)
	if err != nil {
		return intake.ScopedOwnerSubject{}, err
	}
	defer snapshot.root.Close()
	requestDigest, err := SbxExecutionRequestDigest(request)
	if err != nil {
		return intake.ScopedOwnerSubject{}, err
	}
	return intake.ScopedOwnerSubject{
		SchemaVersion: policyVersion, Kind: sbxLaunchKind, ArtifactDigest: requestDigest,
		SubjectRoles: []string{"PROTECTED_SBX_LAUNCHER"}, Operation: "CONTROLLED_CANARY",
		Company: requiredCompany, Project: requiredProject, LaboratoryID: requiredLaboratory,
		PolicyDigest: request.SandboxPolicyDigest,
		EvidenceBindings: []intake.ScopedDigestBinding{
			{Name: "executable-promotion-record", Digest: request.PromotionRecordDigest},
			{Name: "sbx-execution-profile", Digest: request.ProfileDigest},
			{Name: "security-evidence", Digest: snapshot.digests["evidence/security-validation.json"]},
		},
		Scope: sbxLaunchScope, HistoricalKeyID: executablePromotionKeyID,
	}, nil
}

func BuildAndSignSbxLaunchAuthorization(rootPath string, request SbxLaunchSigningRequest, privateKey ed25519.PrivateKey) (SbxLaunchAuthorizationRecord, error) {
	subject, err := SbxLaunchSubject(rootPath, request.Execution)
	if err != nil {
		return SbxLaunchAuthorizationRecord{}, err
	}
	requirements := SbxLaunchOwnerRequirements()
	if len(request.Nonces) != len(requirements.Statements) || !isSHA256Digest(request.RoleSnapshotDigest) || !isSHA256Digest(request.RevocationSnapshotDigest) || request.IssuedAt.IsZero() || request.ExpiresAt.IsZero() || !request.ExpiresAt.After(request.IssuedAt) || request.ExpiresAt.Sub(request.IssuedAt) > 24*time.Hour {
		return SbxLaunchAuthorizationRecord{}, sbxFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.signing_request", "bounded snapshots, time window, and two nonces are required")
	}
	subjectDigest, err := intake.ScopedOwnerSubjectDigest(subject)
	if err != nil {
		return SbxLaunchAuthorizationRecord{}, err
	}
	statements := make([]intake.ScopedOwnerStatement, len(requirements.Statements))
	for index, required := range requirements.Statements {
		statement := intake.ScopedOwnerStatement{
			SchemaVersion: policyVersion, SubjectDigest: subjectDigest, Stage: required.Stage, Action: required.Action,
			ActorID: intake.RequiredOwnerActor, Role: required.SignerRole, KeyID: executablePromotionKeyID, AuthorityMode: intake.SingleOwnerAuthorityMode,
			IssuedAt: request.IssuedAt, ExpiresAt: request.ExpiresAt, Nonce: request.Nonces[index],
			RoleSnapshotDigest: request.RoleSnapshotDigest, RevocationSnapshotDigest: request.RevocationSnapshotDigest,
		}
		statements[index], err = intake.SignScopedOwnerStatement(statement, privateKey)
		if err != nil {
			return SbxLaunchAuthorizationRecord{}, err
		}
	}
	return SbxLaunchAuthorizationRecord{SchemaVersion: policyVersion, Subject: subject, Statements: statements}, nil
}

func DecodeSbxLaunchAuthorizationRecord(data []byte) (SbxLaunchAuthorizationRecord, error) {
	var record SbxLaunchAuthorizationRecord
	if err := intake.DecodeStrict(data, &record); err != nil {
		return SbxLaunchAuthorizationRecord{}, sbxFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.authorization", err.Error())
	}
	return record, nil
}

func ValidateSbxLaunchAuthorizationRecord(rootPath string, request SbxExecutionRequest, record SbxLaunchAuthorizationRecord, now time.Time) error {
	expected, err := SbxLaunchSubject(rootPath, request)
	if err != nil {
		return err
	}
	if record.SchemaVersion != policyVersion || !reflect.DeepEqual(record.Subject, expected) {
		return sbxFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.authorization.subject", "authorization does not bind the exact current sbx request")
	}
	requirements := SbxLaunchOwnerRequirements()
	if len(record.Statements) != len(requirements.Statements) {
		return sbxFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.authorization.statements", "exact qualification and promotion actions are required")
	}
	subjectDigest, err := intake.ScopedOwnerSubjectDigest(expected)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for index, statement := range record.Statements {
		required := requirements.Statements[index]
		signature, decodeErr := hex.DecodeString(statement.Signature)
		if statement.SchemaVersion != policyVersion || statement.SubjectDigest != subjectDigest || statement.Stage != required.Stage || statement.Action != required.Action || statement.ActorID != intake.RequiredOwnerActor || statement.Role != required.SignerRole || statement.KeyID != executablePromotionKeyID || statement.AuthorityMode != intake.SingleOwnerAuthorityMode ||
			!executablePromotionNonce.MatchString(statement.Nonce) || seen[statement.Nonce] || !isSHA256Digest(statement.RoleSnapshotDigest) || !isSHA256Digest(statement.RevocationSnapshotDigest) || decodeErr != nil || len(signature) != ed25519.SignatureSize || strings.ToLower(statement.Signature) != statement.Signature ||
			statement.IssuedAt.IsZero() || statement.ExpiresAt.IsZero() || !statement.ExpiresAt.After(statement.IssuedAt) || statement.ExpiresAt.Sub(statement.IssuedAt) > 24*time.Hour || statement.IssuedAt.After(now.Add(5*time.Minute)) || !now.Before(statement.ExpiresAt) {
			return sbxFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", fmt.Sprintf("$.authorization.statements[%d]", index), "signed action shape or scope changed")
		}
		seen[statement.Nonce] = true
	}
	if record.Statements[0].RoleSnapshotDigest != record.Statements[1].RoleSnapshotDigest || record.Statements[0].RevocationSnapshotDigest != record.Statements[1].RevocationSnapshotDigest {
		return sbxFinding("EXECUTABLE_PROMOTION_MISMATCH", "QUARANTINE", "$.authorization.statements", "actions must bind one current protected snapshot")
	}
	return nil
}

func PreflightSbxLaunchCandidate(rootPath string, request SbxExecutionRequest, data []byte, now time.Time) error {
	record, err := DecodeSbxLaunchAuthorizationRecord(data)
	if err != nil {
		return err
	}
	if err := ValidateSbxLaunchAuthorizationRecord(rootPath, request, record, now); err != nil {
		return err
	}
	return sbxFinding("PROTECTED_CALLER_REQUIRED", "BLOCK", "$.protected_launcher", "candidate-local records cannot prove protected key custody, durable nonce consumption, or launcher provenance")
}

// DecodeSbxExecutionReceipt rejects unknown fields, including any
// workload-authored enforcement or success boolean.
func DecodeSbxExecutionReceipt(data []byte) (SbxExecutionReceipt, error) {
	var receipt SbxExecutionReceipt
	if err := intake.DecodeStrict(data, &receipt); err != nil {
		return SbxExecutionReceipt{}, sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.receipt", err.Error())
	}
	return receipt, nil
}

func validateSupervisorObservation(profile sbxExecutionProfile, request SbxExecutionRequest, observation SupervisorObservation) error {
	preflight := observation.CapabilityPreflight
	wantPreflight := SupervisorCapabilityPreflight{
		Setrlimit:         "getrlimit/setrlimit round-trip succeeded",
		RunTmpfs:          "/run tmpfs observed magic=0x1021994 size=67108864 inodes=16384",
		NoNewPrivs:        "prctl PR_GET_NO_NEW_PRIVS available",
		Stage2Containment: "blocked pipe protocol; process-group plus descriptor-UID containment before release",
		OuterCPU:          "runtime.NumCPU=1",
		InnerCgroup:       "read-only cgroup-v2 memory.max=max cpu.max=max 100000",
		UIDIsolation:      "descriptor-specific UID observed empty before release and swept after wait",
	}
	if preflight != wantPreflight {
		return sbxFinding("SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.supervisor_observation.capability_preflight", "protected-parent preflight differs from the exact measured runtime contract")
	}
	expectedDescriptorDigest, expectation, err := sbxDescriptorContract(request.CanaryID)
	if err != nil {
		return err
	}
	if observation.SchemaVersion != policyVersion || observation.DescriptorID != request.CanaryID || observation.DescriptorDigest != expectedDescriptorDigest || observation.SupervisorDigest != request.SupervisorDigest || observation.SupervisorDigestReopened != request.SupervisorDigest || !isSHA256Digest(observation.StdoutDigest) || !isSHA256Digest(observation.StderrDigest) || observation.RuntimeIdentity == "" || observation.SBXIdentity == "" || !sbxGitObjectPattern.MatchString(observation.SourceCommit) || !sbxGitObjectPattern.MatchString(observation.SourceTree) {
		return sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.supervisor_observation.digests", "descriptor, executable, stream, runtime, or sbx identity is absent or drifted")
	}
	limits := profile.SupervisorLimits
	if observation.Envelope != limits {
		return sbxFinding("SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.supervisor_observation.compiled_envelope", "compiled envelope differs from the retained profile")
	}
	mechanics := observation.EnforcementMechanics
	wantMechanics := supervisorMechanicsFor(limits)
	if mechanics != wantMechanics {
		return sbxFinding("SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.supervisor_observation.enforcement_mechanics", "aggregate UID, outer sbx, FSIZE, or conservative CPU/wall mechanics drifted")
	}
	rusage := observation.Rusage
	if rusage.UTimeUsec < 0 || rusage.STimeUsec < 0 || rusage.MaxRSSBytes < 0 || rusage.CPUUsageUsec != rusage.UTimeUsec+rusage.STimeUsec || observation.Peaks.CPUUsageUsec < rusage.CPUUsageUsec || observation.Peaks.MemoryBytes < rusage.MaxRSSBytes {
		return sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.supervisor_observation.rusage_reaped", "reaped rusage is inconsistent or exceeds the aggregate peak")
	}
	rlimits := observation.RLimits
	if rlimits.CPUCur != uint64(limits.CPUSeconds) || rlimits.CPUMax != rlimits.CPUCur || rlimits.ASCur <= uint64(limits.MemoryBytes) || rlimits.ASMax < rlimits.ASCur || rlimits.NProcCur != uint64(limits.PIDs) || rlimits.NProcMax != rlimits.NProcCur || rlimits.NOFileCur != uint64(limits.OpenFiles) || rlimits.NOFileMax != rlimits.NOFileCur || rlimits.FSizeCur != uint64(mechanics.RLimitFSizeBytes) || rlimits.FSizeMax != rlimits.FSizeCur || rlimits.CoreCur != 0 || rlimits.CoreMax != 0 {
		return sbxFinding("SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.supervisor_observation.rlimits_reopened", "stage-2 reopened rlimits differ from the protected envelope")
	}
	wantUID, wantPaths, identityErr := supervisorDescriptorIdentity(request.CanaryID)
	if identityErr != nil {
		return identityErr
	}
	identity := observation.Identity
	if observation.WorkloadUID != wantUID || identity.UID != int(wantUID) || identity.GID != int(wantUID) || strings.Trim(identity.CapEff, "0") != "" || identity.NoNewPrivs != 1 || identity.OpenFDs < 0 || identity.FDSemantics != "per-process RLIMIT_NOFILE plus parent-observed descriptor-UID aggregate FD kill threshold" {
		return sbxFinding("SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.supervisor_observation.identity_reopened", "descriptor UID, capabilities, no-new-privileges, or exact FD semantics are absent")
	}
	run := observation.RunTmpfs
	if run.Name != "run" || run.MountInfo == "" || run.FSType != 0x01021994 || run.BytesTotal != limits.DiskBytes || run.BytesFree < 0 || run.BytesFree > run.BytesTotal || run.InodesTotal != int64(limits.Inodes) || run.InodesFree < 0 || run.InodesFree > run.InodesTotal {
		return sbxFinding("SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.supervisor_observation.run_tmpfs_reopened", "the exact 64-MiB/16384-inode /run tmpfs observation is absent")
	}
	if !isSHA256Digest(observation.CompleteMountInfoDigest) || observation.CompleteMountInfoDigest != intake.DigestBytes([]byte(observation.CompleteMountInfo)) || validateSBXNoForbiddenMounts(observation.CompleteMountInfo, request.InputRoot) != nil {
		return sbxFinding("SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.supervisor_observation.complete_mountinfo_reopened", "complete mountinfo digest or protected-endpoint closure is invalid")
	}
	if len(observation.WritablePaths) == 0 || validateSBXWritablePaths(observation.WritablePaths, wantPaths) != nil {
		return sbxFinding("SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.supervisor_observation.writable_paths_reopened", "a writable path exists outside the descriptor-specific /run closure")
	}
	peaks := observation.Peaks
	if peaks.CPUUsageUsec < 0 || peaks.MemoryBytes < 0 || peaks.PIDs < 0 || peaks.OpenFiles < 0 || peaks.OutputBytes < 0 || peaks.WorkspaceBytes < 0 || peaks.CacheBytes < 0 || peaks.DiskBytes < 0 || peaks.Inodes < 0 || observation.Termination == "" || observation.ParentWaitStatus == "" || observation.WallDurationNanos < 0 || observation.WallDurationNanos > mechanics.WallKillThresholdNS+int64(time.Second) {
		return sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.supervisor_observation.peaks", "resource peaks, parent-derived termination, or monotonic wall observation is incomplete")
	}
	cleanup := observation.Cleanup
	if cleanup.ProcessGroupKill != "SIGNAL_DELIVERED" && cleanup.ProcessGroupKill != "ALREADY_ABSENT_ESRCH" || cleanup.UIDKill != "SIGNAL_SWEEP_SUCCEEDED" || cleanup.ChildWait != "REAP_SUCCEEDED" || cleanup.UIDProcesses != "<empty>" || cleanup.WorkspacePurge != "WORKSPACE_TMPFS_PURGED" || cleanup.FDClosure != "OWNED_FDS_CLOSED" {
		return sbxFinding("SANDBOX_CLEANUP_INCOMPLETE", "REVOKE", "$.supervisor_observation.cleanup", "process-group and descriptor-UID kill, empty reopen, purge, and FD cleanup observations are required")
	}
	if observation.Assurance != AssuranceOwnerOnly || observation.IndependentReviewClaimed || observation.AutobahnReruns != 0 {
		return sbxFinding("ASSURANCE_CEILING_EXCEEDED", "REVOKE", "$.supervisor_observation.assurance", "supervisor observation exceeds the sole-owner, zero-Autobahn ceiling")
	}
	if err := validateSBXDescriptorOutcome(request.CanaryID, expectation, observation, limits); err != nil {
		return err
	}
	return nil
}

func supervisorMechanicsFor(limits resources) SupervisorEnforcementMechanics {
	return SupervisorEnforcementMechanics{
		RLimitFSizeBytes: limits.DiskBytes, CPUCorroborationUsec: 58_000_000,
		WallKillThresholdNS: 59_000_000_000, MemoryKillBytes: 512 << 20,
		AggregateOpenFiles: int64(limits.OpenFiles), DescriptorUIDPIDs: int64(limits.PIDs),
		OuterCPUs: 1, OuterMemoryBytes: 1 << 30, RunTmpfsBytes: 64 << 20,
	}
}

func supervisorDescriptorIdentity(id string) (uint32, []string, error) {
	programKeys := map[string]string{
		"BENIGN_OPERATION": "benign", "CACHE_WRITE_DENIED": "cache", "CLEAN_EXIT": "clean",
		"CPU_BOUND": "cpu", "ENV_SENTINEL_ABSENT": "secret", "FD_BOUND": "fd",
		"MEMORY_BOUND": "memory", "NETWORK_SOCKET_DENIED": "network", "OUTPUT_BOUND": "output",
		"PID_BOUND": "pid", "PROTECTED_SENTINEL_DENIED": "protected", "SESSION_ESCAPE_CLEANUP": "session",
		"SOURCE_WRITE_DENIED": "source", "WALL_BOUND": "wall", "WORKSPACE_BOUND": "workspace",
	}
	key, ok := programKeys[id]
	if !ok {
		return 0, nil, sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.descriptor_id", "descriptor identity is not compiled")
	}
	for index, planned := range protectedFixedPlan() {
		if planned == id {
			uid := uint32(60000 + index)
			base := "/run/us007-" + key
			return uid, []string{base + "/workspace", base + "/cache", base + "/output", base + "/general"}, nil
		}
	}
	return 0, nil, sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.descriptor_id", "descriptor identity is outside the fixed plan")
}

func validateSBXWritablePaths(observed, allowed []string) error {
	for _, value := range observed {
		path := filepath.Clean(value)
		permitted := false
		for _, root := range allowed {
			cleanRoot := filepath.Clean(root)
			if path == cleanRoot || strings.HasPrefix(path, cleanRoot+string(filepath.Separator)) {
				permitted = true
				break
			}
		}
		if !permitted {
			return fmt.Errorf("writable path %q is outside descriptor closure", path)
		}
	}
	return nil
}

func sbxMountReadOnly(line string) bool {
	fields := strings.Fields(line)
	return len(fields) >= 6 && slices.Contains(strings.Split(fields[5], ","), "ro")
}

func sbxDescriptorContract(id string) (string, string, error) {
	type descriptor struct {
		ID              string `json:"id"`
		ProgramKey      string `json:"program_key"`
		ExpectedOutcome string `json:"expected_outcome"`
	}
	contracts := map[string]descriptor{
		"BENIGN_OPERATION":          {id, "benign", "EXIT_0_PINNED_ARTIFACT"},
		"CACHE_WRITE_DENIED":        {id, "cache", "EXIT_0_DENIED"},
		"CLEAN_EXIT":                {id, "clean", "EXIT_0"},
		"CPU_BOUND":                 {id, "cpu", "CPU_PARENT_KILL"},
		"ENV_SENTINEL_ABSENT":       {id, "secret", "EXIT_0_ABSENT"},
		"FD_BOUND":                  {id, "fd", "FD_PARENT_KILL"},
		"MEMORY_BOUND":              {id, "memory", "MEMORY_PARENT_KILL"},
		"NETWORK_SOCKET_DENIED":     {id, "network", "EXIT_0_DENIED"},
		"OUTPUT_BOUND":              {id, "output", "OUTPUT_PARENT_KILL"},
		"PID_BOUND":                 {id, "pid", "EXIT_23_RLIMIT_NPROC"},
		"PROTECTED_SENTINEL_DENIED": {id, "protected", "EXIT_0_ABSENT"},
		"SESSION_ESCAPE_CLEANUP":    {id, "session", "EXIT_0_UID_SWEEP"},
		"SOURCE_WRITE_DENIED":       {id, "source", "EXIT_0_DENIED"},
		"WALL_BOUND":                {id, "wall", "WALL_PARENT_KILL"},
		"WORKSPACE_BOUND":           {id, "workspace", "EXIT_23_TMPFS_ENOSPC"},
	}
	contract, ok := contracts[id]
	if !ok {
		return "", "", sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.canary_id", "descriptor has no compiled expectation contract")
	}
	data, _ := json.Marshal(contract)
	return intake.DigestBytes(data), contract.ExpectedOutcome, nil
}

func validateSBXDescriptorOutcome(id, expectation string, observation SupervisorObservation, limits resources) error {
	exit := func(code int) bool {
		return observation.ParentExitCode != nil && *observation.ParentExitCode == code && observation.ParentSignal == "" && observation.WorkloadSignal == 0
	}
	valid := false
	switch expectation {
	case "EXIT_0", "EXIT_0_DENIED", "EXIT_0_ABSENT", "EXIT_0_UID_SWEEP":
		valid = observation.Termination == "EXITED" && exit(0)
	case "EXIT_0_PINNED_ARTIFACT":
		artifact := observation.Artifact
		valid = observation.Termination == "EXITED" && exit(0) && artifact.ToolPath == "/usr/bin/go" && artifact.ToolVersion == "go version go1.26.0 linux/arm64" && artifact.Target == "security/fixtures/resource-envelope-canary.go" && artifact.SourceCommit == observation.SourceCommit && artifact.NamespacePath == "/run/us007-benign/output/resource-envelope-canary.o" && artifact.CapturePath == "/tmp/us007-resource-envelope-artifact" && artifact.CaptureChannel == "SUPERVISOR_OWNED_PIPE_REOPENED" && isSHA256Digest(artifact.WorkloadDigest) && artifact.WorkloadDigest == artifact.ParentDigest && artifact.Bytes > 0 && artifact.Bytes <= 4<<20
	case "FD_PARENT_KILL":
		valid = observation.Termination == "FD_LIMIT_EXCEEDED" && observation.Peaks.OpenFiles > observation.EnforcementMechanics.AggregateOpenFiles
	case "CPU_PARENT_KILL":
		valid = observation.Termination == "CPU_LIMIT_EXCEEDED" && observation.Peaks.CPUUsageUsec >= observation.EnforcementMechanics.CPUCorroborationUsec
	case "MEMORY_PARENT_KILL":
		valid = observation.Termination == "MEMORY_LIMIT_EXCEEDED" && observation.Peaks.MemoryBytes > observation.EnforcementMechanics.MemoryKillBytes
	case "OUTPUT_PARENT_KILL":
		valid = observation.Termination == "OUTPUT_LIMIT_EXCEEDED" && observation.Peaks.OutputBytes > limits.OutputBytes
	case "EXIT_23_RLIMIT_NPROC":
		valid = observation.Termination == "PARENT_OBSERVED_NONZERO_EXIT" && exit(23)
	case "WALL_PARENT_KILL":
		valid = observation.Termination == "WALL_LIMIT_EXCEEDED" && observation.WallDurationNanos >= observation.EnforcementMechanics.WallKillThresholdNS
	case "EXIT_23_TMPFS_ENOSPC":
		valid = exit(23) && observation.Peaks.WorkspaceBytes >= limits.WorkspaceBytes-(2<<20)
	}
	if !valid {
		return sbxFinding("SANDBOX_ENFORCEMENT_UNAVAILABLE", "BLOCK", "$.supervisor_observation.termination", "compiled descriptor expectation was not reached for "+id)
	}
	return nil
}

func validateSBXNoForbiddenMounts(data, allowedSourceRoot string) error {
	if strings.TrimSpace(data) == "" {
		return errors.New("missing mountinfo")
	}
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		fields := strings.Fields(line)
		separator := slices.Index(fields, "-")
		if len(fields) < 10 || separator < 6 || separator+2 >= len(fields) {
			return errors.New("invalid mountinfo")
		}
		root, err := unescapeSBXMountInfoField(fields[3])
		if err != nil {
			return err
		}
		target, err := unescapeSBXMountInfoField(fields[4])
		if err != nil {
			return err
		}
		source, err := unescapeSBXMountInfoField(fields[separator+2])
		if err != nil {
			return err
		}
		writable := slices.Contains(strings.Split(fields[5], ","), "rw")
		if separator+3 < len(fields) {
			writable = writable && slices.Contains(strings.Split(fields[separator+3], ","), "rw")
		}
		if allowedSourceRoot != "" && target == allowedSourceRoot && root == "/" && strings.HasPrefix(source, "/dev/") {
			continue
		}
		if allowedSourceRoot != "" && root == allowedSourceRoot && target == "/run/sandbox/source" && fields[separator+1] == "virtiofs" && !writable {
			continue
		}
		forbidden := strings.ToLower(root + " " + target + " " + source)
		if strings.Contains(forbidden, "/protected") || strings.Contains(forbidden, "/canonical") || strings.Contains(forbidden, "/signing") || strings.Contains(forbidden, "/production") || strings.Contains(forbidden, "/cross-company") || strings.Contains(forbidden, "docker.sock") {
			return errors.New("forbidden mount source or target")
		}
	}
	return nil
}

func unescapeSBXMountInfoField(value string) (string, error) {
	var builder strings.Builder
	for index := 0; index < len(value); {
		if value[index] != '\\' {
			builder.WriteByte(value[index])
			index++
			continue
		}
		if index+4 > len(value) {
			return "", errors.New("truncated mountinfo escape")
		}
		escape := value[index : index+4]
		switch escape {
		case `\040`:
			builder.WriteByte(' ')
		case `\011`:
			builder.WriteByte('\t')
		case `\012`:
			builder.WriteByte('\n')
		case `\134`:
			builder.WriteByte('\\')
		default:
			return "", fmt.Errorf("unsupported mountinfo escape %q", escape)
		}
		index += 4
	}
	return builder.String(), nil
}

func validateSbxExecutionReceipt(profile sbxExecutionProfile, request SbxExecutionRequest, receipt SbxExecutionReceipt) error {
	requestDigest, err := SbxExecutionRequestDigest(request)
	if err != nil {
		return err
	}
	if receipt.SchemaVersion != policyVersion || receipt.RequestDigest != requestDigest || receipt.AttemptID != request.AttemptID || receipt.SandboxName != request.SandboxName || receipt.CanaryID != request.CanaryID || receipt.ProfileDigest != request.ProfileDigest || receipt.SandboxPolicyDigest != request.SandboxPolicyDigest || receipt.InputRoot != request.InputRoot || receipt.OutputRoot != request.OutputRoot || receipt.AcceptedRootDigest != request.AcceptedRootDigest || receipt.InventoryRootDigest != request.InventoryRootDigest {
		return sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.receipt", "receipt does not bind the exact request, roots, and identities")
	}
	if receipt.CLIVersion != profile.Runtime.CLIVersion || receipt.CLICommit != profile.Runtime.CLICommit || receipt.CLIBinaryDigest != profile.Runtime.CLIBinaryDigest || receipt.DaemonVersion != profile.Runtime.DaemonVersion {
		return sbxFinding("SBX_RUNTIME_MISMATCH", "QUARANTINE", "$.runtime", "observed CLI or daemon differs from the pinned sbx runtime")
	}
	if receipt.Agent != profile.Runtime.Agent || receipt.TemplateReference != profile.Runtime.TemplateReference || receipt.TemplateIndexDigest != profile.Runtime.TemplateIndexDigest || receipt.TemplatePlatform != profile.Runtime.TemplatePlatform || receipt.TemplateManifestDigest != profile.Runtime.TemplateManifestDigest {
		return sbxFinding("SBX_TEMPLATE_MISMATCH", "QUARANTINE", "$.template", "observed shell template differs from the immutable platform manifest")
	}
	if receipt.WorkspaceMode != "clone" || !receipt.CloneSourceReadOnly || receipt.CPUCount != profile.Isolation.CPUs || receipt.MemoryBytes != profile.Isolation.MemoryBytes || receipt.CompiledSupervisorEnvelope != profile.SupervisorLimits {
		return sbxFinding("SANDBOX_CAPABILITY_MISMATCH", "QUARANTINE", "$.isolation", "clone bounds or compiled supervisor envelope differ from the retained profile")
	}
	if err := validateSupervisorObservation(profile, request, receipt.SupervisorObservation); err != nil {
		return err
	}
	if receipt.NetworkPolicyDigest != profile.Isolation.NetworkPolicy.CanonicalDigest || receipt.NetworkPolicyState != "ACTIVE_DENY_ALL" {
		return sbxFinding("NETWORK_POLICY_VIOLATION", "QUARANTINE", "$.network_policy", "active deny-all rule was not observed")
	}
	if receipt.EnvironmentImportCount != 0 || receipt.SecretImportCount != 0 {
		return sbxFinding("SECRET_ACCESS_DENIED", "QUARANTINE", "$.imports", "host environment or user/service secret material entered the sandbox")
	}
	if receipt.PlatformControlSecretCount != 1 || !receipt.MCPGatewayInfrastructure || receipt.CloneGitBridgePortCount != 1 {
		return sbxFinding("SANDBOX_CAPABILITY_MISMATCH", "QUARANTINE", "$.platform_control_plane", "Docker clone mode must expose exactly its fixed mcpgateway control token and localhost Git bridge, separately from workload capabilities")
	}
	if receipt.HostDockerSocketMounted {
		return sbxFinding("FORBIDDEN_MOUNT_EXPOSED", "REVOKE", "$.host_docker_socket", "host Docker socket was exposed")
	}
	if receipt.SharedSkillsEnabled || receipt.LocalMCPEnabled || receipt.StaticMCPCount != 0 || receipt.KitCount != 0 || receipt.PublishedPortCount != 0 {
		return sbxFinding("FORBIDDEN_CAPABILITY_OBSERVED", "REVOKE", "$.injected_capabilities", "skills, MCP, kits, or published ports were enabled")
	}
	if receipt.CanaryObservationCount != 1 || receipt.ExitCode == nil || receipt.TerminationReason == "" {
		return sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.canary_observations", "one identified canary observation and explicit termination are required")
	}
	if !isSHA256Digest(receipt.ArtifactManifestDigest) || !isSHA256Digest(receipt.OutputRootDigest) {
		return sbxFinding("ARTIFACT_CAPTURE_INCOMPLETE", "QUARANTINE", "$.artifacts", "nonzero artifact inventory and output-root digest are required")
	}
	if !isSHA256Digest(receipt.SourceBeforeDigest) || receipt.SourceBeforeDigest != receipt.SourceAfterDigest {
		return sbxFinding("SOURCE_MUTATION_DETECTED", "QUARANTINE", "$.source_after_digest", "clone source changed during execution")
	}
	started, e1 := time.Parse(time.RFC3339Nano, receipt.StartedAt)
	finished, e2 := time.Parse(time.RFC3339Nano, receipt.FinishedAt)
	removeStarted, e3 := time.Parse(time.RFC3339Nano, receipt.RemovalStartedAt)
	removeFinished, e4 := time.Parse(time.RFC3339Nano, receipt.RemovalFinishedAt)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || finished.Before(started) || removeStarted.Before(finished) || removeFinished.Before(removeStarted) {
		return sbxFinding("SANDBOX_RECEIPT_INVALID", "QUARANTINE", "$.timestamps", "execution and removal timestamps are incomplete or unordered")
	}
	if !receipt.RemoveInvoked || receipt.RemoveExitCode == nil || *receipt.RemoveExitCode != 0 || receipt.SandboxPresentAfterRemoval || !receipt.CleanupComplete {
		return sbxFinding("SANDBOX_CLEANUP_INCOMPLETE", "REVOKE", "$.cleanup", "sbx rm and post-removal absence were not both proven")
	}
	if receipt.Assurance != AssuranceOwnerOnly || receipt.IndependentReviewClaimed || receipt.Production || receipt.Signing || receipt.Publication {
		return sbxFinding("ASSURANCE_CEILING_EXCEEDED", "REVOKE", "$.assurance", "receipt exceeds the sole-owner non-production ceiling")
	}
	return nil
}
