package lab

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

var operationExecutable = map[SandboxOperation]string{
	SandboxMavenAcquire:   "apache-maven-3.9.11",
	SandboxMavenBuild:     "apache-maven-3.9.11",
	SandboxMavenTest:      "apache-maven-3.9.11",
	SandboxJavaOracle:     "openjdk-17.0.19-homebrew-bottle",
	SandboxAutobahnClient: "autobahn-linux-amd64-image",
	SandboxAutobahnServer: "autobahn-linux-amd64-image",
}

type SandboxOperation string

const (
	SandboxMavenAcquire   SandboxOperation = "maven-acquire"
	SandboxMavenBuild     SandboxOperation = "maven-build"
	SandboxMavenTest      SandboxOperation = "maven-test"
	SandboxJavaOracle     SandboxOperation = "java-oracle"
	SandboxAutobahnClient SandboxOperation = "autobahn-client"
	SandboxAutobahnServer SandboxOperation = "autobahn-server"
)

var sandboxOperations = map[SandboxOperation]struct{}{
	SandboxMavenAcquire: {}, SandboxMavenBuild: {}, SandboxMavenTest: {}, SandboxJavaOracle: {},
	SandboxAutobahnClient: {}, SandboxAutobahnServer: {},
}

var requiredEnvironment = []string{
	"HOME", "JAVA_HOME", "LANG", "LC_ALL", "MAVEN_HOME", "MAVEN_OPTS", "SOURCE_DATE_EPOCH", "TZ",
}

func RequiredEnvironmentNames() []string { return append([]string(nil), requiredEnvironment...) }

type EnvironmentVariable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ResourceLimits struct {
	WallTimeSeconds   int   `json:"wall_time_seconds"`
	CPUTimeSeconds    int   `json:"cpu_time_seconds"`
	MemoryBytes       int64 `json:"memory_bytes"`
	MaxProcesses      int   `json:"max_processes"`
	MaxOpenFiles      int   `json:"max_open_files"`
	MaxOutputBytes    int64 `json:"max_output_bytes"`
	MaxWorkspaceBytes int64 `json:"max_workspace_bytes"`
}

type CachePolicy struct {
	Isolated             bool   `json:"isolated"`
	Mode                 string `json:"mode"`
	ClosureManifest      string `json:"closure_manifest_digest"`
	OfflineAuthoritative bool   `json:"offline_authoritative"`
}

type SourcePolicy struct {
	ReadOnly             bool `json:"read_only"`
	NoFollowLinks        bool `json:"no_follow_links"`
	AcceptedRootOnly     bool `json:"accepted_root_only"`
	ProductionUnmodified bool `json:"production_unmodified"`
}

type NetworkPolicy struct {
	Mode             string   `json:"mode"`
	AllowedEndpoints []string `json:"allowed_endpoints"`
	AuditRequired    bool     `json:"audit_required"`
}

type SandboxPlan struct {
	SchemaVersion      string                `json:"schema_version"`
	PlanID             string                `json:"plan_id"`
	Operation          SandboxOperation      `json:"operation"`
	AcceptedRootDigest string                `json:"accepted_root_digest"`
	ExecutableObjectID string                `json:"executable_object_id"`
	SourceDirectory    string                `json:"source_directory"`
	WorkspaceDirectory string                `json:"workspace_directory"`
	CacheDirectory     string                `json:"cache_directory"`
	OutputDirectory    string                `json:"output_directory"`
	Environment        []EnvironmentVariable `json:"environment"`
	Resources          ResourceLimits        `json:"resources"`
	Cache              CachePolicy           `json:"cache"`
	Source             SourcePolicy          `json:"source"`
	Network            NetworkPolicy         `json:"network"`
	Secrets            string                `json:"secrets"`
}

func DecodeSandboxPlan(data []byte) (SandboxPlan, error) {
	var plan SandboxPlan
	if err := intake.DecodeStrict(data, &plan); err != nil {
		return SandboxPlan{}, err
	}
	return plan, plan.Validate()
}

func (p SandboxPlan) Validate() error {
	if p.SchemaVersion != "1.0.0" || !refPattern.MatchString(p.PlanID) {
		return finding("INVALID_SANDBOX_PLAN", "$.plan_id", "schema or plan ID is invalid")
	}
	if _, ok := sandboxOperations[p.Operation]; !ok {
		return finding("ARBITRARY_COMMAND_DENIED", "$.operation", "operation is not in the frozen sandbox registry")
	}
	if p.ExecutableObjectID != operationExecutable[p.Operation] {
		return finding("ARBITRARY_COMMAND_DENIED", "$.executable_object_id", "operation must use its exact frozen executable object")
	}
	if !isDigest(p.AcceptedRootDigest) || !idPattern.MatchString(p.ExecutableObjectID) {
		return finding("INVALID_SANDBOX_PLAN", "$.accepted_root_digest", "accepted root or executable object binding is invalid")
	}
	paths := []*string{&p.SourceDirectory, &p.WorkspaceDirectory, &p.CacheDirectory, &p.OutputDirectory}
	for index, pointer := range paths {
		clean, err := cleanAbsoluteDirectory(*pointer, fmt.Sprintf("$.paths[%d]", index))
		if err != nil {
			return err
		}
		*pointer = clean
	}
	for left := range paths {
		for right := left + 1; right < len(paths); right++ {
			if pathsOverlap(*paths[left], *paths[right]) {
				return finding("SANDBOX_PATH_OVERLAP", "$.paths", "source, workspace, cache, and output roots must be disjoint")
			}
		}
	}
	if !p.Source.ReadOnly || !p.Source.NoFollowLinks || !p.Source.AcceptedRootOnly || !p.Source.ProductionUnmodified {
		return finding("UNSAFE_SOURCE_POLICY", "$.source", "authoritative source must be read-only, no-follow, accepted-root-only, and unmodified")
	}
	if !p.Cache.Isolated || p.Cache.Mode != "disposable" || !isDigest(p.Cache.ClosureManifest) {
		return finding("UNSAFE_CACHE_POLICY", "$.cache", "cache must be disposable, isolated, and closure-bound")
	}
	if p.Operation == SandboxMavenAcquire && p.Cache.OfflineAuthoritative {
		return finding("INVALID_CACHE_POLICY", "$.cache.offline_authoritative", "acquisition populates a disposable cache and is not an authoritative offline run")
	}
	if p.Operation != SandboxMavenAcquire && !p.Cache.OfflineAuthoritative {
		return finding("NETWORK_POLICY_VIOLATION", "$.cache.offline_authoritative", "authoritative execution after acquisition must be offline")
	}
	if p.Secrets != "none" {
		return finding("SECRET_ACCESS_DENIED", "$.secrets", "sandbox plan must expose no secrets")
	}
	if err := validateEnvironment(p); err != nil {
		return err
	}
	if err := validateResources(p.Resources); err != nil {
		return err
	}
	return validateNetwork(p.Operation, p.Network)
}

// ExecutionSpec is intentionally not os/exec.Cmd: its operation and arguments
// are closed enums, so callers cannot smuggle a shell, argv, or inherited env.
type ExecutionSpec struct {
	Operation          SandboxOperation      `json:"operation"`
	ExecutableObjectID string                `json:"executable_object_id"`
	ExecutableDigest   string                `json:"executable_digest"`
	Arguments          []string              `json:"arguments"`
	Environment        []EnvironmentVariable `json:"environment"`
	SourceDirectory    string                `json:"source_directory"`
	WorkspaceDirectory string                `json:"workspace_directory"`
	CacheDirectory     string                `json:"cache_directory"`
	OutputDirectory    string                `json:"output_directory"`
	Profile            string                `json:"profile"`
	Network            NetworkPolicy         `json:"network"`
	Resources          ResourceLimits        `json:"resources"`
}

// BuildExecutionSpec resolves an enumerated operation against verified bytes.
// The platform executor must still prove OS/container enforcement before use.
func BuildExecutionSpec(plan SandboxPlan, root *AcceptedRoot) (ExecutionSpec, error) {
	if err := plan.Validate(); err != nil {
		return ExecutionSpec{}, err
	}
	if root == nil || root.manifest.RootDigest != plan.AcceptedRootDigest {
		return ExecutionSpec{}, finding("ACCEPTED_ROOT_MISMATCH", "$.accepted_root_digest", "sandbox plan is not bound to the verified accepted root")
	}
	object, ok := root.Object(plan.ExecutableObjectID)
	if !ok {
		return ExecutionSpec{}, finding("MISSING_EXECUTABLE_OBJECT", "$.executable_object_id", "frozen operation executable is absent from the accepted root")
	}
	arguments := map[SandboxOperation][]string{
		SandboxMavenAcquire:   {"--batch-mode", "--errors", "--file", "pom.xml", "dependency:go-offline"},
		SandboxMavenBuild:     {"--offline", "--batch-mode", "--errors", "--file", "pom.xml", "-DskipTests", "package"},
		SandboxMavenTest:      {"--offline", "--batch-mode", "--errors", "--file", "pom.xml", "test"},
		SandboxJavaOracle:     {"-jar", "java-oracle.jar"},
		SandboxAutobahnClient: {"fuzzing-client"},
		SandboxAutobahnServer: {"fuzzing-server"},
	}[plan.Operation]
	return ExecutionSpec{
		Operation: plan.Operation, ExecutableObjectID: plan.ExecutableObjectID,
		ExecutableDigest: intake.DigestBytes(object), Arguments: append([]string(nil), arguments...),
		Environment: append([]EnvironmentVariable(nil), plan.Environment...), SourceDirectory: plan.SourceDirectory,
		WorkspaceDirectory: plan.WorkspaceDirectory, CacheDirectory: plan.CacheDirectory, OutputDirectory: plan.OutputDirectory,
		Profile: "read-only-source-disjoint-writes-no-secrets-bounded-deny-default-egress-v1",
		Network: plan.Network, Resources: plan.Resources,
	}, nil
}

// SandboxEnforcementUnavailable is returned unless a platform-specific layer
// can prove every declared filesystem, process, resource, and network control.
func SandboxEnforcementUnavailable(detail string) error {
	if detail == "" {
		detail = "no verified platform sandbox executor is installed"
	}
	return finding("SANDBOX_ENFORCEMENT_UNAVAILABLE", "$.sandbox", detail)
}

// ExecuteSandbox deliberately cannot manufacture a successful receipt. The
// closed spec is usable only after a platform module proves all controls.
func ExecuteSandbox(plan SandboxPlan, root *AcceptedRoot) (*SandboxReceipt, error) {
	if _, err := BuildExecutionSpec(plan, root); err != nil {
		return nil, err
	}
	return nil, SandboxEnforcementUnavailable("no verified OS/container enforcement backend is linked")
}

func SanitizedEnvironment(sourceDirectory, workspaceDirectory, cacheDirectory string) ([]EnvironmentVariable, error) {
	source, err := cleanAbsoluteDirectory(sourceDirectory, "$.source_directory")
	if err != nil {
		return nil, err
	}
	workspace, err := cleanAbsoluteDirectory(workspaceDirectory, "$.workspace_directory")
	if err != nil {
		return nil, err
	}
	cache, err := cleanAbsoluteDirectory(cacheDirectory, "$.cache_directory")
	if err != nil {
		return nil, err
	}
	if pathsOverlap(source, workspace) || pathsOverlap(source, cache) || pathsOverlap(workspace, cache) {
		return nil, finding("SANDBOX_PATH_OVERLAP", "$.environment", "source, workspace, and cache roots must be disjoint")
	}
	values := map[string]string{
		"HOME": filepath.Join(workspace, "home"), "JAVA_HOME": filepath.Join(source, ".lab-tools", "java"),
		"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "MAVEN_HOME": filepath.Join(source, ".lab-tools", "maven"),
		"MAVEN_OPTS":        "-Djava.io.tmpdir=" + filepath.Join(workspace, "tmp") + " -Dmaven.repo.local=" + filepath.Join(cache, "repository"),
		"SOURCE_DATE_EPOCH": "0", "TZ": "UTC",
	}
	environment := make([]EnvironmentVariable, len(requiredEnvironment))
	for index, name := range requiredEnvironment {
		environment[index] = EnvironmentVariable{Name: name, Value: values[name]}
	}
	return environment, nil
}

func validateEnvironment(plan SandboxPlan) error {
	environment := plan.Environment
	if len(environment) != len(requiredEnvironment) {
		return finding("ENVIRONMENT_ALLOWLIST_MISMATCH", "$.environment", "environment must contain the exact frozen allowlist")
	}
	expected, err := SanitizedEnvironment(plan.SourceDirectory, plan.WorkspaceDirectory, plan.CacheDirectory)
	if err != nil {
		return err
	}
	for index, variable := range environment {
		if variable != expected[index] || variable.Name != requiredEnvironment[index] || variable.Value == "" || len(variable.Value) > 1024 || strings.ContainsAny(variable.Value, "\x00\r\n") {
			return finding("ENVIRONMENT_ALLOWLIST_MISMATCH", fmt.Sprintf("$.environment[%d]", index), "environment is not exact, sorted, bounded, and single-line")
		}
	}
	return nil
}

func validateResources(resources ResourceLimits) error {
	if resources.WallTimeSeconds <= 0 || resources.WallTimeSeconds > 3600 || resources.CPUTimeSeconds <= 0 || resources.CPUTimeSeconds > resources.WallTimeSeconds || resources.MemoryBytes < 64<<20 || resources.MemoryBytes > 16<<30 || resources.MaxProcesses <= 0 || resources.MaxProcesses > 512 || resources.MaxOpenFiles <= 0 || resources.MaxOpenFiles > 4096 || resources.MaxOutputBytes <= 0 || resources.MaxOutputBytes > 1<<30 || resources.MaxWorkspaceBytes <= 0 || resources.MaxWorkspaceBytes > 16<<30 {
		return finding("INVALID_RESOURCE_LIMIT", "$.resources", "resource bounds are absent or outside the frozen safety envelope")
	}
	return nil
}

func validateNetwork(operation SandboxOperation, network NetworkPolicy) error {
	if !network.AuditRequired {
		return finding("NETWORK_POLICY_VIOLATION", "$.network.audit_required", "network access must always be audited")
	}
	if operation == SandboxMavenAcquire {
		if network.Mode != "maven-central-only" || len(network.AllowedEndpoints) != 1 || network.AllowedEndpoints[0] != "https://repo.maven.apache.org:443" {
			return finding("NETWORK_POLICY_VIOLATION", "$.network", "Maven acquisition permits exactly audited https://repo.maven.apache.org:443")
		}
		return nil
	}
	if operation != SandboxAutobahnClient && operation != SandboxAutobahnServer {
		if network.Mode != "deny-all" || len(network.AllowedEndpoints) != 0 {
			return finding("NETWORK_POLICY_VIOLATION", "$.network", "non-Autobahn authoritative operations deny all network")
		}
		return nil
	}
	if network.Mode != "local-autobahn" || len(network.AllowedEndpoints) != 1 {
		return finding("NETWORK_POLICY_VIOLATION", "$.network", "Autobahn operations permit exactly one audited loopback endpoint")
	}
	host, port, err := net.SplitHostPort(network.AllowedEndpoints[0])
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || host != "127.0.0.1" || portNumber <= 0 || portNumber > 65535 {
		return finding("NETWORK_POLICY_VIOLATION", "$.network.allowed_endpoints[0]", "endpoint must be an explicit nonzero IPv4 loopback port")
	}
	return nil
}

func (p SandboxPlan) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	bytes, err := intake.CanonicalJSON(p)
	if err != nil {
		return "", err
	}
	return intake.DigestBytes(bytes), nil
}

type SandboxReceipt struct {
	SchemaVersion          string    `json:"schema_version"`
	PlanDigest             string    `json:"plan_digest"`
	StartedAt              time.Time `json:"started_at"`
	FinishedAt             time.Time `json:"finished_at"`
	ExitCode               int       `json:"exit_code"`
	TimedOut               bool      `json:"timed_out"`
	ObservedMaxMemory      int64     `json:"observed_max_memory_bytes"`
	ObservedCPUSeconds     int       `json:"observed_cpu_seconds"`
	ObservedMaxProcesses   int       `json:"observed_max_processes"`
	ObservedMaxOpenFiles   int       `json:"observed_max_open_files"`
	ObservedOutputBytes    int64     `json:"observed_output_bytes"`
	ObservedWorkspaceBytes int64     `json:"observed_workspace_bytes"`
	ObservedEndpoints      []string  `json:"observed_endpoints"`
	EnvironmentDigest      string    `json:"environment_digest"`
	SourceBeforeDigest     string    `json:"source_before_digest"`
	SourceAfterDigest      string    `json:"source_after_digest"`
	CacheManifestDigest    string    `json:"cache_manifest_digest"`
}

func DecodeSandboxReceipt(data []byte, plan SandboxPlan) (SandboxReceipt, error) {
	var receipt SandboxReceipt
	if err := intake.DecodeStrict(data, &receipt); err != nil {
		return SandboxReceipt{}, err
	}
	return receipt, receipt.Validate(plan)
}

func (r SandboxReceipt) Validate(plan SandboxPlan) error {
	planDigest, err := plan.Digest()
	if err != nil {
		return err
	}
	if r.SchemaVersion != "1.0.0" || r.PlanDigest != planDigest || r.StartedAt.IsZero() || !r.FinishedAt.After(r.StartedAt) || r.ExitCode < 0 || r.ExitCode > 255 {
		return finding("INVALID_SANDBOX_RECEIPT", "$", "receipt schema, plan binding, time interval, or exit code is invalid")
	}
	if r.ObservedMaxMemory < 0 || r.ObservedMaxMemory > plan.Resources.MemoryBytes || r.ObservedOutputBytes < 0 || r.ObservedOutputBytes > plan.Resources.MaxOutputBytes {
		return finding("RESOURCE_LIMIT_EXCEEDED", "$.resources", "observed usage exceeds the plan")
	}
	if r.ObservedCPUSeconds < 0 || r.ObservedCPUSeconds > plan.Resources.CPUTimeSeconds || r.ObservedMaxProcesses < 0 || r.ObservedMaxProcesses > plan.Resources.MaxProcesses || r.ObservedMaxOpenFiles < 0 || r.ObservedMaxOpenFiles > plan.Resources.MaxOpenFiles || r.ObservedWorkspaceBytes < 0 || r.ObservedWorkspaceBytes > plan.Resources.MaxWorkspaceBytes || r.FinishedAt.Sub(r.StartedAt) > time.Duration(plan.Resources.WallTimeSeconds)*time.Second {
		return finding("RESOURCE_LIMIT_EXCEEDED", "$.resources", "observed CPU, process, file, workspace, or wall-time usage exceeds the plan")
	}
	environmentBytes, err := intake.CanonicalJSON(plan.Environment)
	if err != nil || r.EnvironmentDigest != intake.DigestBytes(environmentBytes) {
		return finding("ENVIRONMENT_ALLOWLIST_MISMATCH", "$.environment_digest", "receipt does not bind the exact plan environment")
	}
	if r.SourceBeforeDigest == "" || r.SourceBeforeDigest != r.SourceAfterDigest || !isDigest(r.SourceBeforeDigest) {
		return finding("SOURCE_MUTATION_DETECTED", "$.source_after_digest", "read-only source changed or was not measured")
	}
	if r.CacheManifestDigest != plan.Cache.ClosureManifest {
		return finding("CACHE_CLOSURE_MISMATCH", "$.cache_manifest_digest", "executed cache differs from the planned closure")
	}
	allowed := append([]string(nil), plan.Network.AllowedEndpoints...)
	observed := append([]string(nil), r.ObservedEndpoints...)
	sort.Strings(allowed)
	sort.Strings(observed)
	if len(observed) != len(allowed) {
		return finding("NETWORK_POLICY_VIOLATION", "$.observed_endpoints", "observed network endpoints differ from the exact plan")
	}
	for index := range observed {
		if observed[index] != allowed[index] || index > 0 && observed[index] == observed[index-1] {
			return finding("NETWORK_POLICY_VIOLATION", "$.observed_endpoints", "observed network endpoints differ from the exact plan")
		}
	}
	return nil
}
