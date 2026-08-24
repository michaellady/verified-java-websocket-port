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

const darwinMavenTestShellDigest = "sha256:094fc5e188feb7cc18906900b1b5c417e03aaed03a9fc132e925f38640d9bd59"
const darwinMavenTestBashDigest = "sha256:35536aea9733aa345b61134a98d00232380898e55b2ea2a07c497011f7dfc7a3"

const promotedJavaSecurityDigest = "sha256:ae19f494ffc23bd1a3a43e9a009f6ceabc9139c42c63d5747a602156d0a76e60"
const mavenTestSecurityOverlayDigest = "sha256:35115b1757d928f1aeeaed799e1d19cdf1b350d9f2071817d68caba12177808b"
const ownerAttestedNotIndependent = "OWNER_ATTESTED_NOT_INDEPENDENT"
const mavenTestSecurityOverlayName = "test-only-java.security"

const promotedTLSDisabledAlgorithms = "SSLv3,TLSv1,TLSv1.1,DTLSv1.0,RC4,DES,MD5withRSA,DH keySize < 1024,EC keySize < 224,3DES_EDE_CBC,anon,NULL,ECDH,TLS_RSA_*,rsa_pkcs1_sha1 usage HandshakeSignature,ecdsa_sha1 usage HandshakeSignature,dsa_sha1 usage HandshakeSignature"
const overlaidTLSDisabledAlgorithms = "SSLv3,TLSv1,TLSv1.1,DTLSv1.0,RC4,DES,MD5withRSA,DH keySize < 1024,EC keySize < 224,3DES_EDE_CBC,anon,NULL,ECDH,rsa_pkcs1_sha1 usage HandshakeSignature,ecdsa_sha1 usage HandshakeSignature,dsa_sha1 usage HandshakeSignature"

const mavenTestSecurityOverlay = `# US-002 authoritative Maven-test overlay only.
# Promoted JDK 17.0.19 master value with exactly TLS_RSA_* removed.
# Loaded with java.security.properties (append), never as the production master.
jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, DTLSv1.0, RC4, DES, \
    MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, \
    ECDH, rsa_pkcs1_sha1 usage HandshakeSignature, \
    ecdsa_sha1 usage HandshakeSignature, dsa_sha1 usage HandshakeSignature
`

const canonicalMavenTestSelector = "org.java_websocket.client.AttachmentTest,org.java_websocket.client.ConnectBlockingTest,org.java_websocket.client.HeadersTest,org.java_websocket.client.SchemaCheckTest," +
	"org.java_websocket.drafts.Draft_6455Test,org.java_websocket.exceptions.IncompleteExceptionTest,org.java_websocket.exceptions.IncompleteHandshakeExceptionTest,org.java_websocket.exceptions.InvalidDataExceptionTest," +
	"org.java_websocket.exceptions.InvalidEncodingExceptionTest,org.java_websocket.exceptions.InvalidFrameExceptionTest,org.java_websocket.exceptions.InvalidHandshakeExceptionTest,org.java_websocket.exceptions.LimitExceededExceptionTest," +
	"org.java_websocket.exceptions.NotSendableExceptionTest,org.java_websocket.exceptions.WebsocketNotConnectedExceptionTest,org.java_websocket.extensions.CompressionExtensionTest,org.java_websocket.extensions.DefaultExtensionTest," +
	"org.java_websocket.extensions.PerMessageDeflateExtensionTest,org.java_websocket.framing.BinaryFrameTest,org.java_websocket.framing.CloseFrameTest,org.java_websocket.framing.ContinuousFrameTest," +
	"org.java_websocket.framing.FramedataImpl1Test,org.java_websocket.framing.PingFrameTest,org.java_websocket.framing.PongFrameTest,org.java_websocket.framing.TextFrameTest," +
	"org.java_websocket.issues.Issue1142Test,org.java_websocket.issues.Issue1160Test,org.java_websocket.issues.Issue1203Test,org.java_websocket.issues.Issue256Test,org.java_websocket.issues.Issue580Test," +
	"org.java_websocket.issues.Issue598Test,org.java_websocket.issues.Issue609Test,org.java_websocket.issues.Issue621Test,org.java_websocket.issues.Issue661Test,org.java_websocket.issues.Issue666Test," +
	"org.java_websocket.issues.Issue677Test,org.java_websocket.issues.Issue713Test,org.java_websocket.issues.Issue732Test,org.java_websocket.issues.Issue764Test,org.java_websocket.issues.Issue765Test," +
	"org.java_websocket.issues.Issue811Test,org.java_websocket.issues.Issue825Test,org.java_websocket.issues.Issue834Test,org.java_websocket.issues.Issue847Test,org.java_websocket.issues.Issue855Test," +
	"org.java_websocket.issues.Issue879Test,org.java_websocket.issues.Issue890Test,org.java_websocket.issues.Issue900Test,org.java_websocket.issues.Issue941Test,org.java_websocket.issues.Issue962Test," +
	"org.java_websocket.issues.Issue997Test,org.java_websocket.misc.OpeningHandshakeRejectionTest,org.java_websocket.protocols.ProtocolHandshakeRejectionTest,org.java_websocket.protocols.ProtocolTest," +
	"org.java_websocket.server.CustomSSLWebSocketServerFactoryTest,org.java_websocket.server.DaemonThreadTest,org.java_websocket.server.DefaultSSLWebSocketServerFactoryTest," +
	"org.java_websocket.server.DefaultWebSocketServerFactoryTest,org.java_websocket.server.SSLParametersWebSocketServerFactoryTest,org.java_websocket.server.WebSocketServerTest," +
	"org.java_websocket.util.Base64Test,org.java_websocket.util.ByteBufferUtilsTest,org.java_websocket.util.CharsetfunctionsTest"

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
	ToolDirectory      string                `json:"tool_directory"`
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
	paths := []*string{&p.SourceDirectory, &p.ToolDirectory, &p.WorkspaceDirectory, &p.CacheDirectory, &p.OutputDirectory}
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
				return finding("SANDBOX_PATH_OVERLAP", "$.paths", "source, tool, workspace, cache, and output roots must be disjoint")
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
	if p.Operation == SandboxMavenAcquire && p.Cache.ClosureManifest != GenesisLedgerHead {
		return finding("INVALID_CACHE_POLICY", "$.cache.closure_manifest_digest", "acquisition must bind the empty genesis cache; its receipt declares the derived closure")
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
	ToolDirectory      string                `json:"tool_directory"`
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
		SandboxMavenAcquire: {
			"--batch-mode", "--errors", "--file", "pom.xml", "dependency:go-offline",
			"-Dtest=org.java_websocket.util.CharsetfunctionsTest", "-DforkCount=0", "test",
		},
		SandboxMavenBuild:     {"--offline", "--batch-mode", "--errors", "--file", "pom.xml", "-DskipTests", "package"},
		SandboxMavenTest:      canonicalMavenArguments(plan.OutputDirectory),
		SandboxJavaOracle:     {"-jar", "java-oracle.jar"},
		SandboxAutobahnClient: {"fuzzing-client"},
		SandboxAutobahnServer: {"fuzzing-server"},
	}[plan.Operation]
	return ExecutionSpec{
		Operation: plan.Operation, ExecutableObjectID: plan.ExecutableObjectID,
		ExecutableDigest: intake.DigestBytes(object), Arguments: append([]string(nil), arguments...),
		Environment: append([]EnvironmentVariable(nil), plan.Environment...), SourceDirectory: plan.SourceDirectory,
		ToolDirectory: plan.ToolDirectory, WorkspaceDirectory: plan.WorkspaceDirectory, CacheDirectory: plan.CacheDirectory, OutputDirectory: plan.OutputDirectory,
		Profile: "read-only-source-disjoint-writes-no-secrets-bounded-deny-default-egress-v1",
		Network: plan.Network, Resources: plan.Resources,
	}, nil
}

func canonicalMavenArguments(outputDirectory string) []string {
	return append([]string{
		"--offline", "--batch-mode", "--errors", "--file", "pom.xml",
	}, canonicalMavenTestProperties(outputDirectory)...)
}

func canonicalMavenTestProperties(outputDirectory string) []string {
	overlay := filepath.Join(outputDirectory, mavenTestSecurityOverlayName)
	return []string{"-DargLine=-Djava.net.preferIPv4Stack=true -Djava.security.properties=" + overlay, "-Dtest=" + canonicalMavenTestSelector, "-DforkedProcessTimeoutInSeconds=120", "test"}
}

func validateMavenTestSecurity(master []byte) error {
	if intake.DigestBytes(master) != promotedJavaSecurityDigest {
		return finding("PROMOTED_JAVA_SECURITY_MISMATCH", "$.java_security", "promoted JDK master security policy differs from its exact pin")
	}
	original, ok := javaSecurityProperty(master, "jdk.tls.disabledAlgorithms")
	if !ok || normalizeSecurityList(original) != promotedTLSDisabledAlgorithms {
		return finding("PROMOTED_JAVA_SECURITY_MISMATCH", "$.java_security.jdk.tls.disabledAlgorithms", "promoted TLS disabled-algorithm policy differs from its exact pin")
	}
	if intake.DigestBytes([]byte(mavenTestSecurityOverlay)) != mavenTestSecurityOverlayDigest {
		return finding("TEST_SECURITY_OVERLAY_MISMATCH", "$.test_security_overlay", "compiled test-only overlay differs from its exact evidence pin")
	}
	overlaid, ok := javaSecurityProperty([]byte(mavenTestSecurityOverlay), "jdk.tls.disabledAlgorithms")
	if !ok || normalizeSecurityList(overlaid) != overlaidTLSDisabledAlgorithms {
		return finding("TEST_SECURITY_OVERLAY_MISMATCH", "$.test_security_overlay", "test-only overlay is not the exact promoted list minus TLS_RSA_*")
	}
	originalTokens := strings.Split(promotedTLSDisabledAlgorithms, ",")
	overlayTokens := strings.Split(overlaidTLSDisabledAlgorithms, ",")
	removed := 0
	filtered := make([]string, 0, len(originalTokens)-1)
	for _, token := range originalTokens {
		if token == "TLS_RSA_*" {
			removed++
			continue
		}
		filtered = append(filtered, token)
	}
	if removed != 1 || !equalStrings(filtered, overlayTokens) {
		return finding("TEST_SECURITY_OVERLAY_MISMATCH", "$.test_security_overlay", "overlay must remove exactly one TLS_RSA_* token and preserve every other promoted restriction")
	}
	return nil
}

func javaSecurityProperty(data []byte, name string) (string, bool) {
	logical := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if logical == "" && (line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!")) {
			continue
		}
		continued := strings.HasSuffix(line, "\\")
		line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
		logical += line
		if continued {
			continue
		}
		separator := strings.IndexByte(logical, '=')
		if separator > 0 && strings.TrimSpace(logical[:separator]) == name {
			return strings.TrimSpace(logical[separator+1:]), true
		}
		logical = ""
	}
	return "", false
}

func normalizeSecurityList(value string) string {
	parts := strings.Split(value, ",")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	return strings.Join(parts, ",")
}

// SandboxEnforcementUnavailable preserves the typed finding API for callers
// that diagnose an unsupported platform. The Darwin executor no longer uses
// this as its implementation path.
func SandboxEnforcementUnavailable(detail string) error {
	if detail == "" {
		detail = "verified platform enforcement is unavailable"
	}
	return finding("SANDBOX_ENFORCEMENT_UNAVAILABLE", "$.sandbox", detail)
}

func SanitizedEnvironment(toolDirectory, workspaceDirectory, cacheDirectory string) ([]EnvironmentVariable, error) {
	tool, err := cleanAbsoluteDirectory(toolDirectory, "$.tool_directory")
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
	if pathsOverlap(tool, workspace) || pathsOverlap(tool, cache) || pathsOverlap(workspace, cache) {
		return nil, finding("SANDBOX_PATH_OVERLAP", "$.environment", "tool, workspace, and cache roots must be disjoint")
	}
	values := map[string]string{
		"HOME": filepath.Join(workspace, "home"), "JAVA_HOME": filepath.Join(tool, "openjdk@17", "17.0.19", "libexec", "openjdk.jdk", "Contents", "Home"),
		"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "MAVEN_HOME": filepath.Join(tool, "apache-maven-3.9.11"),
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
	expected, err := SanitizedEnvironment(plan.ToolDirectory, plan.WorkspaceDirectory, plan.CacheDirectory)
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
	if operation == SandboxMavenTest {
		if network.Mode != "loopback-only" || len(network.AllowedEndpoints) != 1 || network.AllowedEndpoints[0] != "127.0.0.1:*" {
			return finding("NETWORK_POLICY_VIOLATION", "$.network", "authoritative tests permit only IPv4 loopback sockets and no external egress")
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
	SchemaVersion          string                     `json:"schema_version"`
	PlanDigest             string                     `json:"plan_digest"`
	StartedAt              time.Time                  `json:"started_at"`
	FinishedAt             time.Time                  `json:"finished_at"`
	ExitCode               int                        `json:"exit_code"`
	TimedOut               bool                       `json:"timed_out"`
	ObservedMaxMemory      int64                      `json:"observed_max_memory_bytes"`
	ObservedCPUSeconds     int                        `json:"observed_cpu_seconds"`
	ObservedMaxProcesses   int                        `json:"observed_max_processes"`
	ObservedMaxOpenFiles   int                        `json:"observed_max_open_files"`
	ObservedOutputBytes    int64                      `json:"observed_output_bytes"`
	ObservedWorkspaceBytes int64                      `json:"observed_workspace_bytes"`
	ObservedEndpoints      []string                   `json:"observed_endpoints"`
	ObservedTCBExecutables []TCBExecutable            `json:"observed_tcb_executables"`
	EnvironmentDigest      string                     `json:"environment_digest"`
	SourceBeforeDigest     string                     `json:"source_before_digest"`
	SourceAfterDigest      string                     `json:"source_after_digest"`
	CacheManifestDigest    string                     `json:"cache_manifest_digest"`
	JavaSecurityDigest     string                     `json:"java_security_digest"`
	TestSecurityDigest     string                     `json:"test_security_overlay_digest"`
	TestInventoryDigest    string                     `json:"test_inventory_digest"`
	Assurance              string                     `json:"assurance"`
	IndependentReview      bool                       `json:"independent_review_claimed"`
	EnforcementCanaries    SandboxEnforcementCanaries `json:"enforcement_canaries"`
}

type TCBExecutable struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	Assurance string `json:"assurance"`
}

type SandboxEnforcementCanaries struct {
	SanitizedEnvironment   bool `json:"sanitized_environment"`
	UserHomeDenied         bool `json:"user_home_denied"`
	SourceWriteDenied      bool `json:"source_write_denied"`
	DisjointWritesOnly     bool `json:"disjoint_writes_only"`
	WallTimeEnforced       bool `json:"wall_time_enforced"`
	OutputLimitEnforced    bool `json:"output_limit_enforced"`
	WorkspaceLimitEnforced bool `json:"workspace_limit_enforced"`
	ProcessLimitEnforced   bool `json:"process_limit_enforced"`
	CPULimitEnforced       bool `json:"cpu_limit_enforced"`
	MemoryLimitEnforced    bool `json:"memory_limit_enforced"`
	OpenFileLimitEnforced  bool `json:"open_file_limit_enforced"`
	NetworkPolicyEnforced  bool `json:"network_policy_enforced"`
}

func (c SandboxEnforcementCanaries) complete() bool {
	return c.SanitizedEnvironment && c.UserHomeDenied && c.SourceWriteDenied && c.DisjointWritesOnly && c.WallTimeEnforced && c.OutputLimitEnforced && c.WorkspaceLimitEnforced && c.ProcessLimitEnforced && c.CPULimitEnforced && c.MemoryLimitEnforced && c.OpenFileLimitEnforced && c.NetworkPolicyEnforced
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
	if !r.EnforcementCanaries.complete() {
		return finding("SANDBOX_CANARY_INCOMPLETE", "$.enforcement_canaries", "every filesystem, environment, resource, process, and network control must have a passing canary")
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
	if plan.Operation == SandboxMavenAcquire {
		if !isDigest(r.CacheManifestDigest) || r.CacheManifestDigest == GenesisLedgerHead {
			return finding("CACHE_CLOSURE_MISMATCH", "$.cache_manifest_digest", "acquisition must derive a non-genesis frozen cache closure")
		}
	} else if r.CacheManifestDigest != plan.Cache.ClosureManifest {
		return finding("CACHE_CLOSURE_MISMATCH", "$.cache_manifest_digest", "executed cache differs from the planned closure")
	}
	if plan.Operation == SandboxMavenTest {
		if r.JavaSecurityDigest != promotedJavaSecurityDigest || r.TestSecurityDigest != mavenTestSecurityOverlayDigest || !isDigest(r.TestInventoryDigest) || r.Assurance != ownerAttestedNotIndependent || r.IndependentReview {
			return finding("TEST_POLICY_BINDING_MISMATCH", "$.test_security_overlay_digest", "Maven-test receipt must bind the exact owner-attested policy and reconciled inventory without claiming independent review")
		}
	} else if r.JavaSecurityDigest != "" || r.TestSecurityDigest != "" || r.TestInventoryDigest != "" || r.Assurance != "" || r.IndependentReview {
		return finding("TEST_POLICY_BINDING_MISMATCH", "$.test_security_overlay_digest", "non-test receipt cannot claim Maven-test policy evidence")
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
	expectedExecutables := []TCBExecutable{}
	if plan.Operation == SandboxMavenTest {
		expectedExecutables = append(expectedExecutables, TCBExecutable{
			Path: "/bin/sh", Digest: darwinMavenTestShellDigest, Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT",
		}, TCBExecutable{
			Path: "/bin/bash", Digest: darwinMavenTestBashDigest, Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT",
		})
	}
	if len(r.ObservedTCBExecutables) != len(expectedExecutables) {
		return finding("TCB_EXECUTABLE_MISMATCH", "$.observed_tcb_executables", "receipt does not bind the exact operation-specific executable TCB")
	}
	for index := range expectedExecutables {
		if r.ObservedTCBExecutables[index] != expectedExecutables[index] {
			return finding("TCB_EXECUTABLE_MISMATCH", fmt.Sprintf("$.observed_tcb_executables[%d]", index), "receipt executable identity or assurance differs from its exact pin")
		}
	}
	return nil
}
