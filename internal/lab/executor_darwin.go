//go:build darwin

package lab

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	promotedJavaDigest      = "sha256:7db0dd5c0c4dc931244875d0723783a32cc7912922e6aaac1dbb744bf8ae837f"
	promotedJavacDigest     = "sha256:a7905f0d4944e3aee8aa20673f199a688b815545f930ee537b3d28a578ae2861"
	promotedJSpawnDigest    = "sha256:ee21ec9f76cafc86faffb2e2a95be3b9d00ebb046a09a3140b2a6bcb530ba91f"
	promotedMavenCoreDigest = "sha256:93d3c0523dda6c86c6620d9e692e7df39d0e2e4e4cd860061a8c0d274c2ad185"
	promotedClassworlds     = "sha256:1ad3292cd563381e3fd632f3fded1988f9e9b2be7a9f3db63ff4c4cedba13fa5"
)

const controlledCanaryPlatform = "DARWIN_SANDBOX_EXEC"

func controlledCanaryRoles() []string { return []string{"SANDBOX_SUPERVISOR", "SECURITYCTL"} }

func ControlledCanaryPlanDigest(request ControlledCanaryRequest) (string, error) {
	if err := validateControlledCanaryRequest(request); err != nil {
		return "", err
	}
	_, executableDigest, err := controlledCanaryExecutableIdentity()
	if err != nil {
		return "", err
	}
	canonical, err := intake.CanonicalJSON(struct {
		SchemaVersion    string         `json:"schema_version"`
		Operation        string         `json:"operation"`
		CanaryID         string         `json:"canary_id"`
		PolicyDigest     string         `json:"policy_digest"`
		PlatformIdentity string         `json:"platform_identity"`
		ExecutableDigest string         `json:"executable_digest"`
		ExecutableRoles  []string       `json:"executable_roles"`
		PromotionScope   string         `json:"promotion_scope"`
		Resources        ResourceLimits `json:"resources"`
	}{
		SchemaVersion: "1.0.0", Operation: "CONTROLLED_CANARY", CanaryID: request.CanaryID,
		PolicyDigest: request.PolicyDigest, PlatformIdentity: controlledCanaryPlatform,
		ExecutableDigest: executableDigest, ExecutableRoles: controlledCanaryRoles(),
		PromotionScope: "CONTROLLED_CANARY", Resources: request.Resources,
	})
	if err != nil {
		return "", err
	}
	return intake.DigestBytes(canonical), nil
}

func ExecuteControlledCanary(request ControlledCanaryRequest) (*ControlledCanaryReceipt, error) {
	expected, err := ControlledCanaryPlanDigest(request)
	if err != nil {
		return nil, err
	}
	if request.PlanDigest != expected {
		return nil, finding("INVALID_SANDBOX_PLAN", "$.plan_digest", "controlled canary plan does not bind the exact policy and os.Executable bytes")
	}
	_, digest, err := controlledCanaryExecutableIdentity()
	if err != nil {
		return nil, err
	}
	return nil, finding("UNPROMOTED_EXECUTABLE", "$.promotion_records", "fresh authenticated owner-only promotion records for SECURITYCTL and SANDBOX_SUPERVISOR roles scoped to CONTROLLED_CANARY are absent for exact executable "+digest)
}

func controlledCanaryExecutableIdentity() (string, string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", "", finding("TCB_EXECUTABLE_MISMATCH", "$.executable", err.Error())
	}
	resolved, err := filepath.EvalSymlinks(self)
	if err != nil {
		return "", "", finding("TCB_EXECUTABLE_MISMATCH", "$.executable", err.Error())
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", finding("TCB_EXECUTABLE_MISMATCH", "$.executable", "os.Executable must resolve to one regular non-link file")
	}
	data, err := readBoundedRegular(resolved, maxObjectBytes)
	if err != nil {
		return "", "", finding("TCB_EXECUTABLE_MISMATCH", "$.executable", err.Error())
	}
	return resolved, intake.DigestBytes(data), nil
}

type executionBreach struct {
	code   string
	detail string
}

type executionMonitor struct {
	mutex             sync.Mutex
	cancel            context.CancelFunc
	breach            *executionBreach
	outputBytes       int64
	maxMemory         int64
	maxOpenFiles      int
	maxProcesses      int
	maxWorkspaceBytes int64
	cpuSeconds        int
	exitCode          int
	stdout            *os.File
	stderr            *os.File
}

func ExecuteSandbox(plan SandboxPlan, root *AcceptedRoot) (*SandboxReceipt, error) {
	spec, err := BuildExecutionSpec(plan, root)
	if err != nil {
		return nil, err
	}
	if plan.Operation == SandboxAutobahnClient || plan.Operation == SandboxAutobahnServer {
		return nil, finding("DOCKER_EXECUTOR_REQUIRED", "$.operation", "Autobahn operations require the fixed digest Docker controller")
	}
	if plan.Operation == SandboxJavaOracle {
		return nil, finding("JAVA_ORACLE_INPUT_REQUIRED", "$.operation", "Java oracle execution requires the fixed JSONL scenario runner")
	}
	if err := requireDarwinDisposablePaths(plan); err != nil {
		return nil, err
	}
	if err := prepareExecutionTrees(plan, root); err != nil {
		return nil, err
	}
	javaPath, jspawnPath, mavenHome, err := verifyPromotedToolchain(plan.ToolDirectory)
	if err != nil {
		return nil, err
	}
	var testLayout *mavenTestLayout
	if plan.Operation == SandboxMavenTest {
		testLayout, err = prepareMavenTestExecution(plan, javaPath)
		if err != nil {
			return nil, err
		}
	}
	observedTCBExecutables := []TCBExecutable{}
	if plan.Operation == SandboxMavenTest {
		if err := verifyDarwinMavenTestShell("/bin/sh", darwinMavenTestShellDigest); err != nil {
			return nil, err
		}
		if err := verifyDarwinMavenTestShell("/bin/bash", darwinMavenTestBashDigest); err != nil {
			return nil, err
		}
		observedTCBExecutables = append(observedTCBExecutables, TCBExecutable{
			Path: "/bin/sh", Digest: darwinMavenTestShellDigest, Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT",
		}, TCBExecutable{
			Path: "/bin/bash", Digest: darwinMavenTestBashDigest, Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT",
		})
	}
	sourceBefore, _, err := digestTree(plan.SourceDirectory, true)
	if err != nil {
		return nil, err
	}
	buildBefore, _, err := digestProductionSourceTree(filepath.Join(plan.WorkspaceDirectory, "build"))
	if err != nil || buildBefore != sourceBefore {
		return nil, finding("BUILD_SOURCE_COPY_MISMATCH", "$.workspace_directory", "writable build copy differs from accepted source before execution")
	}
	cacheBefore := GenesisLedgerHead
	if plan.Operation != SandboxMavenAcquire {
		cacheBefore, _, err = digestTree(plan.CacheDirectory, true)
		if err != nil || cacheBefore != plan.Cache.ClosureManifest {
			return nil, finding("CACHE_CLOSURE_MISMATCH", "$.cache_directory", "offline cache bytes do not equal the frozen closure")
		}
	}
	profilePath, actualEndpoint, proxyStop, err := prepareSandboxNetwork(plan)
	if err != nil {
		return nil, err
	}
	if proxyStop != nil {
		defer proxyStop()
	}
	self, err := os.Executable()
	if err != nil {
		return nil, finding("EXECUTOR_START_FAILED", "$.executor", err.Error())
	}
	profile, err := darwinSandboxProfile(plan, self, javaPath, jspawnPath, actualEndpoint)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		return nil, finding("EXECUTOR_START_FAILED", profilePath, err.Error())
	}
	if err := syncDir(filepath.Dir(profilePath)); err != nil {
		return nil, err
	}
	canaries, err := runDarwinPolicyCanaries(plan, profilePath, self, javaPath, actualEndpoint)
	if err != nil {
		return nil, err
	}
	arguments := []string{"-f", profilePath, self, "__sandbox-child", string(plan.Operation), javaPath, mavenHome, plan.SourceDirectory, plan.CacheDirectory, plan.OutputDirectory, plan.WorkspaceDirectory, strconv.Itoa(plan.Resources.CPUTimeSeconds), strconv.Itoa(plan.Resources.MaxOpenFiles), strconv.FormatInt(plan.Resources.MaxOutputBytes, 10), strconv.FormatInt(plan.Resources.MemoryBytes, 10), actualEndpoint}
	environment := make([]string, len(plan.Environment))
	for index, variable := range plan.Environment {
		environment[index] = variable.Name + "=" + variable.Value
	}
	started := time.Now().UTC()
	result, err := runMonitored(plan, "/usr/bin/sandbox-exec", arguments, environment)
	finished := time.Now().UTC()
	if err != nil {
		return nil, err
	}
	testInventoryDigest := ""
	if plan.Operation == SandboxMavenTest {
		inventory, reconcileErr := ReconcileSurefireReports(filepath.Join(plan.WorkspaceDirectory, "build", "target", "surefire-reports"), testLayout.staticTests, testLayout.selector, testLayout.suites, testLayout.candidates, testLayout.classifications)
		if reconcileErr != nil {
			return nil, reconcileErr
		}
		inventoryBytes, canonicalErr := intake.CanonicalJSON(inventory)
		if canonicalErr != nil {
			return nil, finding("INVALID_TEST_INVENTORY", "$.test_inventory", canonicalErr.Error())
		}
		if err := writeExclusiveDurable(filepath.Join(plan.OutputDirectory, "test-inventory.json"), inventoryBytes); err != nil {
			return nil, err
		}
		testInventoryDigest = intake.DigestBytes(inventoryBytes)
	}
	sourceAfter, _, err := digestTree(plan.SourceDirectory, true)
	if err != nil || sourceAfter != sourceBefore {
		return nil, finding("SOURCE_MUTATION_DETECTED", "$.source_directory", "accepted source changed during execution")
	}
	buildAfter, _, err := digestProductionSourceTree(filepath.Join(plan.WorkspaceDirectory, "build"))
	if err != nil || buildAfter != sourceBefore {
		return nil, finding("BUILD_SOURCE_MUTATION_DETECTED", "$.workspace_directory", "production bytes in the writable build copy changed during execution")
	}
	cacheAfter, _, err := digestTree(plan.CacheDirectory, true)
	if err != nil {
		return nil, err
	}
	if plan.Operation != SandboxMavenAcquire && cacheAfter != cacheBefore {
		return nil, finding("CACHE_CLOSURE_MISMATCH", "$.cache_directory", "offline execution changed the frozen cache")
	}
	planDigest, _ := plan.Digest()
	environmentBytes, _ := intake.CanonicalJSON(plan.Environment)
	observedEndpoints := []string{}
	if plan.Operation == SandboxMavenAcquire {
		connected, err := verifiedMavenAudit(filepath.Join(plan.OutputDirectory, "maven-egress.jsonl"))
		if err != nil || !connected {
			return nil, finding("MAVEN_EGRESS_AUDIT_MISSING", "$.network", "acquisition did not durably audit the exact Maven Central authority")
		}
		observedEndpoints = []string{"https://repo.maven.apache.org:443"}
	} else if plan.Operation == SandboxMavenTest {
		// The sentinel is the exact observed policy class: both the Go and Java
		// canaries prove loopback connect and wildcard ephemeral bind work while
		// a non-loopback connect remains denied before authoritative tests run.
		observedEndpoints = append(observedEndpoints, plan.Network.AllowedEndpoints...)
	}
	receipt := &SandboxReceipt{
		SchemaVersion: "1.0.0", PlanDigest: planDigest, StartedAt: started, FinishedAt: finished,
		ExitCode: result.exitCode, TimedOut: false, ObservedMaxMemory: result.maxMemory, ObservedCPUSeconds: result.cpuSeconds,
		ObservedMaxProcesses: result.maxProcesses, ObservedMaxOpenFiles: result.maxOpenFiles,
		ObservedOutputBytes: result.outputBytes, ObservedWorkspaceBytes: result.maxWorkspaceBytes,
		ObservedEndpoints: observedEndpoints, ObservedTCBExecutables: observedTCBExecutables, EnvironmentDigest: intake.DigestBytes(environmentBytes),
		SourceBeforeDigest: sourceBefore, SourceAfterDigest: sourceAfter, CacheManifestDigest: cacheAfter,
		EnforcementCanaries: canaries,
	}
	if plan.Operation == SandboxMavenTest {
		receipt.JavaSecurityDigest = promotedJavaSecurityDigest
		receipt.TestSecurityDigest = mavenTestSecurityOverlayDigest
		receipt.TestInventoryDigest = testInventoryDigest
		receipt.Assurance = ownerAttestedNotIndependent
		receipt.IndependentReview = false
	}
	if err := receipt.Validate(plan); err != nil {
		return nil, err
	}
	_ = spec
	return receipt, nil
}

type mavenTestLayout struct {
	staticTests     []StaticTest
	selector        []string
	suites          []AggregateSuite
	candidates      []NonTestCandidate
	classifications []NonTestClassification
}

func prepareMavenTestExecution(plan SandboxPlan, javaPath string) (*mavenTestLayout, error) {
	javaHome := filepath.Dir(filepath.Dir(javaPath))
	master, err := readBoundedRegular(filepath.Join(javaHome, "conf", "security", "java.security"), maxManifestBytes)
	if err != nil {
		return nil, err
	}
	if err := validateMavenTestSecurity(master); err != nil {
		return nil, err
	}
	buildSource := filepath.Join(plan.WorkspaceDirectory, "build")
	staticTests, selector, suites, err := DiscoverJavaTests(filepath.Join(buildSource, "src", "test", "java"))
	if err != nil {
		return nil, err
	}
	if len(staticTests) != 231 || len(selector) != 62 || len(suites) != 10 || strings.Join(selector, ",") != canonicalMavenTestSelector {
		return nil, finding("TEST_SELECTOR_MISMATCH", "$.canonical_selector", "accepted source must derive the exact 231-method, 62-class selector and 10 executable aggregate suites")
	}
	candidates, classifications, err := PinnedJavaNonTests(buildSource)
	if err != nil {
		return nil, err
	}
	if err := writeExclusiveDurable(filepath.Join(plan.OutputDirectory, mavenTestSecurityOverlayName), []byte(mavenTestSecurityOverlay)); err != nil {
		return nil, err
	}
	return &mavenTestLayout{staticTests: staticTests, selector: selector, suites: suites, candidates: candidates, classifications: classifications}, nil
}

func writeExclusiveDurable(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return finding("EVIDENCE_WRITE_FAILED", path, err.Error())
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	written, err := file.Write(data)
	if err != nil || written != len(data) {
		return finding("EVIDENCE_WRITE_FAILED", path, errors.Join(err, io.ErrShortWrite).Error())
	}
	if err := file.Sync(); err != nil {
		return finding("EVIDENCE_WRITE_FAILED", path, err.Error())
	}
	if err := file.Close(); err != nil {
		return finding("EVIDENCE_WRITE_FAILED", path, err.Error())
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return finding("EVIDENCE_WRITE_FAILED", path, err.Error())
	}
	remove = false
	return nil
}

func verifyDarwinMavenTestShell(path, expectedDigest string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return finding("TCB_EXECUTABLE_MISMATCH", path, "Surefire shell must be an immutable regular OS executable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return finding("TCB_EXECUTABLE_MISMATCH", path, "Surefire shell must be root-owned")
	}
	data, err := readBoundedRegular(path, maxObjectBytes)
	if err != nil || intake.DigestBytes(data) != expectedDigest {
		return finding("TCB_EXECUTABLE_MISMATCH", path, "Surefire shell differs from the owner-attested OS pin")
	}
	return nil
}

func requireDarwinDisposablePaths(plan SandboxPlan) error {
	for path, name := range map[string]string{plan.SourceDirectory: "source", plan.ToolDirectory: "tool", plan.WorkspaceDirectory: "workspace", plan.CacheDirectory: "cache", plan.OutputDirectory: "output"} {
		inPrivateTmp := strings.HasPrefix(path, "/private/tmp/")
		inDarwinUserTemp := strings.HasPrefix(path, "/private/var/folders/") && strings.Contains(path, "/T/")
		if !inPrivateTmp && !inDarwinUserTemp {
			return finding("NONDISPOSABLE_SANDBOX_PATH", "$."+name+"_directory", "Darwin executor paths must be beneath a system disposable temporary root")
		}
	}
	return nil
}

func prepareExecutionTrees(plan SandboxPlan, root *AcceptedRoot) error {
	for _, directory := range []string{plan.SourceDirectory, plan.ToolDirectory, plan.WorkspaceDirectory, plan.OutputDirectory} {
		if _, err := os.Lstat(directory); err == nil || !errors.Is(err, os.ErrNotExist) {
			return finding("NONDISPOSABLE_SANDBOX_PATH", directory, "fresh source, tool, workspace, and output directories must not already exist")
		}
	}
	for _, directory := range []string{plan.WorkspaceDirectory, plan.OutputDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return finding("EXECUTOR_PREPARATION_FAILED", directory, err.Error())
		}
	}
	for _, directory := range []string{filepath.Join(plan.WorkspaceDirectory, "home"), filepath.Join(plan.WorkspaceDirectory, "tmp")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return finding("EXECUTOR_PREPARATION_FAILED", directory, err.Error())
		}
	}
	if plan.Operation == SandboxMavenAcquire {
		if _, err := os.Lstat(plan.CacheDirectory); errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(plan.CacheDirectory, 0o700); err != nil {
				return finding("EXECUTOR_PREPARATION_FAILED", plan.CacheDirectory, err.Error())
			}
		} else if err != nil {
			return finding("EXECUTOR_PREPARATION_FAILED", plan.CacheDirectory, err.Error())
		} else if entries, err := os.ReadDir(plan.CacheDirectory); err != nil || len(entries) != 0 {
			return finding("CACHE_NOT_DISPOSABLE", plan.CacheDirectory, "acquisition cache must start empty")
		}
	}
	source, ok := root.Object("java-websocket-source-archive")
	if !ok {
		return finding("MISSING_EXECUTABLE_OBJECT", "$.accepted_root", "accepted Java source archive is absent")
	}
	if err := extractAcceptedArchive(source, plan.SourceDirectory, archivePolicy{stripTopDirectory: true, readOnly: true}); err != nil {
		return err
	}
	if err := copyAcceptedSourceTree(plan.SourceDirectory, filepath.Join(plan.WorkspaceDirectory, "build")); err != nil {
		return err
	}
	if err := os.MkdirAll(plan.ToolDirectory, 0o700); err != nil {
		return err
	}
	jdk, ok := root.Object("openjdk-17.0.19-homebrew-bottle")
	if !ok {
		return finding("MISSING_EXECUTABLE_OBJECT", "$.accepted_root", "accepted OpenJDK object is absent")
	}
	if err := extractAcceptedArchive(jdk, plan.ToolDirectory, archivePolicy{allowSymlinks: true}); err != nil {
		return err
	}
	maven, ok := root.Object("apache-maven-3.9.11")
	if !ok {
		return finding("MISSING_EXECUTABLE_OBJECT", "$.accepted_root", "accepted Maven object is absent")
	}
	if err := extractAcceptedArchive(maven, plan.ToolDirectory, archivePolicy{allowSymlinks: true}); err != nil {
		return err
	}
	return makeTreeReadOnly(plan.ToolDirectory)
}

func verifyPromotedToolchain(toolDirectory string) (string, string, string, error) {
	javaHome := filepath.Join(toolDirectory, "openjdk@17", "17.0.19", "libexec", "openjdk.jdk", "Contents", "Home")
	mavenHome := filepath.Join(toolDirectory, "apache-maven-3.9.11")
	checks := map[string]string{
		filepath.Join(javaHome, "bin", "java"):                           promotedJavaDigest,
		filepath.Join(javaHome, "bin", "javac"):                          promotedJavacDigest,
		filepath.Join(javaHome, "lib", "jspawnhelper"):                   promotedJSpawnDigest,
		filepath.Join(mavenHome, "lib", "maven-core-3.9.11.jar"):         promotedMavenCoreDigest,
		filepath.Join(mavenHome, "boot", "plexus-classworlds-2.9.0.jar"): promotedClassworlds,
	}
	for path, expected := range checks {
		data, err := readBoundedRegular(path, maxObjectBytes)
		if err != nil || intake.DigestBytes(data) != expected {
			return "", "", "", finding("PROMOTED_TOOLCHAIN_MISMATCH", path, "materialized tool binary differs from its promoted pin")
		}
	}
	return filepath.Join(javaHome, "bin", "java"), filepath.Join(javaHome, "lib", "jspawnhelper"), mavenHome, nil
}

func prepareSandboxNetwork(plan SandboxPlan) (string, string, func(), error) {
	profilePath := filepath.Join(plan.WorkspaceDirectory, "sandbox.sb")
	if plan.Operation != SandboxMavenAcquire {
		return profilePath, "", nil, nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", "", nil, finding("MAVEN_PROXY_LISTENER_DENIED", "$.network", err.Error())
	}
	auditPath := filepath.Join(plan.OutputDirectory, "maven-egress.jsonl")
	audit, err := os.OpenFile(auditPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = listener.Close()
		return "", "", nil, finding("MAVEN_EGRESS_AUDIT_FAILED", auditPath, err.Error())
	}
	ctx, cancel := context.WithCancel(context.Background())
	durable := &syncingWriter{file: audit}
	done := make(chan error, 1)
	go func() { done <- ServeMavenCentralProxy(ctx, listener, durable) }()
	stop := func() {
		cancel()
		_ = listener.Close()
		<-done
		_ = audit.Sync()
		_ = audit.Close()
	}
	return profilePath, listener.Addr().String(), stop, nil
}

type syncingWriter struct{ file *os.File }

func (w *syncingWriter) Write(data []byte) (int, error) {
	written, err := w.file.Write(data)
	if err != nil || written != len(data) {
		return written, errors.Join(err, io.ErrShortWrite)
	}
	if err := w.file.Sync(); err != nil {
		return written, err
	}
	return written, nil
}

func darwinSandboxProfile(plan SandboxPlan, self, javaPath, jspawnPath, endpoint string) (string, error) {
	quote := func(value string) string { return strings.ReplaceAll(value, `"`, `\"`) }
	var profile strings.Builder
	profile.WriteString("(version 1)\n(allow default)\n(deny network*)\n")
	if plan.Operation == SandboxMavenAcquire {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil || host != "127.0.0.1" {
			return "", finding("NETWORK_POLICY_VIOLATION", "$.network", "executor proxy is not explicit IPv4 loopback")
		}
		profile.WriteString("(allow network-outbound (remote tcp \"localhost:" + port + "\"))\n")
	} else if plan.Operation == SandboxMavenTest {
		// The upstream suite creates wildcard ServerSockets on ephemeral ports,
		// then connects only through IPv4 loopback. Outbound non-loopback and DNS
		// remain denied by the preceding deny rule.
		profile.WriteString("(allow network-bind (local ip))\n")
		profile.WriteString("(allow network-inbound (local ip))\n")
		profile.WriteString("(allow network-outbound (remote tcp \"localhost:*\"))\n")
	}
	profile.WriteString("(deny file-read* (subpath \"/Users\"))\n")
	readDirectories := []string{plan.SourceDirectory, plan.ToolDirectory, plan.WorkspaceDirectory, plan.CacheDirectory, plan.OutputDirectory}
	for _, temporaryRoot := range []string{"/private/tmp", "/private/var/folders"} {
		profile.WriteString("(deny file-read-data (require-all (subpath \"" + temporaryRoot + "\")")
		for _, allowed := range readDirectories {
			profile.WriteString(" (require-not (subpath \"" + quote(allowed) + "\"))")
		}
		profile.WriteString(" (require-not (literal \"" + quote(self) + "\"))))\n")
	}
	for _, allowed := range append(readDirectories, self) {
		profile.WriteString("(allow file-read* (subpath \"" + quote(allowed) + "\"))\n")
	}
	profile.WriteString("(deny file-write*)\n")
	writeRoots := []string{
		filepath.Join(plan.WorkspaceDirectory, "home"), filepath.Join(plan.WorkspaceDirectory, "tmp"),
		filepath.Join(plan.WorkspaceDirectory, "build"), plan.OutputDirectory,
	}
	if plan.Operation == SandboxMavenAcquire {
		writeRoots = append(writeRoots, plan.CacheDirectory)
	}
	for _, allowed := range writeRoots {
		profile.WriteString("(allow file-write* (subpath \"" + quote(allowed) + "\"))\n")
	}
	profile.WriteString("(deny process*)\n")
	if plan.Operation == SandboxMavenTest {
		profile.WriteString("(allow process-fork)\n")
	} else {
		profile.WriteString("(deny process-fork)\n")
	}
	profile.WriteString("(allow process-exec (literal \"" + quote(self) + "\"))\n")
	profile.WriteString("(allow process-exec (literal \"" + quote(javaPath) + "\"))\n")
	profile.WriteString("(allow process-exec (literal \"" + quote(jspawnPath) + "\"))\n")
	if plan.Operation == SandboxMavenTest {
		// Surefire's fixed Unix launcher is /bin/sh -c followed by the exact
		// promoted Java command. Other executables remain denied by process*.
		profile.WriteString("(allow process-exec (literal \"/bin/sh\"))\n")
		profile.WriteString("(allow process-exec (literal \"/bin/bash\"))\n")
	}
	return profile.String(), nil
}

func runMonitored(plan SandboxPlan, executable string, arguments, environment []string) (*executionMonitor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(plan.Resources.WallTimeSeconds)*time.Second)
	defer cancel()
	monitor := &executionMonitor{cancel: cancel, maxProcesses: 1, maxOpenFiles: 3}
	stdoutPath := filepath.Join(plan.OutputDirectory, "stdout.log")
	stderrPath := filepath.Join(plan.OutputDirectory, "stderr.log")
	var err error
	monitor.stdout, err = os.OpenFile(stdoutPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer monitor.stdout.Close()
	monitor.stderr, err = os.OpenFile(stderrPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer monitor.stderr.Close()
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = environment
	command.Dir = plan.SourceDirectory
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	writer := &boundedExecutionWriter{monitor: monitor, limit: plan.Resources.MaxOutputBytes}
	command.Stdout = &splitExecutionWriter{file: monitor.stdout, bounded: writer}
	command.Stderr = &splitExecutionWriter{file: monitor.stderr, bounded: writer}
	if err := command.Start(); err != nil {
		return nil, finding("EXECUTOR_START_FAILED", "$.operation", err.Error())
	}
	pid := command.Process.Pid
	killWatchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		case <-killWatchDone:
		}
	}()
	done := make(chan struct{})
	watchExited := make(chan struct{})
	go func() {
		defer close(watchExited)
		monitor.watch(ctx, plan, pid, done)
	}()
	waitErr := command.Wait()
	close(done)
	<-watchExited
	close(killWatchDone)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		monitor.setBreach("WALL_TIME_LIMIT_EXCEEDED", "process exceeded its wall-time limit")
	}
	monitor.mutex.Lock()
	breach := monitor.breach
	monitor.mutex.Unlock()
	if breach != nil {
		return nil, finding(breach.code, "$.resources", breach.detail)
	}
	if waitErr != nil {
		var exitError *exec.ExitError
		if !errors.As(waitErr, &exitError) || exitError.ExitCode() < 0 || exitError.ExitCode() > 255 {
			return nil, finding("SANDBOX_OPERATION_FAILED", "$.operation", waitErr.Error())
		}
		monitor.exitCode = exitError.ExitCode()
	}
	if err := monitor.stdout.Sync(); err != nil {
		return nil, err
	}
	if err := monitor.stderr.Sync(); err != nil {
		return nil, err
	}
	if command.ProcessState != nil {
		observedCPU := int(math.Ceil(command.ProcessState.UserTime().Seconds() + command.ProcessState.SystemTime().Seconds()))
		if observedCPU > monitor.cpuSeconds {
			monitor.cpuSeconds = observedCPU
		}
	}
	return monitor, nil
}

func (m *executionMonitor) watch(ctx context.Context, plan SandboxPlan, pid int, done <-chan struct{}) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			workspace := directoryBytes(plan.WorkspaceDirectory) + directoryBytes(plan.OutputDirectory)
			if plan.Operation == SandboxMavenAcquire {
				workspace += directoryBytes(plan.CacheDirectory)
			}
			pids := processTreePIDs(pid)
			processes := len(pids)
			var memory int64
			openFiles, cpuSeconds := 0, 0
			for _, observedPID := range pids {
				memory += residentBytes(observedPID)
				openFiles += openFileCount(observedPID)
				cpuSeconds += processCPUSeconds(observedPID)
			}
			m.mutex.Lock()
			if workspace > m.maxWorkspaceBytes {
				m.maxWorkspaceBytes = workspace
			}
			if memory > m.maxMemory {
				m.maxMemory = memory
			}
			if openFiles > m.maxOpenFiles {
				m.maxOpenFiles = openFiles
			}
			if cpuSeconds > m.cpuSeconds {
				m.cpuSeconds = cpuSeconds
			}
			if processes > m.maxProcesses {
				m.maxProcesses = processes
			}
			m.mutex.Unlock()
			if workspace > plan.Resources.MaxWorkspaceBytes {
				m.setBreach("WORKSPACE_LIMIT_EXCEEDED", "writable workspace exceeded its byte limit")
			}
			if memory > plan.Resources.MemoryBytes {
				m.setBreach("MEMORY_LIMIT_EXCEEDED", "resident memory exceeded its byte limit")
			}
			if processes > plan.Resources.MaxProcesses {
				m.setBreach("PROCESS_LIMIT_EXCEEDED", fmt.Sprintf("observed %d processes, exceeding limit %d", processes, plan.Resources.MaxProcesses))
			}
			if openFiles > plan.Resources.MaxOpenFiles {
				m.setBreach("OPEN_FILE_LIMIT_EXCEEDED", fmt.Sprintf("observed %d numeric file descriptors, exceeding limit %d", openFiles, plan.Resources.MaxOpenFiles))
			}
			if cpuSeconds > plan.Resources.CPUTimeSeconds {
				m.setBreach("CPU_TIME_LIMIT_EXCEEDED", "process reached its CPU-time limit")
			}
		}
	}
}

func processTreePIDs(root int) []int {
	output, err := exec.Command("/bin/ps", "-axo", "pid=,ppid=").Output()
	if err != nil {
		return []int{root}
	}
	children := make(map[int][]int)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		pid, pidErr := strconv.Atoi(fields[0])
		parent, parentErr := strconv.Atoi(fields[1])
		if pidErr == nil && parentErr == nil {
			children[parent] = append(children[parent], pid)
		}
	}
	pids := []int{root}
	for index := 0; index < len(pids); index++ {
		pids = append(pids, children[pids[index]]...)
	}
	return pids
}

func (m *executionMonitor) setBreach(code, detail string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.breach == nil {
		m.breach = &executionBreach{code: code, detail: detail}
		m.cancel()
	}
}

type boundedExecutionWriter struct {
	monitor *executionMonitor
	limit   int64
}

func (w *boundedExecutionWriter) reserve(length int) (int, error) {
	w.monitor.mutex.Lock()
	defer w.monitor.mutex.Unlock()
	remaining := w.limit - w.monitor.outputBytes
	if remaining <= 0 {
		w.monitor.setBreachLocked("OUTPUT_LIMIT_EXCEEDED", "combined stdout and stderr exceeded their byte limit")
		return 0, io.ErrShortWrite
	}
	allowed := int64(length)
	if allowed > remaining {
		allowed = remaining
	}
	w.monitor.outputBytes += allowed
	if allowed < int64(length) {
		w.monitor.setBreachLocked("OUTPUT_LIMIT_EXCEEDED", "combined stdout and stderr exceeded their byte limit")
		return int(allowed), io.ErrShortWrite
	}
	return length, nil
}

func (m *executionMonitor) setBreachLocked(code, detail string) {
	if m.breach == nil {
		m.breach = &executionBreach{code: code, detail: detail}
		m.cancel()
	}
}

type splitExecutionWriter struct {
	file    *os.File
	bounded *boundedExecutionWriter
}

func (w *splitExecutionWriter) Write(data []byte) (int, error) {
	allowed, err := w.bounded.reserve(len(data))
	if allowed > 0 {
		written, writeErr := w.file.Write(data[:allowed])
		if writeErr != nil || written != allowed {
			return written, errors.Join(writeErr, io.ErrShortWrite)
		}
	}
	return allowed, err
}

func directoryBytes(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if info, statErr := entry.Info(); statErr == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func residentBytes(pid int) int64 {
	output, err := exec.Command("/bin/ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0
	}
	kilobytes, _ := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	return kilobytes * 1024
}

func openFileCount(pid int) int {
	// Restrict lsof to numeric descriptors. Its default output also includes
	// cwd, text, and every memory-mapped file; counting those as open file
	// descriptors produces false limit breaches during Maven class loading.
	output, err := exec.Command("/usr/sbin/lsof", "-n", "-a", "-p", strconv.Itoa(pid), "-d", "0-4095", "-F", "f").Output()
	if err != nil {
		return 0
	}
	return parseOpenFileCount(output)
}

func parseOpenFileCount(output []byte) int {
	count := 0
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		field := scanner.Text()
		if len(field) <= 1 || field[0] != 'f' {
			continue
		}
		if _, err := strconv.Atoi(field[1:]); err == nil {
			count++
		}
	}
	return count
}

func processCPUSeconds(pid int) int {
	output, err := exec.Command("/bin/ps", "-o", "cputime=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0
	}
	value := strings.TrimSpace(string(output))
	dayParts := strings.Split(value, "-")
	days := 0
	if len(dayParts) == 2 {
		days, err = strconv.Atoi(dayParts[0])
		if err != nil {
			return 0
		}
		value = dayParts[1]
	} else if len(dayParts) != 1 {
		return 0
	}
	parts := strings.Split(value, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0
	}
	seconds, err := strconv.ParseFloat(parts[len(parts)-1], 64)
	if err != nil {
		return 0
	}
	minutes, err := strconv.Atoi(parts[len(parts)-2])
	if err != nil {
		return 0
	}
	hours := 0
	if len(parts) == 3 {
		hours, err = strconv.Atoi(parts[0])
		if err != nil {
			return 0
		}
	}
	return int(math.Ceil(float64(days*24*60*60+hours*60*60+minutes*60) + seconds))
}

func runDarwinPolicyCanaries(plan SandboxPlan, profilePath, self, javaPath, actualEndpoint string) (SandboxEnforcementCanaries, error) {
	// Resource monitors and rlimits have direct regression tests. These probes
	// exercise the generated policy against real sandbox-exec before evidence.
	forbidden := filepath.Join(filepath.Dir(plan.SourceDirectory), "forbidden-canary")
	if err := os.WriteFile(forbidden, []byte("canary"), 0o600); err != nil {
		return SandboxEnforcementCanaries{}, err
	}
	defer os.Remove(forbidden)
	denied := [][]string{
		{"read", "/Users"},
		{"write", filepath.Join(plan.SourceDirectory, ".write-canary")},
		{"write", forbidden + ".write"},
		{"fork", ""},
	}
	for _, probe := range denied {
		command := exec.Command("/usr/bin/sandbox-exec", "-f", profilePath, self, "__sandbox-canary", probe[0], probe[1])
		command.Env = []string{"HOME=" + filepath.Join(plan.WorkspaceDirectory, "home"), "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"}
		if err := command.Run(); err == nil {
			return SandboxEnforcementCanaries{}, finding("SANDBOX_CANARY_FAILED", "$.sandbox", "a deny-policy canary unexpectedly succeeded")
		}
	}
	if err := runNetworkPolicyCanary(plan, profilePath, self, actualEndpoint); err != nil {
		return SandboxEnforcementCanaries{}, err
	}
	if err := runJavaNetworkPolicyCanary(plan, profilePath, javaPath, actualEndpoint); err != nil {
		return SandboxEnforcementCanaries{}, err
	}
	resourceCanaries, err := runResourceCanaries(plan, self)
	if err != nil {
		return SandboxEnforcementCanaries{}, err
	}
	return SandboxEnforcementCanaries{
		SanitizedEnvironment: true, UserHomeDenied: true, SourceWriteDenied: true, DisjointWritesOnly: true,
		WallTimeEnforced: resourceCanaries.WallTimeEnforced, OutputLimitEnforced: resourceCanaries.OutputLimitEnforced, WorkspaceLimitEnforced: resourceCanaries.WorkspaceLimitEnforced,
		ProcessLimitEnforced: resourceCanaries.ProcessLimitEnforced, CPULimitEnforced: resourceCanaries.CPULimitEnforced, MemoryLimitEnforced: resourceCanaries.MemoryLimitEnforced,
		OpenFileLimitEnforced: resourceCanaries.OpenFileLimitEnforced, NetworkPolicyEnforced: true,
	}, nil
}

func runJavaNetworkPolicyCanary(plan SandboxPlan, profilePath, javaPath, actualEndpoint string) error {
	allowsLoopback := plan.Operation == SandboxMavenAcquire || plan.Operation == SandboxMavenTest
	endpoint := actualEndpoint
	var listener net.Listener
	if plan.Operation != SandboxMavenAcquire {
		var err error
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return finding("SANDBOX_CANARY_FAILED", "$.network", err.Error())
		}
		defer listener.Close()
		endpoint = listener.Addr().String()
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host != "127.0.0.1" {
		return finding("SANDBOX_CANARY_FAILED", "$.network", "Java canary endpoint is not exact IPv4 loopback")
	}
	sourcePath := filepath.Join(plan.WorkspaceDirectory, "JavaNetworkCanary.java")
	const source = `import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
public final class JavaNetworkCanary {
  public static void main(String[] args) throws Exception {
	if (args[0].equals("fork")) {
	  Process process = new ProcessBuilder(args[1], "-version").inheritIO().start();
	  if (process.waitFor() != 0) { throw new IllegalStateException("child failed"); }
	  return;
	}
	if (args[0].equals("shell-fork")) {
	  Process process = new ProcessBuilder("/bin/sh", "-c", "exec \"$0\" -Djava.net.preferIPv4Stack=true \"$1\" child-network 0 0", args[1], args[2]).inheritIO().start();
	  if (process.waitFor() != 0) { throw new IllegalStateException("shell child failed"); }
	  return;
	}
	if (args[0].equals("child-network")) {
	  try (ServerSocket listener = new ServerSocket(0);
	       Socket client = new Socket()) {
	    client.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), listener.getLocalPort()), 1000);
	    try (Socket accepted = listener.accept()) { }
	  }
	  try (Socket external = new Socket()) {
	    external.connect(new InetSocketAddress(InetAddress.getByName("192.0.2.1"), 9), 1000);
	    throw new IllegalStateException("external connect unexpectedly succeeded");
	  } catch (SocketException expected) {
	    if (!"Operation not permitted".equals(expected.getMessage())) { throw expected; }
	    return;
	  }
	}
	if (args[0].equals("deny")) {
	  try (Socket denied = new Socket()) {
	    denied.connect(new InetSocketAddress(InetAddress.getByName(args[1]), Integer.parseInt(args[2])), 1000);
	    throw new IllegalStateException("denied connect unexpectedly succeeded");
	  } catch (SocketException expected) {
	    if (!"Operation not permitted".equals(expected.getMessage())) { throw expected; }
	    return;
	  }
	}
    if (args[0].equals("roundtrip")) {
      try (ServerSocket listener = new ServerSocket(0);
           Socket client = new Socket()) {
        client.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), listener.getLocalPort()), 1000);
        try (Socket accepted = listener.accept()) { return; }
      }
    }
    try (Socket socket = new Socket()) {
      socket.connect(new InetSocketAddress(InetAddress.getByName(args[1]), Integer.parseInt(args[2])), 1000);
    }
  }
}
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		return finding("SANDBOX_CANARY_FAILED", "$.network", err.Error())
	}
	run := func(arguments ...string) error {
		return javaNetworkCanaryCommand(plan, profilePath, javaPath, sourcePath, arguments...).Run()
	}
	if err := run("connect", "127.0.0.1", port); allowsLoopback && err != nil {
		return finding("SANDBOX_CANARY_FAILED", "$.network", "the Java runtime was denied the allowed loopback endpoint")
	} else if !allowsLoopback && err == nil {
		return finding("SANDBOX_CANARY_FAILED", "$.network", "offline Java network canary unexpectedly connected")
	}
	if plan.Operation == SandboxMavenTest {
		if err := run("roundtrip", "0", "0"); err != nil {
			return finding("SANDBOX_CANARY_FAILED", "$.network", "the Java runtime was denied the wildcard-listener loopback round trip required by the upstream tests")
		}
		if err := run("fork", javaPath, "0"); err != nil {
			return finding("SANDBOX_CANARY_FAILED", "$.resources.max_processes", "the sandbox denied the exact promoted Java child required by upstream Surefire")
		}
		if err := run("shell-fork", javaPath, sourcePath); err != nil {
			return finding("SANDBOX_CANARY_FAILED", "$.resources.max_processes", "the sandbox denied Surefire's fixed shell-to-promoted-Java launch chain")
		}
	}
	if err := run("deny", "192.0.2.1", "9"); err != nil {
		return finding("SANDBOX_CANARY_FAILED", "$.network", "Java non-loopback canary did not fail with exact sandbox permission denial")
	}
	return nil
}

func javaNetworkCanaryCommand(plan SandboxPlan, profilePath, javaPath, sourcePath string, arguments ...string) *exec.Cmd {
	commandArguments := []string{
		"-f", profilePath, javaPath, "-Djava.net.preferIPv4Stack=true",
		"-Duser.home=" + filepath.Join(plan.WorkspaceDirectory, "home"),
		"-Djava.io.tmpdir=" + filepath.Join(plan.WorkspaceDirectory, "tmp"), sourcePath,
	}
	commandArguments = append(commandArguments, arguments...)
	command := exec.Command("/usr/bin/sandbox-exec", commandArguments...)
	command.Dir = plan.WorkspaceDirectory
	command.Env = []string{"HOME=" + filepath.Join(plan.WorkspaceDirectory, "home"), "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"}
	return command
}

func runNetworkPolicyCanary(plan SandboxPlan, profilePath, self, actualEndpoint string) error {
	allowsLoopback := plan.Operation == SandboxMavenAcquire || plan.Operation == SandboxMavenTest
	endpoint := actualEndpoint
	var listener net.Listener
	if plan.Operation != SandboxMavenAcquire {
		var err error
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return finding("SANDBOX_CANARY_FAILED", "$.network", err.Error())
		}
		defer listener.Close()
		endpoint = listener.Addr().String()
	}
	run := func(probe, argument string) error {
		command := exec.Command("/usr/bin/sandbox-exec", "-f", profilePath, self, "__sandbox-canary", probe, argument)
		command.Env = []string{"HOME=" + filepath.Join(plan.WorkspaceDirectory, "home"), "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"}
		return command.Run()
	}
	if err := run("network", endpoint); allowsLoopback && err != nil {
		return finding("SANDBOX_CANARY_FAILED", "$.network", "the allowed loopback endpoint was denied")
	} else if !allowsLoopback && err == nil {
		return finding("SANDBOX_CANARY_FAILED", "$.network", "offline network canary unexpectedly connected")
	}
	if plan.Operation == SandboxMavenTest {
		if err := run("network-roundtrip", "127.0.0.1:0"); err != nil {
			return finding("SANDBOX_CANARY_FAILED", "$.network", "wildcard-listener loopback round trip required by the upstream tests was denied")
		}
	}
	if err := run("network-denied", "192.0.2.1:9"); err != nil {
		return finding("SANDBOX_CANARY_FAILED", "$.network", "non-loopback canary did not fail with exact sandbox permission denial")
	}
	return nil
}

func runResourceCanaries(plan SandboxPlan, self string) (SandboxEnforcementCanaries, error) {
	type canaryCase struct {
		name     string
		argument string
		limits   ResourceLimits
		wantCode string
	}
	base := plan.Resources
	cases := []canaryCase{
		{name: "sleep", argument: "2", limits: withCanaryLimits(base, 1, 1<<20, 1<<20, 64<<20), wantCode: "WALL_TIME_LIMIT_EXCEEDED"},
		{name: "output", argument: "65536", limits: withCanaryLimits(base, 5, 4096, 1<<20, 64<<20), wantCode: "OUTPUT_LIMIT_EXCEEDED"},
		{name: "workspace", argument: "65536", limits: withCanaryLimits(base, 5, 1<<20, 4096, 64<<20), wantCode: "WORKSPACE_LIMIT_EXCEEDED"},
		{name: "memory", argument: strconv.FormatInt(128<<20, 10), limits: withCanaryLimits(base, 5, 1<<20, 1<<20, 32<<20), wantCode: "MEMORY_LIMIT_EXCEEDED"},
		{name: "cpu", argument: "2", limits: withCPUCanaryLimits(base), wantCode: "CPU_TIME_LIMIT_EXCEEDED"},
		{name: "open", argument: "16", limits: withCanaryLimits(base, 5, 1<<20, 1<<20, 64<<20)},
		{name: "processes", argument: "4", limits: withProcessCanaryLimits(base), wantCode: "PROCESS_LIMIT_EXCEEDED"},
	}
	passed := make(map[string]bool, len(cases))
	for index, probe := range cases {
		probePlan := plan
		probePlan.Resources = probe.limits
		probePlan.WorkspaceDirectory = filepath.Join(plan.WorkspaceDirectory, fmt.Sprintf("resource-canary-%d-work", index))
		probePlan.OutputDirectory = filepath.Join(plan.WorkspaceDirectory, fmt.Sprintf("resource-canary-%d-output", index))
		if err := os.MkdirAll(probePlan.WorkspaceDirectory, 0o700); err != nil {
			return SandboxEnforcementCanaries{}, err
		}
		if err := os.MkdirAll(probePlan.OutputDirectory, 0o700); err != nil {
			return SandboxEnforcementCanaries{}, err
		}
		_, err := runMonitored(probePlan, self, []string{"__sandbox-canary", probe.name, probe.argument}, []string{"HOME=" + probePlan.WorkspaceDirectory, "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"})
		_ = os.RemoveAll(probePlan.WorkspaceDirectory)
		_ = os.RemoveAll(probePlan.OutputDirectory)
		if probe.wantCode == "" {
			if err != nil {
				return SandboxEnforcementCanaries{}, finding("SANDBOX_CANARY_FAILED", "$.resources."+probe.name, err.Error())
			}
			passed[probe.name] = true
			continue
		}
		var observed *intake.Finding
		if !errors.As(err, &observed) || observed.Code != probe.wantCode {
			observedCode := "none"
			if observed != nil {
				observedCode = observed.Code
			}
			return SandboxEnforcementCanaries{}, finding("SANDBOX_CANARY_FAILED", "$.resources."+probe.name, "resource canary did not trigger its exact enforcement path; observed "+observedCode)
		}
		passed[probe.name] = true
	}
	return SandboxEnforcementCanaries{
		WallTimeEnforced: passed["sleep"], OutputLimitEnforced: passed["output"], WorkspaceLimitEnforced: passed["workspace"],
		ProcessLimitEnforced: passed["processes"], CPULimitEnforced: passed["cpu"], MemoryLimitEnforced: passed["memory"], OpenFileLimitEnforced: passed["open"],
	}, nil
}

func withCanaryLimits(base ResourceLimits, wall int, output, workspace, memory int64) ResourceLimits {
	base.WallTimeSeconds = wall
	base.CPUTimeSeconds = wall
	base.MaxOutputBytes = output
	base.MaxWorkspaceBytes = workspace
	base.MemoryBytes = memory
	base.MaxOpenFiles = 64
	return base
}

func withCPUCanaryLimits(base ResourceLimits) ResourceLimits {
	base = withCanaryLimits(base, 4, 1<<20, 1<<20, 64<<20)
	base.CPUTimeSeconds = 1
	return base
}

func withProcessCanaryLimits(base ResourceLimits) ResourceLimits {
	// Isolate the process-count control from runtime overhead (notably the Go
	// race runtime used by the regression suite). The canary must fail because
	// it crosses MaxProcesses, never because its fixed helper processes happen
	// to cross an unrelated memory ceiling first.
	memory := base.MemoryBytes
	if memory < 512<<20 {
		memory = 512 << 20
	}
	base = withCanaryLimits(base, 5, 1<<20, 1<<20, memory)
	base.MaxProcesses = 2
	return base
}

func verifiedMavenAudit(path string) (bool, error) {
	data, err := readBoundedRegular(path, maxManifestBytes)
	if err != nil {
		return false, err
	}
	connected := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), `"authority":"repo.maven.apache.org:443"`) && strings.Contains(scanner.Text(), `"result":"connected"`) {
			connected = true
		}
	}
	return connected, scanner.Err()
}

func RunSandboxChild(arguments []string) (bool, int) {
	if len(arguments) == 0 {
		return false, 0
	}
	if arguments[0] == "__sandbox-canary" {
		return true, runSandboxCanary(arguments[1:])
	}
	if arguments[0] != "__sandbox-child" {
		return false, 0
	}
	if len(arguments) != 13 {
		return true, 64
	}
	operation := SandboxOperation(arguments[1])
	if operation != SandboxMavenAcquire && operation != SandboxMavenBuild && operation != SandboxMavenTest {
		return true, 64
	}
	javaPath, mavenHome := arguments[2], arguments[3]
	if data, err := readBoundedRegular(javaPath, maxObjectBytes); err != nil || intake.DigestBytes(data) != promotedJavaDigest {
		return true, 65
	}
	cpu, err1 := strconv.Atoi(arguments[8])
	openFiles, err2 := strconv.Atoi(arguments[9])
	fileBytes, err3 := strconv.ParseInt(arguments[10], 10, 64)
	memoryBytes, err4 := strconv.ParseInt(arguments[11], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || cpu <= 0 || openFiles <= 0 || fileBytes <= 0 || memoryBytes < 64<<20 || memoryBytes > 16<<30 {
		return true, 64
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: uint64(cpu), Max: uint64(cpu)})
	_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: uint64(openFiles), Max: uint64(openFiles)})
	_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: uint64(fileBytes), Max: uint64(fileBytes)})
	cache, output, workspace, endpoint := arguments[5], arguments[6], arguments[7], arguments[12]
	buildSource := filepath.Join(workspace, "build")
	mebibytes := memoryBytes >> 20
	heapMiB := mebibytes / 2
	directMiB := maxInt64(16, mebibytes/16)
	metaspaceMiB := maxInt64(32, mebibytes/8)
	codeMiB := maxInt64(16, mebibytes/16)
	javaArguments := []string{
		"java", fmt.Sprintf("-Xmx%dm", heapMiB), fmt.Sprintf("-XX:MaxDirectMemorySize=%dm", directMiB), fmt.Sprintf("-XX:MaxMetaspaceSize=%dm", metaspaceMiB), fmt.Sprintf("-XX:ReservedCodeCacheSize=%dm", codeMiB), "-Xss1m",
		"-Djava.net.preferIPv4Stack=true",
		"-Duser.home=" + filepath.Join(workspace, "home"), "-Djava.io.tmpdir=" + filepath.Join(workspace, "tmp"),
		"-Dmaven.multiModuleProjectDirectory=" + buildSource, "-Dmaven.repo.local=" + filepath.Join(cache, "repository"),
		"-Dclassworlds.conf=" + filepath.Join(mavenHome, "bin", "m2.conf"), "-Dmaven.home=" + mavenHome,
		"-Dlibrary.jansi.path=" + filepath.Join(mavenHome, "lib", "jansi-native"),
	}
	if operation == SandboxMavenAcquire {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil || host != "127.0.0.1" {
			return true, 64
		}
		javaArguments = append(javaArguments, "-Dhttps.proxyHost=127.0.0.1", "-Dhttps.proxyPort="+port, "-Dhttp.proxyHost=127.0.0.1", "-Dhttp.proxyPort="+port)
	}
	javaArguments = append(javaArguments, "-classpath", filepath.Join(mavenHome, "boot", "plexus-classworlds-2.9.0.jar"), "org.codehaus.plexus.classworlds.launcher.Launcher")
	mavenArguments := []string{"--batch-mode", "--errors", "--no-transfer-progress", "--file", filepath.Join(buildSource, "pom.xml"), "-Dmaven.repo.local=" + filepath.Join(cache, "repository")}
	switch operation {
	case SandboxMavenAcquire:
		settings := filepath.Join(output, "central-settings.xml")
		settingsBytes, err := mavenCentralSettings(endpoint)
		if err != nil {
			return true, 64
		}
		if err := os.WriteFile(settings, settingsBytes, 0o600); err != nil {
			return true, 74
		}
		mavenArguments = append(mavenArguments, "--settings", settings, "dependency:go-offline",
			"-Dtest=org.java_websocket.util.CharsetfunctionsTest", "-DforkCount=0", "test")
	case SandboxMavenBuild:
		settings := filepath.Join(output, "offline-settings.xml")
		if err := os.WriteFile(settings, mavenOfflineSettings(), 0o600); err != nil {
			return true, 74
		}
		mavenArguments = append(mavenArguments, "--settings", settings, "--offline", "-DskipTests", "package")
	case SandboxMavenTest:
		settings := filepath.Join(output, "offline-settings.xml")
		if err := os.WriteFile(settings, mavenOfflineSettings(), 0o600); err != nil {
			return true, 74
		}
		mavenArguments = append(mavenArguments, "--settings", settings, "--offline")
		mavenArguments = append(mavenArguments, canonicalMavenTestProperties(output)...)
	}
	javaArguments = append(javaArguments, mavenArguments...)
	if err := syscall.Exec(javaPath, javaArguments, os.Environ()); err != nil {
		return true, 70
	}
	return true, 0
}

func runSandboxCanary(arguments []string) int {
	if len(arguments) != 2 {
		return 64
	}
	switch arguments[0] {
	case "read":
		file, err := os.Open(arguments[1])
		if err == nil {
			_ = file.Close()
			return 0
		}
		return 73
	case "write":
		if err := os.WriteFile(arguments[1], []byte("denied"), 0o600); err == nil {
			return 0
		}
		return 73
	case "fork":
		if err := exec.Command("/usr/bin/true").Run(); err == nil {
			return 0
		}
		return 73
	case "network":
		connection, err := net.DialTimeout("tcp4", arguments[1], time.Second)
		if err != nil {
			return 73
		}
		_ = connection.Close()
		return 0
	case "network-denied":
		connection, err := net.DialTimeout("tcp4", arguments[1], time.Second)
		if err == nil {
			_ = connection.Close()
			return 75
		}
		if errors.Is(err, syscall.EPERM) {
			return 0
		}
		return 75
	case "network-roundtrip":
		listener, err := net.Listen("tcp4", ":0")
		if err != nil {
			return 73
		}
		defer listener.Close()
		port := listener.Addr().(*net.TCPAddr).Port
		connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		if err != nil {
			return 73
		}
		defer connection.Close()
		accepted, err := listener.Accept()
		if err != nil {
			return 73
		}
		_ = accepted.Close()
		return 0
	case "sleep":
		seconds, err := strconv.Atoi(arguments[1])
		if err != nil || seconds <= 0 || seconds > 10 {
			return 64
		}
		time.Sleep(time.Duration(seconds) * time.Second)
		return 0
	case "output":
		count, err := strconv.Atoi(arguments[1])
		if err != nil || count <= 0 || count > 1<<20 {
			return 64
		}
		_, err = os.Stdout.Write(bytes.Repeat([]byte("x"), count))
		if err != nil {
			return 74
		}
		return 0
	case "workspace":
		count, err := strconv.Atoi(arguments[1])
		if err != nil || count <= 0 || count > 1<<20 {
			return 64
		}
		if err := os.WriteFile(filepath.Join(os.Getenv("HOME"), "workspace-canary"), bytes.Repeat([]byte("w"), count), 0o600); err != nil {
			return 74
		}
		time.Sleep(time.Second)
		return 0
	case "memory":
		count, err := strconv.Atoi(arguments[1])
		if err != nil || count <= 0 || count > 256<<20 {
			return 64
		}
		memory := make([]byte, count)
		for index := 0; index < len(memory); index += 4096 {
			memory[index] = 1
		}
		time.Sleep(2 * time.Second)
		runtime.KeepAlive(memory)
		return 0
	case "cpu":
		limit, err := strconv.Atoi(arguments[1])
		if err != nil || limit <= 0 || limit > 2 {
			return 64
		}
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: uint64(limit), Max: uint64(limit)}); err != nil {
			return 74
		}
		for {
		}
	case "open":
		limit, err := strconv.Atoi(arguments[1])
		if err != nil || limit < 8 || limit > 64 {
			return 64
		}
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: uint64(limit), Max: uint64(limit)}); err != nil {
			return 74
		}
		files := make([]*os.File, 0, limit+16)
		defer func() {
			for _, file := range files {
				_ = file.Close()
			}
		}()
		for index := 0; index < limit+16; index++ {
			file, err := os.Open("/dev/null")
			if err != nil {
				return 0
			}
			files = append(files, file)
		}
		return 75
	case "processes":
		count, err := strconv.Atoi(arguments[1])
		if err != nil || count < 2 || count > 16 {
			return 64
		}
		self, err := os.Executable()
		if err != nil {
			return 74
		}
		children := make([]*exec.Cmd, 0, count)
		for index := 0; index < count; index++ {
			child := exec.Command(self, "__sandbox-canary", "sleep", "2")
			if err := child.Start(); err != nil {
				return 74
			}
			children = append(children, child)
		}
		for _, child := range children {
			_ = child.Wait()
		}
		return 0
	default:
		return 64
	}
}

func mavenCentralSettings(endpoint string) ([]byte, error) {
	host, port, err := net.SplitHostPort(endpoint)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || host != "127.0.0.1" || portNumber <= 0 || portNumber > 65535 {
		return nil, finding("NETWORK_POLICY_VIOLATION", "$.network", "Maven settings require the exact executor loopback proxy")
	}
	return mavenRepositorySettings(`<proxies><proxy><id>exact-loopback-transport</id><active>true</active><protocol>http</protocol><host>127.0.0.1</host><port>` + port + `</port></proxy></proxies>`), nil
}

func mavenOfflineSettings() []byte {
	return mavenRepositorySettings("")
}

func mavenRepositorySettings(proxy string) []byte {
	value := `<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <interactiveMode>false</interactiveMode>
  ` + proxy + `
  <mirrors><mirror><id>central-only</id><mirrorOf>*</mirrorOf><url>https://repo.maven.apache.org/maven2</url></mirror></mirrors>
  <profiles><profile><id>central-only</id><repositories><repository><id>central</id><url>https://repo.maven.apache.org/maven2</url><releases><enabled>true</enabled><checksumPolicy>fail</checksumPolicy></releases><snapshots><enabled>false</enabled></snapshots></repository></repositories><pluginRepositories><pluginRepository><id>central-plugins</id><url>https://repo.maven.apache.org/maven2</url><releases><enabled>true</enabled><checksumPolicy>fail</checksumPolicy></releases><snapshots><enabled>false</enabled></snapshots></pluginRepository></pluginRepositories></profile></profiles>
  <activeProfiles><activeProfile>central-only</activeProfile></activeProfiles>
</settings>
`
	return []byte(value)
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
