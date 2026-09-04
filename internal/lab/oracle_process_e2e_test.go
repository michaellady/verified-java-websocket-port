//go:build oraclee2e

package lab

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

// TestJavaOracleProcessDeterministicReplay crosses the actual Go -> JSONL ->
// Java-WebSocket -> JSONL -> Go boundary twice. The explicit environment is
// mandatory so this gate can only consume promoted and audited artifacts.
func TestJavaOracleProcessDeterministicReplay(t *testing.T) {
	java := requiredE2EPath(t, "JAVA_ORACLE_E2E_JAVA")
	javac := requiredE2EPath(t, "JAVA_ORACLE_E2E_JAVAC")
	jarTool := requiredE2EPath(t, "JAVA_ORACLE_E2E_JAR_TOOL")
	runtimeJAR := requiredE2EPath(t, "JAVA_ORACLE_E2E_RUNTIME_JAR")
	slf4jAPI := requiredE2EPath(t, "JAVA_ORACLE_E2E_SLF4J_API")
	slf4jProvider := requiredE2EPath(t, "JAVA_ORACLE_E2E_SLF4J_PROVIDER")

	root, err := filepath.Abs(filepath.Join(filepath.Dir(currentTestFile()), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	sources, err := filepath.Glob(filepath.Join(root, "java-oracle", "src", "main", "java", "*.java"))
	if err != nil || len(sources) == 0 {
		t.Fatalf("Java sources: %v", err)
	}
	sort.Strings(sources)
	classes := filepath.Join(t.TempDir(), "classes")
	if err := os.Mkdir(classes, 0700); err != nil {
		t.Fatal(err)
	}
	// The accepted content-addressed object intentionally has no filename
	// extension. javac's -Xlint:path warns on that spelling, so compile through
	// a story-local .jar symlink while execution still loads the accepted path.
	compileRuntime := filepath.Join(t.TempDir(), "java-websocket-runtime.jar")
	if err := os.Symlink(runtimeJAR, compileRuntime); err != nil {
		t.Fatal(err)
	}
	compile := []string{"--release", "17", "-encoding", "UTF-8", "-Xlint:all", "-Werror", "-cp", compileRuntime, "-d", classes}
	compile = append(compile, sources...)
	runE2EBuild(t, root, javac, compile...)
	adapter := filepath.Join(t.TempDir(), "java-oracle.jar")
	runE2EBuild(t, root, jarTool, "--create", "--file", adapter, "--main-class", "OracleMain", "-C", classes, ".")

	config := JavaOracleProcessConfig{
		JavaExecutable: java,
		Adapter:        e2eArtifact(t, adapter),
		Runtime:        e2eArtifact(t, runtimeJAR),
		RuntimeSupport: []JavaOracleArtifact{e2eArtifact(t, slf4jAPI), e2eArtifact(t, slf4jProvider)},
	}
	if config.Runtime.Digest != JavaWebSocketRuntimeDigest {
		t.Fatalf("runtime artifact is not the accepted US-001 object: %s", config.Runtime.Digest)
	}
	request := OracleRequest{
		SchemaVersion: JavaOracleVersion,
		ScenarioID:    "go-java-replay-0001",
		Role:          OracleClient,
		InitialState:  "open",
		ByteChunks:    []string{base64.StdEncoding.EncodeToString([]byte{0x81, 0x02, 'h', 'i'})},
		LocalActions:  []LocalAction{{Kind: ActionPing, PayloadBase64: base64.StdEncoding.EncodeToString([]byte("p"))}},
		Limits:        OracleLimits{MaxFrameBytes: 1024, MaxMessageBytes: 2048, MaxBufferedBytes: 4096, MaxEvents: 32},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	first, err := RunJavaOracle(ctx, config, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RunJavaOracle(ctx, config, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := CompareJavaObservations(first, second); err != nil {
		t.Fatal(err)
	}
	planted := second
	planted.ResponseDigest = intake.DigestBytes([]byte("planted Java response drift"))
	assertFinding(t, CompareJavaObservations(first, planted), "NONDETERMINISTIC_JAVA_OBSERVATION")
}

func requiredE2EPath(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		t.Fatalf("%s must name a clean absolute promoted artifact path", name)
	}
	return value
}

func currentTestFile() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("cannot resolve E2E source path")
	}
	return file
}

func runE2EBuild(t *testing.T, directory, executable string, arguments ...string) {
	t.Helper()
	command := exec.Command(executable, arguments...)
	command.Dir = directory
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build command failed: %v: %s", err, boundedDiagnostic(string(output)))
	}
}

func e2eArtifact(t *testing.T, path string) JavaOracleArtifact {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return JavaOracleArtifact{Path: path, Digest: intake.DigestBytes(data)}
}
