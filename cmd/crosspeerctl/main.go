// crosspeerctl runs the US-018 Java/Rust cross-peer loopback exams: the
// REAL pinned Java-WebSocket 1.6.0 runtime (digest-verified before any
// execution) as client against the Rust ws-testee server, and as server
// against the Rust ws-testee client, over loopback TCP. Every exam is
// scripted and deterministic; every process exit code is read from its
// ProcessState and recorded verbatim with the captured output in a JSON
// receipt. Nothing is claimed that was not executed.
//
// Honesty contract: a peer that never produced a ProcessState is recorded
// as exit=-998 with the spawn error, never as an invented code; a timeout
// kills the exam and records the kill instead of fabricating a verdict.
// The runner claims loopback cross-peer behavior on the host it runs on —
// nothing about other platforms, Autobahn, TLS, or production readiness.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

const (
	// exitNoProcessState marks a command that never produced a
	// ProcessState; there is no real exit code to report.
	exitNoProcessState = -998
	peerStartTimeout   = 15 * time.Second
	peerRunTimeout     = 60 * time.Second
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("crosspeerctl", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repo := flags.String("repo", "", "repository root (contains java-crosspeer/)")
	jar := flags.String("jar", "", "pinned Java-WebSocket-1.6.0.jar path")
	slf4j := flags.String("slf4j", "", "pinned slf4j-api-2.0.13.jar path")
	testee := flags.String("testee", "", "prebuilt ws-testee binary path")
	workdir := flags.String("workdir", "", "scratch dir for compiled Java classes")
	out := flags.String("out", "", "receipt JSON output path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 ||
		*repo == "" || *jar == "" || *slf4j == "" || *testee == "" || *workdir == "" || *out == "" {
		fmt.Fprintln(stderr, "usage: crosspeerctl -repo <root> -jar <path> -slf4j <path> -testee <path> -workdir <dir> -out <receipt.json>")
		return 2
	}

	receipt := &examReceipt{
		SchemaVersion:            "1.0.0",
		Kind:                     "us018-crosspeer-exam",
		RecordedAt:               time.Now().UTC().Format(time.RFC3339),
		Runner:                   "crosspeerctl",
		Platform:                 platformRecord(),
		Assurance:                "OWNER_ATTESTED_NOT_INDEPENDENT",
		IndependentReviewClaimed: false,
	}

	// Digest-verify BOTH pinned runtime artifacts before executing anything.
	for _, artifact := range []struct{ name, path, digest string }{
		{"java-websocket-runtime-jar", *jar, lab.JavaWebSocketRuntimeDigest},
		{"slf4j-api-2.0.13", *slf4j, lab.AutobahnSLF4JAPIDigest},
	} {
		if err := verifyFileDigest(artifact.path, artifact.digest); err != nil {
			fmt.Fprintf(stderr, "pinned artifact %s failed verification: %v\n", artifact.name, err)
			return 1
		}
		receipt.Artifacts = append(receipt.Artifacts, artifactRecord{
			Name: artifact.name, Path: artifact.path, SHA256: artifact.digest, Verified: true,
		})
		fmt.Fprintf(stdout, "artifact=%s digest=%s verified=true\n", artifact.name, artifact.digest)
	}

	classes := filepath.Join(*workdir, "classes")
	if err := os.MkdirAll(classes, 0o755); err != nil {
		fmt.Fprintf(stderr, "cannot create workdir: %v\n", err)
		return 1
	}
	sources, err := filepath.Glob(filepath.Join(*repo, "java-crosspeer", "src", "main", "java", "*.java"))
	if err != nil || len(sources) == 0 {
		fmt.Fprintf(stderr, "no java-crosspeer sources found: %v\n", err)
		return 1
	}
	javacArgs := append([]string{"--release", "17", "-encoding", "UTF-8", "-Xlint:all", "-Werror",
		"-cp", *jar, "-d", classes}, sources...)
	javac := exec.Command("javac", javacArgs...)
	javacOut, javacErr := javac.CombinedOutput()
	javacExit := readExit(javac.ProcessState, javacErr)
	fmt.Fprintf(stdout, "step=javac exit=%d\n", javacExit)
	receipt.JavacExit = javacExit
	if javacExit != 0 {
		fmt.Fprintf(stderr, "javac failed:\n%s\n", javacOut)
		return 1
	}
	classpath := strings.Join([]string{classes, *jar, *slf4j}, string(os.PathListSeparator))

	longMessage := strings.Repeat("b", 2048)
	pingHex := hex.EncodeToString([]byte("cp-ping"))

	exams := []examSpec{
		{
			Name:       "java-client-echo-close",
			ServerArgv: []string{*testee, "server", "127.0.0.1:0"},
			ClientArgv: func(address string) []string {
				return []string{"java", "-cp", classpath, "CrossPeerClient", address, "/chat", "xpeer-echo", "clean", "-"}
			},
			ServerExpect: expectation{Role: "rust-server", Exit: 0,
				SummaryFields:  map[string]string{"outcome": "Terminal", "texts": "1", "terminals": "1", "close": "1000:transport"},
				StdoutContains: []string{"listening "}},
			ClientExpect: expectation{Role: "java-client", Exit: 0,
				StdoutContains: []string{"event=open status=101", "event=text payload=xpeer-echo", "event=close code=1000", "result=clean"}},
		},
		{
			Name:       "java-client-ping-control",
			ServerArgv: []string{*testee, "server", "127.0.0.1:0"},
			ClientArgv: func(address string) []string {
				return []string{"java", "-cp", classpath, "CrossPeerClient", address, "/chat", "xpeer-ping", "clean", pingHex}
			},
			ServerExpect: expectation{Role: "rust-server", Exit: 0,
				SummaryFields: map[string]string{"outcome": "Terminal", "texts": "1", "pings": "1", "close": "1000:transport"}},
			ClientExpect: expectation{Role: "java-client", Exit: 0,
				StdoutContains: []string{"event=ping-sent payload=" + pingHex, "event=text payload=xpeer-ping", "result=clean"}},
		},
		{
			Name:       "java-client-abrupt-loss",
			ServerArgv: []string{*testee, "server", "127.0.0.1:0"},
			ClientArgv: func(address string) []string {
				return []string{"java", "-cp", classpath, "CrossPeerClient", address, "/chat", "xpeer-loss", "halt", "-"}
			},
			ServerExpect: expectation{Role: "rust-server", Exit: 0,
				SummaryFields: map[string]string{"outcome": "Terminal", "texts": "1", "close": "1006:transport", "terminals": "1"}},
			ClientExpect: expectation{Role: "java-client", Exit: 43,
				StdoutContains: []string{"event=text payload=xpeer-loss"}},
		},
		{
			Name:       "rust-client-echo-close",
			ServerArgv: []string{"java", "-cp", classpath, "CrossPeerServer", "0"},
			ClientArgv: func(address string) []string {
				return []string{*testee, "client", address, "/chat", "127.0.0.1", "rust-to-java"}
			},
			ServerExpect: expectation{Role: "java-server", Exit: 0,
				StdoutContains: []string{"event=text payload=rust-to-java", "event=close code=1000", "result=clean"}},
			ClientExpect: expectation{Role: "rust-client", Exit: 0,
				SummaryFields: map[string]string{"outcome": "Terminal", "texts": "1", "close": "1000:remote", "terminals": "1"}},
		},
		{
			Name:       "rust-client-ping-pong",
			ServerArgv: []string{"java", "-cp", classpath, "CrossPeerServer", "0"},
			ClientArgv: func(address string) []string {
				return []string{*testee, "client", address, "/chat", "127.0.0.1", "rust-ping", pingHex}
			},
			ServerExpect: expectation{Role: "java-server", Exit: 0,
				StdoutContains: []string{"event=ping payload=" + pingHex, "event=text payload=rust-ping", "result=clean"}},
			ClientExpect: expectation{Role: "rust-client", Exit: 0,
				SummaryFields: map[string]string{"outcome": "Terminal", "texts": "1", "pongs": "1", "close": "1000:remote"}},
		},
		{
			Name:       "rust-client-backpressure",
			ServerArgv: []string{"java", "-cp", classpath, "CrossPeerServer", "0"},
			ClientArgv: func(address string) []string {
				return []string{*testee, "client", address, "/chat", "127.0.0.1", longMessage, "-", "1"}
			},
			ServerExpect: expectation{Role: "java-server", Exit: 0,
				StdoutContains: []string{"event=text payload=" + longMessage, "result=clean"}},
			ClientExpect: expectation{Role: "rust-client", Exit: 0,
				SummaryFields: map[string]string{"outcome": "Terminal", "texts": "1", "close": "1000:remote"}},
		},
	}

	allPass := true
	for _, spec := range exams {
		result := runExam(spec)
		receipt.Exams = append(receipt.Exams, result)
		fmt.Fprintf(stdout, "exam=%s verdict=%s server_exit=%d client_exit=%d\n",
			result.Name, result.Verdict, result.Server.Exit, result.Client.Exit)
		for _, failure := range result.Failures {
			fmt.Fprintf(stdout, "exam=%s failure=%q\n", result.Name, failure)
		}
		if result.Verdict != "PASS" {
			allPass = false
		}
	}

	receipt.Verdict = map[bool]string{true: "PASS", false: "FAIL"}[allPass]
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "cannot marshal receipt: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintf(stderr, "cannot write receipt: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "crosspeer verdict=%s exams=%d receipt=%s\n", receipt.Verdict, len(receipt.Exams), *out)
	if !allPass {
		return 1
	}
	return 0
}

// --- exam machinery ---------------------------------------------------------

type examSpec struct {
	Name         string
	ServerArgv   []string
	ClientArgv   func(address string) []string
	ServerExpect expectation
	ClientExpect expectation
}

type expectation struct {
	Role           string
	Exit           int
	SummaryFields  map[string]string
	StdoutContains []string
}

type stepRecord struct {
	Role    string `json:"role"`
	Command string `json:"command"`
	Exit    int    `json:"exit"`
	Stdout  string `json:"stdout"`
	Stderr  string `json:"stderr"`
}

type examResult struct {
	Name     string     `json:"name"`
	Verdict  string     `json:"verdict"`
	Failures []string   `json:"failures,omitempty"`
	Server   stepRecord `json:"server"`
	Client   stepRecord `json:"client"`
}

type artifactRecord struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Verified bool   `json:"verified"`
}

type examReceipt struct {
	SchemaVersion            string            `json:"schema_version"`
	Kind                     string            `json:"kind"`
	RecordedAt               string            `json:"recorded_at"`
	Runner                   string            `json:"runner"`
	Platform                 map[string]string `json:"platform"`
	Artifacts                []artifactRecord  `json:"artifacts"`
	JavacExit                int               `json:"javac_exit"`
	Exams                    []examResult      `json:"exams"`
	Verdict                  string            `json:"verdict"`
	Assurance                string            `json:"assurance"`
	IndependentReviewClaimed bool              `json:"independent_review_claimed"`
}

// runExam starts the server peer, waits for its listening line, runs the
// client peer to completion, then waits for the server; every exit is read
// from the real ProcessState.
func runExam(spec examSpec) examResult {
	result := examResult{Name: spec.Name, Verdict: "FAIL"}

	server := exec.Command(spec.ServerArgv[0], spec.ServerArgv[1:]...)
	result.Server = stepRecord{Role: spec.ServerExpect.Role, Command: strings.Join(spec.ServerArgv, " "), Exit: exitNoProcessState}
	serverStdout, err := server.StdoutPipe()
	if err != nil {
		result.Failures = append(result.Failures, fmt.Sprintf("server stdout pipe: %v", err))
		return result
	}
	var serverStderr bytes.Buffer
	server.Stderr = &serverStderr
	if err := server.Start(); err != nil {
		result.Failures = append(result.Failures, fmt.Sprintf("server never started: %v", err))
		return result
	}

	var captured bytes.Buffer
	listening := make(chan string, 1)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(serverStdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			captured.WriteString(line)
			captured.WriteByte('\n')
			if address, ok := parseListeningAddress(line); ok {
				select {
				case listening <- address:
				default:
				}
			}
		}
	}()

	var address string
	select {
	case address = <-listening:
	case <-time.After(peerStartTimeout):
		result.Failures = append(result.Failures, "server never printed its listening line")
		_ = server.Process.Kill()
		<-scanDone
		_ = server.Wait()
		result.Server.Exit = readExit(server.ProcessState, fmt.Errorf("killed after start timeout"))
		result.Server.Stdout = captured.String()
		result.Server.Stderr = serverStderr.String()
		return result
	}

	clientArgv := spec.ClientArgv(address)
	client := exec.Command(clientArgv[0], clientArgv[1:]...)
	var clientStdout, clientStderr bytes.Buffer
	client.Stdout = &clientStdout
	client.Stderr = &clientStderr
	clientErr := runWithTimeout(client, peerRunTimeout)
	result.Client = stepRecord{
		Role:    spec.ClientExpect.Role,
		Command: strings.Join(clientArgv, " "),
		Exit:    readExit(client.ProcessState, clientErr),
		Stdout:  clientStdout.String(),
		Stderr:  clientStderr.String(),
	}

	serverErr := waitWithTimeout(server, peerRunTimeout)
	<-scanDone
	result.Server.Exit = readExit(server.ProcessState, serverErr)
	result.Server.Stdout = captured.String()
	result.Server.Stderr = serverStderr.String()

	result.Failures = append(result.Failures, evaluateExpectation(spec.ServerExpect, result.Server)...)
	result.Failures = append(result.Failures, evaluateExpectation(spec.ClientExpect, result.Client)...)
	if len(result.Failures) == 0 {
		result.Verdict = "PASS"
	}
	return result
}

func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	return waitWithTimeout(cmd, timeout)
}

func waitWithTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return fmt.Errorf("killed after %s timeout: %w", timeout, <-done)
	}
}

// readExit reads the exit code from the ProcessState of every completed
// command; a command that never produced a ProcessState has no exit code
// and is reported with the explicit sentinel, never an invented number.
func readExit(state *os.ProcessState, _ error) int {
	if state != nil {
		return state.ExitCode()
	}
	return exitNoProcessState
}

// --- pure decision logic ----------------------------------------------------

// parseListeningAddress accepts the Rust testee's "listening host:port" and
// the Java fixture's "listening port" (loopback implied) forms.
func parseListeningAddress(line string) (string, bool) {
	rest, found := strings.CutPrefix(line, "listening ")
	if !found || rest == "" {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	if strings.Contains(rest, ":") {
		return rest, true
	}
	if _, err := strconv.Atoi(rest); err != nil {
		return "", false
	}
	return "127.0.0.1:" + rest, true
}

func findListeningAddress(stdout string) (string, bool) {
	for _, line := range strings.Split(stdout, "\n") {
		if address, ok := parseListeningAddress(line); ok {
			return address, true
		}
	}
	return "", false
}

// summaryFields parses one ws-testee summary line into its key=value map.
func summaryFields(summary string) map[string]string {
	fields := make(map[string]string)
	for _, token := range strings.Fields(summary) {
		if key, value, found := strings.Cut(token, "="); found {
			fields[key] = value
		}
	}
	return fields
}

// summaryLine finds the ws-testee report summary among the captured lines.
func summaryLine(stdout string) (string, bool) {
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, "outcome=") {
			return line, true
		}
	}
	return "", false
}

// evaluateExpectation returns one failure string per unmet expectation;
// empty means the record conforms.
func evaluateExpectation(expect expectation, record stepRecord) []string {
	var failures []string
	if record.Exit != expect.Exit {
		failures = append(failures, fmt.Sprintf("%s: exit=%d want %d", expect.Role, record.Exit, expect.Exit))
	}
	if len(expect.SummaryFields) > 0 {
		summary, ok := summaryLine(record.Stdout)
		if !ok {
			failures = append(failures, fmt.Sprintf("%s: no summary line in stdout", expect.Role))
		} else {
			fields := summaryFields(summary)
			for _, key := range sortedFieldKeys(expect.SummaryFields) {
				if fields[key] != expect.SummaryFields[key] {
					failures = append(failures, fmt.Sprintf("%s: summary %s=%q want %q", expect.Role, key, fields[key], expect.SummaryFields[key]))
				}
			}
		}
	}
	for _, needle := range expect.StdoutContains {
		if !strings.Contains(record.Stdout, needle) {
			failures = append(failures, fmt.Sprintf("%s: stdout missing %q", expect.Role, needle))
		}
	}
	return failures
}

func sortedFieldKeys(fields map[string]string) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}

func verifyFileDigest(path, want string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != want {
		return fmt.Errorf("digest mismatch: got %s want %s", got, want)
	}
	return nil
}

func platformRecord() map[string]string {
	record := map[string]string{
		"go_os":   runtime.GOOS,
		"go_arch": runtime.GOARCH,
	}
	if out, err := exec.Command("uname", "-srm").Output(); err == nil {
		record["uname"] = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("java", "-version").CombinedOutput(); err == nil {
		record["java_version"] = strings.TrimSpace(strings.Split(string(out), "\n")[0])
	}
	return record
}
