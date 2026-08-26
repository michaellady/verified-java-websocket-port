package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testRunnerDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// scriptedOutput is one queued Output result.
type scriptedOutput struct {
	data string
	err  error
}

// fakeRunner records invocations, scripts Output results in order, and
// scripts Run failures by invocation prefix.
type fakeRunner struct {
	invocations []string
	outputs     []scriptedOutput
	runFailures map[string]int
}

func (r *fakeRunner) Output(name string, arguments ...string) ([]byte, error) {
	r.invocations = append(r.invocations, name+" "+strings.Join(arguments, " "))
	if len(r.outputs) == 0 {
		return nil, fmt.Errorf("no scripted output left")
	}
	next := r.outputs[0]
	r.outputs = r.outputs[1:]
	return []byte(next.data), next.err
}

func (r *fakeRunner) Run(directory, name string, arguments ...string) error {
	invocation := name + " " + strings.Join(arguments, " ")
	r.invocations = append(r.invocations, invocation)
	for prefix, remaining := range r.runFailures {
		if strings.HasPrefix(invocation, prefix) && remaining > 0 {
			r.runFailures[prefix] = remaining - 1
			return fmt.Errorf("scripted failure for %q", prefix)
		}
	}
	return nil
}

func noSleep(time.Duration) {}

func TestTerraformVarArgsConditionals(t *testing.T) {
	cases := []struct {
		pr, instanceType, amiID, allowUnpinned string
		want                                   []string
	}{
		{"7", "", "", "", []string{"-var", "pr_number=7"}},
		{"7", "c5n.metal", "", "", []string{"-var", "pr_number=7", "-var", "instance_type=c5n.metal"}},
		{"7", "", "ami-123", "", []string{"-var", "pr_number=7", "-var", "ami_id=ami-123"}},
		{"7", "", "", "true", []string{"-var", "pr_number=7", "-var", "allow_unpinned_ami=true"}},
		// Anything but the literal "true" must NOT loosen the AMI gate.
		{"7", "", "", "false", []string{"-var", "pr_number=7"}},
		{"7", "", "", "TRUE", []string{"-var", "pr_number=7"}},
		{"7", "c5n.metal", "ami-123", "true", []string{"-var", "pr_number=7", "-var", "instance_type=c5n.metal", "-var", "ami_id=ami-123", "-var", "allow_unpinned_ami=true"}},
	}
	for _, testCase := range cases {
		got := terraformVarArgs(testCase.pr, testCase.instanceType, testCase.amiID, testCase.allowUnpinned)
		if strings.Join(got, " ") != strings.Join(testCase.want, " ") {
			t.Errorf("varArgs(%q,%q,%q,%q) = %v, want %v", testCase.pr, testCase.instanceType, testCase.amiID, testCase.allowUnpinned, got, testCase.want)
		}
	}
}

func TestApplyBuildsConditionalArguments(t *testing.T) {
	runner := &fakeRunner{}
	var stdout, stderr bytes.Buffer
	code := run([]string{"apply", "--chdir", "terraform/benchmark", "--pr", "7", "--instance-type", "c5n.metal", "--allow-unpinned-ami", "true"},
		&stdout, &stderr, runner, noSleep)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	want := "terraform apply -auto-approve -input=false -var pr_number=7 -var instance_type=c5n.metal -var allow_unpinned_ami=true"
	if len(runner.invocations) != 1 || runner.invocations[0] != want {
		t.Fatalf("invocations %v, want [%s]", runner.invocations, want)
	}
}

func TestApplyFailsClosedOnTerraformError(t *testing.T) {
	runner := &fakeRunner{runFailures: map[string]int{"terraform apply": 1}}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"apply", "--chdir", "d", "--pr", "7"}, &stdout, &stderr, runner, noSleep); code != 1 {
		t.Fatalf("a failed apply must exit 1, got %d", code)
	}
}

func TestDestroyRetriesThenSucceeds(t *testing.T) {
	runner := &fakeRunner{runFailures: map[string]int{"terraform destroy": 2}}
	var slept []time.Duration
	var stdout, stderr bytes.Buffer
	code := run([]string{"destroy", "--chdir", "d", "--pr", "7", "--workspace", "bench-pr-7"},
		&stdout, &stderr, runner, func(d time.Duration) { slept = append(slept, d) })
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s", code, stdout.String())
	}
	if len(runner.invocations) != 3 {
		t.Fatalf("expected 3 destroy attempts, got %v", runner.invocations)
	}
	if len(slept) != 2 || slept[0] != 60*time.Second {
		t.Fatalf("expected two 60s backoffs, got %v", slept)
	}
}

func TestDestroyFailsLoudlyAfterAllAttempts(t *testing.T) {
	runner := &fakeRunner{runFailures: map[string]int{"terraform destroy": 3}}
	var stdout, stderr bytes.Buffer
	code := run([]string{"destroy", "--chdir", "d", "--pr", "7", "--workspace", "bench-pr-7"},
		&stdout, &stderr, runner, noSleep)
	if code != 1 {
		t.Fatalf("exhausted destroy must exit 1, got %d", code)
	}
	if !strings.Contains(stdout.String(), "::error::terraform destroy failed after 3 attempts") ||
		!strings.Contains(stdout.String(), "bench-pr-7") {
		t.Fatalf("stdout must carry the janitor-backstop failure: %s", stdout.String())
	}
}

func TestDeleteWorkspacePaths(t *testing.T) {
	// Happy path.
	runner := &fakeRunner{}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"delete-workspace", "--chdir", "d", "--workspace", "bench-pr-7"}, &stdout, &stderr, runner, noSleep); code != 0 {
		t.Fatalf("exit %d", code)
	}
	joined := strings.Join(runner.invocations, "\n")
	if !strings.Contains(joined, "terraform workspace select default") || !strings.Contains(joined, "terraform workspace delete bench-pr-7") {
		t.Fatalf("invocations %v", runner.invocations)
	}
	// Delete failure is a warning, not a job failure.
	runner = &fakeRunner{runFailures: map[string]int{"terraform workspace delete": 1}}
	stdout.Reset()
	if code := run([]string{"delete-workspace", "--chdir", "d", "--workspace", "bench-pr-7"}, &stdout, &stderr, runner, noSleep); code != 0 {
		t.Fatalf("delete failure must warn, not fail: exit %d", code)
	}
	if !strings.Contains(stdout.String(), "::warning::could not delete workspace bench-pr-7") {
		t.Fatalf("stdout must warn: %s", stdout.String())
	}
	// Select-default failure fails the step.
	runner = &fakeRunner{runFailures: map[string]int{"terraform workspace select default": 1}}
	if code := run([]string{"delete-workspace", "--chdir", "d", "--workspace", "bench-pr-7"}, &stdout, &stderr, runner, noSleep); code != 1 {
		t.Fatalf("select-default failure must exit 1, got %d", code)
	}
}

func TestWaitSSMOnlineTransitions(t *testing.T) {
	runner := &fakeRunner{outputs: []scriptedOutput{
		{data: "", err: fmt.Errorf("InvalidInstanceId")},
		{data: "Connecting\n"},
		{data: "Online\n"},
	}}
	var slept []time.Duration
	var stdout, stderr bytes.Buffer
	code := run([]string{"wait-ssm-online", "--instance-id", "i-abc", "--attempts", "5", "--interval-seconds", "15"},
		&stdout, &stderr, runner, func(d time.Duration) { slept = append(slept, d) })
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "PingStatus=None") || !strings.Contains(stdout.String(), "PingStatus=Connecting") ||
		!strings.Contains(stdout.String(), "SSM agent Online on i-abc") {
		t.Fatalf("stdout must show the polling transitions: %s", stdout.String())
	}
	if len(slept) != 2 || slept[0] != 15*time.Second {
		t.Fatalf("expected two 15s sleeps, got %v", slept)
	}
}

func TestWaitSSMOnlineFailsAfterLimit(t *testing.T) {
	runner := &fakeRunner{outputs: []scriptedOutput{{data: "Connecting"}, {data: "Connecting"}}}
	var stdout, stderr bytes.Buffer
	code := run([]string{"wait-ssm-online", "--instance-id", "i-abc", "--attempts", "2", "--interval-seconds", "1"},
		&stdout, &stderr, runner, noSleep)
	if code != 1 || !strings.Contains(stdout.String(), "::error::SSM agent never came Online") {
		t.Fatalf("exit %d, stdout: %s", code, stdout.String())
	}
}

func TestRunRunnerComposesParametersSendsAndPolls(t *testing.T) {
	runner := &fakeRunner{outputs: []scriptedOutput{
		{data: "cmd-123\n"},       // send-command
		{data: "InProgress\n"},    // poll 1
		{data: "Success\n"},       // poll 2
		{data: "self-check ok\n"}, // final stdout fetch
	}}
	var stdout, stderr bytes.Buffer
	code := run([]string{"run-runner", "--instance-id", "i-abc", "--bucket", "results-bkt", "--runner-digest", testRunnerDigest, "--pr", "7", "--workspace", "bench-pr-7"},
		&stdout, &stderr, runner, noSleep)
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	send := runner.invocations[0]
	if !strings.HasPrefix(send, "aws ssm send-command --document-name AWS-RunShellScript --instance-ids i-abc") {
		t.Fatalf("send invocation: %s", send)
	}
	// The parameter document must be well-formed JSON carrying the six
	// stub-runner commands, including mandatory digest verification before exec.
	start := strings.Index(send, "{")
	end := strings.LastIndex(send, "}")
	if start < 0 || end < start {
		t.Fatalf("no JSON parameters in: %s", send)
	}
	var parameters struct {
		ExecutionTimeout []string `json:"executionTimeout"`
		Commands         []string `json:"commands"`
	}
	if err := json.Unmarshal([]byte(send[start:end+1]), &parameters); err != nil {
		t.Fatalf("parameters are not valid JSON: %v", err)
	}
	if len(parameters.ExecutionTimeout) != 1 || parameters.ExecutionTimeout[0] != "5400" {
		t.Fatalf("executionTimeout %v", parameters.ExecutionTimeout)
	}
	if len(parameters.Commands) != 7 {
		t.Fatalf("expected 7 remote commands, got %v", parameters.Commands)
	}
	joinedCommands := strings.Join(parameters.Commands, "\n")
	for _, required := range []string{
		"aws s3 cp s3://results-bkt/runner/benchrunner /opt/vjwp-bench/benchrunner",
		"1111111111111111111111111111111111111111111111111111111111111111  /opt/vjwp-bench/benchrunner' | sha256sum --check --strict",
		"/opt/vjwp-bench/benchrunner --mode pipeline-smoke --pr 7 --workspace bench-pr-7 --out /opt/vjwp-bench/results",
		"aws s3 sync /opt/vjwp-bench/results s3://results-bkt/results/",
	} {
		if !strings.Contains(joinedCommands, required) {
			t.Errorf("remote commands missing %q:\n%s", required, joinedCommands)
		}
	}
	if !strings.Contains(stdout.String(), "Sent SSM command cmd-123") ||
		!strings.Contains(stdout.String(), "SSM command succeeded.") ||
		!strings.Contains(stdout.String(), "self-check ok") {
		t.Fatalf("stdout: %s", stdout.String())
	}
}

func TestRunRunnerFailedInvocationDumpsRemoteOutput(t *testing.T) {
	runner := &fakeRunner{outputs: []scriptedOutput{
		{data: "cmd-123"},
		{data: "Failed"},
		{data: `{"stdout":"","stderr":"error: mode refused"}`},
	}}
	var stdout, stderr bytes.Buffer
	code := run([]string{"run-runner", "--instance-id", "i-abc", "--bucket", "b", "--runner-digest", testRunnerDigest, "--pr", "7", "--workspace", "bench-pr-7"},
		&stdout, &stderr, runner, noSleep)
	if code != 1 {
		t.Fatalf("a Failed invocation must exit 1, got %d", code)
	}
	if !strings.Contains(stdout.String(), "::error::SSM command ended with status Failed") ||
		!strings.Contains(stdout.String(), "mode refused") {
		t.Fatalf("stdout must dump the remote stderr: %s", stdout.String())
	}
}

func TestRunRunnerPollingLimitFails(t *testing.T) {
	runner := &fakeRunner{outputs: []scriptedOutput{
		{data: "cmd-123"},
		{data: "InProgress"},
		{data: "InProgress"},
	}}
	var stdout, stderr bytes.Buffer
	code := run([]string{"run-runner", "--instance-id", "i-abc", "--bucket", "b", "--runner-digest", testRunnerDigest, "--pr", "7", "--workspace", "bench-pr-7", "--poll-attempts", "2", "--poll-interval-seconds", "1"},
		&stdout, &stderr, runner, noSleep)
	if code != 1 || !strings.Contains(stdout.String(), "did not complete before the polling limit") {
		t.Fatalf("exit %d, stdout: %s", code, stdout.String())
	}
}

func TestReadinessSeparatesOwnerFreezeFromSampleReadiness(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"readiness", "--root", "../..", "--mode", "measurement"}, &stdout, &stderr, &fakeRunner{}, noSleep); code != hostBindingPendingExit {
		t.Fatalf("measurement readiness exit %d, want %d; stdout=%s stderr=%s", code, hostBindingPendingExit, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "HOST_BINDING_PENDING") {
		t.Fatalf("measurement refusal must name HOST_BINDING_PENDING: %s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"readiness", "--root", "../..", "--mode", "plumbing"}, &stdout, &stderr, &fakeRunner{}, noSleep); code != 0 {
		t.Fatalf("sentinel plumbing exit %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "sentinel-only plumbing") || !strings.Contains(stdout.String(), "NOT_MEASURED") {
		t.Fatalf("plumbing allowance must remain non-evidence: %s", stdout.String())
	}
}

func TestDigestAndArtifactSidecarVerification(t *testing.T) {
	directory := t.TempDir()
	result := []byte("sentinel result\n")
	resultPath := filepath.Join(directory, "pipeline-smoke-result.json")
	if err := os.WriteFile(resultPath, result, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(result))
	if err := os.WriteFile(resultPath+".sha256", []byte(digest+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify-artifacts", "--dir", directory}, &stdout, &stderr, &fakeRunner{}, noSleep); code != 0 {
		t.Fatalf("valid artifact exit %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(resultPath, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"verify-artifacts", "--dir", directory}, &stdout, &stderr, &fakeRunner{}, noSleep); code != 1 {
		t.Fatalf("tampered artifact exit %d, want 1", code)
	}
}

func TestVerifyNoHostPaths(t *testing.T) {
	// Clean: empty listing.
	runner := &fakeRunner{outputs: []scriptedOutput{{data: "\n"}}}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify-no-host", "--workspace", "bench-pr-7"}, &stdout, &stderr, runner, noSleep); code != 0 {
		t.Fatalf("clean listing: exit %d", code)
	}
	if !strings.Contains(stdout.String(), "No live instances remain for bench-pr-7") {
		t.Fatalf("stdout: %s", stdout.String())
	}
	if !strings.Contains(runner.invocations[0], "Name=tag:Workspace,Values=bench-pr-7") {
		t.Fatalf("filter missing: %s", runner.invocations[0])
	}
	// Leftover instance: loud failure.
	runner = &fakeRunner{outputs: []scriptedOutput{{data: "i-0abc123\n"}}}
	stdout.Reset()
	if code := run([]string{"verify-no-host", "--workspace", "bench-pr-7"}, &stdout, &stderr, runner, noSleep); code != 1 {
		t.Fatalf("leftover instance must exit 1")
	}
	if !strings.Contains(stdout.String(), "::error::instances still not terminated for bench-pr-7: i-0abc123") {
		t.Fatalf("stdout: %s", stdout.String())
	}
	// Listing failure must never read as zero leftovers.
	runner = &fakeRunner{outputs: []scriptedOutput{{err: fmt.Errorf("AccessDenied")}}}
	if code := run([]string{"verify-no-host", "--workspace", "bench-pr-7"}, &stdout, &stderr, runner, noSleep); code != 1 {
		t.Fatalf("listing failure must exit 1")
	}
}

func TestUsageErrors(t *testing.T) {
	runner := &fakeRunner{}
	var stdout, stderr bytes.Buffer
	cases := [][]string{
		nil,
		{"provision"},
		{"apply", "--pr", "7"},                   // missing chdir
		{"apply", "--chdir", "d", "--pr", "7x"},  // non-decimal pr
		{"destroy", "--chdir", "d", "--pr", "7"}, // missing workspace
		{"delete-workspace", "--chdir", "d"},     // missing workspace
		{"wait-ssm-online"},                      // missing instance id
		{"run-runner", "--instance-id", "i", "--bucket", "b", "--pr", "7", "--workspace", "bench-pr-8"}, // workspace contract
	}
	for _, arguments := range cases {
		if code := run(arguments, &stdout, &stderr, runner, noSleep); code != 2 {
			t.Errorf("%v: exit %d, want 2", arguments, code)
		}
	}
	if len(runner.invocations) != 0 {
		t.Fatalf("usage errors must not execute anything: %v", runner.invocations)
	}
}
