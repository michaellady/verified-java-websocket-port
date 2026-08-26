// benchops holds the conditional/loop/state-machine logic of
// .github/workflows/benchmark.yml (review fix round 2: every workflow
// step with real logic is a thin one-line invocation of this binary).
// It never measures anything: the only runner it drives is the
// cmd/benchrunner stub, whose every metric field is the NOT_MEASURED
// sentinel.
//
// Subcommands:
//
//	apply            — build the conditional -var arguments and run
//	                   terraform apply (fails closed on the unpinned-AMI
//	                   precondition exactly as before).
//	destroy          — the same-job teardown: retrying terraform destroy
//	                   (default 3 attempts, 60s backoff), loud failure
//	                   pointing at the janitor backstop.
//	delete-workspace — select default and delete the bench workspace,
//	                   warning (not failing) when state is non-empty.
//	wait-ssm-online  — poll until the SSM agent reports Online.
//	run-runner       — compose the SSM RunShellScript parameters, send
//	                   the command, and poll the invocation to
//	                   completion, dumping remote stdout/stderr on
//	                   failure.
//	verify-no-host   — verify the real path, not the destroy exit code:
//	                   fail loudly if any non-terminated instance is
//	                   still tagged with the bench workspace.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/benchexec"
	"github.com/michaellady/verified-java-websocket-port/internal/benchplan"
)

const hostBindingPendingExit = 3

var sha256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func main() {
	runner := benchexec.ExecRunner{Stdout: os.Stdout, Stderr: os.Stderr}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, runner, time.Sleep))
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  benchops apply --chdir DIR --pr N [--instance-type T] [--ami-id A] [--allow-unpinned-ami true]")
	fmt.Fprintln(output, "  benchops destroy --chdir DIR --pr N --workspace W [--instance-type T] [--ami-id A] [--allow-unpinned-ami true] [--attempts 3]")
	fmt.Fprintln(output, "  benchops delete-workspace --chdir DIR --workspace W")
	fmt.Fprintln(output, "  benchops wait-ssm-online --instance-id I [--attempts 120] [--interval-seconds 15]")
	fmt.Fprintln(output, "  benchops run-runner --instance-id I --bucket B --runner-digest sha256:... --pr N --workspace W [--poll-attempts 360] [--poll-interval-seconds 10]")
	fmt.Fprintln(output, "  benchops verify-no-host --workspace W")
	fmt.Fprintln(output, "  benchops readiness --root DIR --mode measurement|plumbing")
	fmt.Fprintln(output, "  benchops digest --path FILE")
	fmt.Fprintln(output, "  benchops verify-artifacts --dir DIR")
}

func run(arguments []string, stdout, stderr io.Writer, runner benchexec.Runner, sleep func(time.Duration)) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "apply":
		return runApply(arguments[1:], stdout, stderr, runner)
	case "destroy":
		return runDestroy(arguments[1:], stdout, stderr, runner, sleep)
	case "delete-workspace":
		return runDeleteWorkspace(arguments[1:], stdout, stderr, runner)
	case "wait-ssm-online":
		return runWaitSSMOnline(arguments[1:], stdout, stderr, runner, sleep)
	case "run-runner":
		return runRunRunner(arguments[1:], stdout, stderr, runner, sleep)
	case "verify-no-host":
		return runVerifyNoHost(arguments[1:], stdout, stderr, runner)
	case "readiness":
		return runReadiness(arguments[1:], stdout, stderr)
	case "digest":
		return runDigest(arguments[1:], stdout, stderr)
	case "verify-artifacts":
		return runVerifyArtifacts(arguments[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return 2
	}
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// terraformVarArgs builds the conditional -var list shared by apply and
// destroy: pr_number always, instance_type / ami_id only when set, and
// allow_unpinned_ami only when the input is exactly "true". With no
// pinned AMI and no explicit plumbing-test flag, apply FAILS CLOSED on
// the instance precondition — that is the intended preregistration
// gate.
func terraformVarArgs(pr, instanceType, amiID, allowUnpinned string) []string {
	arguments := []string{"-var", "pr_number=" + pr}
	if instanceType != "" {
		arguments = append(arguments, "-var", "instance_type="+instanceType)
	}
	if amiID != "" {
		arguments = append(arguments, "-var", "ami_id="+amiID)
	}
	if allowUnpinned == "true" {
		arguments = append(arguments, "-var", "allow_unpinned_ami=true")
	}
	return arguments
}

func runApply(arguments []string, stdout, stderr io.Writer, runner benchexec.Runner) int {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("chdir", "", "terraform benchmark root directory")
	pr := flags.String("pr", "", "PR number")
	instanceType := flags.String("instance-type", "", "optional instance type override")
	amiID := flags.String("ami-id", "", "optional AMI id override")
	allowUnpinned := flags.String("allow-unpinned-ami", "", "pass exactly 'true' for a plumbing test")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *directory == "" || !isDecimal(*pr) {
		printUsage(stderr)
		return 2
	}
	applyArguments := append([]string{"apply", "-auto-approve", "-input=false"},
		terraformVarArgs(*pr, *instanceType, *amiID, *allowUnpinned)...)
	if err := runner.Run(*directory, "terraform", applyArguments...); err != nil {
		fmt.Fprintf(stderr, "error: terraform apply failed: %v\n", err)
		return 1
	}
	return 0
}

func runDestroy(arguments []string, stdout, stderr io.Writer, runner benchexec.Runner, sleep func(time.Duration)) int {
	flags := flag.NewFlagSet("destroy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("chdir", "", "terraform benchmark root directory")
	pr := flags.String("pr", "", "PR number")
	workspace := flags.String("workspace", "", "bench workspace name (for the failure message)")
	instanceType := flags.String("instance-type", "", "optional instance type override")
	amiID := flags.String("ami-id", "", "optional AMI id override")
	allowUnpinned := flags.String("allow-unpinned-ami", "", "pass exactly 'true' for a plumbing test")
	attempts := flags.Int("attempts", 3, "destroy attempts before failing")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *directory == "" || !isDecimal(*pr) || *workspace == "" || *attempts < 1 {
		printUsage(stderr)
		return 2
	}
	destroyArguments := append([]string{"destroy", "-auto-approve", "-input=false"},
		terraformVarArgs(*pr, *instanceType, *amiID, *allowUnpinned)...)
	for attempt := 1; attempt <= *attempts; attempt++ {
		if err := runner.Run(*directory, "terraform", destroyArguments...); err == nil {
			return 0
		}
		fmt.Fprintf(stdout, "destroy attempt %d failed", attempt)
		if attempt < *attempts {
			fmt.Fprint(stdout, "; sleeping 60s")
			sleep(60 * time.Second)
		}
		fmt.Fprintln(stdout)
	}
	fmt.Fprintf(stdout, "::error::terraform destroy failed after %d attempts — bench-janitor will sweep %s after 3h, but investigate NOW (metal host may still be billing).\n", *attempts, *workspace)
	return 1
}

func runDeleteWorkspace(arguments []string, stdout, stderr io.Writer, runner benchexec.Runner) int {
	flags := flag.NewFlagSet("delete-workspace", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("chdir", "", "terraform benchmark root directory")
	workspace := flags.String("workspace", "", "bench workspace name")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *directory == "" || *workspace == "" {
		printUsage(stderr)
		return 2
	}
	if err := runner.Run(*directory, "terraform", "workspace", "select", "default"); err != nil {
		fmt.Fprintf(stderr, "error: could not select the default workspace: %v\n", err)
		return 1
	}
	if err := runner.Run(*directory, "terraform", "workspace", "delete", *workspace); err != nil {
		fmt.Fprintf(stdout, "::warning::could not delete workspace %s (non-empty state after failed destroy?) — bench-janitor sweeps it after 3h.\n", *workspace)
		return 0
	}
	fmt.Fprintf(stdout, "Deleted workspace %s\n", *workspace)
	return 0
}

func runWaitSSMOnline(arguments []string, stdout, stderr io.Writer, runner benchexec.Runner, sleep func(time.Duration)) int {
	flags := flag.NewFlagSet("wait-ssm-online", flag.ContinueOnError)
	flags.SetOutput(stderr)
	instanceID := flags.String("instance-id", "", "EC2 instance id")
	attempts := flags.Int("attempts", 120, "polling attempts (metal boot can take 10-20 minutes)")
	intervalSeconds := flags.Int("interval-seconds", 15, "seconds between polls")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *instanceID == "" || *attempts < 1 || *intervalSeconds < 1 {
		printUsage(stderr)
		return 2
	}
	for attempt := 1; attempt <= *attempts; attempt++ {
		output, err := runner.Output("aws", "ssm", "describe-instance-information",
			"--filters", "Key=InstanceIds,Values="+*instanceID,
			"--query", "InstanceInformationList[0].PingStatus", "--output", "text")
		status := "None"
		if err == nil {
			if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
				status = trimmed
			}
		}
		if status == "Online" {
			fmt.Fprintf(stdout, "SSM agent Online on %s\n", *instanceID)
			return 0
		}
		fmt.Fprintf(stdout, "PingStatus=%s; waiting...\n", status)
		if attempt < *attempts {
			sleep(time.Duration(*intervalSeconds) * time.Second)
		}
	}
	fmt.Fprintf(stdout, "::error::SSM agent never came Online on %s — failing (teardown still runs).\n", *instanceID)
	return 1
}

// ssmParameters composes the RunShellScript parameter document for the
// stub runner invocation. The runner is a STUB (see cmd/benchrunner):
// it validates its arguments and emits the result-schema skeleton with
// NOT_MEASURED sentinels. It fabricates no benchmark numbers.
func ssmParameters(bucket, runnerDigest, pr, workspace string) (string, error) {
	if !sha256DigestPattern.MatchString(runnerDigest) || runnerDigest == "sha256:"+strings.Repeat("0", 64) {
		return "", fmt.Errorf("runner digest must be a nonzero sha256 digest")
	}
	hexDigest := strings.TrimPrefix(runnerDigest, "sha256:")
	parameters := map[string]any{
		"executionTimeout": []string{"5400"},
		"commands": []string{
			"set -euo pipefail",
			"mkdir -p /opt/vjwp-bench/results",
			fmt.Sprintf("aws s3 cp s3://%s/runner/benchrunner /opt/vjwp-bench/benchrunner", bucket),
			fmt.Sprintf("echo '%s  /opt/vjwp-bench/benchrunner' | sha256sum --check --strict", hexDigest),
			"chmod +x /opt/vjwp-bench/benchrunner",
			fmt.Sprintf("/opt/vjwp-bench/benchrunner --mode pipeline-smoke --pr %s --workspace %s --out /opt/vjwp-bench/results", pr, workspace),
			fmt.Sprintf("aws s3 sync /opt/vjwp-bench/results s3://%s/results/", bucket),
		},
	}
	encoded, err := json.Marshal(parameters)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// runVerifyNoHost verifies the real path, not the destroy exit code:
// it lists any non-terminated instance still tagged with the bench
// workspace and fails loudly if one exists. A listing failure is a
// failure — it must never read as "no leftovers".
func runVerifyNoHost(arguments []string, stdout, stderr io.Writer, runner benchexec.Runner) int {
	flags := flag.NewFlagSet("verify-no-host", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workspace := flags.String("workspace", "", "bench workspace name")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *workspace == "" {
		printUsage(stderr)
		return 2
	}
	output, err := runner.Output("aws", "ec2", "describe-instances",
		"--filters", "Name=tag:Workspace,Values="+*workspace,
		"Name=instance-state-name,Values=pending,running,stopping,stopped",
		"--query", "Reservations[].Instances[].InstanceId", "--output", "text")
	if err != nil {
		fmt.Fprintf(stderr, "error: aws ec2 describe-instances failed: %v (a listing failure must never read as zero leftovers)\n", err)
		return 1
	}
	leftovers := strings.TrimSpace(string(output))
	if leftovers != "" && leftovers != "None" {
		fmt.Fprintf(stdout, "::error::instances still not terminated for %s: %s — a metal host may still be billing.\n", *workspace, leftovers)
		return 1
	}
	fmt.Fprintf(stdout, "No live instances remain for %s.\n", *workspace)
	return 0
}

func runRunRunner(arguments []string, stdout, stderr io.Writer, runner benchexec.Runner, sleep func(time.Duration)) int {
	flags := flag.NewFlagSet("run-runner", flag.ContinueOnError)
	flags.SetOutput(stderr)
	instanceID := flags.String("instance-id", "", "EC2 instance id")
	bucket := flags.String("bucket", "", "results bucket")
	runnerDigest := flags.String("runner-digest", "", "expected sha256 digest of the staged runner")
	pr := flags.String("pr", "", "PR number")
	workspace := flags.String("workspace", "", "bench workspace name")
	pollAttempts := flags.Int("poll-attempts", 360, "invocation polling attempts")
	pollIntervalSeconds := flags.Int("poll-interval-seconds", 10, "seconds between invocation polls")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *instanceID == "" || *bucket == "" || !sha256DigestPattern.MatchString(*runnerDigest) || !isDecimal(*pr) || *workspace != "bench-pr-"+*pr || *pollAttempts < 1 || *pollIntervalSeconds < 1 {
		printUsage(stderr)
		return 2
	}
	parameters, err := ssmParameters(*bucket, *runnerDigest, *pr, *workspace)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	sendOutput, err := runner.Output("aws", "ssm", "send-command",
		"--document-name", "AWS-RunShellScript",
		"--instance-ids", *instanceID,
		"--comment", "US-008 pipeline smoke (stub runner, NOT_MEASURED output only)",
		"--parameters", parameters,
		"--query", "Command.CommandId", "--output", "text")
	if err != nil {
		fmt.Fprintf(stderr, "error: aws ssm send-command failed: %v\n", err)
		return 1
	}
	commandID := strings.TrimSpace(string(sendOutput))
	if commandID == "" {
		fmt.Fprintln(stderr, "error: aws ssm send-command returned an empty command id")
		return 1
	}
	fmt.Fprintf(stdout, "Sent SSM command %s\n", commandID)

	succeeded := false
	for attempt := 1; attempt <= *pollAttempts; attempt++ {
		statusOutput, err := runner.Output("aws", "ssm", "get-command-invocation",
			"--command-id", commandID, "--instance-id", *instanceID,
			"--query", "Status", "--output", "text")
		status := "Pending"
		if err == nil {
			if trimmed := strings.TrimSpace(string(statusOutput)); trimmed != "" {
				status = trimmed
			}
		}
		if status == "Success" {
			fmt.Fprintln(stdout, "SSM command succeeded.")
			succeeded = true
			break
		}
		if status == "Failed" || status == "Cancelled" || status == "TimedOut" {
			fmt.Fprintf(stdout, "::error::SSM command ended with status %s\n", status)
			if dump, dumpErr := runner.Output("aws", "ssm", "get-command-invocation",
				"--command-id", commandID, "--instance-id", *instanceID,
				"--query", "{stdout:StandardOutputContent,stderr:StandardErrorContent}",
				"--output", "json"); dumpErr == nil {
				fmt.Fprintln(stdout, strings.TrimSpace(string(dump)))
			}
			return 1
		}
		fmt.Fprintf(stdout, "Status=%s; waiting...\n", status)
		if attempt < *pollAttempts {
			sleep(time.Duration(*pollIntervalSeconds) * time.Second)
		}
	}
	if !succeeded {
		fmt.Fprintln(stdout, "::error::SSM command did not complete before the polling limit.")
		return 1
	}
	finalOutput, err := runner.Output("aws", "ssm", "get-command-invocation",
		"--command-id", commandID, "--instance-id", *instanceID,
		"--query", "StandardOutputContent", "--output", "text")
	if err != nil {
		fmt.Fprintf(stderr, "error: could not fetch the command output: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, strings.TrimSpace(string(finalOutput)))
	return 0
}

func runReadiness(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("readiness", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root")
	mode := flags.String("mode", "", "measurement or plumbing")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *root == "" || (*mode != "measurement" && *mode != "plumbing") {
		printUsage(stderr)
		return 2
	}
	report, err := benchplan.Verify(*root)
	if err != nil {
		fmt.Fprintf(stderr, "readiness verification failed: %v\n", err)
		return 1
	}
	if report.FullyBound() {
		fmt.Fprintln(stdout, "MEASUREMENT_READY: owner-attested freeze and all host/tool bindings verified")
		return 0
	}
	if !report.HostBindingIsOnlyBlocker() {
		fmt.Fprintf(stderr, "readiness verification failed with blocker classes %v\n", report.BlockerClasses)
		return 1
	}
	if *mode == "plumbing" {
		fmt.Fprintln(stdout, "HOST_BINDING_PENDING: sentinel-only plumbing allowed; every output remains NOT_MEASURED and cannot be evidence")
		return 0
	}
	fmt.Fprintln(stderr, "HOST_BINDING_PENDING: measurement-capable provisioning and runners are refused until every canonical host/tool binding is semantically complete")
	return hostBindingPendingExit
}

func runDigest(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("digest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("path", "", "file to digest")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *path == "" {
		printUsage(stderr)
		return 2
	}
	content, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintf(stderr, "digest failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "sha256:%x\n", sha256.Sum256(content))
	return 0
}

func runVerifyArtifacts(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify-artifacts", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("dir", "", "downloaded result directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *directory == "" {
		printUsage(stderr)
		return 2
	}
	entries, err := os.ReadDir(*directory)
	if err != nil {
		fmt.Fprintf(stderr, "artifact verification failed: %v\n", err)
		return 1
	}
	if len(entries) != 2 {
		fmt.Fprintf(stderr, "artifact verification failed: expected exactly result + digest sidecar, got %d entries\n", len(entries))
		return 1
	}
	resultPath := filepath.Join(*directory, "pipeline-smoke-result.json")
	digestPath := resultPath + ".sha256"
	result, err := os.ReadFile(resultPath)
	if err != nil {
		fmt.Fprintf(stderr, "artifact verification failed: %v\n", err)
		return 1
	}
	digestBytes, err := os.ReadFile(digestPath)
	if err != nil {
		fmt.Fprintf(stderr, "artifact verification failed: %v\n", err)
		return 1
	}
	want := strings.TrimSpace(string(digestBytes))
	got := fmt.Sprintf("sha256:%x", sha256.Sum256(result))
	if !sha256DigestPattern.MatchString(want) || want != got {
		fmt.Fprintf(stderr, "artifact verification failed: sidecar %q does not bind result digest %s\n", want, got)
		return 1
	}
	fmt.Fprintf(stdout, "artifact digest verified: %s\n", got)
	return 0
}
