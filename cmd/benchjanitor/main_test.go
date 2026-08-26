package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeRunner scripts subprocess results and records every invocation.
type fakeRunner struct {
	listing     []byte
	listingErr  error
	invocations []string
	failures    map[string]int // command prefix -> remaining failures
}

func (r *fakeRunner) output(name string, arguments ...string) ([]byte, error) {
	r.invocations = append(r.invocations, name+" "+strings.Join(arguments, " "))
	return r.listing, r.listingErr
}

func (r *fakeRunner) run(directory, name string, arguments ...string) error {
	invocation := name + " " + strings.Join(arguments, " ")
	r.invocations = append(r.invocations, invocation)
	for prefix, remaining := range r.failures {
		if strings.HasPrefix(invocation, prefix) && remaining > 0 {
			r.failures[prefix] = remaining - 1
			return fmt.Errorf("scripted failure for %q", prefix)
		}
	}
	return nil
}

func fixedNow() time.Time {
	return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
}

func listingJSON(entries ...string) []byte {
	return []byte(`{"Contents":[` + strings.Join(entries, ",") + `]}`)
}

func entry(key string, modified time.Time) string {
	return fmt.Sprintf(`{"Key":%q,"LastModified":%q}`, key, modified.Format(time.RFC3339))
}

func TestSelectOrphansAgeThresholdAndKeyFilter(t *testing.T) {
	now := fixedNow()
	objects := []stateObject{
		{Key: "env:/bench-pr-7/benchmark/terraform.tfstate", LastModified: now.Add(-4 * time.Hour)},
		{Key: "env:/bench-pr-8/benchmark/terraform.tfstate", LastModified: now.Add(-1 * time.Hour)},
		{Key: "env:/bench-pr-12/benchmark/terraform.tfstate", LastModified: now.Add(-30 * 24 * time.Hour)},
		{Key: "env:/env-pr-9/benchmark/terraform.tfstate", LastModified: now.Add(-99 * time.Hour)},
		{Key: "env:/bench-pr-x/benchmark/terraform.tfstate", LastModified: now.Add(-99 * time.Hour)},
		{Key: "env:/bench-pr-5/other/terraform.tfstate", LastModified: now.Add(-99 * time.Hour)},
	}
	orphans, lines := selectOrphans(objects, now.Add(-3*time.Hour))
	if len(orphans) != 2 || orphans[0] != 7 || orphans[1] != 12 {
		t.Fatalf("orphans = %v, want [7 12]", orphans)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "keep bench-pr-8") {
		t.Errorf("recent workspace must be kept: %s", joined)
	}
	if !strings.Contains(joined, "ORPHAN bench-pr-7") || !strings.Contains(joined, "ORPHAN bench-pr-12") {
		t.Errorf("stale workspaces must be orphans: %s", joined)
	}
	if strings.Contains(joined, "env-pr-9") || strings.Contains(joined, "bench-pr-x") || strings.Contains(joined, "bench-pr-5") {
		t.Errorf("non-matching keys must be ignored entirely: %s", joined)
	}
}

func TestFindWritesOrphansToGithubOutput(t *testing.T) {
	now := fixedNow()
	runner := &fakeRunner{listing: listingJSON(
		entry("env:/bench-pr-3/benchmark/terraform.tfstate", now.Add(-5*time.Hour)),
		entry("env:/bench-pr-4/benchmark/terraform.tfstate", now.Add(-time.Hour)),
	)}
	outputPath := filepath.Join(t.TempDir(), "github-output")
	t.Setenv("GITHUB_OUTPUT", outputPath)
	var stdout, stderr bytes.Buffer
	code := run([]string{"find", "--bucket", "test-bucket"}, &stdout, &stderr, runner, fixedNow, func(time.Duration) {})
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "orphans=3") {
		t.Fatalf("GITHUB_OUTPUT missing orphans=3: %s", content)
	}
	if !strings.Contains(stdout.String(), "Orphans: 3") {
		t.Fatalf("stdout missing orphan summary: %s", stdout.String())
	}
	if len(runner.invocations) != 1 || !strings.HasPrefix(runner.invocations[0], "aws s3api list-objects-v2 --bucket test-bucket") {
		t.Fatalf("unexpected invocations: %v", runner.invocations)
	}
}

func TestFindFailsLoudlyOnListingError(t *testing.T) {
	runner := &fakeRunner{listingErr: fmt.Errorf("AccessDenied")}
	var stdout, stderr bytes.Buffer
	code := run([]string{"find", "--bucket", "test-bucket"}, &stdout, &stderr, runner, fixedNow, func(time.Duration) {})
	if code != 1 {
		t.Fatalf("a listing failure must fail the command, exit %d", code)
	}
	if !strings.Contains(stderr.String(), "never read as zero orphans") {
		t.Fatalf("stderr must explain the fail-loud rule: %s", stderr.String())
	}
}

func TestFindEmptyListingIsZeroOrphans(t *testing.T) {
	runner := &fakeRunner{listing: []byte("")}
	var stdout, stderr bytes.Buffer
	code := run([]string{"find", "--bucket", "test-bucket"}, &stdout, &stderr, runner, fixedNow, func(time.Duration) {})
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Orphans: none") {
		t.Fatalf("stdout missing 'Orphans: none': %s", stdout.String())
	}
}

func TestDestroySweepsAllAndRetriesOnce(t *testing.T) {
	runner := &fakeRunner{failures: map[string]int{
		"terraform destroy -auto-approve -input=false -var pr_number=3": 1, // first attempt fails, retry succeeds
	}}
	slept := []time.Duration{}
	var stdout, stderr bytes.Buffer
	code := run([]string{"destroy", "--chdir", "terraform/benchmark", "--numbers", "3 9"},
		&stdout, &stderr, runner, fixedNow, func(d time.Duration) { slept = append(slept, d) })
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s", code, stdout.String())
	}
	if len(slept) != 1 || slept[0] != 60*time.Second {
		t.Fatalf("expected one 60s retry sleep, got %v", slept)
	}
	joined := strings.Join(runner.invocations, "\n")
	for _, required := range []string{
		"terraform workspace select bench-pr-3",
		"terraform destroy -auto-approve -input=false -var pr_number=3 -var allow_unpinned_ami=true",
		"terraform workspace select default",
		"terraform workspace delete bench-pr-3",
		"terraform workspace select bench-pr-9",
		"terraform workspace delete bench-pr-9",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("missing invocation %q in:\n%s", required, joined)
		}
	}
	if !strings.Contains(stdout.String(), "cleaned bench-pr-3") || !strings.Contains(stdout.String(), "cleaned bench-pr-9") {
		t.Fatalf("stdout must report both cleaned workspaces: %s", stdout.String())
	}
}

func TestDestroyOneBadWorkspaceDoesNotAbortBatchAndExitsNonzero(t *testing.T) {
	runner := &fakeRunner{failures: map[string]int{
		"terraform destroy -auto-approve -input=false -var pr_number=3": 2, // both attempts fail
	}}
	summaryPath := filepath.Join(t.TempDir(), "summary")
	t.Setenv("GITHUB_STEP_SUMMARY", summaryPath)
	var stdout, stderr bytes.Buffer
	code := run([]string{"destroy", "--chdir", "terraform/benchmark", "--numbers", "3 9"},
		&stdout, &stderr, runner, fixedNow, func(time.Duration) {})
	if code != 1 {
		t.Fatalf("a failed destroy must exit nonzero, got %d", code)
	}
	joined := strings.Join(runner.invocations, "\n")
	if !strings.Contains(joined, "terraform workspace select bench-pr-9") {
		t.Fatalf("the batch must continue past the failed workspace:\n%s", joined)
	}
	if !strings.Contains(stdout.String(), "::error::janitor could not destroy: bench-pr-3") {
		t.Fatalf("stdout must carry the billing warning: %s", stdout.String())
	}
	summary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summary), "failed: bench-pr-3") || !strings.Contains(string(summary), "swept: bench-pr-9") {
		t.Fatalf("step summary must report swept and failed: %s", summary)
	}
}

func TestDestroyWorkspaceDeleteFailureIsRetainedAndReported(t *testing.T) {
	runner := &fakeRunner{failures: map[string]int{
		"terraform workspace delete bench-pr-3": 1,
	}}
	var stdout, stderr bytes.Buffer
	code := run([]string{"destroy", "--chdir", "terraform/benchmark", "--numbers", "3"},
		&stdout, &stderr, runner, fixedNow, func(time.Duration) {})
	if code != 1 {
		t.Fatalf("a failed workspace delete must exit nonzero, got %d", code)
	}
	if !strings.Contains(stdout.String(), "retained for inspection") {
		t.Fatalf("stdout must report retention: %s", stdout.String())
	}
}

func TestDestroyNoOrphansIsANoop(t *testing.T) {
	runner := &fakeRunner{}
	var stdout, stderr bytes.Buffer
	code := run([]string{"destroy", "--chdir", "terraform/benchmark", "--numbers", "  "},
		&stdout, &stderr, runner, fixedNow, func(time.Duration) {})
	if code != 0 || len(runner.invocations) != 0 {
		t.Fatalf("empty orphan list must be a no-op, exit %d invocations %v", code, runner.invocations)
	}
}

func TestUsageErrors(t *testing.T) {
	runner := &fakeRunner{}
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr, runner, fixedNow, func(time.Duration) {}); code != 2 {
		t.Errorf("no arguments: exit %d, want 2", code)
	}
	if code := run([]string{"sweep"}, &stdout, &stderr, runner, fixedNow, func(time.Duration) {}); code != 2 {
		t.Errorf("unknown subcommand: exit %d, want 2", code)
	}
	if code := run([]string{"find"}, &stdout, &stderr, runner, fixedNow, func(time.Duration) {}); code != 2 {
		t.Errorf("find without bucket: exit %d, want 2", code)
	}
	if code := run([]string{"destroy", "--numbers", "3"}, &stdout, &stderr, runner, fixedNow, func(time.Duration) {}); code != 2 {
		t.Errorf("destroy without chdir: exit %d, want 2", code)
	}
	if code := run([]string{"destroy", "--chdir", "x", "--numbers", "3; rm -rf /"}, &stdout, &stderr, runner, fixedNow, func(time.Duration) {}); code != 2 {
		t.Errorf("non-decimal numbers: exit %d, want 2", code)
	}
}
