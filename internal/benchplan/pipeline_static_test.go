package benchplan

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPipelinePrivilegeBoundaryAndTrustedOIDCIdentityAreStatic(t *testing.T) {
	benchmark := readRepoFile(t, ".github/workflows/benchmark.yml")
	if strings.Contains(benchmark, "github.event.label") || strings.Contains(benchmark, "types: [labeled]") {
		t.Fatal("labeled pull requests must not reach the privileged benchmark path")
	}
	for _, required := range []string{
		"validate-pr:",
		"permissions:\n      contents: read",
		"if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'",
		"id-token: write",
		"benchops readiness --root . --mode",
		"go-version: \"1.25.5\"",
		"BENCH_INSTANCE_TYPE: ${{ inputs.plumbing_sentinel_only && 'c7i.large' || 'c7i.xlarge' }}",
		"BENCH_AMI_ID: \"ami-02b3d83d84b07786d\"",
		"benchops verify-artifacts --dir bench-results",
		"--runner-digest \"${RUNNER_DIGEST}\"",
	} {
		if !strings.Contains(benchmark, required) {
			t.Errorf("benchmark workflow missing security invariant %q", required)
		}
	}
	if strings.Count(benchmark, "id-token: write") != 1 {
		t.Fatal("only the default-ref manual benchmark job may request an OIDC token")
	}

	janitor := readRepoFile(t, ".github/workflows/bench-janitor.yml")
	if !strings.Contains(janitor, "github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main')") {
		t.Fatal("manual janitor execution must be restricted to the trusted default ref")
	}

	bootstrap := readRepoFile(t, "terraform/bootstrap/main.tf")
	for _, required := range []string{
		`"token.actions.githubusercontent.com:aud"      = "sts.amazonaws.com"`,
		`"token.actions.githubusercontent.com:ref"      = "refs/heads/main"`,
		`"token.actions.githubusercontent.com:workflow" = var.oidc_trusted_workflow_names`,
		`"repo:${r}:environment:${each.key}"`,
	} {
		if !strings.Contains(bootstrap, required) {
			t.Errorf("bootstrap OIDC trust missing %q", required)
		}
	}
	if strings.Contains(bootstrap, `"repo:${r}:pull_request"`) || strings.Contains(bootstrap, "concat([var.github_repo]") {
		t.Fatal("bootstrap OIDC trust must not admit PR subjects or mutable owner/name identities")
	}
	if strings.Contains(bootstrap, "workflow_ref") || strings.Contains(bootstrap, "job_workflow_ref") {
		t.Fatal("direct workflows must use AWS's supported workflow claim, not workflow_ref or reusable-job-only job_workflow_ref")
	}
	tfvars := readRepoFile(t, "terraform/bootstrap/bootstrap.auto.tfvars")
	for _, workflow := range []struct {
		path string
		name string
	}{
		{".github/workflows/benchmark.yml", "Benchmark Confirmation Host (US-008 pipeline)"},
		{".github/workflows/bench-janitor.yml", "Bench Workspace Janitor"},
	} {
		if !strings.HasPrefix(readRepoFile(t, workflow.path), "name: "+workflow.name+"\n") {
			t.Errorf("%s name must exactly match trusted OIDC workflow claim %q", workflow.path, workflow.name)
		}
		if !strings.Contains(tfvars, `"`+workflow.name+`"`) {
			t.Errorf("bootstrap trust is missing exact workflow name %q", workflow.name)
		}
	}
}

func TestEveryExternalActionAndToolchainIsExactlyPinned(t *testing.T) {
	usesPattern := regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*([^\s#]+)`)
	shaRefPattern := regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	for _, path := range []string{
		".github/workflows/benchmark.yml",
		".github/workflows/bench-janitor.yml",
		".github/actions/dialed-setup/action.yml",
	} {
		content := readRepoFile(t, path)
		for _, match := range usesPattern.FindAllStringSubmatch(content, -1) {
			if strings.HasPrefix(match[1], "./") {
				continue
			}
			if !shaRefPattern.MatchString(match[1]) {
				t.Errorf("%s has mutable action reference %q", path, match[1])
			}
		}
	}

	goMod := readRepoFile(t, "go.mod")
	if !strings.Contains(goMod, "\ngo 1.25.5\n") {
		t.Fatal("go.mod must pin the Go toolchain to exactly 1.25.5")
	}
	action := readRepoFile(t, ".github/actions/dialed-setup/action.yml")
	for _, required := range []string{
		`yq_pin="4.44.3"`,
		`yq_sha256="a2c097180dd884a8d50c956ee16a9cec070f30a7947cf4ebf87d5f36213e9ed7"`,
		"sha256sum --check --strict",
	} {
		if !strings.Contains(action, required) {
			t.Errorf("pinned yq acquisition missing %q", required)
		}
	}
	for _, root := range []string{"terraform/benchmark", "terraform/bootstrap"} {
		versionsPath := filepath.Join(root, "versions.tf")
		if root == "terraform/bootstrap" {
			versionsPath = filepath.Join(root, "main.tf")
		}
		versions := readRepoFile(t, versionsPath)
		if !strings.Contains(versions, `required_version = "= 1.9.8"`) || !strings.Contains(versions, `version = "= 6.0.0"`) {
			t.Errorf("%s must pin exact Terraform/AWS provider versions", versionsPath)
		}
		lock := readRepoFile(t, filepath.Join(root, ".terraform.lock.hcl"))
		if !strings.Contains(lock, `version     = "6.0.0"`) || !strings.Contains(lock, `constraints = "6.0.0"`) || !strings.Contains(lock, "zh:") {
			t.Errorf("%s lock file does not bind AWS provider 6.0.0 checksums", root)
		}
	}
}

func TestTerraformNonPlumbingPathEnforcesFrozenTierOneIdentity(t *testing.T) {
	mainTF := readRepoFile(t, "terraform/benchmark/main.tf")
	for _, exact := range []string{`var.instance_type == "c7i.xlarge"`, `var.ami_id == "ami-02b3d83d84b07786d"`, `var.aws_region == "us-east-1"`} {
		if !strings.Contains(mainTF, exact) {
			t.Errorf("benchmark host precondition missing %s", exact)
		}
	}
	variables := readRepoFile(t, "terraform/benchmark/variables.tf")
	if !strings.Contains(variables, `default     = "c7i.xlarge"`) || !strings.Contains(variables, `default     = "ami-02b3d83d84b07786d"`) {
		t.Fatal("benchmark Terraform defaults must be the exact frozen Tier-1 class and AMI")
	}
}

func readRepoFile(t *testing.T, relative string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
