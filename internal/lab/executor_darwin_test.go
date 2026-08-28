//go:build darwin

package lab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinControlledCanaryBindsExactSelfAndFailsBeforeLaunch(t *testing.T) {
	request := ControlledCanaryRequest{
		CanaryID: "CLEAN_EXIT", PolicyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Resources: validSandboxPlan(t, SandboxMavenBuild).Resources,
	}
	planDigest, err := ControlledCanaryPlanDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.PlanDigest = planDigest
	self, executableDigest, err := controlledCanaryExecutableIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(self) || !strings.HasPrefix(executableDigest, "sha256:") {
		t.Fatalf("invalid exact executable identity: path=%q digest=%q", self, executableDigest)
	}
	if controlledCanaryPlatform != "DARWIN_SANDBOX_EXEC" {
		t.Fatalf("platform identity = %q", controlledCanaryPlatform)
	}
	if _, err := ExecuteControlledCanary(request); err == nil {
		t.Fatal("unpromoted executable was launched")
	} else {
		assertFinding(t, err, "UNPROMOTED_EXECUTABLE")
		if !strings.Contains(err.Error(), executableDigest) {
			t.Fatalf("promotion blocker does not bind exact executable digest: %v", err)
		}
	}
	mutated := request
	mutated.Resources.MaxOpenFiles++
	mutatedDigest, err := ControlledCanaryPlanDigest(mutated)
	if err != nil || mutatedDigest == planDigest {
		t.Fatalf("resource mutation was not bound: digest=%q err=%v", mutatedDigest, err)
	}
}

func TestMain(m *testing.M) {
	if handled, code := RunSandboxChild(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func TestDarwinSandboxProfileClosesAmbientAuthority(t *testing.T) {
	plan := validSandboxPlan(t, SandboxMavenAcquire)
	profile, err := darwinSandboxProfile(plan, "/private/tmp/labctl", "/private/tmp/tools/java", "/private/tmp/tools/jspawnhelper", "127.0.0.1:43117")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"(deny network*)",
		"(allow network-outbound (remote tcp \"localhost:43117\"))",
		"(deny file-read* (subpath \"/Users\"))",
		"(deny file-read-data (require-all",
		"(deny file-write*)",
		"(deny process*)",
		"(deny process-fork)",
		`(allow process-exec (literal "/private/tmp/labctl"))`,
		`(allow process-exec (literal "/private/tmp/tools/java"))`,
		`(allow process-exec (literal "/private/tmp/tools/jspawnhelper"))`,
	} {
		if !strings.Contains(profile, required) {
			t.Fatalf("profile omitted required rule %q:\n%s", required, profile)
		}
	}
	if strings.Contains(profile, `(deny file-read* (subpath "/private/tmp"))`) {
		t.Fatalf("profile used a parent deny that overrides its planned child-path allows:\n%s", profile)
	}
	for _, allowed := range []string{
		plan.SourceDirectory, plan.ToolDirectory, plan.WorkspaceDirectory,
		plan.CacheDirectory, plan.OutputDirectory,
	} {
		if !strings.Contains(profile, `(require-not (subpath "`+allowed+`"))`) {
			t.Fatalf("profile omitted the temporary read-data exclusion for %q:\n%s", allowed, profile)
		}
	}
	if !strings.Contains(profile, `(require-not (literal "/private/tmp/labctl"))`) {
		t.Fatalf("profile omitted the exact executor read-data exclusion:\n%s", profile)
	}
	if strings.Contains(profile, `(allow file-write* (subpath "`+plan.SourceDirectory+`"))`) ||
		strings.Contains(profile, `(allow file-write* (subpath "`+plan.ToolDirectory+`"))`) {
		t.Fatalf("profile made immutable inputs writable:\n%s", profile)
	}
	if !strings.Contains(profile, `(allow file-write* (subpath "`+plan.WorkspaceDirectory+`/build"))`) {
		t.Fatalf("profile did not isolate the writable build copy beneath the workspace:\n%s", profile)
	}
}

func TestDarwinSandboxProfileAllowsPlannedTempDataAndDeniesSiblingData(t *testing.T) {
	base, err := os.MkdirTemp("/private/tmp", "lab-profile-read-data-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	plan := validSandboxPlan(t, SandboxMavenAcquire)
	plan.SourceDirectory = filepath.Join(base, "source")
	plan.ToolDirectory = filepath.Join(base, "tools")
	plan.WorkspaceDirectory = filepath.Join(base, "workspace")
	plan.CacheDirectory = filepath.Join(base, "cache")
	plan.OutputDirectory = filepath.Join(base, "output")
	for _, directory := range []string{
		plan.SourceDirectory, plan.ToolDirectory, plan.WorkspaceDirectory,
		plan.CacheDirectory, plan.OutputDirectory,
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	allowed := filepath.Join(plan.WorkspaceDirectory, "allowed")
	denied := filepath.Join(base, "denied")
	for _, path := range []string{allowed, denied} {
		if err := os.WriteFile(path, []byte("sentinel"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	profile, err := darwinSandboxProfile(
		plan, "/bin/cat", "/private/tmp/tools/java",
		"/private/tmp/tools/jspawnhelper", "127.0.0.1:43117",
	)
	if err != nil {
		t.Fatal(err)
	}
	run := func(path string) error {
		command := exec.Command("/usr/bin/sandbox-exec", "-p", profile, "/bin/cat", path)
		command.Stdout = nil
		command.Stderr = nil
		return command.Run()
	}
	if err := run(allowed); err != nil {
		t.Fatalf("planned temporary data was unreadable: %v", err)
	}
	if err := run(denied); err == nil {
		t.Fatal("sibling temporary data was readable")
	}
}

func TestJavaNetworkCanaryCommandUsesPlannedWorkingDirectory(t *testing.T) {
	plan := validSandboxPlan(t, SandboxMavenAcquire)
	command := javaNetworkCanaryCommand(
		plan, "/private/tmp/profile.sb", "/private/tmp/tools/java",
		"/private/tmp/JavaNetworkCanary.java", "connect", "127.0.0.1", "43117",
	)
	if command.Dir != plan.WorkspaceDirectory {
		t.Fatalf("Java canary cwd = %q, want planned workspace %q", command.Dir, plan.WorkspaceDirectory)
	}
}

func TestDarwinOfflineProfileHasNoNetworkAllow(t *testing.T) {
	plan := validSandboxPlan(t, SandboxMavenBuild)
	profile, err := darwinSandboxProfile(plan, "/private/tmp/labctl", "/private/tmp/tools/java", "/private/tmp/tools/jspawnhelper", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(profile, "allow network") {
		t.Fatalf("offline profile unexpectedly allows network:\n%s", profile)
	}
	if strings.Contains(profile, `(allow file-write* (subpath "`+plan.CacheDirectory+`"))`) {
		t.Fatalf("offline profile unexpectedly permits cache mutation:\n%s", profile)
	}
}

func TestDarwinMavenTestProfileAllowsOnlyRequiredLocalSockets(t *testing.T) {
	plan := validSandboxPlan(t, SandboxMavenTest)
	profile, err := darwinSandboxProfile(plan, "/private/tmp/labctl", "/private/tmp/tools/java", "/private/tmp/tools/jspawnhelper", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"(deny network*)",
		"(allow network-bind (local ip))",
		"(allow network-inbound (local ip))",
		"(allow network-outbound (remote tcp \"localhost:*\"))",
		"(deny process*)",
		"(allow process-fork)",
		`(allow process-exec (literal "/bin/sh"))`,
		`(allow process-exec (literal "/bin/bash"))`,
	} {
		if !strings.Contains(profile, required) {
			t.Fatalf("test profile omitted %q:\n%s", required, profile)
		}
	}
	if strings.Contains(profile, "remote tcp \"*:*\"") {
		t.Fatalf("test profile widened beyond local bind and loopback connect:\n%s", profile)
	}
}

func TestDarwinResourceEnforcementCanaries(t *testing.T) {
	plan := validSandboxPlan(t, SandboxMavenTest)
	for _, directory := range []string{plan.SourceDirectory, plan.WorkspaceDirectory, filepath.Join(plan.WorkspaceDirectory, "home")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	canaries, err := runResourceCanaries(plan, self)
	if err != nil {
		t.Fatal(err)
	}
	if !canaries.WallTimeEnforced || !canaries.OutputLimitEnforced || !canaries.WorkspaceLimitEnforced ||
		!canaries.ProcessLimitEnforced || !canaries.CPULimitEnforced || !canaries.MemoryLimitEnforced || !canaries.OpenFileLimitEnforced {
		t.Fatalf("incomplete resource canaries: %+v", canaries)
	}
}

func TestParseOpenFileCountExcludesMappingsAndMetadata(t *testing.T) {
	output := []byte("p123\nf0\nf1\nf12\nfcwd\nftxt\nfmem\n")
	if count := parseOpenFileCount(output); count != 3 {
		t.Fatalf("numeric descriptor count = %d, want 3", count)
	}
}

func TestRunMonitoredRetainsBoundedNonZeroExit(t *testing.T) {
	plan := validSandboxPlan(t, SandboxMavenTest)
	for _, directory := range []string{plan.SourceDirectory, plan.WorkspaceDirectory, plan.OutputDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	result, err := runMonitored(plan, self, []string{"__sandbox-canary", "read", filepath.Join(plan.SourceDirectory, "absent")}, []string{"HOME=" + plan.WorkspaceDirectory, "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"})
	if err != nil {
		t.Fatal(err)
	}
	if result.exitCode != 73 {
		t.Fatalf("exit code = %d, want retained canary code 73", result.exitCode)
	}
}

func TestMavenSettingsBindOnlyTheExecutorLoopbackProxy(t *testing.T) {
	settings, err := mavenCentralSettings("127.0.0.1:43117")
	if err != nil {
		t.Fatal(err)
	}
	text := string(settings)
	for _, required := range []string{
		"<host>127.0.0.1</host><port>43117</port>",
		"<url>https://repo.maven.apache.org/maven2</url>",
		"<checksumPolicy>fail</checksumPolicy>",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("settings omitted %q: %s", required, text)
		}
	}
	for _, denied := range []string{"localhost:43117", "example.com", "<snapshots><enabled>true"} {
		if strings.Contains(text, denied) {
			t.Fatalf("settings contain forbidden value %q: %s", denied, text)
		}
	}
	if _, err := mavenCentralSettings("localhost:43117"); err == nil {
		t.Fatal("hostname proxy accepted instead of exact IPv4 loopback")
	}
	offline := string(mavenOfflineSettings())
	if strings.Contains(offline, "<proxies>") || !strings.Contains(offline, "<id>central-only</id>") {
		t.Fatalf("offline settings did not retain the frozen repository identity without a proxy: %s", offline)
	}
}
