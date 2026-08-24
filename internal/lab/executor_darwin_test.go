//go:build darwin

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
		"(deny file-read* (subpath \"/private/tmp\"))",
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
	if strings.Contains(profile, `(allow file-write* (subpath "`+plan.SourceDirectory+`"))`) ||
		strings.Contains(profile, `(allow file-write* (subpath "`+plan.ToolDirectory+`"))`) {
		t.Fatalf("profile made immutable inputs writable:\n%s", profile)
	}
	if !strings.Contains(profile, `(allow file-write* (subpath "`+plan.WorkspaceDirectory+`/build"))`) {
		t.Fatalf("profile did not isolate the writable build copy beneath the workspace:\n%s", profile)
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
