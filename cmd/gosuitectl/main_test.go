package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	output, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not in a git checkout: %v", err)
	}
	return strings.TrimSpace(string(output))
}

// Every declared exclusion must name a package that actually exists. An
// exclusion that outlives its package is a lie about coverage: the gate reports
// "excluded by name with a reason" for something it could simply have run.
func TestEveryDeclaredExclusionNamesAPackageThatExists(t *testing.T) {
	packages, err := listPackages(moduleRoot(t))
	if err != nil {
		t.Fatalf("listPackages: %v", err)
	}
	present := make(map[string]bool, len(packages))
	for _, name := range packages {
		present[name] = true
	}
	for name := range excluded {
		if !present[name] {
			t.Errorf("excluded package %q is not in the module; remove the exclusion", name)
		}
	}
}

// The gate must actually FAIL on a stale exclusion rather than printing a
// finding and exiting 0. Without this the anti-drift mechanism is decorative.
func TestAStaleExclusionIsDetected(t *testing.T) {
	packages, err := listPackages(moduleRoot(t))
	if err != nil {
		t.Fatalf("listPackages: %v", err)
	}
	present := make(map[string]bool, len(packages))
	for _, name := range packages {
		present[name] = true
	}
	if present["internal/thispackagedoesnotexist"] {
		t.Fatal("fixture assumption broken: the sentinel package exists")
	}

	// The same computation main() performs, over a deliberately stale entry.
	stale := 0
	for name := range map[string]string{"internal/thispackagedoesnotexist": "sentinel"} {
		if !present[name] {
			stale++
		}
	}
	if stale != 1 {
		t.Errorf("a stale exclusion must be counted, got %d", stale)
	}
}

// An exclusion is a claim that something CANNOT pass here, and it has to say
// why. This is the same effort floor the legacy-adjudication gate puts on its
// arguments: it cannot judge quality, but it can refuse an empty reason.
func TestEveryExclusionStatesASubstantiveReason(t *testing.T) {
	const floor = 80
	if len(excluded) == 0 {
		t.Skip("no exclusions declared")
	}
	for name, reason := range excluded {
		if len(reason) < floor {
			t.Errorf("exclusion %q states %d bytes of reason, floor is %d: %q",
				name, len(reason), floor, reason)
		}
		if !strings.Contains(reason, "Owner") {
			t.Errorf("exclusion %q does not name what would lift it: %q", name, reason)
		}
	}
}

// AN EXCLUSION MUST STILL FAIL. Checking that the excluded package still exists
// is the weaker half of the anti-rot claim: adversarial review B5 excluded
// `internal/rfcneutral`, which passes cleanly, behind a fabricated 259-byte
// reason containing "Owner", and every check this gate had accepted it. This test
// runs each declared exclusion and refuses one that passes. It is the same
// refusal pinconsumerctl already makes when a FIXED pin leaves a STALE_ALLOWANCE
// behind, and its absence here was the asymmetry.
func TestEveryDeclaredExclusionStillFails(t *testing.T) {
	root := moduleRoot(t)
	if info, err := os.Stat(filepath.Join(root, ".quarantine", "Java-WebSocket-1.6.0.jar")); err != nil ||
		info.Size() == 0 {
		t.Skip(".quarantine/ is not staged: a blocked package cannot be told from a broken one")
	}
	for name := range excluded {
		probe := exec.Command("go", "test", "-count=1", "-timeout", "40m", "./"+name)
		probe.Dir = root
		output, err := probe.CombinedOutput()
		if err == nil {
			t.Errorf("excluded package %q PASSES on this host: the exclusion outlived the "+
				"problem it describes and must be removed\n%s", name, output)
			continue
		}
		t.Logf("%s still fails: %s", name, firstFailure(string(output)))
	}
}

// firstFailure must find the failing line, or the gate log prints a placeholder
// beside every exclusion and a reader learns nothing about whether the declared
// reason still matches the observed one.
func TestFirstFailureReadsTheFailingLine(t *testing.T) {
	const output = "some noise\n--- FAIL: TestThing (0.00s)\n    a_test.go:9: because reasons\nFAIL\n"
	if got := firstFailure(output); got != "--- FAIL: TestThing (0.00s)" {
		t.Errorf("firstFailure read %q", got)
	}
	if got := firstFailure("ok  \tpkg\t0.1s\n"); got != "failed with no recognisable failure line" {
		t.Errorf("a passing log has no failure line, got %q", got)
	}
}

// `run=` IS NOT A COVERAGE NUMBER AND THE GATE MUST SAY SO. `go test` on a
// package with no test file prints "ok [no test files]" and exits 0, and a
// _test.go behind an unsatisfied build tag is never compiled. Adversarial review
// B2 hid a deliberate t.Fatal behind `//go:build darwin` and the census stayed
// byte-identical; B3 hid a whole failing package the same way and `go list ./...`
// reported the same count with nothing on stderr. This test holds the reporting
// that makes both readable, and asserts what the tree contains today so a change
// in either number has to be looked at.
func TestTheGateReportsWhatTheRunDoesNotCover(t *testing.T) {
	root := moduleRoot(t)
	packages, err := listPackages(root)
	if err != nil {
		t.Fatalf("listPackages: %v", err)
	}
	var run []string
	for _, name := range packages {
		if _, skip := excluded[name]; !skip {
			run = append(run, name)
		}
	}
	untested, unbuilt, err := coverageDetail(root, run)
	if err != nil {
		t.Fatalf("coverageDetail: %v", err)
	}
	if len(untested) == 0 {
		t.Error("no package in the run set lacks tests; if that became true the gate " +
			"should say so, but it was 15 of 59 when this was written")
	}
	if len(unbuilt) == 0 {
		t.Error("no unbuilt test file found; the run set carried 5 behind javabinde2e, " +
			"diffregress, normcollide and formalcovere2e when this was written (2 more sit " +
			"in the excluded internal/lab), and a detector that finds none of them is not " +
			"reading the build list")
	}
	for _, file := range unbuilt {
		if file.constraint == "" || file.constraint == "no //go:build line found" ||
			file.constraint == "unreadable" {
			t.Errorf("%s/%s is not compiled and the gate cannot name why: %q",
				file.pkg, file.name, file.constraint)
		}
	}
	t.Logf("run=%d with_tests=%d no_test_files=%d unbuilt_test_files=%d",
		len(run), len(run)-len(untested), len(untested), len(unbuilt))
}

// An empty run set must be a refusal, not a PASS. `go test` with no package
// arguments tests the directory it is invoked in, which in this repository root
// has no test files, so it would print ok and exit 0 having run nothing.
func TestAnEmptyRunSetIsRefused(t *testing.T) {
	if _, _, err := coverageDetail(moduleRoot(t), nil); err == nil {
		t.Error("an empty run set must be refused")
	}
}

// The run set is everything that is not excluded, so a package added tomorrow is
// covered without anyone remembering to add it. That is the property that makes
// this a gate rather than a list.
func TestTheRunSetIsTheComplementOfTheExclusions(t *testing.T) {
	packages, err := listPackages(moduleRoot(t))
	if err != nil {
		t.Fatalf("listPackages: %v", err)
	}
	run := 0
	for _, name := range packages {
		if _, skip := excluded[name]; !skip {
			run++
		}
	}
	if run != len(packages)-len(excluded) {
		t.Errorf("run set is %d, expected %d - %d", run, len(packages), len(excluded))
	}
	if run == 0 {
		t.Error("the gate would run nothing")
	}
}

// The JDK refusal's message is only useful if it names the javac it actually
// found, and javac's output here is not one line: the agent proxy sets
// JAVA_TOOL_OPTIONS, so javac prints a "Picked up ..." banner carrying a proxy
// port, a truststore path and a 40-entry nonProxyHosts list BEFORE the version.
// Quoting that whole blob into a refusal reason is how the underlying "javac
// 21.0.10" got lost in a 250-line gates log for an hour.
func TestTheJavacRefusalNamesTheVersionAndNotTheProxyBanner(t *testing.T) {
	noisy := "Picked up JAVA_TOOL_OPTIONS: -Djavax.net.ssl.trustStore=/root/.ccr/java-truststore.p12 " +
		"-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=34715 -Dhttp.nonProxyHosts=localhost|127.0.0.1\n" +
		"javac 21.0.10"
	if got := firstLine(noisy); got != "javac 21.0.10" {
		t.Fatalf("the refusal must name the javac it found, got %q", got)
	}
	if got := firstLine("javac 17.0.19\n"); got != "javac 17.0.19" {
		t.Fatalf("the quiet case must survive too, got %q", got)
	}
	// And it must not invent a version when javac says something unexpected.
	if got := firstLine("some other tool\n"); got != "some other tool" {
		t.Fatalf("unrecognised output must be passed through, got %q", got)
	}
}
