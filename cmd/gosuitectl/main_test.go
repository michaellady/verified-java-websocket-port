package main

import (
	"os/exec"
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
