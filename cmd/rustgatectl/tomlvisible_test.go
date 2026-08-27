package main

import "testing"

// Review 01a0446e RED cases: text inside a multiline TOML string must never
// satisfy a key check, in either [package] or [workspace.package].
func TestMultilineStringBodiesNeverSatisfyKeyChecks(t *testing.T) {
	memberDecoy := "[package]\n" +
		"name = \"decoy\"\n" +
		"description = \"\"\"\n" +
		"rust-version.workspace = true\n" +
		"license.workspace = true\n" +
		"\"\"\"\n"
	if memberInheritsWorkspaceKey(memberDecoy, "rust-version", "1.95.0") {
		t.Fatal("rust-version inside a multiline string body satisfied the member check")
	}
	if memberInheritsWorkspaceKey(memberDecoy, "license", "Apache-2.0") {
		t.Fatal("license inside a multiline string body satisfied the member check")
	}

	literalDecoy := "[workspace.package]\n" +
		"description = '''\n" +
		"rust-version = \"1.95.0\"\n" +
		"'''\n"
	if _, err := parseWorkspacePackageKey(literalDecoy, "rust-version"); err == nil {
		t.Fatal("rust-version inside a literal multiline string satisfied the workspace parse")
	}

	// Legitimate keys after a closed multiline string still count.
	legit := "[package]\n" +
		"description = \"\"\"two\nlines\"\"\"\n" +
		"rust-version.workspace = true\n"
	if !memberInheritsWorkspaceKey(legit, "rust-version", "1.95.0") {
		t.Fatal("a real key after a closed multiline string must still satisfy the check")
	}
}

// Review 01a0446e: the no-ProcessState sentinel must never render as an exit
// code and must never satisfy the bad-canary nonzero expectation.
func TestNoProcessStateNeverCountsAsDetection(t *testing.T) {
	if got := exitDescription(exitNoProcessState); got != "never produced a process state (command did not run)" {
		t.Fatalf("sentinel rendered as %q", got)
	}
	if got := exitDescription(7); got != "exited 7" {
		t.Fatalf("real exit rendered as %q", got)
	}
	good := canaryResult{name: "good", scanExit: 0, clippyExit: 0, testExit: 0}
	bad := canaryResult{name: "bad", scanExit: exitNoProcessState, clippyExit: exitNoProcessState}
	violations := evaluateCanaryPolarity(good, bad)
	if len(violations) == 0 {
		t.Fatal("no-ProcessState canary steps must be violations, not detections")
	}
}
