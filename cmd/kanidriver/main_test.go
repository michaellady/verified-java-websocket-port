package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestEvidenceSchemaCompilesAndIsClosed(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, "schemas", "kani-production-evidence-1.0.0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource("schema", value); err != nil {
		t.Fatal(err)
	}
	if _, err := compiler.Compile("schema"); err != nil {
		t.Fatal(err)
	}
}

func TestPlansCoverCloseCodeAndUTF8ProductionSymbols(t *testing.T) {
	plans := map[string]harnessPlan{}
	for _, plan := range harnessPlans() {
		for _, obligation := range plan.ObligationIDs {
			plans[obligation] = plan
		}
	}
	for obligation, expected := range map[string]struct {
		target string
		path   string
	}{
		"surface.close.status-code": {
			target: "websocket_core::close::validate_code",
			path:   "rust/connection-core/src/close.rs",
		},
		"surface.messages.text-utf8": {
			target: "websocket_core::utf8::Utf8Validator::feed+finish",
			path:   "rust/connection-core/src/utf8.rs",
		},
	} {
		plan, ok := plans[obligation]
		if !ok {
			t.Errorf("missing production proof plan for %s", obligation)
			continue
		}
		if plan.TargetSymbol != expected.target || plan.SourcePath != expected.path {
			t.Errorf("%s plan = %#v", obligation, plan)
		}
	}

	mutations := map[string]mutationPlan{}
	for _, plan := range mutationPlans() {
		for _, obligation := range plan.Obligations {
			mutations[obligation] = plan
		}
	}
	for _, obligation := range []string{
		"surface.close.status-code",
		"surface.messages.text-utf8",
	} {
		if _, ok := mutations[obligation]; !ok {
			t.Errorf("missing exact source mutation for %s", obligation)
		}
	}
}

func TestVerifyRetainedKaniEvidenceAndRejectInflation(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	relative := "evidence/formal/kani-0cf36a9/summary.json"
	value, err := verify(root, relative)
	if err != nil {
		t.Fatal(err)
	}
	if value.Status != "PASS" || value.Execution.RepeatCount != 2 ||
		len(value.Execution.Harnesses) != 11 || len(value.Execution.MutationCanaries) != 11 ||
		value.Execution.MutationSurvivors != 0 || !value.Execution.SemanticallyIdentical {
		t.Fatalf("retained evidence posture drifted: %#v", value)
	}

	value.Execution.MutationSurvivors = 1
	summaryDirectory := filepath.Join(root, "evidence", "formal", "kani-0cf36a9")
	if err := validateReceipt(root, summaryDirectory, value); err == nil {
		t.Fatal("inflated survivor count was accepted")
	}
}

func TestParseKaniResult(t *testing.T) {
	for _, test := range []struct {
		name        string
		output      string
		exitCode    int
		status      string
		failed      int
		total       int
		unreachable int
	}{
		{
			name:     "success",
			output:   "VERIFICATION RESULT:\n ** 0 of 487 failed (6 unreachable)\n\nVERIFICATION:- SUCCESSFUL\n",
			exitCode: 0, status: "PASS", failed: 0, total: 487, unreachable: 6,
		},
		{
			name:     "success_without_unreachable_suffix",
			output:   "VERIFICATION RESULT:\n ** 0 of 398 failed\n\nVERIFICATION:- SUCCESSFUL\n",
			exitCode: 0, status: "PASS", failed: 0, total: 398, unreachable: 0,
		},
		{
			name:     "counterexample",
			output:   "VERIFICATION RESULT:\n ** 1 of 127 failed (1 unreachable)\nFailed Checks: assertion failed\n\nVERIFICATION:- FAILED\n",
			exitCode: 1, status: "COUNTEREXAMPLE", failed: 1, total: 127, unreachable: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed, err := parseKaniResult([]byte(test.output), test.exitCode)
			if err != nil {
				t.Fatal(err)
			}
			if observed.Status != test.status || observed.FailedChecks != test.failed ||
				observed.TotalChecks != test.total || observed.UnreachableChecks != test.unreachable {
				t.Fatalf("result = %#v", observed)
			}
		})
	}
}

func TestParseKaniResultFailsClosed(t *testing.T) {
	for _, output := range []string{
		"VERIFICATION:- SUCCESSFUL\n",
		" ** 0 of 2 failed (0 unreachable)\nVERIFICATION:- FAILED\n",
		" ** 1 of 2 failed (0 unreachable)\nVERIFICATION:- SUCCESSFUL\n",
	} {
		if _, err := parseKaniResult([]byte(output), 0); err == nil {
			t.Fatalf("accepted malformed output %q", output)
		}
	}
}

func TestNormalizeLogRemovesOnlyDeclaredVolatility(t *testing.T) {
	raw := "/private/tmp/run/rust/connection-core/src/frame/mask.rs\nVerification Time: 1.234s\n    Finished `dev` profile [unoptimized] target(s) in 0.31s\nVERIFICATION:- SUCCESSFUL\n"
	actual := normalizeLog([]byte(raw), "/private/tmp/run")
	if strings.Contains(actual, "/private/tmp/run") || strings.Contains(actual, "1.234") || strings.Contains(actual, "0.31") {
		t.Fatalf("volatile data survived: %q", actual)
	}
	for _, wanted := range []string{"<staged-workspace>/rust/connection-core/src/frame/mask.rs", "Verification Time: <elapsed>", "target(s) in <elapsed>", "VERIFICATION:- SUCCESSFUL"} {
		if !strings.Contains(actual, wanted) {
			t.Fatalf("normalized output lacks %q: %q", wanted, actual)
		}
	}
}

func TestApplyExactMutationRequiresOneSite(t *testing.T) {
	updated, err := applyExactMutation([]byte("before needle after"), "needle", "replacement")
	if err != nil || string(updated) != "before replacement after" {
		t.Fatalf("updated=%q err=%v", updated, err)
	}
	for _, source := range []string{"absent", "needle needle"} {
		if _, err := applyExactMutation([]byte(source), "needle", "replacement"); err == nil {
			t.Fatalf("accepted source %q", source)
		}
	}
}

func TestControlledEnvironmentDoesNotShadowRustupCargo(t *testing.T) {
	environment := controlledEnvironment(generateRequest{
		CargoKani: "/pinned/kani/scripts/cargo-kani",
		CBMC:      "/pinned/cbmc/bin/cbmc",
		Rustc:     "/pinned/nightly/bin/rustc",
	})
	for _, entry := range environment {
		if strings.HasPrefix(entry, "PATH=") && strings.Contains(entry, "/pinned/nightly/bin") {
			t.Fatalf("nightly bin directory would shadow rustup-aware cargo: %s", entry)
		}
	}
	for _, wanted := range []string{"KANI_OUTPUT_FORMAT=terse", "CARGO_KANI_JOBS=1"} {
		found := false
		for _, entry := range environment {
			found = found || entry == wanted
		}
		if !found {
			t.Errorf("declared controlled variable is not enacted: %s", wanted)
		}
	}
}

func TestRunRejectsUnknownAndIncompleteCommands(t *testing.T) {
	for _, arguments := range [][]string{nil, {"unknown"}, {"run"}, {"verify"}, {"project-coverage"}, {"verify-coverage"}} {
		var stdout, stderr bytes.Buffer
		if exit := run(arguments, &stdout, &stderr); exit != 2 {
			t.Fatalf("run(%v)=%d stdout=%s stderr=%s", arguments, exit, stdout.String(), stderr.String())
		}
	}
}
