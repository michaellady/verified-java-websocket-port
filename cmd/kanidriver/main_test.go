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

func TestRunRejectsUnknownAndIncompleteCommands(t *testing.T) {
	for _, arguments := range [][]string{nil, {"unknown"}, {"run"}, {"verify"}} {
		var stdout, stderr bytes.Buffer
		if exit := run(arguments, &stdout, &stderr); exit != 2 {
			t.Fatalf("run(%v)=%d stdout=%s stderr=%s", arguments, exit, stdout.String(), stderr.String())
		}
	}
}
