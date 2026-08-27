package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestVerifyCanonicalUS012Receipt(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if exit := run([]string{"verify", "--root", root}, &stdout, &stderr); exit != 0 {
		t.Fatalf("exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	var verdict struct {
		Valid                bool   `json:"valid"`
		ClaimScope           string `json:"claim_scope"`
		AggregateFormalState string `json:"aggregate_formal_state"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &verdict); err != nil {
		t.Fatal(err)
	}
	if !verdict.Valid || verdict.ClaimScope != "BOUNDED_TEST_EVIDENCE" || verdict.AggregateFormalState != "BLOCKED" {
		t.Fatalf("verdict = %#v", verdict)
	}
}

func TestVerifyFailsClosedAndUsageIsDistinct(t *testing.T) {
	for _, test := range []struct {
		arguments []string
		exit      int
	}{
		{nil, 2},
		{[]string{"unknown"}, 2},
		{[]string{"verify", "--root", t.TempDir()}, 1},
	} {
		var stdout, stderr bytes.Buffer
		if actual := run(test.arguments, &stdout, &stderr); actual != test.exit {
			t.Fatalf("run(%v)=%d, want %d; stdout=%s stderr=%s", test.arguments, actual, test.exit, stdout.String(), stderr.String())
		}
	}
}
