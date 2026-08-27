// Unit tests for the US-018 cross-peer exam runner's pure decision logic:
// listening-line parsing, ws-testee summary parsing, digest verification,
// and per-exam assertion evaluation. The live exams (real pinned
// Java-WebSocket 1.6.0 against the Rust ws-testee over loopback TCP) run
// through main and are receipt-recorded, not unit-mocked.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestParseListeningAddress(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
		ok   bool
	}{
		{"rust-full-address", "listening 127.0.0.1:52123", "127.0.0.1:52123", true},
		{"java-port-only", "listening 52123", "127.0.0.1:52123", true},
		{"not-a-listening-line", "outcome=Terminal", "", false},
		{"empty", "", "", false},
		{"garbage-port", "listening zzz", "", false},
	}
	for _, tc := range cases {
		got, ok := parseListeningAddress(tc.line)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: parseListeningAddress(%q) = (%q, %v), want (%q, %v)",
				tc.name, tc.line, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFindListeningAddressScansAllLines(t *testing.T) {
	stdout := "some banner\nlistening 127.0.0.1:9001\nouctome=..."
	got, ok := findListeningAddress(stdout)
	if !ok || got != "127.0.0.1:9001" {
		t.Fatalf("findListeningAddress = (%q, %v)", got, ok)
	}
	if _, ok := findListeningAddress("no such line\n"); ok {
		t.Fatalf("absent listening line must not parse")
	}
}

func TestSummaryFieldsParsesTesteeSummary(t *testing.T) {
	summary := "outcome=Terminal texts=1 binaries=0 pings=0 pongs=1 close=1000:remote terminals=1"
	fields := summaryFields(summary)
	for key, want := range map[string]string{
		"outcome":   "Terminal",
		"texts":     "1",
		"pongs":     "1",
		"close":     "1000:remote",
		"terminals": "1",
	} {
		if fields[key] != want {
			t.Errorf("summaryFields[%q] = %q, want %q", key, fields[key], want)
		}
	}
}

func TestSummaryLineFindsTheSummaryAmongOutput(t *testing.T) {
	stdout := "listening 127.0.0.1:9001\noutcome=Terminal texts=1 binaries=0 pings=1 pongs=0 close=1000:remote terminals=1\n"
	summary, ok := summaryLine(stdout)
	if !ok || summaryFields(summary)["pings"] != "1" {
		t.Fatalf("summaryLine = (%q, %v)", summary, ok)
	}
	if _, ok := summaryLine("no summary here\n"); ok {
		t.Fatalf("absent summary must not parse")
	}
}

func TestVerifyFileDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	content := []byte("pinned bytes")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	good := "sha256:" + hex.EncodeToString(sum[:])
	if err := verifyFileDigest(path, good); err != nil {
		t.Fatalf("matching digest must verify: %v", err)
	}
	bad := "sha256:" + hex.EncodeToString(make([]byte, 32))
	if err := verifyFileDigest(path, bad); err == nil {
		t.Fatalf("mismatched digest must fail closed")
	}
	if err := verifyFileDigest(filepath.Join(dir, "absent"), good); err == nil {
		t.Fatalf("missing file must fail closed")
	}
}

// --- assertion evaluation ---------------------------------------------------

func TestEvaluateExpectationsPolarity(t *testing.T) {
	record := stepRecord{
		Role: "rust-server",
		Exit: 0,
		Stdout: "listening 127.0.0.1:9001\n" +
			"outcome=Terminal texts=1 binaries=0 pings=1 pongs=0 close=1000:remote terminals=1\n",
	}
	pass := expectation{Role: "rust-server", Exit: 0, SummaryFields: map[string]string{"texts": "1", "pings": "1"}, StdoutContains: []string{"listening "}}
	if failures := evaluateExpectation(pass, record); len(failures) != 0 {
		t.Fatalf("conforming record must pass, got %v", failures)
	}
	wrongExit := expectation{Role: "rust-server", Exit: 43}
	if failures := evaluateExpectation(wrongExit, record); len(failures) == 0 {
		t.Fatalf("wrong exit must fail")
	}
	wrongField := expectation{Role: "rust-server", Exit: 0, SummaryFields: map[string]string{"pongs": "1"}}
	if failures := evaluateExpectation(wrongField, record); len(failures) == 0 {
		t.Fatalf("wrong summary field must fail")
	}
	missingLine := expectation{Role: "rust-server", Exit: 0, StdoutContains: []string{"event=pong"}}
	if failures := evaluateExpectation(missingLine, record); len(failures) == 0 {
		t.Fatalf("missing stdout line must fail")
	}
	noSummary := expectation{Role: "java-client", Exit: 0, SummaryFields: map[string]string{"texts": "1"}}
	if failures := evaluateExpectation(noSummary, stepRecord{Role: "java-client", Exit: 0, Stdout: "event=open\n"}); len(failures) == 0 {
		t.Fatalf("summary expectation without a summary line must fail")
	}
}
