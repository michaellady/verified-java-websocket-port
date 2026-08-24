package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

func TestUsageRejectsUnknownAndPositionalCommands(t *testing.T) {
	for _, arguments := range [][]string{{}, {"unknown"}, {"compare-observations", "extra"}} {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != 2 {
			t.Fatalf("run(%q)=%d, want usage error", arguments, code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("usage error wrote protocol output: %q", stdout.String())
		}
	}
}

func TestMavenProxyListenAddressIsExplicitLoopback(t *testing.T) {
	for _, address := range []string{"", "localhost:18080", "0.0.0.0:18080", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1"} {
		if err := validateProxyListen(address); err == nil {
			t.Fatalf("validateProxyListen(%q) succeeded", address)
		}
	}
	if err := validateProxyListen("127.0.0.1:18080"); err != nil {
		t.Fatalf("explicit loopback denied: %v", err)
	}
}

func TestCompareObservationsAcceptsIdenticalAndDeniesDrift(t *testing.T) {
	observation := validObservation()
	first := writeJSONFile(t, "first.json", observation)
	second := writeJSONFile(t, "second.json", observation)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"compare-observations", "--first", first, "--second", second}, &stdout, &stderr); code != 0 {
		t.Fatalf("identical observations denied: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status": "READY"`) {
		t.Fatalf("missing ready result: %s", stdout.String())
	}

	drifted := observation
	drifted.FinalState = "closed"
	second = writeJSONFile(t, "drifted.json", drifted)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"compare-observations", "--first", first, "--second", second}, &stdout, &stderr); code != 1 {
		t.Fatalf("drifted observations returned code %d", code)
	}
	if !strings.Contains(stdout.String(), "NONDETERMINISTIC_JAVA_OBSERVATION") {
		t.Fatalf("drift finding absent: %s", stdout.String())
	}
}

func TestInputLinksAreDenied(t *testing.T) {
	observation := validObservation()
	target := writeJSONFile(t, "target.json", observation)
	link := filepath.Join(t.TempDir(), "observation-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"compare-observations", "--first", link, "--second", target}, &stdout, &stderr); code != 1 {
		t.Fatalf("linked observation returned code %d", code)
	}
	if !strings.Contains(stdout.String(), "UNSAFE_FILE") {
		t.Fatalf("unsafe-file finding absent: %s", stdout.String())
	}
}

func TestAutobahnSelectionAndExactResults(t *testing.T) {
	caseIDs := []string{"1.1.1", "2.1", "3.1", "4.1.1", "5.1", "6.1.1", "7.1.1", "9.1.1", "10.1.1", "12.1.1", "13.1.1"}
	var source strings.Builder
	for _, id := range caseIDs {
		source.WriteString("Case")
		source.WriteString(strings.ReplaceAll(id, ".", "_"))
		source.WriteByte('\n')
	}
	sourceBytes := []byte(source.String())
	registryPath := writeJSONFile(t, "registry-bundle.json", autobahnRegistryBundle{
		SchemaVersion: "1.0.0",
		SourceDigest:  intake.DigestBytes(sourceBytes),
		SourceBase64:  base64.StdEncoding.EncodeToString(sourceBytes),
		Expansions:    []autobahnExpansionSource{},
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"select-autobahn", "--registry-bundle", registryPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("registry selection denied: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var response struct {
		Result struct {
			Selection lab.AutobahnSelection `json:"selection"`
		} `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	selectionPath := writeJSONFile(t, "selection.json", response.Result.Selection)
	results := make([]lab.AutobahnResult, 0, len(response.Result.Selection.SelectedCaseIDs))
	for _, id := range response.Result.Selection.SelectedCaseIDs {
		results = append(results, lab.AutobahnResult{CaseID: id, Status: "OK"})
	}
	resultsPath := writeJSONFile(t, "results.json", autobahnResults{SchemaVersion: "1.0.0", Results: results})
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"verify-autobahn", "--registry-bundle", registryPath, "--selection", selectionPath, "--mode", "client", "--results", resultsPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("exact results denied: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	results = results[:len(results)-1]
	resultsPath = writeJSONFile(t, "missing-results.json", autobahnResults{SchemaVersion: "1.0.0", Results: results})
	stdout.Reset()
	if code := run([]string{"verify-autobahn", "--registry-bundle", registryPath, "--selection", selectionPath, "--mode", "client", "--results", resultsPath}, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "AUTOBAHN_RESULT_MISMATCH") {
		t.Fatalf("missing result was not denied: code=%d stdout=%s", code, stdout.String())
	}
}

func validObservation() lab.OracleObservation {
	return lab.OracleObservation{
		SchemaVersion: "1.0.0", ScenarioID: "scenario-1", RequestDigest: intake.DigestBytes([]byte("request")),
		FinalState: "open", ConsumedBytes: 0, BufferedBytes: 0, Events: []lab.OracleEvent{},
	}
}

func writeJSONFile(t *testing.T, name string, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
