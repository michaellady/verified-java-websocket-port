package corpora

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// The projection to the java-oracle JSONL protocol must carry exactly the
// oracle's request fields and a request digest computed over the identical
// canonical form the oracle recomputes.
func TestOracleRequestShapeAndDigest(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	sc := generated.Public[0]
	request, err := OracleRequest(sc)
	if err != nil {
		t.Fatalf("OracleRequest: %v", err)
	}
	wantFields := []string{"initial_state", "limits", "protocol", "request_digest",
		"request_id", "role", "steps", "version"}
	if len(request) != len(wantFields) {
		t.Fatalf("request fields = %v", request)
	}
	for _, field := range wantFields {
		if _, present := request[field]; !present {
			t.Fatalf("request lacks %s", field)
		}
	}
	if request["protocol"] != "java-websocket-oracle" || request["version"] != "1.0.0" {
		t.Fatalf("protocol pin = %v/%v", request["protocol"], request["version"])
	}
	if request["request_id"] != sc.ScenarioID {
		t.Fatalf("request_id = %v", request["request_id"])
	}
	unsigned := map[string]any{}
	for k, v := range request {
		if k != "request_digest" {
			unsigned[k] = v
		}
	}
	canonical, err := CanonicalJSON(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if request["request_digest"] != DigestSHA256(canonical) {
		t.Fatal("request_digest does not bind the canonical request")
	}
}

// A response matching the expectation passes; any semantic drift fails.
func TestEvaluateOracleResponse(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	var okScenario, errScenario Scenario
	for _, sc := range generated.Public {
		if sc.Expected.Outcome == "ok" && okScenario.ScenarioID == "" {
			okScenario = sc
		}
		if sc.Expected.Outcome == "error" && errScenario.ScenarioID == "" {
			errScenario = sc
		}
	}

	response, err := synthesizeResponse(okScenario)
	if err != nil {
		t.Fatalf("synthesizeResponse: %v", err)
	}
	verdict, detail := EvaluateOracleResponse(okScenario, response)
	if !verdict {
		t.Fatalf("faithful ok response must pass: %s", detail)
	}

	tampered := bytes.Replace(response, []byte(`"final_state":"`),
		[]byte(`"final_state":"x`), 1)
	if verdict, _ := EvaluateOracleResponse(okScenario, tampered); verdict {
		t.Fatal("drifted final_state must fail")
	}

	errResponse, err := synthesizeResponse(errScenario)
	if err != nil {
		t.Fatalf("synthesizeResponse error scenario: %v", err)
	}
	if verdict, detail := EvaluateOracleResponse(errScenario, errResponse); !verdict {
		t.Fatalf("faithful error response must pass: %s", detail)
	}
	wrongCode := bytes.Replace(errResponse,
		[]byte(errScenario.Expected.Error.Code), []byte("OTHER_CODE"), 1)
	if verdict, _ := EvaluateOracleResponse(errScenario, wrongCode); verdict {
		t.Fatal("wrong error code must fail")
	}
}

// Transcript evaluation is fail-closed: every scenario needs exactly one
// matching response; missing or duplicate responses block.
func TestEvaluateTranscriptFailClosed(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	scenarios := generated.Public[:5]
	var transcript bytes.Buffer
	for _, sc := range scenarios {
		response, err := synthesizeResponse(sc)
		if err != nil {
			t.Fatal(err)
		}
		transcript.Write(response)
		transcript.WriteByte('\n')
	}
	report, err := EvaluateTranscript(scenarios, transcript.Bytes())
	if err != nil {
		t.Fatalf("EvaluateTranscript: %v", err)
	}
	if report.Executed != 5 || report.Passed != 5 || report.Failed != 0 || report.Missing != 0 {
		t.Fatalf("report = %+v", report)
	}
	if !report.Reconciled() {
		t.Fatal("full faithful transcript must reconcile")
	}

	lines := strings.SplitN(transcript.String(), "\n", 2)
	partial := lines[1]
	report, err = EvaluateTranscript(scenarios, []byte(partial))
	if err != nil {
		t.Fatalf("EvaluateTranscript partial: %v", err)
	}
	if report.Missing != 1 || report.Reconciled() {
		t.Fatalf("missing response must block: %+v", report)
	}

	duplicated := transcript.String() + lines[0] + "\n"
	if _, err := EvaluateTranscript(scenarios, []byte(duplicated)); err == nil {
		t.Fatal("duplicate responses must error")
	}
}

// The synthesized response follows the oracle's success shape so the
// evaluator is exercised against realistic records.
func TestSynthesizedResponseShape(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatal(err)
	}
	var sc Scenario
	for _, candidate := range generated.Public {
		if candidate.Expected.Outcome == "ok" {
			sc = candidate
			break
		}
	}
	response, err := synthesizeResponse(sc)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(response, &parsed); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	for _, field := range []string{"outcome", "protocol", "request_digest", "request_id",
		"version", "close", "counts", "events", "final_state", "frames",
		"initial_state", "role", "runtime", "transitions"} {
		if _, present := parsed[field]; !present {
			t.Fatalf("synthesized response lacks %s", field)
		}
	}
}
