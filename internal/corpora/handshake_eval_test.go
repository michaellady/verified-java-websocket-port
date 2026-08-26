package corpora

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// The handshake corpus is executable: request lines carry the raw bytes and
// config for an external target, and responses are evaluated fail-closed
// against the RFC-derived expectations.
func TestHandshakeRequestLineShape(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	line, err := HandshakeRequestLine(generated.Handshake[0])
	if err != nil {
		t.Fatalf("HandshakeRequestLine: %v", err)
	}
	var request map[string]any
	if err := json.Unmarshal(line, &request); err != nil {
		t.Fatalf("request line not JSON: %v", err)
	}
	for _, field := range []string{"case_id", "direction", "raw_base64", "config", "context"} {
		if _, present := request[field]; !present {
			t.Fatalf("handshake request lacks %s", field)
		}
	}
	if _, present := request["expected"]; present {
		t.Fatal("handshake request must not leak the expected verdict")
	}
}

func TestEvaluateHandshakeTranscript(t *testing.T) {
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	cases := generated.Handshake[:6]
	var transcript bytes.Buffer
	for _, c := range cases {
		response, err := synthesizeHandshakeResponse(c)
		if err != nil {
			t.Fatal(err)
		}
		transcript.Write(response)
		transcript.WriteByte('\n')
	}
	report, err := EvaluateHandshakeTranscript(cases, transcript.Bytes())
	if err != nil {
		t.Fatalf("EvaluateHandshakeTranscript: %v", err)
	}
	if report.Executed != 6 || report.Passed != 6 || !report.Reconciled() {
		t.Fatalf("report = %+v", report)
	}

	// A drifted verdict fails.
	drifted := strings.Replace(transcript.String(), `"verdict":"`, `"verdict":"x`, 1)
	report, err = EvaluateHandshakeTranscript(cases, []byte(drifted))
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed == 0 || report.Reconciled() {
		t.Fatalf("drifted verdict must fail: %+v", report)
	}

	// Missing responses block.
	lines := strings.SplitN(transcript.String(), "\n", 2)
	report, err = EvaluateHandshakeTranscript(cases, []byte(lines[1]))
	if err != nil {
		t.Fatal(err)
	}
	if report.Missing != 1 || report.Reconciled() {
		t.Fatalf("missing handshake response must block: %+v", report)
	}

	// Duplicates error.
	duplicated := transcript.String() + lines[0] + "\n"
	if _, err := EvaluateHandshakeTranscript(cases, []byte(duplicated)); err == nil {
		t.Fatal("duplicate handshake responses must error")
	}

	// An accepted client request must answer with the exact accept value.
	var acceptCase HandshakeCase
	for _, c := range generated.Handshake {
		if c.Direction == "client_request" && c.Expected.Verdict == "accept" {
			acceptCase = c
			break
		}
	}
	response, err := synthesizeHandshakeResponse(acceptCase)
	if err != nil {
		t.Fatal(err)
	}
	wrongAccept := bytes.Replace(response,
		[]byte(acceptCase.Expected.SecWebSocketAccept),
		[]byte("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), 1)
	if bytes.Equal(wrongAccept, response) {
		wrongAccept = bytes.Replace(response,
			[]byte(acceptCase.Expected.SecWebSocketAccept),
			[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAA="), 1)
	}
	if passed, _ := EvaluateHandshakeResponse(acceptCase, wrongAccept); passed {
		t.Fatal("wrong accept value must fail")
	}
}
