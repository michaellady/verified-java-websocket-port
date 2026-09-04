package lab

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func validOracleRequest() OracleRequest {
	return OracleRequest{
		SchemaVersion: "1.0.0", ScenarioID: "scenario-0000000001", Role: OracleClient, InitialState: "open",
		ByteChunks:   []string{base64.StdEncoding.EncodeToString([]byte{0x81, 0x00})},
		LocalActions: []LocalAction{{Kind: ActionPing, PayloadBase64: base64.StdEncoding.EncodeToString([]byte("p"))}},
		Limits:       OracleLimits{MaxFrameBytes: 1024, MaxMessageBytes: 2048, MaxBufferedBytes: 4096, MaxEvents: 32},
	}
}

func validObservation(t *testing.T) OracleObservation {
	t.Helper()
	requestDigest, err := validOracleRequest().Digest()
	if err != nil {
		t.Fatal(err)
	}
	return OracleObservation{
		SchemaVersion: "1.0.0", ScenarioID: "scenario-0000000001", RequestDigest: requestDigest,
		ResponseDigest: intake.DigestBytes([]byte("exact-java-response")),
		FinalState:     "open", ConsumedBytes: 2, BufferedBytes: 0,
		Events: []OracleEvent{{Sequence: 0, Kind: "frame", State: "open", Opcode: "text", PayloadDigest: intake.DigestBytes([]byte{}), ConsumedBytes: 2}},
	}
}

func TestOracleStrictRequestAndDeterministicObservation(t *testing.T) {
	request := validOracleRequest()
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	first := validObservation(t)
	if err := CompareJavaObservations(first, first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Events = append([]OracleEvent(nil), first.Events...)
	second.Events[0].Opcode = "binary"
	assertFinding(t, CompareJavaObservations(first, second), "NONDETERMINISTIC_JAVA_OBSERVATION")
	second = first
	second.RequestDigest = intake.DigestBytes([]byte("other"))
	assertFinding(t, CompareJavaObservations(first, second), "JAVA_OBSERVATION_SCOPE_MISMATCH")
	second = first
	second.ResponseDigest = intake.DigestBytes([]byte("other response"))
	assertFinding(t, CompareJavaObservations(first, second), "NONDETERMINISTIC_JAVA_OBSERVATION")
}

func TestOracleDecoderRejectsAmbiguityAndUnboundedInput(t *testing.T) {
	_, err := DecodeOracleRequest([]byte(`{"schema_version":"1.0.0","schema_version":"1.0.0"}`))
	assertFinding(t, err, "DUPLICATE_JSON_FIELD")
	request := validOracleRequest()
	request.ByteChunks = []string{"not-base64"}
	if err := request.Validate(); err == nil {
		t.Fatal("invalid bytes accepted")
	}
	request = validOracleRequest()
	request.LocalActions[0].Kind = LocalActionKind("exec")
	if err := request.Validate(); err == nil {
		t.Fatal("arbitrary local action accepted")
	}
}

func TestOracleRequestTranslatesToCanonicalJavaContract(t *testing.T) {
	request := validOracleRequest()
	request.LocalActions = append(request.LocalActions,
		LocalAction{Kind: ActionSendText, PayloadBase64: base64.StdEncoding.EncodeToString([]byte("hello"))},
		LocalAction{Kind: ActionClose, PayloadBase64: base64.StdEncoding.EncodeToString([]byte("done")), CloseCode: 1000})
	encoded, err := EncodeJavaOracleRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	digest, ok := wire["request_digest"].(string)
	if !ok {
		t.Fatal("translated request has no request_digest")
	}
	delete(wire, "request_digest")
	unsigned, err := intake.CanonicalJSON(wire)
	if err != nil {
		t.Fatal(err)
	}
	if digest != intake.DigestBytes(unsigned) {
		t.Fatalf("request digest=%s canonical=%s", digest, intake.DigestBytes(unsigned))
	}
	if digestFromAPI, err := request.Digest(); err != nil || digestFromAPI != digest {
		t.Fatalf("Digest()=%s err=%v wire=%s", digestFromAPI, err, digest)
	}
	steps, ok := wire["steps"].([]any)
	if !ok || len(steps) != 4 {
		t.Fatalf("translated steps=%#v", wire["steps"])
	}
	text := steps[2].(map[string]any)
	if text["action"] != "send_text" || text["text"] != "hello" {
		t.Fatalf("translated text action=%#v", text)
	}
	closeAction := steps[3].(map[string]any)
	if closeAction["action"] != "send_close" || closeAction["reason"] != "done" || closeAction["code"] != float64(1000) {
		t.Fatalf("translated close action=%#v", closeAction)
	}

	changed := request
	changed.LocalActions = append([]LocalAction(nil), request.LocalActions...)
	changed.LocalActions[0].PayloadBase64 = base64.StdEncoding.EncodeToString([]byte("q"))
	changedDigest, err := changed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == digest {
		t.Fatal("canonical Java request digest ignored an executable input change")
	}
}

func TestOracleJavaResponseDecoderRejectsContractExpansion(t *testing.T) {
	data := []byte(`{"protocol":"java-websocket-oracle","version":"1.0.0","extra":true}`)
	var response javaOracleResponse
	assertFinding(t, intake.DecodeStrict(data, &response), "UNKNOWN_JSON_FIELD")
}
