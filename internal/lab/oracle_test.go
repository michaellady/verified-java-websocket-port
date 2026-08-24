package lab

import (
	"encoding/base64"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func validOracleRequest() OracleRequest {
	return OracleRequest{
		SchemaVersion: "1.0.0", ScenarioID: "scenario-0000000001", Role: OracleServer, InitialState: "open",
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
		FinalState: "open", ConsumedBytes: 2, BufferedBytes: 0,
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
