package corpora

import (
	"encoding/base64"
	"testing"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func defaultLimits() Limits {
	return Limits{
		MaxInputBytes:    65536,
		MaxBufferedBytes: 65536,
		MaxActions:       64,
		MaxFrames:        64,
		MaxOutputBytes:   4194304,
	}
}

func mustDerive(t *testing.T, sc ScenarioCore) Expected {
	t.Helper()
	expected, err := DeriveExpected(sc)
	if err != nil {
		t.Fatalf("DeriveExpected failed: %v", err)
	}
	return expected
}

func wantCounts(t *testing.T, expected Expected, want Counts) {
	t.Helper()
	if expected.Counts == nil {
		t.Fatalf("every outcome must carry counts (outcome=%s)", expected.Outcome)
	}
	if *expected.Counts != want {
		t.Fatalf("counts = %+v want %+v", *expected.Counts, want)
	}
}

// closePayloadBase64 is base64([0x03,0xe8]). The pinned CloseFrame ctor
// (setReason("")+setCode(1000)) stores this payload, and the wire-parsing
// setPayload override never replaces it (CloseFrame.java:245-270): every
// parsed inbound close frame records and echoes these two bytes.
const closePayloadBase64 = "A+g="

// Server receives one masked text frame: the RFC 6455 masked "Hello" example.
func TestDeriveServerMaskedTextMessage(t *testing.T) {
	wire := []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
	sc := ScenarioCore{
		Role:         "server",
		InitialState: "open",
		Limits:       defaultLimits(),
		Steps:        []Step{{Kind: "bytes", DataBase64: b64(wire)}},
	}
	expected := mustDerive(t, sc)
	if expected.Outcome != "ok" || expected.FinalState != "open" {
		t.Fatalf("outcome=%s final=%s", expected.Outcome, expected.FinalState)
	}
	if len(expected.Events) != 2 ||
		expected.Events[0]["type"] != "input_chunk" || expected.Events[0]["bytes"] != 11 ||
		expected.Events[1]["type"] != "text" || expected.Events[1]["text"] != "Hello" {
		t.Fatalf("events = %v", expected.Events)
	}
	frame := expected.Frames[0]
	if len(expected.Frames) != 1 || frame["masked"] != true || frame["opcode"] != "text" ||
		frame["payload_base64"] != b64([]byte("Hello")) || frame["wire_bytes"] != 11 {
		t.Fatalf("frames = %v", expected.Frames)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 11, Frames: 1, InputBytes: 11})
}

// Remote close with code+reason while open: the close event carries the
// parsed code, but the recorded frames carry the constructor payload
// [0x03,0xe8], and the echo therefore has wire_bytes 4 for a server.
func TestDeriveRemoteCloseWhileOpen(t *testing.T) {
	payload := append([]byte{0x03, 0xe8}, []byte("bye")...) // 1000 + "bye"
	mask := [4]byte{9, 8, 7, 6}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeClose, Payload: payload}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "ok" || expected.FinalState != "closing" {
		t.Fatalf("outcome=%s final=%s (%+v)", expected.Outcome, expected.FinalState, expected.Error)
	}
	if expected.Close["code"] != 1000 || expected.Close["reason"] != "bye" ||
		expected.Close["origin"] != "remote" || expected.Close["handshake_complete"] != true {
		t.Fatalf("close = %v", expected.Close)
	}
	if len(expected.Frames) != 2 {
		t.Fatalf("frames = %v", expected.Frames)
	}
	inbound, echo := expected.Frames[0], expected.Frames[1]
	if inbound["payload_base64"] != closePayloadBase64 || inbound["payload_bytes"] != 2 ||
		inbound["wire_bytes"] != 11 {
		t.Fatalf("inbound close record = %v", inbound)
	}
	if echo["payload_base64"] != closePayloadBase64 || echo["payload_bytes"] != 2 ||
		echo["wire_bytes"] != 4 || echo["masked"] != false {
		t.Fatalf("echo close record = %v", echo)
	}
	if len(expected.Events) != 3 || expected.Events[1]["type"] != "close" ||
		expected.Events[2]["type"] != "echo_close" {
		t.Fatalf("events = %v", expected.Events)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 11, Frames: 2, InputBytes: 11})
}

// An empty close payload normalizes to code 1000 (CloseFrame.setPayload).
func TestDeriveRemoteCloseEmptyPayloadIs1000(t *testing.T) {
	mask := [4]byte{1, 2, 3, 4}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeClose, Payload: nil}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "ok" || expected.Close["code"] != 1000 ||
		expected.Close["reason"] != "" {
		t.Fatalf("empty close = %+v close=%v", expected, expected.Close)
	}
	if len(expected.Frames) != 2 || expected.Frames[1]["wire_bytes"] != 4 {
		t.Fatalf("frames = %v", expected.Frames)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 6, Frames: 2, InputBytes: 6})
}

// A one-byte close payload is a VALID close with code 1002
// (CloseFrame.setPayload: remaining()==1 -> PROTOCOL_ERROR; isValid passes).
func TestDeriveOneByteClosePayloadIsValid1002(t *testing.T) {
	mask := [4]byte{5, 4, 3, 2}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeClose, Payload: []byte{0x03}}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "ok" || expected.Close["code"] != 1002 ||
		expected.Close["reason"] != "" || expected.FinalState != "closing" {
		t.Fatalf("one-byte close = %+v close=%v", expected, expected.Close)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 7, Frames: 2, InputBytes: 7})
}

// Close-code wire validity mirrors CloseFrame.isValid exactly:
// 1012-1014 valid; 1016-2999, <1000, 1004, 1005, 1006, 1015, >4999 invalid.
func TestDeriveCloseCodeValiditySets(t *testing.T) {
	buildClose := func(code int) ScenarioCore {
		payload := []byte{byte(code >> 8), byte(code)}
		mask := [4]byte{6, 6, 6, 6}
		wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeClose, Payload: payload}, &mask)
		return ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
			Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	}
	for _, code := range []int{1012, 1013, 1014, 3000, 4999} {
		expected := mustDerive(t, buildClose(code))
		if expected.Outcome != "ok" || expected.Close["code"] != code {
			t.Fatalf("code %d must be valid, got %+v", code, expected.Error)
		}
	}
	for _, code := range []int{999, 1004, 1005, 1006, 1015, 1016, 2000, 2999} {
		expected := mustDerive(t, buildClose(code))
		if expected.Outcome != "error" || expected.Error.Code != "JAVA_INVALID_DATA" ||
			*expected.Error.CloseCode != 1002 {
			t.Fatalf("code %d must be a 1002 rejection, got %+v", code, expected.Error)
		}
		// isValid throws after the full frame is read.
		wantCounts(t, expected, Counts{ConsumedBytes: 8, InputBytes: 8})
	}
}

// Close code 1007 with an empty reason is rejected with close code 1007
// (CloseFrame.isValid first check).
func TestDeriveClose1007EmptyReason(t *testing.T) {
	mask := [4]byte{2, 2, 2, 2}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeClose,
		Payload: []byte{0x03, 0xef}}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "error" || expected.Error.Code != "JAVA_INVALID_DATA" ||
		*expected.Error.CloseCode != 1007 {
		t.Fatalf("close 1007 empty reason = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 8, InputBytes: 8})
}

// An invalid-UTF-8 close reason drives CloseFrame.setPayload to a null
// reason, and isValid then fails with a NullPointerException, which the
// adapter reports as JAVA_RUNTIME_REJECTION without a close code.
func TestDeriveCloseInvalidUTF8ReasonIsRuntimeRejection(t *testing.T) {
	mask := [4]byte{7, 1, 7, 1}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeClose,
		Payload: []byte{0x03, 0xe8, 0xff, 0xfe}}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "error" || expected.Error.Code != "JAVA_RUNTIME_REJECTION" ||
		expected.Error.CloseCode != nil {
		t.Fatalf("invalid-utf8 close reason = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 10, InputBytes: 10})
}

// A text frame that is not valid UTF-8 fails 1007 at translate time with the
// whole frame consumed and nothing recorded.
func TestDeriveInvalidUTF8TextFails1007(t *testing.T) {
	mask := [4]byte{1, 2, 3, 4}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText,
		Payload: []byte{0xff, 0xfe}}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "error" || *expected.Error.CloseCode != 1007 ||
		expected.FinalState != "open" {
		t.Fatalf("invalid utf8 = %+v", expected)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 8, InputBytes: 8})
}

// Header-site rejections consume exactly the bytes the runtime read before
// throwing: 2 for unknown opcodes and oversized controls (7-bit or extended
// marker), 4 when a 16-bit length exceeds the frame limit.
func TestDeriveHeaderSiteErrorConsumption(t *testing.T) {
	mask := [4]byte{0, 0, 0, 1}
	badOpcode := EncodeFrame(WireFrame{Fin: true, Opcode: Opcode(0x3), Payload: []byte{1}}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(badOpcode)}}}
	expected := mustDerive(t, sc)
	if expected.Error.Code != "JAVA_INVALID_DATA" || *expected.Error.CloseCode != 1002 {
		t.Fatalf("bad opcode = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 2, InputBytes: len(badOpcode)})

	oversizePing := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodePing,
		Payload: make([]byte, 126)}, &mask)
	sc.Steps = []Step{{Kind: "bytes", DataBase64: b64(oversizePing)}}
	expected = mustDerive(t, sc)
	if *expected.Error.CloseCode != 1002 {
		t.Fatalf("oversize ping = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 2, InputBytes: len(oversizePing)})

	limits := defaultLimits()
	limits.MaxBufferedBytes = 16
	small := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeBinary,
		Payload: make([]byte, 32)}, &mask)
	sc = ScenarioCore{Role: "server", InitialState: "open", Limits: limits,
		Steps: []Step{{Kind: "bytes", DataBase64: b64(small)}}}
	expected = mustDerive(t, sc)
	if *expected.Error.CloseCode != 1009 {
		t.Fatalf("frame size limit = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 2, InputBytes: len(small)})

	big := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeBinary,
		Payload: make([]byte, 300)}, &mask)
	sc.Steps = []Step{{Kind: "bytes", DataBase64: b64(big)}}
	expected = mustDerive(t, sc)
	if *expected.Error.CloseCode != 1009 {
		t.Fatalf("16-bit size limit = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 4, InputBytes: len(big)})
}

// Reserved bits are rejected after the full frame is read.
func TestDeriveReservedBitConsumesFullFrame(t *testing.T) {
	mask := [4]byte{3, 3, 3, 3}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText, RSV1: true,
		Payload: []byte("abc")}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if *expected.Error.CloseCode != 1002 {
		t.Fatalf("rsv = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 9, InputBytes: 9})
}

// Process-stage continuation errors record the offending frame and consume
// the whole chunk.
func TestDeriveUnexpectedContinuationRecordsFrame(t *testing.T) {
	mask := [4]byte{8, 8, 8, 8}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeContinuous,
		Payload: []byte{1, 2, 3}}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if *expected.Error.CloseCode != 1002 {
		t.Fatalf("unexpected continuation = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 9, Frames: 1, InputBytes: 9})
}

// Fragment cumulative overflow: a non-fin continuation trips the adapter
// accounting (BUFFER_LIMIT_EXCEEDED, no close code) because the pinned Java
// only checks the running total at starts and fins; a fin continuation trips
// Java's checkBufferLimit (1009).
func TestDeriveFragmentCumulativeOverflow(t *testing.T) {
	limits := defaultLimits()
	limits.MaxBufferedBytes = 32
	m := [4]byte{4, 4, 4, 4}
	start := EncodeFrame(WireFrame{Fin: false, Opcode: OpcodeBinary,
		Payload: make([]byte, 20)}, &m)
	nonfin := EncodeFrame(WireFrame{Fin: false, Opcode: OpcodeContinuous,
		Payload: make([]byte, 20)}, &m)
	fin := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeContinuous,
		Payload: make([]byte, 20)}, &m)

	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: limits,
		Steps: []Step{
			{Kind: "bytes", DataBase64: b64(start)},
			{Kind: "bytes", DataBase64: b64(nonfin)},
		}}
	expected := mustDerive(t, sc)
	if expected.Error == nil || expected.Error.Code != "BUFFER_LIMIT_EXCEEDED" ||
		expected.Error.CloseCode != nil {
		t.Fatalf("nonfin overflow = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{BufferedBytes: 20, ConsumedBytes: 52, Frames: 2,
		InputBytes: 52, MessageBufferedBytes: 20})

	sc.Steps = []Step{
		{Kind: "bytes", DataBase64: b64(start)},
		{Kind: "bytes", DataBase64: b64(fin)},
	}
	expected = mustDerive(t, sc)
	if expected.Error == nil || expected.Error.Code != "JAVA_INVALID_DATA" ||
		*expected.Error.CloseCode != 1009 {
		t.Fatalf("fin overflow = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{BufferedBytes: 20, ConsumedBytes: 52, Frames: 2,
		InputBytes: 52, MessageBufferedBytes: 20})
}

// Adapter-limit errors carry the exact adapter counter semantics: input
// bytes are not added on overflow, and the action counter includes the
// rejected action.
func TestDeriveAdapterLimitCounts(t *testing.T) {
	limits := defaultLimits()
	limits.MaxInputBytes = 4
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: limits,
		Steps: []Step{{Kind: "bytes", DataBase64: b64([]byte{1, 2, 3, 4, 5})}}}
	expected := mustDerive(t, sc)
	if expected.Error.Code != "INPUT_LIMIT_EXCEEDED" {
		t.Fatalf("input limit = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{})

	limits = defaultLimits()
	limits.MaxActions = 1
	sc = ScenarioCore{Role: "client", InitialState: "open", Limits: limits,
		Steps: []Step{
			{Kind: "action", Action: "send_text", Text: "a"},
			{Kind: "action", Action: "send_text", Text: "b"},
		}}
	expected = mustDerive(t, sc)
	if expected.Error.Code != "ACTION_LIMIT_EXCEEDED" {
		t.Fatalf("action limit = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{Actions: 2, Frames: 1})

	sc = ScenarioCore{Role: "client", InitialState: "closing", Limits: defaultLimits(),
		Steps: []Step{{Kind: "action", Action: "send_text", Text: "x"}}}
	expected = mustDerive(t, sc)
	if expected.Error.Code != "STATE_VIOLATION" || expected.FinalState != "closing" {
		t.Fatalf("closing send = %+v", expected)
	}
	wantCounts(t, expected, Counts{Actions: 1})

	sc = ScenarioCore{Role: "server", InitialState: "closed", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64([]byte{9})}}}
	expected = mustDerive(t, sc)
	if expected.Error.Code != "STATE_VIOLATION" {
		t.Fatalf("closed bytes = %+v", expected)
	}
	wantCounts(t, expected, Counts{})
}

// send-side: oversized control payloads are permitted by the pinned runtime
// (ControlFrame.isValid has no length check), and a fin=true first
// send_fragment emits one complete data frame (Draft.continuousFrame).
func TestDeriveSendSidePinnedBehaviors(t *testing.T) {
	payload := make([]byte, 200)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "action", Action: "send_ping", DataBase64: b64(payload)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "ok" || len(expected.Frames) != 1 {
		t.Fatalf("oversize send_ping = %+v", expected)
	}
	if expected.Frames[0]["payload_bytes"] != 200 || expected.Frames[0]["wire_bytes"] != 204 {
		t.Fatalf("oversize ping frame = %v", expected.Frames[0])
	}

	sc = ScenarioCore{Role: "client", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "action", Action: "send_fragment", Opcode: "text",
			Fin: true, DataBase64: b64([]byte("solo"))}}}
	expected = mustDerive(t, sc)
	if expected.Outcome != "ok" || len(expected.Frames) != 1 ||
		expected.Frames[0]["opcode"] != "text" || expected.Frames[0]["fin"] != true {
		t.Fatalf("single-frame send_fragment = %+v", expected)
	}
}

// send_close with 1015 or 1005 fails 1002 (setCode normalization + isValid).
func TestDeriveSendCloseReservedCodes(t *testing.T) {
	for _, code := range []int{1015, 999} {
		sc := ScenarioCore{Role: "client", InitialState: "open", Limits: defaultLimits(),
			Steps: []Step{{Kind: "action", Action: "send_close", Code: code, Reason: "r"}}}
		expected := mustDerive(t, sc)
		if expected.Outcome != "error" || expected.Error.Code != "JAVA_INVALID_DATA" ||
			*expected.Error.CloseCode != 1002 {
			t.Fatalf("send_close %d = %+v", code, expected.Error)
		}
		wantCounts(t, expected, Counts{Actions: 1})
	}
}

// Local close then transport EOF completes to closed with the local details.
func TestDeriveLocalCloseThenEOF(t *testing.T) {
	sc := ScenarioCore{Role: "client", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{
			{Kind: "action", Action: "send_close", Code: 1001, Reason: "going away"},
			{Kind: "action", Action: "eof"},
		}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "ok" || expected.FinalState != "closed" {
		t.Fatalf("outcome=%s final=%s", expected.Outcome, expected.FinalState)
	}
	if expected.Close["origin"] != "transport" || expected.Close["code"] != 1001 ||
		expected.Close["remote"] != true {
		t.Fatalf("close = %v", expected.Close)
	}
	// Local close frame carries the real code+reason payload: 2+4+2+10.
	if expected.Frames[0]["wire_bytes"] != 18 || expected.Frames[0]["masked"] != true {
		t.Fatalf("frames = %v", expected.Frames)
	}
	wantCounts(t, expected, Counts{Actions: 2, Frames: 1})
}

// Fragmented text across two chunks assembles at the fin continuation.
func TestDeriveFragmentedTextAssembles(t *testing.T) {
	m1 := [4]byte{1, 1, 1, 1}
	m2 := [4]byte{2, 2, 2, 2}
	part1 := EncodeFrame(WireFrame{Fin: false, Opcode: OpcodeText, Payload: []byte("Hel")}, &m1)
	part2 := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeContinuous, Payload: []byte("lo")}, &m2)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{
			{Kind: "bytes", DataBase64: b64(part1)},
			{Kind: "bytes", DataBase64: b64(part2)},
		}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "ok" {
		t.Fatalf("outcome = %s (%+v)", expected.Outcome, expected.Error)
	}
	var texts int
	for _, event := range expected.Events {
		if event["type"] == "text" && event["text"] == "Hello" {
			texts++
		}
	}
	if texts != 1 {
		t.Fatalf("text events = %v", expected.Events)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 17, Frames: 2, InputBytes: 17})
}

// One frame split across two byte chunks buffers on the wire, then completes.
func TestDeriveSplitFrameWireBuffering(t *testing.T) {
	mask := [4]byte{3, 1, 4, 1}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeBinary, Payload: []byte{9, 9, 9, 9}}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{
			{Kind: "bytes", DataBase64: b64(wire[:4])},
			{Kind: "bytes", DataBase64: b64(wire[4:])},
		}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "ok" {
		t.Fatalf("outcome = %s (%+v)", expected.Outcome, expected.Error)
	}
	wantCounts(t, expected, Counts{ConsumedBytes: 10, Frames: 1, InputBytes: 10})
}

// The deriver refuses constructs outside its verified space instead of
// guessing: unknown actions, and masking-role violations (the pinned runtime
// accepts them, so asserting RFC behavior would contradict the oracle; the
// corpus scopes itself to spec-conformant masking as a documented non-goal).
func TestDeriveFailsClosedOnUnsupportedConstructs(t *testing.T) {
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "action", Action: "warp"}}}
	if _, err := DeriveExpected(sc); err == nil {
		t.Fatal("unknown action must fail closed")
	}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText, Payload: []byte("hi")}, nil)
	sc = ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	if _, err := DeriveExpected(sc); err == nil {
		t.Fatal("unmasked server input is outside the corpus masking scope")
	}
}

// Java validates translate-time text UTF-8 with the Hoehrmann DFA, which
// accepts a dangling incomplete tail; the strict REPORT decoder then rejects
// it at process time, AFTER the frame is recorded. Content-invalid UTF-8 is
// rejected at translate with nothing recorded. Both are modeled exactly.
func TestDeriveTruncatedUTF8TailIsProcessStage1007(t *testing.T) {
	mask := [4]byte{1, 1, 2, 2}
	// "ab" + first byte of a two-byte sequence: valid DFA prefix, invalid
	// for the strict decoder.
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText,
		Payload: []byte{'a', 'b', 0xc3}}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "error" || expected.Error.Code != "JAVA_INVALID_DATA" ||
		*expected.Error.CloseCode != 1007 {
		t.Fatalf("truncated tail = %+v", expected.Error)
	}
	// Process-stage: the frame was recorded and the whole chunk consumed.
	wantCounts(t, expected, Counts{ConsumedBytes: 9, Frames: 1, InputBytes: 9})

	// Content-invalid UTF-8 (DFA-rejected) stays a translate-stage 1007
	// with nothing recorded.
	wire = EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText,
		Payload: []byte{'a', 0xc0, 0x80}}, &mask)
	sc.Steps = []Step{{Kind: "bytes", DataBase64: b64(wire)}}
	expected = mustDerive(t, sc)
	if expected.Outcome != "error" || *expected.Error.CloseCode != 1007 ||
		expected.Counts.Frames != 0 {
		t.Fatalf("DFA-rejected UTF-8 = %+v counts=%+v", expected.Error, expected.Counts)
	}
}

// A multi-byte character split across fragments is legal: the truncated-tail
// start passes the DFA, and the assembled message validates strictly.
func TestDeriveFragmentSplitMidRuneAssembles(t *testing.T) {
	m1 := [4]byte{1, 2, 3, 4}
	m2 := [4]byte{5, 6, 7, 8}
	// U+00E9 is 0xc3 0xa9; split between the two bytes.
	start := EncodeFrame(WireFrame{Fin: false, Opcode: OpcodeText,
		Payload: []byte{'a', 0xc3}}, &m1)
	fin := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeContinuous,
		Payload: []byte{0xa9, 'b'}}, &m2)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{
			{Kind: "bytes", DataBase64: b64(start)},
			{Kind: "bytes", DataBase64: b64(fin)},
		}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "ok" {
		t.Fatalf("mid-rune split = %+v", expected.Error)
	}
	var text string
	for _, event := range expected.Events {
		if event["type"] == "text" {
			text = event["text"].(string)
		}
	}
	if text != "aéb" {
		t.Fatalf("assembled text = %q", text)
	}
}

// send_fragment with DFA-rejected text content is JAVA_NOT_SENDABLE
// (TextFrame.isValid -> NotSendable -> IllegalArgumentException caught by
// the adapter); a truncated-tail start is sendable.
func TestDeriveSendFragmentUTF8Semantics(t *testing.T) {
	sc := ScenarioCore{Role: "client", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "action", Action: "send_fragment", Opcode: "text",
			Fin: false, DataBase64: b64([]byte{0xc0, 0x80})}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "error" || expected.Error.Code != "JAVA_NOT_SENDABLE" ||
		expected.Error.CloseCode != nil {
		t.Fatalf("DFA-rejected fragment start = %+v", expected.Error)
	}
	wantCounts(t, expected, Counts{Actions: 1})

	sc.Steps = []Step{{Kind: "action", Action: "send_fragment", Opcode: "text",
		Fin: false, DataBase64: b64([]byte{'a', 0xc3})}}
	expected = mustDerive(t, sc)
	if expected.Outcome != "ok" || len(expected.Frames) != 1 {
		t.Fatalf("truncated-tail fragment start must be sendable: %+v", expected)
	}
}
