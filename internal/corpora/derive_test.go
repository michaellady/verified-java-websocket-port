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
	if len(expected.Events) != 2 {
		t.Fatalf("events = %v", expected.Events)
	}
	if expected.Events[0]["type"] != "input_chunk" || expected.Events[0]["bytes"] != 11 {
		t.Fatalf("input_chunk event = %v", expected.Events[0])
	}
	if expected.Events[1]["type"] != "text" || expected.Events[1]["text"] != "Hello" ||
		expected.Events[1]["utf8_bytes"] != 5 {
		t.Fatalf("text event = %v", expected.Events[1])
	}
	if len(expected.Frames) != 1 {
		t.Fatalf("frames = %v", expected.Frames)
	}
	frame := expected.Frames[0]
	if frame["direction"] != "inbound" || frame["masked"] != true ||
		frame["opcode"] != "text" || frame["payload_base64"] != b64([]byte("Hello")) ||
		frame["wire_bytes"] != 11 || frame["fin"] != true {
		t.Fatalf("frame = %v", frame)
	}
	if expected.Counts == nil {
		t.Fatal("ok outcome must carry counts")
	}
	counts := *expected.Counts
	want := Counts{Actions: 0, BufferedBytes: 0, ConsumedBytes: 11, Frames: 1,
		InputBytes: 11, MessageBufferedBytes: 0, WireBufferedBytes: 0}
	if counts != want {
		t.Fatalf("counts = %+v want %+v", counts, want)
	}
	if expected.Close != nil || len(expected.Transitions) != 0 {
		t.Fatalf("close=%v transitions=%v", expected.Close, expected.Transitions)
	}
}

// A text frame that is not valid UTF-8 fails with the Java 1007 rejection.
func TestDeriveInvalidUTF8TextFails1007(t *testing.T) {
	payload := []byte{0xff, 0xfe}
	mask := [4]byte{1, 2, 3, 4}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText, Payload: payload}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "error" || expected.Error == nil {
		t.Fatalf("expected error outcome, got %+v", expected)
	}
	if expected.Error.Code != "JAVA_INVALID_DATA" || expected.Error.CloseCode == nil ||
		*expected.Error.CloseCode != 1007 {
		t.Fatalf("error = %+v", expected.Error)
	}
	if expected.FinalState != "open" {
		t.Fatalf("final state = %s", expected.FinalState)
	}
	if expected.Counts != nil || len(expected.Events) != 0 {
		t.Fatal("error outcomes must not assert counts or events")
	}
}

// Remote close while open: close event, echoed close frame, open -> closing.
func TestDeriveRemoteCloseWhileOpenEchoesAndTransitions(t *testing.T) {
	payload := append([]byte{0x03, 0xe8}, []byte("bye")...) // 1000 + "bye"
	mask := [4]byte{9, 8, 7, 6}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeClose, Payload: payload}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "ok" || expected.FinalState != "closing" {
		t.Fatalf("outcome=%s final=%s", expected.Outcome, expected.FinalState)
	}
	if len(expected.Events) != 3 || expected.Events[1]["type"] != "close" ||
		expected.Events[2]["type"] != "echo_close" {
		t.Fatalf("events = %v", expected.Events)
	}
	if expected.Close == nil || expected.Close["code"] != 1000 ||
		expected.Close["origin"] != "remote" || expected.Close["reason"] != "bye" ||
		expected.Close["remote"] != true || expected.Close["handshake_complete"] != true {
		t.Fatalf("close = %v", expected.Close)
	}
	if len(expected.Frames) != 2 || expected.Frames[0]["direction"] != "inbound" ||
		expected.Frames[1]["direction"] != "outbound" || expected.Frames[1]["opcode"] != "closing" {
		t.Fatalf("frames = %v", expected.Frames)
	}
	// Server echo is unmasked: 2-byte header + 5-byte payload.
	if expected.Frames[1]["wire_bytes"] != 7 || expected.Frames[1]["masked"] != false {
		t.Fatalf("echo frame = %v", expected.Frames[1])
	}
	if len(expected.Transitions) != 1 || expected.Transitions[0]["from"] != "open" ||
		expected.Transitions[0]["to"] != "closing" || expected.Transitions[0]["cause"] != "receive_close" {
		t.Fatalf("transitions = %v", expected.Transitions)
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
	// send_close emits: send_close event, close_initiated event; then eof event.
	if len(expected.Events) != 3 || expected.Events[0]["type"] != "send_close" ||
		expected.Events[1]["type"] != "close_initiated" || expected.Events[2]["type"] != "eof" {
		t.Fatalf("events = %v", expected.Events)
	}
	if expected.Close["origin"] != "transport" || expected.Close["code"] != 1001 ||
		expected.Close["reason"] != "going away" || expected.Close["remote"] != true {
		t.Fatalf("close = %v", expected.Close)
	}
	// Client outbound close frame is masked: 2 header + 4 mask + 2 code + 10 reason.
	if len(expected.Frames) != 1 || expected.Frames[0]["wire_bytes"] != 18 ||
		expected.Frames[0]["masked"] != true {
		t.Fatalf("frames = %v", expected.Frames)
	}
	if len(expected.Transitions) != 2 {
		t.Fatalf("transitions = %v", expected.Transitions)
	}
}

// A control frame above 125 octets is a Java protocol violation (1002).
func TestDeriveOversizeControlFrameFails1002(t *testing.T) {
	payload := make([]byte, 126)
	mask := [4]byte{5, 5, 5, 5}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodePing, Payload: payload}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "error" || expected.Error.Code != "JAVA_INVALID_DATA" ||
		expected.Error.CloseCode == nil || *expected.Error.CloseCode != 1002 {
		t.Fatalf("expected 1002 protocol error, got %+v", expected.Error)
	}
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
	var texts []map[string]any
	for _, event := range expected.Events {
		if event["type"] == "text" {
			texts = append(texts, event)
		}
	}
	if len(texts) != 1 || texts[0]["text"] != "Hello" || texts[0]["step"] != 1 {
		t.Fatalf("text events = %v", texts)
	}
	want := Counts{Actions: 0, BufferedBytes: 0, ConsumedBytes: 17, Frames: 2,
		InputBytes: 17, MessageBufferedBytes: 0, WireBufferedBytes: 0}
	if *expected.Counts != want {
		t.Fatalf("counts = %+v want %+v", *expected.Counts, want)
	}
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
	var binaries int
	for _, event := range expected.Events {
		if event["type"] == "binary" {
			binaries++
		}
	}
	if binaries != 1 {
		t.Fatalf("binary events = %d", binaries)
	}
	want := Counts{Actions: 0, BufferedBytes: 0, ConsumedBytes: 10, Frames: 1,
		InputBytes: 10, MessageBufferedBytes: 0, WireBufferedBytes: 0}
	if *expected.Counts != want {
		t.Fatalf("counts = %+v want %+v", *expected.Counts, want)
	}
}

// Actions outside OPEN are adapter state violations.
func TestDeriveStateViolations(t *testing.T) {
	closing := ScenarioCore{Role: "server", InitialState: "closing", Limits: defaultLimits(),
		Steps: []Step{{Kind: "action", Action: "send_text", Text: "x"}}}
	expected := mustDerive(t, closing)
	if expected.Outcome != "error" || expected.Error.Code != "STATE_VIOLATION" ||
		expected.FinalState != "closing" {
		t.Fatalf("closing send_text = %+v", expected)
	}
	closed := ScenarioCore{Role: "server", InitialState: "closed", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64([]byte{0x81})}}}
	expected = mustDerive(t, closed)
	if expected.Outcome != "error" || expected.Error.Code != "STATE_VIOLATION" {
		t.Fatalf("closed bytes = %+v", expected)
	}
}

// An unknown opcode is rejected by the Java runtime with 1002.
func TestDeriveBadOpcodeFails1002(t *testing.T) {
	mask := [4]byte{0, 0, 0, 1}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: Opcode(0x3), Payload: []byte{1}}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "error" || expected.Error.Code != "JAVA_INVALID_DATA" ||
		*expected.Error.CloseCode != 1002 {
		t.Fatalf("bad opcode = %+v", expected.Error)
	}
}

// Reserved close codes must not arrive on the wire (1002).
func TestDeriveInvalidWireCloseCodeFails1002(t *testing.T) {
	for _, code := range []int{999, 1005, 1006, 1015, 1004} {
		payload := []byte{byte(code >> 8), byte(code)}
		mask := [4]byte{6, 6, 6, 6}
		wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeClose, Payload: payload}, &mask)
		sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
			Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
		expected := mustDerive(t, sc)
		if expected.Outcome != "error" || expected.Error.Code != "JAVA_INVALID_DATA" ||
			*expected.Error.CloseCode != 1002 {
			t.Fatalf("close code %d = %+v", code, expected.Error)
		}
	}
}

// Adapter resource limits fail closed with adapter error codes.
func TestDeriveAdapterLimits(t *testing.T) {
	limits := defaultLimits()
	limits.MaxInputBytes = 4
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: limits,
		Steps: []Step{{Kind: "bytes", DataBase64: b64([]byte{1, 2, 3, 4, 5})}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "error" || expected.Error.Code != "INPUT_LIMIT_EXCEEDED" {
		t.Fatalf("input limit = %+v", expected.Error)
	}

	limits = defaultLimits()
	limits.MaxActions = 1
	sc = ScenarioCore{Role: "client", InitialState: "open", Limits: limits,
		Steps: []Step{
			{Kind: "action", Action: "send_text", Text: "a"},
			{Kind: "action", Action: "send_text", Text: "b"},
		}}
	expected = mustDerive(t, sc)
	if expected.Outcome != "error" || expected.Error.Code != "ACTION_LIMIT_EXCEEDED" {
		t.Fatalf("action limit = %+v", expected.Error)
	}
}

// A frame larger than max_buffered_bytes is the Java 1009 limit rejection.
func TestDeriveFrameSizeLimitFails1009(t *testing.T) {
	limits := defaultLimits()
	limits.MaxBufferedBytes = 16
	payload := make([]byte, 32)
	mask := [4]byte{7, 7, 7, 7}
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeBinary, Payload: payload}, &mask)
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: limits,
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	expected := mustDerive(t, sc)
	if expected.Outcome != "error" || expected.Error.Code != "JAVA_INVALID_DATA" ||
		*expected.Error.CloseCode != 1009 {
		t.Fatalf("frame size limit = %+v", expected.Error)
	}
}

// The deriver refuses constructs outside its verified space instead of guessing.
func TestDeriveFailsClosedOnUnsupportedConstructs(t *testing.T) {
	sc := ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "action", Action: "warp"}}}
	if _, err := DeriveExpected(sc); err == nil {
		t.Fatal("unknown action must fail closed, not derive an expectation")
	}
	// Unmasked inbound bytes toward a server are outside the verified space.
	wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText, Payload: []byte("hi")}, nil)
	sc = ScenarioCore{Role: "server", InitialState: "open", Limits: defaultLimits(),
		Steps: []Step{{Kind: "bytes", DataBase64: b64(wire)}}}
	if _, err := DeriveExpected(sc); err == nil {
		t.Fatal("unmasked server input is outside the verified expectation space")
	}
}
