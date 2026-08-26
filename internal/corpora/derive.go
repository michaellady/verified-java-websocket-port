package corpora

import (
	"fmt"
	"unicode/utf8"
)

// Behavior parameterizes the reference model. Defaults mirror the pinned
// Java-WebSocket 1.6.0 semantics documented in the frozen port-seam dossier
// and the vendored java-oracle adapter. Calibration flips single fields to
// build reference mutants; production derivation always uses ReferenceBehavior.
type Behavior struct {
	ControlPayloadLimit        int
	ValidateUTF8               bool
	EnforceCloseCodeValidity   bool
	EchoCloseWhileOpen         bool
	EnforceOpenStateForActions bool
	EnforceContinuationStart   bool
	EnforceFrameSizeLimit      bool
	ClientMasksOutbound        bool
	EnforceReservedBits        bool
}

// ReferenceBehavior is the unmutated reference model.
func ReferenceBehavior() Behavior {
	return Behavior{
		ControlPayloadLimit:        125,
		ValidateUTF8:               true,
		EnforceCloseCodeValidity:   true,
		EchoCloseWhileOpen:         true,
		EnforceOpenStateForActions: true,
		EnforceContinuationStart:   true,
		EnforceFrameSizeLimit:      true,
		ClientMasksOutbound:        true,
		EnforceReservedBits:        true,
	}
}

// scenarioError is a derived error-outcome rejection.
type scenarioError struct {
	code      string
	closeCode *int
}

func (e scenarioError) Error() string { return e.code }

func protocolError(code string) scenarioError {
	return scenarioError{code: code}
}

func javaInvalid(closeCode int) scenarioError {
	c := closeCode
	return scenarioError{code: "JAVA_INVALID_DATA", closeCode: &c}
}

// unsupportedError marks constructs outside the verified expectation space.
// The deriver fails closed instead of guessing runtime behavior.
type unsupportedError struct{ reason string }

func (e unsupportedError) Error() string { return "unsupported scenario construct: " + e.reason }

// DeriveExpected computes a scenario's expectation under the reference model.
func DeriveExpected(core ScenarioCore) (Expected, error) {
	return DeriveExpectedWith(core, ReferenceBehavior())
}

// DeriveExpectedWith derives an expectation under an explicit behavior, used
// by calibration to measure whether the corpus kills reference mutants.
func DeriveExpectedWith(core ScenarioCore, behavior Behavior) (Expected, error) {
	d, err := newDeriver(core, behavior)
	if err != nil {
		return Expected{}, err
	}
	runErr := d.run()
	if runErr == nil {
		counts := d.counts()
		return Expected{
			Outcome:     "ok",
			FinalState:  d.state,
			Events:      d.events,
			Frames:      d.frames,
			Transitions: d.transitions,
			Close:       d.closeDetail,
			Counts:      &counts,
		}, nil
	}
	if scErr, ok := runErr.(scenarioError); ok {
		return Expected{
			Outcome:    "error",
			FinalState: d.state,
			Error:      &ExpectedError{Code: scErr.code, CloseCode: scErr.closeCode},
		}, nil
	}
	return Expected{}, runErr
}

type decodedFrame struct {
	fin     bool
	rsv1    bool
	rsv2    bool
	rsv3    bool
	opcode  byte
	masked  bool
	payload []byte
	wire    int
}

type deriver struct {
	behavior Behavior
	role     string
	state    string
	limits   Limits
	steps    []Step

	pending []byte

	inputBytes      int
	consumedBytes   int
	actionCount     int
	messageBuffered int

	fragmentOpcode   byte // adapter-side inbound fragment tracking (0 = none)
	javaFragOpcode   byte // Draft continuation opcode (0 = none)
	javaFragPayload  []byte
	sendFragmentOpen byte // send-side continuous frame type (0 = none)

	frames      []map[string]any
	events      []map[string]any
	transitions []map[string]any
	closeDetail map[string]any
}

func newDeriver(core ScenarioCore, behavior Behavior) (*deriver, error) {
	if core.Role != "server" && core.Role != "client" {
		return nil, unsupportedError{"role must be server or client"}
	}
	switch core.InitialState {
	case "open", "closing", "closed":
	default:
		return nil, unsupportedError{"initial_state must be open, closing, or closed"}
	}
	l := core.Limits
	if l.MaxInputBytes < 1 || l.MaxBufferedBytes < 1 || l.MaxActions < 0 ||
		l.MaxFrames < 1 || l.MaxOutputBytes < 512 {
		return nil, unsupportedError{"limits outside the oracle protocol bounds"}
	}
	return &deriver{
		behavior:    core.normalizedBehavior(behavior),
		role:        core.Role,
		state:       core.InitialState,
		limits:      core.Limits,
		steps:       core.Steps,
		events:      []map[string]any{},
		frames:      []map[string]any{},
		transitions: []map[string]any{},
	}, nil
}

func (core ScenarioCore) normalizedBehavior(behavior Behavior) Behavior { return behavior }

func (d *deriver) run() error {
	for index, step := range d.steps {
		switch step.Kind {
		case "bytes":
			if err := d.inputStep(step, index); err != nil {
				return err
			}
		case "action":
			if err := d.actionStep(step, index); err != nil {
				return err
			}
		default:
			return unsupportedError{fmt.Sprintf("step kind %q", step.Kind)}
		}
	}
	return nil
}

func (d *deriver) event(eventType string, step int, detail map[string]any) {
	value := map[string]any{}
	for k, v := range detail {
		value[k] = v
	}
	value["step"] = step
	value["type"] = eventType
	d.events = append(d.events, value)
}

func (d *deriver) transition(next, cause string, step int) {
	if d.state == next {
		return
	}
	d.transitions = append(d.transitions, map[string]any{
		"cause": cause,
		"from":  d.state,
		"step":  step,
		"to":    next,
	})
	d.state = next
}

func (d *deriver) counts() Counts {
	return Counts{
		Actions:              d.actionCount,
		BufferedBytes:        len(d.pending) + d.messageBuffered,
		ConsumedBytes:        d.consumedBytes,
		Frames:               len(d.frames),
		InputBytes:           d.inputBytes,
		MessageBufferedBytes: d.messageBuffered,
		WireBufferedBytes:    len(d.pending),
	}
}

func (d *deriver) closeMap(origin string, code int, reason string, remote, handshakeComplete bool) map[string]any {
	return map[string]any{
		"code":               code,
		"handshake_complete": handshakeComplete,
		"origin":             origin,
		"reason":             reason,
		"remote":             remote,
	}
}

// inputStep mirrors OracleEngine.Execution.input.
func (d *deriver) inputStep(step Step, index int) error {
	payload, err := step.payload()
	if err != nil {
		return unsupportedError{err.Error()}
	}
	if d.state == "closed" && len(payload) != 0 {
		return protocolError("STATE_VIOLATION")
	}
	d.inputBytes += len(payload)
	if d.inputBytes > d.limits.MaxInputBytes {
		return protocolError("INPUT_LIMIT_EXCEEDED")
	}
	if len(payload) == 0 {
		d.event("input_chunk", index, map[string]any{"bytes": 0})
		return nil
	}

	combined := append(append([]byte{}, d.pending...), payload...)
	var parsed []decodedFrame
	at := 0
	for {
		frame, size, complete, err := d.parseFrame(combined[at:])
		if err != nil {
			return err
		}
		if !complete {
			break
		}
		frame.wire = size
		parsed = append(parsed, frame)
		at += size
	}
	d.pending = combined[at:]
	if len(d.pending) > d.limits.MaxBufferedBytes+14 {
		return protocolError("BUFFER_LIMIT_EXCEEDED")
	}
	d.consumedBytes += len(payload)
	d.event("input_chunk", index, map[string]any{"bytes": len(payload)})
	for _, frame := range parsed {
		if len(d.frames) >= d.limits.MaxFrames {
			return protocolError("FRAME_LIMIT_EXCEEDED")
		}
		d.frames = append(d.frames, d.frameRecord(frame, "inbound", index, frame.masked, frame.wire))
		if err := d.processInbound(frame, index); err != nil {
			return err
		}
	}
	return nil
}

// parseFrame decodes one wire frame, applying the Java validity checks in the
// order the pinned runtime applies them. It returns complete=false when more
// bytes are needed. Header-invalid incomplete frames are rejected as
// unsupported: the runtime errors before buffering them, so generated
// scenarios always materialize invalid frames completely.
func (d *deriver) parseFrame(data []byte) (decodedFrame, int, bool, error) {
	var frame decodedFrame
	if len(data) < 2 {
		if len(data) > 0 {
			return frame, 0, false, nil
		}
		return frame, 0, false, nil
	}
	b1, b2 := data[0], data[1]
	frame.fin = b1&0x80 != 0
	frame.rsv1 = b1&0x40 != 0
	frame.rsv2 = b1&0x20 != 0
	frame.rsv3 = b1&0x10 != 0
	frame.opcode = b1 & 0x0f
	frame.masked = b2&0x80 != 0
	marker := int(b2 & 0x7f)

	header := 2
	length := marker
	isControl := frame.opcode == byte(OpcodeClose) || frame.opcode == byte(OpcodePing) ||
		frame.opcode == byte(OpcodePong)
	if marker == 126 {
		if len(data) < 4 {
			return frame, 0, false, d.requireCompleteForValidity(frame, data)
		}
		header = 4
		length = int(data[2])<<8 | int(data[3])
	} else if marker == 127 {
		if len(data) < 10 {
			return frame, 0, false, d.requireCompleteForValidity(frame, data)
		}
		header = 10
		length = 0
		for i := 0; i < 8; i++ {
			if length > (1 << 40) {
				return frame, 0, false, unsupportedError{"64-bit lengths beyond the generated space"}
			}
			length = length<<8 | int(data[2+i])
		}
	}
	if frame.masked {
		header += 4
	}
	total := header + length
	if len(data) < total {
		return frame, 0, false, d.requireCompleteForValidity(frame, data)
	}

	// Java validity order: opcode, control extended length, frame size limit,
	// reserved bits, then frame-specific validity.
	if !validOpcode(frame.opcode) {
		return frame, 0, false, javaInvalid(1002)
	}
	if isControl && length > d.behavior.ControlPayloadLimit {
		return frame, 0, false, javaInvalid(1002)
	}
	if d.behavior.EnforceFrameSizeLimit && length > d.limits.MaxBufferedBytes {
		return frame, 0, false, javaInvalid(1009)
	}

	frame.payload = make([]byte, length)
	copy(frame.payload, data[header:total])
	if frame.masked {
		maskStart := header - 4
		for i := range frame.payload {
			frame.payload[i] ^= data[maskStart+i%4]
		}
	}

	// Masking discipline: the generated space always masks toward servers and
	// never toward clients; anything else is outside the verified space.
	if d.role == "server" && !frame.masked {
		return frame, 0, false, unsupportedError{"unmasked inbound bytes toward a server"}
	}
	if d.role == "client" && frame.masked {
		return frame, 0, false, unsupportedError{"masked inbound bytes toward a client"}
	}

	if d.behavior.EnforceReservedBits && (frame.rsv1 || frame.rsv2 || frame.rsv3) {
		return frame, 0, false, javaInvalid(1002)
	}
	if isControl && !frame.fin {
		return frame, 0, false, javaInvalid(1002)
	}
	if frame.opcode == byte(OpcodeClose) {
		if err := d.validateCloseFramePayload(frame.payload); err != nil {
			return frame, 0, false, err
		}
	}
	return frame, total, true, nil
}

// requireCompleteForValidity fails closed when an incomplete frame's header
// already carries a violation the runtime would reject before buffering.
func (d *deriver) requireCompleteForValidity(frame decodedFrame, data []byte) error {
	if !validOpcode(frame.opcode) || frame.rsv1 || frame.rsv2 || frame.rsv3 {
		return unsupportedError{"invalid header on an incomplete frame"}
	}
	return nil
}

func validOpcode(op byte) bool {
	switch Opcode(op) {
	case OpcodeContinuous, OpcodeText, OpcodeBinary, OpcodeClose, OpcodePing, OpcodePong:
		return true
	}
	return false
}

func (d *deriver) validateCloseFramePayload(payload []byte) error {
	if len(payload) == 1 {
		return javaInvalid(1002)
	}
	if len(payload) >= 2 {
		code := int(payload[0])<<8 | int(payload[1])
		if d.behavior.EnforceCloseCodeValidity && !wireCloseCodeValid(code) {
			return javaInvalid(1002)
		}
		if !utf8.Valid(payload[2:]) {
			return unsupportedError{"close reason with invalid UTF-8 is outside the verified space"}
		}
	}
	return nil
}

// wireCloseCodeValid mirrors CloseFrame validity for the code set the
// generator uses; codes with uncertain 1.6.0 handling are never generated.
func wireCloseCodeValid(code int) bool {
	switch {
	case code == 1004, code == 1005, code == 1006, code == 1015:
		return false
	case code < 1000, code > 4999:
		return false
	}
	if code >= 1012 && code <= 2999 {
		// Outside the generated space: 1.6.0 acceptance is not pinned here.
		return true
	}
	return true
}

func closeCodeFromPayload(payload []byte) (int, string) {
	if len(payload) < 2 {
		return 1005, ""
	}
	return int(payload[0])<<8 | int(payload[1]), string(payload[2:])
}

func (d *deriver) processInbound(frame decodedFrame, index int) error {
	if d.state == "closed" {
		return protocolError("STATE_VIOLATION")
	}
	if d.state == "closing" && frame.opcode != byte(OpcodeClose) {
		return protocolError("STATE_VIOLATION")
	}
	switch Opcode(frame.opcode) {
	case OpcodeClose:
		code, reason := closeCodeFromPayload(frame.payload)
		wasClosing := d.state == "closing"
		d.closeDetail = d.closeMap("remote", code, reason, true, true)
		d.event("close", index, d.closeDetail)
		if wasClosing {
			d.transition("closed", "receive_close", index)
			return nil
		}
		if d.behavior.EchoCloseWhileOpen {
			if err := d.emitOutbound(index, "echo_close", WireFrame{
				Fin: true, Opcode: OpcodeClose, Payload: frame.payload,
			}); err != nil {
				return err
			}
		}
		d.transition("closing", "receive_close", index)
		return nil
	case OpcodePing:
		d.event("ping", index, map[string]any{
			"data_base64": base64Std(frame.payload), "bytes": len(frame.payload)})
		return nil
	case OpcodePong:
		d.event("pong", index, map[string]any{
			"data_base64": base64Std(frame.payload), "bytes": len(frame.payload)})
		return nil
	}
	return d.processDataFrame(frame, index)
}

// processDataFrame mirrors Draft_6455.processFrame for text, binary, and
// continuation frames, then the adapter's message-buffer accounting.
func (d *deriver) processDataFrame(frame decodedFrame, index int) error {
	op := Opcode(frame.opcode)
	switch {
	case op != OpcodeContinuous && !frame.fin:
		// Fragment start.
		if d.behavior.EnforceContinuationStart && d.javaFragOpcode != 0 {
			return javaInvalid(1002)
		}
		if op == OpcodeText && d.behavior.ValidateUTF8 && !utf8.Valid(frame.payload) {
			// 1.6.0 validates a text fragment start standalone; the generator
			// splits at rune boundaries so this only fires for mutants and
			// deliberately invalid single fragments.
			return javaInvalid(1007)
		}
		d.javaFragOpcode = frame.opcode
		d.javaFragPayload = append([]byte{}, frame.payload...)
		d.fragmentOpcode = frame.opcode
		d.messageBuffered = len(frame.payload)
		return nil
	case op == OpcodeContinuous && !frame.fin:
		if d.javaFragOpcode == 0 {
			if d.behavior.EnforceContinuationStart {
				return javaInvalid(1002)
			}
			return nil
		}
		d.javaFragPayload = append(d.javaFragPayload, frame.payload...)
		if d.behavior.EnforceFrameSizeLimit &&
			len(d.javaFragPayload) > d.limits.MaxBufferedBytes {
			return javaInvalid(1009)
		}
		d.messageBuffered += len(frame.payload)
		if d.messageBuffered > d.limits.MaxBufferedBytes {
			return protocolError("BUFFER_LIMIT_EXCEEDED")
		}
		return nil
	case op == OpcodeContinuous && frame.fin:
		if d.javaFragOpcode == 0 {
			if d.behavior.EnforceContinuationStart {
				return javaInvalid(1002)
			}
			return nil
		}
		assembled := append(append([]byte{}, d.javaFragPayload...), frame.payload...)
		messageOpcode := Opcode(d.javaFragOpcode)
		d.javaFragOpcode = 0
		d.javaFragPayload = nil
		if err := d.emitMessage(messageOpcode, assembled, index); err != nil {
			return err
		}
		d.fragmentOpcode = 0
		d.messageBuffered = 0
		return nil
	default:
		// Unfragmented data frame.
		if d.javaFragOpcode != 0 {
			if d.behavior.EnforceContinuationStart {
				return javaInvalid(1002)
			}
		}
		return d.emitMessage(op, frame.payload, index)
	}
}

func (d *deriver) emitMessage(op Opcode, payload []byte, index int) error {
	if op == OpcodeText {
		if d.behavior.ValidateUTF8 && !utf8.Valid(payload) {
			return javaInvalid(1007)
		}
		d.event("text", index, map[string]any{
			"text": string(payload), "utf8_bytes": len(payload)})
		return nil
	}
	d.event("binary", index, map[string]any{
		"data_base64": base64Std(payload), "bytes": len(payload)})
	return nil
}

// emitOutbound mirrors OracleEngine.Execution.emitOutbound: frame record,
// then the cause event carrying the opcode name.
func (d *deriver) emitOutbound(index int, cause string, frame WireFrame) error {
	if len(d.frames) >= d.limits.MaxFrames {
		return protocolError("FRAME_LIMIT_EXCEEDED")
	}
	client := d.role == "client"
	masked := client && d.behavior.ClientMasksOutbound
	wire := headerSize(len(frame.Payload)) + len(frame.Payload)
	if masked {
		wire += 4
	}
	record := map[string]any{
		"direction":      "outbound",
		"fin":            frame.Fin,
		"masked":         masked,
		"opcode":         frame.Opcode.Name(),
		"payload_base64": base64Std(frame.Payload),
		"payload_bytes":  len(frame.Payload),
		"rsv1":           frame.RSV1,
		"rsv2":           frame.RSV2,
		"rsv3":           frame.RSV3,
		"step":           index,
		"wire_bytes":     wire,
	}
	d.frames = append(d.frames, record)
	d.event(cause, index, map[string]any{"opcode": frame.Opcode.Name()})
	return nil
}

func (d *deriver) frameRecord(frame decodedFrame, direction string, step int, masked bool, wireBytes int) map[string]any {
	return map[string]any{
		"direction":      direction,
		"fin":            frame.fin,
		"masked":         masked,
		"opcode":         Opcode(frame.opcode).Name(),
		"payload_base64": base64Std(frame.payload),
		"payload_bytes":  len(frame.payload),
		"rsv1":           frame.rsv1,
		"rsv2":           frame.rsv2,
		"rsv3":           frame.rsv3,
		"step":           step,
		"wire_bytes":     wireBytes,
	}
}

func (d *deriver) requireOpen() error {
	if d.behavior.EnforceOpenStateForActions && d.state != "open" {
		return protocolError("STATE_VIOLATION")
	}
	return nil
}

func (d *deriver) requirePayloadLimit(size int) error {
	if size > d.limits.MaxBufferedBytes {
		return protocolError("BUFFER_LIMIT_EXCEEDED")
	}
	return nil
}

func (d *deriver) actionStep(step Step, index int) error {
	d.actionCount++
	if d.actionCount > d.limits.MaxActions {
		return protocolError("ACTION_LIMIT_EXCEEDED")
	}
	switch step.Action {
	case "send_text":
		if err := d.requireOpen(); err != nil {
			return err
		}
		if d.sendFragmentOpen != 0 {
			return unsupportedError{"send_text during an open fragment sequence"}
		}
		if err := d.requirePayloadLimit(len([]byte(step.Text))); err != nil {
			return err
		}
		return d.emitOutbound(index, "send_text", WireFrame{
			Fin: true, Opcode: OpcodeText, Payload: []byte(step.Text)})
	case "send_binary":
		if err := d.requireOpen(); err != nil {
			return err
		}
		if d.sendFragmentOpen != 0 {
			return unsupportedError{"send_binary during an open fragment sequence"}
		}
		payload, err := step.payload()
		if err != nil {
			return unsupportedError{err.Error()}
		}
		if err := d.requirePayloadLimit(len(payload)); err != nil {
			return err
		}
		return d.emitOutbound(index, "send_binary", WireFrame{
			Fin: true, Opcode: OpcodeBinary, Payload: payload})
	case "send_ping", "send_pong":
		if err := d.requireOpen(); err != nil {
			return err
		}
		payload, err := step.payload()
		if err != nil {
			return unsupportedError{err.Error()}
		}
		if len(payload) > 125 {
			return unsupportedError{"send-side control payloads above 125 octets"}
		}
		opcode := OpcodePing
		if step.Action == "send_pong" {
			opcode = OpcodePong
		}
		return d.emitOutbound(index, step.Action, WireFrame{
			Fin: true, Opcode: opcode, Payload: payload})
	case "send_close":
		return d.sendClose(step, index)
	case "send_fragment":
		return d.sendFragment(step, index)
	case "eof":
		return d.eof(index)
	}
	return unsupportedError{fmt.Sprintf("action %q", step.Action)}
}

func (d *deriver) sendClose(step Step, index int) error {
	if err := d.requireOpen(); err != nil {
		return err
	}
	if step.Code == 1005 {
		return unsupportedError{"send_close with 1005 is outside the generated space"}
	}
	if d.behavior.EnforceCloseCodeValidity && !wireCloseCodeValid(step.Code) {
		return javaInvalid(1002)
	}
	payload := append([]byte{byte(step.Code >> 8), byte(step.Code)}, []byte(step.Reason)...)
	if len(payload) > d.behavior.ControlPayloadLimit+2 {
		return unsupportedError{"send_close reason beyond the generated space"}
	}
	if err := d.emitOutbound(index, "send_close", WireFrame{
		Fin: true, Opcode: OpcodeClose, Payload: payload}); err != nil {
		return err
	}
	d.closeDetail = d.closeMap("local", step.Code, step.Reason, false, false)
	d.event("close_initiated", index, d.closeDetail)
	d.transition("closing", "send_close", index)
	return nil
}

func (d *deriver) sendFragment(step Step, index int) error {
	if err := d.requireOpen(); err != nil {
		return err
	}
	if step.Opcode != "text" && step.Opcode != "binary" {
		return unsupportedError{"send_fragment opcode must be text or binary"}
	}
	payload, err := step.payload()
	if err != nil {
		return unsupportedError{err.Error()}
	}
	if err := d.requirePayloadLimit(len(payload)); err != nil {
		return err
	}
	declared := byte(OpcodeText)
	if step.Opcode == "binary" {
		declared = byte(OpcodeBinary)
	}
	var wireOpcode Opcode
	if d.sendFragmentOpen == 0 {
		if step.Fin {
			return unsupportedError{"single-frame send_fragment is outside the generated space"}
		}
		if declared == byte(OpcodeText) && !utf8.Valid(payload) {
			return unsupportedError{"text fragment start with invalid UTF-8"}
		}
		wireOpcode = Opcode(declared)
		d.sendFragmentOpen = declared
	} else {
		if declared != d.sendFragmentOpen {
			return unsupportedError{"fragment opcode change mid-sequence"}
		}
		wireOpcode = OpcodeContinuous
		if step.Fin {
			d.sendFragmentOpen = 0
		}
	}
	return d.emitOutbound(index, "send_fragment", WireFrame{
		Fin: step.Fin, Opcode: wireOpcode, Payload: payload})
}

func (d *deriver) eof(index int) error {
	if d.state == "closed" {
		return protocolError("STATE_VIOLATION")
	}
	code := 1006
	reason := "transport EOF before close handshake completed"
	if d.state == "closing" && d.closeDetail != nil {
		code = d.closeDetail["code"].(int)
		reason = d.closeDetail["reason"].(string)
	}
	handshakeComplete := d.closeDetail != nil && d.closeDetail["handshake_complete"] == true
	d.closeDetail = d.closeMap("transport", code, reason, d.state == "closing", handshakeComplete)
	d.event("eof", index, d.closeDetail)
	d.transition("closed", "eof", index)
	return nil
}
