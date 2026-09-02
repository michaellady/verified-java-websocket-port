package corpora

import (
	"fmt"
	"unicode/utf8"
)

// Behavior parameterizes the reference model. Defaults mirror the pinned
// Java-WebSocket 1.6.0 sources in the quarantined archive (Draft_6455,
// CloseFrame, ControlFrame, TextFrame, Draft) plus the vendored java-oracle
// adapter. Calibration flips single fields to build reference mutants;
// production derivation always uses ReferenceBehavior.
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

// closeFrameConstructorPayload mirrors CloseFrame's constructor: setReason("")
// then setCode(1000) store payload [0x03,0xe8] via updatePayload, and the
// wire-parsing setPayload override never replaces it. Every parsed inbound
// close frame therefore records and echoes exactly these two bytes.
var closeFrameConstructorPayload = []byte{0x03, 0xe8}

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

func javaRuntimeRejection() scenarioError {
	return scenarioError{code: "JAVA_RUNTIME_REJECTION"}
}

// unsupportedError marks constructs outside the verified expectation space.
// The deriver fails closed instead of guessing runtime behavior.
type unsupportedError struct{ reason string }

func (e unsupportedError) Error() string { return "unsupported scenario construct: " + e.reason }

// DeriveExpected computes a scenario's expectation under the reference model.
func DeriveExpected(core ScenarioCore) (Expected, error) {
	return DeriveExpectedWith(core, ReferenceBehavior())
}

// DeriveExpectedAndFailingStep derives a scenario's expectation under the
// reference model AND reports the INDEX OF THE STEP THE RUN STOPPED ON, or -1
// when the run completed. The index comes from EXECUTING the scenario's own
// steps, so it is a fact about the scenario program rather than a fact restated
// beside it.
//
// It exists because internal/deltaledger needs to know which step failed in
// order to decide protocol-rejection-class membership, and review round 3
// established that deriving that from `expected.counts` lets whoever writes the
// scenario choose the answer: a valid inbound frame followed by a rejected
// local `send_close` recorded as `input_bytes=5, actions=0` makes the counts
// name the bytes prefix uniquely, so the ambiguity refusal never fires and a
// locally caused failure is enrolled as an inbound decode rejection. Executing
// the steps cannot be talked into that, because the counts are not consulted.
func DeriveExpectedAndFailingStep(core ScenarioCore) (Expected, int, error) {
	return deriveExpected(core, ReferenceBehavior())
}

// DeriveExpectedWith derives an expectation under an explicit behavior, used
// by calibration to measure whether the corpus kills reference mutants.
// Both outcomes carry exact counts: the oracle's failure responses include
// the counters, so error expectations assert them too.
func DeriveExpectedWith(core ScenarioCore, behavior Behavior) (Expected, error) {
	expected, _, err := deriveExpected(core, behavior)
	return expected, err
}

func deriveExpected(core ScenarioCore, behavior Behavior) (Expected, int, error) {
	d, err := newDeriver(core, behavior)
	if err != nil {
		return Expected{}, 0, err
	}
	runErr := d.run()
	counts := d.counts()
	if runErr == nil {
		return Expected{
			Outcome:     "ok",
			FinalState:  d.state,
			Events:      d.events,
			Frames:      d.frames,
			Transitions: d.transitions,
			Close:       d.closeDetail,
			Counts:      &counts,
		}, -1, nil
	}
	if scErr, ok := runErr.(scenarioError); ok {
		return Expected{
			Outcome:    "error",
			FinalState: d.state,
			Error:      &ExpectedError{Code: scErr.code, CloseCode: scErr.closeCode},
			Counts:     &counts,
		}, d.failingStep, nil
	}
	return Expected{}, 0, runErr
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

	javaFragOpcode   byte // Draft continuation opcode (0 = none)
	javaFragPayload  []byte
	sendFragmentOpen byte // send-side continuous frame type (0 = none)

	frames      []map[string]any
	events      []map[string]any
	transitions []map[string]any
	closeDetail map[string]any

	// failingStep is the index of the step whose execution returned the error
	// that stopped the run, or -1 while the run is still going. It is set by
	// run() at the single place a step's error propagates, so it cannot fall
	// out of step with which step actually failed.
	failingStep int
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
		behavior:    behavior,
		role:        core.Role,
		state:       core.InitialState,
		limits:      core.Limits,
		steps:       core.Steps,
		events:      []map[string]any{},
		frames:      []map[string]any{},
		transitions: []map[string]any{},
		failingStep: -1,
	}, nil
}

func (d *deriver) run() error {
	for index, step := range d.steps {
		var err error
		switch step.Kind {
		case "bytes":
			err = d.inputStep(step, index)
		case "action":
			err = d.actionStep(step, index)
		default:
			err = unsupportedError{fmt.Sprintf("step kind %q", step.Kind)}
		}
		if err != nil {
			d.failingStep = index
			return err
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

// frameSpan is one wire frame's absolute extent within a combined buffer.
type frameSpan struct {
	start int
	size  int
}

// scanSpans mirrors WireTracker.frameLength: extract complete frame spans by
// length grammar only, leaving the incomplete tail.
func scanSpans(data []byte) ([]frameSpan, int, error) {
	var spans []frameSpan
	at := 0
	for {
		if len(data)-at < 2 {
			break
		}
		marker := int(data[at+1] & 0x7f)
		header := 2
		length := marker
		if marker == 126 {
			if len(data)-at < 4 {
				break
			}
			header = 4
			length = int(data[at+2])<<8 | int(data[at+3])
		} else if marker == 127 {
			if len(data)-at < 10 {
				break
			}
			header = 10
			length = 0
			for i := 0; i < 8; i++ {
				if length > (1 << 40) {
					return nil, 0, unsupportedError{"64-bit lengths beyond the generated space"}
				}
				length = length<<8 | int(data[at+2+i])
			}
		}
		if data[at+1]&0x80 != 0 {
			header += 4
		}
		total := header + length
		if len(data)-at < total {
			break
		}
		spans = append(spans, frameSpan{start: at, size: total})
		at += total
	}
	return spans, at, nil
}

// inputStep mirrors OracleEngine.Execution.input with the pinned Java
// consumption semantics at every error site.
func (d *deriver) inputStep(step Step, index int) error {
	payload, err := step.payload()
	if err != nil {
		return unsupportedError{err.Error()}
	}
	if d.state == "closed" && len(payload) != 0 {
		return protocolError("STATE_VIOLATION")
	}
	// addBounded semantics: the counter is only updated when within bounds.
	if d.inputBytes+len(payload) > d.limits.MaxInputBytes {
		return protocolError("INPUT_LIMIT_EXCEEDED")
	}
	d.inputBytes += len(payload)
	if len(payload) == 0 {
		d.event("input_chunk", index, map[string]any{"bytes": 0})
		return nil
	}

	chunkStart := len(d.pending)
	combined := append(append([]byte{}, d.pending...), payload...)
	spans, consumedSpanEnd, err := scanSpans(combined)
	if err != nil {
		return err
	}
	leftover := combined[consumedSpanEnd:]
	leftoverStart := consumedSpanEnd
	// WireTracker.accept: pending is replaced before the overflow check, and
	// the overflow throw happens before any translation (consumed stays 0
	// for this chunk).
	d.pending = append([]byte{}, leftover...)
	if len(leftover) > d.limits.MaxBufferedBytes+14 {
		return protocolError("BUFFER_LIMIT_EXCEEDED")
	}

	// Translate stage: sequential decode with Java's validity order and
	// per-site consumption.
	var decoded []decodedFrame
	for _, span := range spans {
		frame, errSite, decodeErr, unsupported := d.decodeFrame(
			combined[span.start : span.start+span.size])
		if unsupported != nil {
			return unsupported
		}
		if decodeErr != nil {
			if span.start < chunkStart {
				return unsupportedError{
					"translate-stage rejection inside a frame completed from buffered bytes"}
			}
			d.consumedBytes += span.start + errSite - chunkStart
			return *decodeErr
		}
		frame.wire = span.size
		decoded = append(decoded, frame)
	}
	// A fresh incomplete frame whose visible header already violates the
	// runtime rules is rejected during this step (translateSingleFrame reads
	// the header before noticing the frame is incomplete).
	if len(leftover) >= 2 {
		site, screenErr, unsupported := d.screenIncompleteHeader(leftover)
		if unsupported != nil {
			return unsupported
		}
		if screenErr != nil {
			if leftoverStart < chunkStart {
				return unsupportedError{
					"header rejection inside a frame extended from buffered bytes"}
			}
			d.consumedBytes += leftoverStart + site - chunkStart
			return *screenErr
		}
	}
	d.consumedBytes += len(payload)
	d.event("input_chunk", index, map[string]any{"bytes": len(payload)})
	for _, frame := range decoded {
		if len(d.frames) >= d.limits.MaxFrames {
			return protocolError("FRAME_LIMIT_EXCEEDED")
		}
		d.frames = append(d.frames, d.inboundFrameRecord(frame, index))
		if err := d.processInbound(frame, index); err != nil {
			return err
		}
	}
	return nil
}

// decodeFrame mirrors translateSingleFrame on one complete frame. On a
// rejection it reports the exact byte offset the runtime consumed before
// throwing: 2 after the base header (unknown opcode, oversized control,
// 7-bit length limit), 4 after a 16-bit length (length limit), and the full
// frame for post-payload checks (reserved bits, frame validity, close
// semantics, text UTF-8).
func (d *deriver) decodeFrame(data []byte) (decodedFrame, int, *scenarioError, error) {
	var frame decodedFrame
	b1, b2 := data[0], data[1]
	frame.fin = b1&0x80 != 0
	frame.rsv1 = b1&0x40 != 0
	frame.rsv2 = b1&0x20 != 0
	frame.rsv3 = b1&0x10 != 0
	frame.opcode = b1 & 0x0f
	frame.masked = b2&0x80 != 0
	marker := int(b2 & 0x7f)

	fail := func(site int, err scenarioError) (decodedFrame, int, *scenarioError, error) {
		return frame, site, &err, nil
	}

	if !validOpcode(frame.opcode) {
		return fail(2, javaInvalid(1002))
	}
	isControl := frame.opcode == byte(OpcodeClose) || frame.opcode == byte(OpcodePing) ||
		frame.opcode == byte(OpcodePong)

	header := 2
	length := marker
	lengthSite := 2
	if marker >= 126 {
		// translateSingleFramePayloadLength rejects extended control frames
		// before reading the extended length bytes.
		if isControl && d.behavior.ControlPayloadLimit <= 125 {
			return fail(2, javaInvalid(1002))
		}
		if marker == 126 {
			header = 4
			length = int(data[2])<<8 | int(data[3])
			lengthSite = 4
		} else {
			header = 10
			length = 0
			for i := 0; i < 8; i++ {
				length = length<<8 | int(data[2+i])
			}
			lengthSite = 10
		}
	}
	if isControl && length > d.behavior.ControlPayloadLimit {
		return fail(lengthSite, javaInvalid(1002))
	}
	if d.behavior.EnforceFrameSizeLimit && length > d.limits.MaxBufferedBytes {
		return fail(lengthSite, javaInvalid(1009))
	}
	if frame.masked {
		header += 4
	}
	frame.payload = make([]byte, length)
	copy(frame.payload, data[header:header+length])
	if frame.masked {
		maskStart := header - 4
		for i := range frame.payload {
			frame.payload[i] ^= data[maskStart+i%4]
		}
	}

	// Masking discipline: the pinned runtime accepts either masking toward
	// either role; the corpus scopes itself to spec-conformant masking (a
	// documented Java-compatibility non-goal), so anything else is outside
	// the verified space rather than an expectation.
	if d.role == "server" && !frame.masked {
		return frame, 0, nil, unsupportedError{"unmasked inbound bytes toward a server"}
	}
	if d.role == "client" && frame.masked {
		return frame, 0, nil, unsupportedError{"masked inbound bytes toward a client"}
	}

	full := len(data)
	// DefaultExtension.isFrameValid runs after the payload is read.
	if d.behavior.EnforceReservedBits && (frame.rsv1 || frame.rsv2 || frame.rsv3) {
		return fail(full, javaInvalid(1002))
	}
	// frame.isValid(): ControlFrame fin check, then per-frame semantics.
	if isControl && !frame.fin {
		return fail(full, javaInvalid(1002))
	}
	if frame.opcode == byte(OpcodeClose) {
		if _, _, closeErr, unsupported := d.parseCloseSemantics(frame.payload); unsupported != nil {
			return frame, 0, nil, unsupported
		} else if closeErr != nil {
			return fail(full, *closeErr)
		}
	}
	// TextFrame.isValid validates standalone UTF-8 at translate time using
	// the Hoehrmann DFA, which rejects invalid content but ACCEPTS a
	// dangling incomplete tail; the strict REPORT decoder rejects the tail
	// later at process time, after the frame is recorded (handled in
	// emitMessage).
	if frame.opcode == byte(OpcodeText) && d.behavior.ValidateUTF8 &&
		!dfaAcceptsAtTranslate(frame.payload) {
		return fail(full, javaInvalid(1007))
	}
	return frame, 0, nil, nil
}

// dfaAcceptsAtTranslate mirrors Charsetfunctions.isValidUTF8: the DFA only
// reports failure when it reaches the error state, so a payload ending in a
// valid-but-incomplete multi-byte prefix is accepted at translate time.
func dfaAcceptsAtTranslate(payload []byte) bool {
	i := 0
	for i < len(payload) {
		r, size := utf8.DecodeRune(payload[i:])
		if r == utf8.RuneError && size <= 1 {
			return isIncompleteUTF8Tail(payload[i:])
		}
		i += size
	}
	return true
}

// isIncompleteUTF8Tail reports whether the bytes are a strict prefix of one
// valid UTF-8 sequence (the DFA's non-error, non-accept end state).
func isIncompleteUTF8Tail(tail []byte) bool {
	if len(tail) == 0 {
		return false
	}
	first := tail[0]
	var need int
	var secondLow, secondHigh byte = 0x80, 0xbf
	switch {
	case first >= 0xc2 && first <= 0xdf:
		need = 2
	case first == 0xe0:
		need, secondLow = 3, 0xa0
	case first >= 0xe1 && first <= 0xec:
		need = 3
	case first == 0xed:
		need, secondHigh = 3, 0x9f
	case first >= 0xee && first <= 0xef:
		need = 3
	case first == 0xf0:
		need, secondLow = 4, 0x90
	case first >= 0xf1 && first <= 0xf3:
		need = 4
	case first == 0xf4:
		need, secondHigh = 4, 0x8f
	default:
		return false
	}
	if len(tail) >= need {
		return false
	}
	for i := 1; i < len(tail); i++ {
		low, high := byte(0x80), byte(0xbf)
		if i == 1 {
			low, high = secondLow, secondHigh
		}
		if tail[i] < low || tail[i] > high {
			return false
		}
	}
	return true
}

// screenIncompleteHeader mirrors the header checks the runtime performs
// before discovering a frame is incomplete.
func (d *deriver) screenIncompleteHeader(data []byte) (int, *scenarioError, error) {
	b1, b2 := data[0], data[1]
	opcode := b1 & 0x0f
	marker := int(b2 & 0x7f)
	if !validOpcode(opcode) {
		err := javaInvalid(1002)
		return 2, &err, nil
	}
	isControl := opcode == byte(OpcodeClose) || opcode == byte(OpcodePing) ||
		opcode == byte(OpcodePong)
	if isControl && marker >= 126 && d.behavior.ControlPayloadLimit <= 125 {
		err := javaInvalid(1002)
		return 2, &err, nil
	}
	length := -1
	site := 2
	if marker <= 125 {
		length = marker
	} else if marker == 126 && len(data) >= 4 {
		length = int(data[2])<<8 | int(data[3])
		site = 4
	} else if marker == 127 && len(data) >= 10 {
		return 0, nil, unsupportedError{"64-bit lengths beyond the generated space"}
	}
	if length >= 0 {
		if isControl && length > d.behavior.ControlPayloadLimit {
			err := javaInvalid(1002)
			return site, &err, nil
		}
		if d.behavior.EnforceFrameSizeLimit && length > d.limits.MaxBufferedBytes {
			err := javaInvalid(1009)
			return site, &err, nil
		}
	}
	return 0, nil, nil
}

func validOpcode(op byte) bool {
	switch Opcode(op) {
	case OpcodeContinuous, OpcodeText, OpcodeBinary, OpcodeClose, OpcodePing, OpcodePong:
		return true
	}
	return false
}

// parseCloseSemantics mirrors CloseFrame.setPayload followed by isValid:
//   - empty payload -> code 1000, reason ""
//   - one byte      -> code 1002, reason "" (valid)
//   - >= two bytes  -> big-endian code + UTF-8 reason; an invalid reason
//     becomes code 1007 with a null reason, and isValid's reason.isEmpty()
//     then raises a NullPointerException -> JAVA_RUNTIME_REJECTION
//
// isValid rejections: 1007 with empty reason -> 1007; 1005 with a reason,
// 1016-2999, {<1000, 1004, 1005, 1006, 1015, >4999} -> 1002.
func (d *deriver) parseCloseSemantics(payload []byte) (int, string, *scenarioError, error) {
	code := 1005
	reason := ""
	switch {
	case len(payload) == 0:
		code = 1000
	case len(payload) == 1:
		code = 1002
	default:
		code = int(payload[0])<<8 | int(payload[1])
		if d.behavior.ValidateUTF8 && !utf8.Valid(payload[2:]) {
			err := javaRuntimeRejection()
			return 0, "", &err, nil
		}
		reason = string(payload[2:])
	}
	if d.behavior.EnforceCloseCodeValidity {
		if failCode, failed := closeIsValidRejection(code, reason); failed {
			err := javaInvalid(failCode)
			return 0, "", &err, nil
		}
	}
	return code, reason, nil, nil
}

// closeIsValidRejection mirrors CloseFrame.isValid's rejection chain and
// returns the close code the adapter reports.
func closeIsValidRejection(code int, reason string) (int, bool) {
	if code == 1007 && reason == "" {
		return 1007, true
	}
	if code == 1005 && reason != "" {
		return 1002, true
	}
	if code > 1015 && code < 3000 {
		return 1002, true
	}
	if code == 1006 || code == 1015 || code == 1005 || code > 4999 || code < 1000 || code == 1004 {
		return 1002, true
	}
	return 0, false
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
		code, reason, closeErr, unsupported := d.parseCloseSemantics(frame.payload)
		if unsupported != nil {
			return unsupported
		}
		if closeErr != nil {
			// Unreachable: decodeFrame already applied close semantics.
			return *closeErr
		}
		wasClosing := d.state == "closing"
		d.closeDetail = d.closeMap("remote", code, reason, true, true)
		d.event("close", index, d.closeDetail)
		if wasClosing {
			d.transition("closed", "receive_close", index)
			return nil
		}
		if d.behavior.EchoCloseWhileOpen {
			// The echoed frame object carries the constructor payload.
			if err := d.emitOutbound(index, "echo_close", WireFrame{
				Fin: true, Opcode: OpcodeClose,
				Payload: closeFrameConstructorPayload,
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
// continuation frames, then the adapter's message-buffer accounting. The
// pinned runtime checks the cumulative fragment total only at starts and
// fins (checkBufferLimit); a non-fin continuation that overflows trips the
// adapter's own accounting instead (BUFFER_LIMIT_EXCEEDED, no close code).
func (d *deriver) processDataFrame(frame decodedFrame, index int) error {
	op := Opcode(frame.opcode)
	switch {
	case op != OpcodeContinuous && !frame.fin:
		// Fragment start (processFrameIsNotFin).
		if d.behavior.EnforceContinuationStart && d.javaFragOpcode != 0 {
			return javaInvalid(1002)
		}
		d.javaFragOpcode = frame.opcode
		d.javaFragPayload = append([]byte{}, frame.payload...)
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
		// Adapter addBounded: the counter is only updated within bounds.
		if d.messageBuffered+len(frame.payload) > d.limits.MaxBufferedBytes {
			return protocolError("BUFFER_LIMIT_EXCEEDED")
		}
		d.messageBuffered += len(frame.payload)
		return nil
	case op == OpcodeContinuous && frame.fin:
		if d.javaFragOpcode == 0 {
			if d.behavior.EnforceContinuationStart {
				return javaInvalid(1002)
			}
			return nil
		}
		// processFrameIsFin: addToBufferList + checkBufferLimit before
		// assembly and emission.
		assembledSize := len(d.javaFragPayload) + len(frame.payload)
		if d.behavior.EnforceFrameSizeLimit && assembledSize > d.limits.MaxBufferedBytes {
			return javaInvalid(1009)
		}
		assembled := append(append([]byte{}, d.javaFragPayload...), frame.payload...)
		messageOpcode := Opcode(d.javaFragOpcode)
		d.javaFragOpcode = 0
		d.javaFragPayload = nil
		if err := d.emitMessage(messageOpcode, assembled, index); err != nil {
			return err
		}
		d.messageBuffered = 0
		return nil
	default:
		// Unfragmented data frame.
		if d.javaFragOpcode != 0 && d.behavior.EnforceContinuationStart {
			return javaInvalid(1002)
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

// inboundFrameRecord mirrors OracleEngine.frame for inbound frames. Close
// frames record the constructor payload, never the wire payload.
func (d *deriver) inboundFrameRecord(frame decodedFrame, step int) map[string]any {
	payload := frame.payload
	if frame.opcode == byte(OpcodeClose) {
		payload = closeFrameConstructorPayload
	}
	return map[string]any{
		"direction":      "inbound",
		"fin":            frame.fin,
		"masked":         frame.masked,
		"opcode":         Opcode(frame.opcode).Name(),
		"payload_base64": base64Std(payload),
		"payload_bytes":  len(payload),
		"rsv1":           frame.rsv1,
		"rsv2":           frame.rsv2,
		"rsv3":           frame.rsv3,
		"step":           step,
		"wire_bytes":     frame.wire,
	}
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
	// The adapter increments the counter before the limit check, so the
	// rejected action is included in the failure counts.
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
		// sendControl performs no payload-size check: ControlFrame.isValid
		// only checks fin and reserved bits, so oversized control payloads
		// are sent successfully by the pinned runtime.
		if err := d.requireOpen(); err != nil {
			return err
		}
		payload, err := step.payload()
		if err != nil {
			return unsupportedError{err.Error()}
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

// sendClose mirrors OracleEngine.sendClose over CloseFrame.setCode (which
// normalizes 1015 to 1005), setReason, and isValid.
func (d *deriver) sendClose(step Step, index int) error {
	if err := d.requireOpen(); err != nil {
		return err
	}
	code := step.Code
	if code == 1015 {
		code = 1005
	}
	if d.behavior.EnforceCloseCodeValidity {
		if failCode, failed := closeIsValidRejection(code, step.Reason); failed {
			return javaInvalid(failCode)
		}
	}
	payload := append([]byte{byte(code >> 8), byte(code)}, []byte(step.Reason)...)
	if err := d.emitOutbound(index, "send_close", WireFrame{
		Fin: true, Opcode: OpcodeClose, Payload: payload}); err != nil {
		return err
	}
	d.closeDetail = d.closeMap("local", code, step.Reason, false, false)
	d.event("close_initiated", index, d.closeDetail)
	d.transition("closing", "send_close", index)
	return nil
}

// sendFragment mirrors Draft.continuousFrame: the first call keeps the
// declared opcode (including a fin=true single-frame message); later calls
// emit continuation frames until a fin closes the sequence.
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
		// Draft.continuousFrame builds a TextFrame whose isValid applies the
		// DFA: rejected content becomes NotSendable -> IllegalArgumentException,
		// which the adapter reports as JAVA_NOT_SENDABLE; truncated tails pass.
		if declared == byte(OpcodeText) && d.behavior.ValidateUTF8 &&
			!dfaAcceptsAtTranslate(payload) {
			return protocolError("JAVA_NOT_SENDABLE")
		}
		wireOpcode = Opcode(declared)
		if !step.Fin {
			d.sendFragmentOpen = declared
		}
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
