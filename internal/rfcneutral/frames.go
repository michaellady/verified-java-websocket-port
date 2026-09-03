package rfcneutral

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

// Opcodes, section 5.2.
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// frame is one decoded WebSocket frame header plus its payload.
type frame struct {
	fin     bool
	rsv     byte // the three reserved bits, still in their high positions
	opcode  byte
	masked  bool
	payload []byte
	// wire is how many octets the frame occupied, used only to advance.
	wire int
}

func (f frame) isControl() bool { return f.opcode&0x8 != 0 }

// violation is a rule this stream broke. ruleID indexes the table in rules.go.
type violation struct {
	ruleID string
	detail string
}

func (v violation) Error() string { return v.ruleID + ": " + v.detail }

// errNeedMore says the buffer does not yet hold a whole frame. It is not a
// violation: section 5.2 has the endpoint wait for more octets.
type errNeedMore struct{ have, want int }

func (e errNeedMore) Error() string {
	return fmt.Sprintf("frame header or payload incomplete: have %d octets, need at least %d", e.have, e.want)
}

// decodeFrame reads one frame from the head of buf, applying only the rules
// that are decidable from the frame's own octets. It returns errNeedMore when
// the buffer is short, and a violation when a rule in rules.go is broken.
//
// maxBuffered is the scenario's own declared max_buffered_bytes. A declared
// payload length above it is not an RFC violation, so decodeFrame reports it
// as a harness-limit abstention rather than a failure.
func decodeFrame(buf []byte, serverRole bool, maxBuffered uint64) (frame, error) {
	if len(buf) < 2 {
		return frame{}, errNeedMore{have: len(buf), want: 2}
	}
	var f frame
	f.fin = buf[0]&0x80 != 0
	f.rsv = buf[0] & 0x70
	f.opcode = buf[0] & 0x0F
	f.masked = buf[1]&0x80 != 0
	length := uint64(buf[1] & 0x7F)
	off := 2

	switch length {
	case 126:
		if len(buf) < off+2 {
			return frame{}, errNeedMore{have: len(buf), want: off + 2}
		}
		length = uint64(binary.BigEndian.Uint16(buf[off : off+2]))
		off += 2
		if length < 126 {
			return frame{}, violation{RuleNonMinimalLength,
				fmt.Sprintf("a 16-bit extended length encodes %d, which fits in the 7-bit field", length)}
		}
	case 127:
		if len(buf) < off+8 {
			return frame{}, errNeedMore{have: len(buf), want: off + 8}
		}
		length = binary.BigEndian.Uint64(buf[off : off+8])
		off += 8
		if length&(1<<63) != 0 {
			return frame{}, violation{RuleLength64HighBit,
				"the most significant bit of the 64-bit length is set"}
		}
		if length < 65536 {
			return frame{}, violation{RuleNonMinimalLength,
				fmt.Sprintf("a 64-bit extended length encodes %d, which fits in 16 bits or in the 7-bit field", length)}
		}
	}

	// Rules decidable from the header alone, in table order.
	if f.masked && !serverRole {
		return frame{}, violation{RuleMaskedToClient,
			"the endpoint under test is a client and this inbound frame from the server sets MASK"}
	}
	if !f.masked && serverRole {
		return frame{}, violation{RuleUnmaskedToServer,
			"the endpoint under test is a server and this inbound frame from the client does not set MASK"}
	}
	if f.rsv != 0 {
		return frame{}, violation{RuleReservedBit,
			fmt.Sprintf("RSV bits 0x%02x are set and no extension is negotiated", f.rsv>>4)}
	}
	switch f.opcode {
	case opContinuation, opText, opBinary, opClose, opPing, opPong:
	default:
		return frame{}, violation{RuleReservedOpcode,
			fmt.Sprintf("opcode 0x%x is reserved", f.opcode)}
	}
	if f.isControl() {
		if length > 125 {
			return frame{}, violation{RuleControlOversize,
				fmt.Sprintf("control frame opcode 0x%x carries a payload length of %d", f.opcode, length)}
		}
		if !f.fin {
			return frame{}, violation{RuleControlFragmented,
				fmt.Sprintf("control frame opcode 0x%x has FIN clear", f.opcode)}
		}
	}

	if length > maxBuffered {
		return frame{}, harnessLimit{fmt.Sprintf(
			"the frame declares a payload of %d octets and the scenario's own max_buffered_bytes is %d", length, maxBuffered)}
	}

	if f.masked {
		if len(buf) < off+4 {
			return frame{}, errNeedMore{have: len(buf), want: off + 4}
		}
		off += 4
	}
	end := off + int(length)
	if uint64(off)+length > uint64(len(buf)) {
		return frame{}, errNeedMore{have: len(buf), want: off + int(length)}
	}
	f.payload = append([]byte(nil), buf[off:end]...)
	if f.masked {
		key := buf[off-4 : off]
		for i := range f.payload {
			f.payload[i] ^= key[i%4]
		}
	}
	f.wire = end
	return f, nil
}

// harnessLimit says the run met a bound the scenario declares and RFC 6455 does
// not state. It abstains rather than deciding.
type harnessLimit struct{ detail string }

func (h harnessLimit) Error() string { return AbstainHarnessLimit + ": " + h.detail }

// checkClosePayload applies the Close-frame rules of sections 5.5.1 and 7.4.
func checkClosePayload(p []byte) error {
	switch {
	case len(p) == 0:
		return nil
	case len(p) == 1:
		return violation{RuleCloseBodyLength1,
			"the Close frame carries a one-octet body, which cannot hold the 2-byte status code"}
	}
	code := binary.BigEndian.Uint16(p[:2])
	if !validCloseCode(code) {
		return violation{RuleCloseCodeInvalid,
			fmt.Sprintf("the Close frame carries status code %d, which section 7.4 does not define for the wire", code)}
	}
	if !utf8.Valid(p[2:]) {
		return violation{RuleCloseReasonNotUTF8,
			"the Close frame's reason is not valid UTF-8"}
	}
	return nil
}
