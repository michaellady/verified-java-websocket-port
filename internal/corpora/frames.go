package corpora

import "encoding/binary"

// Opcode is the RFC 6455 4-bit frame opcode.
type Opcode byte

// RFC 6455 section 5.2 opcodes plus the oracle's lowercase names.
const (
	OpcodeContinuous Opcode = 0x0
	OpcodeText       Opcode = 0x1
	OpcodeBinary     Opcode = 0x2
	OpcodeClose      Opcode = 0x8
	OpcodePing       Opcode = 0x9
	OpcodePong       Opcode = 0xA
)

// Name returns the java-oracle protocol name for an opcode.
func (o Opcode) Name() string {
	switch o {
	case OpcodeContinuous:
		return "continuous"
	case OpcodeText:
		return "text"
	case OpcodeBinary:
		return "binary"
	case OpcodeClose:
		return "closing"
	case OpcodePing:
		return "ping"
	case OpcodePong:
		return "pong"
	}
	return ""
}

// WireFrame is one RFC 6455 frame prior to wire encoding.
type WireFrame struct {
	Fin     bool
	RSV1    bool
	RSV2    bool
	RSV3    bool
	Opcode  Opcode
	Payload []byte
}

// EncodeFrame writes an RFC 6455 wire frame, masking the payload when a
// masking key is supplied (RFC 6455 sections 5.2 and 5.3).
func EncodeFrame(frame WireFrame, mask *[4]byte) []byte {
	header := byte(frame.Opcode) & 0x0f
	if frame.Fin {
		header |= 0x80
	}
	if frame.RSV1 {
		header |= 0x40
	}
	if frame.RSV2 {
		header |= 0x20
	}
	if frame.RSV3 {
		header |= 0x10
	}
	out := []byte{header}
	maskBit := byte(0)
	if mask != nil {
		maskBit = 0x80
	}
	length := len(frame.Payload)
	switch {
	case length <= 125:
		out = append(out, maskBit|byte(length))
	case length <= 0xffff:
		out = append(out, maskBit|126, 0, 0)
		binary.BigEndian.PutUint16(out[len(out)-2:], uint16(length))
	default:
		out = append(out, maskBit|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(out[len(out)-8:], uint64(length))
	}
	if mask != nil {
		out = append(out, mask[:]...)
		for i, b := range frame.Payload {
			out = append(out, b^mask[i%4])
		}
		return out
	}
	return append(out, frame.Payload...)
}

// headerSize returns the RFC 6455 header size for a payload length,
// excluding any masking key.
func headerSize(payloadLength int) int {
	switch {
	case payloadLength <= 125:
		return 2
	case payloadLength <= 0xffff:
		return 4
	default:
		return 10
	}
}

// outboundWireBytes mirrors Draft_6455.createBinaryFrame length accounting:
// header plus masking key (client role) plus payload.
func outboundWireBytes(payloadLength int, client bool) int {
	size := headerSize(payloadLength) + payloadLength
	if client {
		size += 4
	}
	return size
}
