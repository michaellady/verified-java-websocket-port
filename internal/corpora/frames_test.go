package corpora

import (
	"bytes"
	"testing"
)

// RFC 6455 section 5.7 example vectors pin the wire codec.
func TestEncodeFrameMatchesRFC6455Examples(t *testing.T) {
	unmasked := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText, Payload: []byte("Hello")}, nil)
	if !bytes.Equal(unmasked, []byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}) {
		t.Fatalf("unmasked Hello mismatch: %x", unmasked)
	}
	mask := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	masked := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText, Payload: []byte("Hello")}, &mask)
	if !bytes.Equal(masked, []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}) {
		t.Fatalf("masked Hello mismatch: %x", masked)
	}
	ping := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodePing, Payload: []byte("Hello")}, nil)
	if !bytes.Equal(ping[:2], []byte{0x89, 0x05}) {
		t.Fatalf("ping header mismatch: %x", ping[:2])
	}
}

func TestEncodeFrameExtendedLengths(t *testing.T) {
	payload256 := make([]byte, 256)
	frame := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeBinary, Payload: payload256}, nil)
	if !bytes.Equal(frame[:4], []byte{0x82, 0x7e, 0x01, 0x00}) {
		t.Fatalf("16-bit length header mismatch: %x", frame[:4])
	}
	if len(frame) != 4+256 {
		t.Fatalf("16-bit frame size = %d", len(frame))
	}
	payload64k := make([]byte, 65536)
	frame64 := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeBinary, Payload: payload64k}, nil)
	if !bytes.Equal(frame64[:10], []byte{0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0}) {
		t.Fatalf("64-bit length header mismatch: %x", frame64[:10])
	}
}

func TestEncodeFrameControlBitsAndRSV(t *testing.T) {
	frame := EncodeFrame(WireFrame{Fin: false, Opcode: OpcodeText, RSV1: true, Payload: nil}, nil)
	if frame[0] != 0x41 {
		t.Fatalf("rsv1 non-fin text header = %02x", frame[0])
	}
	cont := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeContinuous, Payload: []byte{1}}, nil)
	if cont[0] != 0x80 {
		t.Fatalf("fin continuation header = %02x", cont[0])
	}
}

// WireLength mirrors the adapter's independent frame-length accounting so
// buffered-byte expectations reconcile with the oracle's WireTracker.
func TestWireLengthAccounting(t *testing.T) {
	mask := [4]byte{1, 2, 3, 4}
	frame := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText, Payload: []byte("abc")}, &mask)
	if got := len(frame); got != 2+4+3 {
		t.Fatalf("masked frame length = %d", got)
	}
}
