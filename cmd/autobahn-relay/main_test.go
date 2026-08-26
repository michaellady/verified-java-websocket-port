package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestListenRelayPairsExactlyOneAttachedSession(t *testing.T) {
	port := freePort(t)
	address := "127.0.0.1:" + strconv.Itoa(port)
	var input bytes.Buffer
	if err := writeFrame(&input, frameData, []byte("attach-to-test")); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&input, frameEnd, nil); err != nil {
		t.Fatal(err)
	}
	var framedOutput bytes.Buffer
	var lifecycle bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- runListenRelay(address, net.ParseIP("127.0.0.1"), &input, &framedOutput, &lifecycle) }()
	testConnection := dialFrom(t, "127.0.0.1", address)
	buffer := make([]byte, len("attach-to-test"))
	if _, err := io.ReadFull(testConnection, buffer); err != nil || string(buffer) != "attach-to-test" {
		t.Fatalf("forward mismatch: %q %v", buffer, err)
	}
	if second, err := net.DialTimeout("tcp4", address, 100*time.Millisecond); err == nil {
		_ = second.Close()
		t.Fatal("second test session accepted")
	}
	if _, err := testConnection.Write([]byte("test-to-attach")); err != nil {
		t.Fatal(err)
	}
	if err := testConnection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not terminate")
	}
	var output bytes.Buffer
	if err := copyFramedInput(bytes.NewReader(framedOutput.Bytes()), &output); err != nil {
		t.Fatalf("framed output rejected: %v", err)
	}
	if output.String() != "test-to-attach" {
		t.Fatalf("raw output was corrupted: %q", output.String())
	}
	for _, marker := range []string{"RELAY_READY role=listen test=9010", "RELAY_PAIRED role=listen", "RELAY_COMPLETE role=listen"} {
		if !strings.Contains(lifecycle.String(), marker) {
			t.Fatalf("missing lifecycle proof %q: %q", marker, lifecycle.String())
		}
	}
}

func TestFramingRejectsMalformedSequences(t *testing.T) {
	frame := func(frameType byte, length uint32, payload []byte) []byte {
		value := make([]byte, frameHeaderBytes+len(payload))
		value[0] = frameType
		binary.BigEndian.PutUint32(value[1:], length)
		copy(value[frameHeaderBytes:], payload)
		return value
	}
	validData := frame(frameData, 1, []byte("x"))
	end := frame(frameEnd, 0, nil)
	for name, value := range map[string][]byte{
		"missing end":    validData,
		"truncated head": {frameData, 0},
		"truncated data": frame(frameData, 2, []byte("x")),
		"unknown":        frame(9, 0, nil),
		"zero data":      frame(frameData, 0, nil),
		"oversize data":  frame(frameData, maximumFramePayload+1, nil),
		"end payload":    frame(frameEnd, 1, []byte("x")),
		"duplicate end":  append(append([]byte(nil), end...), end...),
		"data after end": append(append([]byte(nil), end...), validData...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := copyFramedInput(bytes.NewReader(value), io.Discard); err == nil {
				t.Fatal("malformed frame sequence accepted")
			}
		})
	}
	valid := append(append([]byte(nil), validData...), end...)
	var decoded bytes.Buffer
	if err := copyFramedInput(bytes.NewReader(valid), &decoded); err != nil || decoded.String() != "x" {
		t.Fatalf("valid framing rejected: %q %v", decoded.String(), err)
	}
}

func TestFramedOutputTreatsVerifiedPeerResetAsTerminal(t *testing.T) {
	var framed bytes.Buffer
	if err := copyFramedOutput(&dataThenErrorReader{data: []byte("response"), err: syscall.ECONNRESET}, &framed); err != nil {
		t.Fatalf("verified peer reset rejected after bounded response bytes: %v", err)
	}
	var decoded bytes.Buffer
	if err := copyFramedInput(bytes.NewReader(framed.Bytes()), &decoded); err != nil || decoded.String() != "response" {
		t.Fatalf("terminal reset framing mismatch: %q %v", decoded.String(), err)
	}
	if err := copyFramedOutput(&dataThenErrorReader{err: errors.New("unexpected read failure")}, io.Discard); err == nil || err.Error() != "transport" {
		t.Fatalf("unknown read failure accepted: %v", err)
	}
}

func TestFramedInputDrainsAfterVerifiedPeerStopsReading(t *testing.T) {
	var framed bytes.Buffer
	if err := writeFrame(&framed, frameData, []byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&framed, frameEnd, nil); err != nil {
		t.Fatal(err)
	}
	if err := copyFramedInput(bytes.NewReader(framed.Bytes()), &fixedErrorWriter{err: syscall.EPIPE}); err != nil {
		t.Fatalf("verified peer terminal write rejected: %v", err)
	}
	if err := copyFramedInput(bytes.NewReader(framed.Bytes()), &fixedErrorWriter{err: errors.New("unexpected write failure")}); err == nil || err.Error() != "transport" {
		t.Fatalf("unknown write failure accepted: %v", err)
	}
	malformed := append(append([]byte(nil), framed.Bytes()[:len(framed.Bytes())-frameHeaderBytes]...), 9, 0, 0, 0, 0)
	if err := copyFramedInput(bytes.NewReader(malformed), &fixedErrorWriter{err: syscall.EPIPE}); err == nil || err.Error() != "unknown-frame" {
		t.Fatalf("malformed trailing frame accepted after terminal write: %v", err)
	}
}

func TestListenRelayRejectsUnknownPeer(t *testing.T) {
	port := freePort(t)
	done := make(chan error, 1)
	go func() {
		done <- runListenRelay("127.0.0.1:"+strconv.Itoa(port), net.ParseIP("127.0.0.2"), bytes.NewReader(nil), io.Discard, io.Discard)
	}()
	connection := dialFrom(t, "127.0.0.1", "127.0.0.1:"+strconv.Itoa(port))
	_ = connection.Close()
	select {
	case err := <-done:
		if err == nil || err.Error() != "unknown-peer" {
			t.Fatalf("unexpected denial: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not reject peer")
	}
}

func TestDialRelayRejectsAnyNonFixedTarget(t *testing.T) {
	if err := runDialRelay("127.0.0.1:9001", bytes.NewReader(nil), io.Discard, io.Discard); err == nil || err.Error() != "dial-target" {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestDialRelayWaitsForAttachAndPreservesFirstFrame(t *testing.T) {
	input, attached := io.Pipe()
	defer input.Close()
	ready := make(chan io.Reader, 1)
	failure := make(chan error, 1)
	go func() {
		reader, err := waitForAttachedInput(input, time.Now().Add(2*time.Second))
		if err != nil {
			failure <- err
			return
		}
		ready <- reader
	}()
	select {
	case <-ready:
		t.Fatal("dial relay passed its attach gate before framed input arrived")
	case err := <-failure:
		t.Fatalf("attach gate failed early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	go func() {
		defer attached.Close()
		if err := writeFrame(attached, frameData, []byte("request")); err != nil {
			return
		}
		_ = writeFrame(attached, frameEnd, nil)
	}()
	select {
	case reader := <-ready:
		var decoded bytes.Buffer
		if err := copyFramedInput(reader, &decoded); err != nil || decoded.String() != "request" {
			t.Fatalf("first attach frame was not preserved: %q %v", decoded.String(), err)
		}
	case err := <-failure:
		t.Fatalf("attach gate failed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("dial relay attach gate exceeded its bound")
	}
}

func TestExactPeerRejectsPublicAndMissingValues(t *testing.T) {
	t.Setenv("AUTOBAHN_RELAY_TEST_PEER", "8.8.8.8")
	if _, err := exactPeer("AUTOBAHN_RELAY_TEST_PEER"); err == nil {
		t.Fatal("public peer accepted")
	}
	if _, err := exactPeer("AUTOBAHN_RELAY_MISSING"); err == nil {
		t.Fatal("missing peer accepted")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func dialFrom(t *testing.T, source, destination string) *net.TCPConn {
	t.Helper()
	var last error
	for attempt := 0; attempt < 50; attempt++ {
		connection, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}).Dial("tcp4", destination)
		if err == nil {
			return connection.(*net.TCPConn)
		}
		last = err
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("dial failed: %v", last)
	return nil
}

type dataThenErrorReader struct {
	data []byte
	err  error
}

type fixedErrorWriter struct {
	err error
}

func (writer *fixedErrorWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

func (reader *dataThenErrorReader) Read(destination []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, reader.err
	}
	read := copy(destination, reader.data)
	reader.data = reader.data[read:]
	return read, reader.err
}
