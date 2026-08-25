package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	listenAddress       = "0.0.0.0:9010"
	fuzzingServer       = "172.30.242.4:9001"
	maximumDirection    = int64(256 << 20)
	sessionLifetime     = 180 * time.Second
	dialAttemptInterval = 50 * time.Millisecond
	frameData           = byte(1)
	frameEnd            = byte(2)
	frameHeaderBytes    = 5
	maximumFramePayload = 64 << 10
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "RELAY_DENIED arguments")
		os.Exit(2)
	}
	role, exists := os.LookupEnv("AUTOBAHN_RELAY_ROLE")
	if !exists || strings.TrimSpace(role) != role {
		fmt.Fprintln(os.Stderr, "RELAY_DENIED role")
		os.Exit(2)
	}
	var err error
	switch role {
	case "listen":
		peer, peerErr := exactPeer("AUTOBAHN_RELAY_TEST_PEER")
		if peerErr != nil {
			fmt.Fprintln(os.Stderr, "RELAY_DENIED test-peer")
			os.Exit(2)
		}
		err = runListenRelay(listenAddress, peer, os.Stdin, os.Stdout, os.Stderr)
	case "dial":
		if _, unexpected := os.LookupEnv("AUTOBAHN_RELAY_TEST_PEER"); unexpected {
			fmt.Fprintln(os.Stderr, "RELAY_DENIED test-peer")
			os.Exit(2)
		}
		err = runDialRelay(fuzzingServer, os.Stdin, os.Stdout, os.Stderr)
	default:
		fmt.Fprintln(os.Stderr, "RELAY_DENIED role")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "RELAY_DENIED "+sanitize(err.Error()))
		os.Exit(1)
	}
}

func exactPeer(name string) (net.IP, error) {
	value, exists := os.LookupEnv(name)
	if !exists || strings.TrimSpace(value) != value {
		return nil, errors.New("missing exact peer")
	}
	peer := net.ParseIP(value).To4()
	if peer == nil || !(peer[0] == 10 || peer[0] == 172 && peer[1] >= 16 && peer[1] <= 31 || peer[0] == 192 && peer[1] == 168) {
		return nil, errors.New("peer is not private IPv4")
	}
	return peer, nil
}

func runListenRelay(bind string, peer net.IP, input io.Reader, output, lifecycle io.Writer) error {
	listener, err := net.Listen("tcp4", bind)
	if err != nil {
		return errors.New("test-listen")
	}
	defer listener.Close()
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		return errors.New("test-listener-type")
	}
	deadline := time.Now().Add(sessionLifetime)
	if err := tcpListener.SetDeadline(deadline); err != nil {
		return errors.New("test-deadline")
	}
	fmt.Fprintln(lifecycle, "RELAY_READY role=listen test=9010")
	connection, err := tcpListener.AcceptTCP()
	if err != nil {
		return errors.New("test-accept")
	}
	defer connection.Close()
	if err := listener.Close(); err != nil {
		return errors.New("test-close")
	}
	if err := verifyPeer(connection, peer, tcpListener.Addr().(*net.TCPAddr).Port); err != nil {
		return err
	}
	return bridgeAttachedSession(connection, input, output, lifecycle, "listen", deadline)
}

func runDialRelay(target string, input io.Reader, output, lifecycle io.Writer) error {
	if target != fuzzingServer {
		return errors.New("dial-target")
	}
	deadline := time.Now().Add(sessionLifetime)
	fmt.Fprintln(lifecycle, "RELAY_READY role=dial target=172.30.242.4:9001")
	dialer := net.Dialer{Timeout: time.Second}
	var connection *net.TCPConn
	for time.Now().Before(deadline) {
		raw, err := dialer.Dial("tcp4", target)
		if err == nil {
			var ok bool
			connection, ok = raw.(*net.TCPConn)
			if !ok {
				_ = raw.Close()
				return errors.New("dial-type")
			}
			break
		}
		time.Sleep(dialAttemptInterval)
	}
	if connection == nil {
		return errors.New("dial-timeout")
	}
	defer connection.Close()
	remote, ok := connection.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.IP.String() != "172.30.242.4" || remote.Port != 9001 {
		return errors.New("dial-peer")
	}
	return bridgeAttachedSession(connection, input, output, lifecycle, "dial", deadline)
}

func bridgeAttachedSession(connection *net.TCPConn, input io.Reader, output, lifecycle io.Writer, role string, deadline time.Time) error {
	if err := connection.SetDeadline(deadline); err != nil {
		return errors.New("session-deadline")
	}
	fmt.Fprintln(lifecycle, "RELAY_PAIRED role="+role)
	results := make(chan error, 2)
	go attachedInputDirection(results, input, connection)
	go attachedOutputDirection(results, connection, output)
	for count := 0; count < 2; count++ {
		if transferErr := <-results; transferErr != nil {
			return transferErr
		}
	}
	fmt.Fprintln(lifecycle, "RELAY_COMPLETE role="+role)
	return nil
}

func attachedInputDirection(result chan<- error, source io.Reader, destination *net.TCPConn) {
	if err := copyFramedInput(source, destination); err != nil {
		result <- err
		return
	}
	_ = destination.CloseWrite()
	result <- nil
}

func attachedOutputDirection(result chan<- error, source *net.TCPConn, destination io.Writer) {
	if err := copyFramedOutput(source, destination); err != nil {
		result <- err
		return
	}
	_ = source.CloseRead()
	result <- nil
}

func copyFramedInput(source io.Reader, destination io.Writer) error {
	reader := bufio.NewReaderSize(source, maximumFramePayload+frameHeaderBytes)
	var total int64
	for {
		header := make([]byte, frameHeaderBytes)
		if _, err := io.ReadFull(reader, header); err != nil {
			return errors.New("truncated-frame")
		}
		frameType := header[0]
		length := int64(binary.BigEndian.Uint32(header[1:]))
		switch frameType {
		case frameData:
			if length < 1 || length > maximumFramePayload || total > maximumDirection-length {
				return errors.New("frame-limit")
			}
			payload := make([]byte, int(length))
			if _, err := io.ReadFull(reader, payload); err != nil {
				return errors.New("truncated-frame")
			}
			written, err := destination.Write(payload)
			if err != nil || written != len(payload) {
				return errors.New("transport")
			}
			total += length
		case frameEnd:
			if length != 0 {
				return errors.New("invalid-end")
			}
			if reader.Buffered() != 0 {
				return errors.New("data-after-end")
			}
			return nil
		default:
			return errors.New("unknown-frame")
		}
	}
}

func copyFramedOutput(source io.Reader, destination io.Writer) error {
	buffer := make([]byte, maximumFramePayload)
	var total int64
	for {
		read, err := source.Read(buffer)
		if read > 0 {
			if total > maximumDirection-int64(read) {
				return errors.New("frame-limit")
			}
			if err := writeFrame(destination, frameData, buffer[:read]); err != nil {
				return err
			}
			total += int64(read)
		}
		if err != nil {
			if !terminalReadError(err) {
				return errors.New("transport")
			}
			return writeFrame(destination, frameEnd, nil)
		}
	}
}

func terminalReadError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET)
}

func writeFrame(destination io.Writer, frameType byte, payload []byte) error {
	if frameType == frameData && (len(payload) == 0 || len(payload) > maximumFramePayload) || frameType == frameEnd && len(payload) != 0 || frameType != frameData && frameType != frameEnd {
		return errors.New("invalid-frame")
	}
	header := make([]byte, frameHeaderBytes)
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	for _, value := range [][]byte{header, payload} {
		if len(value) == 0 {
			continue
		}
		written, err := destination.Write(value)
		if err != nil || written != len(value) {
			return errors.New("transport")
		}
	}
	return nil
}

func verifyPeer(connection *net.TCPConn, expected net.IP, expectedLocalPort int) error {
	remote, ok := connection.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.IP.To4() == nil || !remote.IP.To4().Equal(expected.To4()) {
		return errors.New("unknown-peer")
	}
	local, ok := connection.LocalAddr().(*net.TCPAddr)
	if !ok || local.IP.To4() == nil || local.Port != expectedLocalPort {
		return errors.New("listener-binding")
	}
	return nil
}

func sanitize(value string) string {
	return strings.Map(func(character rune) rune {
		if character >= 'a' && character <= 'z' || character == '-' {
			return character
		}
		return '?'
	}, value)
}
