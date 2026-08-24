package lab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMavenCentralProxyOnlyTunnelsExactAuthority(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		connection, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		request := make([]byte, 4)
		if _, readErr := io.ReadFull(connection, request); readErr == nil && string(request) == "PING" {
			_, _ = connection.Write([]byte("PONG"))
		}
	}()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var audit bytes.Buffer
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- serveMavenCentralProxy(ctx, listener, &audit, func(context.Context) (net.Conn, error) {
			return net.DialTimeout("tcp4", upstream.Addr().String(), time.Second)
		})
	}()

	denied, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprint(denied, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	deniedLine, err := bufio.NewReader(denied).ReadString('\n')
	_ = denied.Close()
	if err != nil || !strings.Contains(deniedLine, "403") {
		t.Fatalf("wrong authority response=%q err=%v", deniedLine, err)
	}

	allowed, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(allowed)
	_, _ = fmt.Fprint(allowed, "CONNECT repo.maven.apache.org:443 HTTP/1.1\r\nHost: repo.maven.apache.org:443\r\n\r\n")
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("exact authority response=%q err=%v", status, err)
	}
	if output := audit.String(); !strings.Contains(output, `"result":"connected"`) {
		t.Fatalf("CONNECT 200 became visible before its audit record: %s", output)
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		if line == "\r\n" {
			break
		}
	}
	_, _ = allowed.Write([]byte("PING"))
	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil || string(reply) != "PONG" {
		t.Fatalf("tunnel reply=%q err=%v", reply, err)
	}
	_ = allowed.Close()
	<-upstreamDone

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not stop after cancellation")
	}
	if output := audit.String(); !strings.Contains(output, `"authority":"example.com:443"`) || !strings.Contains(output, `"result":"denied"`) || !strings.Contains(output, `"authority":"repo.maven.apache.org:443"`) || !strings.Contains(output, `"result":"connected"`) {
		t.Fatalf("audit output did not retain both decisions: %s", output)
	}
}

func TestMavenCentralProxyAuditFailureDeniesBeforeHijack(t *testing.T) {
	cases := map[string]*auditFailureWriter{
		"write": {writeErr: errors.New("disk unavailable")},
		"sync":  {syncErr: errors.New("sync unavailable")},
	}
	for name, writer := range cases {
		t.Run(name, func(t *testing.T) {
			upstream := &eofConn{}
			proxy := &mavenCentralProxy{
				audit: writer,
				dial:  func(context.Context) (net.Conn, error) { return upstream, nil },
			}
			response := &trackingHijackResponse{ResponseRecorder: httptest.NewRecorder()}
			request := httptest.NewRequest(http.MethodConnect, "https://"+MavenCentralAuthority, nil)
			request.Host = MavenCentralAuthority
			request.RequestURI = MavenCentralAuthority

			proxy.ServeHTTP(response, request)

			if response.Code != http.StatusInternalServerError || response.hijacked {
				t.Fatalf("audit failure status=%d hijacked=%v", response.Code, response.hijacked)
			}
			if !upstream.closed {
				t.Fatal("upstream was not closed after audit failure")
			}
			if proxy.sequence != 0 {
				t.Fatalf("failed audit advanced sequence to %d", proxy.sequence)
			}
		})
	}
}

func TestMavenCentralProxySyncFailurePoisonsAudit(t *testing.T) {
	writer := &auditFailureWriter{syncErr: errors.New("sync unavailable")}
	proxy := &mavenCentralProxy{audit: writer}
	first := proxy.writeAudit(MavenCentralAuthority, "connected")
	assertFinding(t, first, "MAVEN_PROXY_AUDIT_FAILED")
	writer.syncErr = nil
	second := proxy.writeAudit(MavenCentralAuthority, "denied")
	assertFinding(t, second, "MAVEN_PROXY_AUDIT_FAILED")
	if proxy.sequence != 0 || writer.writes != 1 {
		t.Fatalf("poisoned audit sequence=%d writes=%d", proxy.sequence, writer.writes)
	}
}

func TestMavenCentralProxyConcurrentAuditOrderIsSerialized(t *testing.T) {
	const records = 256
	var audit bytes.Buffer
	proxy := &mavenCentralProxy{audit: &audit}
	var wait sync.WaitGroup
	errorsSeen := make(chan error, records)
	for index := 0; index < records; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errorsSeen <- proxy.writeAudit(fmt.Sprintf("request-%03d.example:443", index), "denied")
		}(index)
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	lines := bytes.Split(bytes.TrimSpace(audit.Bytes()), []byte{'\n'})
	if len(lines) != records {
		t.Fatalf("audit records=%d want=%d", len(lines), records)
	}
	for index, line := range lines {
		var record mavenProxyAuditRecord
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("record %d: %v", index, err)
		}
		if record.Sequence != uint64(index+1) {
			t.Fatalf("record %d sequence=%d", index, record.Sequence)
		}
	}
}

func TestMavenCentralProxyRejectsNonLoopbackListener(t *testing.T) {
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	err = ServeMavenCentralProxy(context.Background(), listener, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "MAVEN_PROXY_LISTENER_DENIED") {
		t.Fatalf("non-loopback listener error=%v", err)
	}
}

type auditFailureWriter struct {
	writeErr error
	syncErr  error
	writes   int
}

func (w *auditFailureWriter) Write(data []byte) (int, error) {
	w.writes++
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return len(data), nil
}

func (w *auditFailureWriter) Sync() error { return w.syncErr }

type trackingHijackResponse struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (r *trackingHijackResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijacked = true
	return nil, nil, errors.New("unexpected hijack")
}

type eofConn struct {
	closed bool
}

func (c *eofConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *eofConn) Write(data []byte) (int, error)   { return len(data), nil }
func (c *eofConn) Close() error                     { c.closed = true; return nil }
func (c *eofConn) LocalAddr() net.Addr              { return staticAddr("local") }
func (c *eofConn) RemoteAddr() net.Addr             { return staticAddr("remote") }
func (c *eofConn) SetDeadline(time.Time) error      { return nil }
func (c *eofConn) SetReadDeadline(time.Time) error  { return nil }
func (c *eofConn) SetWriteDeadline(time.Time) error { return nil }

type staticAddr string

func (a staticAddr) Network() string { return string(a) }
func (a staticAddr) String() string  { return string(a) }
