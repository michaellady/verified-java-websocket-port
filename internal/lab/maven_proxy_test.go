package lab

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
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
