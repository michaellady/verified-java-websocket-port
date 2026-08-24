package lab

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const MavenCentralAuthority = "repo.maven.apache.org:443"

type mavenProxyDial func(context.Context) (net.Conn, error)

type mavenProxyAuditRecord struct {
	SchemaVersion string `json:"schema_version"`
	Sequence      uint64 `json:"sequence"`
	Authority     string `json:"authority"`
	Result        string `json:"result"`
}

// ServeMavenCentralProxy exposes a loopback-only HTTP CONNECT proxy whose
// only possible upstream is the frozen Maven Central authority. It converts a
// hostname policy that macOS sandbox-exec cannot express into an auditable,
// fail-closed local transport boundary.
func ServeMavenCentralProxy(ctx context.Context, listener net.Listener, audit io.Writer) error {
	dialer := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return serveMavenCentralProxy(ctx, listener, audit, func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", MavenCentralAuthority)
	})
}

func serveMavenCentralProxy(ctx context.Context, listener net.Listener, audit io.Writer, dial mavenProxyDial) error {
	if ctx == nil || listener == nil || audit == nil || dial == nil {
		return finding("INVALID_MAVEN_PROXY", "$", "context, listener, audit writer, and fixed dialer are required")
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.IP == nil || !address.IP.IsLoopback() || address.Port == 0 {
		return finding("MAVEN_PROXY_LISTENER_DENIED", "$.listener", "Maven proxy must listen on one explicit loopback TCP port")
	}
	proxy := &mavenCentralProxy{audit: audit, dial: dial}
	server := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-stopped:
		}
	}()
	err := server.Serve(listener)
	close(stopped)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}

type mavenCentralProxy struct {
	audit       io.Writer
	dial        mavenProxyDial
	sequence    uint64
	mutex       sync.Mutex
	auditPoison error
}

func (p *mavenCentralProxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	authority := request.Host
	if request.Method != http.MethodConnect || authority != MavenCentralAuthority || request.RequestURI != MavenCentralAuthority || request.Header.Get("Proxy-Authorization") != "" {
		if err := p.writeAudit(authority, "denied"); err != nil {
			http.Error(response, "proxy audit unavailable", http.StatusInternalServerError)
			return
		}
		http.Error(response, "proxy authority denied", http.StatusForbidden)
		return
	}
	upstream, err := p.dial(request.Context())
	if err != nil {
		if auditErr := p.writeAudit(authority, "upstream-failed"); auditErr != nil {
			http.Error(response, "proxy audit unavailable", http.StatusInternalServerError)
			return
		}
		http.Error(response, "fixed upstream unavailable", http.StatusBadGateway)
		return
	}
	hijacker, ok := response.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		if err := p.writeAudit(authority, "transport-failed"); err != nil {
			http.Error(response, "proxy audit unavailable", http.StatusInternalServerError)
			return
		}
		http.Error(response, "tunnel unavailable", http.StatusInternalServerError)
		return
	}
	// A successful, durable audit record is a precondition for granting the
	// tunnel. In particular, no CONNECT 200 bytes can exist before this returns.
	if err := p.writeAudit(authority, "connected"); err != nil {
		_ = upstream.Close()
		http.Error(response, "proxy audit unavailable", http.StatusInternalServerError)
		return
	}
	downstream, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		_ = p.writeAudit(authority, "transport-failed")
		return
	}
	defer downstream.Close()
	defer upstream.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		_ = p.writeAudit(authority, "transport-failed")
		return
	}
	tunnel(downstream, buffered.Reader, upstream)
}

func (p *mavenCentralProxy) writeAudit(authority, result string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.auditPoison != nil {
		return p.auditPoison
	}
	record := mavenProxyAuditRecord{
		SchemaVersion: "1.0.0",
		Sequence:      p.sequence + 1,
		Authority:     authority,
		Result:        result,
	}
	data, err := json.Marshal(record)
	if err == nil {
		data = append(data, '\n')
		var written int
		written, err = p.audit.Write(data)
		if err == nil && written != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		if syncer, ok := p.audit.(interface{ Sync() error }); ok {
			err = syncer.Sync()
		}
	}
	if err != nil {
		p.auditPoison = finding("MAVEN_PROXY_AUDIT_FAILED", "$.audit", err.Error())
		return p.auditPoison
	}
	p.sequence = record.Sequence
	return nil
}

func tunnel(downstream net.Conn, buffered *bufio.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, buffered)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(downstream, upstream)
		closeWrite(downstream)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(connection net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if writer, ok := connection.(closeWriter); ok {
		_ = writer.CloseWrite()
	}
}

func MavenProxyAddress(listener net.Listener) (string, error) {
	if listener == nil {
		return "", fmt.Errorf("listener is nil")
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.IP == nil || !address.IP.IsLoopback() || address.Port == 0 {
		return "", finding("MAVEN_PROXY_LISTENER_DENIED", "$.listener", "Maven proxy must listen on one explicit loopback TCP port")
	}
	return address.String(), nil
}
