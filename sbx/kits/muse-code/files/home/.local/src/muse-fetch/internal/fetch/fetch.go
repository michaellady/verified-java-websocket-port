// Package fetch downloads one explicitly described executable artifact.
// Version, platform, URL, checksum, and destination policy belong to the caller.
package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const executableMode = 0o755

// Artifact is a fully resolved download request. Fetch never selects a version
// or platform and never derives one field from another.
type Artifact struct {
	URL         string
	SHA256      string
	Size        int64
	Destination string
}

// Downloader performs bounded HTTP transport and atomic publication.
type Downloader struct {
	Client  *http.Client
	Timeout time.Duration
}

// NewHTTPClient returns the production client. Redirects are rejected so the
// explicitly supplied URL remains the only contacted origin.
func NewHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.ExpectContinueTimeout = time.Second
	transport.IdleConnTimeout = 30 * time.Second

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Fetch downloads artifact to a temporary file in the destination directory,
// verifies the exact byte count and SHA-256 digest, then atomically renames it.
// A failed fetch leaves any existing destination entry unchanged.
func (d Downloader) Fetch(ctx context.Context, artifact Artifact) error {
	if d.Client == nil {
		return errors.New("HTTP client is required")
	}
	if d.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if artifact.Size < 0 || artifact.Size == math.MaxInt64 {
		return fmt.Errorf("size must be between 0 and %d bytes", int64(math.MaxInt64-1))
	}
	if !filepath.IsAbs(artifact.Destination) {
		return errors.New("destination must be an absolute path")
	}

	parsedURL, err := url.ParseRequestURI(artifact.URL)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return errors.New("URL must be an absolute HTTP or HTTPS URL")
	}
	expectedDigest, err := decodeDigest(artifact.SHA256)
	if err != nil {
		return err
	}

	requestContext, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept-Encoding", "identity")

	response, err := d.Client.Do(request)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download: unexpected HTTP status %s", response.Status)
	}
	if response.ContentLength >= 0 && response.ContentLength != artifact.Size {
		return fmt.Errorf("download: Content-Length is %d, want %d", response.ContentLength, artifact.Size)
	}

	destinationDir := filepath.Dir(filepath.Clean(artifact.Destination))
	temporary, err := os.CreateTemp(destinationDir, ".muse-fetch-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	published := false
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		if !published {
			_ = os.Remove(temporaryPath)
		}
	}()

	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(response.Body, artifact.Size+1))
	if copyErr != nil {
		return fmt.Errorf("download body: %w", copyErr)
	}
	if written != artifact.Size {
		return fmt.Errorf("download: received %d bytes, want %d", written, artifact.Size)
	}
	if !bytes.Equal(hasher.Sum(nil), expectedDigest) {
		return errors.New("download: SHA-256 mismatch")
	}
	if err := temporary.Chmod(executableMode); err != nil {
		return fmt.Errorf("chmod temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		closed = true
		return fmt.Errorf("close temporary file: %w", err)
	}
	closed = true

	if err := os.Rename(temporaryPath, artifact.Destination); err != nil {
		return fmt.Errorf("publish destination: %w", err)
	}
	published = true
	return nil
}

func decodeDigest(value string) ([]byte, error) {
	if len(value) != sha256.Size*2 {
		return nil, errors.New("SHA-256 must contain exactly 64 hexadecimal characters")
	}
	digest, err := hex.DecodeString(value)
	if err != nil {
		return nil, errors.New("SHA-256 must contain exactly 64 hexadecimal characters")
	}
	return digest, nil
}
