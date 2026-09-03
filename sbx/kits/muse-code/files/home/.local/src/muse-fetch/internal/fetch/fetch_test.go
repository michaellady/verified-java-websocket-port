package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFetchPublishesVerifiedExecutable(t *testing.T) {
	t.Parallel()
	data := []byte("verified muse payload")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Accept-Encoding"); got != "identity" {
			http.Error(w, "unexpected Accept-Encoding", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()

	dir := t.TempDir()
	destination := filepath.Join(dir, "muse")
	err := (Downloader{Client: server.Client(), Timeout: time.Second}).Fetch(context.Background(), Artifact{
		URL: server.URL, SHA256: digest(data), Size: int64(len(data)), Destination: destination,
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("destination = %q, error = %v", got, err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != executableMode {
		t.Fatalf("mode = %v, want %v", info.Mode().Perm(), executableMode)
	}
	assertNoTemporaryFiles(t, dir)
}

func TestFetchRejectsInvalidPayloadAndPreservesDestination(t *testing.T) {
	t.Parallel()
	good := []byte("expected")
	tests := []struct {
		name     string
		body     []byte
		size     int64
		checksum string
	}{
		{name: "short body", body: good[:4], size: int64(len(good)), checksum: digest(good)},
		{name: "long body", body: append(append([]byte{}, good...), '!'), size: int64(len(good)), checksum: digest(good)},
		{name: "wrong digest", body: good, size: int64(len(good)), checksum: strings.Repeat("0", 64)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(test.body)
			}))
			defer server.Close()
			dir := t.TempDir()
			destination := filepath.Join(dir, "muse")
			old := []byte("existing executable")
			if err := os.WriteFile(destination, old, 0o700); err != nil {
				t.Fatal(err)
			}
			err := (Downloader{Client: server.Client(), Timeout: time.Second}).Fetch(context.Background(), Artifact{
				URL: server.URL, SHA256: test.checksum, Size: test.size, Destination: destination,
			})
			if err == nil {
				t.Fatal("Fetch() error = nil, want failure")
			}
			got, readErr := os.ReadFile(destination)
			if readErr != nil || !bytes.Equal(got, old) {
				t.Fatalf("destination = %q, error = %v", got, readErr)
			}
			assertNoTemporaryFiles(t, dir)
		})
	}
}

func TestFetchRejectsRedirectAndBoundsRead(t *testing.T) {
	t.Parallel()
	destinationRequests := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationRequests++
		_, _ = w.Write([]byte("payload"))
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, destination.URL, http.StatusFound)
	}))
	defer redirect.Close()
	dir := t.TempDir()
	err := (Downloader{Client: NewHTTPClient(time.Second), Timeout: time.Second}).Fetch(context.Background(), Artifact{
		URL: redirect.URL, SHA256: digest([]byte("payload")), Size: 7, Destination: filepath.Join(dir, "muse"),
	})
	if err == nil || !strings.Contains(err.Error(), "302 Found") || destinationRequests != 0 {
		t.Fatalf("redirect error = %v, destination requests = %d", err, destinationRequests)
	}

	body := &countingBody{reader: bytes.NewReader(bytes.Repeat([]byte("x"), 1024))}
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: body, Header: make(http.Header), ContentLength: -1, Request: request}, nil
	})}
	err = (Downloader{Client: client, Timeout: time.Second}).Fetch(context.Background(), Artifact{
		URL: "https://example.invalid/muse", SHA256: digest([]byte("xxx")), Size: 3, Destination: filepath.Join(dir, "muse"),
	})
	if err == nil || !strings.Contains(err.Error(), "received 4 bytes") || body.read != 4 {
		t.Fatalf("bounded read error = %v, bytes read = %d", err, body.read)
	}
}

func TestFetchRequiresSafeExplicitInputs(t *testing.T) {
	t.Parallel()
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("must not contact network")
	})}
	tests := []Artifact{
		{URL: "not-a-url", SHA256: strings.Repeat("0", 64), Size: 1, Destination: "/tmp/muse"},
		{URL: "https://example.invalid/muse", SHA256: "bad", Size: 1, Destination: "/tmp/muse"},
		{URL: "https://example.invalid/muse", SHA256: strings.Repeat("0", 64), Size: -1, Destination: "/tmp/muse"},
		{URL: "https://example.invalid/muse", SHA256: strings.Repeat("0", 64), Size: 1, Destination: "relative"},
	}
	for _, artifact := range tests {
		if err := (Downloader{Client: client, Timeout: time.Second}).Fetch(context.Background(), artifact); err == nil {
			t.Fatalf("unsafe artifact accepted: %#v", artifact)
		}
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

func assertNoTemporaryFiles(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".muse-fetch-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files = %v, error = %v", matches, err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type countingBody struct {
	reader io.Reader
	read   int
}

func (body *countingBody) Read(buffer []byte) (int, error) {
	count, err := body.reader.Read(buffer)
	body.read += count
	return count, err
}

func (*countingBody) Close() error { return nil }
