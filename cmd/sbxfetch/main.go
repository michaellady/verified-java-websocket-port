// Command sbxfetch acquires every artifact a sandbox attempt needs, on the
// HOST, verifying each one against a PUBLISHED checksum before it is allowed
// anywhere near the sandbox.
//
// It exists because the accepted US-007 profile denies network inside the
// sandbox, so tools must be fetched host-side first (the tla2tools and
// rust-toolchain precedents, attempts 0125-0128 and 0126). The manifest is
// DATA: each entry names the artifact, the URL, the published sha256, and the
// source that published that digest, so the provenance chain is auditable
// without reading this program.
//
// Usage:
//
//	sbxfetch -manifest <fetch.json> -dir <staging dir> [-report <path>]
//
// A digest mismatch is a hard failure: the partial file is removed and the
// process exits nonzero. Nothing is "repaired" and nothing is retried with a
// relaxed check.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type fetchManifest struct {
	SchemaVersion string     `json:"schema_version"`
	Kind          string     `json:"kind"`
	Statement     string     `json:"statement"`
	Artifacts     []artifact `json:"artifacts"`
}

type artifact struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	ChecksumSource string `json:"checksum_source"`
}

type record struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	ExpectedSHA256 string `json:"expected_sha256"`
	ActualSHA256   string `json:"actual_sha256"`
	Bytes          int64  `json:"bytes"`
	Match          bool   `json:"match"`
	Reused         bool   `json:"reused_existing_verified_copy"`
	ChecksumSource string `json:"checksum_source"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sbxfetch: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	manifestPath := flag.String("manifest", "", "path to the fetch manifest")
	dir := flag.String("dir", "", "staging directory receiving the verified artifacts")
	report := flag.String("report", "", "optional path for the JSON acquisition report")
	flag.Parse()
	if *manifestPath == "" || *dir == "" {
		return errors.New("-manifest and -dir are required")
	}

	raw, err := os.ReadFile(*manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	var manifest fetchManifest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if manifest.Kind != "sbx-fetch-manifest" {
		return fmt.Errorf("unexpected manifest kind %q", manifest.Kind)
	}
	if len(manifest.Artifacts) == 0 {
		return errors.New("manifest declares no artifacts")
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Minute}
	records := make([]record, 0, len(manifest.Artifacts))
	for _, art := range manifest.Artifacts {
		if art.Name == "" || art.URL == "" || len(art.SHA256) != 64 {
			return fmt.Errorf("artifact %q: name, url and a 64-hex sha256 are all required", art.Name)
		}
		if strings.ContainsAny(art.Name, "/\\") {
			return fmt.Errorf("artifact %q: name must be a bare filename", art.Name)
		}
		target := filepath.Join(*dir, art.Name)

		// A previously verified copy is reused only when it still hashes to the
		// published value; a stale or truncated file is re-fetched, never trusted.
		if existing, err := digestFile(target); err == nil && existing == art.SHA256 {
			info, statErr := os.Stat(target)
			if statErr != nil {
				return statErr
			}
			records = append(records, record{art.Name, art.URL, art.SHA256, existing, info.Size(), true, true, art.ChecksumSource})
			fmt.Printf("REUSE name=%s sha256=%s bytes=%d\n", art.Name, existing, info.Size())
			continue
		}

		written, actual, err := download(client, art.URL, target)
		if err != nil {
			return fmt.Errorf("fetch %s: %w", art.Name, err)
		}
		if actual != art.SHA256 {
			os.Remove(target)
			return fmt.Errorf("PUBLISHED DIGEST MISMATCH for %s: published=%s actual=%s (artifact removed)", art.Name, art.SHA256, actual)
		}
		if art.Size != 0 && written != art.Size {
			os.Remove(target)
			return fmt.Errorf("size mismatch for %s: declared=%d actual=%d", art.Name, art.Size, written)
		}
		records = append(records, record{art.Name, art.URL, art.SHA256, actual, written, true, false, art.ChecksumSource})
		fmt.Printf("FETCH name=%s sha256=%s bytes=%d\n", art.Name, actual, written)
	}

	fmt.Printf("SUMMARY artifacts=%d verified=%d mismatches=0\n", len(records), len(records))
	if *report != "" {
		blob, err := json.MarshalIndent(struct {
			SchemaVersion string   `json:"schema_version"`
			Kind          string   `json:"kind"`
			GeneratedAt   string   `json:"generated_at"`
			Statement     string   `json:"statement"`
			Records       []record `json:"records"`
			Total         int      `json:"total"`
			Mismatches    int      `json:"mismatches"`
		}{"1.0.0", "sbx-fetch-report", time.Now().UTC().Format(time.RFC3339), manifest.Statement, records, len(records), 0}, "", " ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*report, append(blob, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func download(client *http.Client, url, target string) (int64, string, error) {
	response, err := client.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("http status %d", response.StatusCode)
	}
	file, err := os.Create(target)
	if err != nil {
		return 0, "", err
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), response.Body)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(target)
		return 0, "", err
	}
	return written, hex.EncodeToString(hash.Sum(nil)), nil
}

func digestFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
