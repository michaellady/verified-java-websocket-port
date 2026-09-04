package portplan

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Pinned identity of the quarantined upstream source, copied verbatim from
// evidence/intake/source-pins.json (artifact java-websocket-source-archive).
const (
	QuarantineDirectory   = ".quarantine"
	SourceArchiveFileName = "java-websocket-source-archive.tar.gz"
	SourceArchiveURL      = "https://github.com/TooTallNate/Java-WebSocket/archive/da3cf2a777aed862f2f5b5cf060cae7969958667.tar.gz"
	SourceArchiveSHA256   = "sha256:f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4"
	SourceTreeDirectory   = "Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667"
)

// EnsureQuarantinedSource makes the digest-pinned upstream tree available under
// root/.quarantine and returns its path. It re-acquires the archive from the pinned immutable
// URL when it is absent, verifies the sha256 against the pin before any use, and extracts the
// tree with pure Go (no shelling out, nothing executed from the archive). Every failure is a
// typed, fail-closed error; the caller must never soften one into a skip.
func EnsureQuarantinedSource(root string) (string, error) {
	quarantine := filepath.Join(root, QuarantineDirectory)
	archivePath := filepath.Join(quarantine, SourceArchiveFileName)
	treePath := filepath.Join(quarantine, SourceTreeDirectory)

	if err := os.MkdirAll(quarantine, 0o755); err != nil {
		return "", fmt.Errorf("QUARANTINE_UNWRITABLE: %w", err)
	}

	archive, err := os.ReadFile(archivePath)
	if os.IsNotExist(err) {
		archive, err = downloadPinnedArchive()
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(archivePath, archive, 0o644); err != nil {
			return "", fmt.Errorf("QUARANTINE_UNWRITABLE: %w", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("QUARANTINE_UNREADABLE: %w", err)
	}

	digest := sha256.Sum256(archive)
	computed := "sha256:" + hex.EncodeToString(digest[:])
	if computed != SourceArchiveSHA256 {
		return "", fmt.Errorf(
			"QUARANTINE_ARCHIVE_DIGEST_MISMATCH: computed %s, pinned %s (source-pins.json)",
			computed, SourceArchiveSHA256)
	}

	if _, err := os.Stat(filepath.Join(treePath, "src", "main", "java")); err != nil {
		if err := extractArchive(archive, quarantine); err != nil {
			return "", err
		}
	}
	if _, err := os.Stat(filepath.Join(treePath, "src", "main", "java")); err != nil {
		return "", fmt.Errorf("QUARANTINE_TREE_INCOMPLETE: %w", err)
	}
	return treePath, nil
}

func downloadPinnedArchive() ([]byte, error) {
	client := &http.Client{Timeout: 90 * time.Second}
	response, err := client.Get(SourceArchiveURL)
	if err != nil {
		return nil, fmt.Errorf("JAVA_SOURCE_UNAVAILABLE_OFFLINE: re-acquisition of the pinned"+
			" archive failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JAVA_SOURCE_UNAVAILABLE_OFFLINE: pinned immutable URL returned"+
			" HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("JAVA_SOURCE_UNAVAILABLE_OFFLINE: %w", err)
	}
	return content, nil
}

// extractArchive unpacks the digest-verified tarball beneath the quarantine directory. Entries
// are path-sanitized; permissions are normalized; nothing is ever executed.
func extractArchive(archive []byte, quarantine string) error {
	gzipReader, err := gzip.NewReader(strings.NewReader(string(archive)))
	if err != nil {
		return fmt.Errorf("QUARANTINE_ARCHIVE_UNREADABLE: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("QUARANTINE_ARCHIVE_UNREADABLE: %w", err)
		}
		// GitHub codeload tarballs open with pax metadata pseudo-entries
		// (pax_global_header, type 'g'/'x') that carry no payload path and
		// are not part of the source tree; skip them before the tree-prefix
		// check instead of failing the whole materialization (mainline
		// integration regression: US-003's lane never extracted fresh).
		if header.Typeflag == tar.TypeXGlobalHeader || header.Typeflag == tar.TypeXHeader {
			continue
		}
		cleaned := filepath.Clean(header.Name)
		if cleaned == "." || strings.HasPrefix(cleaned, "..") || filepath.IsAbs(cleaned) {
			continue
		}
		if !strings.HasPrefix(cleaned, SourceTreeDirectory) {
			return fmt.Errorf("QUARANTINE_ARCHIVE_UNEXPECTED_ENTRY: %s", header.Name)
		}
		target := filepath.Join(quarantine, cleaned)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("QUARANTINE_UNWRITABLE: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("QUARANTINE_UNWRITABLE: %w", err)
			}
			content, err := io.ReadAll(io.LimitReader(tarReader, 32<<20))
			if err != nil {
				return fmt.Errorf("QUARANTINE_ARCHIVE_UNREADABLE: %w", err)
			}
			if err := os.WriteFile(target, content, 0o644); err != nil {
				return fmt.Errorf("QUARANTINE_UNWRITABLE: %w", err)
			}
		default:
			// Symlinks, devices, and every other entry type stay unextracted by policy.
		}
	}
}
