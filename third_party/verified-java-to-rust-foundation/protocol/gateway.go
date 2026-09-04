package protocol

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

type IngestManifest struct {
	SchemaVersion  string          `json:"schema_version"`
	Company        string          `json:"company"`
	Project        string          `json:"project"`
	SnapshotID     string          `json:"snapshot_id"`
	SnapshotDigest string          `json:"snapshot_digest"`
	Entries        []ManifestEntry `json:"entries"`
}

type ManifestEntry struct {
	Path       string   `json:"path"`
	Digest     string   `json:"digest"`
	Encoding   string   `json:"encoding"`
	Executable bool     `json:"executable"`
	DependsOn  []string `json:"depends_on"`
}

type GatewayLimits struct {
	MaximumFiles      int
	MaximumFileBytes  int64
	MaximumTotalBytes int64
	MaximumDepth      int
	QuarantineRoot    string
}

type IngestResult struct {
	SnapshotID      string   `json:"snapshot_id"`
	PromotedDigests []string `json:"promoted_digests"`
	QuarantineGone  bool     `json:"quarantine_gone"`
}

func DefaultGatewayLimits(root string) GatewayLimits {
	return GatewayLimits{MaximumFiles: 256, MaximumFileBytes: 4 << 20, MaximumTotalBytes: 32 << 20, MaximumDepth: 16, QuarantineRoot: root}
}

// IngestTar streams an untrusted tar into a disposable quarantine directory,
// validates the complete manifest, then sends one all-or-none batch to the
// promoter. No canonical bytes are visible before the complete batch commits.
func IngestTar(ctx context.Context, stream io.Reader, manifest IngestManifest, policy Policy, limits GatewayLimits, promoter TransactionalPromoter) (IngestResult, *Finding) {
	if manifest.SchemaVersion != SchemaVersion || manifest.Company != policy.Company || manifest.Project != policy.Project {
		return IngestResult{}, gatewayFinding("CROSS_COMPANY_REFERENCE", Quarantine, "$.manifest", "manifest scope does not match the active Java-to-Rust project")
	}
	if manifest.SnapshotID == "" || !validDigest(manifest.SnapshotDigest) {
		return IngestResult{}, gatewayFinding("INVALID_MANIFEST", Block, "$.manifest", "snapshot identity and digest are required")
	}
	if limits.MaximumFiles <= 0 || limits.MaximumFileBytes <= 0 || limits.MaximumTotalBytes <= 0 || limits.MaximumDepth <= 0 || limits.QuarantineRoot == "" {
		return IngestResult{}, gatewayFinding("INVALID_GATEWAY_LIMIT", Block, "$.limits", "positive quarantine limits and root are required")
	}
	if promoter == nil {
		return IngestResult{}, gatewayFinding("INVALID_GATEWAY", Block, "$.promoter", "transactional promoter is required")
	}
	if err := os.MkdirAll(limits.QuarantineRoot, 0o700); err != nil {
		return IngestResult{}, gatewayFinding("QUARANTINE_UNAVAILABLE", Retry, "$.limits.quarantine_root", safeError(err))
	}
	rootInfo, err := os.Lstat(limits.QuarantineRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return IngestResult{}, gatewayFinding("UNSAFE_QUARANTINE_ROOT", Quarantine, "$.limits.quarantine_root", "quarantine root must be a real directory")
	}
	quarantine, err := os.MkdirTemp(limits.QuarantineRoot, ".ingest-")
	if err != nil {
		return IngestResult{}, gatewayFinding("QUARANTINE_UNAVAILABLE", Retry, "$.limits.quarantine_root", safeError(err))
	}
	removed := false
	defer func() {
		_ = os.RemoveAll(quarantine)
		removed = true
	}()

	declared, finding := validateManifestEntries(manifest.Entries, limits)
	if finding != nil {
		return IngestResult{}, finding
	}
	reader := tar.NewReader(io.LimitReader(stream, limits.MaximumTotalBytes+(1<<20)))
	seen := make(map[string]bool, len(declared))
	seenNormalized := make(map[string]string, len(declared))
	objects := make([]PromotionObject, 0, len(declared))
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return IngestResult{}, gatewayFinding("INGEST_CANCELLED", Block, "$.archive", "ingestion was cancelled")
		}
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return IngestResult{}, gatewayFinding("INVALID_ARCHIVE", Quarantine, "$.archive", safeError(nextErr))
		}
		canonical, normalizedKey, pathFinding := canonicalArchivePath(header.Name, limits.MaximumDepth)
		if pathFinding != nil {
			return IngestResult{}, pathFinding
		}
		if prior, exists := seenNormalized[normalizedKey]; exists && prior != canonical {
			return IngestResult{}, gatewayFinding("NORMALIZATION_COLLISION", Quarantine, "$.archive", "archive paths collide after Unicode and case normalization")
		}
		seenNormalized[normalizedKey] = canonical
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return IngestResult{}, gatewayFinding("UNSAFE_ARCHIVE_ENTRY", Quarantine, "$.archive."+canonical, "links, devices, sockets, and special files are forbidden")
		}
		entry, declaredHere := declared[canonical]
		if !declaredHere {
			return IngestResult{}, gatewayFinding("UNDECLARED_ARTIFACT", Quarantine, "$.archive."+canonical, "archive entry is absent from the manifest")
		}
		if seen[canonical] {
			return IngestResult{}, gatewayFinding("DUPLICATE_ARCHIVE_ENTRY", Quarantine, "$.archive."+canonical, "archive path occurs more than once")
		}
		if header.Size < 0 || header.Size > limits.MaximumFileBytes || total+header.Size > limits.MaximumTotalBytes || len(seen)+1 > limits.MaximumFiles {
			return IngestResult{}, gatewayFinding("ARCHIVE_LIMIT_EXCEEDED", Quarantine, "$.archive."+canonical, "archive exceeds declared file, byte, or count limits")
		}
		if nestedArchive(canonical) {
			return IngestResult{}, gatewayFinding("NESTED_ARCHIVE_DENIED", Quarantine, "$.archive."+canonical, "nested archives are forbidden at the ingestion boundary")
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, limits.MaximumFileBytes+1))
		if readErr != nil || int64(len(data)) != header.Size || int64(len(data)) > limits.MaximumFileBytes {
			return IngestResult{}, gatewayFinding("ARCHIVE_LIMIT_EXCEEDED", Quarantine, "$.archive."+canonical, "archive entry did not reconcile to its declared bounded size")
		}
		total += int64(len(data))
		if nestedArchiveContent(data) {
			return IngestResult{}, gatewayFinding("NESTED_ARCHIVE_DENIED", Quarantine, "$.archive."+canonical, "nested archive content is forbidden at the ingestion boundary")
		}
		if executableBytes(data, header.FileInfo().Mode()) && !entry.Executable {
			return IngestResult{}, gatewayFinding("UNDECLARED_EXECUTABLE", Quarantine, "$.archive."+canonical, "executable content or mode was not declared")
		}
		if entry.Encoding == "utf-8" && !utf8.Valid(data) {
			return IngestResult{}, gatewayFinding("INVALID_ENCODING", Quarantine, "$.archive."+canonical, "declared UTF-8 content is invalid")
		}
		if entry.Encoding == "json" {
			if !utf8.Valid(data) || !json.Valid(data) {
				return IngestResult{}, gatewayFinding("INVALID_ENCODING", Quarantine, "$.archive."+canonical, "declared JSON content is invalid")
			}
			var document any
			if err := DecodeStrict(data, &document); err != nil {
				return IngestResult{}, gatewayFinding("INVALID_ENCODING", Quarantine, "$.archive."+canonical, "declared JSON must be strict and singular")
			}
		}
		if DigestBytes(data) != entry.Digest {
			return IngestResult{}, gatewayFinding("DIGEST_MISMATCH", Quarantine, "$.archive."+canonical, "archive bytes do not match the manifest digest")
		}
		destination := filepath.Join(quarantine, filepath.FromSlash(canonical))
		if !strings.HasPrefix(destination, quarantine+string(os.PathSeparator)) {
			return IngestResult{}, gatewayFinding("PATH_TRAVERSAL", Quarantine, "$.archive."+canonical, "resolved path escapes quarantine")
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return IngestResult{}, gatewayFinding("QUARANTINE_UNAVAILABLE", Retry, "$.archive."+canonical, safeError(err))
		}
		file, openErr := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if openErr != nil {
			return IngestResult{}, gatewayFinding("QUARANTINE_UNAVAILABLE", Retry, "$.archive."+canonical, safeError(openErr))
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return IngestResult{}, gatewayFinding("QUARANTINE_UNAVAILABLE", Retry, "$.archive."+canonical, "quarantine write failed")
		}
		seen[canonical] = true
		objects = append(objects, PromotionObject{Key: manifest.SnapshotID + "/" + canonical, Digest: entry.Digest, Bytes: data})
	}
	if len(seen) != len(declared) {
		return IngestResult{}, gatewayFinding("MISSING_ARTIFACT", Block, "$.archive", "archive omitted one or more manifest entries")
	}
	if err := promoter.Promote(ctx, PromotionBatch{SnapshotID: manifest.SnapshotID, SnapshotDigest: manifest.SnapshotDigest, Objects: objects}); err != nil {
		return IngestResult{}, gatewayFinding("PARTIAL_PUBLICATION", Quarantine, "$.publication", safeError(err))
	}
	digests := make([]string, 0, len(objects))
	for _, object := range objects {
		digests = append(digests, object.Digest)
	}
	sort.Strings(digests)
	_ = os.RemoveAll(quarantine)
	removed = true
	return IngestResult{SnapshotID: manifest.SnapshotID, PromotedDigests: digests, QuarantineGone: removed}, nil
}

func validateManifestEntries(entries []ManifestEntry, limits GatewayLimits) (map[string]ManifestEntry, *Finding) {
	if len(entries) == 0 || len(entries) > limits.MaximumFiles {
		return nil, gatewayFinding("INVALID_MANIFEST", Block, "$.manifest.entries", "manifest requires a bounded non-empty entry set")
	}
	result := make(map[string]ManifestEntry, len(entries))
	normalized := make(map[string]string, len(entries))
	for index, entry := range entries {
		canonical, key, finding := canonicalArchivePath(entry.Path, limits.MaximumDepth)
		if finding != nil {
			finding.Path = fmt.Sprintf("$.manifest.entries[%d].path", index)
			return nil, finding
		}
		if canonical != entry.Path || !validDigest(entry.Digest) || (entry.Encoding != "binary" && entry.Encoding != "utf-8" && entry.Encoding != "json") {
			return nil, gatewayFinding("INVALID_MANIFEST", Block, fmt.Sprintf("$.manifest.entries[%d]", index), "entry path, digest, or encoding is invalid")
		}
		if _, exists := result[canonical]; exists {
			return nil, gatewayFinding("DUPLICATE_ARCHIVE_ENTRY", Quarantine, fmt.Sprintf("$.manifest.entries[%d].path", index), "manifest path occurs more than once")
		}
		if prior, exists := normalized[key]; exists && prior != canonical {
			return nil, gatewayFinding("NORMALIZATION_COLLISION", Quarantine, fmt.Sprintf("$.manifest.entries[%d].path", index), "manifest paths collide after normalization")
		}
		normalized[key] = canonical
		result[canonical] = entry
	}
	for source, entry := range result {
		for _, dependency := range entry.DependsOn {
			if _, exists := result[dependency]; !exists {
				return nil, gatewayFinding("DANGLING_EDGE", Block, "$.manifest.entries."+source+".depends_on", "manifest dependency does not resolve")
			}
		}
	}
	return result, nil
}

func canonicalArchivePath(value string, maximumDepth int) (string, string, *Finding) {
	if value == "" || !utf8.ValidString(value) || strings.ContainsRune(value, 0) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || filepath.VolumeName(value) != "" {
		return "", "", gatewayFinding("ABSOLUTE_PATH", Quarantine, "$.archive", "archive path must be relative UTF-8 with slash separators")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", "", gatewayFinding("PATH_TRAVERSAL", Quarantine, "$.archive", "archive path contains an empty, dot, or parent segment")
		}
	}
	canonical := norm.NFC.String(value)
	if path.Clean(canonical) != canonical || len(strings.Split(canonical, "/")) > maximumDepth {
		return "", "", gatewayFinding("PATH_TRAVERSAL", Quarantine, "$.archive", "archive path is non-canonical or too deeply nested")
	}
	return canonical, strings.ToLower(canonical), nil
}

func executableBytes(data []byte, mode os.FileMode) bool {
	if mode.Perm()&0o111 != 0 || bytes.HasPrefix(data, []byte("#!")) || bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) || bytes.HasPrefix(data, []byte{'M', 'Z'}) {
		return true
	}
	return len(data) >= 4 && bytes.Equal(data[:4], []byte{0xca, 0xfe, 0xba, 0xbe})
}

func nestedArchive(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".jar", ".war"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func nestedArchiveContent(data []byte) bool {
	zipArchive := len(data) >= 4 && data[0] == 'P' && data[1] == 'K' &&
		(data[2] == 0x03 && data[3] == 0x04 || data[2] == 0x05 && data[3] == 0x06 ||
			data[2] == 0x07 && data[3] == 0x08 || data[2] == 0x06 && data[3] == 0x06)
	gzipArchive := len(data) >= 3 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 0x08
	bzip2Archive := len(data) >= 4 && bytes.Equal(data[:3], []byte{'B', 'Z', 'h'}) && data[3] >= '1' && data[3] <= '9'
	xzArchive := len(data) >= 6 && bytes.Equal(data[:6], []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00})
	tarArchive := len(data) >= 262 && bytes.Equal(data[257:262], []byte("ustar"))
	return zipArchive || gzipArchive || bzip2Archive || xzArchive || tarArchive
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func gatewayFinding(code string, disposition Disposition, pathValue, message string) *Finding {
	return &Finding{Code: code, Disposition: disposition, Path: pathValue, Message: message}
}

func safeError(err error) string {
	if err == nil {
		return "operation failed"
	}
	return strings.ReplaceAll(filepath.Base(err.Error()), "\n", " ")
}
