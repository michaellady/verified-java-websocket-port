package intake

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

type ArchivePolicy struct {
	DeclaredExecutables map[string]bool
	DeclaredNested      map[string]string
	MaxEntries          int
	MaxFileBytes        int64
	MaxTotalBytes       int64
	MaxDepth            int
}

type ArchiveEntry struct {
	Path   string
	Size   int64
	Digest string
}

func InspectTar(reader io.Reader, policy ArchivePolicy) ([]ArchiveEntry, error) {
	if policy.MaxEntries <= 0 || policy.MaxFileBytes <= 0 || policy.MaxTotalBytes <= 0 || policy.MaxDepth <= 0 {
		return nil, deny("INVALID_ARCHIVE_POLICY", "$", "all archive bounds must be positive")
	}
	tarReader := tar.NewReader(io.LimitReader(reader, policy.MaxTotalBytes*2+1<<20))
	seen := make(map[string]string)
	entries := make([]ArchiveEntry, 0)
	var total int64
	for {
		header, err := tarReader.Next()
		if isEOF(err) {
			break
		}
		if err != nil {
			return nil, deny("INVALID_ARCHIVE", "$", err.Error())
		}
		if len(entries) >= policy.MaxEntries {
			return nil, deny("ARCHIVE_LIMIT_EXCEEDED", "$", "archive entry count exceeds policy")
		}
		clean, err := validateArchivePath(header.Name, policy.MaxDepth)
		if err != nil {
			return nil, err
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return nil, deny("UNSAFE_ARCHIVE_ENTRY", clean, "links and special files are forbidden")
		}
		key, err := normalizationKey(clean)
		if err != nil {
			return nil, err
		}
		if prior, exists := seen[key]; exists {
			if prior == clean {
				return nil, deny("DUPLICATE_ARCHIVE_ENTRY", clean, "duplicate archive path")
			}
			return nil, deny("NORMALIZATION_COLLISION", clean, "path collides with "+prior)
		}
		seen[key] = clean
		if header.Size < 0 || header.Size > policy.MaxFileBytes || total > policy.MaxTotalBytes-header.Size {
			return nil, deny("ARCHIVE_LIMIT_EXCEEDED", clean, "archive size bound exceeded")
		}
		if header.Mode&0o111 != 0 && !policy.DeclaredExecutables[clean] {
			return nil, deny("UNDECLARED_EXECUTABLE", clean, "executable mode was not declared")
		}
		limited := io.LimitReader(tarReader, header.Size+1)
		buffered := bufio.NewReader(limited)
		prefix, _ := buffered.Peek(512)
		if nestedArchive(prefix) && policy.DeclaredNested[clean] == "" {
			return nil, deny("NESTED_ARCHIVE_DENIED", clean, "nested archive content is not allowed in this transport")
		}
		data, err := io.ReadAll(buffered)
		if err != nil || int64(len(data)) != header.Size {
			return nil, deny("INVALID_ARCHIVE", clean, "entry bytes do not match declared size")
		}
		total += header.Size
		entries = append(entries, ArchiveEntry{Path: clean, Size: header.Size, Digest: DigestBytes(data)})
	}
	return entries, nil
}

// InspectZip validates ZIP/JAR/VSIX metadata and streams every entry through
// strict expansion bounds. It never extracts candidate paths to the host.
func InspectZip(reader io.ReaderAt, compressedSize int64, policy ArchivePolicy) ([]ArchiveEntry, error) {
	if compressedSize <= 0 || policy.MaxEntries <= 0 || policy.MaxFileBytes <= 0 || policy.MaxTotalBytes <= 0 || policy.MaxDepth <= 0 {
		return nil, deny("INVALID_ARCHIVE_POLICY", "$", "all archive bounds must be positive")
	}
	archive, err := zip.NewReader(reader, compressedSize)
	if err != nil {
		return nil, deny("INVALID_ARCHIVE", "$", err.Error())
	}
	if len(archive.File) > policy.MaxEntries {
		return nil, deny("ARCHIVE_LIMIT_EXCEEDED", "$", "archive entry count exceeds policy")
	}
	seen := make(map[string]string)
	entries := make([]ArchiveEntry, 0, len(archive.File))
	var total int64
	for _, file := range archive.File {
		clean, err := validateArchivePath(strings.TrimSuffix(file.Name, "/"), policy.MaxDepth)
		if file.FileInfo().IsDir() && err == nil {
			continue
		}
		if err != nil {
			return nil, err
		}
		mode := file.Mode()
		if !mode.IsRegular() {
			return nil, deny("UNSAFE_ARCHIVE_ENTRY", clean, "links and special files are forbidden")
		}
		key, err := normalizationKey(clean)
		if err != nil {
			return nil, err
		}
		if prior, exists := seen[key]; exists {
			if prior == clean {
				return nil, deny("DUPLICATE_ARCHIVE_ENTRY", clean, "duplicate archive path")
			}
			return nil, deny("NORMALIZATION_COLLISION", clean, "path collides with "+prior)
		}
		seen[key] = clean
		uncompressed := int64(file.UncompressedSize64)
		compressed := int64(file.CompressedSize64)
		if uncompressed < 0 || uncompressed > policy.MaxFileBytes || total > policy.MaxTotalBytes-uncompressed {
			return nil, deny("ARCHIVE_LIMIT_EXCEEDED", clean, "archive size bound exceeded")
		}
		if compressed == 0 && uncompressed > 0 || compressed > 0 && uncompressed/compressed > 100 {
			return nil, deny("ARCHIVE_LIMIT_EXCEEDED", clean, "archive expansion ratio exceeds 100:1")
		}
		if mode&0o111 != 0 && !policy.DeclaredExecutables[clean] {
			return nil, deny("UNDECLARED_EXECUTABLE", clean, "executable mode was not declared")
		}
		stream, err := file.Open()
		if err != nil {
			return nil, deny("INVALID_ARCHIVE", clean, err.Error())
		}
		data, readErr := io.ReadAll(io.LimitReader(stream, policy.MaxFileBytes+1))
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil || int64(len(data)) != uncompressed {
			return nil, deny("INVALID_ARCHIVE", clean, "entry bytes do not match declared size")
		}
		if nestedArchive(data) && policy.DeclaredNested[clean] == "" {
			return nil, deny("NESTED_ARCHIVE_DENIED", clean, "undeclared nested archive content is forbidden")
		}
		total += uncompressed
		entries = append(entries, ArchiveEntry{Path: clean, Size: uncompressed, Digest: DigestBytes(data)})
	}
	return entries, nil
}

func validateArchivePath(name string, maxDepth int) (string, error) {
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") || (len(name) >= 2 && name[1] == ':') {
		return "", deny("ABSOLUTE_PATH", name, "absolute archive path is forbidden")
	}
	if strings.Contains(name, "\\") {
		return "", deny("PATH_TRAVERSAL", name, "backslash archive paths are forbidden")
	}
	parts := strings.Split(name, "/")
	if len(parts) > maxDepth {
		return "", deny("PATH_TRAVERSAL", name, "archive path exceeds depth bound")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", deny("PATH_TRAVERSAL", name, "empty, dot, and parent path components are forbidden")
		}
	}
	clean := path.Clean(name)
	if clean != name || strings.HasPrefix(clean, "../") {
		return "", deny("PATH_TRAVERSAL", name, "archive path escapes its root")
	}
	return clean, nil
}

func normalizationKey(name string) (string, error) {
	if !utf8.ValidString(name) {
		return "", deny("INVALID_PATH_ENCODING", name, "archive path is not valid UTF-8")
	}
	for _, r := range name {
		if r > 0x7f {
			return "", deny("NORMALIZATION_COLLISION", name, "non-ASCII archive paths require an unavailable normalization proof")
		}
	}
	return strings.ToLower(name), nil
}

func nestedArchive(prefix []byte) bool {
	magics := [][]byte{
		{'P', 'K', 3, 4},
		{0x1f, 0x8b},
		{'B', 'Z', 'h'},
		{0xfd, '7', 'z', 'X', 'Z', 0},
	}
	for _, magic := range magics {
		if bytes.HasPrefix(prefix, magic) {
			return true
		}
	}
	if len(prefix) >= 265 && string(prefix[257:262]) == "ustar" {
		return true
	}
	return false
}

func (p ArchiveEntry) String() string { return fmt.Sprintf("%s:%d:%s", p.Path, p.Size, p.Digest) }
