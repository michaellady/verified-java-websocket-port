package lab

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	maxManifestBytes = 8 << 20
	maxObjectBytes   = 512 << 20
	maxAcceptedBytes = 1 << 30
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	refPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$`)
)

func finding(code, path, message string) error {
	return &intake.Finding{Code: code, Path: path, Message: message}
}

func isDigest(value string) bool { return digestPattern.MatchString(value) }

func cleanAbsoluteDirectory(value, field string) (string, error) {
	if value == "" || strings.ContainsRune(value, 0) || strings.ContainsAny(value, " \r\n\t") {
		return "", finding("INVALID_PATH", field, "path must be a specific absolute directory")
	}
	clean := filepath.Clean(value)
	if clean != value || !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return "", finding("INVALID_PATH", field, "path must be clean, absolute, and narrower than the filesystem root")
	}
	return clean, nil
}

func pathsOverlap(left, right string) bool {
	rel, err := filepath.Rel(left, right)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	rel, err = filepath.Rel(right, left)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// readBoundedRegular reads one immutable-looking filesystem member. It rejects
// links and detects identity/metadata changes across the read. Callers still
// bind the returned bytes cryptographically before using them.
func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, finding("MISSING_FILE", path, err.Error())
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 0 || before.Size() > maximum || linkCount(before) != 1 {
		return nil, finding("UNSAFE_FILE", path, "member must be one bounded, non-linked regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, finding("UNSAFE_FILE", path, err.Error())
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || linkCount(opened) != 1 {
		return nil, finding("CONCURRENT_FILE_DRIFT", path, "member identity changed before reading")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, finding("INPUT_TOO_LARGE", path, "member exceeds its byte bound")
	}
	afterFD, fdErr := file.Stat()
	afterPath, pathErr := os.Lstat(path)
	if fdErr != nil || pathErr != nil || !os.SameFile(before, afterFD) || !os.SameFile(afterFD, afterPath) || afterFD.Size() != int64(len(data)) || !afterPath.Mode().IsRegular() || linkCount(afterFD) != 1 || linkCount(afterPath) != 1 {
		return nil, finding("CONCURRENT_FILE_DRIFT", path, "member identity or metadata changed while reading")
	}
	return data, nil
}

func linkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 1
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func renameExclusive(source, destination string) error {
	if _, err := os.Lstat(destination); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Link(source, destination); err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		return err
	}
	return syncDir(filepath.Dir(destination))
}

func requireRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		if err == nil {
			err = errors.New("not a real directory")
		}
		return finding("UNSAFE_DIRECTORY", path, err.Error())
	}
	return nil
}

func exactSet(values []string, path string, maximum int) (map[string]struct{}, error) {
	if len(values) == 0 || len(values) > maximum {
		return nil, finding("INVALID_SET", path, fmt.Sprintf("set must contain 1..%d entries", maximum))
	}
	set := make(map[string]struct{}, len(values))
	for index, value := range values {
		if !refPattern.MatchString(value) {
			return nil, finding("INVALID_REFERENCE", fmt.Sprintf("%s[%d]", path, index), "reference is empty, oversized, or contains forbidden characters")
		}
		if _, duplicate := set[value]; duplicate {
			return nil, finding("DUPLICATE_ENTRY", fmt.Sprintf("%s[%d]", path, index), "duplicate set member")
		}
		set[value] = struct{}{}
	}
	return set, nil
}
