package corpora

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type us010FileIdentity struct {
	device uint64
	inode  uint64
	links  uint64
}

const us010MaxArtifactBytes int64 = 16 << 20

// readUS010Artifact is the single fail-closed reader for every path introduced
// by the US-010 projection and evidence receipts.
func readUS010Artifact(root, relative string) ([]byte, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative ||
		relative == "." || strings.Contains(relative, "\\") {
		return nil, fmt.Errorf("unsafe US-010 artifact path %q", relative)
	}
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		if component == "" || component == "." || component == ".." {
			return nil, fmt.Errorf("unsafe US-010 artifact path %q", relative)
		}
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve US-010 repository root: %w", err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(filepath.Clean(absRoot))
	if err != nil {
		return nil, fmt.Errorf("resolve US-010 repository root: %w", err)
	}
	rootInfo, err := os.Lstat(canonicalRoot)
	if err != nil || !rootInfo.IsDir() {
		return nil, fmt.Errorf("US-010 repository root is not a directory")
	}

	candidate := filepath.Join(canonicalRoot, relative)
	contained, err := filepath.Rel(canonicalRoot, candidate)
	if err != nil || contained == ".." || strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("US-010 artifact path escapes repository root: %q", relative)
	}

	current := canonicalRoot
	components := strings.Split(filepath.FromSlash(relative), string(filepath.Separator))
	var before os.FileInfo
	for index, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("inspect US-010 artifact %q: %w", relative, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("US-010 artifact path contains a symlink: %q", relative)
		}
		if index != len(components)-1 && !info.IsDir() {
			return nil, fmt.Errorf("US-010 artifact parent is not a directory: %q", relative)
		}
		before = info
	}
	if before == nil || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("US-010 artifact is not a regular file: %q", relative)
	}
	if before.Size() < 0 || before.Size() > us010MaxArtifactBytes {
		return nil, fmt.Errorf("US-010 artifact exceeds the fixed byte limit: %q", relative)
	}
	beforeIdentity, ok := us010Identity(before)
	if !ok || beforeIdentity.links != 1 {
		return nil, fmt.Errorf("US-010 artifact must have exactly one link: %q", relative)
	}

	file, err := os.Open(candidate)
	if err != nil {
		return nil, fmt.Errorf("open US-010 artifact %q: %w", relative, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("inspect opened US-010 artifact %q", relative)
	}
	openedIdentity, ok := us010Identity(opened)
	if !ok || openedIdentity != beforeIdentity || openedIdentity.links != 1 {
		return nil, fmt.Errorf("US-010 artifact changed before read: %q", relative)
	}
	raw, err := io.ReadAll(io.LimitReader(file, us010MaxArtifactBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read US-010 artifact %q: %w", relative, err)
	}
	if int64(len(raw)) != opened.Size() || int64(len(raw)) > us010MaxArtifactBytes {
		return nil, fmt.Errorf("US-010 artifact size changed during read: %q", relative)
	}
	after, err := os.Lstat(candidate)
	if err != nil || !after.Mode().IsRegular() {
		return nil, fmt.Errorf("inspect US-010 artifact after read: %q", relative)
	}
	afterIdentity, ok := us010Identity(after)
	if !ok || afterIdentity != beforeIdentity || afterIdentity.links != 1 || after.Size() != int64(len(raw)) {
		return nil, fmt.Errorf("US-010 artifact changed during read: %q", relative)
	}
	return raw, nil
}

func us010Identity(info os.FileInfo) (us010FileIdentity, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return us010FileIdentity{}, false
	}
	return us010FileIdentity{
		device: uint64(stat.Dev),
		inode:  uint64(stat.Ino),
		links:  uint64(stat.Nlink),
	}, true
}
