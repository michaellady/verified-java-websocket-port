package corpora

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"
)

type us010FileIdentity struct {
	device uint64
	inode  uint64
	links  uint64
}

type us010FileMetadata struct {
	identity   us010FileIdentity
	size       int64
	mode       os.FileMode
	modifiedAt time.Time
	changedAt  string
}

type us010ArtifactReadHooks struct {
	beforeOpen func()
	afterOpen  func()
}

const us010MaxArtifactBytes int64 = 16 << 20

// readUS010Artifact is the single fail-closed reader for every path introduced
// by the US-010 projection and evidence receipts.
func readUS010Artifact(root, relative string) ([]byte, error) {
	return readUS010ArtifactWithHooks(root, relative, us010ArtifactReadHooks{})
}

func readUS010ArtifactWithHooks(root, relative string, hooks us010ArtifactReadHooks) ([]byte, error) {
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
	rootHandle, err := os.OpenRoot(canonicalRoot)
	if err != nil {
		return nil, fmt.Errorf("open US-010 repository root: %w", err)
	}
	defer rootHandle.Close()
	openedRoot, err := rootHandle.Stat(".")
	if err != nil || !openedRoot.IsDir() || !os.SameFile(rootInfo, openedRoot) {
		return nil, fmt.Errorf("US-010 repository root changed while being opened")
	}

	before, err := inspectUS010ArtifactPath(rootHandle, relative)
	if err != nil {
		return nil, err
	}
	beforeMetadata, ok := us010Metadata(before)
	if !ok || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("US-010 artifact is not a regular file: %q", relative)
	}
	if before.Size() < 0 || before.Size() > us010MaxArtifactBytes {
		return nil, fmt.Errorf("US-010 artifact exceeds the fixed byte limit: %q", relative)
	}
	if beforeMetadata.identity.links != 1 {
		return nil, fmt.Errorf("US-010 artifact must have exactly one link: %q", relative)
	}

	if hooks.beforeOpen != nil {
		hooks.beforeOpen()
	}
	file, err := rootHandle.OpenFile(relative, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open US-010 artifact %q: %w", relative, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("inspect opened US-010 artifact %q", relative)
	}
	openedMetadata, ok := us010Metadata(opened)
	if !ok || openedMetadata != beforeMetadata || openedMetadata.identity.links != 1 {
		return nil, fmt.Errorf("US-010 artifact changed before read: %q", relative)
	}
	if hooks.afterOpen != nil {
		hooks.afterOpen()
	}
	raw, err := io.ReadAll(io.LimitReader(file, us010MaxArtifactBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read US-010 artifact %q: %w", relative, err)
	}
	if int64(len(raw)) != openedMetadata.size || int64(len(raw)) > us010MaxArtifactBytes {
		return nil, fmt.Errorf("US-010 artifact size changed during read: %q", relative)
	}
	afterOpen, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened US-010 artifact after read: %q", relative)
	}
	afterOpenMetadata, ok := us010Metadata(afterOpen)
	if !ok || afterOpenMetadata != beforeMetadata || afterOpenMetadata.identity.links != 1 {
		return nil, fmt.Errorf("US-010 artifact changed during read: %q", relative)
	}
	afterPath, err := inspectUS010ArtifactPath(rootHandle, relative)
	if err != nil {
		return nil, err
	}
	afterPathMetadata, ok := us010Metadata(afterPath)
	if !ok || afterPathMetadata != beforeMetadata || afterPathMetadata.identity.links != 1 {
		return nil, fmt.Errorf("US-010 artifact changed during read: %q", relative)
	}
	return raw, nil
}

func inspectUS010ArtifactPath(root *os.Root, relative string) (os.FileInfo, error) {
	components := strings.Split(filepath.ToSlash(relative), "/")
	current := ""
	var final os.FileInfo
	for index, component := range components {
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("inspect US-010 artifact %q: %w", relative, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("US-010 artifact path contains a symlink: %q", relative)
		}
		if index != len(components)-1 && !info.IsDir() {
			return nil, fmt.Errorf("US-010 artifact parent is not a directory: %q", relative)
		}
		final = info
	}
	return final, nil
}

func us010Metadata(info os.FileInfo) (us010FileMetadata, bool) {
	identity, ok := us010Identity(info)
	if !ok {
		return us010FileMetadata{}, false
	}
	changedAt, ok := us010ChangeTime(info)
	if !ok {
		return us010FileMetadata{}, false
	}
	return us010FileMetadata{
		identity:   identity,
		size:       info.Size(),
		mode:       info.Mode(),
		modifiedAt: info.ModTime(),
		changedAt:  changedAt,
	}, true
}

func us010ChangeTime(info os.FileInfo) (string, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	value := reflect.ValueOf(stat).Elem()
	for _, name := range []string{"Ctimespec", "Ctim", "Ctime"} {
		field := value.FieldByName(name)
		if field.IsValid() && field.CanInterface() {
			return fmt.Sprint(field.Interface()), true
		}
	}
	return "", false
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
