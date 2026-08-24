package lab

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	maxArchiveEntries = 100000
	maxExpandedBytes  = int64(2 << 30)
)

type archivePolicy struct {
	stripTopDirectory bool
	allowSymlinks     bool
	readOnly          bool
}

type pendingSymlink struct {
	name   string
	target string
}

func extractAcceptedArchive(data []byte, destination string, policy archivePolicy) error {
	clean, err := cleanAbsoluteDirectory(destination, "$.archive_destination")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return finding("ARCHIVE_EXTRACTION_FAILED", clean, err.Error())
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return finding("INVALID_ACCEPTED_ARCHIVE", "$", "accepted object is not a valid gzip stream")
	}
	defer reader.Close()
	tarReader := tar.NewReader(reader)
	seen := make(map[string]byte)
	links := make([]pendingSymlink, 0)
	var top string
	var expanded int64
	seenGlobalPAX := false
	for entries := 0; ; entries++ {
		if entries >= maxArchiveEntries {
			return finding("ARCHIVE_LIMIT_EXCEEDED", "$", "archive entry count exceeds the fixed limit")
		}
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return finding("INVALID_ACCEPTED_ARCHIVE", "$", nextErr.Error())
		}
		// GitHub's exact accepted source tarball starts with one global PAX
		// metadata header. It does not materialize a filesystem member; every
		// effective member name is still validated independently below.
		if header.Typeflag == tar.TypeXGlobalHeader {
			if seenGlobalPAX || header.Name != "pax_global_header" || header.Linkname != "" || header.Size < 0 || header.Size > maxManifestBytes {
				return finding("INVALID_ACCEPTED_ARCHIVE", header.Name, "global PAX metadata is not the single bounded accepted form")
			}
			seenGlobalPAX = true
			continue
		}
		name, root, nameErr := cleanArchiveName(header.Name, policy.stripTopDirectory)
		if nameErr != nil {
			return nameErr
		}
		if policy.stripTopDirectory {
			if top == "" {
				top = root
			} else if root != top {
				return finding("INVALID_ACCEPTED_ARCHIVE", header.Name, "archive top-level directory differs from the first member")
			}
			if name == "" {
				continue
			}
		}
		if priorType, duplicate := seen[name]; duplicate {
			if priorType == tar.TypeDir && header.Typeflag == tar.TypeDir {
				continue
			}
			return finding("DUPLICATE_ARCHIVE_ENTRY", header.Name, "archive member occurs more than once")
		}
		seen[name] = header.Typeflag
		target := filepath.Join(clean, filepath.FromSlash(name))
		if !pathsOverlap(clean, target) {
			return finding("ARCHIVE_PATH_ESCAPE", header.Name, "archive member leaves the destination")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return finding("ARCHIVE_EXTRACTION_FAILED", header.Name, err.Error())
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || expanded > maxExpandedBytes-header.Size {
				return finding("ARCHIVE_LIMIT_EXCEEDED", header.Name, "expanded bytes exceed the fixed limit")
			}
			expanded += header.Size
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return finding("ARCHIVE_EXTRACTION_FAILED", header.Name, err.Error())
			}
			mode := os.FileMode(0o600)
			if header.FileInfo().Mode()&0o111 != 0 {
				mode = 0o700
			}
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return finding("ARCHIVE_EXTRACTION_FAILED", header.Name, err.Error())
			}
			written, copyErr := io.CopyN(file, tarReader, header.Size)
			syncErr := file.Sync()
			closeErr := file.Close()
			if copyErr != nil || written != header.Size || syncErr != nil || closeErr != nil {
				return finding("ARCHIVE_EXTRACTION_FAILED", header.Name, "regular member could not be durably materialized")
			}
		case tar.TypeSymlink:
			if !policy.allowSymlinks {
				return finding("ARCHIVE_LINK_DENIED", header.Name, "links are forbidden in this accepted archive")
			}
			if err := validateArchiveLink(name, header.Linkname); err != nil {
				return err
			}
			links = append(links, pendingSymlink{name: name, target: header.Linkname})
		default:
			return finding("ARCHIVE_MEMBER_DENIED", header.Name, fmt.Sprintf("archive member type %d is forbidden", header.Typeflag))
		}
	}
	for _, link := range links {
		target := filepath.Join(clean, filepath.FromSlash(link.name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return finding("ARCHIVE_EXTRACTION_FAILED", link.name, err.Error())
		}
		if err := os.Symlink(link.target, target); err != nil {
			return finding("ARCHIVE_EXTRACTION_FAILED", link.name, err.Error())
		}
	}
	if policy.readOnly {
		return makeTreeReadOnly(clean)
	}
	return syncDir(clean)
}

func cleanArchiveName(raw string, stripTop bool) (string, string, error) {
	if raw == "" || strings.ContainsRune(raw, 0) || strings.HasPrefix(raw, "/") || strings.Contains(raw, "\\") {
		return "", "", finding("ARCHIVE_PATH_ESCAPE", raw, "archive member name is not a relative slash path")
	}
	clean := path.Clean(raw)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != strings.TrimSuffix(raw, "/") {
		return "", "", finding("ARCHIVE_PATH_ESCAPE", raw, "archive member name is not canonical")
	}
	parts := strings.Split(clean, "/")
	root := parts[0]
	if !stripTop {
		return clean, root, nil
	}
	if len(parts) == 1 {
		return "", root, nil
	}
	return strings.Join(parts[1:], "/"), root, nil
}

func validateArchiveLink(name, target string) error {
	if target == "" || strings.ContainsRune(target, 0) || strings.HasPrefix(target, "/") || strings.Contains(target, "\\") {
		return finding("ARCHIVE_LINK_ESCAPE", name, "link target must be a relative slash path")
	}
	resolved := path.Clean(path.Join(path.Dir(name), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return finding("ARCHIVE_LINK_ESCAPE", name, "link target leaves the accepted tool root")
	}
	return nil
}

func makeTreeReadOnly(root string) error {
	paths := make([]string, 0)
	err := filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		paths = append(paths, name)
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return finding("UNSAFE_MATERIALIZED_TREE", name, "member is not a regular file")
		}
		mode := os.FileMode(0o400)
		if info.Mode()&0o111 != 0 {
			mode = 0o500
		}
		return os.Chmod(name, mode)
	})
	if err != nil {
		return finding("ARCHIVE_EXTRACTION_FAILED", root, err.Error())
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, name := range paths {
		info, err := os.Lstat(name)
		if err != nil || !info.IsDir() {
			continue
		}
		if err := os.Chmod(name, 0o500); err != nil {
			return finding("ARCHIVE_EXTRACTION_FAILED", name, err.Error())
		}
	}
	return syncDir(filepath.Dir(root))
}

func digestTree(root string, rejectLinks bool) (string, int64, error) {
	return digestTreeExcluding(root, rejectLinks, nil)
}

func digestProductionSourceTree(root string) (string, int64, error) {
	return digestTreeExcluding(root, true, map[string]struct{}{"target": {}})
}

func digestTreeExcluding(root string, rejectLinks bool, excluded map[string]struct{}) (string, int64, error) {
	clean, err := cleanAbsoluteDirectory(root, "$.tree")
	if err != nil {
		return "", 0, err
	}
	entries := make([]string, 0)
	var totalBytes int64
	err = filepath.WalkDir(clean, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == clean {
			return nil
		}
		relative, err := filepath.Rel(clean, name)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		info, err := os.Lstat(name)
		if err != nil {
			return err
		}
		if _, skip := excluded[relative]; skip {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return finding("UNSAFE_MATERIALIZED_TREE", name, "excluded writable output must remain a real directory")
			}
			return filepath.SkipDir
		}
		switch {
		case info.IsDir():
			entries = append(entries, "d "+relative)
		case info.Mode().IsRegular():
			data, err := readBoundedRegular(name, maxObjectBytes)
			if err != nil {
				return err
			}
			totalBytes += int64(len(data))
			entries = append(entries, "f "+relative+" "+intake.DigestBytes(data))
		case info.Mode()&os.ModeSymlink != 0 && !rejectLinks:
			target, err := os.Readlink(name)
			if err != nil {
				return err
			}
			entries = append(entries, "l "+relative+" "+target)
		default:
			return finding("UNSAFE_MATERIALIZED_TREE", name, "tree contains a link or special member")
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Strings(entries)
	return intake.DigestBytes([]byte(strings.Join(entries, "\n") + "\n")), totalBytes, nil
}

func copyAcceptedSourceTree(source, destination string) error {
	sourceClean, err := cleanAbsoluteDirectory(source, "$.source")
	if err != nil {
		return err
	}
	destinationClean, err := cleanAbsoluteDirectory(destination, "$.build_tree")
	if err != nil {
		return err
	}
	if pathsOverlap(sourceClean, destinationClean) {
		return finding("SANDBOX_PATH_OVERLAP", "$.build_tree", "build copy must be disjoint from accepted source")
	}
	if _, err := os.Lstat(destinationClean); err == nil || !errors.Is(err, os.ErrNotExist) {
		return finding("NONDISPOSABLE_SANDBOX_PATH", destinationClean, "build copy must not already exist")
	}
	if err := os.Mkdir(destinationClean, 0o700); err != nil {
		return finding("EXECUTOR_PREPARATION_FAILED", destinationClean, err.Error())
	}
	return filepath.WalkDir(sourceClean, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == sourceClean {
			return nil
		}
		relative, err := filepath.Rel(sourceClean, name)
		if err != nil {
			return err
		}
		target := filepath.Join(destinationClean, relative)
		info, err := os.Lstat(name)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			return nil
		case info.Mode().IsRegular():
			data, err := readBoundedRegular(name, maxObjectBytes)
			if err != nil {
				return err
			}
			mode := os.FileMode(0o600)
			if info.Mode()&0o111 != 0 {
				mode = 0o700
			}
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return err
			}
			written, writeErr := file.Write(data)
			syncErr := file.Sync()
			closeErr := file.Close()
			if writeErr != nil || written != len(data) || syncErr != nil || closeErr != nil {
				return finding("EXECUTOR_PREPARATION_FAILED", target, "accepted source copy could not be durably written")
			}
			return nil
		default:
			return finding("UNSAFE_MATERIALIZED_TREE", name, "accepted source contains a link or special member")
		}
	})
}
