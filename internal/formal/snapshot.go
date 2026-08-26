package formal

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
)

const (
	maxJSONBytes = int64(8 << 20)
	maxTLABytes  = int64(1 << 20)
)

type snapshot struct {
	root    *os.Root
	files   map[string][]byte
	errors  map[string]error
	readSet map[string]bool
}

type fileIdentity struct {
	device uint64
	inode  uint64
	links  uint64
}

func newSnapshot(rootPath string) (*snapshot, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	value := &snapshot{
		root:    root,
		files:   make(map[string][]byte),
		errors:  make(map[string]error),
		readSet: make(map[string]bool),
	}
	for _, item := range []struct {
		path  string
		limit int64
	}{
		{proofTargetsPath, maxJSONBytes},
		{backendQualificationPath, maxJSONBytes},
		{connectionModelPath, maxTLABytes},
		{concurrencyPlanPath, maxJSONBytes},
		{proofTargetsSchemaPath, maxJSONBytes},
		{backendSchemaPath, maxJSONBytes},
		{concurrencySchemaPath, maxJSONBytes},
	} {
		_, _ = value.read(item.path, item.limit)
	}
	return value, nil
}

func (value *snapshot) close() error {
	return value.root.Close()
}

func (value *snapshot) read(name string, limit int64) ([]byte, error) {
	canonical, err := canonicalPath(name)
	if err != nil {
		return nil, err
	}
	if value.readSet[canonical] {
		return value.files[canonical], value.errors[canonical]
	}
	value.readSet[canonical] = true
	data, err := readRegularFile(value.root, canonical, limit)
	if err != nil {
		value.errors[canonical] = err
		return nil, err
	}
	value.files[canonical] = data
	return data, nil
}

func readRegularFile(root *os.Root, name string, limit int64) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	beforeID, ok := identityOf(before)
	if !ok || !before.Mode().IsRegular() || before.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if beforeID.links != 1 {
		return nil, fmt.Errorf("%s is not an immutable single-link file", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	openedID, ok := identityOf(opened)
	if !ok || openedID != beforeID || opened.Size() != before.Size() {
		return nil, fmt.Errorf("%s changed while being opened", name)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", name, limit)
	}
	afterOpen, err := file.Stat()
	if err != nil {
		return nil, err
	}
	afterOpenID, ok := identityOf(afterOpen)
	if !ok || afterOpenID != beforeID || afterOpen.Size() != before.Size() {
		return nil, fmt.Errorf("%s changed while being read", name)
	}
	afterPath, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	afterPathID, ok := identityOf(afterPath)
	if !ok || afterPathID != beforeID || afterPath.Size() != before.Size() {
		return nil, fmt.Errorf("%s changed while being read", name)
	}
	return data, nil
}

func identityOf(info fs.FileInfo) (fileIdentity, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, false
	}
	return fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), links: uint64(stat.Nlink)}, true
}

func canonicalPath(name string) (string, error) {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("path must be slash-relative")
	}
	if strings.HasPrefix(name, "./") || strings.Contains(name, "//") || strings.Contains(name, "/./") {
		return "", fmt.Errorf("path must be canonical")
	}
	clean := path.Clean(name)
	if clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("path escapes root")
	}
	if clean != name {
		return "", fmt.Errorf("path must be canonical")
	}
	return clean, nil
}
