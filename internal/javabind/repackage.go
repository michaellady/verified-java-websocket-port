package javabind

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RepackageRuntime writes a copy of the pinned Java-WebSocket archive in which
// the class files produced by compiling one source file replace their originals.
// Every other entry is copied byte for byte, so the resulting archive differs
// from the pinned one only in the compiled form of that single compilation unit.
//
// The archive is written deterministically: entries keep the pinned archive's
// order, and replacement entries are stored with a fixed modification time, so
// two runs over the same inputs produce the same bytes.
func RepackageRuntime(pinnedJAR, classesDir, outputJAR string) (string, error) {
	replacements, err := collectClasses(classesDir)
	if err != nil {
		return "", err
	}
	if len(replacements) == 0 {
		return "", fmt.Errorf("javabind: no compiled classes found under %q", classesDir)
	}
	reader, err := zip.OpenReader(pinnedJAR)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	replaced := map[string]bool{}
	for _, entry := range reader.File {
		if body, ok := replacements[entry.Name]; ok {
			header := &zip.FileHeader{Name: entry.Name, Method: zip.Deflate}
			target, err := writer.CreateHeader(header)
			if err != nil {
				return "", err
			}
			if _, err := target.Write(body); err != nil {
				return "", err
			}
			replaced[entry.Name] = true
			continue
		}
		source, err := entry.Open()
		if err != nil {
			return "", err
		}
		header := entry.FileHeader
		header.Method = zip.Deflate
		target, err := writer.CreateHeader(&header)
		if err != nil {
			source.Close()
			return "", err
		}
		if _, err := io.Copy(target, source); err != nil {
			source.Close()
			return "", err
		}
		source.Close()
	}
	// A recompiled unit may introduce a class the pinned archive does not carry.
	// Append those in a stable order rather than dropping them silently.
	extra := make([]string, 0)
	for name := range replacements {
		if !replaced[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		target, err := writer.CreateHeader(header)
		if err != nil {
			return "", err
		}
		if _, err := target.Write(replacements[name]); err != nil {
			return "", err
		}
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(outputJAR), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(outputJAR, buffer.Bytes(), 0o644); err != nil {
		return "", err
	}
	return Digest(buffer.Bytes()), nil
}

func collectClasses(classesDir string) (map[string][]byte, error) {
	classes := map[string][]byte{}
	err := filepath.Walk(classesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".class") {
			return nil
		}
		relative, err := filepath.Rel(classesDir, path)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		classes[filepath.ToSlash(relative)] = body
		return nil
	})
	if err != nil {
		return nil, err
	}
	return classes, nil
}

// SemanticProjection strips the fields of an adapter response that are expected
// to differ between a run against the pinned archive and a run against a
// repackaged one, so the remainder can be compared exactly. Only the runtime
// identity block is removed; every observable of the scenario is kept.
func SemanticProjection(responseLine []byte) ([]byte, error) {
	var response map[string]any
	if err := decodeJSON(responseLine, &response); err != nil {
		return nil, err
	}
	delete(response, "runtime")
	return canonicalJSON(response)
}
