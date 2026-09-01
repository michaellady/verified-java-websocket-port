// Command javaoraclejar writes the Java oracle classes as a canonical JAR.
// It deliberately does not use the JDK's host-dependent ZIP implementation.
package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

var boundArchiveTime = time.Date(2026, time.August, 28, 17, 16, 22, 0, time.UTC)

type classFile struct {
	name string
	data []byte
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("javaoraclejar", flag.ContinueOnError)
	flags.SetOutput(stderr)
	classes := flags.String("classes", "", "directory containing compiled class files")
	output := flags.String("output", "", "destination JAR path")
	mainClass := flags.String("main-class", "", "JAR main class")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *classes == "" || *output == "" || *mainClass == "" {
		if err == nil {
			_, _ = fmt.Fprintln(stderr, "usage: javaoraclejar --classes DIR --output FILE --main-class CLASS")
		}
		return 2
	}
	var archive bytes.Buffer
	if err := buildArchive(&archive, *classes, *mainClass); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if err := writeAtomic(*output, archive.Bytes()); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func buildArchive(destination io.Writer, classesRoot, mainClass string) error {
	if !validMainClass(mainClass) {
		return fmt.Errorf("invalid main class %q", mainClass)
	}
	root, err := filepath.Abs(classesRoot)
	if err != nil {
		return fmt.Errorf("resolve classes directory: %w", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect classes directory: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("classes path must be a real directory")
	}
	classes, err := collectClasses(root)
	if err != nil {
		return err
	}
	if len(classes) == 0 {
		return errors.New("classes directory contains no .class files")
	}

	writer := zip.NewWriter(destination)
	if err := writeEntry(writer, "META-INF/", nil, true); err != nil {
		return err
	}
	manifest := []byte("Manifest-Version: 1.0\r\nMain-Class: " + mainClass + "\r\n\r\n")
	if err := writeEntry(writer, "META-INF/MANIFEST.MF", manifest, false); err != nil {
		return err
	}
	for _, class := range classes {
		if err := writeEntry(writer, class.name, class.data, false); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finalize JAR: %w", err)
	}
	return nil
}

func collectClasses(root string) ([]classFile, error) {
	var classes []classFile
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("classes tree contains symlink %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || filepath.Ext(path) != ".class" {
			return fmt.Errorf("classes tree contains non-class file %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if strings.HasPrefix(name, "../") || name == ".." || strings.HasPrefix(name, "/") {
			return fmt.Errorf("class path escapes root: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		classes = append(classes, classFile{name: name, data: data})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("collect classes: %w", err)
	}
	sort.Slice(classes, func(left, right int) bool { return classes[left].name < classes[right].name })
	return classes, nil
}

func writeEntry(writer *zip.Writer, name string, data []byte, directory bool) error {
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetModTime(boundArchiveTime)
	if directory {
		header.SetMode(0o755 | os.ModeDir)
	} else {
		header.SetMode(0o644)
	}
	entry, err := writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create JAR entry %s: %w", name, err)
	}
	if _, err := entry.Write(data); err != nil {
		return fmt.Errorf("write JAR entry %s: %w", name, err)
	}
	return nil
}

func writeAtomic(destination string, data []byte) error {
	path, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output parent must be a real directory")
	}
	temporary, err := os.CreateTemp(directory, ".javaoraclejar-*.tmp")
	if err != nil {
		return fmt.Errorf("create staged JAR: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write staged JAR: %w", err)
	}
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set staged JAR mode: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync staged JAR: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close staged JAR: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish JAR: %w", err)
	}
	return nil
}

func validMainClass(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, character := range value {
		if character != '.' && character != '$' && character != '_' && !unicode.IsLetter(character) && !unicode.IsDigit(character) {
			return false
		}
	}
	return true
}
