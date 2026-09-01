package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestBuildArchiveIsIndependentOfHostMetadataAndCreationOrder(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	writeClassFixture(t, first, []string{"z/Z.class", "A.class"}, 0o600, time.Unix(1, 0))
	writeClassFixture(t, second, []string{"A.class", "z/Z.class"}, 0o755, time.Unix(2_000_000_000, 0))

	var left bytes.Buffer
	if err := buildArchive(&left, first, "OracleMain"); err != nil {
		t.Fatal(err)
	}
	var right bytes.Buffer
	if err := buildArchive(&right, second, "OracleMain"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left.Bytes(), right.Bytes()) {
		t.Fatal("archive bytes depend on filesystem metadata or creation order")
	}

	reader, err := zip.NewReader(bytes.NewReader(left.Bytes()), int64(left.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range reader.File {
		names = append(names, entry.Name)
		if entry.Method != zip.Store {
			t.Fatalf("entry %s uses method %d, want Store", entry.Name, entry.Method)
		}
		if !entry.Modified.Equal(boundArchiveTime) {
			t.Fatalf("entry %s time = %s, want %s", entry.Name, entry.Modified, boundArchiveTime)
		}
	}
	wantNames := []string{"META-INF/", "META-INF/MANIFEST.MF", "A.class", "z/Z.class"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("entry order = %q, want %q", names, wantNames)
	}
	manifest, err := readZipEntry(reader, "META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(manifest), "Manifest-Version: 1.0\r\nMain-Class: OracleMain\r\n\r\n"; got != want {
		t.Fatalf("manifest = %q, want %q", got, want)
	}
}

func TestBuildArchiveRejectsSymlinksAndNonClassFiles(t *testing.T) {
	classes := t.TempDir()
	if err := os.WriteFile(filepath.Join(classes, "unexpected.txt"), []byte("no"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := buildArchive(&bytes.Buffer{}, classes, "OracleMain"); err == nil {
		t.Fatal("non-class file was accepted")
	}
	if err := os.Remove(filepath.Join(classes, "unexpected.txt")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(classes, "Real.class")
	if err := os.WriteFile(target, []byte("class"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(classes, "Alias.class")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := buildArchive(&bytes.Buffer{}, classes, "OracleMain"); err == nil {
		t.Fatal("symlinked class was accepted")
	}
}

func writeClassFixture(t *testing.T, root string, order []string, mode os.FileMode, modified time.Time) {
	t.Helper()
	for _, relative := range order {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("class:"+relative), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
}

func readZipEntry(reader *zip.Reader, name string) ([]byte, error) {
	for _, entry := range reader.File {
		if entry.Name == name {
			handle, err := entry.Open()
			if err != nil {
				return nil, err
			}
			defer handle.Close()
			return io.ReadAll(handle)
		}
	}
	return nil, os.ErrNotExist
}
