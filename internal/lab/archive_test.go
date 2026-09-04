package lab

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

type tarMember struct {
	name     string
	kind     byte
	contents string
	link     string
}

func TestAcceptedArchiveExtractionRejectsEscapesLinksAndDuplicates(t *testing.T) {
	tests := map[string][]tarMember{
		"escape":    {{name: "root/../escape", kind: tar.TypeReg, contents: "x"}},
		"link":      {{name: "root/link", kind: tar.TypeSymlink, link: "target"}},
		"duplicate": {{name: "root/file", kind: tar.TypeReg, contents: "a"}, {name: "root/file", kind: tar.TypeReg, contents: "b"}},
	}
	for name, members := range tests {
		t.Run(name, func(t *testing.T) {
			err := extractAcceptedArchive(makeTarGzip(t, members), filepath.Join(t.TempDir(), "out"), archivePolicy{stripTopDirectory: true, readOnly: true})
			if err == nil {
				t.Fatal("hostile archive accepted")
			}
		})
	}
}

func TestAcceptedArchiveExtractionAndTreeDigestDetectMutation(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "out")
	data := makeTarGzip(t, []tarMember{{name: "root/", kind: tar.TypeDir}, {name: "root/src/Main.java", kind: tar.TypeReg, contents: "class Main {}"}})
	if err := extractAcceptedArchive(data, destination, archivePolicy{stripTopDirectory: true}); err != nil {
		t.Fatal(err)
	}
	before, size, err := digestTree(destination, true)
	if err != nil || size != int64(len("class Main {}")) {
		t.Fatalf("digest=%s size=%d err=%v", before, size, err)
	}
	if err := os.WriteFile(filepath.Join(destination, "src", "Main.java"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, _, err := digestTree(destination, true)
	if err != nil || before == after {
		t.Fatalf("mutation not detected: before=%s after=%s err=%v", before, after, err)
	}
}

func TestAcceptedArchiveAllowsRepeatedDirectoryHeadersWithoutOverwrite(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "out")
	data := makeTarGzip(t, []tarMember{
		{name: "root/", kind: tar.TypeDir},
		{name: "root/repeated/", kind: tar.TypeDir},
		{name: "root/repeated/", kind: tar.TypeDir},
		{name: "root/repeated/file", kind: tar.TypeReg, contents: "fixed"},
	})
	if err := extractAcceptedArchive(data, destination, archivePolicy{stripTopDirectory: true}); err != nil {
		t.Fatal(err)
	}
	dataOnDisk, err := os.ReadFile(filepath.Join(destination, "repeated", "file"))
	if err != nil || string(dataOnDisk) != "fixed" {
		t.Fatalf("materialized file=%q err=%v", dataOnDisk, err)
	}
}

func TestProductionSourceDigestExcludesOnlyRealTargetDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pom.xml"), []byte("fixed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	before, _, err := digestProductionSourceTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "target", "classes.bin"), []byte("generated"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, _, err := digestProductionSourceTree(root)
	if err != nil || after != before {
		t.Fatalf("generated target changed production digest: before=%s after=%s err=%v", before, after, err)
	}
	if err := os.WriteFile(filepath.Join(root, "pom.xml"), []byte("mutated"), 0o600); err != nil {
		t.Fatal(err)
	}
	mutated, _, err := digestProductionSourceTree(root)
	if err != nil || mutated == before {
		t.Fatalf("production mutation was not detected: before=%s mutated=%s err=%v", before, mutated, err)
	}
}

func TestAcceptedSourceCopyStartsByteExactAndDetectsProductionMutation(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "accepted-source")
	build := filepath.Join(base, "workspace", "build")
	if err := os.MkdirAll(filepath.Join(source, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(build), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "pom.xml"), []byte("fixed-pom"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "src", "Main.java"), []byte("class Main {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, _, err := digestTree(source, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyAcceptedSourceTree(source, build); err != nil {
		t.Fatal(err)
	}
	got, _, err := digestProductionSourceTree(build)
	if err != nil || got != want {
		t.Fatalf("copy digest=%s want=%s err=%v", got, want, err)
	}
	if err := os.Mkdir(filepath.Join(build, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(build, "target", "artifact"), []byte("generated"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, err = digestProductionSourceTree(build)
	if err != nil || got != want {
		t.Fatalf("generated output affected production copy digest=%s want=%s err=%v", got, want, err)
	}
}

func TestAcceptedToolArchiveAllowsOnlyConfinedSymlinks(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "tools")
	data := makeTarGzip(t, []tarMember{{name: "tool/target", kind: tar.TypeReg, contents: "ok"}, {name: "tool/link", kind: tar.TypeSymlink, link: "target"}})
	if err := extractAcceptedArchive(data, destination, archivePolicy{allowSymlinks: true}); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(destination, "tool", "link")); err != nil || target != "target" {
		t.Fatalf("link=%q err=%v", target, err)
	}
	escape := makeTarGzip(t, []tarMember{{name: "tool/link", kind: tar.TypeSymlink, link: "../../escape"}})
	if err := extractAcceptedArchive(escape, filepath.Join(t.TempDir(), "escape"), archivePolicy{allowSymlinks: true}); err == nil {
		t.Fatal("escaping link accepted")
	}
}

func makeTarGzip(t *testing.T, members []tarMember) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, member := range members {
		header := &tar.Header{Name: member.name, Typeflag: member.kind, Mode: 0o644, Linkname: member.link, Size: int64(len(member.contents))}
		if member.kind == tar.TypeDir || member.kind == tar.TypeSymlink {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tarWriter.Write([]byte(member.contents)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
