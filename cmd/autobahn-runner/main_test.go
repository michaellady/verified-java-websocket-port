package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixedContractHasNoArbitraryExecutableOrConfiguration(t *testing.T) {
	for _, role := range []string{"fuzzingclient", "fuzzingserver"} {
		contract, err := fixedContract(role)
		if err != nil || contract.role != role || len(contract.arguments) != 4 || contract.arguments[1] != role || contract.arguments[3] != contract.configPath {
			t.Fatalf("invalid fixed contract for %s: %#v %v", role, contract, err)
		}
	}
	for _, role := range []string{"", "client", "fuzzingclient;sh", "fuzzingserver\n"} {
		if _, err := fixedContract(role); err == nil {
			t.Fatalf("accepted arbitrary role %q", role)
		}
	}
}

func TestCopySignalIsExactAndSingleUse(t *testing.T) {
	token := strings.Repeat("a", 64)
	if err := readCopySignal(strings.NewReader(token+"\n"), token); err != nil {
		t.Fatal(err)
	}
	for _, hostile := range []string{token, token + "\nextra", strings.Repeat("b", 64) + "\n", ""} {
		if err := readCopySignal(strings.NewReader(hostile), token); err == nil {
			t.Fatalf("accepted hostile signal %q", hostile)
		}
	}
}

func TestChildOutputIsBoundedAndDigestBound(t *testing.T) {
	var destination bytes.Buffer
	writer := newBoundedDigestWriter(&destination, 4)
	if written, err := writer.Write([]byte("test")); err != nil || written != 4 {
		t.Fatalf("bounded write = %d, %v", written, err)
	}
	if _, err := writer.Write([]byte("x")); err == nil {
		t.Fatal("accepted output beyond bound")
	}
	digest, count := writer.receipt()
	if digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" || count != 4 || destination.String() != "test" {
		t.Fatalf("receipt = %s/%d output=%q", digest, count, destination.String())
	}
}

func TestReportArchiveStreamsExactBoundedRegularSet(t *testing.T) {
	directory := t.TempDir()
	want := map[string]string{
		"index.html": "index-html", "index.json": "index-json",
		"java_websocket_adapter_case_1_1_1.html": "case-html",
		"java_websocket_adapter_case_1_1_1.json": "case-json",
	}
	for name, content := range want {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := writeReportArchive(directory, &output); err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(&output)
	got := make(map[string]string)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg || header.Mode != 0o400 {
			t.Fatalf("unsafe header for %q: type=%d mode=%o", header.Name, header.Typeflag, header.Mode)
		}
		got[header.Name] = string(data)
	}
	if len(got) != len(want) {
		t.Fatalf("archive entries=%v", got)
	}
	for name, content := range want {
		if got[name] != content {
			t.Fatalf("archive content %q=%q", name, got[name])
		}
	}
}

func TestReportArchiveRejectsRetainedAndHostileFilesystemShapes(t *testing.T) {
	for name, arrange := range map[string]func(*testing.T, string){
		"empty tmpfs copy result": func(t *testing.T, directory string) {},
		"fewer than four": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "index.json"), []byte("x"), 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"nested directory": func(t *testing.T, directory string) {
			if err := os.Mkdir(filepath.Join(directory, "nested"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, directory string) {
			if err := os.Symlink("missing", filepath.Join(directory, "index.json")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			arrange(t, directory)
			if err := writeReportArchive(directory, io.Discard); err == nil {
				t.Fatal("hostile report directory accepted")
			}
		})
	}
}
