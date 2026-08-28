package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRejectsRelativeRepeatedAndInvalidTimeArguments(t *testing.T) {
	root := t.TempDir()
	valid := []string{"qualify", "--repository-root", root, "--toolchain-bin-dir", filepath.Join(root, "toolchain"), "--go", filepath.Join(root, "go"), "--validation-time", "2026-08-28T12:00:00Z"}
	if _, err := parse(valid); err != nil {
		t.Fatalf("valid arguments rejected: %v", err)
	}
	for name, mutate := range map[string]func([]string){
		"relative root": func(arguments []string) { arguments[2] = "." },
		"repeated flag": func(arguments []string) { arguments[3] = "--repository-root" },
		"invalid time":  func(arguments []string) { arguments[8] = "now" },
	} {
		t.Run(name, func(t *testing.T) {
			arguments := append([]string(nil), valid...)
			mutate(arguments)
			if _, err := parse(arguments); err == nil {
				t.Fatal("invalid arguments were accepted")
			}
		})
	}
}

func TestParseRustcIdentityRequiresReleaseAndHost(t *testing.T) {
	release, host, err := parseRustcIdentity([]byte("rustc 1.95.0 (59807616e 2026-04-14)\nhost: aarch64-apple-darwin\n"))
	if err != nil || release != "rustc 1.95.0 (59807616e 2026-04-14)" || host != "aarch64-apple-darwin" {
		t.Fatalf("identity = %q %q %v", release, host, err)
	}
	for _, raw := range [][]byte{[]byte("host: aarch64-apple-darwin\n"), []byte("rustc 1.95.0\n")} {
		if _, _, err := parseRustcIdentity(raw); err == nil {
			t.Fatal("incomplete identity was accepted")
		}
	}
}

func TestBoundedTailKeepsOnlyTheDiagnosticSuffix(t *testing.T) {
	raw := bytes.Repeat([]byte("x"), 5000)
	tail := boundedTail(raw, 4096)
	if len(tail) != 4096 || strings.Contains(tail, "\n") {
		t.Fatalf("tail length/content = %d", len(tail))
	}
}
