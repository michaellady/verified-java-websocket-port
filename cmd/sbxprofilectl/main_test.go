package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryProfileCatalogPasses(t *testing.T) {
	value, err := loadCatalog("../..")
	if err != nil {
		t.Fatal(err)
	}
	if value.LaunchReady || len(value.Profiles) != 6 {
		t.Fatalf("catalog = launch_ready:%t profiles:%d", value.LaunchReady, len(value.Profiles))
	}
}

func TestClosedProfileInvariantsRejectUnsafeMutations(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*catalog)
		wantErr string
	}{
		{
			name: "shared skills",
			mutate: func(value *catalog) {
				value.Profiles[0].SharedSkills = true
			},
			wantErr: "least-privilege",
		},
		{
			name: "published port",
			mutate: func(value *catalog) {
				value.Profiles[0].PublishedPorts = []string{"8080:8080"}
			},
			wantErr: "least-privilege",
		},
		{
			name: "direct workspace",
			mutate: func(value *catalog) {
				value.Profiles[0].WorkspaceMode = "direct"
			},
			wantErr: "least-privilege",
		},
		{
			name: "host stdio mcp",
			mutate: func(value *catalog) {
				value.Profiles[0].HostStdioMCP = true
			},
			wantErr: "least-privilege",
		},
		{
			name: "missing stable baseline blocker",
			mutate: func(value *catalog) {
				value.Profiles[0].Blockers = value.Profiles[0].Blockers[1:]
			},
			wantErr: "stable SBX isolation blocker",
		},
		{
			name: "arm64 claims authoritative bootstrap",
			mutate: func(value *catalog) {
				value.Profiles[0].BootstrapCommand = value.AMD64BootstrapCommand
			},
			wantErr: "development lane",
		},
		{
			name: "shared contract kit removed",
			mutate: func(value *catalog) {
				value.Profiles[0].Kits = nil
				value.Profiles[0].LaunchArgv = canonicalLaunch(value.Profiles[0])
			},
			wantErr: "port-contract kit",
		},
		{
			name: "launch drops no-share-skills",
			mutate: func(value *catalog) {
				arguments := append([]string(nil), value.Profiles[0].LaunchArgv...)
				value.Profiles[0].LaunchArgv = append(arguments[:3], arguments[4:]...)
			},
			wantErr: "launch_argv",
		},
		{
			name: "kit digest changed",
			mutate: func(value *catalog) {
				value.KitFilesSHA256["sbx/kits/port-contract/spec.yaml"] = "sha256:" + strings.Repeat("0", 64)
			},
			wantErr: "content digest does not match",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := loadCatalog("../..")
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&value)
			err = validateCatalog("../..", value)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateCatalog() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestValidateKitBindingsRejectsUnboundFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "kit")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	spec := []byte("schemaVersion: 2\n")
	if err := os.WriteFile(filepath.Join(directory, "spec.yaml"), spec, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unbound"), []byte("unsafe"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spec)
	value := catalog{
		KitFilesSHA256: map[string]string{"kit/spec.yaml": "sha256:" + hex.EncodeToString(sum[:])},
		Profiles:       []profile{{Kits: []string{"kit"}}},
	}
	if err := validateKitBindings(root, value); err == nil || !strings.Contains(err.Error(), "no digest binding") {
		t.Fatalf("validateKitBindings() error = %v, want unbound-file rejection", err)
	}
}

func TestResolveRegularFileRejectsSymlinkComponents(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "spec.yaml"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "kit")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveRegularFile(root, "kit/spec.yaml"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("resolveRegularFile() error = %v, want symlink rejection", err)
	}
}

func TestShowCommandIsReadOnlyAndLabelsBlockedProfile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"show-command", "--root", "../..", "--id", "muse-amd64-formal"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	output := stdout.String()
	for _, required := range []string{"# BLOCKED:", "sbx run --clone --no-share-skills", "--kit sbx/kits/muse-code", "--kit sbx/kits/port-contract", "muse-code ."} {
		if !strings.Contains(output, required) {
			t.Fatalf("show-command output missing %q: %s", required, output)
		}
	}
}

func TestUnknownProfileFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"show-command", "--root", "../..", "--id", "missing"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}
