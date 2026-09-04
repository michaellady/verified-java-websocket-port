package lab

import (
	"context"
	"path/filepath"
	"testing"
)

func TestBuildAutobahnRunnerRejectsUnpinnedSource(t *testing.T) {
	directory := t.TempDir()
	if _, err := BuildAutobahnRunner(context.Background(), AutobahnRunnerBuildConfig{
		SourcePath: filepath.Join(directory, "missing.go"), GoRoot: directory, WorkDirectory: filepath.Join(directory, "work"),
	}); err == nil {
		t.Fatal("accepted missing and unpinned runner source/toolchain")
	}
}

func TestExactAutobahnRunnerRejectsSecurityDrift(t *testing.T) {
	receipt := AutobahnRunnerReceipt{
		Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT", Qualification: "QUALIFIED_NOT_PROMOTED",
		Source: AutobahnArtifactBinding{Digest: AutobahnRunnerSourceDigest}, Binary: AutobahnArtifactBinding{Digest: AutobahnRunnerBinaryDigest, Bytes: 1, Links: 1},
		GoExecutable: AutobahnArtifactBinding{Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		GoVersion:    AutobahnRelayGoVersion, GoRootDigest: AutobahnRelayGoRootDigest, WSTestPath: AutobahnWSTestPath,
		WSTestDigest: AutobahnWSTestDigest, InterpreterPath: AutobahnPyPyPath, InterpreterDigest: AutobahnPyPyDigest,
		RepeatableBuild: true, LinuxAMD64StaticELF: true, SourceUnchanged: true, ToolchainUnchanged: true,
	}
	if !exactAutobahnRunner(receipt) {
		t.Fatal("exact runner rejected")
	}
	receipt.WSTestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if exactAutobahnRunner(receipt) {
		t.Fatal("accepted drifted wstest digest")
	}
}
