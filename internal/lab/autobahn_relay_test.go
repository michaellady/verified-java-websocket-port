package lab

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func TestAutobahnRelaySourcePin(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "cmd", "autobahn-relay", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if digest := intake.DigestBytes(data); digest != AutobahnRelaySourceDigest {
		t.Fatalf("relay source pin drift: %s", digest)
	}
}

func TestVerifyStaticLinuxAMD64RejectsNonELF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay")
	if err := os.WriteFile(path, []byte("not-elf"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := verifyStaticLinuxAMD64(path); err == nil {
		t.Fatal("non-ELF relay accepted")
	}
}

func TestAutobahnRelayToolchainProbe(t *testing.T) {
	root := os.Getenv("AUTOBAHN_RELAY_E2E_GOROOT")
	if root == "" {
		t.Skip("owner-qualified relay toolchain is not configured")
	}
	digest, _, err := digestTree(root, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GOROOT_DIGEST=%s", digest)
}

func TestAutobahnRelayBuildE2E(t *testing.T) {
	root := os.Getenv("AUTOBAHN_RELAY_E2E_GOROOT")
	source := os.Getenv("AUTOBAHN_RELAY_E2E_SOURCE")
	if root == "" || source == "" {
		t.Skip("owner-qualified relay build inputs are not configured")
	}
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	receipt, err := BuildAutobahnRelay(ctx, AutobahnRelayBuildConfig{SourcePath: source, GoRoot: root, WorkDirectory: filepath.Join(work, "relay")})
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.RepeatableBuild || !receipt.LinuxAMD64StaticELF || !receipt.SourceUnchanged || !receipt.ToolchainUnchanged || receipt.Qualification != "QUALIFIED_NOT_PROMOTED" {
		t.Fatalf("relay build proof incomplete: %+v", receipt)
	}
}
