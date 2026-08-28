package projection_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/projection"
)

func TestCaptureRejectsSymlinkInputAndLock(t *testing.T) {
	root := fixtureRoot(t)
	target := filepath.Join(root, "contracts", "laboratory-template.json")
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(repositoryRoot(t), "contracts", "laboratory-template.json"), target); err != nil {
		t.Fatal(err)
	}
	if _, err := projection.Capture(root); err == nil {
		t.Fatal("symlink input accepted")
	}

	root = fixtureRoot(t)
	if err := os.WriteFile(filepath.Join(root, ".us027-projection.lock"), []byte("held\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := projection.Capture(root); err == nil {
		t.Fatal("existing lock accepted")
	}
}

func TestVerifyRejectsUnexpectedPublicDescendant(t *testing.T) {
	root := fixtureRoot(t)
	if _, err := projection.Capture(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "public", "unexpected.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := projection.Verify(root); err == nil {
		t.Fatal("unexpected public descendant accepted")
	}
}
