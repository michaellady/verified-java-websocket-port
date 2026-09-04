package lab

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func TestAutobahnEndpointSourcePin(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "autobahn-endpoint", "src", "main", "java", "AutobahnEndpoint.java"))
	if err != nil {
		t.Fatal(err)
	}
	if got := intake.DigestBytes(data); got != AutobahnEndpointSourceDigest {
		t.Fatalf("source pin drift: got %s", got)
	}
}

func TestCopyExactRegularIsByteCopy(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "runtime-object")
	destination := filepath.Join(directory, "runtime.jar")
	data := []byte("exact-runtime")
	if err := os.WriteFile(source, data, 0o400); err != nil {
		t.Fatal(err)
	}
	digest := intake.DigestBytes(data)
	if err := copyExactRegular(source, destination, digest); err != nil {
		t.Fatal(err)
	}
	if sameFilesystemIdentity(source, destination) {
		t.Fatal("copy reused source identity")
	}
	if got, err := os.ReadFile(destination); err != nil || string(got) != string(data) {
		t.Fatalf("copy mismatch: %q %v", got, err)
	}
	if err := copyExactRegular(source, destination, digest); err == nil {
		t.Fatal("existing destination was overwritten")
	}
}

func TestBoundArtifactRejectsLinksAndDigestDrift(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "source")
	if err := os.WriteFile(source, []byte("bytes"), 0o400); err != nil {
		t.Fatal(err)
	}
	digest := intake.DigestBytes([]byte("bytes"))
	if _, err := boundArtifact("artifact", source, digest, 1024); err != nil {
		t.Fatal(err)
	}
	if _, err := boundArtifact("artifact", source, intake.DigestBytes([]byte("different")), 1024); err == nil {
		t.Fatal("digest drift accepted")
	}
	link := filepath.Join(directory, "link")
	if err := os.Link(source, link); err != nil {
		t.Fatal(err)
	}
	if _, err := boundArtifact("artifact", source, digest, 1024); err == nil {
		t.Fatal("multiply linked source accepted")
	}
}
