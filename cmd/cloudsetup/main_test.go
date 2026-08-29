package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCloudSetupPlanUsesExactProjectAndVerifierPins(t *testing.T) {
	root := filepath.Clean("/repo")
	home := filepath.Clean("/home/codex")
	plan := setupPlan(root, home)
	want := []commandSpec{
		{Name: "rust-toolchain", Dir: root, Path: "rustup", Args: []string{"toolchain", "install", "1.95.0", "--profile", "minimal", "--component", "rustfmt", "--component", "clippy"}},
		{Name: "go-dependencies", Dir: root, Path: "go", Args: []string{"mod", "download"}},
		{Name: "rust-dependencies", Dir: root, Path: "cargo", Args: []string{"+1.95.0", "fetch", "--locked", "--manifest-path", filepath.Join(root, "rust", "Cargo.toml")}},
	}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("setup plan = %#v, want %#v", plan, want)
	}
	if kaniCommit != "37960b2bea719b86f3a99d28b650110203cffabb" ||
		kaniTree != "140c732427576e199ba96406f3657b2c2008d35d" {
		t.Fatalf("Kani source pin drifted: commit=%s tree=%s", kaniCommit, kaniTree)
	}
	paths := cloudPaths(home)
	if paths.KaniRoot != filepath.Join(home, ".cache", "verified-java-websocket-port", "kani-37960b2bea71") ||
		paths.JavaHome != filepath.Join(home, ".cache", "verified-java-websocket-port", "jdk-17.0.19+10") ||
		paths.MavenHome != filepath.Join(home, ".cache", "verified-java-websocket-port", "apache-maven-3.9.11") {
		t.Fatalf("cloud paths = %#v", paths)
	}
}

func TestLoadCloudPinsUsesTheRetainedImmutableCatalog(t *testing.T) {
	root := filepath.Join("..", "..")
	pins, err := loadCloudPins(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]downloadPin{
		"java-websocket-source-archive": {
			URL:    "https://github.com/TooTallNate/Java-WebSocket/archive/da3cf2a777aed862f2f5b5cf060cae7969958667.tar.gz",
			SHA256: "sha256:f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4",
			Bytes:  190008,
		},
		"java-websocket-runtime-jar": {
			URL:    "https://repo1.maven.org/maven2/org/java-websocket/Java-WebSocket/1.6.0/Java-WebSocket-1.6.0.jar",
			SHA256: "sha256:eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f",
			Bytes:  140686,
		},
		"apache-maven-3.9.11": {
			URL:    "https://archive.apache.org/dist/maven/maven-3/3.9.11/binaries/apache-maven-3.9.11-bin.tar.gz",
			SHA256: "sha256:4b7195b6a4f5c81af4c0212677a32ee8143643401bc6e1e8412e6b06ea82beac",
			Bytes:  9160848,
		},
	}
	for id, expected := range want {
		if pins[id] != expected {
			t.Errorf("pin %s = %#v, want %#v", id, pins[id], expected)
		}
	}
}

func TestLinuxJDKPinIsTheProbedTemurinRelease(t *testing.T) {
	if linuxJDK.URL != "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.19%2B10/OpenJDK17U-jdk_x64_linux_hotspot_17.0.19_10.tar.gz" ||
		linuxJDK.SHA256 != "sha256:d8afc263758141a66e0e3aafc321e783f7016696f4eaea067d340a269037d331" ||
		linuxJDK.Bytes != 193335385 {
		t.Fatalf("Linux JDK pin drifted: %#v", linuxJDK)
	}
}

func TestLoadCloudPinsRejectsDuplicateSelectedArtifact(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "evidence", "intake")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	artifact := `{"id":"java-websocket-source-archive","immutable_url":"https://example.test/source.tar.gz","sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","byte_size":1}`
	document := `{"schema_version":"test","artifacts":[` + artifact + `,` + artifact + `]}`
	if err := os.WriteFile(filepath.Join(path, "source-pins.json"), []byte(document), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadCloudPins(root)
	if err == nil || !strings.Contains(err.Error(), "is duplicated") {
		t.Fatalf("loadCloudPins duplicate error = %v", err)
	}
}

func TestAppendBashEnvironmentIsIdempotentAndFailsClosedOnDrift(t *testing.T) {
	home := t.TempDir()
	cloud := cloudPaths(home)
	if err := appendBashEnvironment(home, cloud); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(home, ".bashrc"))
	if err != nil {
		t.Fatal(err)
	}
	if err := appendBashEnvironment(home, cloud); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(home, ".bashrc"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("managed block was appended more than once")
	}
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("# verified-java-websocket-port cloud environment (managed block)\nchanged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := appendBashEnvironment(home, cloud); err == nil {
		t.Fatal("drifted managed block was accepted")
	}
}
