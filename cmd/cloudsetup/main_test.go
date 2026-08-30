package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
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
		{Name: "java-oracle", Dir: root, Path: "make", Args: []string{"-C", "java-oracle", "build", "JAVA_WEBSOCKET_JAR=../.quarantine/Java-WebSocket-1.6.0.jar"}},
	}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("setup plan = %#v, want %#v", plan, want)
	}
	paths := cloudPaths(home)
	if paths.KaniRoot != filepath.Join(home, ".cache", "verified-java-websocket-port", "kani-37960b2bea71") ||
		paths.CBMCRoot != filepath.Join(home, ".cache", "verified-java-websocket-port", "cbmc-6.11.0-ubuntu-24.04") ||
		paths.JavaHome != filepath.Join(home, ".cache", "verified-java-websocket-port", "jdk-17.0.19+10") ||
		paths.MavenHome != filepath.Join(home, ".cache", "verified-java-websocket-port", "apache-maven-3.9.11") {
		t.Fatalf("cloud paths = %#v", paths)
	}
}

func TestJavaOracleIdentityMatchesDifferentialEvidence(t *testing.T) {
	if javaOracleSHA256 != "sha256:a9f895456837a90ae7e7652421f4d4c41ed9643e0b9f9f9e4d2a552007e769c7" || javaOracleBytes != 38637 {
		t.Fatalf("Java oracle identity drifted: digest=%s bytes=%d", javaOracleSHA256, javaOracleBytes)
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

func TestFormalToolClosureUsesExactPublicPinsWithoutUpstreamInstaller(t *testing.T) {
	if kaniURL != "https://github.com/model-checking/kani.git" ||
		kaniCommit != "37960b2bea719b86f3a99d28b650110203cffabb" ||
		kaniTree != "140c732427576e199ba96406f3657b2c2008d35d" ||
		kaniCharonCommit != "b250680abd40ff1aaa07081d0497dc2755ed112e" ||
		kaniCharonTree != "a83f56525e28511f65e17584db0303fed72b00b2" {
		t.Fatalf("Kani source pin drifted: url=%s commit=%s tree=%s charon_commit=%s charon_tree=%s", kaniURL, kaniCommit, kaniTree, kaniCharonCommit, kaniCharonTree)
	}
	if cbmcUbuntu2404.URL != "https://github.com/diffblue/cbmc/releases/download/cbmc-6.11.0/ubuntu-24.04-cbmc-6.11.0-Linux.deb" ||
		cbmcUbuntu2404.SHA256 != "sha256:b3721aa541038384d7801ea3aeabbcddc3e8845ac8f1cbff637cf8dec7481ac8" ||
		cbmcUbuntu2404.Bytes != 73477756 {
		t.Fatalf("CBMC pin drifted: %#v", cbmcUbuntu2404)
	}
	want := []commandSpec{
		{Name: "submodules-kani", Dir: "/kani", Path: "git", Args: []string{"submodule", "update", "--init", "--depth", "1"}},
		{Name: "build-kani", Dir: "/kani", Path: "cargo", Args: []string{"build-dev"}},
	}
	plan := kaniBuildPlan("/kani")
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("Kani build plan = %#v, want %#v", plan, want)
	}
	for _, command := range plan {
		joined := command.Path + " " + strings.Join(command.Args, " ")
		if strings.Contains(joined, "install_deps") || strings.Contains(joined, "install_cbmc") ||
			strings.Contains(joined, "install_kissat") || strings.Contains(joined, "cvc5") {
			t.Fatalf("Kani build delegates unpinned dependency installation: %s", joined)
		}
	}
	checkout := kaniCheckoutCommand("/kani")
	wantCheckout := commandSpec{Name: "checkout-kani", Dir: "/kani", Path: "git", Args: []string{"checkout", "--detach", kaniCommit}}
	if !reflect.DeepEqual(checkout, wantCheckout) {
		t.Fatalf("Kani checkout command = %#v, want %#v", checkout, wantCheckout)
	}
}

func TestTrackedStatusDiagnosticIsBounded(t *testing.T) {
	status := "D  first\nD  second\nD  third\n"
	if got := summarizeStatus(status, 2); got != "D  first; D  second; ..." {
		t.Fatalf("summarizeStatus = %q", got)
	}
}

func TestCloudEnvironmentExportsPinnedFormalTools(t *testing.T) {
	home := t.TempDir()
	if err := appendBashEnvironment(home, cloudPaths(home)); err != nil {
		t.Fatal(err)
	}
	bashrc, err := os.ReadFile(filepath.Join(home, ".bashrc"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("VJWP_KANI_ROOT"),
		[]byte("VJWP_CBMC_ROOT"),
		[]byte("$VJWP_KANI_ROOT/scripts"),
		[]byte("$VJWP_CBMC_ROOT/usr/bin"),
	} {
		if !bytes.Contains(bashrc, required) {
			t.Fatalf("managed environment does not export %q: %s", required, bashrc)
		}
	}
}

func TestCloudOperatingSystemMustBeUbuntu2404(t *testing.T) {
	if err := verifyOperatingSystem([]byte("NAME=Ubuntu\nID=ubuntu\nVERSION_ID=\"24.04\"\n")); err != nil {
		t.Fatalf("Ubuntu 24.04 rejected: %v", err)
	}
	for _, body := range [][]byte{
		[]byte("ID=ubuntu\nVERSION_ID=\"22.04\"\n"),
		[]byte("ID=debian\nVERSION_ID=\"24.04\"\n"),
		[]byte("ID=ubuntu\n"),
	} {
		if err := verifyOperatingSystem(body); err == nil {
			t.Fatalf("unsupported operating system accepted: %q", body)
		}
	}
}

func TestCBMCPackageAndPayloadValidationFailClosed(t *testing.T) {
	if err := verifyDebianMembers("debian-binary\ncontrol.tar.gz\ndata.tar.gz\n"); err != nil {
		t.Fatalf("exact Debian members rejected: %v", err)
	}
	for _, members := range []string{
		"debian-binary\ndata.tar.gz\ncontrol.tar.gz\n",
		"debian-binary\ncontrol.tar.gz\ndata.tar.gz\npostinst\n",
	} {
		if err := verifyDebianMembers(members); err == nil {
			t.Fatalf("unexpected Debian members accepted: %q", members)
		}
	}

	valid := writeTestTarGzip(t, []tar.Header{
		{Name: "./usr/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "./usr/bin/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "./usr/bin/cbmc", Typeflag: tar.TypeReg, Mode: 0o755},
		{Name: "./usr/bin/goto-gcc", Typeflag: tar.TypeSymlink, Linkname: "goto-cc"},
	})
	if err := validateTarGzip(valid, "usr"); err != nil {
		t.Fatalf("valid CBMC payload rejected: %v", err)
	}

	for _, headers := range [][]tar.Header{
		{{Name: "./usr/bin/cbmc", Typeflag: tar.TypeReg, Mode: 0o755}, {Name: "../../escape", Typeflag: tar.TypeReg}},
		{{Name: "./usr/bin/cbmc", Typeflag: tar.TypeSymlink, Linkname: "../../../escape"}},
		{{Name: "/usr/bin/cbmc", Typeflag: tar.TypeReg, Mode: 0o755}},
		{{Name: "./usr/device", Typeflag: tar.TypeChar}},
	} {
		archive := writeTestTarGzip(t, headers)
		if err := validateTarGzip(archive, "usr"); err == nil {
			t.Fatalf("unsafe archive accepted: %#v", headers)
		}
	}
}

func TestPinnedJDKArchiveFixture(t *testing.T) {
	archive := os.Getenv("VJWP_CLOUDSETUP_JDK_ARCHIVE")
	if archive == "" {
		t.Skip("set VJWP_CLOUDSETUP_JDK_ARCHIVE to exercise the probed Linux archive")
	}
	if err := validateTarGzip(archive, "jdk-17.0.19+10"); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedCBMCPackageFixture(t *testing.T) {
	archive := os.Getenv("VJWP_CLOUDSETUP_CBMC_PACKAGE")
	if archive == "" {
		t.Skip("set VJWP_CLOUDSETUP_CBMC_PACKAGE to exercise the probed Linux package")
	}
	destination := filepath.Join(t.TempDir(), "cbmc")
	var output bytes.Buffer
	if err := ensureCBMC(cbmcUbuntu2404, archive, destination, &output, &output); err != nil {
		t.Fatalf("materialize CBMC: %v\n%s", err, output.String())
	}
	command := exec.Command(filepath.Join(destination, "usr", "bin", "cbmc"), "--version")
	body, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(body, []byte("6.11.0 (cbmc-6.11.0)")) {
		t.Fatalf("run materialized CBMC: %v\n%s", err, body)
	}
}

func writeTestTarGzip(t *testing.T, headers []tar.Header) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.tar.gz")
	handle, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(handle)
	archive := tar.NewWriter(compressed)
	for index := range headers {
		header := headers[index]
		if err := archive.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	return path
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

func TestCloudEnvironmentPrecedesUbuntuNoninteractiveReturnAndMigratesCache(t *testing.T) {
	home := t.TempDir()
	cloud := cloudPaths(home)
	ubuntuGuard := []byte("# If not running interactively, don't do anything\ncase $- in\n    *i*) ;;\n      *) return;;\nesac\nexport UNRELATED=preserved\n")
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), ubuntuGuard, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := appendBashEnvironment(home, cloud); err != nil {
		t.Fatal(err)
	}
	assertCloudEnvironmentLoadsBeforeGuard(t, home, cloud)

	first, err := os.ReadFile(filepath.Join(home, ".bashrc"))
	if err != nil {
		t.Fatal(err)
	}
	begin := []byte("# verified-java-websocket-port cloud environment (managed block)")
	end := []byte("# end verified-java-websocket-port cloud environment\n")
	start := bytes.Index(first, begin)
	finish := bytes.Index(first, end)
	if start != 0 || finish < 0 {
		t.Fatalf("managed block not prepended: %s", first)
	}
	finish += len(end)
	legacy := append(append([]byte(nil), ubuntuGuard...), first[start:finish]...)
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := appendBashEnvironment(home, cloud); err != nil {
		t.Fatal(err)
	}
	migrated, err := os.ReadFile(filepath.Join(home, ".bashrc"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(migrated, begin) != 1 || !bytes.HasPrefix(migrated, begin) || !bytes.Contains(migrated, []byte("export UNRELATED=preserved")) {
		t.Fatalf("cached block was not migrated without disturbing user content: %s", migrated)
	}
	assertCloudEnvironmentLoadsBeforeGuard(t, home, cloud)
}

func assertCloudEnvironmentLoadsBeforeGuard(t *testing.T, home string, cloud paths) {
	t.Helper()
	command := exec.Command("bash", "-c", `source "$HOME/.bashrc"; printf '%s\n%s\n' "$JAVA_HOME" "$MAVEN_HOME"`)
	command.Env = append(os.Environ(), "HOME="+home)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("source managed environment: %v: %s", err, output)
	}
	want := cloud.JavaHome + "\n" + cloud.MavenHome + "\n"
	if string(output) != want {
		t.Fatalf("noninteractive environment = %q, want %q", output, want)
	}
}

func TestEnsureRepositoryHistoryRestoresDetachedShallowCheckoutWithoutRemote(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	runTestGit(t, "", "init", source)
	runTestGit(t, source, "config", "user.name", "Cloud Setup Test")
	runTestGit(t, source, "config", "user.email", "cloudsetup@example.test")
	if err := os.WriteFile(filepath.Join(source, "tracked.txt"), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, source, "add", "tracked.txt")
	runTestGit(t, source, "commit", "-m", "old")
	oldCommit := strings.TrimSpace(runTestGit(t, source, "rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(source, "tracked.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, source, "add", "tracked.txt")
	runTestGit(t, source, "commit", "-m", "new")

	checkout := filepath.Join(t.TempDir(), "checkout")
	runTestGit(t, "", "clone", "--depth", "1", "--no-tags", "file://"+source, checkout)
	runTestGit(t, checkout, "remote", "remove", "origin")
	head := strings.TrimSpace(runTestGit(t, checkout, "rev-parse", "HEAD"))
	if command := exec.Command("git", "-C", checkout, "cat-file", "-e", oldCommit+"^{commit}"); command.Run() == nil {
		t.Fatal("shallow fixture unexpectedly contains historical commit")
	}

	var output bytes.Buffer
	if err := ensureRepositoryHistory(checkout, "file://"+source, os.Environ(), &output, &output); err != nil {
		t.Fatalf("restore repository history: %v\n%s", err, output.String())
	}
	if got := strings.TrimSpace(runTestGit(t, checkout, "rev-parse", "HEAD")); got != head {
		t.Fatalf("history restoration moved HEAD from %s to %s", head, got)
	}
	runTestGit(t, checkout, "cat-file", "-e", oldCommit+"^{commit}")
	if got := strings.TrimSpace(runTestGit(t, checkout, "rev-parse", "--is-shallow-repository")); got != "false" {
		t.Fatalf("repository remains shallow: %s", got)
	}
	if got := strings.TrimSpace(runTestGit(t, checkout, "status", "--porcelain")); got != "" {
		t.Fatalf("history restoration changed working tree: %s", got)
	}
	if got := strings.TrimSpace(runTestGit(t, checkout, "remote")); got != "" {
		t.Fatalf("history restoration invented a configured remote: %s", got)
	}
}

func runTestGit(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	if directory != "" {
		command = exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return string(output)
}
