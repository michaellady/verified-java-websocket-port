// Command cloudsetup materializes the exact public dependencies needed by a
// Codex cloud worker and prepares the pinned Rust and Kani toolchains.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/portplan"
)

const (
	kaniCommit = "37960b2bea719b86f3a99d28b650110203cffabb"
	kaniTree   = "140c732427576e199ba96406f3657b2c2008d35d"
	kaniURL    = "https://github.com/model-checking/kani.git"
	cacheName  = "verified-java-websocket-port"
)

var linuxJDK = downloadPin{
	URL:    "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.19%2B10/OpenJDK17U-jdk_x64_linux_hotspot_17.0.19_10.tar.gz",
	SHA256: "sha256:d8afc263758141a66e0e3aafc321e783f7016696f4eaea067d340a269037d331",
	Bytes:  193335385,
}

type downloadPin struct {
	URL    string
	SHA256 string
	Bytes  int64
}

type sourcePinDocument struct {
	Artifacts []struct {
		ID           string `json:"id"`
		ImmutableURL string `json:"immutable_url"`
		SHA256       string `json:"sha256"`
		ByteSize     int64  `json:"byte_size"`
	} `json:"artifacts"`
}

type commandSpec struct {
	Name string
	Dir  string
	Path string
	Args []string
}

type paths struct {
	KaniRoot  string `json:"kani_root"`
	JavaHome  string `json:"java_home"`
	MavenHome string `json:"maven_home"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		usage(stderr)
		return 2
	}
	flags := flag.NewFlagSet(arguments[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	home := flags.String("home", os.Getenv("HOME"), "cloud worker home")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	rootPath, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	homePath, err := filepath.Abs(*home)
	if err != nil || strings.ContainsAny(homePath, "\r\n") {
		fmt.Fprintln(stderr, "home must resolve to one absolute path")
		return 1
	}
	switch arguments[0] {
	case "paths":
		return encode(stdout, cloudPaths(homePath))
	case "setup", "maintain":
		if err := prepare(rootPath, homePath, stdout, stderr); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return encode(stdout, cloudPaths(homePath))
	default:
		usage(stderr)
		return 2
	}
}

func usage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: cloudsetup setup|maintain|paths --root DIR [--home DIR]")
}

func encode(writer io.Writer, value any) int {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return 1
	}
	return 0
}

func cloudPaths(home string) paths {
	root := filepath.Join(home, ".cache", cacheName)
	return paths{
		KaniRoot:  filepath.Join(root, "kani-"+kaniCommit[:12]),
		JavaHome:  filepath.Join(root, "jdk-17.0.19+10"),
		MavenHome: filepath.Join(root, "apache-maven-3.9.11"),
	}
}

func setupPlan(root, _ string) []commandSpec {
	return []commandSpec{
		{Name: "rust-toolchain", Dir: root, Path: "rustup", Args: []string{"toolchain", "install", "1.95.0", "--profile", "minimal", "--component", "rustfmt", "--component", "clippy"}},
		{Name: "go-dependencies", Dir: root, Path: "go", Args: []string{"mod", "download"}},
		{Name: "rust-dependencies", Dir: root, Path: "cargo", Args: []string{"+1.95.0", "fetch", "--locked", "--manifest-path", filepath.Join(root, "rust", "Cargo.toml")}},
	}
}

func prepare(root, home string, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fmt.Errorf("cloud setup requires linux/amd64, observed %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	for _, required := range []string{"go.mod", "rust/Cargo.toml", "evidence/intake/source-pins.json"} {
		if info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(required))); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("repository root is missing regular file %s", required)
		}
	}
	pins, err := loadCloudPins(root)
	if err != nil {
		return err
	}
	cloud := cloudPaths(home)
	cacheRoot := filepath.Dir(cloud.KaniRoot)
	if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
		return err
	}
	if err := ensureArchive(linuxJDK, filepath.Join(cacheRoot, "OpenJDK17U-jdk_x64_linux_hotspot_17.0.19_10.tar.gz"), cloud.JavaHome, "jdk-17.0.19+10", stdout, stderr); err != nil {
		return fmt.Errorf("JDK: %w", err)
	}
	if err := ensureArchive(pins["apache-maven-3.9.11"], filepath.Join(cacheRoot, "apache-maven-3.9.11-bin.tar.gz"), cloud.MavenHome, "apache-maven-3.9.11", stdout, stderr); err != nil {
		return fmt.Errorf("Maven: %w", err)
	}
	if _, err := portplan.EnsureQuarantinedSource(root); err != nil {
		return err
	}
	if _, err := portplan.EnsureSLF4JAPIJar(root); err != nil {
		return err
	}
	runtimeJar := filepath.Join(root, ".quarantine", "Java-WebSocket-1.6.0.jar")
	if err := downloadExact(pins["java-websocket-runtime-jar"], runtimeJar); err != nil {
		return fmt.Errorf("Java runtime: %w", err)
	}
	if err := ensureKani(cloud.KaniRoot, stdout, stderr); err != nil {
		return err
	}
	environment := append(os.Environ(),
		"JAVA_HOME="+cloud.JavaHome,
		"MAVEN_HOME="+cloud.MavenHome,
		"PATH="+strings.Join([]string{filepath.Join(cloud.JavaHome, "bin"), filepath.Join(cloud.MavenHome, "bin"), filepath.Join(cloud.KaniRoot, "scripts"), filepath.Join(home, ".cargo", "bin"), os.Getenv("PATH")}, string(os.PathListSeparator)),
	)
	for _, command := range setupPlan(root, home) {
		if err := execute(command, environment, stdout, stderr); err != nil {
			return err
		}
	}
	if err := verifyTools(cloud, environment, stdout, stderr); err != nil {
		return err
	}
	return appendBashEnvironment(home, cloud)
}

func loadCloudPins(root string) (map[string]downloadPin, error) {
	body, err := os.ReadFile(filepath.Join(root, "evidence", "intake", "source-pins.json"))
	if err != nil {
		return nil, err
	}
	var document sourcePinDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	wanted := map[string]bool{
		"java-websocket-source-archive": true,
		"java-websocket-runtime-jar":    true,
		"apache-maven-3.9.11":           true,
	}
	result := make(map[string]downloadPin, len(wanted))
	for _, item := range document.Artifacts {
		if wanted[item.ID] {
			if _, duplicate := result[item.ID]; duplicate {
				return nil, fmt.Errorf("source pin %s is duplicated", item.ID)
			}
			result[item.ID] = downloadPin{URL: item.ImmutableURL, SHA256: item.SHA256, Bytes: item.ByteSize}
		}
	}
	for id := range wanted {
		pin, ok := result[id]
		if !ok || !strings.HasPrefix(pin.URL, "https://") || len(pin.SHA256) != 71 || pin.Bytes <= 0 {
			return nil, fmt.Errorf("source pin %s is missing or invalid", id)
		}
	}
	return result, nil
}

func ensureArchive(pin downloadPin, archive, destination, top string, stdout, stderr io.Writer) error {
	if err := downloadExact(pin, archive); err != nil {
		return err
	}
	if info, err := os.Lstat(destination); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("materialized tool path is not a real directory")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listing := exec.Command("tar", "-tzf", archive)
	listed, err := listing.Output()
	if err != nil {
		return fmt.Errorf("inspect archive: %w", err)
	}
	for _, name := range strings.Split(strings.TrimSpace(string(listed)), "\n") {
		clean := filepath.ToSlash(filepath.Clean(name))
		if clean == "." || clean == top || strings.HasPrefix(clean, top+"/") {
			continue
		}
		return fmt.Errorf("archive member escapes expected top-level directory: %s", name)
	}
	parent := filepath.Dir(destination)
	staging, err := os.MkdirTemp(parent, ".cloudsetup-extract-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	command := commandSpec{Name: "extract-" + top, Dir: parent, Path: "tar", Args: []string{"-xzf", archive, "-C", staging}}
	if err := execute(command, os.Environ(), stdout, stderr); err != nil {
		return err
	}
	extracted := filepath.Join(staging, top)
	if info, err := os.Lstat(extracted); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("archive did not produce the expected real directory")
	}
	return os.Rename(extracted, destination)
}

func downloadExact(pin downloadPin, destination string) error {
	if body, err := os.ReadFile(destination); err == nil {
		return verifyDownloaded(body, pin)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Minute}
	response, err := client.Get(pin.URL)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", pin.URL, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, pin.Bytes+1))
	if err != nil {
		return err
	}
	if err := verifyDownloaded(body, pin); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".cloudsetup-download-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryName, 0o644); err != nil {
		return err
	}
	return os.Rename(temporaryName, destination)
}

func verifyDownloaded(body []byte, pin downloadPin) error {
	if int64(len(body)) != pin.Bytes {
		return fmt.Errorf("downloaded byte count %d != %d", len(body), pin.Bytes)
	}
	digest := sha256.Sum256(body)
	actual := "sha256:" + hex.EncodeToString(digest[:])
	if actual != pin.SHA256 {
		return fmt.Errorf("downloaded digest %s != %s", actual, pin.SHA256)
	}
	return nil
}

func ensureKani(root string, stdout, stderr io.Writer) error {
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
			return err
		}
		if err := execute(commandSpec{Name: "clone-kani", Dir: filepath.Dir(root), Path: "git", Args: []string{"clone", "--filter=blob:none", "--no-checkout", kaniURL, root}}, os.Environ(), stdout, stderr); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	head, _ := commandOutput(root, "git", "rev-parse", "HEAD")
	if strings.TrimSpace(head) != kaniCommit {
		if strings.TrimSpace(head) != "HEAD" && strings.TrimSpace(head) != "" {
			return fmt.Errorf("cached Kani checkout is at %s, expected %s", strings.TrimSpace(head), kaniCommit)
		}
		if err := execute(commandSpec{Name: "checkout-kani", Dir: root, Path: "git", Args: []string{"checkout", "--detach", kaniCommit}}, os.Environ(), stdout, stderr); err != nil {
			return err
		}
	}
	if err := execute(commandSpec{Name: "submodules-kani", Dir: root, Path: "git", Args: []string{"submodule", "update", "--init", "--depth", "1"}}, os.Environ(), stdout, stderr); err != nil {
		return err
	}
	if err := verifyKaniIdentity(root); err != nil {
		return err
	}
	compiler := filepath.Join(root, "target", "kani", "bin", "kani-compiler")
	if info, err := os.Lstat(compiler); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
		return nil
	}
	if err := execute(commandSpec{Name: "kani-system-dependencies", Dir: root, Path: "bash", Args: []string{"scripts/setup/ubuntu/install_deps.sh"}}, os.Environ(), stdout, stderr); err != nil {
		return err
	}
	return execute(commandSpec{Name: "build-kani", Dir: root, Path: "cargo", Args: []string{"build-dev"}}, os.Environ(), stdout, stderr)
}

func verifyKaniIdentity(root string) error {
	head, err := commandOutput(root, "git", "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(head) != kaniCommit {
		return errors.New("Kani commit binding failed")
	}
	tree, err := commandOutput(root, "git", "rev-parse", "HEAD^{tree}")
	if err != nil || strings.TrimSpace(tree) != kaniTree {
		return errors.New("Kani tree binding failed")
	}
	status, err := commandOutput(root, "git", "status", "--porcelain", "--untracked-files=no")
	if err != nil || strings.TrimSpace(status) != "" {
		return errors.New("Kani checkout has tracked modifications")
	}
	return nil
}

func execute(spec commandSpec, environment []string, stdout, stderr io.Writer) error {
	command := exec.Command(spec.Path, spec.Args...)
	command.Dir = spec.Dir
	command.Env = environment
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s: %w", spec.Name, err)
	}
	return nil
}

func commandOutput(directory, path string, arguments ...string) (string, error) {
	command := exec.Command(path, arguments...)
	command.Dir = directory
	body, err := command.Output()
	return string(body), err
}

func verifyTools(cloud paths, environment []string, stdout, stderr io.Writer) error {
	if runtime.Version() != "go1.25.5" {
		return fmt.Errorf("cloudsetup is running under %s, expected go1.25.5", runtime.Version())
	}
	fmt.Fprintln(stdout, "go-version=1.25.5")
	checks := []struct {
		spec commandSpec
		want string
	}{
		{commandSpec{Name: "java-version", Dir: cloud.JavaHome, Path: filepath.Join(cloud.JavaHome, "bin", "javac"), Args: []string{"-version"}}, "17.0.19"},
		{commandSpec{Name: "maven-version", Dir: cloud.MavenHome, Path: filepath.Join(cloud.MavenHome, "bin", "mvn"), Args: []string{"-version"}}, "3.9.11"},
		{commandSpec{Name: "rust-version", Dir: cloud.KaniRoot, Path: "rustc", Args: []string{"+1.95.0", "--version"}}, "1.95.0"},
		{commandSpec{Name: "kani-version", Dir: cloud.KaniRoot, Path: filepath.Join(cloud.KaniRoot, "scripts", "cargo-kani"), Args: []string{"--version"}}, "0.67.0"},
		{commandSpec{Name: "cbmc-version", Dir: cloud.KaniRoot, Path: "cbmc", Args: []string{"--version"}}, "6.11.0"},
	}
	for _, check := range checks {
		command := exec.Command(check.spec.Path, check.spec.Args...)
		command.Dir = check.spec.Dir
		command.Env = environment
		body, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(body, []byte(check.want)) {
			_, _ = stderr.Write(body)
			return fmt.Errorf("%s did not report pinned version %s", check.spec.Name, check.want)
		}
		fmt.Fprintf(stdout, "%s=%s\n", check.spec.Name, check.want)
	}
	return verifyKaniIdentity(cloud.KaniRoot)
}

func appendBashEnvironment(home string, cloud paths) error {
	const begin = "# verified-java-websocket-port cloud environment (managed block)"
	block := strings.Join([]string{
		begin,
		"export JAVA_HOME=" + shellQuote(cloud.JavaHome),
		"export MAVEN_HOME=" + shellQuote(cloud.MavenHome),
		"export VJWP_KANI_ROOT=" + shellQuote(cloud.KaniRoot),
		`export PATH="$JAVA_HOME/bin:$MAVEN_HOME/bin:$VJWP_KANI_ROOT/scripts:$HOME/.cargo/bin:$PATH"`,
		"# end verified-java-websocket-port cloud environment",
		"",
	}, "\n")
	path := filepath.Join(home, ".bashrc")
	body, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if bytes.Contains(body, []byte(begin)) {
		if !bytes.Contains(body, []byte(block)) {
			return errors.New("existing managed cloud environment block differs; reset the Codex environment cache")
		}
		return nil
	}
	handle, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if len(body) > 0 && body[len(body)-1] != '\n' {
		if _, err := handle.WriteString("\n"); err != nil {
			_ = handle.Close()
			return err
		}
	}
	if _, err := handle.WriteString(block); err != nil {
		_ = handle.Close()
		return err
	}
	return handle.Close()
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
