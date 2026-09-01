// Command cloudsetup materializes the exact public dependencies needed by a
// Codex cloud worker and prepares the pinned Java, Rust, Kani, and CBMC
// toolchains.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	pathpkg "path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/portplan"
)

const (
	kaniCommit       = "37960b2bea719b86f3a99d28b650110203cffabb"
	kaniTree         = "140c732427576e199ba96406f3657b2c2008d35d"
	kaniCharonCommit = "b250680abd40ff1aaa07081d0497dc2755ed112e"
	kaniCharonTree   = "a83f56525e28511f65e17584db0303fed72b00b2"
	kaniURL          = "https://github.com/model-checking/kani.git"
	projectURL       = "https://github.com/michaellady/verified-java-websocket-port.git"
	cacheName        = "verified-java-websocket-port"
	javaOracleSHA256 = "sha256:8cfd5f53cfaa028f8f359dc84fecefad1a317a68cd269c6cfac97870411e353d"
	javaOracleBytes  = 76321
)

var linuxJDK = downloadPin{
	URL:    "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.19%2B10/OpenJDK17U-jdk_x64_linux_hotspot_17.0.19_10.tar.gz",
	SHA256: "sha256:d8afc263758141a66e0e3aafc321e783f7016696f4eaea067d340a269037d331",
	Bytes:  193335385,
}

var cbmcUbuntu2404 = downloadPin{
	URL:    "https://github.com/diffblue/cbmc/releases/download/cbmc-6.11.0/ubuntu-24.04-cbmc-6.11.0-Linux.deb",
	SHA256: "sha256:b3721aa541038384d7801ea3aeabbcddc3e8845ac8f1cbff637cf8dec7481ac8",
	Bytes:  73477756,
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
	CBMCRoot  string `json:"cbmc_root"`
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
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	homePath, err := filepath.Abs(*home)
	if err != nil || strings.ContainsAny(homePath, "\r\n") {
		_, _ = fmt.Fprintln(stderr, "home must resolve to one absolute path")
		return 1
	}
	switch arguments[0] {
	case "paths":
		return encode(stdout, cloudPaths(homePath))
	case "setup", "maintain":
		if err := prepare(rootPath, homePath, stdout, stderr); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		return encode(stdout, cloudPaths(homePath))
	default:
		usage(stderr)
		return 2
	}
}

func usage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, "usage: cloudsetup setup|maintain|paths --root DIR [--home DIR]")
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
		CBMCRoot:  filepath.Join(root, "cbmc-6.11.0-ubuntu-24.04"),
		JavaHome:  filepath.Join(root, "jdk-17.0.19+10"),
		MavenHome: filepath.Join(root, "apache-maven-3.9.11"),
	}
}

func setupPlan(root, _ string) []commandSpec {
	return []commandSpec{
		{Name: "rust-toolchain", Dir: root, Path: "rustup", Args: []string{"toolchain", "install", "1.95.0", "--profile", "minimal", "--component", "rustfmt", "--component", "clippy"}},
		{Name: "go-dependencies", Dir: root, Path: "go", Args: []string{"mod", "download"}},
		{Name: "rust-dependencies", Dir: root, Path: "cargo", Args: []string{"+1.95.0", "fetch", "--locked", "--manifest-path", filepath.Join(root, "rust", "Cargo.toml")}},
		{Name: "java-oracle", Dir: root, Path: "make", Args: []string{"-C", "java-oracle", "build", "JAVA_WEBSOCKET_JAR=../.quarantine/Java-WebSocket-1.6.0.jar"}},
	}
}

func kaniBuildPlan(root string) []commandSpec {
	return []commandSpec{
		{Name: "submodules-kani", Dir: root, Path: "git", Args: []string{"submodule", "update", "--init", "--depth", "1"}},
		{Name: "build-kani", Dir: root, Path: "cargo", Args: []string{"build-dev"}},
	}
}

func kaniCheckoutCommand(root string) commandSpec {
	return commandSpec{Name: "checkout-kani", Dir: root, Path: "git", Args: []string{"checkout", "--detach", kaniCommit}}
}

func prepare(root, home string, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fmt.Errorf("cloud setup requires linux/amd64, observed %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	osRelease, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return fmt.Errorf("read cloud operating-system identity: %w", err)
	}
	if err := verifyOperatingSystem(osRelease); err != nil {
		return err
	}
	for _, required := range []string{"go.mod", "rust/Cargo.toml", "evidence/intake/source-pins.json"} {
		if info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(required))); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("repository root is missing regular file %s", required)
		}
	}
	if err := ensureRepositoryHistory(root, projectURL, os.Environ(), stdout, stderr); err != nil {
		return err
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
		return fmt.Errorf("maven: %w", err)
	}
	if _, err := portplan.EnsureQuarantinedSource(root); err != nil {
		return err
	}
	if _, err := portplan.EnsureSLF4JAPIJar(root); err != nil {
		return err
	}
	runtimeJar := filepath.Join(root, ".quarantine", "Java-WebSocket-1.6.0.jar")
	if err := downloadExact(pins["java-websocket-runtime-jar"], runtimeJar); err != nil {
		return fmt.Errorf("java runtime: %w", err)
	}
	cbmcArchive := filepath.Join(cacheRoot, "ubuntu-24.04-cbmc-6.11.0-Linux.deb")
	if err := ensureCBMC(cbmcUbuntu2404, cbmcArchive, cloud.CBMCRoot, stdout, stderr); err != nil {
		return fmt.Errorf("CBMC: %w", err)
	}
	environment := append(os.Environ(),
		"JAVA_HOME="+cloud.JavaHome,
		"MAVEN_HOME="+cloud.MavenHome,
		"VJWP_KANI_ROOT="+cloud.KaniRoot,
		"VJWP_CBMC_ROOT="+cloud.CBMCRoot,
		"PATH="+strings.Join([]string{filepath.Join(cloud.JavaHome, "bin"), filepath.Join(cloud.MavenHome, "bin"), filepath.Join(cloud.KaniRoot, "scripts"), filepath.Join(cloud.CBMCRoot, "usr", "bin"), filepath.Join(home, ".cargo", "bin"), os.Getenv("PATH")}, string(os.PathListSeparator)),
	)
	for _, command := range setupPlan(root, home) {
		if err := execute(command, environment, stdout, stderr); err != nil {
			return err
		}
	}
	javaOracle, err := os.ReadFile(filepath.Join(root, "java-oracle", "build", "java-oracle.jar"))
	if err != nil {
		return fmt.Errorf("read Java oracle adapter: %w", err)
	}
	if err := verifyDownloaded(javaOracle, downloadPin{SHA256: javaOracleSHA256, Bytes: javaOracleBytes}); err != nil {
		return fmt.Errorf("Java oracle adapter identity: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "java-oracle=%s\n", javaOracleSHA256)
	if err := ensureKani(cloud.KaniRoot, environment, stdout, stderr); err != nil {
		return err
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

func verifyOperatingSystem(body []byte) error {
	values := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		values[parts[0]] = strings.Trim(strings.TrimSpace(parts[1]), "\"'")
	}
	if values["ID"] != "ubuntu" || values["VERSION_ID"] != "24.04" {
		return fmt.Errorf("cloud setup requires Ubuntu 24.04, observed ID=%q VERSION_ID=%q", values["ID"], values["VERSION_ID"])
	}
	return nil
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
	if err := validateTarGzip(archive, top); err != nil {
		return err
	}
	parent := filepath.Dir(destination)
	staging, err := os.MkdirTemp(parent, ".cloudsetup-extract-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	command := commandSpec{Name: "extract-" + top, Dir: parent, Path: "tar", Args: []string{"-xzf", archive, "-C", staging, "--no-same-owner"}}
	if err := execute(command, os.Environ(), stdout, stderr); err != nil {
		return err
	}
	extracted := filepath.Join(staging, top)
	if info, err := os.Lstat(extracted); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("archive did not produce the expected real directory")
	}
	return os.Rename(extracted, destination)
}

func validateTarGzip(archive, expectedTop string) error {
	handle, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer func() { _ = handle.Close() }()
	compressed, err := gzip.NewReader(handle)
	if err != nil {
		return fmt.Errorf("inspect archive: %w", err)
	}
	defer func() { _ = compressed.Close() }()
	reader := tar.NewReader(compressed)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect archive: %w", err)
		}
		clean := pathpkg.Clean(strings.TrimPrefix(header.Name, "./"))
		if pathpkg.IsAbs(header.Name) || !withinArchiveTop(clean, expectedTop) {
			return fmt.Errorf("archive member escapes expected top-level directory: %s", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		case tar.TypeSymlink:
			if pathpkg.IsAbs(header.Linkname) {
				return fmt.Errorf("archive link escapes expected top-level directory: %s -> %s", header.Name, header.Linkname)
			}
			target := pathpkg.Clean(pathpkg.Join(pathpkg.Dir(clean), header.Linkname))
			if !withinArchiveTop(target, expectedTop) {
				return fmt.Errorf("archive link escapes expected top-level directory: %s -> %s", header.Name, header.Linkname)
			}
		case tar.TypeLink:
			target := pathpkg.Clean(strings.TrimPrefix(header.Linkname, "./"))
			if pathpkg.IsAbs(header.Linkname) || !withinArchiveTop(target, expectedTop) {
				return fmt.Errorf("archive link escapes expected top-level directory: %s -> %s", header.Name, header.Linkname)
			}
		default:
			return fmt.Errorf("archive contains unsupported member type %d: %s", header.Typeflag, header.Name)
		}
	}
}

func withinArchiveTop(candidate, expectedTop string) bool {
	return candidate == expectedTop || strings.HasPrefix(candidate, expectedTop+"/")
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
	defer func() { _ = response.Body.Close() }()
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

func ensureCBMC(pin downloadPin, archive, destination string, stdout, stderr io.Writer) error {
	if err := downloadExact(pin, archive); err != nil {
		return err
	}
	if info, err := os.Lstat(destination); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("materialized CBMC path is not a real directory")
		}
		return verifyExecutable(filepath.Join(destination, "usr", "bin", "cbmc"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(destination)
	staging, err := os.MkdirTemp(parent, ".cloudsetup-cbmc-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	members, err := commandOutput(staging, "ar", "t", archive)
	if err != nil {
		return fmt.Errorf("inspect CBMC package: %w", err)
	}
	if err := verifyDebianMembers(members); err != nil {
		return err
	}
	if err := execute(commandSpec{Name: "unpack-cbmc-package", Dir: staging, Path: "ar", Args: []string{"x", archive, "data.tar.gz"}}, os.Environ(), stdout, stderr); err != nil {
		return err
	}
	dataArchive := filepath.Join(staging, "data.tar.gz")
	if info, err := os.Lstat(dataArchive); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("CBMC package did not contain a regular data.tar.gz member")
	}
	if err := validateTarGzip(dataArchive, "usr"); err != nil {
		return fmt.Errorf("inspect CBMC payload: %w", err)
	}
	extracted := filepath.Join(staging, "root")
	if err := os.Mkdir(extracted, 0o755); err != nil {
		return err
	}
	if err := execute(commandSpec{Name: "extract-cbmc", Dir: staging, Path: "tar", Args: []string{"-xzf", dataArchive, "-C", extracted, "--no-same-owner"}}, os.Environ(), stdout, stderr); err != nil {
		return err
	}
	if err := verifyExecutable(filepath.Join(extracted, "usr", "bin", "cbmc")); err != nil {
		return err
	}
	return os.Rename(extracted, destination)
}

func verifyDebianMembers(body string) error {
	members := strings.Fields(body)
	want := []string{"debian-binary", "control.tar.gz", "data.tar.gz"}
	if len(members) != len(want) {
		return fmt.Errorf("CBMC Debian package has unexpected members: %q", members)
	}
	for index := range want {
		if members[index] != want[index] {
			return fmt.Errorf("CBMC Debian package has unexpected members: %q", members)
		}
	}
	return nil
}

func verifyExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("expected a regular executable at %s", path)
	}
	return nil
}

func ensureKani(root string, environment []string, stdout, stderr io.Writer) error {
	newCheckout := false
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
			return err
		}
		if err := execute(commandSpec{Name: "clone-kani", Dir: filepath.Dir(root), Path: "git", Args: []string{"clone", "--filter=blob:none", "--no-checkout", kaniURL, root}}, environment, stdout, stderr); err != nil {
			return err
		}
		newCheckout = true
	} else if err != nil {
		return err
	} else if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("materialized Kani path is not a real directory")
	}
	head, headErr := commandOutput(root, "git", "rev-parse", "HEAD")
	if headErr != nil && !newCheckout {
		return errors.New("cached Kani checkout is not a Git repository")
	}
	if newCheckout {
		if err := execute(kaniCheckoutCommand(root), environment, stdout, stderr); err != nil {
			return err
		}
	} else if strings.TrimSpace(head) != kaniCommit {
		return fmt.Errorf("cached Kani checkout is at %s, expected %s", strings.TrimSpace(head), kaniCommit)
	}
	plan := kaniBuildPlan(root)
	if err := execute(plan[0], environment, stdout, stderr); err != nil {
		return err
	}
	if err := verifyKaniIdentity(root); err != nil {
		return err
	}
	compiler := filepath.Join(root, "target", "kani", "bin", "kani-compiler")
	if err := verifyExecutable(compiler); err == nil {
		return verifyExecutable(filepath.Join(root, "scripts", "cargo-kani"))
	}
	if err := execute(plan[1], environment, stdout, stderr); err != nil {
		return err
	}
	if err := verifyExecutable(compiler); err != nil {
		return err
	}
	return verifyExecutable(filepath.Join(root, "scripts", "cargo-kani"))
}

func verifyKaniIdentity(root string) error {
	if err := verifyGitIdentity(root, "Kani", kaniCommit, kaniTree, true); err != nil {
		return err
	}
	return verifyGitIdentity(filepath.Join(root, "charon"), "Kani Charon submodule", kaniCharonCommit, kaniCharonTree, false)
}

func verifyGitIdentity(root, name, commit, tree string, ignoreSubmodules bool) error {
	head, err := commandOutput(root, "git", "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(head) != commit {
		return fmt.Errorf("%s commit binding failed", name)
	}
	observedTree, err := commandOutput(root, "git", "rev-parse", "HEAD^{tree}")
	if err != nil || strings.TrimSpace(observedTree) != tree {
		return fmt.Errorf("%s tree binding failed", name)
	}
	arguments := []string{"status", "--porcelain", "--untracked-files=no"}
	if ignoreSubmodules {
		arguments = append(arguments, "--ignore-submodules=all")
	}
	status, err := commandOutput(root, "git", arguments...)
	if err != nil {
		return fmt.Errorf("%s tracked-source cleanliness check failed", name)
	}
	if strings.TrimSpace(status) != "" {
		return fmt.Errorf("%s has tracked modifications: %s", name, summarizeStatus(status, 10))
	}
	return nil
}

func summarizeStatus(status string, limit int) string {
	lines := strings.Split(strings.TrimSpace(status), "\n")
	if len(lines) <= limit {
		return strings.Join(lines, "; ")
	}
	return strings.Join(lines[:limit], "; ") + "; ..."
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

func ensureRepositoryHistory(root, repository string, environment []string, stdout, stderr io.Writer) error {
	headBefore, err := commandOutput(root, "git", "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return errors.New("cloud checkout has no committed HEAD")
	}
	statusBefore, err := commandOutput(root, "git", "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return errors.New("cloud checkout status is unavailable")
	}
	shallow, err := commandOutput(root, "git", "rev-parse", "--is-shallow-repository")
	if err != nil || (strings.TrimSpace(shallow) != "true" && strings.TrimSpace(shallow) != "false") {
		return errors.New("cloud checkout shallow identity is unavailable")
	}
	arguments := []string{"fetch", "--no-tags", "--force"}
	if strings.TrimSpace(shallow) == "true" {
		arguments = append(arguments, "--unshallow")
	}
	arguments = append(arguments, repository, "+refs/heads/*:refs/remotes/vjwp-cloud/*")
	if err := execute(commandSpec{Name: "fetch-project-history", Dir: root, Path: "git", Args: arguments}, environment, stdout, stderr); err != nil {
		return err
	}
	headAfter, err := commandOutput(root, "git", "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || headAfter != headBefore {
		return errors.New("project history fetch changed the checked-out commit")
	}
	statusAfter, err := commandOutput(root, "git", "status", "--porcelain", "--untracked-files=all")
	if err != nil || statusAfter != statusBefore {
		return errors.New("project history fetch changed the working tree")
	}
	objects, err := commandOutput(root, "git", "rev-list", "--objects", "--missing=print", "HEAD")
	if err != nil {
		return errors.New("project history remains unreadable after fetch")
	}
	for _, line := range strings.Split(objects, "\n") {
		if strings.HasPrefix(line, "?") {
			return errors.New("project history remains incomplete after fetch")
		}
	}
	_, _ = fmt.Fprintln(stdout, "repository-history=complete")
	return nil
}

func verifyTools(cloud paths, environment []string, stdout, stderr io.Writer) error {
	if runtime.Version() != "go1.25.5" {
		return fmt.Errorf("cloudsetup is running under %s, expected go1.25.5", runtime.Version())
	}
	_, _ = fmt.Fprintln(stdout, "go-version=1.25.5")
	checks := []struct {
		spec commandSpec
		want string
	}{
		{commandSpec{Name: "java-version", Dir: cloud.JavaHome, Path: filepath.Join(cloud.JavaHome, "bin", "javac"), Args: []string{"-version"}}, "17.0.19"},
		{commandSpec{Name: "maven-version", Dir: cloud.MavenHome, Path: filepath.Join(cloud.MavenHome, "bin", "mvn"), Args: []string{"-version"}}, "3.9.11"},
		{commandSpec{Name: "rust-version", Dir: cloud.KaniRoot, Path: "rustc", Args: []string{"+1.95.0", "--version"}}, "1.95.0"},
		{commandSpec{Name: "kani-rust-version", Dir: cloud.KaniRoot, Path: "rustc", Args: []string{"+nightly-2026-08-21", "--version"}}, "rustc 1.100.0-nightly (8925ea358 2026-08-20)"},
		{commandSpec{Name: "kani-version", Dir: cloud.KaniRoot, Path: filepath.Join(cloud.KaniRoot, "scripts", "cargo-kani"), Args: []string{"--version"}}, "Kani Rust Verifier 0.67.0"},
		{commandSpec{Name: "cbmc-version", Dir: cloud.CBMCRoot, Path: filepath.Join(cloud.CBMCRoot, "usr", "bin", "cbmc"), Args: []string{"--version"}}, "6.11.0 (cbmc-6.11.0)"},
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
		_, _ = fmt.Fprintf(stdout, "%s=%s\n", check.spec.Name, check.want)
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
		"export VJWP_CBMC_ROOT=" + shellQuote(cloud.CBMCRoot),
		`export PATH="$JAVA_HOME/bin:$MAVEN_HOME/bin:$VJWP_KANI_ROOT/scripts:$VJWP_CBMC_ROOT/usr/bin:$HOME/.cargo/bin:$PATH"`,
		"# end verified-java-websocket-port cloud environment",
		"",
	}, "\n")
	path := filepath.Join(home, ".bashrc")
	body, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	blockBytes := []byte(block)
	beginBytes := []byte(begin)
	if bytes.Contains(body, beginBytes) {
		if bytes.Count(body, beginBytes) != 1 {
			return errors.New("existing managed cloud environment block is duplicated; reset the Codex environment cache")
		}
		start := bytes.Index(body, beginBytes)
		if start < 0 || !bytes.HasPrefix(body[start:], blockBytes) {
			return errors.New("existing managed cloud environment block differs; reset the Codex environment cache")
		}
		if start == 0 {
			return nil
		}
		migrated := make([]byte, 0, len(body))
		migrated = append(migrated, blockBytes...)
		migrated = append(migrated, body[:start]...)
		migrated = append(migrated, body[start+len(blockBytes):]...)
		return os.WriteFile(path, migrated, 0o644)
	}
	updated := make([]byte, 0, len(blockBytes)+len(body))
	updated = append(updated, blockBytes...)
	updated = append(updated, body...)
	return os.WriteFile(path, updated, 0o644)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
