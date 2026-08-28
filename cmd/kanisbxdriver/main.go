// Command kanisbxdriver materializes the Kani toolchain inside the accepted
// US-007 sandbox and runs the actual-code verification harnesses there.
//
// It runs with NO NETWORK. Every byte it needs arrives in a digest-verified
// bundle that the host launcher copied in; this driver re-verifies every member
// against the manifest before touching any of it, so `sbx cp`'s exit code is
// never load-bearing (the 0124 finding).
//
// It also acts as the C-preprocessor shim. Kani's goto-cc execs `gcc` to
// preprocess kani_lib.c, and the pinned template ships no C compiler. Rather
// than install one as root, this driver extracts the gcc/libc6-dev deb closure
// UNPRIVILEGED with `dpkg-deb -x` into a user prefix (the attempt-0126
// precedent) and installs a copy of ITSELF named `gcc` on PATH. When argv[0] is
// `gcc` the process execs the extracted compiler with the prefix's include,
// library and -B paths. That keeps the shim a compiled binary rather than a
// shell script, and keeps uid 1000 unprivileged throughout.
//
// The driver's own stdout is written INTO the output directory as well as to
// the terminal: the E3 lane lost two runs' evidence because stdout lived only
// on a shared host path that a later run overwrote.
//
// Usage (inside the sandbox):
//
//	kanisbxdriver -inbound <dir> -repo <dir> -out <dir> -harnesses <spec,...>
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	kaniVersion   = "0.67.0"
	kaniToolchain = "nightly-2025-11-21-aarch64-unknown-linux-gnu"
	gccMajor      = "15"
	targetTriple  = "aarch64-linux-gnu"
	prefixEnv     = "US012_CC_PREFIX"
)

func main() {
	// argv[0] dispatch: the same binary is installed on PATH as `gcc`.
	if filepath.Base(os.Args[0]) == "gcc" {
		if err := runAsCompilerShim(); err != nil {
			fmt.Fprintf(os.Stderr, "gcc-shim: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "kanisbxdriver: %v\n", err)
		os.Exit(1)
	}
}

// runAsCompilerShim execs the unprivileged-extracted gcc with the include,
// library and tool-search paths that make the user prefix behave like /usr.
func runAsCompilerShim() error {
	prefix := os.Getenv(prefixEnv)
	if prefix == "" {
		return fmt.Errorf("%s is not set; the shim cannot locate the extracted toolchain", prefixEnv)
	}
	real := filepath.Join(prefix, "usr", "bin", "gcc-"+gccMajor)
	gccLib := filepath.Join(prefix, "usr", "lib", "gcc", targetTriple, gccMajor)
	argv := append([]string{real,
		"-B" + filepath.Join(prefix, "usr", "bin") + "/",
		"-B" + gccLib + "/",
		"-L" + filepath.Join(prefix, "usr", "lib", targetTriple),
		"-isystem", filepath.Join(gccLib, "include"),
		"-isystem", filepath.Join(prefix, "usr", "include", targetTriple),
		"-isystem", filepath.Join(prefix, "usr", "include"),
	}, os.Args[1:]...)

	env := os.Environ()
	ld := filepath.Join(prefix, "usr", "lib", targetTriple) + ":" + filepath.Join(prefix, "usr", "lib")
	if existing := os.Getenv("LD_LIBRARY_PATH"); existing != "" {
		ld += ":" + existing
	}
	env = append(env, "LD_LIBRARY_PATH="+ld)
	return syscall.Exec(real, argv, env)
}

type materialization struct {
	Artifact string `json:"artifact"`
	SHA256   string `json:"sha256"`
	Note     string `json:"note,omitempty"`
}

func run() error {
	inboundDir := flag.String("inbound", "", "directory holding the digest-verified inbound bundle contents")
	repo := flag.String("repo", ".", "repository root inside the sandbox (the clone-mode workspace)")
	out := flag.String("out", "", "directory receiving every receipt this attempt produces")
	harnesses := flag.String("harnesses", "", "comma-separated harness=expectation specs passed through to kanirun")
	flag.Parse()
	if *inboundDir == "" || *out == "" || *harnesses == "" {
		return errors.New("-inbound, -out and -harnesses are all required")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}

	// Everything printed goes to stdout AND into the output directory, so the
	// recorded exit codes are bound to bytes that leave the sandbox.
	log, err := os.Create(filepath.Join(*out, "driver-stdout.txt"))
	if err != nil {
		return err
	}
	defer log.Close()
	say := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		fmt.Println(line)
		fmt.Fprintln(log, line)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	say("WINDOW start=%s", nowUTC())
	say("IDENTITY uid=%d gid=%d home=%s", os.Getuid(), os.Getgid(), home)
	if os.Getuid() == 0 {
		return errors.New("refusing to run as root: the accepted profile is an unprivileged uid-1000 workload")
	}

	// 1. Re-verify every inbound artifact against the manifest built on the host.
	verified, err := verifyInbound(*inboundDir, say)
	if err != nil {
		return err
	}
	say("INBOUND verified=%d mismatches=0", verified)

	// 2. Materialize the toolchain, recording the digest of every binary that
	//    ends up on disk so the host receipt can bind the tools that actually ran.
	records, err := materialize(*inboundDir, home, say)
	if err != nil {
		return err
	}
	blob, err := json.MarshalIndent(records, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "materialization.json"), append(blob, '\n'), 0o644); err != nil {
		return err
	}

	// 3. Prove the toolchain is live before spending time on the sweep.
	prefix := filepath.Join(home, "tc")
	kaniBin := filepath.Join(home, ".kani", "kani-"+kaniVersion, "bin")
	toolchainBin := filepath.Join(home, ".rustup", "toolchains", kaniToolchain, "bin")
	shimBin := filepath.Join(home, "bin")
	path := strings.Join([]string{shimBin, kaniBin, toolchainBin, os.Getenv("PATH")}, string(os.PathListSeparator))
	env := append(os.Environ(), "PATH="+path, prefixEnv+"="+prefix, "RUSTUP_TOOLCHAIN="+kaniToolchain)

	for _, probe := range [][]string{
		{filepath.Join(kaniBin, "kani-driver"), "--version"},
		{filepath.Join(kaniBin, "cbmc"), "--version"},
		{filepath.Join(toolchainBin, "rustc"), "--version"},
		{filepath.Join(toolchainBin, "cargo"), "--version"},
		{filepath.Join(shimBin, "gcc"), "--version"},
	} {
		output, code := runCommand(probe, env, "")
		first := strings.TrimSpace(strings.SplitN(strings.TrimSpace(output), "\n", 2)[0])
		say("PROBE tool=%s exit=%d version=%q", filepath.Base(probe[0]), code, first)
		if code != 0 {
			return fmt.Errorf("toolchain probe %s exited %d", probe[0], code)
		}
	}

	// 4. Run the sweep with the SAME runner binary the host run used, built from
	//    the same source at the same commit for this target. Delegating keeps the
	//    outcome classification byte-identical between host and sandbox.
	runner := filepath.Join(*inboundDir, "kanirun")
	if err := os.Chmod(runner, 0o755); err != nil {
		return err
	}
	harnessDir := filepath.Join(*repo, "assurance", "formal", "kani", "harness")
	if _, err := os.Stat(filepath.Join(harnessDir, "Cargo.toml")); err != nil {
		return fmt.Errorf("harness crate not found at %s: %w", harnessDir, err)
	}
	say("SWEEP runner=%s dir=%s", runner, harnessDir)
	sweepStart := nowUTC()
	results := filepath.Join(*out, "results.json")
	output, code := runCommand([]string{runner, "-dir", harnessDir, "-kani-bin", kaniBin, "-out", results, "-harnesses", *harnesses}, env, "")
	sweepEnd := nowUTC()
	if err := os.WriteFile(filepath.Join(*out, "kanirun-output.txt"), []byte(output), 0o644); err != nil {
		return err
	}
	say("WINDOW sweep_start=%s sweep_end=%s", sweepStart, sweepEnd)
	say("RESULT step=kanirun exit=%d", code)

	// Report every harness line from the runner's OWN json, not from its text.
	summary, summaryErr := summarize(results, say)
	if summaryErr != nil {
		say("SUMMARY_ERROR %v", summaryErr)
	}
	say("WINDOW end=%s", nowUTC())

	// 5. The output manifest is written LAST and covers everything except itself,
	//    so the host can verify each extracted file independently.
	if err := log.Sync(); err != nil {
		return err
	}
	if err := writeOutputManifest(*out); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("kanirun exited %d: %s", code, summary)
	}
	if summaryErr != nil {
		return summaryErr
	}
	return nil
}

func verifyInbound(dir string, say func(string, ...any)) (int, error) {
	manifestPath := filepath.Join(dir, "inbound-manifest.sha256")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return 0, fmt.Errorf("read inbound manifest: %w", err)
	}
	verified, mismatched := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		want, name := fields[0], fields[1]
		got, err := digestFile(filepath.Join(dir, name))
		if err != nil {
			say("INBOUND_MISMATCH name=%s error=%v", name, err)
			mismatched++
			continue
		}
		if got != want {
			say("INBOUND_MISMATCH name=%s want=%s got=%s", name, want, got)
			mismatched++
			continue
		}
		verified++
	}
	if mismatched > 0 {
		return verified, fmt.Errorf("INBOUND VERIFICATION FAILED: %d of %d artifacts differ from their host digests", mismatched, verified+mismatched)
	}
	if verified == 0 {
		return 0, errors.New("inbound manifest listed no artifacts")
	}
	return verified, nil
}

func materialize(inboundDir, home string, say func(string, ...any)) ([]materialization, error) {
	records := []materialization{}

	// Kani release bundle -> ~/.kani/kani-<version>
	kaniHome := filepath.Join(home, ".kani")
	if err := os.MkdirAll(kaniHome, 0o755); err != nil {
		return nil, err
	}
	bundle := filepath.Join(inboundDir, "kani-"+kaniVersion+"-aarch64-unknown-linux-gnu.tar.gz")
	if output, code := runCommand([]string{"tar", "-xzf", bundle, "-C", kaniHome}, os.Environ(), ""); code != 0 {
		return nil, fmt.Errorf("extract kani bundle exited %d: %s", code, output)
	}
	say("MATERIALIZE kani_bundle_extracted=%s", filepath.Join(kaniHome, "kani-"+kaniVersion))

	// Rust nightly -> ~/.rustup/toolchains/<toolchain> via the installer's own script.
	stage := filepath.Join(home, "rust-nightly-stage")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return nil, err
	}
	if output, code := runCommand([]string{"tar", "-xzf", filepath.Join(inboundDir, "rust-nightly-aarch64-unknown-linux-gnu.tar.gz"), "-C", stage, "--strip-components=1"}, os.Environ(), ""); code != 0 {
		return nil, fmt.Errorf("extract rust nightly exited %d: %s", code, output)
	}
	toolchainDir := filepath.Join(home, ".rustup", "toolchains", kaniToolchain)
	if err := os.MkdirAll(toolchainDir, 0o755); err != nil {
		return nil, err
	}
	output, code := runCommand([]string{filepath.Join(stage, "install.sh"),
		"--prefix=" + toolchainDir,
		"--components=rustc,rust-std-aarch64-unknown-linux-gnu,cargo",
		"--disable-ldconfig"}, os.Environ(), stage)
	if code != 0 {
		return nil, fmt.Errorf("rust install.sh exited %d: %s", code, output)
	}
	say("MATERIALIZE rust_toolchain=%s install_exit=0", toolchainDir)

	// Kani resolves librustc_driver through <kani home>/toolchain.
	link := filepath.Join(kaniHome, "kani-"+kaniVersion, "toolchain")
	os.Remove(link)
	if err := os.Symlink(toolchainDir, link); err != nil {
		return nil, fmt.Errorf("link kani toolchain: %w", err)
	}

	// C toolchain: UNPRIVILEGED extraction, no root at any point.
	prefix := filepath.Join(home, "tc")
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(inboundDir)
	if err != nil {
		return nil, err
	}
	debs := 0
	for _, entry := range entries {
		// `._*` are macOS AppleDouble resource forks, never real packages.
		if !strings.HasSuffix(entry.Name(), ".deb") || strings.HasPrefix(entry.Name(), "._") {
			continue
		}
		if output, code := runCommand([]string{"dpkg-deb", "-x", filepath.Join(inboundDir, entry.Name()), prefix}, os.Environ(), ""); code != 0 {
			return nil, fmt.Errorf("dpkg-deb -x %s exited %d: %s", entry.Name(), code, output)
		}
		debs++
	}
	say("MATERIALIZE debs_extracted=%d prefix=%s privileged=false", debs, prefix)

	// Install this binary as the `gcc` shim and kani-driver as `cargo-kani`.
	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if err := copyFile(self, filepath.Join(binDir, "gcc"), 0o755); err != nil {
		return nil, fmt.Errorf("install gcc shim: %w", err)
	}
	driver := filepath.Join(kaniHome, "kani-"+kaniVersion, "bin", "kani-driver")
	for _, alias := range []string{"cargo-kani", "kani"} {
		target := filepath.Join(binDir, alias)
		os.Remove(target)
		if err := os.Symlink(driver, target); err != nil {
			return nil, fmt.Errorf("alias %s: %w", alias, err)
		}
	}
	say("MATERIALIZE cargo_kani_alias=kani-driver gcc_shim=self")

	// Record the digest of every tool binary that will actually run.
	for _, name := range []string{"cbmc", "goto-analyzer", "goto-cc", "goto-instrument", "kani-compiler", "kani-cov", "kani-driver", "kissat"} {
		path := filepath.Join(kaniHome, "kani-"+kaniVersion, "bin", name)
		digest, err := digestFile(path)
		if err != nil {
			return nil, err
		}
		records = append(records, materialization{"kani/bin/" + name, "sha256:" + digest, "extracted in-sandbox from the digest-verified linux/arm64 release bundle"})
		say("DIGEST kind=tool name=kani/bin/%s sha256=sha256:%s", name, digest)
	}
	for _, name := range []string{"rustc", "cargo"} {
		digest, err := digestFile(filepath.Join(toolchainDir, "bin", name))
		if err != nil {
			return nil, err
		}
		records = append(records, materialization{"toolchain/bin/" + name, "sha256:" + digest, "installed in-sandbox from the published-checksum-verified nightly tarball"})
		say("DIGEST kind=toolchain name=%s sha256=sha256:%s", name, digest)
	}
	gccDigest, err := digestFile(filepath.Join(prefix, "usr", "bin", "gcc-"+gccMajor))
	if err != nil {
		return nil, err
	}
	records = append(records, materialization{"tc/usr/bin/gcc-" + gccMajor, "sha256:" + gccDigest, "unprivileged dpkg-deb -x from the signed-apt-index-verified deb closure"})
	say("DIGEST kind=cc name=gcc-%s sha256=sha256:%s", gccMajor, gccDigest)
	return records, nil
}

type harnessResult struct {
	Harness      string  `json:"harness"`
	Expectation  string  `json:"expectation"`
	ExitCode     int     `json:"exit_code"`
	Verification string  `json:"verification"`
	FailedChecks int     `json:"failed_checks"`
	TotalChecks  int     `json:"total_checks"`
	Outcome      string  `json:"outcome"`
	Matches      bool    `json:"matches_expectation"`
	FirstFailure string  `json:"first_failure_description,omitempty"`
	DurationSec  float64 `json:"duration_seconds"`
}

func summarize(path string, say func(string, ...any)) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read runner results: %w", err)
	}
	var results []harnessResult
	if err := json.Unmarshal(raw, &results); err != nil {
		return "", fmt.Errorf("decode runner results: %w", err)
	}
	matched := 0
	for _, r := range results {
		say("HARNESS name=%s expect=%s outcome=%s exit=%d checks=%d/%d match=%t seconds=%.3f",
			r.Harness, r.Expectation, r.Outcome, r.ExitCode, r.FailedChecks, r.TotalChecks, r.Matches, r.DurationSec)
		if r.Matches {
			matched++
		}
	}
	summary := fmt.Sprintf("total=%d matched=%d mismatched=%d", len(results), matched, len(results)-matched)
	say("SUMMARY harnesses=%s", summary)
	if matched != len(results) {
		return summary, fmt.Errorf("HARNESS OUTCOME MISMATCH: %s", summary)
	}
	return summary, nil
}

func writeOutputManifest(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	lines := []string{}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "out-digests.sha256" {
			continue
		}
		digest, err := digestFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		lines = append(lines, digest+"  "+entry.Name())
	}
	sort.Strings(lines)
	return os.WriteFile(filepath.Join(dir, "out-digests.sha256"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// runCommand execs a real process and returns its REAL exit status. Nothing in
// this driver infers an outcome from output text.
func runCommand(argv []string, env []string, dir string) (string, int) {
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = env
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err == nil {
		return string(output), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(output), exitErr.ExitCode()
	}
	return string(output) + "\n" + err.Error(), -1
}

func copyFile(source, target string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	os.Remove(target)
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func digestFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}
