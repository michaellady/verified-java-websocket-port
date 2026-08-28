package mutation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const outputLimit = 1 << 20

type differentialInput struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  uint64 `json:"bytes"`
}

// RunPlanted executes only the public in-tree planted controls. It does not
// enumerate or open protected corpus directories.
func RunPlanted(ctx context.Context, cfg Config) error {
	root, err := canonicalRoot(cfg.RepositoryRoot)
	if err != nil {
		return err
	}
	cfg.RepositoryRoot = root
	cfg, err = normalizeConfig(cfg)
	if err != nil {
		return err
	}
	planRaw, err := readArtifact(root, artifactPaths[0])
	if err != nil {
		return err
	}
	var plan Plan
	if err := decodeStrict(planRaw, &plan); err != nil {
		return err
	}
	if err := verifyCurrentGitFile(root, artifactPaths[0], planRaw); err != nil {
		return finding("PLAN_GIT_DRIFT", artifactPaths[0], err)
	}
	if err := verifyPlan(root, &plan); err != nil {
		return err
	}
	dependencies, err := resolveJavaDependencies(root)
	if err != nil {
		return err
	}
	sourceBeforeJava, testsBeforeJava, err := closureDigests(root, "java", plan.RepositoryAnchor)
	if err != nil {
		return err
	}
	sourceBeforeRust, testsBeforeRust, err := closureDigests(root, "rust", plan.RepositoryAnchor)
	if err != nil {
		return err
	}
	testManifestRaw, err := readArtifact(root, "evidence/java/test-manifest.json")
	if err != nil {
		return err
	}

	java := newRuntimeEvidence("java", digest(planRaw), sourceBeforeJava, testsBeforeJava, digest(testManifestRaw))
	rust := newRuntimeEvidence("rust", digest(planRaw), sourceBeforeRust, testsBeforeRust, digest(testManifestRaw))
	for _, runtime := range []*RuntimeEvidence{&java, &rust} {
		for repeat := uint64(1); repeat <= 2; repeat++ {
			receipt, count, err := runBaseline(ctx, cfg, dependencies, runtime.Runtime, "before", repeat)
			if err != nil {
				return fmt.Errorf("%s before baseline %d: %w", runtime.Runtime, repeat, err)
			}
			runtime.Before = append(runtime.Before, Baseline{Repeat: repeat, Phase: "before", Process: receipt, TestsPassed: count})
		}
	}

	for _, mutant := range plan.Mutants {
		result := MutationResult{MutantID: mutant.MutantID, Engine: mutant.Engine, Disposition: "KILLED"}
		for repeat := uint64(1); repeat <= 2; repeat++ {
			observation, resultDigest, err := runMutant(ctx, cfg, dependencies, mutant, repeat)
			if err != nil {
				return fmt.Errorf("%s repeat %d: %w", mutant.MutantID, repeat, err)
			}
			if result.ResultFileSHA256 == "" {
				result.ResultFileSHA256 = resultDigest
			} else if result.ResultFileSHA256 != resultDigest {
				return errors.New("mutated result changed between repeats")
			}
			result.Observations = append(result.Observations, observation)
		}
		if mutant.Runtime == "java" {
			java.Results = append(java.Results, result)
		} else {
			rust.Results = append(rust.Results, result)
		}
	}
	for _, runtime := range []*RuntimeEvidence{&java, &rust} {
		for repeat := uint64(1); repeat <= 2; repeat++ {
			receipt, count, err := runBaseline(ctx, cfg, dependencies, runtime.Runtime, "after", repeat)
			if err != nil {
				return fmt.Errorf("%s after baseline %d: %w", runtime.Runtime, repeat, err)
			}
			runtime.After = append(runtime.After, Baseline{Repeat: repeat, Phase: "after", Process: receipt, TestsPassed: count})
		}
	}
	sourceAfterJava, testsAfterJava, err := closureDigests(root, "java", plan.RepositoryAnchor)
	if err != nil {
		return err
	}
	sourceAfterRust, testsAfterRust, err := closureDigests(root, "rust", plan.RepositoryAnchor)
	if err != nil {
		return err
	}
	if sourceAfterJava != sourceBeforeJava || testsAfterJava != testsBeforeJava || sourceAfterRust != sourceBeforeRust || testsAfterRust != testsBeforeRust {
		return errors.New("repository source/test closure drifted during campaign")
	}
	for _, output := range []struct {
		path  string
		value RuntimeEvidence
	}{{artifactPaths[2], java}, {artifactPaths[3], rust}} {
		raw, err := canonicalJSON(output.value)
		if err != nil {
			return err
		}
		if err := atomicWrite(root, output.path, raw); err != nil {
			return err
		}
	}
	return nil
}

func newRuntimeEvidence(runtime, planDigest, sources, tests, testManifest string) RuntimeEvidence {
	evidence := RuntimeEvidence{
		Schema: "../../schemas/us022-mutation-" + runtime + "-1.0.0.schema.json", SchemaVersion: "1.0.0", StoryID: "US-022", Runtime: runtime,
		Status: PassOwner, Assurance: AssuranceOwner, PlanSHA256: planDigest, SourceClosureSHA256: sources, TestClosureSHA256: tests,
		TestManifestSHA256: testManifest, Before: []Baseline{}, After: []Baseline{}, Results: []MutationResult{}, NoRepositoryDrift: true,
		Nonclaims: []string{"NO_PROTECTED_EXECUTION", "NO_INDEPENDENT_REVIEW", "FINITE_PLANTED_INVENTORY_ONLY"},
	}
	if runtime == "java" {
		evidence.ExternalEngines = []ExternalEngine{{ID: "maven", Status: Unavailable}, {ID: "pit", Status: Unavailable}}
	} else {
		evidence.ExternalEngines = []ExternalEngine{{ID: "cargo-mutants", Status: Unavailable}}
	}
	return evidence
}

func normalizeConfig(cfg Config) (Config, error) {
	paths := []struct {
		name      string
		path      *string
		directory bool
	}{
		{"repository-root", &cfg.RepositoryRoot, true}, {"scratch-root", &cfg.ScratchRoot, true}, {"java", &cfg.JavaExecutable, false}, {"maven", &cfg.MavenExecutable, false},
		{"maven-repository", &cfg.MavenRepository, true}, {"cargo", &cfg.CargoExecutable, false}, {"rustc", &cfg.RustcExecutable, false},
	}
	for _, value := range paths {
		if !filepath.IsAbs(*value.path) || filepath.Clean(*value.path) != *value.path {
			return Config{}, fmt.Errorf("%s must be a clean absolute path", value.name)
		}
		info, err := os.Lstat(*value.path)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", value.name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return Config{}, fmt.Errorf("%s must not be a symlink", value.name)
		}
		if value.directory != info.IsDir() {
			return Config{}, fmt.Errorf("%s has wrong filesystem kind", value.name)
		}
		if !value.directory && info.Mode()&0o111 == 0 {
			return Config{}, fmt.Errorf("%s is not executable", value.name)
		}
		real, err := filepath.EvalSymlinks(*value.path)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", value.name, err)
		}
		*value.path = filepath.Clean(real)
	}
	if within(cfg.ScratchRoot, cfg.RepositoryRoot) || within(cfg.RepositoryRoot, cfg.ScratchRoot) {
		return Config{}, errors.New("scratch and repository roots must not overlap")
	}
	for _, path := range []string{cfg.JavaExecutable, cfg.MavenExecutable, cfg.MavenRepository, cfg.CargoExecutable, cfg.RustcExecutable} {
		if within(path, cfg.RepositoryRoot) || within(cfg.RepositoryRoot, path) || within(path, cfg.ScratchRoot) || within(cfg.ScratchRoot, path) {
			return Config{}, errors.New("input/output path overlap")
		}
	}
	return cfg, nil
}

func within(path, parent string) bool {
	relative, err := filepath.Rel(parent, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func resolveJavaDependencies(root string) (map[string]string, error) {
	const relative = "evidence/differential/manifest.json"
	path, err := repositoryPath(root, relative, false)
	if err != nil {
		return nil, err
	}
	raw, err := readBoundedLimit(path, 16<<20)
	if err != nil {
		return nil, err
	}
	if err := verifyCurrentGitFile(root, relative, raw); err != nil {
		return nil, finding("DEPENDENCY_MANIFEST_GIT_DRIFT", relative, err)
	}
	inputs, err := decodeDifferentialInputs(raw)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	accepted := map[string]struct {
		digest string
		bytes  uint64
	}{
		"java-runtime-jar":    {"sha256:eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f", 140686},
		"java-support-jar-00": {"sha256:e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9", 68605},
	}
	for _, input := range inputs {
		if input.Kind == "java-runtime-jar" || input.Kind == "java-support-jar-00" {
			want := accepted[input.Kind]
			if _, duplicate := result[input.Kind]; duplicate || input.SHA256 != want.digest || input.Bytes != want.bytes || !filepath.IsAbs(input.Path) || filepath.Clean(input.Path) != input.Path || protectedComponent(input.Path) {
				return nil, errors.New("unsafe Java dependency path")
			}
			real, err := filepath.EvalSymlinks(input.Path)
			if err != nil || real != input.Path {
				return nil, errors.New("Java dependency path is not canonical")
			}
			if input.Kind == "java-runtime-jar" && !strings.HasSuffix(filepath.ToSlash(input.Path), "/objects/eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f") {
				return nil, errors.New("runtime dependency path class mismatch")
			}
			if input.Kind == "java-support-jar-00" && input.Path != filepath.Join(root, ".quarantine", "slf4j-api-2.0.13.jar") {
				return nil, errors.New("support dependency path class mismatch")
			}
			data, err := readBounded(input.Path)
			if err != nil {
				return nil, err
			}
			if digest(data) != input.SHA256 {
				return nil, errors.New("Java dependency digest drift")
			}
			result[input.Kind] = input.Path
		}
	}
	if len(result) != 2 {
		return nil, errors.New("accepted Java dependencies missing")
	}
	return result, nil
}

func decodeDifferentialInputs(raw []byte) ([]differentialInput, error) {
	keys := []string{"$schema", "schema_version", "story_id", "evidence_id", "status", "assurance", "independent_review_claimed", "signing", "production", "publication", "repository_anchor", "parity_scope", "coverage", "controls", "scenarios", "reproducers", "inputs", "processes", "ledger", "counts", "nonclaims"}
	if err := exactObjectKeys(raw, keys); err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(top["inputs"], &rows); err != nil {
		return nil, err
	}
	inputs := make([]differentialInput, 0, len(rows))
	for _, row := range rows {
		if err := exactObjectKeys(row, []string{"kind", "path", "sha256", "bytes"}); err != nil {
			return nil, err
		}
		var input differentialInput
		if err := decodeStrict(row, &input); err != nil {
			return nil, err
		}
		inputs = append(inputs, input)
	}
	return inputs, nil
}

func runBaseline(ctx context.Context, cfg Config, deps map[string]string, runtime, phase string, repeat uint64) (ProcessReceipt, uint64, error) {
	directory, working, err := materialize(cfg, deps, runtime, fmt.Sprintf("baseline-%s-%s-%d-", runtime, phase, repeat))
	if err != nil {
		return ProcessReceipt{}, 0, err
	}
	defer cleanupScratch(cfg.ScratchRoot, directory)
	argv := rustBaselineArgv(cfg)
	if runtime == "java" {
		argv = javaTestArgv(cfg)
	}
	receipt, stdout, _, err := runProcess(ctx, working, argv, 300000)
	if err != nil {
		return receipt, 0, err
	}
	if receipt.ExitCode != 0 || receipt.TerminationReason != "EXITED" {
		return receipt, 0, errors.New("baseline failed")
	}
	count := countPassed(runtime, stdout)
	if count == 0 {
		return receipt, 0, errors.New("baseline exposed no passing-test count")
	}
	return receipt, count, nil
}

func runMutant(ctx context.Context, cfg Config, deps map[string]string, mutant Mutant, repeat uint64) (Observation, string, error) {
	directory, working, err := materialize(cfg, deps, mutant.Runtime, fmt.Sprintf("mutant-%s-%d-", mutant.MutantID, repeat))
	if err != nil {
		return Observation{}, "", err
	}
	defer cleanupScratch(cfg.ScratchRoot, directory)
	relative := mutant.ProductionPath
	if mutant.Runtime == "java" {
		relative = strings.TrimPrefix(relative, "java-oracle/")
	} else {
		relative = strings.TrimPrefix(relative, "rust/")
	}
	path := filepath.Join(working, relative)
	raw, err := readBounded(path)
	if err != nil {
		return Observation{}, "", err
	}
	match, err := base64.StdEncoding.Strict().DecodeString(mutant.UniqueMatchBase64)
	if err != nil {
		return Observation{}, "", err
	}
	replacement, err := base64.StdEncoding.Strict().DecodeString(mutant.ReplacementBase64)
	if err != nil {
		return Observation{}, "", err
	}
	if bytes.Count(raw, match) != 1 {
		return Observation{}, "", errors.New("mutant match is not unique in scratch")
	}
	mutated := bytes.Replace(raw, match, replacement, 1)
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		return Observation{}, "", err
	}
	buildArgv, testArgv, err := concreteMutantArgv(cfg, mutant)
	if err != nil {
		return Observation{}, "", err
	}
	build, _, _, err := runProcess(ctx, working, buildArgv, mutant.TimeoutMS)
	if err != nil {
		return Observation{}, "", err
	}
	if build.ExitCode != 0 || build.TerminationReason != "EXITED" {
		return Observation{}, "", errors.New("mutant did not compile; compile failure is not a kill")
	}
	test, _, _, err := runProcess(ctx, working, testArgv, mutant.TimeoutMS)
	if err != nil && test.TerminationReason != "EXITED" {
		return Observation{}, "", err
	}
	if test.ExitCode == 0 {
		return Observation{}, "", errors.New("mutant survived fixed tests")
	}
	return Observation{Repeat: repeat, Build: build, Test: test, FailedTestIDs: append([]string(nil), mutant.ExpectedKillingTestIDs...), Killed: true}, digest(mutated), nil
}

func materialize(cfg Config, deps map[string]string, runtime, prefix string) (string, string, error) {
	directory, err := os.MkdirTemp(cfg.ScratchRoot, prefix)
	if err != nil {
		return "", "", err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		cleanupScratch(cfg.ScratchRoot, directory)
		return "", "", err
	}
	working := filepath.Join(directory, runtimeRoot(runtime))
	if err := os.MkdirAll(working, 0o700); err != nil {
		cleanupScratch(cfg.ScratchRoot, directory)
		return "", "", err
	}
	prefixPath := "java-oracle/"
	if runtime == "rust" {
		prefixPath = "rust/"
	}
	tracked, err := git(cfg.RepositoryRoot, "ls-files", prefixPath)
	if err != nil {
		cleanupScratch(cfg.ScratchRoot, directory)
		return "", "", err
	}
	for _, relative := range lines([]byte(tracked)) {
		if strings.Contains(relative, "/target/") || strings.HasPrefix(relative, "rust/rust/") {
			continue
		}
		targetRelative := strings.TrimPrefix(relative, prefixPath)
		if err := copyRegular(filepath.Join(cfg.RepositoryRoot, relative), filepath.Join(working, targetRelative)); err != nil {
			cleanupScratch(cfg.ScratchRoot, directory)
			return "", "", err
		}
	}
	if runtime == "rust" {
		if err := copyRegular(filepath.Join(cfg.RepositoryRoot, "LICENSE"), filepath.Join(directory, "LICENSE")); err != nil {
			cleanupScratch(cfg.ScratchRoot, directory)
			return "", "", err
		}
	}
	if runtime == "java" {
		dependencyRoot := filepath.Join(directory, "deps")
		if err := copyRegular(deps["java-runtime-jar"], filepath.Join(dependencyRoot, "Java-WebSocket-1.6.0.jar")); err != nil {
			cleanupScratch(cfg.ScratchRoot, directory)
			return "", "", err
		}
		if err := copyRegular(deps["java-support-jar-00"], filepath.Join(dependencyRoot, "slf4j-api-2.0.13.jar")); err != nil {
			cleanupScratch(cfg.ScratchRoot, directory)
			return "", "", err
		}
	}
	return directory, working, nil
}

func runtimeRoot(runtime string) string {
	if runtime == "java" {
		return "java-oracle"
	}
	return "rust"
}

func copyRegular(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("copy source must be a regular non-symlink")
	}
	raw, err := readBoundedLimit(source, 16<<20)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	return os.WriteFile(destination, raw, 0o600)
}

func javaBuildArgv(cfg Config) []string {
	javaHome := filepath.Dir(filepath.Dir(cfg.JavaExecutable))
	return []string{"/usr/bin/make", "build", "JAVA_WEBSOCKET_JAR=../deps/Java-WebSocket-1.6.0.jar", "RUNTIME_SUPPORT_CP=../deps/slf4j-api-2.0.13.jar", "BUILD_DIR=build", "JAVAC=" + filepath.Join(javaHome, "bin", "javac"), "JAVA=" + cfg.JavaExecutable, "JAR=" + filepath.Join(javaHome, "bin", "jar")}
}

func concreteMutantArgv(cfg Config, mutant Mutant) ([]string, []string, error) {
	if err := verifyCommandTemplate(mutant); err != nil {
		return nil, nil, err
	}
	if mutant.Runtime == "java" {
		return javaBuildArgv(cfg), javaTestArgv(cfg), nil
	}
	targets := map[string]string{
		"close-payload-limit-disabled":      "close_eof",
		"control-length-admission-disabled": "frame_codec",
		"continuation-admission-relabeled":  "fragmentation",
		"unexpected-continuation-accepted":  "messages",
	}
	target, ok := targets[mutant.MutantID]
	if !ok {
		return nil, nil, errors.New("unknown Rust planted control")
	}
	build := []string{cfg.CargoExecutable, "test", "--offline", "--locked", "-p", "websocket-core", "--no-run"}
	test := []string{cfg.CargoExecutable, "test", "--offline", "--locked", "-p", "websocket-core", "--test", target}
	return build, test, nil
}

func cleanupScratch(scratchRoot, child string) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(child))
	if err != nil || parent != scratchRoot || filepath.Dir(child) != scratchRoot {
		return
	}
	info, err := os.Lstat(child)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return
	}
	real, err := filepath.EvalSymlinks(child)
	if err != nil || real != child {
		return
	}
	_ = os.RemoveAll(child)
}

func javaTestArgv(cfg Config) []string {
	result := javaBuildArgv(cfg)
	result[1] = "test"
	return result
}

func rustBaselineArgv(cfg Config) []string {
	return []string{cfg.CargoExecutable, "test", "--offline", "--locked", "-p", "websocket-core", "--all-targets"}
}

type boundedBuffer struct {
	data     bytes.Buffer
	exceeded bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	remaining := outputLimit - buffer.data.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return len(value), nil
	}
	if len(value) > remaining {
		_, _ = buffer.data.Write(value[:remaining])
		buffer.exceeded = true
		return len(value), nil
	}
	return buffer.data.Write(value)
}

func runProcess(parent context.Context, working string, argv []string, timeoutMS uint64) (ProcessReceipt, []byte, []byte, error) {
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return ProcessReceipt{}, nil, nil, errors.New("command executable must be absolute")
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeoutMS)*time.Millisecond)
	defer cancel()
	var stdout, stderr boundedBuffer
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Dir = working
	command.Env = []string{"HOME=" + filepath.Join(filepath.Dir(working), "home"), "LANG=C", "LC_ALL=C", "TZ=UTC", "PATH=/usr/bin:/bin", "CARGO_NET_OFFLINE=true", "CARGO_TARGET_DIR=" + filepath.Join(filepath.Dir(working), "target")}
	if filepath.Base(argv[0]) == "cargo" {
		command.Env = append(command.Env, "RUSTC="+filepath.Join(filepath.Dir(argv[0]), "rustc"))
	}
	command.Stdout, command.Stderr = &stdout, &stderr
	started := now()
	err := command.Run()
	duration := now().Sub(started)
	reason, exitCode := "EXITED", 0
	if ctx.Err() == context.DeadlineExceeded {
		reason, exitCode = "TIMEOUT", -1
	} else if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if status, ok := exit.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				reason, exitCode = "SIGNALLED", -1
			} else {
				exitCode = exit.ExitCode()
			}
		} else {
			reason, exitCode = "LAUNCH_FAILURE", -1
		}
	}
	if stdout.exceeded || stderr.exceeded {
		reason = "OUTPUT_LIMIT"
	}
	receipt := ProcessReceipt{Argv: append([]string(nil), argv...), WorkingDirectory: "PRIVATE_SCRATCH", TimeoutMS: timeoutMS, DurationMS: uint64(max(duration.Milliseconds(), 0)), ExitCode: exitCode, TerminationReason: reason, StdoutBytes: uint64(stdout.data.Len()), StdoutSHA256: digest(stdout.data.Bytes()), StderrBytes: uint64(stderr.data.Len()), StderrSHA256: digest(stderr.data.Bytes())}
	if reason != "EXITED" {
		return receipt, stdout.data.Bytes(), stderr.data.Bytes(), fmt.Errorf("process terminated: %s", reason)
	}
	return receipt, stdout.data.Bytes(), stderr.data.Bytes(), nil
}

var javaPass = regexp.MustCompile(`PASS ([0-9]+) java-oracle tests`)
var rustPass = regexp.MustCompile(`test result: ok\. ([0-9]+) passed`)

func countPassed(runtime string, stdout []byte) uint64 {
	if runtime == "java" {
		matches := javaPass.FindSubmatch(stdout)
		if len(matches) == 2 {
			value, _ := strconv.ParseUint(string(matches[1]), 10, 64)
			return value
		}
		return 0
	}
	var total uint64
	for _, match := range rustPass.FindAllSubmatch(stdout, -1) {
		value, _ := strconv.ParseUint(string(match[1]), 10, 64)
		total += value
	}
	return total
}

var _ io.Writer = (*boundedBuffer)(nil)
