// Package refinement captures and verifies the bounded US-024 Rust
// before/after refinement receipt.
package refinement

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/differential"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	SchemaPath      = "schemas/us024-refinement-replay-1.0.0.schema.json"
	EvidencePath    = "evidence/refinement-replay.json"
	beforeCommit    = "7ea615dfee70ae71af59e83559110c6c4671c405"
	beforeTree      = "9353bf8cd67ad401eec2036c661441a6c9bf95b0"
	candidateRoot   = "sha256:dd96c5fb0346f736e6ddadf7848d34ceb5e4c2beefe77c1730bec6649516190e"
	evaluationRoot  = "sha256:4f608c8f658dd287efef362bdfe027cf66116f95e1192810bce2fb3e1d83ce21"
	assurance       = "OWNER_ATTESTED_NOT_INDEPENDENT"
	maximumEvidence = 16 << 20
	pinnedCargo     = "/Users/mikelady/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo"
)

var (
	fullGitObject     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	testResultPattern = regexp.MustCompile(`test result: (?:ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed;`)
	rustTestPattern   = regexp.MustCompile(`(?m)#\s*\[\s*test\s*\]\s*(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)`)
)

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type Subject struct {
	Commit                 string `json:"commit"`
	Tree                   string `json:"tree"`
	RustTree               string `json:"rust_tree_sha256"`
	CargoLock              string `json:"cargo_lock_sha256"`
	Binary                 string `json:"binary_sha256"`
	BinarySize             int64  `json:"binary_bytes"`
	BinaryCanonicalization string `json:"binary_canonicalization"`
}

type PairRow struct {
	ScenarioID string `json:"scenario_id"`
	Input      string `json:"input_sha256"`
	Before     string `json:"before_normalized_sha256"`
	After      string `json:"after_normalized_sha256"`
	BeforeExit int    `json:"before_exit_code"`
	AfterExit  int    `json:"after_exit_code"`
	TimedOut   bool   `json:"timed_out"`
}

type ReplayCounts struct {
	Expected  int `json:"expected"`
	Selected  int `json:"selected"`
	Executed  int `json:"executed"`
	Compared  int `json:"compared"`
	Equal     int `json:"equal"`
	Failed    int `json:"failed"`
	Duplicate int `json:"duplicate"`
	Missing   int `json:"missing"`
	Filtered  int `json:"filtered"`
	Skipped   int `json:"skipped"`
	TimedOut  int `json:"timed_out"`
}

type PublicReplay struct {
	Kind            string       `json:"kind"`
	Counts          ReplayCounts `json:"counts"`
	Rows            []PairRow    `json:"rows"`
	ForwardRoot     string       `json:"forward_transcript_root"`
	ReverseRoot     string       `json:"reverse_transcript_root"`
	ReverseAllEqual bool         `json:"reverse_all_equal"`
}

type CommandResult struct {
	Status       string `json:"status"`
	ExitCode     int    `json:"exit_code"`
	TimedOut     bool   `json:"timed_out"`
	ResultSHA256 string `json:"result_sha256"`
	TestsPassed  int    `json:"tests_passed"`
	TestsFailed  int    `json:"tests_failed"`
}

type LocalReplay struct {
	Kind     string        `json:"kind"`
	Manifest Artifact      `json:"manifest"`
	TargetID string        `json:"target_id"`
	Profile  string        `json:"profile"`
	Command  []string      `json:"command"`
	Repeat   int           `json:"repeat"`
	Before   CommandResult `json:"before"`
	After    CommandResult `json:"after"`
}

type TestInventory struct {
	BeforeNames []string `json:"before_names"`
	AfterNames  []string `json:"after_names"`
	AddedNames  []string `json:"added_names"`
}

type Membership struct {
	Production []Artifact `json:"production"`
	Tests      []Artifact `json:"tests"`
	Tools      []Artifact `json:"tools"`
}

type ImmutableUS023 struct {
	TargetCommit   string     `json:"target_commit"`
	TargetTree     string     `json:"target_tree"`
	CandidateRoot  string     `json:"candidate_root"`
	EvaluationRoot string     `json:"evaluation_root"`
	SnapshotState  string     `json:"snapshot_state"`
	ParityState    string     `json:"parity_state"`
	RequiredGates  int        `json:"required_gates"`
	SatisfiedGates int        `json:"satisfied_gates"`
	BlockedGates   int        `json:"blocked_gates"`
	ProtectedFiles []Artifact `json:"protected_files"`
}

type Connections struct {
	FormalConnection      string `json:"formal_connection"`
	FormalBackend         string `json:"formal_backend"`
	ProductionRefinement  string `json:"production_refinement"`
	ConcurrencyConnection string `json:"concurrency_connection"`
	SystematicTests       string `json:"systematic_tests"`
	FormalEquivalence     string `json:"formal_equivalence"`
}

type GateCounts struct {
	Required int `json:"required"`
	Passed   int `json:"passed"`
	Blocked  int `json:"blocked"`
}

type GateSummary struct {
	Counts   GateCounts `json:"counts"`
	Blockers []string   `json:"blockers"`
}

type PhaseProvenance struct {
	Review  string `json:"review"`
	QA      string `json:"qa"`
	Reality string `json:"reality"`
}

type Evidence struct {
	Schema                   string          `json:"$schema"`
	SchemaVersion            string          `json:"schema_version"`
	StoryID                  string          `json:"story_id"`
	Status                   string          `json:"status"`
	Assurance                string          `json:"assurance"`
	IndependentReviewClaimed bool            `json:"independent_review_claimed"`
	Production               bool            `json:"production"`
	Publication              bool            `json:"publication"`
	Signing                  bool            `json:"signing"`
	PerformanceClaimed       bool            `json:"performance_claimed"`
	CutoverClaimed           bool            `json:"cutover_claimed"`
	Before                   Subject         `json:"before"`
	After                    Subject         `json:"after"`
	US023                    ImmutableUS023  `json:"immutable_us023"`
	Membership               Membership      `json:"membership"`
	PublicReplay             PublicReplay    `json:"public_replay"`
	LocalReplays             []LocalReplay   `json:"local_replays"`
	TestInventory            TestInventory   `json:"test_inventory"`
	Connections              Connections     `json:"connections"`
	Gates                    GateSummary     `json:"gates"`
	Provenance               PhaseProvenance `json:"provenance"`
	Nonclaims                []string        `json:"nonclaims"`
}

type CaptureConfig struct {
	RepositoryRoot string
	BeforeCommit   string
	AfterCommit    string
	Cargo          string
	EvidencePath   string
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readBounded(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 || info.Size() > maximum {
		return nil, errors.New("input must be a bounded regular non-symlink file")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("input exceeded bound")
	}
	return raw, nil
}

func git(root string, args ...string) ([]byte, error) {
	return gitBounded(root, 64<<20, args...)
}

func gitBounded(root string, maximum int, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	stdout := &cappedOutput{limit: maximum}
	stderr := &cappedOutput{limit: 4 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, stderr.value.String())
	}
	return append([]byte(nil), stdout.value.Bytes()...), nil
}

func resolveSubject(root, commit string) (string, error) {
	if !fullGitObject.MatchString(commit) {
		return "", errors.New("subject commit must be full 40-hex")
	}
	raw, err := git(root, "rev-parse", commit+"^{tree}")
	if err != nil {
		return "", err
	}
	tree := strings.TrimSpace(string(raw))
	if !fullGitObject.MatchString(tree) {
		return "", errors.New("subject tree must be full 40-hex")
	}
	return tree, nil
}

func extractSubject(root, commit string) (string, func(), error) {
	raw, err := gitBounded(root, 512<<20, "archive", "--format=tar", commit)
	if err != nil {
		return "", nil, err
	}
	if len(raw) > 512<<20 {
		return "", nil, errors.New("subject archive exceeded bound")
	}
	destination, err := os.MkdirTemp("/private/tmp", "us024-subject-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(destination) }
	reader := tar.NewReader(bytes.NewReader(raw))
	entries := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cleanup()
			return "", nil, err
		}
		entries++
		memberName := header.Name
		if header.Typeflag == tar.TypeDir {
			memberName = strings.TrimSuffix(memberName, "/")
		}
		if entries > 50_000 || memberName == "" || filepath.IsAbs(memberName) || filepath.Clean(memberName) != memberName || memberName == ".." || strings.HasPrefix(memberName, "../") {
			cleanup()
			return "", nil, fmt.Errorf("unsafe archive member %q", header.Name)
		}
		path := filepath.Join(destination, memberName)
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(path, 0o755); err != nil {
				cleanup()
				return "", nil, err
			}
			continue
		}
		if header.Typeflag == tar.TypeXGlobalHeader && header.Name == "pax_global_header" {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			cleanup()
			return "", nil, fmt.Errorf("nonregular archive member %q type %d", header.Name, header.Typeflag)
		}
		if header.Size < 0 || header.Size > 128<<20 {
			cleanup()
			return "", nil, errors.New("archive member exceeded bound")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			cleanup()
			return "", nil, err
		}
		mode := fs.FileMode(0o644)
		if header.Mode&0o111 != 0 {
			mode = 0o755
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		_, copyErr := io.CopyN(file, reader, header.Size)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			cleanup()
			return "", nil, errors.Join(copyErr, closeErr)
		}
	}
	return destination, cleanup, nil
}

func runCargoBuild(ctx context.Context, root, cargo string) (Artifact, error) {
	command := exec.CommandContext(ctx, cargo, "build", "--locked", "--offline", "-p", "websocket-testee", "--bin", "websocket-testee")
	command.Dir = filepath.Join(root, "rust")
	environment, err := cargoEnvironment(root, cargo)
	if err != nil {
		return Artifact{}, err
	}
	command.Env = environment
	output, err := command.CombinedOutput()
	if err != nil {
		return Artifact{}, fmt.Errorf("cargo build: %w: %s", err, string(output))
	}
	path := filepath.Join(root, "rust/target/debug/websocket-testee")
	if err := canonicalizeMachOUUID(path); err != nil {
		return Artifact{}, err
	}
	if err := adhocSignMachO(ctx, path); err != nil {
		return Artifact{}, err
	}
	raw, err := readBounded(path, 512<<20)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Path: "rust/target/debug/websocket-testee", SHA256: digest(raw), Bytes: int64(len(raw))}, nil
}

func adhocSignMachO(ctx context.Context, path string) error {
	command := exec.CommandContext(ctx, "/usr/bin/codesign", "--force", "--sign", "-", path)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	output := &cappedOutput{limit: 4 << 10}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		return fmt.Errorf("ad-hoc codesign failed: %w: %s", err, output.value.String())
	}
	verify := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", path)
	verify.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	if output, err := verify.CombinedOutput(); err != nil {
		return fmt.Errorf("ad-hoc signature verification failed: %w: %s", err, string(output))
	}
	return nil
}

func canonicalizeMachOUUID(path string) error {
	raw, err := readBounded(path, 512<<20)
	if err != nil {
		return err
	}
	if len(raw) < 32 || binary.LittleEndian.Uint32(raw[:4]) != 0xfeedfacf {
		return errors.New("replay binary is not a little-endian Mach-O 64 executable")
	}
	commands := int(binary.LittleEndian.Uint32(raw[16:20]))
	commandBytes := int(binary.LittleEndian.Uint32(raw[20:24]))
	if commands <= 0 || commands > 4096 || commandBytes < 8 || 32+commandBytes > len(raw) {
		return errors.New("Mach-O load-command envelope invalid")
	}
	offset, uuidOffset := 32, -1
	for range commands {
		if offset+8 > 32+commandBytes {
			return errors.New("Mach-O load command truncated")
		}
		kind := binary.LittleEndian.Uint32(raw[offset : offset+4])
		size := int(binary.LittleEndian.Uint32(raw[offset+4 : offset+8]))
		if size < 8 || offset+size > 32+commandBytes {
			return errors.New("Mach-O load command size invalid")
		}
		if kind == 0x1b {
			if uuidOffset >= 0 || size != 24 {
				return errors.New("Mach-O LC_UUID denominator invalid")
			}
			uuidOffset = offset + 8
		}
		offset += size
	}
	if uuidOffset < 0 {
		return errors.New("Mach-O LC_UUID absent")
	}
	for index := 0; index < 16; index++ {
		raw[uuidOffset+index] = 0
	}
	hash := sha256.New()
	hash.Write([]byte("us024-macho-lc-uuid-v1\x00"))
	hash.Write(raw)
	uuid := hash.Sum(nil)[:16]
	uuid[6] = (uuid[6] & 0x0f) | 0x50
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := file.WriteAt(uuid, int64(uuidOffset)); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func cargoEnvironment(root, cargo string) ([]string, error) {
	environmentRoot := filepath.Join(root, "rust", "target", ".us024-environment")
	home := filepath.Join(environmentRoot, "home")
	cargoHome := filepath.Join(environmentRoot, "cargo-home")
	temporary := filepath.Join(environmentRoot, "tmp")
	for _, directory := range []string{home, cargoHome, temporary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, err
		}
	}
	flags := "--remap-path-prefix=" + root + "=/us024/source -C codegen-units=1"
	toolchain := filepath.Dir(cargo)
	return []string{
		"LANG=C", "LC_ALL=C", "TZ=UTC", "CARGO_NET_OFFLINE=true", "CARGO_INCREMENTAL=0", "SOURCE_DATE_EPOCH=0",
		"PATH=" + toolchain + ":/usr/bin:/bin",
		"HOME=" + home,
		"CARGO_HOME=" + cargoHome,
		"CARGO_TARGET_DIR=" + filepath.Join(root, "rust", "target"),
		"TMPDIR=" + temporary,
		"RUSTC=" + filepath.Join(toolchain, "rustc"),
		"RUSTDOC=" + filepath.Join(toolchain, "rustdoc"),
		"RUSTFLAGS=" + flags,
	}, nil
}

func treeDigest(root, relative string) (string, error) {
	type row struct{ path, sha string }
	rows := []row{}
	err := filepath.WalkDir(filepath.Join(root, relative), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || strings.Contains(path, string(filepath.Separator)+"target"+string(filepath.Separator)) {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return errors.New("Rust tree contains nonregular member")
		}
		raw, err := readBounded(path, 128<<20)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rows = append(rows, row{filepath.ToSlash(rel), digest(raw)})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].path < rows[j].path })
	hash := sha256.New()
	hash.Write([]byte("us024-rust-tree-v1\x00"))
	for _, row := range rows {
		hash.Write([]byte(row.path))
		hash.Write([]byte{0})
		hash.Write([]byte(row.sha))
		hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func artifactAt(root, commit, path string) (Artifact, error) {
	if filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, "../") {
		return Artifact{}, errors.New("noncanonical artifact path")
	}
	raw, err := git(root, "show", commit+":"+path)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Path: path, SHA256: digest(raw), Bytes: int64(len(raw))}, nil
}

func replayRoot(domain string, before, after Subject, rows []PairRow, swapped bool) string {
	hash := sha256.New()
	hash.Write([]byte(domain))
	hash.Write([]byte{0})
	if swapped {
		hash.Write([]byte(after.Commit + "\x00" + before.Commit + "\x00"))
	} else {
		hash.Write([]byte(before.Commit + "\x00" + after.Commit + "\x00"))
	}
	for _, row := range rows {
		hash.Write([]byte(row.ScenarioID + "\x00" + row.Input + "\x00"))
		if swapped {
			hash.Write([]byte(row.After + "\x00" + row.Before + "\x00"))
		} else {
			hash.Write([]byte(row.Before + "\x00" + row.After + "\x00"))
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func classifyMembership(root, commit string, paths []string) (Membership, error) {
	result := Membership{Production: []Artifact{}, Tests: []Artifact{}, Tools: []Artifact{}}
	for _, path := range paths {
		artifact, err := artifactAt(root, commit, path)
		if err != nil {
			return Membership{}, err
		}
		switch {
		case path == "rust/websocket-driver/src/lib.rs" || path == "rust/websocket-driver/src/output.rs":
			result.Production = append(result.Production, artifact)
		case strings.HasPrefix(path, "rust/") && strings.Contains(path, "/tests/"):
			result.Tests = append(result.Tests, artifact)
		default:
			result.Tools = append(result.Tools, artifact)
		}
	}
	return result, nil
}

var allowedDiff = map[string]bool{
	"docs/us024-refinement-contract.md":                  true,
	"rust/websocket-driver/src/lib.rs":                   true,
	"rust/websocket-driver/src/output.rs":                true,
	"rust/websocket-driver/tests/refinement_contract.rs": true,
	"rust/websocket-testee/tests/process.rs":             true,
	"internal/differential/differential.go":              true,
	"internal/differential/differential_test.go":         true,
	"internal/refinement/refinement.go":                  true,
	"internal/refinement/refinement_test.go":             true,
	"cmd/refinementctl/main.go":                          true,
	"cmd/refinementctl/main_test.go":                     true,
	"schemas/us024-refinement-replay-1.0.0.schema.json":  true,
}

func changedPaths(root, before, after string) ([]string, error) {
	raw, err := git(root, "diff", "--name-status", "-z", before, after)
	if err != nil {
		return nil, err
	}
	fields := bytes.Split(raw, []byte{0})
	paths := []string{}
	for index := 0; index < len(fields) && len(fields[index]) != 0; {
		status := string(fields[index])
		index++
		if status != "A" && status != "M" {
			return nil, fmt.Errorf("deleted, renamed, copied, or type-changed path: %s", status)
		}
		if index >= len(fields) || len(fields[index]) == 0 {
			return nil, errors.New("malformed git name-status output")
		}
		path := string(fields[index])
		index++
		if !allowedDiff[path] {
			return nil, fmt.Errorf("undeclared changed path %s", path)
		}
		paths = append(paths, path)
	}
	return paths, nil
}

type replaySpec struct {
	kind, manifestPath, targetID, profile string
	command                               []string
	repeat                                int
}

func loadReplaySpecs(root string) ([]replaySpec, error) {
	type observation struct {
		Platform string `json:"platform"`
		Profile  string `json:"profile"`
		Repeat   int    `json:"repeat"`
	}
	type target struct {
		ID            string        `json:"id"`
		ReplayCommand []string      `json:"replay_command"`
		Observations  []observation `json:"observations"`
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	specs := []replaySpec{}
	for _, kind := range []string{"property", "fuzz"} {
		path := filepath.Join(root, "evidence", kind, "manifest.json")
		raw, err := readBounded(path, 4<<20)
		if err != nil {
			return nil, err
		}
		var manifest struct {
			Targets []target `json:"targets"`
		}
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return nil, err
		}
		if len(manifest.Targets) == 0 || len(manifest.Targets) > 32 {
			return nil, fmt.Errorf("%s target denominator invalid", kind)
		}
		for _, target := range manifest.Targets {
			repeats := 0
			for _, observation := range target.Observations {
				if observation.Platform == platform && observation.Profile == "debug" && observation.Repeat > repeats {
					repeats = observation.Repeat
				}
			}
			if target.ID == "" || repeats <= 0 || repeats > 4 || len(target.ReplayCommand) < 3 {
				return nil, fmt.Errorf("%s target replay contract invalid", kind)
			}
			for repeat := 1; repeat <= repeats; repeat++ {
				specs = append(specs, replaySpec{kind: kind, manifestPath: "evidence/" + kind + "/manifest.json", targetID: target.ID, profile: "debug", command: append([]string(nil), target.ReplayCommand...), repeat: repeat})
			}
		}
	}

	runtimePath := filepath.Join(root, "evidence/runtime/manifest.json")
	runtimeRaw, err := readBounded(runtimePath, 4<<20)
	if err != nil {
		return nil, err
	}
	type runtimeRun struct {
		Repeat  int      `json:"repeat"`
		Command []string `json:"command"`
	}
	var runtimeManifest struct {
		Platforms []struct {
			ID      string       `json:"id"`
			Debug   []runtimeRun `json:"debug"`
			Release []runtimeRun `json:"release"`
		} `json:"platforms"`
	}
	if err := json.Unmarshal(runtimeRaw, &runtimeManifest); err != nil {
		return nil, err
	}
	found := false
	for _, declared := range runtimeManifest.Platforms {
		if declared.ID != platform {
			continue
		}
		found = true
		for _, profile := range []struct {
			name string
			runs []runtimeRun
		}{{"debug", declared.Debug}, {"release", declared.Release}} {
			if len(profile.runs) == 0 || len(profile.runs) > 4 {
				return nil, errors.New("runtime repeat denominator invalid")
			}
			for _, run := range profile.runs {
				specs = append(specs, replaySpec{kind: "runtime", manifestPath: "evidence/runtime/manifest.json", targetID: "workspace-" + profile.name, profile: profile.name, command: append([]string(nil), run.Command...), repeat: run.Repeat})
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("runtime manifest has no %s platform", platform)
	}
	return specs, nil
}

type cappedOutput struct {
	value bytes.Buffer
	limit int
}

func (output *cappedOutput) Write(data []byte) (int, error) {
	remaining := output.limit - output.value.Len()
	if remaining <= 0 {
		return 0, errors.New("command output exceeded bound")
	}
	if len(data) > remaining {
		_, _ = output.value.Write(data[:remaining])
		return remaining, errors.New("command output exceeded bound")
	}
	return output.value.Write(data)
}

func runReplayCommand(ctx context.Context, root, cargo string, argv []string) (CommandResult, error) {
	if len(argv) < 3 || argv[0] != "cargo" || argv[1] != "test" || !containsString(argv, "--locked") {
		return CommandResult{}, errors.New("manifest replay command is not an exact locked cargo test")
	}
	commandCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(commandCtx, cargo, argv[1:]...)
	command.Dir = filepath.Join(root, "rust")
	environment, err := cargoEnvironment(root, cargo)
	if err != nil {
		return CommandResult{}, err
	}
	command.Env = environment
	output := &cappedOutput{limit: 4 << 20}
	command.Stdout = output
	command.Stderr = output
	err = command.Run()
	passed, failed := 0, 0
	for _, match := range testResultPattern.FindAllSubmatch(output.value.Bytes(), -1) {
		value, parseErr := strconv.Atoi(string(match[1]))
		if parseErr != nil {
			return CommandResult{}, parseErr
		}
		passed += value
		value, parseErr = strconv.Atoi(string(match[2]))
		if parseErr != nil {
			return CommandResult{}, parseErr
		}
		failed += value
	}
	result := CommandResult{Status: "PASS", ExitCode: 0, TimedOut: false, TestsPassed: passed, TestsFailed: failed}
	if commandCtx.Err() != nil {
		result.Status, result.ExitCode, result.TimedOut = "BLOCKED_UNAVAILABLE", -1, true
		return result, fmt.Errorf("manifest replay timed out: %w", commandCtx.Err())
	}
	if err != nil {
		if command.ProcessState != nil {
			result.ExitCode = command.ProcessState.ExitCode()
		}
		result.Status = "FAIL"
		tail := output.value.Bytes()
		if len(tail) > 4<<10 {
			tail = tail[len(tail)-(4<<10):]
		}
		return result, fmt.Errorf("manifest replay failed: %w: %s", err, string(tail))
	}
	if result.TestsPassed <= 0 || result.TestsFailed != 0 {
		return result, errors.New("manifest replay test denominator was not reconciled")
	}
	result.ResultSHA256 = commandResultDigest(result)
	return result, nil
}

func commandResultDigest(result CommandResult) string {
	canonical := fmt.Sprintf("us024-command-result-v1\x00%s\x00%d\x00%t\x00%d\x00%d", result.Status, result.ExitCode, result.TimedOut, result.TestsPassed, result.TestsFailed)
	return digest([]byte(canonical))
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func runLocalReplays(ctx context.Context, beforeRoot, afterRoot, cargo string) ([]LocalReplay, error) {
	specs, err := loadReplaySpecs(afterRoot)
	if err != nil {
		return nil, err
	}
	results := make([]LocalReplay, 0, len(specs))
	manifestIdentities := map[string]Artifact{}
	for _, spec := range specs {
		manifest := manifestIdentities[spec.manifestPath]
		if manifest.Path == "" {
			raw, err := readBounded(filepath.Join(afterRoot, spec.manifestPath), 4<<20)
			if err != nil {
				return nil, err
			}
			beforeRaw, err := readBounded(filepath.Join(beforeRoot, spec.manifestPath), 4<<20)
			if err != nil || !bytes.Equal(raw, beforeRaw) {
				return nil, fmt.Errorf("manifest drift: %s", spec.manifestPath)
			}
			manifest = Artifact{Path: spec.manifestPath, SHA256: digest(raw), Bytes: int64(len(raw))}
			manifestIdentities[spec.manifestPath] = manifest
		}
		before, err := runReplayCommand(ctx, beforeRoot, cargo, spec.command)
		if err != nil {
			return nil, fmt.Errorf("before %s/%s repeat %d: %w", spec.kind, spec.targetID, spec.repeat, err)
		}
		after, err := runReplayCommand(ctx, afterRoot, cargo, spec.command)
		if err != nil {
			return nil, fmt.Errorf("after %s/%s repeat %d: %w", spec.kind, spec.targetID, spec.repeat, err)
		}
		results = append(results, LocalReplay{Kind: "FRESH_LOCAL_TEST_REPLAY", Manifest: manifest, TargetID: spec.kind + "." + spec.targetID, Profile: spec.profile, Command: spec.command, Repeat: spec.repeat, Before: before, After: after})
	}
	return results, nil
}

func testNamesAt(root, commit, path string) ([]string, error) {
	raw, err := git(root, "show", commit+":"+path)
	if err != nil {
		return nil, err
	}
	names := []string{}
	if strings.HasSuffix(path, ".go") {
		file, err := parser.ParseFile(token.NewFileSet(), path, raw, 0)
		if err != nil {
			return nil, err
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil && strings.HasPrefix(function.Name.Name, "Test") {
				names = append(names, path+"::"+function.Name.Name)
			}
		}
	} else {
		for _, match := range rustTestPattern.FindAllSubmatch(raw, -1) {
			names = append(names, path+"::"+string(match[1]))
		}
	}
	sort.Strings(names)
	return names, nil
}

func testNamesIfPresentAt(root, commit, path string) ([]string, error) {
	entry, err := git(root, "ls-tree", "-z", "--full-tree", commit, "--", path)
	if err != nil {
		return nil, err
	}
	if len(entry) == 0 {
		return []string{}, nil
	}
	if bytes.Count(entry, []byte{0}) != 1 || entry[len(entry)-1] != 0 || !bytes.HasSuffix(entry[:len(entry)-1], []byte("\t"+path)) {
		return nil, fmt.Errorf("ambiguous Git tree entry for %s", path)
	}
	return testNamesAt(root, commit, path)
}

func deriveTestInventory(root, before, after string) (TestInventory, error) {
	changed, err := changedPaths(root, before, after)
	if err != nil {
		return TestInventory{}, err
	}
	beforeNames, afterNames := []string{}, []string{}
	for _, path := range changed {
		if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".rs") {
			continue
		}
		left, err := testNamesIfPresentAt(root, before, path)
		if err != nil {
			return TestInventory{}, err
		}
		right, err := testNamesIfPresentAt(root, after, path)
		if err != nil {
			return TestInventory{}, err
		}
		beforeNames = append(beforeNames, left...)
		afterNames = append(afterNames, right...)
	}
	sort.Strings(beforeNames)
	sort.Strings(afterNames)
	afterSet := map[string]bool{}
	for _, name := range afterNames {
		afterSet[name] = true
	}
	for _, name := range beforeNames {
		if !afterSet[name] {
			return TestInventory{}, fmt.Errorf("pre-existing test name disappeared: %s", name)
		}
	}
	beforeSet := map[string]bool{}
	for _, name := range beforeNames {
		beforeSet[name] = true
	}
	added := []string{}
	for _, name := range afterNames {
		if !beforeSet[name] {
			added = append(added, name)
		}
	}
	return TestInventory{BeforeNames: beforeNames, AfterNames: afterNames, AddedNames: added}, nil
}

func Capture(ctx context.Context, cfg CaptureConfig) (Evidence, error) {
	if cfg.BeforeCommit != beforeCommit {
		return Evidence{}, errors.New("before subject is not the frozen US-023 completion")
	}
	beforeResolved, err := resolveSubject(cfg.RepositoryRoot, cfg.BeforeCommit)
	if err != nil || beforeResolved != beforeTree {
		return Evidence{}, errors.New("before tree drift")
	}
	afterTree, err := resolveSubject(cfg.RepositoryRoot, cfg.AfterCommit)
	if err != nil {
		return Evidence{}, err
	}
	paths, err := changedPaths(cfg.RepositoryRoot, cfg.BeforeCommit, cfg.AfterCommit)
	if err != nil {
		return Evidence{}, err
	}
	beforeRoot, cleanBefore, err := extractSubject(cfg.RepositoryRoot, cfg.BeforeCommit)
	if err != nil {
		return Evidence{}, err
	}
	defer cleanBefore()
	afterRoot, cleanAfter, err := extractSubject(cfg.RepositoryRoot, cfg.AfterCommit)
	if err != nil {
		return Evidence{}, err
	}
	defer cleanAfter()

	buildCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	beforeBinary, err := runCargoBuild(buildCtx, beforeRoot, cfg.Cargo)
	if err != nil {
		return Evidence{}, err
	}
	afterBinary, err := runCargoBuild(buildCtx, afterRoot, cfg.Cargo)
	if err != nil {
		return Evidence{}, err
	}
	beforeRust, err := treeDigest(beforeRoot, "rust")
	if err != nil {
		return Evidence{}, err
	}
	afterRust, err := treeDigest(afterRoot, "rust")
	if err != nil {
		return Evidence{}, err
	}
	beforeLock, err := readBounded(filepath.Join(beforeRoot, "rust/Cargo.lock"), 8<<20)
	if err != nil {
		return Evidence{}, err
	}
	afterLock, err := readBounded(filepath.Join(afterRoot, "rust/Cargo.lock"), 8<<20)
	if err != nil || !bytes.Equal(beforeLock, afterLock) {
		return Evidence{}, errors.New("Cargo.lock drift")
	}
	beforeSubject := Subject{Commit: cfg.BeforeCommit, Tree: beforeResolved, RustTree: beforeRust, CargoLock: digest(beforeLock), Binary: beforeBinary.SHA256, BinarySize: beforeBinary.Bytes, BinaryCanonicalization: "MACHO_LC_UUID_SHA256_V1_ADHOC"}
	afterSubject := Subject{Commit: cfg.AfterCommit, Tree: afterTree, RustTree: afterRust, CargoLock: digest(afterLock), Binary: afterBinary.SHA256, BinarySize: afterBinary.Bytes, BinaryCanonicalization: "MACHO_LC_UUID_SHA256_V1_ADHOC"}

	beforeRows, err := differential.ReplayRustPublic(ctx, differential.RustReplayConfig{RepositoryRoot: beforeRoot, Executable: filepath.Join(beforeRoot, beforeBinary.Path), ScenarioTimeout: 5 * time.Second, SuiteTimeout: 15 * time.Minute})
	if err != nil {
		return Evidence{}, err
	}
	afterRows, err := differential.ReplayRustPublic(ctx, differential.RustReplayConfig{RepositoryRoot: afterRoot, Executable: filepath.Join(afterRoot, afterBinary.Path), ScenarioTimeout: 5 * time.Second, SuiteTimeout: 15 * time.Minute})
	if err != nil {
		return Evidence{}, err
	}
	if len(beforeRows) != 74 || len(afterRows) != 74 {
		return Evidence{}, errors.New("public replay denominator drift")
	}
	rows := make([]PairRow, 0, 74)
	for index := range beforeRows {
		left, right := beforeRows[index], afterRows[index]
		if left.ScenarioID != right.ScenarioID || left.InputSHA256 != right.InputSHA256 || left.NormalizedSHA256 != right.NormalizedSHA256 {
			return Evidence{}, fmt.Errorf("semantic drift at %s", left.ScenarioID)
		}
		rows = append(rows, PairRow{ScenarioID: left.ScenarioID, Input: left.InputSHA256, Before: left.NormalizedSHA256, After: right.NormalizedSHA256, BeforeExit: left.ExitCode, AfterExit: right.ExitCode, TimedOut: left.TimedOut || right.TimedOut})
	}
	localReplays, err := runLocalReplays(ctx, beforeRoot, afterRoot, cfg.Cargo)
	if err != nil {
		return Evidence{}, err
	}
	testInventory, err := deriveTestInventory(cfg.RepositoryRoot, cfg.BeforeCommit, cfg.AfterCommit)
	if err != nil {
		return Evidence{}, err
	}
	membership, err := classifyMembership(cfg.RepositoryRoot, cfg.AfterCommit, paths)
	if err != nil {
		return Evidence{}, err
	}
	protectedPaths := []string{"assurance/candidate-manifest.json", "evidence/parity-replay.json", "evidence/java/behavior-delta-ledger.json"}
	protected := make([]Artifact, 0, len(protectedPaths))
	for _, path := range protectedPaths {
		beforeArtifact, err := artifactAt(cfg.RepositoryRoot, cfg.BeforeCommit, path)
		if err != nil {
			return Evidence{}, err
		}
		afterArtifact, err := artifactAt(cfg.RepositoryRoot, cfg.AfterCommit, path)
		if err != nil || beforeArtifact != afterArtifact {
			return Evidence{}, fmt.Errorf("protected artifact drift: %s", path)
		}
		protected = append(protected, afterArtifact)
	}
	evidence := Evidence{
		Schema: SchemaPath, SchemaVersion: "1.0.0", StoryID: "US-024", Status: "IMPLEMENTATION_REPLAY_PASS_PENDING_REVIEW_QA_REALITY", Assurance: assurance,
		Before: beforeSubject, After: afterSubject,
		US023:         ImmutableUS023{TargetCommit: "1ff89fa30cb0ab6ff339afd3ce486a36e9f7f325", TargetTree: "dfb1950301e9680b1c47f0bd9debc0fc026d0e4f", CandidateRoot: candidateRoot, EvaluationRoot: evaluationRoot, SnapshotState: "FROZEN", ParityState: "BLOCKED", RequiredGates: 44, SatisfiedGates: 0, BlockedGates: 44, ProtectedFiles: protected},
		Membership:    membership,
		PublicReplay:  PublicReplay{Kind: "FRESH_BEFORE_AFTER_PUBLIC_REPLAY", Counts: ReplayCounts{Expected: 74, Selected: 74, Executed: 74, Compared: 74, Equal: 74}, Rows: rows, ReverseAllEqual: true},
		LocalReplays:  localReplays,
		TestInventory: testInventory,
		Connections:   Connections{FormalConnection: "DISCONNECTED_BLOCKED", FormalBackend: "NOT_EXECUTED", ProductionRefinement: "ABSENT", ConcurrencyConnection: "RETAINED_DIFFERENT_SUBJECT_BLOCKED", SystematicTests: "FRESH_LOCAL_TEST_REPLAY", FormalEquivalence: "NOT_CLAIMED"},
		Gates:         GateSummary{Counts: GateCounts{Required: 12, Passed: 4, Blocked: 8}, Blockers: []string{"AUTOBAHN_AUTHORITY_CONSUMED", "HIDDEN_SEALED_NOT_EXECUTED", "FORMAL_BACKEND_NOT_EXECUTED", "FORMAL_REFINEMENT_DISCONNECTED", "CONCURRENCY_DIFFERENT_SUBJECT", "INDEPENDENT_HOST_NOT_EXECUTED", "INDEPENDENT_HUMAN_REVIEW_NOT_EXECUTED", "PRODUCTION_CUTOVER_NOT_AUTHORIZED"}},
		Provenance:    PhaseProvenance{Review: "NOT_EXECUTED", QA: "NOT_EXECUTED", Reality: "NOT_EXECUTED"},
		Nonclaims:     []string{"no fresh Java differential comparison", "no Autobahn or Docker/wstest rerun", "no hidden or sealed confirmation", "no formal proof or equivalence", "no independent host or human review", "no performance result", "no production, publication, signing, or cutover"},
	}
	evidence.PublicReplay.ForwardRoot = replayRoot("us024-refinement-forward-v1", evidence.Before, evidence.After, rows, false)
	evidence.PublicReplay.ReverseRoot = replayRoot("us024-refinement-reverse-v1", evidence.Before, evidence.After, rows, true)
	if err := validateStatic(evidence); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}

func validateStatic(e Evidence) error {
	if e.Schema != SchemaPath || e.SchemaVersion != "1.0.0" || e.StoryID != "US-024" || e.Status != "IMPLEMENTATION_REPLAY_PASS_PENDING_REVIEW_QA_REALITY" || e.Assurance != assurance {
		return errors.New("claim boundary drift")
	}
	if e.Provenance != (PhaseProvenance{Review: "NOT_EXECUTED", QA: "NOT_EXECUTED", Reality: "NOT_EXECUTED"}) {
		return errors.New("repository receipt cannot claim review, QA, or reality provenance")
	}
	if e.IndependentReviewClaimed || e.Production || e.Publication || e.Signing || e.PerformanceClaimed || e.CutoverClaimed {
		return errors.New("unsupported positive claim")
	}
	if e.Before.Commit != beforeCommit || e.Before.Tree != beforeTree || !fullGitObject.MatchString(e.After.Commit) || !fullGitObject.MatchString(e.After.Tree) || e.After.Commit == e.Before.Commit {
		return errors.New("subject identity drift")
	}
	for _, subject := range []Subject{e.Before, e.After} {
		if !digestPattern.MatchString(subject.RustTree) || !digestPattern.MatchString(subject.CargoLock) || !digestPattern.MatchString(subject.Binary) || subject.BinarySize <= 0 || subject.BinaryCanonicalization != "MACHO_LC_UUID_SHA256_V1_ADHOC" {
			return errors.New("subject artifact identity drift")
		}
	}
	if e.Before.CargoLock != "sha256:4e889e0da92e71acff96ad07d7bc2ffcee24968fbb21d580b8b0c9aad9a043cb" || e.After.CargoLock != e.Before.CargoLock {
		return errors.New("Cargo.lock identity drift")
	}
	if e.US023.CandidateRoot != candidateRoot || e.US023.EvaluationRoot != evaluationRoot || e.US023.SnapshotState != "FROZEN" || e.US023.ParityState != "BLOCKED" || e.US023.RequiredGates != 44 || e.US023.SatisfiedGates != 0 || e.US023.BlockedGates != 44 {
		return errors.New("US-023 identity or parity truth drift")
	}
	if e.PublicReplay.Kind != "FRESH_BEFORE_AFTER_PUBLIC_REPLAY" || e.PublicReplay.Counts != (ReplayCounts{Expected: 74, Selected: 74, Executed: 74, Compared: 74, Equal: 74}) || len(e.PublicReplay.Rows) != 74 || !e.PublicReplay.ReverseAllEqual {
		return errors.New("public replay denominator drift")
	}
	seen := map[string]bool{}
	for index, row := range e.PublicReplay.Rows {
		wantID := fmt.Sprintf("us005.pub.%04d", index)
		if row.ScenarioID != wantID || seen[row.ScenarioID] || !digestPattern.MatchString(row.Input) || !digestPattern.MatchString(row.Before) || row.Before != row.After || row.BeforeExit != 0 || row.AfterExit != 0 || row.TimedOut {
			return errors.New("public replay row drift")
		}
		seen[row.ScenarioID] = true
	}
	if e.PublicReplay.ForwardRoot != replayRoot("us024-refinement-forward-v1", e.Before, e.After, e.PublicReplay.Rows, false) || e.PublicReplay.ReverseRoot != replayRoot("us024-refinement-reverse-v1", e.Before, e.After, e.PublicReplay.Rows, true) {
		return errors.New("transcript root drift")
	}
	if e.Connections != (Connections{FormalConnection: "DISCONNECTED_BLOCKED", FormalBackend: "NOT_EXECUTED", ProductionRefinement: "ABSENT", ConcurrencyConnection: "RETAINED_DIFFERENT_SUBJECT_BLOCKED", SystematicTests: "FRESH_LOCAL_TEST_REPLAY", FormalEquivalence: "NOT_CLAIMED"}) {
		return errors.New("formal or concurrency claim drift")
	}
	if e.Gates.Counts.Required != e.Gates.Counts.Passed+e.Gates.Counts.Blocked || e.Gates.Counts.Blocked == 0 || len(e.Gates.Blockers) != e.Gates.Counts.Blocked {
		return errors.New("gate reconciliation drift")
	}
	if len(e.LocalReplays) != 34 {
		return errors.New("manifest-derived local replay denominator drift")
	}
	for _, replay := range e.LocalReplays {
		if replay.Kind != "FRESH_LOCAL_TEST_REPLAY" || replay.TargetID == "" || replay.Profile == "" || replay.Repeat <= 0 || len(replay.Command) < 3 || replay.Command[0] != "cargo" || !containsString(replay.Command, "--locked") || replay.Before.Status != "PASS" || replay.After.Status != "PASS" || replay.Before.ExitCode != 0 || replay.After.ExitCode != 0 || replay.Before.TimedOut || replay.After.TimedOut || replay.Before.ResultSHA256 != commandResultDigest(replay.Before) || replay.After.ResultSHA256 != commandResultDigest(replay.After) || replay.Before.TestsPassed <= 0 || replay.After.TestsPassed < replay.Before.TestsPassed || replay.Before.TestsFailed != 0 || replay.After.TestsFailed != 0 {
			return errors.New("manifest-derived local replay drift")
		}
	}
	if len(e.TestInventory.BeforeNames) == 0 || len(e.TestInventory.AfterNames) < len(e.TestInventory.BeforeNames) {
		return errors.New("pre-existing test-name denominator drift")
	}
	if !sort.StringsAreSorted(e.TestInventory.BeforeNames) || !sort.StringsAreSorted(e.TestInventory.AfterNames) || !sort.StringsAreSorted(e.TestInventory.AddedNames) {
		return errors.New("test-name inventory order drift")
	}
	afterNames := map[string]bool{}
	for _, name := range e.TestInventory.AfterNames {
		if name == "" || afterNames[name] {
			return errors.New("after test-name inventory invalid")
		}
		afterNames[name] = true
	}
	beforeNames := map[string]bool{}
	for _, name := range e.TestInventory.BeforeNames {
		if !afterNames[name] {
			return errors.New("pre-existing test name absent after refinement")
		}
		beforeNames[name] = true
	}
	wantAdded := []string{}
	for _, name := range e.TestInventory.AfterNames {
		if !beforeNames[name] {
			wantAdded = append(wantAdded, name)
		}
	}
	if !reflect.DeepEqual(e.TestInventory.AddedNames, wantAdded) {
		return errors.New("added test-name inventory drift")
	}
	if len(e.Membership.Production) != 2 || e.Membership.Production[0].Path != "rust/websocket-driver/src/lib.rs" || e.Membership.Production[1].Path != "rust/websocket-driver/src/output.rs" || len(e.Membership.Tests) != 2 || e.Membership.Tests[0].Path != "rust/websocket-driver/tests/refinement_contract.rs" || e.Membership.Tests[1].Path != "rust/websocket-testee/tests/process.rs" {
		return errors.New("production or hostile-test membership drift")
	}
	wantProtected := map[string]string{
		"assurance/candidate-manifest.json":        "sha256:ab24fb6cbc3b811ef1d08c46c3c1b4925b03595836f5ccd65f0858fea66c9925",
		"evidence/parity-replay.json":              "sha256:f2ca5d490429609977fc4782da3890e29629a9353fd5bfdc9bc6390a89c5f182",
		"evidence/java/behavior-delta-ledger.json": "sha256:e4800359d8a667524216b74947e43c169153406338398473221286bfbba9724a",
	}
	if len(e.US023.ProtectedFiles) != len(wantProtected) {
		return errors.New("protected artifact denominator drift")
	}
	for _, artifact := range e.US023.ProtectedFiles {
		if wantProtected[artifact.Path] != artifact.SHA256 {
			return errors.New("protected artifact identity drift")
		}
	}
	for _, collection := range [][]Artifact{e.Membership.Production, e.Membership.Tests, e.Membership.Tools, e.US023.ProtectedFiles} {
		for _, artifact := range collection {
			if artifact.Path == "" || filepath.IsAbs(artifact.Path) || filepath.Clean(artifact.Path) != artifact.Path || strings.HasPrefix(artifact.Path, "../") || !digestPattern.MatchString(artifact.SHA256) || artifact.Bytes <= 0 {
				return errors.New("artifact membership drift")
			}
		}
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("duplicate or invalid JSON object key")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func decodeStrict(raw []byte, destination any) error {
	if err := rejectDuplicateKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func validateSchema(root string, raw []byte) error {
	schemaRaw, err := readBounded(filepath.Join(root, SchemaPath), 4<<20)
	if err != nil {
		return err
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("mem:///us024-refinement.json", value); err != nil {
		return err
	}
	schema, err := compiler.Compile("mem:///us024-refinement.json")
	if err != nil {
		return err
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return schema.Validate(document)
}

func verifyArtifactMembership(root, commit string, artifact Artifact) error {
	actual, err := artifactAt(root, commit, artifact.Path)
	if err != nil {
		return err
	}
	if actual != artifact {
		return fmt.Errorf("artifact membership drift: %s", artifact.Path)
	}
	return nil
}

func Verify(repositoryRoot string, raw []byte) error {
	return VerifyContext(context.Background(), repositoryRoot, raw, pinnedCargo)
}

func verifyRederivedClaims(evidence, rederived Evidence) error {
	if !reflect.DeepEqual(evidence, rederived) {
		return errors.New("fresh receipt rederivation drift")
	}
	return nil
}

func VerifyContext(ctx context.Context, repositoryRoot string, raw []byte, cargo string) error {
	if len(raw) == 0 || len(raw) > maximumEvidence {
		return errors.New("evidence size invalid")
	}
	if err := validateSchema(repositoryRoot, raw); err != nil {
		return err
	}
	var evidence Evidence
	if err := decodeStrict(raw, &evidence); err != nil {
		return err
	}
	canonical, err := json.Marshal(evidence)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("evidence is not canonical JSON")
	}
	if err := validateStatic(evidence); err != nil {
		return err
	}
	beforeResolved, err := resolveSubject(repositoryRoot, evidence.Before.Commit)
	if err != nil || beforeResolved != evidence.Before.Tree {
		return errors.New("before Git subject drift")
	}
	afterResolved, err := resolveSubject(repositoryRoot, evidence.After.Commit)
	if err != nil || afterResolved != evidence.After.Tree {
		return errors.New("after Git subject drift")
	}
	paths, err := changedPaths(repositoryRoot, evidence.Before.Commit, evidence.After.Commit)
	if err != nil {
		return err
	}
	wantMembership := map[string]bool{}
	for _, path := range paths {
		wantMembership[path] = true
	}
	for _, collection := range [][]Artifact{evidence.Membership.Production, evidence.Membership.Tests, evidence.Membership.Tools} {
		for _, artifact := range collection {
			if !wantMembership[artifact.Path] {
				return fmt.Errorf("membership path not changed: %s", artifact.Path)
			}
			delete(wantMembership, artifact.Path)
		}
	}
	if len(wantMembership) != 0 {
		return errors.New("changed path absent from membership")
	}
	for _, collection := range [][]Artifact{evidence.Membership.Production, evidence.Membership.Tests, evidence.Membership.Tools} {
		for _, artifact := range collection {
			if err := verifyArtifactMembership(repositoryRoot, evidence.After.Commit, artifact); err != nil {
				return err
			}
		}
	}
	for _, artifact := range evidence.US023.ProtectedFiles {
		if err := verifyArtifactMembership(repositoryRoot, evidence.Before.Commit, artifact); err != nil {
			return err
		}
		if err := verifyArtifactMembership(repositoryRoot, evidence.After.Commit, artifact); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(filepath.Join(repositoryRoot, "evidence/behavior-delta-ledger.json")); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("stale parallel behavior ledger exists")
	}
	rederived, err := Capture(ctx, CaptureConfig{RepositoryRoot: repositoryRoot, BeforeCommit: evidence.Before.Commit, AfterCommit: evidence.After.Commit, Cargo: cargo})
	if err != nil {
		return fmt.Errorf("fresh subject replay failed: %w", err)
	}
	return verifyRederivedClaims(evidence, rederived)
}

func Marshal(e Evidence) ([]byte, error) { return json.Marshal(e) }

// RefreshTestInventory updates only the inventory derived from the immutable
// before/after Git subjects. It intentionally does not rerun any replay.
func RefreshTestInventory(repositoryRoot string, raw []byte) (Evidence, error) {
	if len(raw) == 0 || len(raw) > maximumEvidence {
		return Evidence{}, errors.New("evidence size invalid")
	}
	if err := validateSchema(repositoryRoot, raw); err != nil {
		return Evidence{}, err
	}
	var evidence Evidence
	if err := decodeStrict(raw, &evidence); err != nil {
		return Evidence{}, err
	}
	canonical, err := json.Marshal(evidence)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Evidence{}, errors.New("evidence is not canonical JSON")
	}
	if err := validateStatic(evidence); err != nil {
		return Evidence{}, err
	}
	inventory, err := deriveTestInventory(repositoryRoot, evidence.Before.Commit, evidence.After.Commit)
	if err != nil {
		return Evidence{}, err
	}
	evidence.TestInventory = inventory
	if err := validateStatic(evidence); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}
