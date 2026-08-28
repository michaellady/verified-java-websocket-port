// Command tlcdriver runs digest-pinned TLA+ models and exact-string mutation
// canaries. Its structure is adapted from Claude's dc07516 runner, with
// fail-closed verdict checks and bounded process execution added here.
package main

import (
	"context"
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
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type manifest struct {
	SchemaVersion string     `json:"schema_version"`
	Kind          string     `json:"kind"`
	ToolSHA256    string     `json:"tool_sha256"`
	Models        []model    `json:"models"`
	Mutations     []mutation `json:"mutations"`
}

type model struct {
	Module  string `json:"module"`
	TLAPath string `json:"tla_path"`
	CFGPath string `json:"cfg_path"`
}

type mutation struct {
	ID            string `json:"id"`
	Module        string `json:"module"`
	Target        string `json:"target"`
	ExpectedExit  int    `json:"expected_exit"`
	ExpectedKind  string `json:"expected_kind"`
	ExpectedCheck string `json:"expected_check"`
	Rationale     string `json:"rationale"`
	Edits         []edit `json:"edits"`
}

type edit struct {
	Find    string `json:"find"`
	Replace string `json:"replace"`
	Count   int    `json:"count"`
}

type artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type result struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	ExitCode int      `json:"exit_code"`
	Verdict  string   `json:"verdict"`
	Check    string   `json:"check"`
	Log      artifact `json:"log"`
}

type receipt struct {
	SchemaVersion string      `json:"schema_version"`
	Kind          string      `json:"kind"`
	StartedAt     string      `json:"started_at"`
	FinishedAt    string      `json:"finished_at"`
	Driver        artifact    `json:"driver"`
	Tool          artifact    `json:"tool"`
	Java          artifact    `json:"java"`
	Runtime       runtimeInfo `json:"runtime"`
	Checker       checkerInfo `json:"checker"`
	Manifest      artifact    `json:"manifest"`
	Models        []artifact  `json:"models"`
	Results       []result    `json:"results"`
	Status        string      `json:"status"`
	ClaimScope    string      `json:"claim_scope"`
}

type runtimeInfo struct {
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	GoVersion string `json:"go_version"`
}

type checkerInfo struct {
	Workers          int    `json:"workers"`
	FingerprintIndex int    `json:"fingerprint_index"`
	Seed             int64  `json:"seed"`
	ProcessTimeout   string `json:"process_timeout"`
}

const (
	tlcWorkers          = 2
	tlcFingerprintIndex = 0
	tlcSeed             = int64(20260828)
)

var (
	invariantViolation = regexp.MustCompile(`Error: Invariant ([A-Za-z][A-Za-z0-9_]*) is violated`)
	propertyViolation  = regexp.MustCompile(`Error: Temporal property ([A-Za-z][A-Za-z0-9_]*) was violated`)
	actionViolation    = regexp.MustCompile(`Error: Action property ([A-Za-z][A-Za-z0-9_]*) is violated`)
	identifier         = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "tlcdriver: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("tlcdriver", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "repository root")
	jar := flags.String("jar", "", "digest-pinned tla2tools.jar")
	java := flags.String("java", "", "absolute Java executable")
	work := flags.String("work", "", "empty staging directory")
	out := flags.String("out", "", "empty receipt directory")
	timeout := flags.Duration("timeout", 60*time.Second, "per-process timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *root == "" || *jar == "" || *java == "" || *work == "" || *out == "" {
		return errors.New("-root, -jar, -java, -work, and -out are required")
	}
	if *timeout <= 0 || *timeout > 10*time.Minute {
		return errors.New("-timeout must be within (0, 10m]")
	}
	for _, directory := range []string{*work, *out} {
		if err := ensureEmptyDirectory(directory); err != nil {
			return err
		}
	}

	javaPath, err := regularExecutable(*java)
	if err != nil {
		return fmt.Errorf("java: %w", err)
	}
	manifestPath := filepath.Join(*root, "assurance", "formal", "model-mutations.json")
	manifestBody, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	var plan manifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestBody)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if err := validateManifest(plan); err != nil {
		return err
	}
	jarDigest, err := digestFile(*jar)
	if err != nil {
		return fmt.Errorf("digest tool: %w", err)
	}
	if jarDigest != plan.ToolSHA256 {
		return fmt.Errorf("tool digest %s, want %s", jarDigest, plan.ToolSHA256)
	}
	javaDigest, err := digestFile(javaPath)
	if err != nil {
		return fmt.Errorf("digest java: %w", err)
	}
	driverPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve driver: %w", err)
	}
	driverPath, err = filepath.EvalSymlinks(driverPath)
	if err != nil {
		return fmt.Errorf("resolve driver links: %w", err)
	}
	driverDigest, err := digestFile(driverPath)
	if err != nil {
		return fmt.Errorf("digest driver: %w", err)
	}

	started := time.Now().UTC()
	record := receipt{
		SchemaVersion: "1.0.0",
		Kind:          "tlc-execution-receipt",
		StartedAt:     started.Format(time.RFC3339),
		Driver:        artifact{Path: driverPath, SHA256: driverDigest},
		Tool:          artifact{Path: *jar, SHA256: jarDigest},
		Java:          artifact{Path: javaPath, SHA256: javaDigest},
		Runtime:       runtimeInfo{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, GoVersion: runtime.Version()},
		Checker:       checkerInfo{Workers: tlcWorkers, FingerprintIndex: tlcFingerprintIndex, Seed: tlcSeed, ProcessTimeout: timeout.String()},
		Manifest:      artifact{Path: manifestPath, SHA256: digestBytes(manifestBody)},
		Status:        "RUNNING",
		ClaimScope:    "PROVED_MODEL_ONLY",
	}

	staged := make(map[string]map[string][]byte, len(plan.Models))
	for _, candidate := range plan.Models {
		staged[candidate.Module] = make(map[string][]byte, 2)
		for extension, relative := range map[string]string{"tla": candidate.TLAPath, "cfg": candidate.CFGPath} {
			body, readErr := os.ReadFile(filepath.Join(*root, filepath.FromSlash(relative)))
			if readErr != nil {
				return fmt.Errorf("read %s: %w", relative, readErr)
			}
			target := filepath.Join(*work, candidate.Module+"."+extension)
			if writeErr := os.WriteFile(target, body, 0o644); writeErr != nil {
				return fmt.Errorf("stage %s: %w", target, writeErr)
			}
			staged[candidate.Module][extension] = body
			record.Models = append(record.Models, artifact{Path: relative, SHA256: digestBytes(body)})
		}
	}
	if err := validateCheckCoverage(plan, staged); err != nil {
		return err
	}

	for _, candidate := range plan.Models {
		sany, runErr := execute(javaPath, *jar, *work, *out, *timeout,
			"sany."+candidate.Module, "tla2sany.SANY", candidate.Module+".tla")
		if runErr != nil {
			return runErr
		}
		record.Results = append(record.Results, sany)
		if sany.ExitCode != 0 {
			return fmt.Errorf("%s exited %d", sany.ID, sany.ExitCode)
		}
		tlc, runErr := execute(javaPath, *jar, *work, *out, *timeout,
			"tlc."+candidate.Module, "tlc2.TLC", "-workers", fmt.Sprint(tlcWorkers), "-fp", fmt.Sprint(tlcFingerprintIndex), "-seed", fmt.Sprint(tlcSeed), "-config", candidate.Module+".cfg", candidate.Module)
		if runErr != nil {
			return runErr
		}
		record.Results = append(record.Results, tlc)
		if tlc.ExitCode != 0 || tlc.Verdict != "clean" {
			return fmt.Errorf("%s was exit=%d verdict=%s check=%s", tlc.ID, tlc.ExitCode, tlc.Verdict, tlc.Check)
		}
	}

	for _, mutant := range plan.Mutations {
		directory := filepath.Join(*work, "mutants", mutant.ID)
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
		for _, extension := range []string{"tla", "cfg"} {
			body := staged[mutant.Module][extension]
			if extension == mutant.Target {
				updated, editErr := applyEdits(string(body), mutant.Edits)
				if editErr != nil {
					return fmt.Errorf("mutation %s: %w", mutant.ID, editErr)
				}
				body = []byte(updated)
			}
			if err := os.WriteFile(filepath.Join(directory, mutant.Module+"."+extension), body, 0o644); err != nil {
				return err
			}
		}
		observed, runErr := execute(javaPath, *jar, directory, *out, *timeout,
			"mutant."+mutant.ID, "tlc2.TLC", "-workers", fmt.Sprint(tlcWorkers), "-fp", fmt.Sprint(tlcFingerprintIndex), "-seed", fmt.Sprint(tlcSeed), "-config", mutant.Module+".cfg", mutant.Module)
		if runErr != nil {
			return runErr
		}
		record.Results = append(record.Results, observed)
		if observed.ExitCode != mutant.ExpectedExit || observed.Verdict != mutant.ExpectedKind || observed.Check != mutant.ExpectedCheck {
			return fmt.Errorf("mutation %s was exit=%d verdict=%s check=%s", mutant.ID, observed.ExitCode, observed.Verdict, observed.Check)
		}
	}

	for module, files := range staged {
		for extension, original := range files {
			body, readErr := os.ReadFile(filepath.Join(*work, module+"."+extension))
			if readErr != nil || string(body) != string(original) {
				return fmt.Errorf("pristine staged artifact changed: %s.%s", module, extension)
			}
		}
	}
	record.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	record.Status = "PASS"
	sort.Slice(record.Models, func(left, right int) bool { return record.Models[left].Path < record.Models[right].Path })
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := os.WriteFile(filepath.Join(*out, "receipt.json"), body, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "PASS models=%d mutations=%d receipt_sha256=%s\n", len(plan.Models), len(plan.Mutations), digestBytes(body))
	return nil
}

func validateManifest(plan manifest) error {
	if plan.SchemaVersion != "1.0.0" || plan.Kind != "formal-model-mutations" || !strings.HasPrefix(plan.ToolSHA256, "sha256:") {
		return errors.New("manifest identity or tool digest is invalid")
	}
	modules := make(map[string]bool, len(plan.Models))
	for _, candidate := range plan.Models {
		if !identifier.MatchString(candidate.Module) || modules[candidate.Module] {
			return fmt.Errorf("invalid or duplicate module %q", candidate.Module)
		}
		modules[candidate.Module] = true
		for _, path := range []string{candidate.TLAPath, candidate.CFGPath} {
			if filepath.IsAbs(path) || strings.Contains(filepath.ToSlash(path), "../") {
				return fmt.Errorf("unsafe model path %q", path)
			}
		}
	}
	ids := make(map[string]bool, len(plan.Mutations))
	checks := make(map[string]bool, len(plan.Mutations))
	for _, mutant := range plan.Mutations {
		if !identifier.MatchString(mutant.ID) || ids[mutant.ID] || !modules[mutant.Module] || (mutant.Target != "tla" && mutant.Target != "cfg") || len(mutant.Edits) == 0 {
			return fmt.Errorf("invalid mutation %q", mutant.ID)
		}
		ids[mutant.ID] = true
		checkKey := mutant.Module + ":" + mutant.ExpectedCheck
		if mutant.ExpectedExit == 0 || mutant.ExpectedKind != "violated" || !identifier.MatchString(mutant.ExpectedCheck) || strings.TrimSpace(mutant.Rationale) == "" || checks[checkKey] {
			return fmt.Errorf("mutation %q has an unsafe expected outcome", mutant.ID)
		}
		checks[checkKey] = true
	}
	return nil
}

func validateCheckCoverage(plan manifest, staged map[string]map[string][]byte) error {
	expected := make(map[string][]string, len(plan.Models))
	for _, mutant := range plan.Mutations {
		expected[mutant.Module] = append(expected[mutant.Module], mutant.ExpectedCheck)
	}
	for _, candidate := range plan.Models {
		var declared []string
		for _, line := range strings.Split(string(staged[candidate.Module]["cfg"]), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && (fields[0] == "INVARIANT" || fields[0] == "PROPERTY") {
				declared = append(declared, fields[1])
			}
		}
		sort.Strings(declared)
		sort.Strings(expected[candidate.Module])
		if strings.Join(declared, "\n") != strings.Join(expected[candidate.Module], "\n") {
			return fmt.Errorf("model %s checked properties %v do not match mutation coverage %v", candidate.Module, declared, expected[candidate.Module])
		}
	}
	return nil
}

func applyEdits(body string, edits []edit) (string, error) {
	for index, candidate := range edits {
		if candidate.Count < 1 || candidate.Find == candidate.Replace {
			return "", fmt.Errorf("edit %d is not a positive mutation", index)
		}
		if found := strings.Count(body, candidate.Find); found != candidate.Count {
			return "", fmt.Errorf("edit %d matched %d times, want %d", index, found, candidate.Count)
		}
		body = strings.Replace(body, candidate.Find, candidate.Replace, candidate.Count)
	}
	return body, nil
}

func execute(java, jar, directory, out string, timeout time.Duration, id string, arguments ...string) (result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, java, append([]string{"-XX:+UseParallelGC", "-cp", jar}, arguments...)...)
	command.Dir = directory
	body, err := command.CombinedOutput()
	logPath := filepath.Join(out, strings.ReplaceAll(id, "/", "_")+".out")
	if writeErr := os.WriteFile(logPath, body, 0o644); writeErr != nil {
		return result{}, writeErr
	}
	if ctx.Err() != nil {
		return result{}, fmt.Errorf("%s timed out after %s", id, timeout)
	}
	exitCode := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			return result{}, err
		}
		exitCode = exitError.ExitCode()
	}
	verdict, check := classify(string(body))
	return result{ID: id, Kind: arguments[0], ExitCode: exitCode, Verdict: verdict, Check: check, Log: artifact{Path: filepath.Base(logPath), SHA256: digestBytes(body)}}, nil
}

func classify(body string) (string, string) {
	for _, candidate := range []struct {
		expression *regexp.Regexp
		kind       string
	}{{invariantViolation, "violated"}, {propertyViolation, "violated"}, {actionViolation, "violated"}} {
		if match := candidate.expression.FindStringSubmatch(body); match != nil {
			return candidate.kind, match[1]
		}
	}
	if strings.Contains(body, "Model checking completed. No error has been found.") {
		return "clean", "NONE"
	}
	return "indeterminate", "NONE"
}

func ensureEmptyDirectory(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("directory must be empty: %s", path)
	}
	return nil
}

func regularExecutable(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("path must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("path must resolve to a regular executable")
	}
	return resolved, nil
}

func digestFile(path string) (string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = handle.Close() }()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, handle); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
