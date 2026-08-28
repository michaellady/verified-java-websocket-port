// Command tlcdriver executes the US-012 / US-016 TLA+ model checks and their
// seeded-defect runs inside the accepted sandbox profile.
//
// It exists because review round 2 (session 01a045ba-61a3-76e1-b214-88178f506760,
// BLOCKING-3) correctly found that the attempt-0127 driver was a Bash script
// carrying loops, branching, mutation logic, and orchestration — a direct
// violation of the standing rule that non-trivial logic lives in a compiled
// binary, and one that being "evidence" does not excuse. Everything that
// script did in shell now lives here:
//
//   - the mutations are DATA (assurance/formal/model-mutations.json), applied
//     as exact-string edits with a declared occurrence count that this binary
//     enforces, so a mutation can never silently no-op the way a mistyped sed
//     expression can;
//   - every checker invocation is an exec of the real java command and every
//     exit code is read from that process, never from a wrapper's echo and
//     never through `go run`;
//   - stdout is a machine-readable receipt: RESULT / DIGEST / WINDOW lines
//     that the formalplan validator parses and binds to the recorded claims.
//
// Usage:
//
//	tlcdriver -root <repo> -jar <tla2tools.jar> -work <scratch> -out <dir>
//
// The exit status is 0 only when every model and every mutation ran. A
// mutation whose edits do not apply exactly as declared is a hard failure:
// silently skipping it would fabricate non-vacuity evidence.
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
	"regexp"
	"sort"
	"strings"
	"time"
)

// mutationManifest is assurance/formal/model-mutations.json.
type mutationManifest struct {
	SchemaVersion string          `json:"schema_version"`
	Kind          string          `json:"kind"`
	Statement     string          `json:"statement"`
	Models        []manifestModel `json:"models"`
	Mutations     []mutation      `json:"mutations"`
}

type manifestModel struct {
	Module  string `json:"module"`
	TLAPath string `json:"tla_path"`
	CfgPath string `json:"cfg_path"`
}

type mutation struct {
	DefectID        string `json:"defect_id"`
	Module          string `json:"module"`
	Target          string `json:"target"`
	ExpectedOutcome string `json:"expected_outcome"`
	ExpectedCheck   string `json:"expected_check"`
	Rationale       string `json:"rationale"`
	Edits           []edit `json:"edits"`
}

type edit struct {
	Find    string `json:"find"`
	Replace string `json:"replace"`
	Count   int    `json:"count"`
}

var (
	invariantViolation = regexp.MustCompile(`Error: Invariant ([A-Za-z][A-Za-z0-9_]*) is violated`)
	propertyViolation  = regexp.MustCompile(`Error: Temporal property ([A-Za-z][A-Za-z0-9_]*) was violated`)
	cleanVerdict       = "Model checking completed. No error has been found."
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "tlcdriver: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	root := flag.String("root", "", "repository root holding the model artifacts and the mutation manifest")
	jar := flag.String("jar", "", "path to the digest-pinned tla2tools.jar")
	work := flag.String("work", "", "scratch directory for staged models and mutants")
	out := flag.String("out", "", "directory receiving the verbatim checker output receipts")
	flag.Parse()
	if *root == "" || *jar == "" || *work == "" || *out == "" {
		return errors.New("-root, -jar, -work and -out are all required")
	}
	for _, dir := range []string{*work, *out} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	manifestPath := filepath.Join(*root, "assurance", "formal", "model-mutations.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read mutation manifest: %w", err)
	}
	var manifest mutationManifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("decode mutation manifest: %w", err)
	}
	if manifest.Kind != "formal-model-mutations" {
		return fmt.Errorf("unexpected manifest kind %q", manifest.Kind)
	}

	jarDigest, err := digestFile(*jar)
	if err != nil {
		return fmt.Errorf("digest checker archive: %w", err)
	}
	fmt.Printf("DIGEST kind=tool name=tla2tools.jar sha256=%s\n", jarDigest)
	fmt.Printf("DIGEST kind=manifest name=model-mutations.json sha256=%s\n", digestBytes(manifestBytes))
	fmt.Printf("WINDOW start=%s\n", nowUTC())

	byModule := map[string]manifestModel{}
	for _, model := range manifest.Models {
		byModule[model.Module] = model
	}

	// Stage each model under its TLA+ module name (module identifiers cannot
	// contain the hyphen the shipped file names use) and bind the staged
	// bytes to the repository bytes by digest.
	staged := map[string]map[string]string{}
	for _, model := range manifest.Models {
		staged[model.Module] = map[string]string{}
		for suffix, source := range map[string]string{"tla": model.TLAPath, "cfg": model.CfgPath} {
			target := filepath.Join(*work, model.Module+"."+suffix)
			body, err := os.ReadFile(filepath.Join(*root, filepath.FromSlash(source)))
			if err != nil {
				return fmt.Errorf("read %s: %w", source, err)
			}
			if err := os.WriteFile(target, body, 0o644); err != nil {
				return fmt.Errorf("stage %s: %w", target, err)
			}
			staged[model.Module][suffix] = string(body)
			fmt.Printf("DIGEST kind=staged name=%s.%s sha256=%s\n",
				model.Module, suffix, digestBytes(body))
		}
	}

	// The shipped runs.
	for _, model := range manifest.Models {
		sanyExit, err := runJava(*jar, *work, filepath.Join(*out, "sany-"+model.Module+".out"),
			"tla2sany.SANY", model.Module+".tla")
		if err != nil {
			return err
		}
		fmt.Printf("RESULT step=sany.%s exit=%d\n", model.Module, sanyExit)

		tlcPath := filepath.Join(*out, "tlc-"+model.Module+".out")
		tlcExit, err := runJava(*jar, *work, tlcPath,
			"tlc2.TLC", "-config", model.Module+".cfg", model.Module)
		if err != nil {
			return err
		}
		verdict, check := classify(tlcPath)
		fmt.Printf("RESULT step=tlc.%s exit=%d verdict=%s check=%s\n",
			model.Module, tlcExit, verdict, check)
	}

	// The seeded defects. Each mutant gets its own directory so the shipped
	// artifacts are never touched; the driver re-reads them afterwards and
	// says so.
	for _, m := range manifest.Mutations {
		if _, ok := byModule[m.Module]; !ok {
			return fmt.Errorf("mutation %s names unknown module %s", m.DefectID, m.Module)
		}
		dir := filepath.Join(*work, "mut", m.DefectID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		for _, suffix := range []string{"tla", "cfg"} {
			body := staged[m.Module][suffix]
			if suffix == m.Target {
				mutated, err := applyEdits(body, m.Edits)
				if err != nil {
					return fmt.Errorf("mutation %s: %w", m.DefectID, err)
				}
				body = mutated
			}
			if err := os.WriteFile(filepath.Join(dir, m.Module+"."+suffix), []byte(body), 0o644); err != nil {
				return fmt.Errorf("write mutant %s: %w", m.DefectID, err)
			}
		}
		mutantPath := filepath.Join(*out, "tlc-mutant-"+m.DefectID+".out")
		exitCode, err := runJava(*jar, dir, mutantPath,
			"tlc2.TLC", "-config", m.Module+".cfg", m.Module)
		if err != nil {
			return err
		}
		verdict, check := classify(mutantPath)
		outcome := "Survived"
		if verdict == "violated" {
			outcome = "Killed"
		}
		fmt.Printf("RESULT step=mutant.%s exit=%d outcome=%s check=%s expected_check=%s\n",
			m.DefectID, exitCode, outcome, check, m.ExpectedCheck)
	}

	// The shipped artifacts must be byte-identical to what was staged: a
	// mutation that leaked into the pristine copy would invalidate the clean
	// runs above.
	for _, model := range manifest.Models {
		for _, suffix := range []string{"tla", "cfg"} {
			body, err := os.ReadFile(filepath.Join(*work, model.Module+"."+suffix))
			if err != nil {
				return fmt.Errorf("re-read staged %s.%s: %w", model.Module, suffix, err)
			}
			if string(body) != staged[model.Module][suffix] {
				return fmt.Errorf("staged %s.%s changed during the run", model.Module, suffix)
			}
			fmt.Printf("DIGEST kind=pristine name=%s.%s sha256=%s\n",
				model.Module, suffix, digestBytes(body))
		}
	}

	fmt.Printf("WINDOW end=%s\n", nowUTC())
	if err := writeDigestManifest(*out); err != nil {
		return err
	}
	fmt.Printf("SUMMARY models=%d mutations=%d\n", len(manifest.Models), len(manifest.Mutations))
	return nil
}

// applyEdits performs each declared exact-string replacement and enforces its
// occurrence count. A count mismatch is fatal: an edit that matched a
// different number of places than declared is not the mutation the manifest
// describes, and running it anyway would produce evidence for a defect nobody
// specified.
func applyEdits(body string, edits []edit) (string, error) {
	for index, e := range edits {
		if e.Count < 1 {
			return "", fmt.Errorf("edit %d declares a non-positive count", index)
		}
		found := strings.Count(body, e.Find)
		if found != e.Count {
			return "", fmt.Errorf("edit %d matched %d times, manifest declares %d", index, found, e.Count)
		}
		body = strings.Replace(body, e.Find, e.Replace, e.Count)
	}
	return body, nil
}

// runJava executes one checker invocation, captures its combined output
// verbatim to logPath, and returns the process's real exit status.
func runJava(jar, dir, logPath string, args ...string) (int, error) {
	full := append([]string{"-cp", jar}, args...)
	command := exec.Command("java", full...)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if writeErr := os.WriteFile(logPath, output, 0o644); writeErr != nil {
		return 0, fmt.Errorf("write %s: %w", logPath, writeErr)
	}
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return 0, fmt.Errorf("run java %s: %w", strings.Join(args, " "), err)
}

// classify reads a TLC output file and reports what the checker actually
// said: a clean verdict, a named violation, or neither.
func classify(path string) (string, string) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "unreadable", "NONE"
	}
	text := string(body)
	if match := invariantViolation.FindStringSubmatch(text); match != nil {
		return "violated", match[1]
	}
	if match := propertyViolation.FindStringSubmatch(text); match != nil {
		return "violated", match[1]
	}
	if strings.Contains(text, cleanVerdict) {
		return "clean", "NONE"
	}
	return "indeterminate", "NONE"
}

func writeDigestManifest(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() != "out-digests.sha256" {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	var builder strings.Builder
	for _, name := range names {
		digest, err := digestFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		fmt.Fprintf(&builder, "%s  %s\n", strings.TrimPrefix(digest, "sha256:"), name)
	}
	return os.WriteFile(filepath.Join(dir, "out-digests.sha256"), []byte(builder.String()), 0o644)
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

func nowUTC() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}
