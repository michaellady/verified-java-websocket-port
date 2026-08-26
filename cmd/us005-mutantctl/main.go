// Command us005-mutantctl stages and builds the planted US-005 Java oracle
// mutants. A mutant is a full-file source overlay under mutants/java/<id>/
// applied to a COPY of the pristine java-oracle sources; the pristine tree is
// never modified. Staging is fail-closed: an overlay must name an existing
// pristine source and must differ from it byte-wise, and every staged file's
// SHA-256 is recorded in staged-manifest.json so the built mutant jar is
// traceable to its exact planted deviation (see mutants/manifest.json).
//
// Usage:
//
//	us005-mutantctl stage --pristine java-oracle/src/main/java \
//	  --overlay mutants/java/<id> --out DIR
//	us005-mutantctl build --staged DIR --java-websocket-jar JAR \
//	  [--javac javac] [--jar jar]
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// OverlaidFile records one applied overlay with its before/after digests.
type OverlaidFile struct {
	File           string `json:"file"`
	PristineSHA256 string `json:"pristine_sha256"`
	MutantSHA256   string `json:"mutant_sha256"`
}

// StagedFile records one staged source file digest.
type StagedFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// StageManifest is the persisted record of one mutant staging.
type StageManifest struct {
	SchemaVersion string         `json:"schema_version"`
	MutantID      string         `json:"mutant_id"`
	Overlaid      []OverlaidFile `json:"overlaid"`
	Staged        []StagedFile   `json:"staged"`
}

func digestFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func javaSources(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".java") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func copyFile(source, destination string) error {
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, raw, 0o644)
}

// stage assembles out/src from the pristine sources plus the overlay and
// writes out/staged-manifest.json. It never writes into the pristine tree.
func stage(pristineDir, overlayDir, outDir string) (StageManifest, error) {
	manifest := StageManifest{
		SchemaVersion: "1.0.0",
		MutantID:      filepath.Base(filepath.Clean(overlayDir)),
	}
	pristineNames, err := javaSources(pristineDir)
	if err != nil {
		return manifest, fmt.Errorf("pristine sources: %w", err)
	}
	if len(pristineNames) == 0 {
		return manifest, fmt.Errorf("pristine directory %s contains no .java sources", pristineDir)
	}
	overlayNames, err := javaSources(overlayDir)
	if err != nil {
		return manifest, fmt.Errorf("overlay sources: %w", err)
	}
	if len(overlayNames) == 0 {
		return manifest, fmt.Errorf("overlay directory %s contains no .java sources", overlayDir)
	}
	pristineSet := map[string]bool{}
	for _, name := range pristineNames {
		pristineSet[name] = true
	}
	overlaySet := map[string]bool{}
	for _, name := range overlayNames {
		if !pristineSet[name] {
			return manifest, fmt.Errorf(
				"OVERLAY_UNKNOWN_FILE: %s does not exist in the pristine tree; "+
					"planted mutants may only modify existing sources", name)
		}
		pristineDigest, err := digestFile(filepath.Join(pristineDir, name))
		if err != nil {
			return manifest, err
		}
		mutantDigest, err := digestFile(filepath.Join(overlayDir, name))
		if err != nil {
			return manifest, err
		}
		if pristineDigest == mutantDigest {
			return manifest, fmt.Errorf(
				"OVERLAY_IDENTICAL: %s is byte-identical to the pristine source; "+
					"a planted mutant must deviate", name)
		}
		overlaySet[name] = true
		manifest.Overlaid = append(manifest.Overlaid, OverlaidFile{
			File: name, PristineSHA256: pristineDigest, MutantSHA256: mutantDigest})
	}
	stagedSrc := filepath.Join(outDir, "src")
	if err := os.MkdirAll(stagedSrc, 0o755); err != nil {
		return manifest, err
	}
	for _, name := range pristineNames {
		source := filepath.Join(pristineDir, name)
		if overlaySet[name] {
			source = filepath.Join(overlayDir, name)
		}
		destination := filepath.Join(stagedSrc, name)
		if err := copyFile(source, destination); err != nil {
			return manifest, err
		}
		digest, err := digestFile(destination)
		if err != nil {
			return manifest, err
		}
		manifest.Staged = append(manifest.Staged, StagedFile{File: name, SHA256: digest})
	}
	rendered, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return manifest, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "staged-manifest.json"),
		append(rendered, '\n'), 0o644); err != nil {
		return manifest, err
	}
	return manifest, nil
}

// build compiles a staged mutant with the java-oracle gate flags and packs
// the jar. It mirrors java-oracle/Makefile exactly (javac --release 17
// -encoding UTF-8 -Xlint:all -Werror) so a mutant that would not survive the
// oracle's own build gates cannot be planted.
func build(stagedDir, javaWebSocketJar, javacBinary, jarBinary string, stdout, stderr io.Writer) error {
	if _, err := os.Stat(javaWebSocketJar); err != nil {
		return fmt.Errorf("java-websocket jar: %w", err)
	}
	names, err := javaSources(filepath.Join(stagedDir, "src"))
	if err != nil || len(names) == 0 {
		return fmt.Errorf("staged sources unavailable in %s: %w", stagedDir, err)
	}
	classesDir := filepath.Join(stagedDir, "classes")
	if err := os.MkdirAll(classesDir, 0o755); err != nil {
		return err
	}
	arguments := []string{"--release", "17", "-encoding", "UTF-8", "-Xlint:all",
		"-Werror", "-cp", javaWebSocketJar, "-d", classesDir}
	for _, name := range names {
		arguments = append(arguments, filepath.Join(stagedDir, "src", name))
	}
	compile := exec.Command(javacBinary, arguments...)
	compile.Stdout = stdout
	compile.Stderr = stderr
	if err := compile.Run(); err != nil {
		return fmt.Errorf("javac: %w", err)
	}
	pack := exec.Command(jarBinary, "--create",
		"--file", filepath.Join(stagedDir, "java-oracle-mutant.jar"),
		"--main-class", "OracleMain", "-C", classesDir, ".")
	pack.Stdout = stdout
	pack.Stderr = stderr
	if err := pack.Run(); err != nil {
		return fmt.Errorf("jar: %w", err)
	}
	return nil
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		fmt.Fprintln(stderr, "usage: us005-mutantctl stage|build ...")
		return 2
	}
	switch arguments[0] {
	case "stage":
		flags := flag.NewFlagSet("stage", flag.ContinueOnError)
		flags.SetOutput(stderr)
		pristine := flags.String("pristine", "", "pristine java-oracle source directory")
		overlay := flags.String("overlay", "", "mutant overlay directory")
		out := flags.String("out", "", "staging output directory")
		if err := flags.Parse(arguments[1:]); err != nil ||
			*pristine == "" || *overlay == "" || *out == "" {
			fmt.Fprintln(stderr, "usage: us005-mutantctl stage --pristine DIR --overlay DIR --out DIR")
			return 2
		}
		manifest, err := stage(*pristine, *overlay, *out)
		if err != nil {
			fmt.Fprintln(stderr, "stage:", err)
			return 1
		}
		rendered, _ := json.MarshalIndent(manifest, "", "  ")
		fmt.Fprintln(stdout, string(rendered))
		return 0
	case "build":
		flags := flag.NewFlagSet("build", flag.ContinueOnError)
		flags.SetOutput(stderr)
		staged := flags.String("staged", "", "staged mutant directory (from stage)")
		runtimeJar := flags.String("java-websocket-jar", "", "pinned Java-WebSocket jar")
		javacBinary := flags.String("javac", "javac", "javac binary")
		jarBinary := flags.String("jar", "jar", "jar binary")
		if err := flags.Parse(arguments[1:]); err != nil ||
			*staged == "" || *runtimeJar == "" {
			fmt.Fprintln(stderr, "usage: us005-mutantctl build --staged DIR --java-websocket-jar JAR")
			return 2
		}
		if err := build(*staged, *runtimeJar, *javacBinary, *jarBinary, stdout, stderr); err != nil {
			fmt.Fprintln(stderr, "build:", err)
			return 1
		}
		fmt.Fprintln(stdout, "built", filepath.Join(*staged, "java-oracle-mutant.jar"))
		return 0
	default:
		fmt.Fprintln(stderr, "usage: us005-mutantctl stage|build ...")
		return 2
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
