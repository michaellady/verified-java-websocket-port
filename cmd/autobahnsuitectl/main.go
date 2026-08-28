// Command autobahnsuitectl builds the US-019 Autobahn case manifest and
// reconciles a wstest report against it.
//
// Subcommands:
//
//	build-manifest -root DIR -out FILE
//	    Statically expand the immutable case manifest from the committed
//	    reports of BOTH modes and write it.
//
//	verify-manifest -root DIR -manifest FILE
//	    Rebuild from the same committed sources and require byte equality
//	    with the committed manifest (the immutability gate).
//
//	digest-manifest -root DIR -tree SUBTREE -out FILE
//	    Pin every byte of an evidence subtree by sha256.
//
//	reconcile -manifest FILE -index FILE [-cases DIR] [-subject S]
//	          [-require-agent NAME] [-out FILE]
//	    Count a report against the manifest in every dimension and print the
//	    ledger plus, when a subject is named, its discrimination verdict.
//
// Every exit code is meaningful: 0 success, 1 a gate failed, 2 usage.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/michaellady/verified-java-websocket-port/internal/autobahnsuite"
)

const (
	exitOK    = 0
	exitGate  = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(arguments []string) int {
	if len(arguments) == 0 {
		fmt.Fprintln(os.Stderr,
			"usage: autobahnsuitectl build-manifest|verify-manifest|reconcile [flags]")
		return exitUsage
	}
	switch arguments[0] {
	case "build-manifest":
		return buildManifest(arguments[1:], true)
	case "verify-manifest":
		return buildManifest(arguments[1:], false)
	case "reconcile":
		return reconcile(arguments[1:])
	case "digest-manifest":
		return digestManifest(arguments[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", arguments[0])
		return exitUsage
	}
}

// devSources are the committed reports the manifest is expanded from. Both
// modes are required: each numbers cases differently, and the manifest
// records both numberings.
func devSources(root string) []autobahnsuite.ReportSource {
	base := filepath.Join(root, "evidence", "autobahn", "dev-aarch64-nonauthoritative")
	return []autobahnsuite.ReportSource{
		{
			Name:      "dev-aarch64-fuzzingserver-run1",
			Role:      autobahnsuite.RoleClient,
			IndexPath: filepath.Join(base, "fuzzingserver-run1", "index.json"),
			CasesDir:  filepath.Join(base, "fuzzingserver-run1", "cases"),
		},
		{
			Name:      "dev-aarch64-fuzzingclient-run1",
			Role:      autobahnsuite.RoleServer,
			IndexPath: filepath.Join(base, "fuzzingclient-run1", "index.json"),
			CasesDir:  filepath.Join(base, "fuzzingclient-run1", "cases"),
		},
	}
}

// render produces the manifest's canonical bytes: indented JSON with a
// trailing newline, matching the repo's other generated artifacts.
func render(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// relativise rewrites source paths to be repo-relative so the manifest is
// reproducible from any checkout rather than pinned to one machine.
func relativise(root string, manifest *autobahnsuite.Manifest) {
	for index := range manifest.Sources {
		if rel, err := filepath.Rel(root, manifest.Sources[index].IndexPath); err == nil {
			manifest.Sources[index].IndexPath = rel
		}
		if rel, err := filepath.Rel(root, manifest.Sources[index].CasesDir); err == nil {
			manifest.Sources[index].CasesDir = rel
		}
	}
}

func buildManifest(arguments []string, write bool) int {
	flags := flag.NewFlagSet("build-manifest", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	out := flags.String("out", "autobahn/case-manifest.json", "manifest path")
	manifestPath := flags.String("manifest", "autobahn/case-manifest.json", "manifest to verify")
	if err := flags.Parse(arguments); err != nil {
		return exitUsage
	}
	absoluteRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "root: %v\n", err)
		return exitUsage
	}
	manifest, err := autobahnsuite.BuildManifest(devSources(absoluteRoot))
	if err != nil {
		fmt.Fprintf(os.Stderr, "build-manifest: %v\n", err)
		return exitGate
	}
	relativise(absoluteRoot, manifest)
	rendered, err := render(manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "render: %v\n", err)
		return exitGate
	}
	if write {
		target := filepath.Join(absoluteRoot, *out)
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
			return exitGate
		}
		if err := os.WriteFile(target, rendered, 0o644); err != nil { //nolint:gosec // evidence
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			return exitGate
		}
		fmt.Printf("manifest=%s cases=%d\n", *out, manifest.ExpectedCaseCount)
		return exitOK
	}
	target := filepath.Join(absoluteRoot, *manifestPath)
	committed, err := os.ReadFile(target) //nolint:gosec // repo-relative manifest
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-manifest: %v\n", err)
		return exitGate
	}
	if string(committed) != string(rendered) {
		fmt.Fprintf(os.Stderr,
			"verify-manifest: committed manifest differs from the one its sources expand to "+
				"(committed %d bytes, derived %d bytes)\n", len(committed), len(rendered))
		return exitGate
	}
	fmt.Printf("manifest=%s VERIFIED cases=%d\n", *manifestPath, manifest.ExpectedCaseCount)
	return exitOK
}

func reconcile(arguments []string) int {
	flags := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	manifestPath := flags.String("manifest", "autobahn/case-manifest.json", "manifest path")
	indexPath := flags.String("index", "", "wstest report index.json")
	casesDir := flags.String("cases", "", "directory of per-case wstest reports")
	subject := flags.String("subject", "",
		"subject-under-test|java-baseline|negative-control|planted-mutant")
	requireAgent := flags.String("require-agent", "",
		"refuse a report filed under any other agent name")
	out := flags.String("out", "", "write the ledger JSON here")
	if err := flags.Parse(arguments); err != nil {
		return exitUsage
	}
	if *indexPath == "" {
		fmt.Fprintln(os.Stderr, "reconcile: -index is required")
		return exitUsage
	}
	raw, err := os.ReadFile(*manifestPath) //nolint:gosec // operator-supplied path
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconcile: %v\n", err)
		return exitGate
	}
	var manifest autobahnsuite.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		fmt.Fprintf(os.Stderr, "reconcile: parse manifest: %v\n", err)
		return exitGate
	}
	ledger, err := autobahnsuite.Reconcile(&manifest, *indexPath, *casesDir,
		&autobahnsuite.Options{RequireAgent: *requireAgent})
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconcile: %v\n", err)
		return exitGate
	}
	for _, identity := range ledger.Identities {
		fmt.Printf("identity %s\n", identity)
	}
	fmt.Printf(
		"ledger agent=%s expected=%d selected=%d executed=%d passed=%d failed=%d "+
			"non_strict=%d informational=%d skipped=%d filtered=%d timed_out=%d missing=%d "+
			"unclassified=%d reconciles=%t strict_pass_all=%t\n",
		ledger.Agent, ledger.Expected, ledger.Selected, ledger.Executed, ledger.Passed,
		ledger.Failed, ledger.NonStrict, ledger.Informational, ledger.Skipped, ledger.Filtered,
		ledger.TimedOut, ledger.Missing, ledger.Unclassified, ledger.Reconciles,
		ledger.StrictPassAll)

	status := exitOK
	if !ledger.Reconciles {
		status = exitGate
	}
	if *subject != "" {
		verdict := autobahnsuite.Discriminate(autobahnsuite.Subject(*subject), ledger)
		fmt.Printf("verdict subject=%s as_expected=%t reason=%q\n",
			verdict.Subject, verdict.AsExpected, verdict.Reason)
		if !verdict.AsExpected {
			status = exitGate
		}
	}
	if *out != "" {
		rendered, err := render(ledger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "render: %v\n", err)
			return exitGate
		}
		if err := os.MkdirAll(filepath.Dir(*out), 0o750); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
			return exitGate
		}
		if err := os.WriteFile(*out, rendered, 0o644); err != nil { //nolint:gosec // evidence
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			return exitGate
		}
	}
	return status
}

// digestEntry is one digest-pinned evidence file, recorded repo-relative so
// the manifest is checkable from any checkout.
type digestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// digestManifestDocument pins every byte of an evidence tree.
type digestManifestDocument struct {
	SchemaVersion string        `json:"schema_version"`
	EntityType    string        `json:"entity_type"`
	Root          string        `json:"root"`
	FileCount     int           `json:"file_count"`
	TotalBytes    int64         `json:"total_bytes"`
	Files         []digestEntry `json:"files"`
}

// digestManifest walks an evidence tree and pins every file by sha256, so a
// later reader can prove the reports it is judging are the reports that were
// produced. Reused unchanged for the native x86_64 run.
func digestManifest(arguments []string) int {
	flags := flag.NewFlagSet("digest-manifest", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	tree := flags.String("tree", "", "evidence subtree to pin, repo-relative")
	out := flags.String("out", "", "manifest output path")
	if err := flags.Parse(arguments); err != nil {
		return exitUsage
	}
	if *tree == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "digest-manifest: -tree and -out are required")
		return exitUsage
	}
	absoluteRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "root: %v\n", err)
		return exitUsage
	}
	base := filepath.Join(absoluteRoot, *tree)
	document := digestManifestDocument{
		SchemaVersion: autobahnsuite.SchemaVersion,
		EntityType:    "AutobahnEvidenceDigestManifest",
		Root:          *tree,
	}
	walkErr := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(absoluteRoot, path)
		if err != nil {
			return err
		}
		// The manifest must never pin itself: its own digest cannot be
		// known before it is written.
		if relative == *out {
			return nil
		}
		raw, err := os.ReadFile(path) //nolint:gosec // repo-relative evidence path
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		document.Files = append(document.Files, digestEntry{
			Path:   relative,
			SHA256: "sha256:" + hex.EncodeToString(sum[:]),
			Bytes:  int64(len(raw)),
		})
		document.TotalBytes += int64(len(raw))
		return nil
	})
	if walkErr != nil {
		fmt.Fprintf(os.Stderr, "digest-manifest: %v\n", walkErr)
		return exitGate
	}
	sort.Slice(document.Files, func(left, right int) bool {
		return document.Files[left].Path < document.Files[right].Path
	})
	document.FileCount = len(document.Files)
	rendered, err := render(document)
	if err != nil {
		fmt.Fprintf(os.Stderr, "render: %v\n", err)
		return exitGate
	}
	target := filepath.Join(absoluteRoot, *out)
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		return exitGate
	}
	if err := os.WriteFile(target, rendered, 0o644); err != nil { //nolint:gosec // evidence
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		return exitGate
	}
	fmt.Printf("digest-manifest=%s files=%d bytes=%d\n",
		*out, document.FileCount, document.TotalBytes)
	return exitOK
}
