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
//	verify-digest-manifest -root DIR -tree SUBTREE -manifest FILE
//	    Re-walk the pinned subtree and require every committed digest to
//	    still describe the bytes on disk, with no pinned file missing and no
//	    tree file unpinned. This is the digest manifest's CONSUMER: without
//	    it the manifest is a generated artifact nothing ever reads.
//
//	amended-ac3 -manifest FILE -role R -subject-index FILE -subject-cases DIR
//	    -baseline-index FILE -baseline-cases DIR -register FILE -ledger FILE
//	    The AC3 bar as the owner amended it on 2026-08-28: per-case
//	    behavior-class agreement with the pinned Java baseline, every residual
//	    difference registered with the ledger record that analyses it. Prints
//	    the literal reading too, which stays NEGATIVE on this run.
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
	case "amended-ac3":
		return amendedAC3(os.Args[2:])
	case "verify-digest-manifest":
		return verifyDigestManifest(arguments[1:])
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
	// Byte equality with a re-expansion of the SAME sources proves the
	// manifest is immutable; it proves nothing about whether those sources
	// described the suite (review 01a04961 finding 7). The independent
	// constraints are checked here, against the frozen family policy, the
	// pinned selected-case count, the suite's identity grammar and the
	// configurations the runs were launched with.
	var configs []*autobahnsuite.SuiteConfig
	for _, name := range nativeSuiteConfigs {
		config, err := autobahnsuite.ReadSuiteConfig(filepath.Join(absoluteRoot, name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "verify-manifest: %v\n", err)
			return exitGate
		}
		configs = append(configs, config)
	}
	status := exitOK
	for _, problem := range autobahnsuite.VerifyManifestIndependence(manifest, configs) {
		fmt.Fprintf(os.Stderr, "independence %s\n", problem)
		status = exitGate
	}
	if status != exitOK {
		return status
	}
	fmt.Printf("manifest=%s VERIFIED cases=%d independent-constraints=ok\n",
		*manifestPath, manifest.ExpectedCaseCount)
	return exitOK
}

// nativeSuiteConfigs are the committed wstest configurations the four legs of
// the native run were launched with.
var nativeSuiteConfigs = []string{
	"evidence/autobahn/native-x86_64-provenance/config/fuzzingclient-rust.json",
	"evidence/autobahn/native-x86_64-provenance/config/fuzzingclient-java.json",
	"evidence/autobahn/native-x86_64-provenance/config/fuzzingserver-derived.json",
}

// amendedAC3 computes the amended AC3 verdict from two runs' own reports.
//
// Every input is required. A default would arm nothing: without the baseline
// there is nothing to agree with, without the register a divergence is
// unaccounted for rather than waived, and without the ledger the register's
// analysis claim resolves to nothing.
func amendedAC3(arguments []string) int {
	flags := flag.NewFlagSet("amended-ac3", flag.ContinueOnError)
	manifestPath := flags.String("manifest", "autobahn/case-manifest.json", "manifest path")
	role := flags.String("role", "", "client|server")
	subjectIndex := flags.String("subject-index", "", "the port's wstest index.json")
	subjectCases := flags.String("subject-cases", "", "the port's per-case report directory")
	baselineIndex := flags.String("baseline-index", "", "the pinned Java baseline's index.json")
	baselineCases := flags.String("baseline-cases", "", "the baseline's per-case report directory")
	registerPath := flags.String("register", autobahnsuite.DivergenceRegisterPath,
		"committed divergence register")
	ledgerPath := flags.String("ledger", "evidence/java/behavior-delta-ledger.json",
		"behavior-delta ledger the register's entries must resolve in")
	if err := flags.Parse(arguments); err != nil {
		return exitUsage
	}
	for name, value := range map[string]string{
		"-role": *role, "-subject-index": *subjectIndex, "-subject-cases": *subjectCases,
		"-baseline-index": *baselineIndex, "-baseline-cases": *baselineCases,
	} {
		if value == "" {
			fmt.Fprintf(os.Stderr, "amended-ac3: %s is required\n", name)
			return exitUsage
		}
	}
	raw, err := os.ReadFile(*manifestPath) //nolint:gosec // operator-supplied path
	if err != nil {
		fmt.Fprintf(os.Stderr, "amended-ac3: %v\n", err)
		return exitGate
	}
	var manifest autobahnsuite.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		fmt.Fprintf(os.Stderr, "amended-ac3: parse manifest: %v\n", err)
		return exitGate
	}
	register, err := autobahnsuite.ReadDivergenceRegister(*registerPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "amended-ac3: %v\n", err)
		return exitGate
	}
	problems, err := autobahnsuite.VerifyRegisterAgainstLedger(register, *ledgerPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "amended-ac3: %v\n", err)
		return exitGate
	}
	status := exitOK
	for _, problem := range problems {
		fmt.Fprintf(os.Stderr, "register-ledger %s\n", problem)
		status = exitGate
	}
	subjectLedger, err := autobahnsuite.Reconcile(&manifest, *subjectIndex, *subjectCases, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "amended-ac3: subject: %v\n", err)
		return exitGate
	}
	baselineLedger, err := autobahnsuite.Reconcile(&manifest, *baselineIndex, *baselineCases, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "amended-ac3: baseline: %v\n", err)
		return exitGate
	}
	agreement, err := autobahnsuite.CompareToBaseline(&manifest, autobahnsuite.Role(*role),
		*subjectIndex, *baselineIndex, register)
	if err != nil {
		fmt.Fprintf(os.Stderr, "amended-ac3: %v\n", err)
		return exitGate
	}
	for _, problem := range autobahnsuite.VerifyRegisterIsExact(register, agreement) {
		fmt.Fprintf(os.Stderr, "register-exactness %s\n", problem)
		status = exitGate
	}
	for _, identity := range agreement.Identities {
		fmt.Printf("identity %s\n", identity)
	}
	for _, detail := range agreement.DivergenceDetail {
		fmt.Printf("divergence %s\n", detail)
	}
	fmt.Printf(
		"agreement role=%s subject=%s baseline=%s agree=%d subject_stricter=%d "+
			"subject_weaker=%d differ=%d unobserved=%d registered=%d unregistered=%d of %d\n",
		agreement.Role, agreement.SubjectAgent, agreement.BaselineAgent, agreement.Agree,
		agreement.SubjectStricter, agreement.SubjectWeaker, agreement.Differ,
		agreement.Unobserved, agreement.RegisteredDelta, agreement.UnregisteredDelta,
		agreement.Expected)
	// BOTH readings are printed. The amendment did not repeal the literal
	// clause; it changed which one AC3 is judged by, and a reader is owed
	// the other.
	literal := autobahnsuite.Discriminate(autobahnsuite.SubjectUnderTest, subjectLedger)
	fmt.Printf("verdict reading=literal as_expected=%t reason=%q\n",
		literal.AsExpected, literal.Reason)
	amended := autobahnsuite.DiscriminateAgainstBaseline(subjectLedger, baselineLedger, agreement)
	fmt.Printf("verdict reading=amended as_expected=%t reason=%q\n",
		amended.AsExpected, amended.Reason)
	if !amended.AsExpected {
		status = exitGate
	}
	return status
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
	// The anti-stale binding is not optional. Left to default, it is a gate
	// nobody arms: a report from any other run satisfies the command. The
	// caller must state which agent's evidence this reconciliation is FOR.
	if *requireAgent == "" {
		fmt.Fprintln(os.Stderr,
			"reconcile: -require-agent is required; without it any run's report satisfies "+
				"this command, including a stale one from another agent")
		return exitUsage
	}
	// The per-case reports are what bind the index to the run that produced
	// it. Reconciling an index alone cannot detect an index paired with
	// another run's cases, so the cases directory is required too.
	if *casesDir == "" {
		fmt.Fprintln(os.Stderr,
			"reconcile: -cases is required; the index alone cannot be bound to the run "+
				"that produced it")
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

// buildDigestManifest walks an evidence tree and pins every file by sha256.
// `selfPath` is the repo-relative path of the manifest being produced, which
// is excluded because its own digest cannot be known before it is written.
func buildDigestManifest(absoluteRoot, tree, selfPath string) (*digestManifestDocument, error) {
	base := filepath.Join(absoluteRoot, tree)
	document := &digestManifestDocument{
		SchemaVersion: autobahnsuite.SchemaVersion,
		EntityType:    "AutobahnEvidenceDigestManifest",
		Root:          tree,
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
		if relative == selfPath {
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
		return nil, walkErr
	}
	sort.Slice(document.Files, func(left, right int) bool {
		return document.Files[left].Path < document.Files[right].Path
	})
	document.FileCount = len(document.Files)
	return document, nil
}

// verifyDigestManifest re-walks the pinned tree and requires every committed
// digest to still describe the bytes on disk.
//
// Without this, the digest manifest is a large generated artifact that
// nothing ever reads: tampering with a pinned report, or deleting one,
// changes no gate outcome. This is its verification consumer.
func verifyDigestManifest(arguments []string) int {
	flags := flag.NewFlagSet("verify-digest-manifest", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	tree := flags.String("tree", "", "evidence subtree the manifest pins, repo-relative")
	manifestPath := flags.String("manifest", "", "committed digest manifest to verify")
	if err := flags.Parse(arguments); err != nil {
		return exitUsage
	}
	if *tree == "" || *manifestPath == "" {
		fmt.Fprintln(os.Stderr, "verify-digest-manifest: -tree and -manifest are required")
		return exitUsage
	}
	absoluteRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "root: %v\n", err)
		return exitUsage
	}
	raw, err := os.ReadFile(filepath.Join(absoluteRoot, *manifestPath)) //nolint:gosec // repo-relative
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-digest-manifest: %v\n", err)
		return exitGate
	}
	var committed digestManifestDocument
	if err := json.Unmarshal(raw, &committed); err != nil {
		fmt.Fprintf(os.Stderr, "verify-digest-manifest: parse: %v\n", err)
		return exitGate
	}
	observed, err := buildDigestManifest(absoluteRoot, *tree, *manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-digest-manifest: %v\n", err)
		return exitGate
	}
	observedByPath := make(map[string]digestEntry, len(observed.Files))
	for _, entry := range observed.Files {
		observedByPath[entry.Path] = entry
	}
	findings := 0
	report := func(format string, args ...any) {
		findings++
		if findings <= 20 {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}
	for _, want := range committed.Files {
		got, present := observedByPath[want.Path]
		if !present {
			report("MISSING %s: pinned by the manifest but absent from the tree", want.Path)
			continue
		}
		if got.SHA256 != want.SHA256 {
			report("TAMPERED %s: pinned %s but the tree holds %s",
				want.Path, want.SHA256, got.SHA256)
		}
		delete(observedByPath, want.Path)
	}
	for path := range observedByPath {
		report("UNPINNED %s: present in the tree but not pinned by the manifest", path)
	}
	if committed.FileCount != len(committed.Files) {
		report("file_count says %d but %d files are listed",
			committed.FileCount, len(committed.Files))
	}
	if findings > 0 {
		fmt.Fprintf(os.Stderr,
			"verify-digest-manifest: %d finding(s) against %s\n", findings, *manifestPath)
		return exitGate
	}
	fmt.Printf("digest-manifest=%s VERIFIED files=%d bytes=%d\n",
		*manifestPath, committed.FileCount, committed.TotalBytes)
	return exitOK
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
	document, walkErr := buildDigestManifest(absoluteRoot, *tree, *out)
	if walkErr != nil {
		fmt.Fprintf(os.Stderr, "digest-manifest: %v\n", walkErr)
		return exitGate
	}
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
