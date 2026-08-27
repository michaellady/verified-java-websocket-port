// rustgatectl runs the US-009 AC1 workspace gates for the rust/ cargo
// workspace: forbid(unsafe_code) enforcement, the dependency-unsafe
// inventory, MSRV declaration + build, license policy, audit probing,
// reproducible-lockfile checks, and the good/bad scaffold canary polarity
// run. It is invoked by `make -C rust ac1-gates` (part of `make -C rust
// gates`).
//
// Honesty contract: every completed external command's exit code is read
// from its process state — success and failure alike — and printed verbatim
// as a `gate=... step=... exit=N` line; a command that never produced a
// ProcessState is reported as `exit=none process_state=absent` with the
// error, never as an invented number. A gate verdict is only PASS when every
// required exit was read as zero and every mechanical assertion held. A
// check whose execution is part of the gate's claim FAILS when it cannot
// execute (an absent MSRV toolchain fails the msrv gate; absent audit tools
// fail the audit gate whenever any non-path dependency exists). Only checks
// outside the claim — the below-MSRV differential, audit-tool execution over
// an empty dependency surface — are recorded as explicit `pending=` notes,
// never silently passed.
//
// This tool claims infrastructure only. Executing these gates through the
// accepted US-007 Docker sbx workload profile before artifact promotion is a
// separate, parent-run step that this tool does not perform and does not
// claim.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	inventoryRelPath = "rust/gates/dependency-unsafe-inventory.json"
	canariesRelPath  = "rust/gates/canaries"
	// exitNotRun marks a canary step that was intentionally not executed.
	exitNotRun = -999
	// exitNoProcessState marks a command that never produced a ProcessState
	// (it never started); there is no real exit code to report.
	exitNoProcessState = -998
)

// completedExit reads the exit code from the ProcessState of EVERY completed
// command — success and failure alike — and renders it verbatim for the log
// line. A command that never produced a ProcessState (it never started) has
// no exit code to read; that absence is stated explicitly instead of
// inventing a number.
// exitDescription renders an exit for messages: a real code as "exited N",
// the no-ProcessState sentinel as its honest description — the sentinel is
// NEVER shown as an exit code (review 01a0446e: an invented "exited -998"
// could read as a legitimate nonzero failure).
func exitDescription(exit int) string {
	if exit == exitNoProcessState {
		return "never produced a process state (command did not run)"
	}
	return fmt.Sprintf("exited %d", exit)
}

func completedExit(state *os.ProcessState, runErr error) (int, string) {
	if state != nil {
		exit := state.ExitCode()
		return exit, fmt.Sprintf("exit=%d", exit)
	}
	errText := "none"
	if runErr != nil {
		errText = runErr.Error()
	}
	return exitNoProcessState, fmt.Sprintf("exit=none process_state=absent error=%q", errText)
}

// buildUnderMSRVOutcome decides the msrv gate's build-under-MSRV step given
// the resolved MSRV toolchain name ("" when not installed). Building the
// workspace under the MSRV toolchain is a hard requirement of the gate's
// claim: when the toolchain is unavailable the gate FAILS — it is never
// recorded as a passing pending note. Only the below-MSRV differential,
// which needs a toolchain this workspace deliberately does not require, may
// remain pending-recorded.
func buildUnderMSRVOutcome(msrvToolchain, msrv string, runBuild func(toolchain string) int) (bool, string) {
	if msrvToolchain == "" {
		return false, fmt.Sprintf("MSRV toolchain %s is not installed via rustup: build-under-MSRV is a hard requirement and cannot execute, so the gate FAILS rather than passing pending (rustup toolchain install %s to run it)", msrv, msrv)
	}
	if exit := runBuild(msrvToolchain); exit != 0 {
		return false, fmt.Sprintf("workspace does not build under MSRV toolchain %s (exit %d)", msrvToolchain, exit)
	}
	return true, ""
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("rustgatectl", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root (the directory containing rust/)")
	only := flags.String("gate", "", "run a single gate by name (default: all)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: rustgatectl -root <repo-root> [-gate <name>]")
		return 2
	}
	if *root == "" {
		fmt.Fprintln(stderr, "usage: rustgatectl -root <repo-root> [-gate <name>]")
		return 2
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(stderr, "cannot resolve root: %v\n", err)
		return 1
	}
	rustDir := filepath.Join(absRoot, "rust")
	if _, err := os.Stat(filepath.Join(rustDir, "Cargo.toml")); err != nil {
		fmt.Fprintf(stderr, "no rust workspace at %s: %v\n", rustDir, err)
		return 1
	}

	runner := &gateRunner{root: absRoot, rustDir: rustDir, stdout: stdout}

	// cargo metadata --locked is shared input for several gates; read its
	// exit explicitly once, up front.
	metadata, metadataErr := runner.loadMetadata()

	type gate struct {
		name string
		fn   func() (bool, string)
	}
	gates := []gate{
		{"forbid-unsafe", func() (bool, string) { return runner.gateForbidUnsafe(metadata, metadataErr) }},
		{"dependency-inventory", func() (bool, string) { return runner.gateDependencyInventory(metadata, metadataErr) }},
		{"msrv", func() (bool, string) { return runner.gateMSRV(metadata, metadataErr) }},
		{"license", func() (bool, string) { return runner.gateLicense(metadata, metadataErr) }},
		{"audit", func() (bool, string) { return runner.gateAudit(metadata, metadataErr) }},
		{"lockfile", runner.gateLockfile},
		{"canaries", runner.gateCanaries},
	}

	failures := 0
	ran := 0
	for _, g := range gates {
		if *only != "" && g.name != *only {
			continue
		}
		ran++
		passed, detail := g.fn()
		verdict := "PASS"
		if !passed {
			verdict = "FAIL"
			failures++
		}
		fmt.Fprintf(stdout, "gate=%s verdict=%s detail=%q\n", g.name, verdict, detail)
	}
	if ran == 0 {
		fmt.Fprintf(stderr, "unknown gate %q\n", *only)
		return 2
	}
	fmt.Fprintf(stdout, "ac1-gates verdict=%s gates_passed=%d/%d\n", map[bool]string{true: "PASS", false: "FAIL"}[failures == 0], ran-failures, ran)
	if failures > 0 {
		return 1
	}
	return 0
}

// --- runner plumbing --------------------------------------------------------

type gateRunner struct {
	root    string
	rustDir string
	stdout  io.Writer
}

// execStep runs one external command, reads its true exit code from the
// process state of every completed command (success and failure alike), and
// prints it verbatim; a command that never produced a ProcessState is
// reported as such explicitly. Output is echoed on non-success (or when
// echoAlways is set) so failures are diagnosable from the log.
func (r *gateRunner) execStep(gate, step, dir string, echoAlways bool, name string, args ...string) (int, string) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	exit, exitField := completedExit(cmd.ProcessState, err)
	fmt.Fprintf(r.stdout, "gate=%s step=%s cmd=%q %s\n", gate, step, name+" "+strings.Join(args, " "), exitField)
	if (exit != 0 || echoAlways) && len(out) > 0 {
		for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
			fmt.Fprintf(r.stdout, "gate=%s step=%s | %s\n", gate, step, line)
		}
	}
	return exit, string(out)
}

func (r *gateRunner) note(gate, format string, args ...any) {
	fmt.Fprintf(r.stdout, "gate=%s %s\n", gate, fmt.Sprintf(format, args...))
}

// --- cargo metadata ---------------------------------------------------------

type cargoTarget struct {
	Kind    []string `json:"kind"`
	Name    string   `json:"name"`
	SrcPath string   `json:"src_path"`
}

type cargoPackage struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Source       *string       `json:"source"`
	ManifestPath string        `json:"manifest_path"`
	Targets      []cargoTarget `json:"targets"`
}

type cargoMetadata struct {
	Packages         []cargoPackage `json:"packages"`
	WorkspaceMembers []string       `json:"workspace_members"`
}

func (r *gateRunner) loadMetadata() (*cargoMetadata, error) {
	exit, out := r.execStep("metadata", "cargo-metadata-locked", r.rustDir, false,
		"cargo", "metadata", "--format-version", "1", "--locked", "--no-deps")
	// --no-deps is NOT used for dependency discovery; re-run with deps below.
	_ = out
	if exit != 0 {
		return nil, fmt.Errorf("cargo metadata --locked --no-deps %s", exitDescription(exit))
	}
	exit, full := r.execStep("metadata", "cargo-metadata-locked-full", r.rustDir, false,
		"cargo", "metadata", "--format-version", "1", "--locked")
	if exit != 0 {
		return nil, fmt.Errorf("cargo metadata --locked %s", exitDescription(exit))
	}
	var meta cargoMetadata
	if err := json.Unmarshal([]byte(full), &meta); err != nil {
		return nil, fmt.Errorf("cargo metadata output did not parse: %v", err)
	}
	return &meta, nil
}

func (m *cargoMetadata) memberPackages() []cargoPackage {
	members := make(map[string]bool, len(m.WorkspaceMembers))
	for _, id := range m.WorkspaceMembers {
		members[id] = true
	}
	var out []cargoPackage
	for _, p := range m.Packages {
		if members[p.ID] {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type externalDependency struct {
	Name    string
	Version string
	Source  string
}

func (m *cargoMetadata) externalDependencies() []externalDependency {
	var out []externalDependency
	for _, p := range m.Packages {
		if p.Source != nil && *p.Source != "" {
			out = append(out, externalDependency{Name: p.Name, Version: p.Version, Source: *p.Source})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// --- gate 1: forbid(unsafe_code) enforcement --------------------------------

// hasForbidUnsafe reports whether the source carries a real
// `#![forbid(unsafe_code)]` inner attribute at crate-root position. This is
// a tokenizer-grade scan, not a line match: `//` line comments (including
// `//!`/`///` doc comments), nested `/* */` block comments (per Rust
// nesting), and string/raw-string literals are skipped rather than matched,
// and the attribute only counts in the crate-root prelude — before the first
// token that is not whitespace, a comment, or another inner attribute.
// Mentions inside comments, inside string or raw-string literals, inside
// nested modules, or anywhere after the first item therefore never count.
func hasForbidUnsafe(source string) bool {
	i, n := 0, len(source)
	// A shebang line (`#!` at byte 0 that does not introduce an attribute)
	// is not part of the prelude.
	if strings.HasPrefix(source, "#!") && !strings.HasPrefix(strings.TrimLeft(source[2:], " \t"), "[") {
		nl := strings.IndexByte(source, '\n')
		if nl < 0 {
			return false
		}
		i = nl + 1
	}
	for i < n {
		c := source[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '/' && i+1 < n && source[i+1] == '/':
			for i < n && source[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && source[i+1] == '*':
			end, ok := skipBlockComment(source, i)
			if !ok {
				return false // unterminated block comment: nothing real follows
			}
			i = end
		case c == '#':
			// Only an inner attribute `#![...]` may continue the prelude; an
			// outer attribute or stray `#` ends it (a crate-root inner
			// attribute after an outer attribute is not valid Rust anyway).
			j := skipSpace(source, i+1)
			if j >= n || source[j] != '!' {
				return false
			}
			j = skipSpace(source, j+1)
			if j >= n || source[j] != '[' {
				return false
			}
			body, end, ok := scanAttributeBody(source, j)
			if !ok {
				return false
			}
			if isForbidUnsafeAttribute(body) {
				return true
			}
			i = end
		default:
			// First token that is neither a comment nor an inner attribute —
			// an item (`mod`, `pub`, ...), a literal, an outer attribute.
			// The crate-root prelude is over.
			return false
		}
	}
	return false
}

// skipSpace returns the first index at or after i that is not whitespace.
func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	return i
}

// skipBlockComment consumes a (nested, per Rust) `/* */` comment starting at
// s[i] and returns the index just past it; ok is false when unterminated.
func skipBlockComment(s string, i int) (int, bool) {
	depth := 0
	n := len(s)
	for i < n {
		switch {
		case i+1 < n && s[i] == '/' && s[i+1] == '*':
			depth++
			i += 2
		case i+1 < n && s[i] == '*' && s[i+1] == '/':
			depth--
			i += 2
			if depth == 0 {
				return i, true
			}
		default:
			i++
		}
	}
	return i, false
}

// scanAttributeBody consumes a bracketed attribute body whose `[` is at
// s[open], honoring nested brackets, comments, and string/raw-string
// literals so a `]` inside a literal cannot close the attribute early. It
// returns the inner body and the index just past the closing `]`.
func scanAttributeBody(s string, open int) (string, int, bool) {
	depth := 0
	i, n := open, len(s)
	for i < n {
		switch {
		case s[i] == '[':
			depth++
			i++
		case s[i] == ']':
			depth--
			i++
			if depth == 0 {
				return s[open+1 : i-1], i, true
			}
		case s[i] == '/' && i+1 < n && s[i+1] == '/':
			for i < n && s[i] != '\n' {
				i++
			}
		case s[i] == '/' && i+1 < n && s[i+1] == '*':
			end, ok := skipBlockComment(s, i)
			if !ok {
				return "", 0, false
			}
			i = end
		case s[i] == '"':
			end, ok := skipStringLiteral(s, i)
			if !ok {
				return "", 0, false
			}
			i = end
		case s[i] == 'r' && i+1 < n && (s[i+1] == '"' || s[i+1] == '#'):
			if end, ok := skipRawStringLiteral(s, i); ok {
				i = end
			} else {
				i++ // raw identifier (r#foo) or bare `r`, not a raw string
			}
		default:
			i++
		}
	}
	return "", 0, false
}

// skipStringLiteral consumes a basic `"..."` literal (backslash escapes
// honored) starting at s[i] and returns the index just past it.
func skipStringLiteral(s string, i int) (int, bool) {
	i++ // opening quote
	for i < len(s) {
		switch s[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1, true
		default:
			i++
		}
	}
	return i, false
}

// skipRawStringLiteral consumes a raw string literal r"..." / r#"..."# (any
// hash depth) starting at the `r` at s[i]; ok is false when s[i:] is not
// actually a raw string (e.g. a raw identifier like r#foo).
func skipRawStringLiteral(s string, i int) (int, bool) {
	j := i + 1
	hashes := 0
	for j < len(s) && s[j] == '#' {
		hashes++
		j++
	}
	if j >= len(s) || s[j] != '"' {
		return 0, false
	}
	j++
	closer := `"` + strings.Repeat("#", hashes)
	end := strings.Index(s[j:], closer)
	if end < 0 {
		return len(s), false
	}
	return j + end + len(closer), true
}

// isForbidUnsafeAttribute reports whether an inner-attribute body, with
// token-irrelevant whitespace removed, is exactly forbid(unsafe_code).
func isForbidUnsafeAttribute(body string) bool {
	compact := strings.Join(strings.Fields(body), "")
	return compact == "forbid(unsafe_code)" || compact == "forbid(unsafe_code,)"
}

// scanRootsForForbid returns one violation per crate-root file that is
// unreadable or lacks the forbid attribute.
func scanRootsForForbid(rootFiles []string) []string {
	var violations []string
	for _, path := range rootFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			violations = append(violations, fmt.Sprintf("%s: unreadable crate root: %v", path, err))
			continue
		}
		if !hasForbidUnsafe(string(data)) {
			violations = append(violations, fmt.Sprintf("%s: missing #![forbid(unsafe_code)]", path))
		}
	}
	return violations
}

func (r *gateRunner) gateForbidUnsafe(meta *cargoMetadata, metaErr error) (bool, string) {
	const g = "forbid-unsafe"
	if metaErr != nil {
		return false, "cargo metadata unavailable: " + metaErr.Error()
	}
	var roots []string
	for _, pkg := range meta.memberPackages() {
		for _, target := range pkg.Targets {
			for _, kind := range target.Kind {
				if kind == "lib" || kind == "bin" {
					roots = append(roots, target.SrcPath)
				}
			}
		}
	}
	sort.Strings(roots)
	for _, root := range roots {
		r.note(g, "step=scan root=%s", root)
	}
	violations := scanRootsForForbid(roots)
	for _, v := range violations {
		r.note(g, "violation=%q", v)
	}
	if len(violations) > 0 {
		return false, fmt.Sprintf("%d of %d first-party crate roots missing #![forbid(unsafe_code)]", len(violations), len(roots))
	}
	if len(roots) == 0 {
		return false, "no first-party lib/bin crate roots found — scan surface empty, refusing to pass vacuously"
	}
	return true, fmt.Sprintf("%d first-party crate roots (lib+bin) all carry #![forbid(unsafe_code)]", len(roots))
}

// --- gate 2: dependency-unsafe inventory ------------------------------------

type inventoryEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Source      string `json:"source"`
	UnsafeUsage string `json:"unsafe_usage"`
}

type dependencyInventory struct {
	SchemaVersion        string           `json:"schema_version"`
	Story                string           `json:"story"`
	Policy               string           `json:"policy"`
	ExternalDependencies []inventoryEntry `json:"external_dependencies"`
}

// compareDependencyInventory demands a reviewed inventory entry for every
// external (non-path) dependency, and no stale entries. The reviewed
// identity is name@version@source: `source` is REQUIRED on every entry, and
// the same name/version arriving from a different source (the source-swap
// bypass) fails until a renewed reviewed entry lands.
func compareDependencyInventory(externals []externalDependency, entries []inventoryEntry) []string {
	var violations []string
	type nameVersion struct{ name, version string }
	byNameVersion := make(map[nameVersion][]inventoryEntry, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e.Source) == "" {
			violations = append(violations, fmt.Sprintf("inventory entry %s@%s lacks a source; the inventory policy requires the reviewed source to be recorded, so this entry covers nothing", e.Name, e.Version))
			continue
		}
		key := nameVersion{e.Name, e.Version}
		byNameVersion[key] = append(byNameVersion[key], e)
	}
	matched := make(map[string]bool)
	for _, dep := range externals {
		candidates := byNameVersion[nameVersion{dep.Name, dep.Version}]
		if len(candidates) == 0 {
			violations = append(violations, fmt.Sprintf("external dependency %s@%s (source %q) lacks an inventory entry with an unsafe-usage statement", dep.Name, dep.Version, dep.Source))
			continue
		}
		var covering *inventoryEntry
		for i := range candidates {
			if candidates[i].Source == dep.Source {
				covering = &candidates[i]
				break
			}
		}
		if covering == nil {
			var reviewed []string
			for _, c := range candidates {
				reviewed = append(reviewed, c.Source)
			}
			violations = append(violations, fmt.Sprintf("external dependency %s@%s comes from source %q but the inventory reviewed %s — a changed source requires a renewed reviewed entry", dep.Name, dep.Version, dep.Source, strings.Join(reviewed, ", ")))
			continue
		}
		matched[covering.Name+"@"+covering.Version+"@"+covering.Source] = true
		if strings.TrimSpace(covering.UnsafeUsage) == "" {
			violations = append(violations, fmt.Sprintf("inventory entry %s@%s (source %q) has a blank unsafe_usage statement", covering.Name, covering.Version, covering.Source))
		}
	}
	for _, list := range byNameVersion {
		for _, e := range list {
			if !matched[e.Name+"@"+e.Version+"@"+e.Source] {
				violations = append(violations, fmt.Sprintf("stale inventory entry %s@%s (source %q) matches no dependency in cargo metadata", e.Name, e.Version, e.Source))
			}
		}
	}
	sort.Strings(violations)
	return violations
}

func (r *gateRunner) gateDependencyInventory(meta *cargoMetadata, metaErr error) (bool, string) {
	const g = "dependency-inventory"
	if metaErr != nil {
		return false, "cargo metadata unavailable: " + metaErr.Error()
	}
	inventoryPath := filepath.Join(r.root, filepath.FromSlash(inventoryRelPath))
	data, err := os.ReadFile(inventoryPath)
	if err != nil {
		return false, fmt.Sprintf("inventory file missing: %v", err)
	}
	var inventory dependencyInventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		return false, fmt.Sprintf("inventory file does not parse: %v", err)
	}
	externals := meta.externalDependencies()
	for _, dep := range externals {
		r.note(g, "external=%s@%s source=%q", dep.Name, dep.Version, dep.Source)
	}
	r.note(g, "externals=%d inventory_entries=%d inventory=%s", len(externals), len(inventory.ExternalDependencies), inventoryRelPath)
	violations := compareDependencyInventory(externals, inventory.ExternalDependencies)
	for _, v := range violations {
		r.note(g, "violation=%q", v)
	}
	if len(violations) > 0 {
		return false, fmt.Sprintf("%d inventory violations", len(violations))
	}
	return true, fmt.Sprintf("workspace has %d non-path dependencies; inventory agrees (%d entries)", len(externals), len(inventory.ExternalDependencies))
}

// --- gate 3: MSRV -----------------------------------------------------------

func parseToolchainChannel(toml string) (string, error) {
	for _, raw := range strings.Split(toml, "\n") {
		line := strings.TrimSpace(raw)
		if value, ok := parseQuotedAssignment(line, "channel"); ok {
			return value, nil
		}
	}
	return "", fmt.Errorf("no channel = \"...\" line found")
}

// stripTOMLLineComment removes a trailing `# ...` comment, honoring basic
// ("...") and literal ('...') strings so a `#` inside a value survives.
func stripTOMLLineComment(line string) string {
	inBasic, inLiteral := false, false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case inBasic:
			if c == '\\' {
				i++
			} else if c == '"' {
				inBasic = false
			}
		case inLiteral:
			if c == '\'' {
				inLiteral = false
			}
		case c == '"':
			inBasic = true
		case c == '\'':
			inLiteral = true
		case c == '#':
			return line[:i]
		}
	}
	return line
}

// tomlSectionName recognizes a `[section]` / `[[section]]` header line
// (already comment-stripped and trimmed) and returns its dotted name with
// insignificant whitespace removed, so `[ package ]` and `[package]` agree.
func tomlSectionName(line string) (string, bool) {
	if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
		return "", false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
	inner = strings.TrimSuffix(strings.TrimPrefix(inner, "["), "]") // [[array-of-tables]]
	inner = strings.ReplaceAll(inner, " ", "")
	inner = strings.ReplaceAll(inner, "\t", "")
	return inner, true
}

// parseWorkspacePackageKey reads `key = "value"` from the [workspace.package]
// section only; the walk is section-aware, so the key in any other section
// (including metadata sections) never satisfies it.
func parseWorkspacePackageKey(manifest, key string) (string, error) {
	section := ""
	for _, raw := range tomlVisibleLines(manifest) {
		line := strings.TrimSpace(stripTOMLLineComment(raw))
		if name, ok := tomlSectionName(line); ok {
			section = name
			continue
		}
		if section != "workspace.package" {
			continue
		}
		if value, ok := parseQuotedAssignment(line, key); ok {
			return value, nil
		}
	}
	return "", fmt.Errorf("no %s = \"...\" in [workspace.package]", key)
}

// memberInheritsWorkspaceKey accepts, under the member's [package] section
// ONLY, `key.workspace = true`, the inline-table form, or an explicit value
// exactly equal to the workspace value. The walk is section-aware: the same
// key under [package.metadata.*] or any other section is a decoy and never
// satisfies the check.
func memberInheritsWorkspaceKey(manifest, key, workspaceValue string) bool {
	section := ""
	for _, raw := range tomlVisibleLines(manifest) {
		line := strings.TrimSpace(stripTOMLLineComment(raw))
		if name, ok := tomlSectionName(line); ok {
			section = name
			continue
		}
		if section != "package" {
			continue
		}
		compact := strings.ReplaceAll(strings.ReplaceAll(line, " ", ""), "\t", "")
		if compact == key+".workspace=true" || compact == key+"={workspace=true}" {
			return true
		}
		if value, ok := parseQuotedAssignment(line, key); ok && value == workspaceValue {
			return true
		}
	}
	return false
}

func parseQuotedAssignment(line, key string) (string, bool) {
	if !strings.HasPrefix(line, key) {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, key))
	if !strings.HasPrefix(rest, "=") {
		return "", false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
	if len(rest) < 2 || rest[0] != '"' {
		return "", false
	}
	end := strings.IndexByte(rest[1:], '"')
	if end < 0 {
		return "", false
	}
	return rest[1 : 1+end], true
}

type installedToolchain struct {
	name    string
	version string
}

// parseInstalledToolchains splits `rustup toolchain list` output into
// version-named toolchains (1.95.0-...) and symbolic ones (stable-...).
func parseInstalledToolchains(listing string) ([]installedToolchain, []string) {
	var versioned []installedToolchain
	var symbolic []string
	for _, raw := range strings.Split(listing, "\n") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if idx := strings.IndexByte(name, ' '); idx >= 0 {
			name = name[:idx] // strip "(active, default)" annotations
		}
		head := strings.SplitN(name, "-", 2)[0]
		if parts := strings.Split(head, "."); len(parts) == 3 {
			numeric := true
			for _, p := range parts {
				if _, err := strconv.Atoi(p); err != nil {
					numeric = false
					break
				}
			}
			if numeric {
				versioned = append(versioned, installedToolchain{name: name, version: head})
				continue
			}
		}
		symbolic = append(symbolic, name)
	}
	return versioned, symbolic
}

func versionOlderThan(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3 && i < len(pa) && i < len(pb); i++ {
		na, _ := strconv.Atoi(pa[i])
		nb, _ := strconv.Atoi(pb[i])
		if na != nb {
			return na < nb
		}
	}
	return false
}

// intakeQualifiedRustcVersion reads the version of the rustc-* executable pin
// from evidence/intake/toolchain-pins.json, so the MSRV cross-check anchors
// on the intake evidence rather than a constant in this tool.
func (r *gateRunner) intakeQualifiedRustcVersion() (string, error) {
	data, err := os.ReadFile(filepath.Join(r.root, "evidence", "intake", "toolchain-pins.json"))
	if err != nil {
		return "", err
	}
	var pins struct {
		Executables []struct {
			ArtifactID string `json:"artifact_id"`
			Version    string `json:"version"`
		} `json:"executables"`
	}
	if err := json.Unmarshal(data, &pins); err != nil {
		return "", err
	}
	for _, e := range pins.Executables {
		if strings.HasPrefix(e.ArtifactID, "rustc-") {
			return e.Version, nil
		}
	}
	return "", fmt.Errorf("no rustc-* executable in toolchain-pins.json")
}

func (r *gateRunner) gateMSRV(meta *cargoMetadata, metaErr error) (bool, string) {
	const g = "msrv"
	pinData, err := os.ReadFile(filepath.Join(r.rustDir, "rust-toolchain.toml"))
	if err != nil {
		return false, fmt.Sprintf("rust-toolchain.toml unreadable: %v", err)
	}
	channel, err := parseToolchainChannel(string(pinData))
	if err != nil {
		return false, fmt.Sprintf("rust-toolchain.toml: %v", err)
	}
	workspaceManifest, err := os.ReadFile(filepath.Join(r.rustDir, "Cargo.toml"))
	if err != nil {
		return false, fmt.Sprintf("workspace Cargo.toml unreadable: %v", err)
	}
	msrv, err := parseWorkspacePackageKey(string(workspaceManifest), "rust-version")
	if err != nil {
		return false, fmt.Sprintf("workspace Cargo.toml: %v", err)
	}
	intakeVersion, err := r.intakeQualifiedRustcVersion()
	if err != nil {
		return false, fmt.Sprintf("intake toolchain pin unreadable: %v", err)
	}
	r.note(g, "declared: toolchain_channel=%s workspace_rust_version=%s intake_qualified_rustc=%s", channel, msrv, intakeVersion)
	if channel != msrv || msrv != intakeVersion {
		return false, fmt.Sprintf("MSRV declarations disagree: channel=%s rust-version=%s intake=%s", channel, msrv, intakeVersion)
	}
	if metaErr != nil {
		return false, "cargo metadata unavailable: " + metaErr.Error()
	}
	for _, pkg := range meta.memberPackages() {
		manifest, err := os.ReadFile(pkg.ManifestPath)
		if err != nil {
			return false, fmt.Sprintf("member manifest %s unreadable: %v", pkg.ManifestPath, err)
		}
		if !memberInheritsWorkspaceKey(string(manifest), "rust-version", msrv) {
			return false, fmt.Sprintf("member %s does not inherit or match workspace rust-version %s", pkg.Name, msrv)
		}
		r.note(g, "member=%s rust-version=inherited-or-equal(%s)", pkg.Name, msrv)
	}

	// Probe installed toolchains: is any toolchain OLDER than the MSRV
	// available for a below-MSRV differential build?
	exit, listing := r.execStep(g, "rustup-toolchain-list", r.rustDir, true, "rustup", "toolchain", "list")
	if exit != 0 {
		return false, fmt.Sprintf("rustup toolchain list %s", exitDescription(exit))
	}
	versioned, symbolic := parseInstalledToolchains(listing)
	olderAvailable := false
	msrvToolchain := ""
	for _, tc := range versioned {
		if versionOlderThan(tc.version, msrv) {
			olderAvailable = true
		}
		if tc.version == msrv {
			msrvToolchain = tc.name
		}
	}
	for _, name := range symbolic {
		exit, out := r.execStep(g, "resolve-toolchain-"+name, r.rustDir, true, "rustup", "run", name, "rustc", "--version")
		if exit == 0 {
			fields := strings.Fields(out)
			if len(fields) >= 2 && versionOlderThan(fields[1], msrv) {
				olderAvailable = true
			}
		}
	}
	if !olderAvailable {
		r.note(g, "pending=%q", "no installed toolchain is older than the MSRV, so a below-MSRV differential build cannot execute on this host; recorded pending toolchain availability")
	}

	// The build-under-MSRV check. The MSRV equals the pinned toolchain
	// (1.95.0), so building under the pin IS the MSRV build; it runs
	// explicitly under the version-named toolchain. This is a hard
	// requirement: an absent MSRV toolchain FAILS the gate (see
	// buildUnderMSRVOutcome) — only the below-MSRV differential above may
	// remain pending-recorded.
	pass, failDetail := buildUnderMSRVOutcome(msrvToolchain, msrv, func(toolchain string) int {
		exit, _ := r.execStep(g, "cargo-check-under-msrv", r.rustDir, false,
			"rustup", "run", toolchain, "cargo", "check", "--workspace", "--all-targets", "--locked")
		return exit
	})
	if !pass {
		return false, failDetail
	}
	return true, fmt.Sprintf("declarations consistent (channel=rust-version=intake=%s); workspace builds under MSRV toolchain %s", msrv, msrvToolchain)
}

// --- gate 4: license --------------------------------------------------------

// licenseFileLooksApache2 checks for the canonical Apache-2.0 header lines.
func licenseFileLooksApache2(content string) bool {
	return strings.Contains(content, "Apache License") && strings.Contains(content, "Version 2.0")
}

func (r *gateRunner) gateLicense(meta *cargoMetadata, metaErr error) (bool, string) {
	const g = "license"
	// Policy (stated honestly): one root LICENSE file (Apache-2.0) governs
	// the repository; every first-party crate declares SPDX
	// `license = "Apache-2.0"` via workspace inheritance. Per-source-file
	// license headers are NOT required by this policy.
	r.note(g, "policy=%q", "root LICENSE (Apache-2.0) + per-crate SPDX license field via workspace inheritance; per-file headers not required")
	licenseData, err := os.ReadFile(filepath.Join(r.root, "LICENSE"))
	if err != nil {
		return false, fmt.Sprintf("root LICENSE missing: %v", err)
	}
	if !licenseFileLooksApache2(string(licenseData)) {
		return false, "root LICENSE does not carry the Apache License, Version 2.0 header"
	}
	workspaceManifest, err := os.ReadFile(filepath.Join(r.rustDir, "Cargo.toml"))
	if err != nil {
		return false, fmt.Sprintf("workspace Cargo.toml unreadable: %v", err)
	}
	license, err := parseWorkspacePackageKey(string(workspaceManifest), "license")
	if err != nil {
		return false, fmt.Sprintf("workspace Cargo.toml: %v", err)
	}
	if license != "Apache-2.0" {
		return false, fmt.Sprintf("workspace license is %q, want Apache-2.0", license)
	}
	if metaErr != nil {
		return false, "cargo metadata unavailable: " + metaErr.Error()
	}
	members := meta.memberPackages()
	for _, pkg := range members {
		manifest, err := os.ReadFile(pkg.ManifestPath)
		if err != nil {
			return false, fmt.Sprintf("member manifest %s unreadable: %v", pkg.ManifestPath, err)
		}
		if !memberInheritsWorkspaceKey(string(manifest), "license", license) {
			return false, fmt.Sprintf("member %s does not inherit or match workspace license %s", pkg.Name, license)
		}
		r.note(g, "member=%s license=inherited-or-equal(%s)", pkg.Name, license)
	}
	return true, fmt.Sprintf("root LICENSE is Apache-2.0 and all %d members declare license=Apache-2.0", len(members))
}

// --- gate 5: audit ----------------------------------------------------------

func (r *gateRunner) gateAudit(meta *cargoMetadata, metaErr error) (bool, string) {
	const g = "audit"
	if metaErr != nil {
		return false, "cargo metadata unavailable: " + metaErr.Error()
	}
	externals := meta.externalDependencies()
	r.note(g, "audit_surface: %d non-path dependencies", len(externals))

	toolsRun := 0
	for _, tool := range []struct {
		binary string
		args   []string
	}{
		{"cargo-audit", []string{"audit"}},
		{"cargo-deny", []string{"deny", "check"}},
	} {
		path, err := exec.LookPath(tool.binary)
		if err != nil {
			r.note(g, "probe=%s result=%q", tool.binary, "not found on PATH ("+err.Error()+")")
			continue
		}
		r.note(g, "probe=%s result=%q", tool.binary, path)
		exit, _ := r.execStep(g, "run-"+tool.binary, r.rustDir, false, "cargo", tool.args...)
		if exit != 0 {
			return false, fmt.Sprintf("%s %s", tool.binary, exitDescription(exit))
		}
		toolsRun++
	}

	if toolsRun == 0 {
		if len(externals) == 0 {
			r.note(g, "pending=%q", "cargo-audit and cargo-deny are not installed on this host; with zero non-path dependencies the audit surface is empty and the zero-dependency assertion is the effective check; tool execution recorded pending availability")
			return true, "zero non-path dependencies (empty audit surface); audit tools absent, execution pending availability"
		}
		return false, fmt.Sprintf("%d non-path dependencies present but no audit tool is installed to audit them", len(externals))
	}
	return true, fmt.Sprintf("%d audit tools executed cleanly over %d non-path dependencies", toolsRun, len(externals))
}

// --- gate 6: reproducible lockfile ------------------------------------------

func (r *gateRunner) gateLockfile() (bool, string) {
	const g = "lockfile"
	lockPath := filepath.Join(r.rustDir, "Cargo.lock")
	before, err := os.ReadFile(lockPath)
	if err != nil {
		return false, fmt.Sprintf("Cargo.lock missing: %v", err)
	}
	if exit, _ := r.execStep(g, "cargo-build-locked", r.rustDir, false, "cargo", "build", "--workspace", "--locked"); exit != 0 {
		return false, fmt.Sprintf("cargo build --locked %s", exitDescription(exit))
	}
	if exit, _ := r.execStep(g, "cargo-metadata-locked", r.rustDir, false, "cargo", "metadata", "--format-version", "1", "--locked"); exit != 0 {
		return false, fmt.Sprintf("cargo metadata --locked %s", exitDescription(exit))
	}
	after, err := os.ReadFile(lockPath)
	if err != nil {
		return false, fmt.Sprintf("Cargo.lock unreadable after build: %v", err)
	}
	if string(before) != string(after) {
		return false, "cargo build --locked modified Cargo.lock"
	}
	if exit, _ := r.execStep(g, "git-diff-cargo-lock", r.root, false, "git", "-C", r.root, "diff", "--exit-code", "--", "rust/Cargo.lock"); exit != 0 {
		return false, "rust/Cargo.lock differs from the committed lockfile (git diff --exit-code nonzero)"
	}
	return true, "cargo build --locked and cargo metadata --locked succeeded; Cargo.lock byte-identical and git-clean"
}

// --- gate 7: good/bad scaffold canaries --------------------------------------

type canaryResult struct {
	name       string
	scanExit   int
	clippyExit int
	testExit   int
}

// evaluateCanaryPolarity encodes the polarity contract: the good scaffold
// must pass the forbid scan, clippy -D warnings, and its tests; the bad
// scaffold (unsafe code + clippy violation + missing forbid attribute) must
// FAIL both the forbid scan and clippy. Any inversion is a gate failure.
func evaluateCanaryPolarity(good, bad canaryResult) []string {
	var violations []string
	if good.scanExit != 0 {
		violations = append(violations, fmt.Sprintf("good canary %s failed the forbid scan (exit %d)", good.name, good.scanExit))
	}
	if good.clippyExit != 0 {
		violations = append(violations, fmt.Sprintf("good canary %s failed clippy (exit %d)", good.name, good.clippyExit))
	}
	if good.testExit != 0 {
		violations = append(violations, fmt.Sprintf("good canary %s failed its tests (exit %d)", good.name, good.testExit))
	}
	if bad.scanExit == 0 {
		violations = append(violations, fmt.Sprintf("bad canary %s PASSED the forbid scan — the scan cannot detect a missing attribute", bad.name))
	}
	if bad.clippyExit == 0 {
		violations = append(violations, fmt.Sprintf("bad canary %s PASSED clippy -D warnings — the lint gate cannot detect a violation", bad.name))
	}
	// Review 01a0446e: a command that never ran (no ProcessState) is NOT a
	// detection — for either canary, on any step, it is its own violation.
	for _, probe := range []struct {
		name string
		step string
		exit int
	}{
		{good.name, "forbid scan", good.scanExit},
		{good.name, "clippy", good.clippyExit},
		{good.name, "tests", good.testExit},
		{bad.name, "forbid scan", bad.scanExit},
		{bad.name, "clippy", bad.clippyExit},
	} {
		if probe.exit == exitNoProcessState {
			violations = append(violations, fmt.Sprintf(
				"canary %s: the %s step never produced a process state — polarity cannot be judged from a command that did not run", probe.name, probe.step))
		}
	}
	return violations
}

// canaryRoots discovers the crate roots of a standalone canary crate
// (src/lib.rs, src/main.rs, src/bin/*.rs) without cargo metadata, then feeds
// them through the SAME scanRootsForForbid used for the workspace gate.
func canaryRoots(crateDir string) []string {
	var roots []string
	for _, candidate := range []string{"src/lib.rs", "src/main.rs"} {
		path := filepath.Join(crateDir, filepath.FromSlash(candidate))
		if _, err := os.Stat(path); err == nil {
			roots = append(roots, path)
		}
	}
	if bins, err := filepath.Glob(filepath.Join(crateDir, "src", "bin", "*.rs")); err == nil {
		roots = append(roots, bins...)
	}
	sort.Strings(roots)
	return roots
}

func (r *gateRunner) runCanary(name string, runTests bool) (canaryResult, error) {
	const g = "canaries"
	dir := filepath.Join(r.root, filepath.FromSlash(canariesRelPath), name)
	if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err != nil {
		return canaryResult{}, fmt.Errorf("canary crate %s missing: %v", name, err)
	}
	result := canaryResult{name: name, testExit: exitNotRun}

	roots := canaryRoots(dir)
	if len(roots) == 0 {
		return canaryResult{}, fmt.Errorf("canary crate %s has no crate roots to scan", name)
	}
	violations := scanRootsForForbid(roots)
	result.scanExit = 0
	if len(violations) > 0 {
		result.scanExit = 1
	}
	fmt.Fprintf(r.stdout, "gate=%s step=%s:forbid-scan roots=%d violations=%d exit=%d\n", g, name, len(roots), len(violations), result.scanExit)
	for _, v := range violations {
		r.note(g, "step=%s:forbid-scan violation=%q", name, v)
	}

	result.clippyExit, _ = r.execStep(g, name+":clippy", dir, false, "cargo", "clippy", "--all-targets", "--", "-D", "warnings")
	if runTests {
		result.testExit, _ = r.execStep(g, name+":test", dir, false, "cargo", "test")
	}
	return result, nil
}

func (r *gateRunner) gateCanaries() (bool, string) {
	const g = "canaries"
	good, err := r.runCanary("good-scaffold", true)
	if err != nil {
		return false, err.Error()
	}
	// The bad canary contains a deliberate clippy violation and unsafe code
	// with the forbid attribute deliberately absent; its clippy invocation is
	// EXPECTED to exit nonzero (that nonzero is the polarity proof, echoed
	// verbatim above, not an error of this gate).
	bad, err := r.runCanary("bad-scaffold", false)
	if err != nil {
		return false, err.Error()
	}
	violations := evaluateCanaryPolarity(good, bad)
	for _, v := range violations {
		r.note(g, "violation=%q", v)
	}
	if len(violations) > 0 {
		return false, fmt.Sprintf("canary polarity broken: %d violations", len(violations))
	}
	return true, fmt.Sprintf("polarity proven: good-scaffold passed scan/clippy/test (exits %d/%d/%d); bad-scaffold failed scan and clippy as required (exits %d/%d)",
		good.scanExit, good.clippyExit, good.testExit, bad.scanExit, bad.clippyExit)
}
