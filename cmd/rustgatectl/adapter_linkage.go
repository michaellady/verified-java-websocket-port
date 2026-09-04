// US-018 adapter-linkage architecture gate (AC3): the thin blocking TCP
// adapters must call the exact shipped core/driver symbols, and any seeded
// adapter-side parser or protocol branch must fail this gate.
//
// Typed-finding vocabulary and the role-scoped design are adopted with
// attribution from the Codex-plane US-018 rustgate extension (codex-import
// b7146dd/9cd886c): ADAPTER_LINKAGE_MISSING, ADAPTER_PROTOCOL_SURFACE,
// ADAPTER_PROTOCOL_BRANCH, ADAPTER_DEPENDENCY_NOT_ALLOWED. The scan is
// reimplemented on this plane: comments are stripped with a tokenizer (doc
// comments in the shipped adapter legitimately NAME core types), while
// string literals stay scannable because a WebSocket/HTTP wire literal in a
// production string is exactly the seeded-parser canary the AC forbids.
//
// Scope honesty: this is an architecture gate over the adapter crate's
// production sources (rust/ws-testee/src) and its cargo dependency edges,
// plus in-test polarity canaries. It is not a formal proof that arbitrary
// Rust cannot obscure protocol logic.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// adapterFinding is one typed architecture violation.
type adapterFinding struct {
	Kind   string
	Detail string
}

func (f adapterFinding) String() string {
	return fmt.Sprintf("%s: %s", f.Kind, f.Detail)
}

// requiredLinkageSubstrings are the shipped seams the adapter production
// sources must visibly drive: the sole driver constructor and the owner
// poll. Both must appear in stripped production code.
var requiredLinkageSubstrings = []struct{ needle, symbol string }{
	{"connection_driver(", "ws_driver::connection_driver"},
	{".poll(", "ConnectionDriver::poll"},
}

// forbiddenProtocolSurface are core protocol symbols and modules adapter
// production code must never name: naming them means protocol logic (or a
// bypass of the driver seam) moved into networking code.
var forbiddenProtocolSurface = []string{
	"ConnectionCore",
	"Draft6455",
	"FrameHeader",
	"HeaderDecode",
	"DecodedFrame",
	"FrameReject",
	"ProcessOutcome",
	"apply_mask",
	"ws_core::framing",
	"ws_core::handshake",
	"ws_core::fragment",
	"ws_core::close",
	"ws_core::control",
	"ws_core::message",
	"ws_core::queue",
}

// forbiddenProtocolBranch are parser-shaped patterns: opcode/payload-length
// bitmasks and WebSocket/HTTP wire literals. In adapter production code any
// of these is an adapter-side parser or protocol branch.
var forbiddenProtocolBranch = []string{
	"& 0x0f",
	"& 0x0F",
	"& 0x7f",
	"& 0x7F",
	"& 0x80",
	"0x0f &",
	"0x0F &",
	"0x7f &",
	"0x7F &",
	"0x80 &",
	"Sec-WebSocket",
	"HTTP/1.1",
	"101 Switching",
}

// scanAdapterSources scans adapter PRODUCTION sources (path -> contents;
// tests are exempt fixtures by design) and returns every typed finding.
func scanAdapterSources(sources map[string]string) []adapterFinding {
	var findings []adapterFinding
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	linkageSeen := make(map[string]bool, len(requiredLinkageSubstrings))
	for _, path := range paths {
		stripped := stripRustComments(sources[path])
		for _, required := range requiredLinkageSubstrings {
			if strings.Contains(stripped, required.needle) {
				linkageSeen[required.symbol] = true
			}
		}
		for _, symbol := range forbiddenProtocolSurface {
			if strings.Contains(stripped, symbol) {
				findings = append(findings, adapterFinding{
					Kind:   "ADAPTER_PROTOCOL_SURFACE",
					Detail: fmt.Sprintf("%s names forbidden protocol symbol %q", path, symbol),
				})
			}
		}
		for _, pattern := range forbiddenProtocolBranch {
			if strings.Contains(stripped, pattern) {
				findings = append(findings, adapterFinding{
					Kind:   "ADAPTER_PROTOCOL_BRANCH",
					Detail: fmt.Sprintf("%s contains parser/wire pattern %q", path, pattern),
				})
			}
		}
	}
	for _, required := range requiredLinkageSubstrings {
		if !linkageSeen[required.symbol] {
			findings = append(findings, adapterFinding{
				Kind:   "ADAPTER_LINKAGE_MISSING",
				Detail: fmt.Sprintf("no production source drives the shipped seam %s", required.symbol),
			})
		}
	}
	return findings
}

// checkAdapterEdges validates the exact dependency edges from cargo
// metadata: ws-testee depends on exactly {ws-core, ws-driver} as local path
// edges, ws-driver on exactly {ws-core}; nothing external anywhere in the
// adapter chain.
func checkAdapterEdges(pkgs []cargoPackage) []adapterFinding {
	required := map[string]map[string]bool{
		"ws-testee": {"ws-core": true, "ws-driver": true},
		"ws-driver": {"ws-core": true},
	}
	var findings []adapterFinding
	for _, name := range []string{"ws-driver", "ws-testee"} {
		pkg := findPackage(pkgs, name)
		if pkg == nil {
			findings = append(findings, adapterFinding{
				Kind:   "ADAPTER_LINKAGE_MISSING",
				Detail: fmt.Sprintf("workspace package %q is absent from cargo metadata", name),
			})
			continue
		}
		want := required[name]
		seen := make(map[string]bool, len(want))
		for _, dep := range pkg.Dependencies {
			if want[dep.Name] && dep.Path != nil && *dep.Path != "" {
				seen[dep.Name] = true
				continue
			}
			findings = append(findings, adapterFinding{
				Kind:   "ADAPTER_DEPENDENCY_NOT_ALLOWED",
				Detail: fmt.Sprintf("%s declares dependency %q outside the exact local path edges", name, dep.Name),
			})
		}
		for _, depName := range sortedKeys(want) {
			if !seen[depName] {
				findings = append(findings, adapterFinding{
					Kind:   "ADAPTER_LINKAGE_MISSING",
					Detail: fmt.Sprintf("%s is missing the required local path edge to %q", name, depName),
				})
			}
		}
	}
	return findings
}

func findPackage(pkgs []cargoPackage, name string) *cargoPackage {
	for index := range pkgs {
		if pkgs[index].Name == name {
			return &pkgs[index]
		}
	}
	return nil
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// stripRustComments removes `//` line comments (incl. doc comments) and
// nested `/* */` block comments while PRESERVING code and string-literal
// contents. String and raw-string literals are tokenized so `//` or `/*`
// inside a string never starts a comment; char literals and lifetimes are
// handled well enough for this scan (a lifetime tick is not a char open
// unless a closing tick follows within a char-sized span).
func stripRustComments(source string) string {
	var out strings.Builder
	i, n := 0, len(source)
	for i < n {
		c := source[i]
		switch {
		case c == '/' && i+1 < n && source[i+1] == '/':
			for i < n && source[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && source[i+1] == '*':
			end, ok := skipBlockComment(source, i)
			if !ok {
				return out.String()
			}
			// Preserve line structure for any diagnostics.
			out.WriteByte(' ')
			i = end
		case c == 'r' && i+1 < n && (source[i+1] == '"' || source[i+1] == '#'):
			end, ok := scanRawString(source, i)
			if !ok {
				out.WriteString(source[i:])
				return out.String()
			}
			out.WriteString(source[i:end])
			i = end
		case c == '"':
			end := scanStringLiteral(source, i)
			out.WriteString(source[i:end])
			i = end
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String()
}

// scanStringLiteral returns the index just past the closing quote of the
// plain string literal starting at the opening quote `start`.
func scanStringLiteral(source string, start int) int {
	i := start + 1
	for i < len(source) {
		switch source[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1
		default:
			i++
		}
	}
	return len(source)
}

// scanRawString returns the index just past a raw string literal starting
// at the `r` of `r"..."` / `r#"..."#` (any hash depth), or ok=false when
// the prefix is not actually a raw string (e.g. an identifier ending in r).
func scanRawString(source string, start int) (int, bool) {
	i := start + 1
	hashes := 0
	for i < len(source) && source[i] == '#' {
		hashes++
		i++
	}
	if i >= len(source) || source[i] != '"' {
		return 0, false
	}
	closer := `"` + strings.Repeat("#", hashes)
	end := strings.Index(source[i+1:], closer)
	if end < 0 {
		return 0, false
	}
	return i + 1 + end + len(closer), true
}

// gateAdapterLinkage is the live gate over the real tree: exact dependency
// edges from cargo metadata plus the production-source scan.
func (r *gateRunner) gateAdapterLinkage(meta *cargoMetadata, metaErr error) (bool, string) {
	const g = "adapter-linkage"
	if metaErr != nil {
		return false, "cargo metadata unavailable: " + metaErr.Error()
	}
	findings := checkAdapterEdges(meta.memberPackages())

	sourceDir := filepath.Join(r.rustDir, "ws-testee", "src")
	sources := make(map[string]string)
	walkErr := filepath.WalkDir(sourceDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".rs") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(r.rustDir, path)
		if relErr != nil {
			rel = path
		}
		sources[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if walkErr != nil {
		return false, fmt.Sprintf("cannot read adapter production sources: %v", walkErr)
	}
	if len(sources) == 0 {
		return false, "no adapter production sources found under rust/ws-testee/src"
	}
	findings = append(findings, scanAdapterSources(sources)...)

	// The protocol-state half of AC1's third bullet (F016). The governed
	// vocabulary is re-derived from ws-core on every run rather than listed,
	// which is also how `Role` and `ReadyState` are reached at all: they are
	// ROOT RE-EXPORTS, invisible to the module-path-keyed
	// forbiddenProtocolSurface list.
	coreSources, coreErr := readRustSources(r.rustDir, filepath.Join("ws-core", "src"))
	if coreErr != nil {
		return false, fmt.Sprintf("cannot read core sources for protocol-state derivation: %v", coreErr)
	}
	branchFindings, sites, governed := scanProtocolBranches(sources, coreSources)
	findings = append(findings, branchFindings...)

	governedNames := make([]string, 0, len(governed))
	for _, enum := range governed {
		governedNames = append(governedNames, enum.Name)
	}

	r.note(g, "production_sources=%d required_seams=%d forbidden_surface=%d forbidden_branch=%d",
		len(sources), len(requiredLinkageSubstrings), len(forbiddenProtocolSurface), len(forbiddenProtocolBranch))
	r.note(g, "core_sources=%d governed_protocol_enums=%d governed=%s seam_enums=%d branch_sites=%d declared_allowances=%d cfg_test_items_skipped=%d",
		len(coreSources), len(governed), strings.Join(governedNames, ","),
		len(protocolSeamEnums), len(sites), len(protocolBranchAllowance), cfgTestItems)
	for _, site := range sites {
		r.note(g, "branch_site=%s:%d fn=%s rule=%s evidence=%q fingerprint=%s declared=%t",
			site.Path, site.Line, site.Enclosing, site.Rule, site.Evidence,
			site.Fingerprint, allowanceIndexFor(site) >= 0)
	}
	for _, finding := range findings {
		r.note(g, "finding=%s detail=%q", finding.Kind, finding.Detail)
	}
	if len(findings) > 0 {
		return false, fmt.Sprintf("%d adapter architecture findings", len(findings))
	}
	return true, fmt.Sprintf(
		"adapter linkage exact over %d production sources; edges exact; no protocol surface "+
			"or parser branch; %d protocol-state branch site(s) over %d governed core enums, "+
			"all declared", len(sources), len(sites), len(governed))
}

// readRustSources reads every .rs file under rustDir/relative, keyed by the
// path relative to rustDir.
func readRustSources(rustDir, relative string) (map[string]string, error) {
	root := filepath.Join(rustDir, relative)
	sources := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".rs") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(rustDir, path)
		if relErr != nil {
			rel = path
		}
		sources[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no .rs sources under %s", root)
	}
	return sources, nil
}
