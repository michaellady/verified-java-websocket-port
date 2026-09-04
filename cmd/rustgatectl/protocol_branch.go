// US-018 AC1, third bullet: "a seeded adapter-side parser or protocol branch
// fails the architecture gate."
//
// The parser half was already enforced by forbiddenProtocolBranch (opcode and
// payload-length bitmasks, wire literals). This file adds the PROTOCOL half:
// adapter production code deciding its behaviour from the core's connection
// protocol state.
//
// F016 recorded the hole. A `match (role, state)` over `Role` and `ReadyState`
// -- both core enums, both imported by the adapter -- was seeded into
// rust/ws-testee/src/io_loop.rs and the gate reported
// verdict=PASS ... "no protocol surface or parser branch", exit 0. It passed
// because every pattern it knew was parser-shaped, and because
// forbiddenProtocolSurface is keyed on MODULE paths (`ws_core::close`) while
// `Role` and `ReadyState` reach the adapter as ROOT RE-EXPORTS
// (`use ws_core::{ReadyState, Role}`), so no module prefix ever matches.
//
// # What is detected, and what is deliberately not
//
// The forbidden thing is BRANCHING on protocol state, not TOUCHING it. The
// adapter legitimately passes a Role to the driver constructor, stores one in a
// report struct, and prints one. None of those decide anything. What the AC
// forbids is the adapter reaching a decision from the core's protocol state,
// because that is protocol logic living in networking code.
//
// So a finding requires a governed value in a DECISION POSITION:
//
//   - a match arm pattern              match (role, state) { (Role::Server, ..
//   - an `if let` / `while let` pattern  if let ReadyState::Open = s
//   - a `matches!` pattern              matches!(state, ReadyState::Closing)
//   - an equality operand              role == Role::Server, s != ReadyState::Open
//   - a governed-typed binding named in an `if`/`while`/`match`/`matches!`
//     scrutinee or condition (rule 2 below)
//
// and NOT: an argument (`connection_driver(config, Role::Client)`), an
// initializer (`let r = Role::Server;`), a struct field value, a returned
// value, or a formatting argument.
//
// # Re-derivation
//
// Today's adversarial round defeated three same-day gates with one shared
// flaw: each checked that a DECLARATION was well formed and never that its
// CLAIM was still true. Nothing here is a hand-maintained list of names:
//
//   - the governed enums and their variants are re-derived every run from the
//     ws-core sources (`pub enum` declarations plus `pub type` aliases);
//   - the names the adapter can reach them by are re-derived every run from the
//     adapter's own `use` trees, so root re-exports, `as` aliases, variant
//     imports and globs are all resolved rather than guessed;
//   - each declared allowance is re-matched every run against a fingerprint
//     recomputed from the current source, and an allowance whose site is gone
//     fails as STALE_PROTOCOL_BRANCH_ALLOWANCE.
//
// An empty derived vocabulary FAILS CLOSED: a detector that has quietly
// stopped seeing any protocol type is indistinguishable from a clean tree, and
// that is exactly the failure F016 recorded.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// --- token scanner ----------------------------------------------------------

// rustToken is one lexical token of comment-stripped Rust: an identifier, a
// literal, or a punctuator. Multi-character punctuators are kept whole so that
// `==` is never read as two `=`.
type rustToken struct {
	Text string
	Line int
}

var multiCharPunct = []string{
	"...", "..=", "<<=", ">>=",
	"::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", "..",
	"+=", "-=", "*=", "/=", "%=", "^=", "&=", "|=", "<<", ">>",
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// tokenizeRust turns comment-stripped Rust into tokens. String and character
// literals collapse to a single "\"\"" placeholder token: their CONTENT is
// already scanned by the wire-literal rules, and keeping it here would let a
// string containing "=>" invent match arms that do not exist.
func tokenizeRust(source string) []rustToken {
	var tokens []rustToken
	line := 1
	i, n := 0, len(source)
	for i < n {
		c := source[i]
		if c == '\n' {
			line++
			i++
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' {
			i++
			continue
		}
		if c == '"' {
			end := scanStringLiteral(source, i)
			line += strings.Count(source[i:end], "\n")
			tokens = append(tokens, rustToken{Text: `""`, Line: line})
			i = end
			continue
		}
		if c == 'r' && i+1 < n && (source[i+1] == '"' || source[i+1] == '#') {
			if end, ok := scanRawString(source, i); ok {
				line += strings.Count(source[i:end], "\n")
				tokens = append(tokens, rustToken{Text: `""`, Line: line})
				i = end
				continue
			}
		}
		if isIdentStart(c) {
			start := i
			for i < n && isIdentPart(source[i]) {
				i++
			}
			tokens = append(tokens, rustToken{Text: source[start:i], Line: line})
			continue
		}
		if c >= '0' && c <= '9' {
			start := i
			for i < n && (isIdentPart(source[i]) || source[i] == '.' &&
				i+1 < n && source[i+1] >= '0' && source[i+1] <= '9') {
				i++
			}
			tokens = append(tokens, rustToken{Text: source[start:i], Line: line})
			continue
		}
		matched := ""
		for _, punct := range multiCharPunct {
			if strings.HasPrefix(source[i:], punct) {
				matched = punct
				break
			}
		}
		if matched == "" {
			matched = string(c)
		}
		tokens = append(tokens, rustToken{Text: matched, Line: line})
		i += len(matched)
	}
	return tokens
}

// --- governed vocabulary, re-derived from ws-core ---------------------------

// governedEnum is one core enum whose variants encode protocol state. It is
// DERIVED from the ws-core sources on every run, never listed here: renaming
// Role, or adding a new state enum beside it, changes what this gate governs
// without anyone remembering to update a constant.
type governedEnum struct {
	Name     string
	Variants []string
	Origin   string // source path the declaration was read from
}

// seamEnum names a core enum the adapter is architecturally ENTITLED to branch
// on. The io_loop module doc states the seam: "message-level policy (echo,
// scripted sends, close initiation) is injected as an adapter policy over the
// drained events." Reacting to a drained event IS the adapter's job; deciding
// from connection state is not.
//
// This is a declaration, so it carries the same anti-rot duty as an allowance:
// checkSeamDeclarations re-derives whether the named enum still exists in
// ws-core and fails STALE_PROTOCOL_SEAM when it does not, so a seam entry
// cannot outlive the type it exempts.
type seamEnum struct {
	Name   string
	Reason string
}

var protocolSeamEnums = []seamEnum{
	{
		Name: "SemanticEventKind",
		Reason: "the drained-event seam. rust/ws-testee/src/io_loop.rs module doc: " +
			"\"message-level policy (echo, scripted sends, close initiation) is injected " +
			"as an adapter policy over the drained events\". The adapter matching a drained " +
			"event kind is the declared seam, not a protocol branch.",
	},
}

func isSeamEnum(name string) bool {
	for _, seam := range protocolSeamEnums {
		if seam.Name == name {
			return true
		}
	}
	return false
}

// deriveGovernedEnums reads the ws-core sources and returns every `pub enum`
// with its variants, minus the declared event seam. `pub type A = B;` aliases
// of a governed enum are registered under the alias name too, so the type
// alias ConnectionState = ReadyState is governed exactly like ReadyState.
func deriveGovernedEnums(coreSources map[string]string) []governedEnum {
	byName := make(map[string]governedEnum)
	paths := make([]string, 0, len(coreSources))
	for path := range coreSources {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		tokens := tokenizeRust(stripRustComments(coreSources[path]))
		for i := 0; i < len(tokens); i++ {
			if tokens[i].Text != "enum" {
				continue
			}
			if i == 0 || tokens[i-1].Text != "pub" {
				continue
			}
			if i+1 >= len(tokens) || !isIdentStart(tokens[i+1].Text[0]) {
				continue
			}
			name := tokens[i+1].Text
			open := indexOfBraceAfterGenerics(tokens, i+2)
			if open < 0 {
				continue
			}
			close := matchingDelimiter(tokens, open)
			if close < 0 {
				continue
			}
			byName[name] = governedEnum{
				Name:     name,
				Variants: enumVariants(tokens, open, close),
				Origin:   path,
			}
		}
	}
	// `pub type Alias = Existing;`
	for _, path := range paths {
		tokens := tokenizeRust(stripRustComments(coreSources[path]))
		for i := 0; i+4 < len(tokens); i++ {
			if tokens[i].Text != "pub" || tokens[i+1].Text != "type" {
				continue
			}
			alias, eq, target := tokens[i+2].Text, tokens[i+3].Text, tokens[i+4].Text
			if eq != "=" {
				continue
			}
			if base, ok := byName[target]; ok {
				if _, taken := byName[alias]; !taken {
					byName[alias] = governedEnum{Name: alias, Variants: base.Variants, Origin: path}
				}
			}
		}
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		if isSeamEnum(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]governedEnum, 0, len(names))
	for _, name := range names {
		out = append(out, byName[name])
	}
	return out
}

// indexOfBraceAfterGenerics finds the `{` that opens an enum body, stepping
// over a generic parameter list such as `<'a>` or `<T: Trait>`.
func indexOfBraceAfterGenerics(tokens []rustToken, from int) int {
	depth := 0
	for i := from; i < len(tokens); i++ {
		switch tokens[i].Text {
		case "<":
			depth++
		case ">":
			if depth > 0 {
				depth--
			}
		case ">>":
			depth -= 2
			if depth < 0 {
				depth = 0
			}
		case "{":
			if depth == 0 {
				return i
			}
		case ";":
			if depth == 0 {
				return -1
			}
		}
	}
	return -1
}

// enumVariants collects the variant identifiers declared at the top level of an
// enum body, skipping attributes, doc-stripped comments and any nested
// tuple/struct payloads.
func enumVariants(tokens []rustToken, open, close int) []string {
	var variants []string
	expect := true
	for i := open + 1; i < close; i++ {
		switch tokens[i].Text {
		case "#":
			// Attribute: skip the bracket group that follows.
			if i+1 < close && tokens[i+1].Text == "[" {
				if end := matchingDelimiter(tokens, i+1); end > 0 {
					i = end
				}
			}
			continue
		case "(", "{", "[":
			if end := matchingDelimiter(tokens, i); end > 0 {
				i = end
			}
			expect = false
			continue
		case ",":
			expect = true
			continue
		case "=":
			expect = false
			continue
		}
		if expect && isIdentStart(tokens[i].Text[0]) {
			variants = append(variants, tokens[i].Text)
			expect = false
		}
	}
	return variants
}

// matchingDelimiter returns the index of the delimiter closing the one at
// `open`, or -1.
func matchingDelimiter(tokens []rustToken, open int) int {
	pairs := map[string]string{"(": ")", "[": "]", "{": "}"}
	closer, ok := pairs[tokens[open].Text]
	if !ok {
		return -1
	}
	depth := 0
	for i := open; i < len(tokens); i++ {
		switch tokens[i].Text {
		case tokens[open].Text:
			depth++
		case closer:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// --- reachability: what the ADAPTER can name these enums by -----------------

// adapterVocabulary is the set of tokens that, in this one adapter file, refer
// to a governed protocol enum or one of its variants.
//
// It is re-derived per file from that file's own `use` trees, which is the
// point F016 turned on: `Role` and `ReadyState` are ROOT RE-EXPORTS
// (`pub use connection::{... ReadyState, Role}` in ws-core/src/lib.rs), so a
// rule keyed on module paths such as `ws_core::close` can never see them. What
// the adapter can branch on is exactly what the adapter can NAME, so the names
// are read off the adapter's imports instead of assumed.
type adapterVocabulary struct {
	// enumNames maps every local spelling of a governed enum (its own name, an
	// `as` alias) to the canonical enum.
	enumNames map[string]governedEnum
	// bareVariants maps an unqualified variant token (from
	// `use ws_core::ReadyState::Closing` or a `::*` glob) to its enum.
	bareVariants map[string]governedEnum
}

func newAdapterVocabulary() *adapterVocabulary {
	return &adapterVocabulary{
		enumNames:    map[string]governedEnum{},
		bareVariants: map[string]governedEnum{},
	}
}

func (v *adapterVocabulary) empty() bool {
	return len(v.enumNames) == 0 && len(v.bareVariants) == 0
}

// useLeaf is one flattened leaf of a `use` tree: the full path segments and the
// local name it binds (equal to the last segment unless renamed with `as`).
type useLeaf struct {
	path  []string
	local string
	glob  bool
}

// parseUseTrees flattens every `use` declaration in a token stream, expanding
// brace groups (`use ws_core::{A, B::C, D as E};`) and recording globs.
func parseUseTrees(tokens []rustToken) []useLeaf {
	var leaves []useLeaf
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Text != "use" {
			continue
		}
		// A `use` inside a function body is still an import; both count.
		end := i + 1
		for end < len(tokens) && tokens[end].Text != ";" {
			if tokens[end].Text == "{" {
				if close := matchingDelimiter(tokens, end); close > 0 {
					end = close
				}
			}
			end++
		}
		leaves = append(leaves, flattenUseTree(tokens, i+1, end, nil)...)
		i = end
	}
	return leaves
}

// flattenUseTree walks tokens[from:to) as a use tree rooted at `prefix`.
func flattenUseTree(tokens []rustToken, from, to int, prefix []string) []useLeaf {
	var leaves []useLeaf
	path := append([]string{}, prefix...)
	for i := from; i < to; i++ {
		text := tokens[i].Text
		switch {
		case text == "::":
			continue
		case text == "*":
			leaves = append(leaves, useLeaf{path: append([]string{}, path...), glob: true})
		case text == "{":
			close := matchingDelimiter(tokens, i)
			if close < 0 || close > to {
				close = to
			}
			// Split the group on commas at brace depth 1.
			start := i + 1
			depth := 0
			for j := i + 1; j < close; j++ {
				switch tokens[j].Text {
				case "{", "(", "[":
					depth++
				case "}", ")", "]":
					depth--
				case ",":
					if depth == 0 {
						leaves = append(leaves, flattenUseTree(tokens, start, j, path)...)
						start = j + 1
					}
				}
			}
			if start < close {
				leaves = append(leaves, flattenUseTree(tokens, start, close, path)...)
			}
			i = close
			path = append([]string{}, prefix...)
		case text == "as":
			if i+1 < to && len(path) > 0 {
				leaves = append(leaves, useLeaf{path: append([]string{}, path...), local: tokens[i+1].Text})
				i++
				path = append([]string{}, prefix...)
			}
		case isIdentStart(text[0]):
			path = append(path, text)
		}
	}
	// A tail path with no glob/alias/group binds its last segment.
	if len(path) > len(prefix) {
		hasLeaf := false
		for _, leaf := range leaves {
			if len(leaf.path) >= len(path) {
				hasLeaf = true
			}
		}
		if !hasLeaf {
			leaves = append(leaves, useLeaf{path: path, local: path[len(path)-1]})
		}
	}
	return leaves
}

// buildAdapterVocabulary resolves one adapter file's imports against the
// governed enums derived from ws-core. Both qualified use (`Role::Server`,
// `ws_core::Role::Server`) and unqualified use enabled by a variant or glob
// import are made visible.
func buildAdapterVocabulary(tokens []rustToken, governed []governedEnum) *adapterVocabulary {
	vocab := newAdapterVocabulary()
	byName := make(map[string]governedEnum, len(governed))
	for _, enum := range governed {
		byName[enum.Name] = enum
		// A governed enum is always reachable by its own name through a fully
		// qualified path (`ws_core::Role::Server`), import or not.
		vocab.enumNames[enum.Name] = enum
	}
	for _, leaf := range parseUseTrees(tokens) {
		if len(leaf.path) == 0 {
			continue
		}
		last := leaf.path[len(leaf.path)-1]
		if leaf.glob {
			// `use ws_core::ReadyState::*;` -- every variant becomes bare.
			if enum, ok := byName[last]; ok {
				for _, variant := range enum.Variants {
					vocab.bareVariants[variant] = enum
				}
			}
			continue
		}
		if enum, ok := byName[last]; ok {
			local := leaf.local
			if local == "" {
				local = last
			}
			vocab.enumNames[local] = enum
			continue
		}
		// `use ws_core::ReadyState::Closing;` (optionally `as X`).
		if len(leaf.path) >= 2 {
			if enum, ok := byName[leaf.path[len(leaf.path)-2]]; ok && enum.hasVariant(last) {
				local := leaf.local
				if local == "" {
					local = last
				}
				vocab.bareVariants[local] = enum
			}
		}
	}
	return vocab
}

func (e governedEnum) hasVariant(name string) bool {
	for _, variant := range e.Variants {
		if variant == name {
			return true
		}
	}
	return false
}

// --- decision positions -----------------------------------------------------

// tokenSpan is a half-open token range [Start, End).
type tokenSpan struct{ Start, End int }

func (s tokenSpan) contains(i int) bool { return i >= s.Start && i < s.End }

// decisionRegions returns the token ranges in which a value is DECIDING rather
// than being carried:
//
//	patterns    -- match arm patterns, `if let`/`while let` patterns, the
//	               pattern argument of `matches!`
//	conditions  -- `if`/`while` conditions, `match` and `matches!` scrutinees
//
// Everything outside them (arguments, initializers, struct field values, return
// expressions, format arguments) is a value position and is NOT a finding. That
// split is the whole design constraint: passing a Role through, storing one and
// printing one must stay legal; branching on one must not.
func decisionRegions(tokens []rustToken) (patterns, conditions []tokenSpan) {
	for i := 0; i < len(tokens); i++ {
		switch tokens[i].Text {
		case "match":
			// `match <scrutinee> { <arm> ... }`; a bare `match` that is part of
			// a path (`x.match`) cannot occur -- match is a keyword.
			open := indexOfBlockOpen(tokens, i+1)
			if open < 0 {
				continue
			}
			close := matchingDelimiter(tokens, open)
			if close < 0 {
				continue
			}
			conditions = append(conditions, tokenSpan{i + 1, open})
			patterns = append(patterns, matchArmPatterns(tokens, open, close)...)
		case "if", "while":
			if i+1 < len(tokens) && tokens[i+1].Text == "let" {
				// `if let <pattern> = <scrutinee> {`
				open := indexOfBlockOpen(tokens, i+2)
				if open < 0 {
					continue
				}
				eq := indexOfTopLevel(tokens, i+2, open, "=")
				if eq < 0 {
					patterns = append(patterns, tokenSpan{i + 2, open})
					continue
				}
				patterns = append(patterns, tokenSpan{i + 2, eq})
				conditions = append(conditions, tokenSpan{eq + 1, open})
				continue
			}
			open := indexOfBlockOpen(tokens, i+1)
			if open < 0 {
				continue
			}
			conditions = append(conditions, tokenSpan{i + 1, open})
		case "matches":
			// `matches!(<scrutinee>, <pattern>)`
			if i+2 >= len(tokens) || tokens[i+1].Text != "!" || tokens[i+2].Text != "(" {
				continue
			}
			close := matchingDelimiter(tokens, i+2)
			if close < 0 {
				continue
			}
			comma := indexOfTopLevel(tokens, i+3, close, ",")
			if comma < 0 {
				conditions = append(conditions, tokenSpan{i + 3, close})
				continue
			}
			conditions = append(conditions, tokenSpan{i + 3, comma})
			patterns = append(patterns, tokenSpan{comma + 1, close})
		}
	}
	return patterns, conditions
}

// indexOfBlockOpen finds the `{` that opens a block following a scrutinee or
// condition, ignoring braces nested inside parens/brackets and inside struct
// literals that are themselves nested.
func indexOfBlockOpen(tokens []rustToken, from int) int {
	depth := 0
	for i := from; i < len(tokens); i++ {
		switch tokens[i].Text {
		case "(", "[":
			if end := matchingDelimiter(tokens, i); end > 0 {
				i = end
			}
		case "{":
			if depth == 0 {
				return i
			}
		case ";":
			if depth == 0 {
				return -1
			}
		}
	}
	return -1
}

// indexOfTopLevel finds `text` in [from, to) at bracket depth zero.
func indexOfTopLevel(tokens []rustToken, from, to int, text string) int {
	for i := from; i < to && i < len(tokens); i++ {
		switch tokens[i].Text {
		case "(", "[", "{":
			if end := matchingDelimiter(tokens, i); end > 0 && end < to {
				i = end
				continue
			}
			return -1
		}
		if tokens[i].Text == text {
			return i
		}
	}
	return -1
}

// matchArmPatterns splits a match block into its arm PATTERN spans: each runs
// from the start of an arm to the `=>` that ends its pattern (guards included,
// because `s if s == ReadyState::Open =>` decides exactly as an arm does).
func matchArmPatterns(tokens []rustToken, open, close int) []tokenSpan {
	var spans []tokenSpan
	armStart := open + 1
	for i := open + 1; i < close; i++ {
		switch tokens[i].Text {
		case "(", "[", "{":
			if end := matchingDelimiter(tokens, i); end > 0 && end < close {
				i = end
			}
			continue
		case "=>":
			spans = append(spans, tokenSpan{armStart, i})
			// Arm body: a block, or an expression ending at a top-level comma.
			j := i + 1
			if j < close && tokens[j].Text == "{" {
				if end := matchingDelimiter(tokens, j); end > 0 && end < close {
					j = end + 1
					if j < close && tokens[j].Text == "," {
						j++
					}
					armStart = j
					i = j - 1
					continue
				}
			}
			for ; j < close; j++ {
				switch tokens[j].Text {
				case "(", "[", "{":
					if end := matchingDelimiter(tokens, j); end > 0 && end < close {
						j = end
					}
					continue
				case ",":
					armStart = j + 1
					i = j
					j = close
				}
			}
			if armStart <= i {
				armStart = close
			}
			i = armStart - 1
		}
	}
	return spans
}

// --- governed-typed bindings (rule 2) ---------------------------------------

// governedBindings collects the identifiers this file binds to a governed enum
// through an explicit type annotation: function parameters (`role: Role`),
// typed lets (`let s: ReadyState = ..`) and struct fields (`role: Role,`).
//
// Rule 2 exists because rule 1 only sees a value whose VARIANT is spelled out.
// `if state as u8 == 2` and `match role.wire_name() { "server" => .. }` decide
// from protocol state while naming no variant at all. Both name the governed
// BINDING in a condition, and that is what rule 2 catches.
func governedBindings(tokens []rustToken, vocab *adapterVocabulary) (map[string]string, map[string]bool) {
	bindings := map[string]string{}
	fields := map[string]bool{}
	structSpans := structBodySpans(tokens)
	for i := 1; i+1 < len(tokens); i++ {
		if tokens[i].Text != ":" {
			continue
		}
		name := tokens[i-1].Text
		if !isIdentStart(name[0]) || rustKeywords[name] {
			continue
		}
		// Type position: take the last path segment before a terminator.
		j := i + 1
		last := ""
		for ; j < len(tokens); j++ {
			text := tokens[j].Text
			if text == "," || text == ")" || text == ";" || text == "=" ||
				text == "{" || text == "}" {
				break
			}
			if isIdentStart(text[0]) {
				last = text
			}
		}
		if last == "" {
			continue
		}
		if enum, ok := vocab.enumNames[last]; ok {
			bindings[name] = enum.Name
			for _, span := range structSpans {
				if span.contains(i) {
					fields[name] = true
				}
			}
		}
	}
	return bindings, fields
}

// structBodySpans indexes the bodies of `struct Name { .. }` declarations, so a
// governed binding can be told apart by ORIGIN. It matters after a `.`:
// `report.role` is a governed FIELD and decides, while `driver.state()` merely
// shares its spelling with some other function's parameter.
func structBodySpans(tokens []rustToken) []tokenSpan {
	var spans []tokenSpan
	for i := 0; i+2 < len(tokens); i++ {
		if tokens[i].Text != "struct" || !isIdentStart(tokens[i+1].Text[0]) {
			continue
		}
		open := indexOfBlockOpen(tokens, i+2)
		if open < 0 {
			continue
		}
		if end := matchingDelimiter(tokens, open); end > 0 {
			spans = append(spans, tokenSpan{open, end})
			i = end
		}
	}
	return spans
}

var rustKeywords = map[string]bool{
	"if": true, "else": true, "match": true, "while": true, "for": true,
	"loop": true, "fn": true, "let": true, "mut": true, "ref": true,
	"return": true, "self": true, "Self": true, "impl": true, "struct": true,
	"enum": true, "trait": true, "use": true, "pub": true, "crate": true,
	"super": true, "as": true, "in": true, "where": true, "const": true,
	"static": true, "type": true, "mod": true, "move": true, "dyn": true,
	"unsafe": true, "extern": true, "break": true, "continue": true,
	"true": true, "false": true, "_": true,
}

// --- branch sites -----------------------------------------------------------

// protocolBranchSite is one re-derived adapter-side decision taken on core
// protocol state.
type protocolBranchSite struct {
	Path        string // adapter source, repo-relative
	Line        int
	Enclosing   string // enclosing `fn`, or "<item>" when none was found
	Rule        string // "variant-in-pattern" | "variant-in-equality" | "governed-binding-in-condition"
	Evidence    string // the exact spelling that decided
	Fingerprint string // sha256 over the enclosing item's normalized token stream

	// instance distinguishes two DIFFERENT functions that happen to normalize
	// to the same fingerprint -- a verbatim copy of a ruled function into a
	// nested module of the same file. It is the enclosing item's token offset,
	// so it is meaningful only WITHIN one run: it is never pinned and never
	// compared across versions, it only counts how many distinct functions an
	// allowance is covering. See checkProtocolBranchAllowances.
	instance int
}

// findProtocolBranchSites re-derives every adapter-side branch on core protocol
// state in one file, and reports how many `#[cfg(test)]` items it stepped over.
func findProtocolBranchSites(path, source string, governed []governedEnum) ([]protocolBranchSite, int) {
	tokens := tokenizeRust(stripRustComments(source))
	vocab := buildAdapterVocabulary(tokens, governed)
	if vocab.empty() {
		return nil, 0
	}
	patterns, conditions := decisionRegions(tokens)
	bindings, governedFields := governedBindings(tokens, vocab)
	items := enclosingItems(tokens)
	testSpans := cfgTestSpans(tokens)

	inAny := func(spans []tokenSpan, i int) bool {
		for _, span := range spans {
			if span.contains(i) {
				return true
			}
		}
		return false
	}

	var sites []protocolBranchSite
	seen := map[string]bool{}
	add := func(i int, rule, evidence string) {
		item := itemAt(items, tokens, i)
		key := fmt.Sprintf("%s|%d|%s|%s", path, tokens[i].Line, rule, evidence)
		if seen[key] {
			return
		}
		seen[key] = true
		sites = append(sites, protocolBranchSite{
			Path:        path,
			Line:        tokens[i].Line,
			Enclosing:   item.name,
			Rule:        rule,
			Evidence:    evidence,
			Fingerprint: fingerprintTokens(tokens, item.span),
			instance:    item.span.Start,
		})
	}

	for i := 0; i < len(tokens); i++ {
		text := tokens[i].Text
		if !isIdentStart(text[0]) {
			continue
		}
		if inAny(testSpans, i) {
			continue
		}
		// Rule 1: a governed VARIANT PATH in a decision position.
		enumName, variant, width := vocab.variantPathAt(tokens, i)
		if width > 0 {
			evidence := enumName + "::" + variant
			switch {
			case inAny(patterns, i):
				add(i, "variant-in-pattern", evidence)
			case isComparisonOperand(tokens, i, i+width):
				add(i, "variant-in-equality", evidence)
			case isComparisonMethodArgument(tokens, i):
				add(i, "variant-in-comparison-call", evidence)
			case inAny(conditions, i) && !insideCallArguments(tokens, i, conditions):
				// A variant named inside a condition but NOT handed to a call
				// is deciding: `if [ReadyState::Open, ..].contains(&s)`,
				// `if s > ReadyState::Open`.
				add(i, "variant-in-condition", evidence)
			}
			i += width - 1
			continue
		}
		// Rule 2: a governed-TYPED BINDING named in a condition or scrutinee.
		if enum, ok := bindings[text]; ok && inAny(conditions, i) {
			if i > 0 && tokens[i-1].Text == "::" {
				continue // a path segment, not this file's binding
			}
			if i > 0 && tokens[i-1].Text == "." {
				// After a dot, only a governed FIELD decides:
				// `if report.role.is_server()` reads protocol state, while
				// `driver.state()` is a method that merely shares a spelling
				// with some other function's parameter.
				isCall := i+1 < len(tokens) && tokens[i+1].Text == "("
				if isCall || !governedFields[text] {
					continue
				}
			}
			// Being an ARGUMENT to a call inside a condition is passing the
			// value, not deciding on it: `if server_closes_transport(role, ..)`
			// consumes a predicate's answer. Grouping parens are not calls, so
			// `if (state as u8) == 2` still decides.
			if insideCallArguments(tokens, i, conditions) {
				continue
			}
			add(i, "governed-binding-in-condition", text+": "+enum)
		}
	}
	return sites, len(testSpans)
}

// variantPathAt recognises a governed variant reference starting at token i and
// returns the canonical enum name, the variant and the token width consumed.
// It accepts `Role::Server`, an aliased `RS::Closing`, a fully qualified
// `ws_core::ReadyState::Closed`, and a bare `Closing` imported by name or glob.
func (v *adapterVocabulary) variantPathAt(tokens []rustToken, i int) (string, string, int) {
	// Qualified: <name> :: <variant>, walking back over any leading path.
	if i+2 < len(tokens) && tokens[i+1].Text == "::" {
		if enum, ok := v.enumNames[tokens[i].Text]; ok && enum.hasVariant(tokens[i+2].Text) {
			// Do not fire on the middle of a longer path (ws_core::Role::Server
			// is handled when i lands on `Role`).
			return enum.Name, tokens[i+2].Text, 3
		}
		return "", "", 0
	}
	if enum, ok := v.bareVariants[tokens[i].Text]; ok {
		// Not part of a longer path: `Closing` alone, not `X::Closing`.
		if i > 0 && (tokens[i-1].Text == "::" || tokens[i-1].Text == ".") {
			return "", "", 0
		}
		return enum.Name, tokens[i].Text, 1
	}
	return "", "", 0
}

// comparisonOperators are the operators whose operands are compared rather than
// carried. Ordering operators are included because a future core enum that
// derives Ord would otherwise be comparable without a finding.
var comparisonOperators = map[string]bool{
	"==": true, "!=": true, "<": true, ">": true, "<=": true, ">=": true,
}

// isComparisonOperand reports whether the path spanning [start, end) is an
// operand of a comparison operator.
func isComparisonOperand(tokens []rustToken, start, end int) bool {
	if start > 0 && comparisonOperators[tokens[start-1].Text] {
		return true
	}
	if end < len(tokens) && comparisonOperators[tokens[end].Text] {
		return true
	}
	return false
}

// comparisonMethods are the method spellings of the comparison operators.
// `d.state().eq(&ReadyState::Closing)` decides exactly as `d.state() ==
// ReadyState::Closing` does, and it names no operator at all: against an
// earlier draft of this gate that got a protocol branch into shipped adapter
// code at exit 0, because the variant sat in a call ARGUMENT, which every other
// rule treats as a value position.
var comparisonMethods = map[string]bool{
	"eq": true, "ne": true, "lt": true, "gt": true, "le": true, "ge": true,
	"cmp": true, "partial_cmp": true, "contains": true, "eq_ignore_ascii_case": true,
}

// isComparisonMethodArgument reports whether the token at i is an operand of a
// comparison method call -- on EITHER side. Both of these decide, and neither
// writes an operator:
//
//	d.state().eq(&ReadyState::Closing)                 // argument side
//	[ReadyState::Closing, ReadyState::Closed].contains(&d.state())  // receiver side
func isComparisonMethodArgument(tokens []rustToken, i int) bool {
	for _, group := range enclosingGroups(tokens, i) {
		// Argument side: the group is the call's argument list.
		if tokens[group.Start].Text == "(" && group.Start >= 2 {
			if prev, name := tokens[group.Start-2].Text, tokens[group.Start-1].Text; comparisonMethods[name] &&
				(prev == "." || prev == "::") {
				return true
			}
		}
		// Receiver side: the group is followed by `.method(`.
		end := group.End - 1
		if end+2 < len(tokens) && tokens[end+1].Text == "." &&
			comparisonMethods[tokens[end+2].Text] {
			return true
		}
	}
	return false
}

// enclosingGroups lists the bracket groups containing token i, innermost first,
// stopping at the enclosing statement or block.
func enclosingGroups(tokens []rustToken, i int) []tokenSpan {
	var groups []tokenSpan
	depth := map[string]int{")": 0, "]": 0}
	for j := i; j > 0; j-- {
		switch tokens[j].Text {
		case ")":
			depth[")"]++
		case "]":
			depth["]"]++
		case "(":
			if depth[")"] > 0 {
				depth[")"]--
				continue
			}
			if end := matchingDelimiter(tokens, j); end > 0 {
				groups = append(groups, tokenSpan{j, end + 1})
			}
		case "[":
			if depth["]"] > 0 {
				depth["]"]--
				continue
			}
			if end := matchingDelimiter(tokens, j); end > 0 {
				groups = append(groups, tokenSpan{j, end + 1})
			}
		case ";", "{", "}":
			return groups
		}
	}
	return groups
}

// --- enclosing item and fingerprint ----------------------------------------

type itemSpan struct {
	name string
	span tokenSpan
}

type itemIndex []itemSpan

func (idx itemIndex) at(i int) itemSpan {
	best := itemSpan{}
	for _, item := range idx {
		if item.span.contains(i) {
			if best.span.End == 0 || item.span.End-item.span.Start < best.span.End-best.span.Start {
				best = item
			}
		}
	}
	return best
}

// itemAt returns the enclosing named item, falling back to the innermost brace
// group when a site is inside no `fn` or macro at all (a branch written in a
// `macro_rules!` body, a const initializer). Without the fallback such a site
// hashed the EMPTY span -- every one of them shared the sha256 of "", so two
// different hidden branches were indistinguishable. It still FAILED, since a
// site with no allowance always does, but the fingerprint it reported was a
// constant rather than a description of the code.
func itemAt(idx itemIndex, tokens []rustToken, i int) itemSpan {
	if found := idx.at(i); found.span.End != 0 {
		return found
	}
	return itemSpan{name: "<item>", span: enclosingBraceSpan(tokens, i)}
}

// enclosingBraceSpan returns the innermost brace group containing i, or the
// whole token stream when i is at the top level.
func enclosingBraceSpan(tokens []rustToken, i int) tokenSpan {
	depth := 0
	for j := i; j >= 0; j-- {
		switch tokens[j].Text {
		case "}":
			depth++
		case "{":
			if depth > 0 {
				depth--
				continue
			}
			if end := matchingDelimiter(tokens, j); end > 0 {
				return tokenSpan{j, end + 1}
			}
		}
	}
	return tokenSpan{0, len(tokens)}
}

// enclosingItems indexes every `fn` in a token stream by name and body span, so
// a finding can be pinned to the function it lives in rather than to a line
// number. Line numbers drift; a function's normalized body does not move
// without the code moving with it.
func enclosingItems(tokens []rustToken) itemIndex {
	var items itemIndex
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i].Text == "macro_rules" && i+3 < len(tokens) &&
			tokens[i+1].Text == "!" && isIdentStart(tokens[i+2].Text[0]) {
			if open := indexOfBlockOpen(tokens, i+3); open > 0 {
				if close := matchingDelimiter(tokens, open); close > 0 {
					items = append(items, itemSpan{
						name: "macro_rules!" + tokens[i+2].Text,
						span: tokenSpan{i, close + 1},
					})
				}
			}
			continue
		}
		if tokens[i].Text != "fn" || !isIdentStart(tokens[i+1].Text[0]) {
			continue
		}
		open := indexOfBlockOpen(tokens, i+2)
		if open < 0 {
			continue
		}
		close := matchingDelimiter(tokens, open)
		if close < 0 {
			continue
		}
		items = append(items, itemSpan{name: tokens[i+1].Text, span: tokenSpan{i, close + 1}})
	}
	return items
}

// fingerprintTokens hashes the NORMALIZED token stream of a span: comments are
// already gone, whitespace and layout are gone, and string contents collapsed.
//
// This is what an allowance is pinned to. It is deliberately not a file:line --
// a line number drifts under an unrelated edit above it, and a plane
// correspondence pinned that loosely is exactly the drift this repository has
// already paid for. It is also deliberately not a raw byte hash: rustfmt must
// not invalidate an owner ruling, while ANY change to the tokens that decide --
// a variant swapped, an arm added, an operand renamed -- must.
func fingerprintTokens(tokens []rustToken, span tokenSpan) string {
	var builder strings.Builder
	for i := span.Start; i < span.End && i < len(tokens); i++ {
		builder.WriteString(tokens[i].Text)
		builder.WriteByte('\x1f')
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

// --- declared allowances ----------------------------------------------------

// allowedProtocolBranch is a DECLARED acknowledgement of one adapter-side
// protocol branch that the owner has ruled stays. It is not an explanation and
// not a coverage claim: the branch really is there.
//
// The point of declaring rather than deleting the rule is that a NEW protocol
// branch must fail on the run it appears, which it cannot do if the gate is red
// forever on a site nobody is allowed to remove.
//
// Three properties, each of which a same-day gate was defeated for lacking:
//
//  1. PINNED TO THE CODE, NOT TO A LINE. Fingerprint is the sha256 of the
//     enclosing function's normalized token stream. Edit the decision -- swap a
//     variant, add an arm, rename an operand -- and the fingerprint moves, the
//     allowance stops matching, and the site is reported as undeclared. An
//     unrelated edit ABOVE the function, or a rustfmt pass, does not move it.
//  2. CARRIES THE RULING. Reason records who decided and what they decided.
//  3. FAILS WHEN THE INSTANCE DISAPPEARS. checkProtocolBranchAllowances emits
//     STALE_PROTOCOL_BRANCH_ALLOWANCE for any entry that matched nothing this
//     run. A stale allowance is a lie about coverage: it claims the gate is
//     watching a site that no longer exists.
type allowedProtocolBranch struct {
	Path        string
	Enclosing   string
	Fingerprint string
	Reason      string
}

var protocolBranchAllowance = []allowedProtocolBranch{
	{
		Path:        "ws-testee/src/io_loop.rs",
		Enclosing:   "server_closes_transport",
		Fingerprint: "f0996c863a59ddb05c4e698016169f8abf0e6470d194cab60195fad0ada411a9",
		Reason: "OWNER RULING (F016, 2026-09-04): server_closes_transport stays where it is " +
			"and the gate is fixed instead. Which endpoint hangs up the TCP connection is " +
			"transport policy; the Sans-I/O core owns no socket and takes no position on it, " +
			"and Java's own answer lives in its I/O helper (WebSocketImpl.closeConnection) " +
			"rather than in Draft_6455. Delete this entry only if the function is deleted; " +
			"re-pin it only on a fresh ruling, because any edit to the decision moves the " +
			"fingerprint by design.",
	},
	{
		Path:        "ws-testee/src/io_loop.rs",
		Enclosing:   "drive_until_open",
		Fingerprint: "2c05c5aeae1c8921428d807f0163f30e1ad804c4d3477ff403de0c407b3e11e4",
		Reason: "NOT RULED ON. Found by this detector on its first run over the real tree, " +
			"not by the F016 probe: drive_until_open decides from ReadyState::NotYetConnected " +
			"(`if driver.state() != ReadyState::NotYetConnected { return true; }`) to know when " +
			"the handshake has completed and its message script may start. It is a readiness " +
			"poll rather than a protocol decision, which is an argument for it and not a " +
			"ruling. OWNER ACTION: rule on it as server_closes_transport was ruled on, or " +
			"replace the state comparison with a driver-side readiness predicate so the " +
			"adapter stops naming a ReadyState variant at all.",
	},
}

// An EMPTY fingerprint above means "not yet pinned" and FAILS as
// UNPINNED_PROTOCOL_BRANCH_ALLOWANCE: an unpinned allowance would match any
// future mutation of its function, which is precisely the rot this guards
// against. The current value for a site is printed by the gate itself on its
// `branch_site=... fingerprint=...` note line, so re-pinning after a ruling is
// a copy from the run that reported the site.

// checkProtocolBranchAllowances partitions re-derived sites into allowed and
// reported, and reports every allowance that matched nothing.
func checkProtocolBranchAllowances(sites []protocolBranchSite) []adapterFinding {
	var findings []adapterFinding
	matched := make([]bool, len(protocolBranchAllowance))
	instances := make([]map[int]bool, len(protocolBranchAllowance))
	for i := range instances {
		instances[i] = map[int]bool{}
	}

	for _, site := range sites {
		index := allowanceIndexFor(site)
		if index < 0 {
			findings = append(findings, adapterFinding{
				Kind: "ADAPTER_PROTOCOL_BRANCH",
				Detail: fmt.Sprintf(
					"%s:%d fn %s branches on core protocol state (%s via %s); "+
						"no declared allowance matches fingerprint %s",
					site.Path, site.Line, site.Enclosing, site.Evidence, site.Rule,
					site.Fingerprint[:16]),
			})
			continue
		}
		matched[index] = true
		instances[index][site.instance] = true
	}

	// An allowance rules on ONE instance. A byte-identical copy of a ruled
	// function -- say into a nested `mod` of the same file -- normalizes to the
	// same fingerprint under the same name and would otherwise inherit the
	// ruling silently. This attack DID get a protocol branch past an earlier
	// draft of this gate at exit 0; it is closed by re-deriving how many
	// distinct functions the allowance actually covered this run.
	for index, entry := range protocolBranchAllowance {
		if len(instances[index]) <= 1 {
			continue
		}
		findings = append(findings, adapterFinding{
			Kind: "DUPLICATE_PROTOCOL_BRANCH_ALLOWANCE",
			Detail: fmt.Sprintf(
				"allowance for %s fn %s (fingerprint %s) matched %d distinct functions; a "+
					"ruling covers one instance, and a copy of a ruled decision must be "+
					"ruled on separately rather than inheriting it",
				entry.Path, entry.Enclosing, entry.Fingerprint[:16], len(instances[index])),
		})
	}

	for index, entry := range protocolBranchAllowance {
		if matched[index] {
			continue
		}
		if entry.Fingerprint == "" {
			findings = append(findings, adapterFinding{
				Kind: "UNPINNED_PROTOCOL_BRANCH_ALLOWANCE",
				Detail: fmt.Sprintf(
					"allowance for %s fn %s declares no fingerprint; an unpinned allowance "+
						"would cover any future edit of that function",
					entry.Path, entry.Enclosing),
			})
			continue
		}
		findings = append(findings, adapterFinding{
			Kind: "STALE_PROTOCOL_BRANCH_ALLOWANCE",
			Detail: fmt.Sprintf(
				"allowance for %s fn %s (fingerprint %s) matched no branch this run: the "+
					"site was removed or changed, so the allowance now claims coverage of "+
					"something that is not there",
				entry.Path, entry.Enclosing, entry.Fingerprint[:16]),
		})
	}
	return findings
}

// allowanceIndexFor matches on path, enclosing function AND fingerprint, so an
// edited decision loses its acknowledgement instead of inheriting it.
func allowanceIndexFor(site protocolBranchSite) int {
	for index, entry := range protocolBranchAllowance {
		if entry.Fingerprint == "" {
			continue
		}
		if entry.Path == site.Path && entry.Enclosing == site.Enclosing &&
			entry.Fingerprint == site.Fingerprint {
			return index
		}
	}
	return -1
}

// checkSeamDeclarations re-derives whether each declared event-seam enum still
// exists in ws-core. A seam entry exempts a whole enum from the branch rule, so
// it must not outlive the type it names: a seam whose enum was renamed silently
// exempts nothing while still reading like coverage.
func checkSeamDeclarations(coreSources map[string]string) []adapterFinding {
	declared := map[string]bool{}
	for _, path := range sortedSourcePaths(coreSources) {
		tokens := tokenizeRust(stripRustComments(coreSources[path]))
		for i := 1; i+1 < len(tokens); i++ {
			if tokens[i].Text == "enum" && tokens[i-1].Text == "pub" {
				declared[tokens[i+1].Text] = true
			}
		}
	}
	var findings []adapterFinding
	for _, seam := range protocolSeamEnums {
		if !declared[seam.Name] {
			findings = append(findings, adapterFinding{
				Kind: "STALE_PROTOCOL_SEAM",
				Detail: fmt.Sprintf(
					"declared event-seam enum %q no longer exists in ws-core; the "+
						"declaration exempts a type that is gone", seam.Name),
			})
		}
	}
	return findings
}

func sortedSourcePaths(sources map[string]string) []string {
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// cfgTestItems counts the `#[cfg(test)]` items the last scan stepped over, so
// the gate can report the exclusion instead of applying it silently.
var cfgTestItems int

// scanProtocolBranches is the whole protocol-state half of the gate: derive the
// governed vocabulary from ws-core, re-derive every adapter-side branch site,
// then reconcile those sites against the declared allowances.
func scanProtocolBranches(adapterSources, coreSources map[string]string) ([]adapterFinding, []protocolBranchSite, []governedEnum) {
	findings := checkSeamDeclarations(coreSources)
	cfgTestItems = 0
	governed := deriveGovernedEnums(coreSources)
	if len(governed) == 0 {
		// FAIL CLOSED. A detector that derives nothing reports nothing, and a
		// silent detector is indistinguishable from a clean tree -- the exact
		// failure mode F016 recorded.
		findings = append(findings, adapterFinding{
			Kind: "PROTOCOL_VOCABULARY_EMPTY",
			Detail: "no core protocol enums were derived from ws-core; the protocol-branch " +
				"rule would pass vacuously",
		})
		return findings, nil, nil
	}

	var sites []protocolBranchSite
	for _, path := range sortedSourcePaths(adapterSources) {
		found, skipped := findProtocolBranchSites(path, adapterSources[path], governed)
		sites = append(sites, found...)
		cfgTestItems += skipped
	}
	findings = append(findings, checkProtocolBranchAllowances(sites)...)
	return findings, sites, governed
}

// insideCallArguments reports whether token i sits inside a CALL argument list
// that is itself nested within the enclosing decision region. A paren group is
// a call when the token before `(` can end a callee expression (an identifier,
// `)` or `]`); otherwise it is grouping.
func insideCallArguments(tokens []rustToken, i int, regions []tokenSpan) bool {
	start := 0
	for _, region := range regions {
		if region.contains(i) {
			start = region.Start
			break
		}
	}
	var open []int
	for j := start; j < i; j++ {
		switch tokens[j].Text {
		case "(":
			open = append(open, j)
		case ")":
			if len(open) > 0 {
				open = open[:len(open)-1]
			}
		}
	}
	for _, j := range open {
		if j == 0 {
			continue
		}
		prev := tokens[j-1].Text
		if prev == ")" || prev == "]" {
			return true
		}
		if isIdentStart(prev[0]) && !rustKeywords[prev] {
			return true
		}
	}
	return false
}

// cfgTestSpans locates every item introduced by a bare `#[cfg(test)]`
// attribute. Such an item is not compiled into the shipped adapter at all, so a
// decision inside it is not adapter production logic -- it is the polarity
// canary that PROVES the production decision behaves. The count is reported on
// the gate's note line so the exclusion is visible rather than silent, and only
// the exact attribute `#[cfg(test)]` qualifies: `#[cfg(any(test, feature=..))]`
// can reach a shipped build and stays scanned.
func cfgTestSpans(tokens []rustToken) []tokenSpan {
	var spans []tokenSpan
	for i := 0; i+4 < len(tokens); i++ {
		if tokens[i].Text != "#" || tokens[i+1].Text != "[" {
			continue
		}
		close := matchingDelimiter(tokens, i+1)
		if close < 0 {
			continue
		}
		inner := tokens[i+2 : close]
		if len(inner) != 4 || inner[0].Text != "cfg" || inner[1].Text != "(" ||
			inner[2].Text != "test" || inner[3].Text != ")" {
			continue
		}
		// The attributed item: skip any further attributes and visibility.
		j := close + 1
		for j < len(tokens) && (tokens[j].Text == "#" || tokens[j].Text == "pub") {
			if tokens[j].Text == "#" && j+1 < len(tokens) && tokens[j+1].Text == "[" {
				if end := matchingDelimiter(tokens, j+1); end > 0 {
					j = end + 1
					continue
				}
			}
			j++
			if j < len(tokens) && tokens[j].Text == "(" {
				if end := matchingDelimiter(tokens, j); end > 0 {
					j = end + 1
				}
			}
		}
		open := indexOfBlockOpen(tokens, j)
		if open < 0 {
			continue
		}
		end := matchingDelimiter(tokens, open)
		if end < 0 {
			continue
		}
		spans = append(spans, tokenSpan{i, end + 1})
	}
	return spans
}
