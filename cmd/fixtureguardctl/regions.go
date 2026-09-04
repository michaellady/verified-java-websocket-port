package main

// regions.go — which part of a file is a FIXTURE.
//
// The rule binds test fixtures, not production code: a production retry loop
// with an attempt cap is a design decision, while a fixture's own liveness
// guard written as a count is the defect this tool hunts. Files under a
// crate's `tests/` directory are fixtures end to end. Files under `src/` are
// fixtures only inside a `#[cfg(test)]` module, so those modules are located
// and everything outside them is left alone.

import (
	"fmt"
	"strings"
)

type region struct{ start, end int }

// braceSearchLimit is how far after a `#[cfg(test)]` the module's opening brace
// is searched for. It is a deterministic domain bound, and it is now REPORTED
// when it is hit rather than being a silent skip.
const braceSearchLimit = 400

// inRegions reports whether off falls in one of the regions. An empty region
// list means the whole file.
func inRegions(off int, regions []region) bool {
	if len(regions) == 0 {
		return true
	}
	for _, r := range regions {
		if off >= r.start && off < r.end {
			return true
		}
	}
	return false
}

// cfgTestRegions returns the byte extent of every `#[cfg(test)] mod ... { }`
// in masked source, and one GAP line for every `#[cfg(test)]` whose fixture
// code this scan does not reach.
//
// The gap list is the correction of a comment that was true of nothing. This
// function used to say a file with the attribute but no matching module body
// "is reported by the caller"; the caller did `return nil` and the file was
// dropped in silence, so a count-shaped guard passed the gate two ways. Both
// were reached by attack, not by reading:
//
//   - `#[cfg(test)] mod tests;` -- ORDINARY Rust, the fixture in its own file.
//     That file carries no `#[cfg(test)]` of its own, so it was skipped whole
//     and `files=` did not move.
//   - more than 400 bytes of attributes or comments between the attribute and
//     the module's `{`, which is nextBrace's deterministic search bound.
//
// A gap is not a violation of the liveness rule. It is a statement that the
// rule was not APPLIED where it was supposed to be, which is the thing this
// tool's honesty contract already refuses to leave unsaid.
func cfgTestRegions(masked string) ([]region, []string) {
	var out []region
	var gaps []string
	from := 0
	for {
		at, after, ok := nextCfgTestAttribute(masked, from)
		if !ok {
			return out, gaps
		}
		from = after
		if name, ok := bodylessModule(masked, from); ok {
			gaps = append(gaps, fmt.Sprintf(
				"declares `mod %s;` with no inline body: the fixture code is in %s.rs or "+
					"%s/mod.rs, which carries no #[cfg(test)] of its own and is therefore "+
					"never scanned", name, name, name))
			continue
		}
		open, ok := nextBrace(masked, after)
		if !ok {
			gaps = append(gaps, fmt.Sprintf(
				"no module body found within %d bytes of a #[cfg(test)] at offset %d, so "+
					"whatever it guards was not scanned", braceSearchLimit, at))
			continue
		}
		end, ok := matchBrace(masked, open)
		if !ok {
			gaps = append(gaps, fmt.Sprintf(
				"the #[cfg(test)] module opening at offset %d has no matching brace", open))
			continue
		}
		out = append(out, region{start: open, end: end})
		from = end
	}
}

// nextCfgTestAttribute finds the next TEST-GATING cfg attribute at or after
// `from`, returning the offset of its `#` and the offset just past its `]`.
//
// ROUND 3, ATTACKS F-R2 AND F-R3. This scan used to be
// `strings.Index(masked, "#[cfg(test)]")` -- one spelling, matched as bytes.
// Two files placed in rust/ws-core/src/, each carrying a count-shaped
// liveness guard of exactly the shape this tool exists to refuse, were both
// skipped WHOLE at exit 0 with the census line byte-identical to the clean
// tree (`files=49 loops=310 violations=0 unscanned=0`):
//
//	#[cfg(all(test, not(miri)))]   mod tests { ... }
//	#[cfg( test )]                 mod tests { ... }
//
// Worse than the H2 case round 2 closed: H2 at least produced an `unscanned=`
// gap, because the needle had matched and only the BODY was unreachable.
// Here the needle never matched, so the gap list -- which is keyed on it --
// had nothing to report, and `if len(regions) == 0 { return nil }` in the
// caller dropped the file in silence.
//
// So the attribute is recognised by what it MEANS. Any `#[cfg(...)]` whose
// predicate names the bare identifier `test` gates test-only code.
//
// CEILING, stated rather than guarded: `#[cfg(not(test))]` names `test` and
// means production, so it is excluded by name; and `#[cfg_attr(test, ...)]`
// is not a cfg gate on an item and is not recognised. Every one of the 16
// cfg-test attributes under rust/ today is the plain `#[cfg(test)]` on a
// `mod` line, so neither edge is exercised by this tree.
func nextCfgTestAttribute(masked string, from int) (int, int, bool) {
	for i := from; i < len(masked); {
		idx := strings.Index(masked[i:], "#[")
		if idx < 0 {
			return 0, 0, false
		}
		at := i + idx
		open := at + 1 // the '['
		end, ok := matchBracket(masked, open)
		if !ok {
			return 0, 0, false
		}
		body := masked[open+1 : end-1]
		if cfgPredicateGatesTest(body) {
			return at, end, true
		}
		i = at + 2
	}
	return 0, 0, false
}

// matchBracket returns the index just past the `]` matching the `[` at open.
func matchBracket(masked string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(masked); i++ {
		switch masked[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}

// cfgPredicateGatesTest reports whether an attribute body is a `cfg(...)`
// whose predicate names the bare identifier `test` outside a `not(...)`.
func cfgPredicateGatesTest(body string) bool {
	trimmed := strings.TrimSpace(body)
	if !strings.HasPrefix(trimmed, "cfg") {
		return false
	}
	rest := strings.TrimSpace(trimmed[len("cfg"):])
	if !strings.HasPrefix(rest, "(") {
		return false
	}
	// `feature = "test"` must not count, so string literals are removed
	// before the identifier search.
	var stripped strings.Builder
	inString := false
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if inString {
			if c == '\\' {
				i++
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		stripped.WriteByte(c)
	}
	predicate := stripped.String()
	if strings.Contains(strings.ReplaceAll(strings.ReplaceAll(predicate, " ", ""), "\t", ""), "not(test)") {
		return false
	}
	return containsBareIdentifier(predicate, "test")
}

// containsBareIdentifier reports whether ident appears in s delimited by
// non-identifier bytes on both sides.
func containsBareIdentifier(s, ident string) bool {
	isWord := func(c byte) bool {
		return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
	}
	for i := 0; ; {
		idx := strings.Index(s[i:], ident)
		if idx < 0 {
			return false
		}
		at := i + idx
		after := at + len(ident)
		if (at == 0 || !isWord(s[at-1])) && (after >= len(s) || !isWord(s[after])) {
			return true
		}
		i = after
	}
}

// bodylessModule reports `mod <name>;` -- a module declaration whose body is in
// another file -- starting at or after from, before any `{`.
func bodylessModule(masked string, from int) (string, bool) {
	i := from
	limit := from + braceSearchLimit
	for i < len(masked) && i < limit {
		switch {
		case masked[i] == ' ' || masked[i] == '\t' || masked[i] == '\n' || masked[i] == '\r':
			i++
		case strings.HasPrefix(masked[i:], "pub"):
			i += 3
		case masked[i] == '(' || masked[i] == ')' || masked[i] == '#' || masked[i] == '[' || masked[i] == ']':
			i++
		case strings.HasPrefix(masked[i:], "mod "):
			j := i + 4
			for j < len(masked) && (masked[j] == ' ' || masked[j] == '\t') {
				j++
			}
			start := j
			for j < len(masked) && (masked[j] == '_' || masked[j] >= 'a' && masked[j] <= 'z' ||
				masked[j] >= 'A' && masked[j] <= 'Z' || masked[j] >= '0' && masked[j] <= '9') {
				j++
			}
			name := masked[start:j]
			for j < len(masked) && (masked[j] == ' ' || masked[j] == '\t' || masked[j] == '\n') {
				j++
			}
			return name, j < len(masked) && masked[j] == ';' && name != ""
		default:
			return "", false
		}
	}
	return "", false
}

// nextBrace finds the first `{` after from, at paren/bracket depth zero.
func nextBrace(masked string, from int) (int, bool) {
	depth := 0
	// Deterministic domain bound; see the note on headerEnd in scan.go.
	limit := from + braceSearchLimit
	for i := from; i < len(masked) && i < limit; i++ {
		switch masked[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case '{':
			if depth == 0 {
				return i, true
			}
			depth++
		}
	}
	return 0, false
}
