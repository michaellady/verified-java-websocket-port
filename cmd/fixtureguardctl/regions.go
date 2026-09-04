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
	needle := "#[cfg(test)]"
	from := 0
	for {
		idx := strings.Index(masked[from:], needle)
		if idx < 0 {
			return out, gaps
		}
		at := from + idx
		from = at + len(needle)
		if name, ok := bodylessModule(masked, from); ok {
			gaps = append(gaps, fmt.Sprintf(
				"declares `mod %s;` with no inline body: the fixture code is in %s.rs or "+
					"%s/mod.rs, which carries no #[cfg(test)] of its own and is therefore "+
					"never scanned", name, name, name))
			continue
		}
		open, ok := nextBrace(masked, at+len(needle))
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
