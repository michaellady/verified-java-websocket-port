package main

// regions.go — which part of a file is a FIXTURE.
//
// The rule binds test fixtures, not production code: a production retry loop
// with an attempt cap is a design decision, while a fixture's own liveness
// guard written as a count is the defect this tool hunts. Files under a
// crate's `tests/` directory are fixtures end to end. Files under `src/` are
// fixtures only inside a `#[cfg(test)]` module, so those modules are located
// and everything outside them is left alone.

import "strings"

type region struct{ start, end int }

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
// in masked source. A file with the attribute but no matching module body
// yields no region, which is reported by the caller rather than silently
// treated as "nothing to scan".
func cfgTestRegions(masked string) []region {
	var out []region
	needle := "#[cfg(test)]"
	from := 0
	for {
		idx := strings.Index(masked[from:], needle)
		if idx < 0 {
			return out
		}
		at := from + idx
		open, ok := nextBrace(masked, at+len(needle))
		if !ok {
			return out
		}
		end, ok := matchBrace(masked, open)
		if !ok {
			return out
		}
		out = append(out, region{start: open, end: end})
		from = end
	}
}

// nextBrace finds the first `{` after from, at paren/bracket depth zero.
func nextBrace(masked string, from int) (int, bool) {
	depth := 0
	// Deterministic domain bound; see the note on headerEnd in scan.go.
	limit := from + 400
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
