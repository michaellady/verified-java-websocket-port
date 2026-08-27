package main

import "strings"

// tomlVisibleLines returns each manifest line with any content that lies
// inside a multiline TOML string ("""...""" or ”'...”') blanked, so
// key/section scanning can never match text TOML treats as string data
// (review 01a0446e: `description = """` followed by
// `rust-version.workspace = true` inside the string body must not satisfy a
// key check). Single-line basic/literal strings are left intact —
// stripTOMLLineComment already honors those.
func tomlVisibleLines(manifest string) []string {
	const basicDelim = `"""`
	const literalDelim = "'''"
	lines := strings.Split(manifest, "\n")
	out := make([]string, len(lines))
	state := ""
	for idx, line := range lines {
		var visible strings.Builder
		i := 0
		for i < len(line) {
			if state != "" {
				end := strings.Index(line[i:], state)
				if end < 0 {
					i = len(line)
					break
				}
				i += end + len(state)
				state = ""
				continue
			}
			if strings.HasPrefix(line[i:], basicDelim) {
				state = basicDelim
				i += len(basicDelim)
				continue
			}
			if strings.HasPrefix(line[i:], literalDelim) {
				state = literalDelim
				i += len(literalDelim)
				continue
			}
			visible.WriteByte(line[i])
			i++
		}
		out[idx] = visible.String()
	}
	return out
}
