package main

// scan.go — the rule.
//
// THE RULE (mechanical form of the generalisation filed by F005, which is the
// third sighting of the class first filed by F002 and rediscovered by F004):
//
//	A COUNT OF OPERATIONS MAY NOT DECIDE WHETHER A FIXTURE'S LOOP KEEPS GOING.
//
// stated as two shapes, both restricted to loops that can fail to terminate
// on their own (`loop` and `while`; never `for`, which an iterator bounds):
//
//	SHAPE A — the guard is a conjunct of the loop header.
//	  `while <...> && counter < K { counter += 1; ... }`
//	  where `counter` is a plain local integer incremented UNCONDITIONALLY in
//	  the body (at the body's own brace depth, so once per iteration) and `K`
//	  is an integer literal or a SCREAMING_SNAKE constant.
//
//	SHAPE B — the guard is a bail-out inside the loop.
//	  `loop { ...; counter += 1; ...; assert!(counter < K, "...") }`
//	  `loop { ...; if counter > K { break } }`
//	  where `counter` is incremented ANYWHERE inside that same loop and `K` is
//	  as above. Only the DECIDING position is read: the first argument of
//	  `assert!`, or the condition of an `if` whose body bails out. A counter
//	  named in the assertion MESSAGE is ignored, which is exactly F005's
//	  "may only REPORT in the failure message, never decide".
//
// WHY THE TWO SHAPES DIFFER ON "UNCONDITIONAL". Shape A must separate a
// liveness guard from a GOAL: `while disposed < 20 && deadline` is a loop
// whose purpose is to reach 20 dispositions, and `disposed` is incremented
// conditionally, when progress actually happens. An unconditionally
// incremented counter counts iterations of the machine and nothing else, so
// only that shape is a guard. Shape B needs no such test: an `assert!` or a
// `break` on a count, evaluated while the loop is still running, is a guard by
// construction — nothing else uses that position.
//
// WHAT IS DELIBERATELY NOT A VIOLATION: a bound compared against a dynamic
// quantity (`while i < bytes.len()`), a config value (`max_frames(1024)`), a
// domain constant used as a loop GOAL, an assertion about the system under
// test placed AFTER the loop (`assert!(accepted <= 8)`), and a wall-clock
// deadline (`started.elapsed() < POLL_DEADLINE`), which is exempt for free
// because its left side is not a bare incremented counter.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Violation is one count-shaped liveness guard.
type Violation struct {
	File    string
	Line    int
	Shape   string // "A" or "B"
	Counter string
	Bound   string
	Loop    string // "while" or "loop"
	LoopLn  int
	Text    string
	Waived  bool
	Reason  string

	offset  int // byte offset of the deciding comparison, in masked source
	loopOff int // byte offset of the loop keyword
}

// waiverMarker is the escape hatch. It must carry a justification and it is
// counted, so a pile of them cannot grow quietly: the gate declares a ceiling.
const waiverMarker = "FIXTURE-COUNT-GUARD-ALLOWED:"

// minJustification is the shortest justification accepted after the marker.
const minJustification = 20

// waiverLookback is how many source lines above the reported line are searched
// for the marker (a multi-line `assert!` puts the comparison below its head).
const waiverLookback = 3

var (
	identRe  = `[a-z_][A-Za-z0-9_]*`
	boundRe  = `(?:[0-9][0-9_]*(?:usize|isize|u8|u16|u32|u64|u128|i8|i16|i32|i64|i128)?|(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Z][A-Z0-9_]*)`
	ltFormRe = regexp.MustCompile(`^(` + identRe + `)(?:\s*\.\s*load\s*\([^()]*\))?\s*(<|<=)\s*(` + boundRe + `)$`)
	gtFormRe = regexp.MustCompile(`^(` + boundRe + `)\s*(>|>=)\s*(` + identRe + `)(?:\s*\.\s*load\s*\([^()]*\))?$`)
	// The bail-out forms: the counter has RUN OUT.
	overLtRe = regexp.MustCompile(`^(` + identRe + `)(?:\s*\.\s*load\s*\([^()]*\))?\s*(>|>=|==)\s*(` + boundRe + `)$`)
	overGtRe = regexp.MustCompile(`^(` + boundRe + `)\s*(<|<=|==)\s*(` + identRe + `)(?:\s*\.\s*load\s*\([^()]*\))?$`)

	incRe      = regexp.MustCompile(`(?:^|[;{}\s(])(` + identRe + `)\s*\+=\s*[0-9]`)
	fetchAddRe = regexp.MustCompile(`(?:^|[;{}\s(.])(` + identRe + `)\s*\.\s*fetch_add\s*\(`)
	asCastRe   = regexp.MustCompile(`\s+as\s+[A-Za-z_][A-Za-z0-9_]*`)
	keywordRe  = regexp.MustCompile(`\b(loop|while|for)\b`)
	assertRe   = regexp.MustCompile(`\b(debug_assert|assert)\s*!\s*\(`)
	ifRe       = regexp.MustCompile(`\bif\b`)
	// A block that ABORTS: reaching it is a failure, so the condition that
	// reaches it is a liveness guard by construction.
	failBailRe = regexp.MustCompile(`(?:panic|unreachable|todo)\s*!`)
	// A block that merely LEAVES the loop: reaching it may equally well be
	// the loop's goal, so the counter shape has to decide.
	breakBailRe = regexp.MustCompile(`\bbreak\b`)
)

type loopSite struct {
	kind      string // loop | while | for
	keywordAt int
	header    string // condition text (while only)
	bodyStart int    // offset of '{'
	bodyEnd   int    // offset of matching '}'
}

// scanFile applies the rule to one Rust source file. `regions`, when
// non-empty, restricts the scan to those [start,end) byte ranges (used for
// `#[cfg(test)]` modules inside src/).
func scanFile(path, src string, regions []region) ([]Violation, int) {
	masked := maskSource(src)
	lines := strings.Split(src, "\n")
	loops := findLoops(masked)
	var out []Violation
	examined := 0
	seen := map[string]bool{}
	for _, lp := range loops {
		if !inRegions(lp.keywordAt, regions) {
			continue
		}
		examined++
		if lp.kind == "for" {
			// An iterator bounds it; it cannot fail to terminate, so it
			// cannot carry a liveness guard.
			continue
		}
		body := masked[lp.bodyStart:lp.bodyEnd]
		incAll, incTop := increments(body)
		for _, v := range shapeA(lp, incTop, masked) {
			v.File, v.Loop = path, lp.kind
			out = appendUnique(out, v, seen)
		}
		for _, v := range shapeB(lp, incAll, incTop, masked) {
			v.File, v.Loop = path, lp.kind
			out = appendUnique(out, v, seen)
		}
	}
	// SHAPE C is not a property of any loop in THIS file — it is a count this
	// fixture hands to a loop in production code (budget.go), so it is applied
	// once per file rather than once per loop.
	for _, v := range scanBudgets(masked, regions) {
		v.File, v.Loop = path, "fixture-supply"
		out = appendUnique(out, v, seen)
	}
	for i := range out {
		out[i].Line = lineOf(masked, out[i].offset)
		out[i].LoopLn = lineOf(masked, out[i].loopOff)
		out[i].Text = strings.TrimSpace(lineAt(lines, out[i].Line))
		out[i].Waived, out[i].Reason = waiverFor(lines, out[i].Line)
	}
	return out, examined
}

// Row renders one finding as the canonical, sortable form the polarity
// manifest declares and the gate compares against. Pinning the ROW rather
// than a count is what makes a deletion of any one shape visible: dropping
// shape B still leaves shape A firing, and a bare "did anything fire?" check
// would stay green through it.
func (v Violation) Row() string {
	return fmt.Sprintf("%d|%s|%s|%s|%t", v.Line, v.Shape, v.Counter, v.Bound, v.Waived)
}

// Rows renders a whole scan, sorted, for comparison against a declaration.
func Rows(vs []Violation) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Row())
	}
	sort.Strings(out)
	return out
}

func appendUnique(out []Violation, v Violation, seen map[string]bool) []Violation {
	key := fmt.Sprintf("%d|%s|%s|%s", v.offset, v.Counter, v.Bound, v.Shape)
	if seen[key] {
		return out
	}
	seen[key] = true
	return append(out, v)
}

// findLoops locates every `loop`/`while`/`for` in masked source and the extent
// of its body.
func findLoops(masked string) []loopSite {
	var out []loopSite
	for _, m := range keywordRe.FindAllStringIndex(masked, -1) {
		kw := masked[m[0]:m[1]]
		open, ok := headerEnd(masked, m[1])
		if !ok {
			continue
		}
		end, ok := matchBrace(masked, open)
		if !ok {
			continue
		}
		site := loopSite{kind: kw, keywordAt: m[0], bodyStart: open, bodyEnd: end}
		if kw == "while" {
			site.header = masked[m[1]:open]
		}
		out = append(out, site)
	}
	return out
}

// headerEnd finds the `{` that opens the loop body: the first one at paren and
// bracket depth zero. Rust forbids an unparenthesised struct literal in a loop
// header, so that `{` is unambiguous. Angle brackets are deliberately NOT
// tracked — `polls < POLL_BUDGET` is the very text this tool reads.
func headerEnd(masked string, from int) (int, bool) {
	depth := 0
	// A deterministic domain bound over a finite string, not a liveness
	// guard: the same character count on every host and every run, and
	// exceeding it SKIPS the construct rather than aborting anything. A loop
	// header 4000 characters long is not a loop header.
	limit := from + 4000
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
		case '}':
			if depth == 0 {
				return 0, false
			}
			depth--
		case ';':
			if depth == 0 {
				return 0, false
			}
		}
	}
	return 0, false
}

func matchBrace(masked string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(masked); i++ {
		switch masked[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// increments returns the counters incremented anywhere in the body, and those
// incremented at the body's own brace depth (once per iteration).
func increments(body string) (all, top map[string]bool) {
	all, top = map[string]bool{}, map[string]bool{}
	record := func(re *regexp.Regexp) {
		for _, m := range re.FindAllStringSubmatchIndex(body, -1) {
			name := body[m[2]:m[3]]
			all[name] = true
			if braceDepthAt(body, m[2]) == 1 {
				top[name] = true
			}
		}
	}
	record(incRe)
	record(fetchAddRe)
	return all, top
}

// braceDepthAt counts open braces before off within body (body starts at its
// own `{`, so a statement directly in the body sits at depth 1).
func braceDepthAt(body string, off int) int {
	depth := 0
	for i := 0; i < off && i < len(body); i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return depth
}

// shapeA: a count conjunct in a `while` header over an unconditionally
// incremented counter.
func shapeA(lp loopSite, incTop map[string]bool, masked string) []Violation {
	if lp.kind != "while" {
		return nil
	}
	var out []Violation
	base := lp.keywordAt + len("while")
	for _, c := range splitConjuncts(lp.header) {
		counter, bound, ok := matchRemainingBudget(c.text)
		if !ok || !incTop[counter] {
			continue
		}
		out = append(out, Violation{
			Shape: "A", Counter: counter, Bound: bound,
			offset: base + c.off, loopOff: lp.keywordAt,
		})
	}
	return out
}

// shapeB: an in-loop `assert!` or bail-out `if` deciding on a count.
//
// B1 (abort): `assert!(counter < K, ..)` or `if counter > K { panic!(..) }`.
// Reaching the bound is a FAILURE, so the bound is a liveness guard however
// the counter is incremented. This is F004's exact text.
//
// B2 (silent break): `if counter > K { break }`. Leaving the loop here may
// equally well be the loop's GOAL ("stop once eight sends were accepted"), so
// this form is reported only when the counter is incremented unconditionally
// — once per iteration, which is a count of the machine and nothing else.
func shapeB(lp loopSite, incAll, incTop map[string]bool, masked string) []Violation {
	body := masked[lp.bodyStart:lp.bodyEnd]
	var out []Violation
	add := func(shape, counter, bound string, off int) {
		out = append(out, Violation{
			Shape: shape, Counter: counter, Bound: bound,
			offset: lp.bodyStart + off, loopOff: lp.keywordAt,
		})
	}
	// assert!(<condition>, "a message naming {counter} is fine")
	for _, m := range assertRe.FindAllStringSubmatchIndex(body, -1) {
		openParen := m[1] - 1
		closeParen, ok := matchParen(body, openParen)
		if !ok {
			continue
		}
		args := splitTopLevel(body[openParen+1:closeParen], ',')
		if len(args) == 0 {
			continue
		}
		// Only argument 0 — the CONDITION — is read. A counter that appears
		// solely in the message is reporting, which the rule allows.
		for _, c := range splitConjuncts(args[0].text) {
			if counter, bound, ok := matchRemainingBudget(c.text); ok && incAll[counter] {
				add("B1", counter, bound, openParen+1+args[0].off+c.off)
			}
		}
	}
	// if <condition> { panic!(..) }  /  if <condition> { break }
	for _, m := range ifRe.FindAllStringIndex(body, -1) {
		open, ok := headerEnd(body, m[1])
		if !ok {
			continue
		}
		end, ok := matchBrace(body, open)
		if !ok {
			continue
		}
		block := body[open:end]
		shape := ""
		switch {
		case failBailRe.MatchString(block):
			shape = "B1"
		case breakBailRe.MatchString(block):
			shape = "B2"
		default:
			continue
		}
		cond := body[m[1]:open]
		for _, c := range splitAny(cond) {
			counter, bound, ok := matchExhaustedBudget(c.text)
			if !ok {
				continue
			}
			if shape == "B1" && incAll[counter] {
				add("B1", counter, bound, m[1]+c.off)
			}
			if shape == "B2" && incTop[counter] {
				add("B2", counter, bound, m[1]+c.off)
			}
		}
	}
	return out
}

type piece struct {
	text string
	off  int
}

// trimmed advances a piece past its leading whitespace, so a violation inside
// a multi-line `assert!(\n    counter < K,\n ...)` is reported on the line the
// comparison is actually written on.
func trimmed(text string, off int) piece {
	lead := 0
	for lead < len(text) && (text[lead] == ' ' || text[lead] == '\t' || text[lead] == '\n' || text[lead] == '\r') {
		lead++
	}
	return piece{text: text[lead:], off: off + lead}
}

// splitConjuncts splits on top-level `&&`.
func splitConjuncts(s string) []piece { return splitOnOp(s, "&&") }

// splitAny splits on top-level `&&` and `||`.
func splitAny(s string) []piece {
	var out []piece
	for _, a := range splitOnOp(s, "&&") {
		for _, b := range splitOnOp(a.text, "||") {
			out = append(out, piece{text: b.text, off: a.off + b.off})
		}
	}
	return out
}

func splitOnOp(s, op string) []piece {
	var out []piece
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		}
		if depth == 0 && i+len(op) <= len(s) && s[i:i+len(op)] == op {
			out = append(out, trimmed(s[start:i], start))
			i += len(op) - 1
			start = i + 1
		}
	}
	out = append(out, trimmed(s[start:], start))
	return out
}

func splitTopLevel(s string, sep byte) []piece {
	var out []piece
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case sep:
			if depth == 0 {
				out = append(out, trimmed(s[start:i], start))
				start = i + 1
			}
		}
	}
	out = append(out, trimmed(s[start:], start))
	return out
}

func matchParen(s string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// matchRemainingBudget recognises "the counter still has budget left", the
// form a loop header or an assertion uses to KEEP GOING.
func matchRemainingBudget(s string) (counter, bound string, ok bool) {
	s = normalise(s)
	if m := ltFormRe.FindStringSubmatch(s); m != nil {
		return m[1], m[3], true
	}
	if m := gtFormRe.FindStringSubmatch(s); m != nil {
		return m[3], m[1], true
	}
	return "", "", false
}

// matchExhaustedBudget recognises "the counter has run out", the form a
// bail-out `if` uses to STOP.
func matchExhaustedBudget(s string) (counter, bound string, ok bool) {
	s = normalise(s)
	if m := overLtRe.FindStringSubmatch(s); m != nil {
		return m[1], m[3], true
	}
	if m := overGtRe.FindStringSubmatch(s); m != nil {
		return m[3], m[1], true
	}
	return "", "", false
}

func normalise(s string) string {
	s = asCastRe.ReplaceAllString(s, "")
	s = strings.Join(strings.Fields(s), " ")
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		inner := s[1 : len(s)-1]
		if _, ok := matchParen(s, 0); !ok {
			break
		}
		if end, _ := matchParen(s, 0); end != len(s)-1 {
			break
		}
		s = strings.TrimSpace(inner)
	}
	return s
}

func lineOf(s string, off int) int {
	if off > len(s) {
		off = len(s)
	}
	return strings.Count(s[:off], "\n") + 1
}

func lineAt(lines []string, n int) string {
	if n-1 < 0 || n-1 >= len(lines) {
		return ""
	}
	return lines[n-1]
}

// waiverFor looks for the escape hatch on the reported line or just above it.
// A marker with too short a justification is NOT a waiver: it is reported, so
// that "// FIXTURE-COUNT-GUARD-ALLOWED: ok" cannot silence the gate.
func waiverFor(lines []string, line int) (bool, string) {
	for n := line; n >= line-waiverLookback && n >= 1; n-- {
		text := lineAt(lines, n)
		idx := strings.Index(text, waiverMarker)
		if idx < 0 {
			continue
		}
		just := strings.TrimSpace(text[idx+len(waiverMarker):])
		if len(just) < minJustification {
			return false, fmt.Sprintf("waiver marker present but the justification is %d characters; at least %d are required", len(just), minJustification)
		}
		return true, just
	}
	return false, ""
}
