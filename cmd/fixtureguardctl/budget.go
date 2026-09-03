package main

// budget.go — SHAPE C, the blind spot §5.2 of
// drafts/self-review/fixture-liveness-guard-detector.md named and F005's bin
// note carried forward: a fixture liveness bound written as a count, one
// indirection away.
//
// THE SHAPE. `rust/ws-testee/src/io_loop.rs` bounds its run with
// `while report.polls < bounds.max_polls`. That is PRODUCTION code and shapes
// A and B deliberately do not report it — a retry cap in a shipped loop is a
// design decision. But the number is not production's: the fixtures choose it,
// `max_polls: 50_000`, `4_000`, `2_000`, `250`, `64`. A fixture that picks the
// number has written its own liveness guard as a count of operations, which is
// exactly the sentence F005 filed; that the count sits behind a struct field
// instead of a loop header changes nothing about what it measures.
//
// THE HARD PART, AND HOW IT IS DECIDED. `max_polls` serves TWO roles, and they
// are spelled identically:
//
//	LIVENESS   `max_polls: 50_000` alongside `write_stall_limit: 300ms`, then
//	           `assert_eq!(report.outcome, LoopOutcome::WriteStalled)`. The
//	           budget must NOT be reached; if this host is fast enough to spend
//	           50,000 polls inside 300ms the outcome is `BudgetExhausted` and
//	           the assertion fails with a host-speed message. F005 verbatim.
//
//	SUBJECT    `max_polls: 0` / `: 1`, then
//	           `assert_eq!(report.outcome, LoopOutcome::BudgetExhausted)`. The
//	           budget MUST be reached: these are tests OF the budget mechanism,
//	           and they are correct exactly as written.
//
// The discriminator is the same move shape B1 already makes — read what
// REACHING the bound means. B1 fires on an in-loop `assert!` because reaching
// it is a FAILURE by construction. Shape C stays SILENT when the enclosing
// test names the bound's own exhaustion outcome, because reaching it is then
// the EXPECTED RESULT by construction. A test that asserts `BudgetExhausted`
// is not guarding against a slow host; it is measuring the guard. No
// threshold on the value is used anywhere: `max_polls: 64` is a violation in
// one test and `max_polls: 0` is silent in another, and the number is not what
// decides.
//
// WHY THE TABLE CANNOT ROT. The production anchor is declared here and
// VERIFIED against the tree on every run (`verifyBudgetAnchors`): if
// `io_loop.rs` stops containing that loop condition, or the outcome token
// disappears, the gate FAILS rather than falling silent. A rule that reaches
// across an indirection has to prove the far end still exists.

import (
	"fmt"
	"regexp"
	"strings"
)

// productionBudget is one count-shaped bound that lives in production code and
// is SUPPLIED by fixtures.
type productionBudget struct {
	// Field is the name fixtures set, both as a struct-literal field and as a
	// forwarder's parameter.
	Field string
	// Anchor is the production file that consumes it, relative to the repo
	// root and checked for existence on every run.
	Anchor string
	// LoopText is the production loop condition the field bounds, checked
	// verbatim in Anchor so this table cannot drift from the code.
	LoopText string
	// Outcome is the typed result the production loop reports when the bound
	// IS reached. A fixture whose enclosing function names it is testing the
	// mechanism, not guarding against a slow host.
	Outcome string
}

// productionBudgets is the whole table. One entry today; adding a second is a
// data change, not a code change.
var productionBudgets = []productionBudget{
	{
		Field:    "max_polls",
		Anchor:   "rust/ws-testee/src/io_loop.rs",
		LoopText: "while report.polls < bounds.max_polls",
		Outcome:  "BudgetExhausted",
	},
}

var (
	fnDeclRe = regexp.MustCompile(`\bfn\s+([a-z_][A-Za-z0-9_]*)\s*[(<]`)
	// A named-field supply: `max_polls: 50_000` / `max_polls: SOME_CONST`.
	// The bound alternation is `boundRe`, so a type annotation in a parameter
	// list (`max_polls: u64`) does not match and the forwarder's own signature
	// is not a site.
	budgetFieldRe = func(field string) *regexp.Regexp {
		return regexp.MustCompile(`\b` + regexp.QuoteMeta(field) + `\s*:\s*(` + boundRe + `)\b`)
	}
	// A call to a forwarder: `prompt_bounds(2_000)`. Every argument is read,
	// and the one in the forwarded POSITION is the site.
	budgetCallRe = func(name string) *regexp.Regexp {
		return regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\(`)
	}
	// `max_polls: n` inside a helper's body, where `n` is one of its own
	// parameters: that helper FORWARDS the budget, whatever its parameter is
	// called. Keying on the assignment rather than on the parameter's NAME is
	// what stops a rename from dodging the rule.
	budgetFromParamRe = func(field string) *regexp.Regexp {
		return regexp.MustCompile(`\b` + regexp.QuoteMeta(field) + `\s*:\s*(` + identRe + `)\s*[,}]`)
	}
)

// fnItem is one `fn`, the extent of its body, and its parameter names in
// declaration order — the order a call site's arguments line up with.
type fnItem struct {
	name   string
	params []string
	start  int // offset of the `fn` keyword
	open   int // offset of the body's `{`
	end    int // offset of the matching `}`
}

// findFns locates every `fn` in masked source together with its body extent
// and its parameter names.
func findFns(masked string) []fnItem {
	var out []fnItem
	for _, m := range fnDeclRe.FindAllStringSubmatchIndex(masked, -1) {
		// Start the brace search just after the `fn` keyword, NOT after the
		// match: the match consumes the opening `(`, and headerEnd must see
		// that paren to balance the parameter list. Starting past it left
		// every parameter list unbalanced, so no body was ever found, so no
		// supply site had an enclosing function, so the two roles could not
		// be told apart and the budget tests were reported as guards.
		open, ok := headerEnd(masked, m[0]+len("fn"))
		if !ok {
			continue
		}
		end, ok := matchBrace(masked, open)
		if !ok {
			continue
		}
		out = append(out, fnItem{
			name:   masked[m[2]:m[3]],
			params: paramNames(masked[m[3]:open]),
			start:  m[0], open: open, end: end,
		})
	}
	return out
}

// paramNames reads the parameter names out of the text between a function's
// name and its body brace. Only the leading `ident :` of each top-level
// comma-separated piece inside the parameter parens is read, so a generic
// list or a return type contributes nothing.
func paramNames(header string) []string {
	openIdx := strings.IndexByte(header, '(')
	if openIdx < 0 {
		return nil
	}
	closeIdx, ok := matchParen(header, openIdx)
	if !ok {
		return nil
	}
	var out []string
	for _, p := range splitTopLevel(header[openIdx+1:closeIdx], ',') {
		text := strings.TrimSpace(p.text)
		colon := strings.IndexByte(text, ':')
		if colon < 0 {
			out = append(out, "")
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text[:colon]), "mut "))
		if !plainIdentRe.MatchString(name) {
			out = append(out, "")
			continue
		}
		out = append(out, name)
	}
	return out
}

var plainIdentRe = regexp.MustCompile(`^[a-z_][A-Za-z0-9_]*$`)

// enclosingFn returns the innermost `fn` whose body contains off.
func enclosingFn(fns []fnItem, off int) (fnItem, bool) {
	best := fnItem{}
	found := false
	for _, f := range fns {
		if off <= f.open || off >= f.end {
			continue
		}
		if !found || f.open > best.open {
			best, found = f, true
		}
	}
	return best, found
}

// forwarder is a fixture helper that hands one of its own parameters to the
// production budget field, plus which parameter position that is.
type forwarder struct {
	name     string
	position int
}

// findForwarders locates the helpers that pass a parameter straight through to
// the budget field. `fn prompt_bounds(max_polls: u64) -> IoBounds { IoBounds {
// max_polls, .. } }` is one, and so is the same helper with its parameter
// renamed — which is the point of keying on the ASSIGNMENT rather than on the
// parameter's name. A helper that DERIVES the budget from something else
// (`max_polls: polls_for(deadline)`) forwards nothing and is not one.
func findForwarders(masked string, fns []fnItem, pb productionBudget) []forwarder {
	var out []forwarder
	shorthandRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(pb.Field) + `\s*[,}]`)
	for _, f := range fns {
		body := masked[f.open:f.end]
		named := ""
		if m := budgetFromParamRe(pb.Field).FindStringSubmatch(body); m != nil {
			named = m[1]
		} else if shorthandRe.MatchString(body) {
			// Field-init shorthand: `IoBounds { max_polls, .. }` forwards the
			// parameter of the same name.
			named = pb.Field
		}
		if named == "" {
			continue
		}
		for i, p := range f.params {
			if p == named {
				out = append(out, forwarder{name: f.name, position: i})
				break
			}
		}
	}
	return out
}

// callArgs returns the top-level argument pieces of the call whose `(` sits at
// openAt, with offsets relative to the whole source.
func callArgs(masked string, openAt int) ([]piece, bool) {
	closeAt, ok := matchParen(masked, openAt)
	if !ok {
		return nil, false
	}
	args := splitTopLevel(masked[openAt+1:closeAt], ',')
	for i := range args {
		args[i].off += openAt + 1
	}
	return args, true
}

// scanBudgets applies shape C to one masked fixture source.
//
// Reported: a literal or SCREAMING_SNAKE count supplied to a declared
// production budget from a function that does NOT name that budget's
// exhaustion outcome. Silent: the same supply from a function that does.
func scanBudgets(masked string, regions []region) []Violation {
	fns := findFns(masked)
	wholeBoundRe := regexp.MustCompile(`^(?:` + boundRe + `)$`)
	var out []Violation
	for _, pb := range productionBudgets {
		sites := map[int]string{}
		for _, m := range budgetFieldRe(pb.Field).FindAllStringSubmatchIndex(masked, -1) {
			sites[m[2]] = masked[m[2]:m[3]]
		}
		for _, fw := range findForwarders(masked, fns, pb) {
			for _, m := range budgetCallRe(fw.name).FindAllStringIndex(masked, -1) {
				args, ok := callArgs(masked, m[1]-1)
				if !ok || fw.position >= len(args) {
					continue
				}
				arg := args[fw.position]
				text := normalise(arg.text)
				if wholeBoundRe.MatchString(text) {
					sites[arg.off] = text
				}
			}
		}
		for off, value := range sites {
			if !inRegions(off, regions) {
				continue
			}
			owner, ok := enclosingFn(fns, off)
			if ok && strings.Contains(masked[owner.open:owner.end], pb.Outcome) {
				// A test OF the budget mechanism: reaching the bound is what
				// it asserts. Correct as written, and left alone.
				continue
			}
			out = append(out, Violation{
				Shape:   "C",
				Counter: pb.Field,
				Bound:   value,
				offset:  off,
				loopOff: off,
			})
		}
	}
	return out
}

// budgetExplain is shape C's remedy text.
func budgetExplain(v Violation) string {
	pb, ok := budgetFor(v.Counter)
	if !ok {
		return ""
	}
	return fmt.Sprintf("this fixture supplies `%s = %s` into the production loop bound `%s` (%s), "+
		"so a count of operations decides whether this run keeps going — a measurement of how fast this host is, "+
		"one indirection away from the loop header. Either bound the fixture by a generous wall-clock deadline and let "+
		"`%s` only report, or, if reaching the bound is the POINT of the test, assert `%s` in this function and the rule "+
		"will read it as a test of the budget rather than a guard.",
		v.Counter, v.Bound, pb.LoopText, pb.Anchor, v.Counter, pb.Outcome)
}

func budgetFor(field string) (productionBudget, bool) {
	for _, pb := range productionBudgets {
		if pb.Field == field {
			return pb, true
		}
	}
	return productionBudget{}, false
}

// verifyBudgetAnchors proves the far end of the indirection still exists. A
// rule that reaches across a file boundary must fail loudly when the code it
// points at moves, or it becomes a rule about nothing.
func verifyBudgetAnchors(root string, readFile func(string) (string, error)) []string {
	var problems []string
	for _, pb := range productionBudgets {
		src, err := readFile(pb.Anchor)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: production anchor unreadable: %v", pb.Field, err))
			continue
		}
		if !strings.Contains(src, pb.LoopText) {
			problems = append(problems, fmt.Sprintf("%s: %s no longer contains %q, so this rule points at nothing", pb.Field, pb.Anchor, pb.LoopText))
		}
		if !strings.Contains(src, pb.Outcome) {
			problems = append(problems, fmt.Sprintf("%s: %s no longer names the exhaustion outcome %q, so the two roles can no longer be told apart", pb.Field, pb.Anchor, pb.Outcome))
		}
	}
	return problems
}
