// Command taskgraphctl checks the work plan the way this repository checks
// everything else: by re-deriving it.
//
// The loop this replaces read a prose board and picked "one bounded unit" per
// firing. Three problems, all observed on 2026-09-03/04: the one-unit rule was
// ignored every firing; priorities were re-derived from prose each time; and
// blocked-versus-ready existed only in whoever was reading. Worse, a prose plan
// rots exactly as `normalization-collision-audit.md` did — it stated 26 distinct
// observations while the artifact it cited measured 29, for hours, because
// nothing read the prose.
//
// So the plan is data with a gate. The load-bearing rule is the last one:
//
//  1. Every `depends_on` names a real node; every `blocked_by` names a real
//     owner action. A dangling reference is a plan about nothing.
//  2. No cycles.
//  3. A node cannot be `ready` while a dependency is unfinished or an owner
//     action it names is still open.
//  4. A node cannot stay `blocked` once every owner action it names is ruled.
//     That is the state this plan is most likely to get wrong, because a ruling
//     arrives from outside and nothing here notices.
//  5. **A `done` node must cite evidence the gate can CHECK, and that evidence
//     must still hold.** Not "name evidence" — name evidence of a kind this
//     program re-derives on every run. A `done` node whose only evidence is a
//     command nobody runs is `UNVERIFIABLE_DONE` and fails, because that is the
//     shape every defeated gate in this repository had: a well-formed
//     declaration whose claim went unchecked.
//
// Rule 5 is why `command` evidence does not count toward the requirement. It is
// recorded, and a reader can run it, but it is not a claim this gate has verified
// and it must not be able to masquerade as one.
//
//  6. Evidence that CANNOT fail is refused before it is checked. An adversarial
//     round (drafts/self-review/gate-attack-round-2.md) got a done node past
//     rule 5 six different ways with evidence that was true and said nothing:
//     `path_exists` with an empty path (which stats the repository root),
//     `grep` with an empty pattern, a `grep` of THIS FILE for a token that
//     exists only as its own pattern value, `path_exists` of a path outside the
//     tree, and -- the round-1 regex class in its fail-OPEN polarity -- a
//     `grep_absent` whose `^` was never given `(?m)`, so it could not match and
//     the absence was guaranteed. Rule 5 asks whether evidence HOLDS; rule 6
//     asks whether it could ever not.
//
// Two more things that round moved out of the plan's reach. The plan is parsed
// with unknown fields and duplicate keys REFUSED, because `"depends_on"` written
// twice, or misspelled once, deleted a dependency edge at exit 0 and printed the
// same census. And the ceiling below is a CONSTANT in this file rather than a
// string read from the plan: a gate whose disclosure of its own limits is
// authored by the artifact it audits can be made to disclose anything.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// TaskGraphPath is the authored plan.
const TaskGraphPath = "assurance/plan/task-graph.json"

// CeilingText is this program's disclosure of what it does NOT establish. It is
// a constant here, and the plan's `ceiling` field is required to equal it, for
// the reason the package comment gives: rewriting the plan's ceiling to say the
// gate checked sufficiency exited 0, and the gate printed the rewrite as its own
// disclosure. A ceiling is a property of the CODE.
const CeilingText = "This gate checks the plan's INTERNAL consistency and that " +
	"each done node's cited evidence still holds. It does NOT check that the " +
	"evidence is SUFFICIENT for the claim -- a node may cite a weak-but-true " +
	"fact and pass, and this was MEASURED rather than assumed: of the 13 done " +
	"nodes at the time of the measurement, 5 could have every source file of " +
	"the work they name deleted from the tree with this gate still at exit 0, " +
	"because their evidence was `path_exists` of a file the work did not create " +
	"or a `grep` for an identifier a comment can carry. The remaining 8 cite a " +
	"value the work itself produced. Rule 6 refuses evidence that cannot fail; " +
	"it cannot refuse evidence that is merely weak. It does not discover work: " +
	"a task nobody wrote down is invisible here, so the graph is a floor on " +
	"what remains, never a total -- and nothing counts the nodes, so deleting " +
	"one is silent. And `command` evidence is recorded but never verified, " +
	"deliberately, so it cannot masquerade as a checked claim."

type Evidence struct {
	Kind    string `json:"kind"`
	Path    string `json:"path,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Cmd     string `json:"cmd,omitempty"`
	Note    string `json:"note,omitempty"`
}

type Node struct {
	ID        string     `json:"id"`
	Title     string     `json:"title"`
	State     string     `json:"state"`
	Story     string     `json:"story,omitempty"`
	DependsOn []string   `json:"depends_on"`
	BlockedBy []string   `json:"blocked_by"`
	Evidence  []Evidence `json:"evidence"`
	Note      string     `json:"note,omitempty"`
}

type OwnerAction struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Needed   string `json:"what_is_needed"`
	RuledAt  string `json:"ruled_at,omitempty"`
	Ruling   string `json:"ruling,omitempty"`
	Blocking string `json:"why_it_blocks,omitempty"`
}

type Graph struct {
	SchemaVersion string        `json:"schema_version"`
	Statement     string        `json:"statement"`
	Ceiling       string        `json:"ceiling"`
	OwnerActions  []OwnerAction `json:"owner_actions"`
	Nodes         []Node        `json:"nodes"`
}

const (
	StateDone       = "done"
	StateReady      = "ready"
	StateBlocked    = "blocked"
	StateInProgress = "in-progress"
)

const (
	OwnerOpen  = "open"
	OwnerRuled = "ruled"
)

// checkableKinds are the evidence kinds this program re-derives on every run.
// `command` is deliberately absent: it is recorded for a reader, never counted as
// verified.
var checkableKinds = map[string]bool{
	"path_exists": true, "path_absent": true,
	"grep": true, "grep_absent": true,
	"git_tracked": true, "git_not_tracked": true,
}

var validKinds = map[string]bool{
	"path_exists": true, "path_absent": true,
	"grep": true, "grep_absent": true,
	"git_tracked": true, "git_not_tracked": true,
	"command": true,
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()

	graph, err := load(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskgraphctl: %v\n", err)
		os.Exit(2)
	}

	findings := Verify(*root, graph)
	for _, f := range findings {
		fmt.Printf("gate=task-graph finding=%s node=%s detail=%q\n", f.Code, f.Subject, f.Detail)
	}

	counts := map[string]int{}
	for _, n := range graph.Nodes {
		counts[n.State]++
	}
	open := 0
	for _, a := range graph.OwnerActions {
		if a.State == OwnerOpen {
			open++
		}
	}
	fmt.Printf("gate=task-graph nodes=%d done=%d ready=%d in_progress=%d blocked=%d "+
		"owner_actions=%d open=%d\n",
		len(graph.Nodes), counts[StateDone], counts[StateReady], counts[StateInProgress],
		counts[StateBlocked], len(graph.OwnerActions), open)

	if len(findings) > 0 {
		fmt.Printf("gate=task-graph result=FAIL reason=%q\n",
			fmt.Sprintf("%d finding(s); the plan does not describe this tree", len(findings)))
		os.Exit(1)
	}
	fmt.Printf("gate=task-graph result=PASS detail=%q\n",
		fmt.Sprintf("every done node's evidence re-derived; %d ready, %d blocked on %d open owner action(s)",
			counts[StateReady], counts[StateBlocked], open))
	fmt.Printf("gate=task-graph ceiling=%q\n", CeilingText)
}

type Finding struct {
	Code    string
	Subject string
	Detail  string
}

// Verify applies every rule and returns each violation as a typed finding.
func Verify(root string, g *Graph) []Finding {
	var findings []Finding
	add := func(code, subject, detail string) {
		findings = append(findings, Finding{code, subject, detail})
	}

	// An empty plan is not a satisfied plan. gosuitectl learned this in the
	// adversarial round before this one -- an empty run set `go test`ed the
	// repository root, found nothing and PASSed -- and the same shape was still
	// here: deleting every node gave `nodes=0 ... result=PASS`.
	if len(g.Nodes) == 0 {
		add("EMPTY_PLAN", TaskGraphPath,
			"the plan declares no nodes; a plan about nothing is not a plan that holds")
	}
	nodeByID := map[string]*Node{}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if _, dup := nodeByID[n.ID]; dup {
			add("DUPLICATE_NODE", n.ID, "two nodes share this id")
		}
		nodeByID[n.ID] = n
	}
	ownerByID := map[string]*OwnerAction{}
	for i := range g.OwnerActions {
		a := &g.OwnerActions[i]
		if _, dup := ownerByID[a.ID]; dup {
			add("DUPLICATE_OWNER_ACTION", a.ID, "two owner actions share this id")
		}
		ownerByID[a.ID] = a
		if a.State != OwnerOpen && a.State != OwnerRuled {
			add("BAD_OWNER_STATE", a.ID, fmt.Sprintf("state %q is neither open nor ruled", a.State))
		}
		if a.State == OwnerRuled && strings.TrimSpace(a.Ruling) == "" {
			add("RULING_WITH_NO_CONTENT", a.ID,
				"declared ruled but states no ruling; a ruling nobody wrote down is not a ruling")
		}
		// The mirror image, and the one rule 4 cannot see. Rule 4 catches a node
		// still blocked after its action was flipped to `ruled`. It cannot catch
		// the action itself: writing the owner's answer into `ruling` and leaving
		// `state` at `open` is exactly the rot rule 4 exists for, arriving one
		// field earlier, and it passed at exit 0.
		if a.State == OwnerOpen && strings.TrimSpace(a.Ruling) != "" {
			add("OPEN_WITH_A_RULING", a.ID,
				"declared open but records a ruling; if the owner has answered, the state is "+
					"`ruled` and every node blocked on it becomes ready")
		}
	}

	for i := range g.Nodes {
		n := &g.Nodes[i]

		switch n.State {
		case StateDone, StateReady, StateBlocked, StateInProgress:
		default:
			add("BAD_NODE_STATE", n.ID, fmt.Sprintf("state %q is not one of done/ready/blocked/in-progress", n.State))
		}

		for _, dep := range n.DependsOn {
			if _, ok := nodeByID[dep]; !ok {
				add("DANGLING_DEPENDENCY", n.ID, fmt.Sprintf("depends_on %q names no node", dep))
			}
		}
		for _, oa := range n.BlockedBy {
			if _, ok := ownerByID[oa]; !ok {
				add("DANGLING_OWNER_ACTION", n.ID, fmt.Sprintf("blocked_by %q names no owner action", oa))
			}
		}

		// Rule 3: readiness is a claim about dependencies, so recompute it.
		if n.State == StateReady || n.State == StateInProgress {
			for _, dep := range n.DependsOn {
				if d, ok := nodeByID[dep]; ok && d.State != StateDone {
					add("READY_ON_UNFINISHED_DEPENDENCY", n.ID,
						fmt.Sprintf("state %s but %s is %s", n.State, dep, d.State))
				}
			}
			for _, oa := range n.BlockedBy {
				if a, ok := ownerByID[oa]; ok && a.State == OwnerOpen {
					add("READY_WHILE_OWNER_ACTION_OPEN", n.ID,
						fmt.Sprintf("state %s but owner action %s is still open", n.State, oa))
				}
			}
		}

		// Rule 4: the state a ruling arriving from outside silently invalidates.
		if n.State == StateBlocked {
			if len(n.BlockedBy) == 0 {
				add("BLOCKED_ON_NOTHING", n.ID,
					"blocked but names no owner action; blocked on what?")
			}
			allRuled := len(n.BlockedBy) > 0
			for _, oa := range n.BlockedBy {
				if a, ok := ownerByID[oa]; !ok || a.State == OwnerOpen {
					allRuled = false
				}
			}
			depsDone := true
			for _, dep := range n.DependsOn {
				if d, ok := nodeByID[dep]; !ok || d.State != StateDone {
					depsDone = false
				}
			}
			if allRuled && depsDone {
				add("STALE_BLOCK", n.ID,
					"every owner action it names is RULED and every dependency is done, "+
						"so this is ready and the plan has not noticed")
			}
		}

		// Rule 6 applies to every node, done or not: an evidence item that cannot
		// fail is not made honest by the state of the node that cites it.
		for _, e := range n.Evidence {
			if !validKinds[e.Kind] {
				add("BAD_EVIDENCE_KIND", n.ID, fmt.Sprintf("evidence kind %q is not recognised", e.Kind))
				continue
			}
			if problem := evidenceShapeProblem(root, e); problem != "" {
				add("VACUOUS_EVIDENCE", n.ID, problem)
			}
		}

		// Rule 5, the load-bearing one.
		if n.State == StateDone {
			// `done` was a total exemption from the dependency rules: rule 3 reads
			// ready and in-progress, rule 4 reads blocked, and nothing read done.
			// A node could be finished on top of a blocked prerequisite at exit 0.
			for _, dep := range n.DependsOn {
				if d, ok := nodeByID[dep]; ok && d.State != StateDone {
					add("DONE_ON_UNFINISHED_DEPENDENCY", n.ID,
						fmt.Sprintf("state done but %s is %s; work is not finished on top of "+
							"work that is not", dep, d.State))
				}
			}
			checkable := 0
			for _, e := range n.Evidence {
				if !validKinds[e.Kind] {
					continue // already reported above
				}
				if evidenceShapeProblem(root, e) != "" {
					continue // vacuous: reported above, and it must not COUNT
				}
				if checkableKinds[e.Kind] {
					checkable++
				}
				if problem := checkEvidence(root, e); problem != "" {
					add("EVIDENCE_NO_LONGER_HOLDS", n.ID, problem)
				}
			}
			if checkable == 0 {
				add("UNVERIFIABLE_DONE", n.ID,
					"declared done with no evidence this gate can re-derive; a command nobody "+
						"runs is not a verified claim")
			}
		}
	}

	findings = append(findings, detectCycles(g, nodeByID)...)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Subject != findings[j].Subject {
			return findings[i].Subject < findings[j].Subject
		}
		return findings[i].Code < findings[j].Code
	})
	return findings
}

// pathBearingKinds are the kinds whose `path` field must name something inside
// this tree. `command` is not one of them.
var pathBearingKinds = map[string]bool{
	"path_exists": true, "path_absent": true,
	"grep": true, "grep_absent": true,
	"git_tracked": true, "git_not_tracked": true,
}

// escapeRe and classRe strip the two places a `^` or `$` is NOT a line anchor:
// an escaped one, and one inside a character class.
var (
	escapeRe = regexp.MustCompile(`\\.`)
	classRe  = regexp.MustCompile(`\[[^\]]*\]`)
	// multilineRe matches an inline flag group that turns `m` ON: `(?m)`,
	// `(?im)`, `(?ms:`. A group that turns it off (`(?-m)`) does not match.
	multilineRe = regexp.MustCompile(`\(\?[a-zA-Z]*m[a-zA-Z]*[:)]`)
)

// anchorsLines reports whether the pattern uses `^` or `$` as an anchor.
func anchorsLines(pattern string) bool {
	bare := classRe.ReplaceAllString(escapeRe.ReplaceAllString(pattern, ""), "")
	return strings.ContainsAny(bare, "^$")
}

// evidenceShapeProblem is rule 6: it reports evidence whose verdict does not
// depend on the tree. Rule 5 asks whether an item HOLDS; this asks whether it
// could ever not hold, and refuses the ones that could not.
//
// Every case here was reached by an actual attack that exited 0, not by
// imagination; the codes are the ones that attack would now produce.
func evidenceShapeProblem(root string, e Evidence) string {
	if pathBearingKinds[e.Kind] {
		raw := strings.TrimSpace(e.Path)
		clean := path.Clean(raw)
		if raw == "" || clean == "." || clean == "/" {
			return fmt.Sprintf("%s names no path: %q resolves to the repository root, "+
				"which exists on every run and says nothing about any work", e.Kind, e.Path)
		}
		if clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
			return fmt.Sprintf("%s path %q leaves this tree; a fact about a file outside "+
				"the repository is not evidence about the repository", e.Kind, e.Path)
		}
	}
	// An ABSENCE claim is a claim about a removal, so ask git whether there was
	// ever anything to remove. `path_absent no/such/file/ever` held at exit 0 and
	// said nothing; both live absence claims here -- F011's `.quarantine` symlink
	// and the committed `pinconsumerctl` binary -- were tracked before the work
	// that this evidence records, which is exactly what makes them evidence.
	if e.Kind == "path_absent" || e.Kind == "git_not_tracked" {
		if known, decidable := gitEverKnew(root, e.Path); decidable && !known {
			return fmt.Sprintf("%s %s: git has no history for this path, so it was never "+
				"there to be removed. An absence that was always absent records no work",
				e.Kind, e.Path)
		}
	}
	if e.Kind != "grep" && e.Kind != "grep_absent" {
		return ""
	}
	if strings.TrimSpace(e.Pattern) == "" {
		return fmt.Sprintf("%s %s has an empty pattern, which matches every file that "+
			"can be read", e.Kind, e.Path)
	}
	if path.Clean(strings.TrimSpace(e.Path)) == TaskGraphPath {
		return fmt.Sprintf("%s targets the plan itself, where the pattern's own text is "+
			"one of the bytes it searches: the item holds by construction", e.Kind)
	}
	if anchorsLines(e.Pattern) && !multilineRe.MatchString(e.Pattern) {
		return fmt.Sprintf("%s %s: pattern %q anchors with ^ or $ but does not set (?m), "+
			"so Go anchors it to the start and end of the WHOLE FILE. For grep that is a "+
			"false negative waiting to happen; for grep_absent the absence is guaranteed "+
			"and the item can never fail", e.Kind, e.Path, e.Pattern)
	}
	return ""
}

// gitEverKnew reports whether git history mentions the path at all, and whether
// the question could be decided here.
//
// It is UNDECIDABLE where there is no history to read -- outside a checkout, and
// in the unit tests' temporary directories. The remaining caveat is stated
// rather than guarded: in a clone shallow enough that the removal itself is
// below the graft boundary, this reports "never there" for a path that was, and
// the gate fails. That is a loud refusal rather than a silent pass, which is the
// direction this family errs in; the checkout these gates run in carries 526
// commits and both live absence claims resolve inside it.
func gitEverKnew(root, target string) (known, decidable bool) {
	head := exec.Command("git", "log", "--oneline", "-1")
	head.Dir = root
	if out, err := head.Output(); err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return false, false
	}
	history := exec.Command("git", "log", "--oneline", "-1", "--", target)
	history.Dir = root
	out, err := history.Output()
	if err != nil {
		return false, false
	}
	return len(strings.TrimSpace(string(out))) > 0, true
}

// checkEvidence re-derives one evidence item, returning "" when it still holds.
func checkEvidence(root string, e Evidence) string {
	switch e.Kind {
	case "command":
		return "" // recorded, never counted; see the package comment
	case "path_exists":
		if _, err := os.Stat(filepath.Join(root, e.Path)); err != nil {
			return fmt.Sprintf("path_exists %s: %v", e.Path, err)
		}
	case "path_absent":
		if _, err := os.Stat(filepath.Join(root, e.Path)); err == nil {
			return fmt.Sprintf("path_absent %s: it exists", e.Path)
		}
	case "git_tracked", "git_not_tracked":
		// Several fixes in this repository are claims about what git TRACKS --
		// F011's self-referential `.quarantine` symlink, the 3.9 MiB binary I
		// committed. Citing the finding that records such a fix would prove only
		// that the finding exists, which is the founding defect class here. So
		// this kind asks git.
		command := exec.Command("git", "ls-files", "--error-unmatch", "--", e.Path)
		command.Dir = root
		tracked := command.Run() == nil
		if e.Kind == "git_tracked" && !tracked {
			return fmt.Sprintf("git_tracked %s: git does not track it", e.Path)
		}
		if e.Kind == "git_not_tracked" && tracked {
			return fmt.Sprintf("git_not_tracked %s: git tracks it and must not", e.Path)
		}
	case "grep", "grep_absent":
		content, err := os.ReadFile(filepath.Join(root, e.Path))
		if err != nil {
			return fmt.Sprintf("%s %s: %v", e.Kind, e.Path, err)
		}
		re, err := regexp.Compile(e.Pattern)
		if err != nil {
			return fmt.Sprintf("%s %s: pattern %q does not compile: %v", e.Kind, e.Path, e.Pattern, err)
		}
		found := re.Match(content)
		if e.Kind == "grep" && !found {
			return fmt.Sprintf("grep %s: pattern %q no longer matches", e.Path, e.Pattern)
		}
		if e.Kind == "grep_absent" && found {
			return fmt.Sprintf("grep_absent %s: pattern %q matches and must not", e.Path, e.Pattern)
		}
	}
	return ""
}

// detectCycles reports each dependency cycle once, naming the nodes in it.
func detectCycles(g *Graph, byID map[string]*Node) []Finding {
	const (
		white = 0
		grey  = 1
		black = 2
	)
	colour := map[string]int{}
	var findings []Finding
	var stack []string

	var walk func(id string)
	walk = func(id string) {
		colour[id] = grey
		stack = append(stack, id)
		if n, ok := byID[id]; ok {
			for _, dep := range n.DependsOn {
				if _, exists := byID[dep]; !exists {
					continue
				}
				switch colour[dep] {
				case white:
					walk(dep)
				case grey:
					at := 0
					for i, s := range stack {
						if s == dep {
							at = i
							break
						}
					}
					findings = append(findings, Finding{"DEPENDENCY_CYCLE", id,
						"cycle: " + strings.Join(append(stack[at:], dep), " -> ")})
				}
			}
		}
		stack = stack[:len(stack)-1]
		colour[id] = black
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if colour[id] == white {
			walk(id)
		}
	}
	return findings
}

func load(root string) (*Graph, error) {
	raw, err := os.ReadFile(filepath.Join(root, TaskGraphPath))
	if err != nil {
		return nil, err
	}
	return parse(raw)
}

// parse refuses two silent edits before it maps anything.
//
// A DUPLICATE key is kept-last by encoding/json and reported by nothing: a
// second `"depends_on": []` beside a real one, in either order, deleted the edge
// and printed the identical census. A duplicate `"kind"` is the same trick on an
// evidence item, and it is the only way found to make a `command` item behave as
// a checkable one.
//
// An UNKNOWN field is the same loss by typo: `"dependsOn"` instead of
// `"depends_on"` is not matched by encoding/json's case-insensitive fallback --
// the underscore differs -- so every dependency of that node silently vanished.
func parse(raw []byte) (*Graph, error) {
	if err := refuseDuplicateKeys(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var g Graph
	if err := decoder.Decode(&g); err != nil {
		return nil, fmt.Errorf("%s: %w", TaskGraphPath, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%s: trailing content after the plan document", TaskGraphPath)
	}
	// The ceiling is a property of THIS program, mirrored into the plan so a
	// reader of the plan sees it. Rewriting it in the plan to say the gate checked
	// sufficiency exited 0, and the gate printed the rewrite as its own disclosure.
	if strings.TrimSpace(g.Ceiling) != CeilingText {
		return nil, fmt.Errorf("%s: the plan's `ceiling` is not this program's CeilingText. "+
			"A gate does not take the statement of its own limits from the artifact it audits; "+
			"change the constant in cmd/taskgraphctl/main.go and mirror it here", TaskGraphPath)
	}
	return &g, nil
}

// refuseDuplicateKeys walks the token stream and refuses any object that names
// the same key twice, reporting the path to it.
func refuseDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func(where string) error
	walk = func(where string) error {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", TaskGraphPath, err)
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return fmt.Errorf("%s: %w", TaskGraphPath, err)
				}
				key, _ := keyToken.(string)
				if seen[key] {
					return fmt.Errorf("%s: the object at %s names %q twice. encoding/json keeps "+
						"the LAST, so a duplicate key is an edit no reader of this file sees",
						TaskGraphPath, where, key)
				}
				seen[key] = true
				if err := walk(where + "." + key); err != nil {
					return err
				}
			}
		case '[':
			for index := 0; decoder.More(); index++ {
				if err := walk(fmt.Sprintf("%s[%d]", where, index)); err != nil {
					return err
				}
			}
		}
		if _, err := decoder.Token(); err != nil { // the closing delimiter
			return fmt.Errorf("%s: %w", TaskGraphPath, err)
		}
		return nil
	}
	return walk("$")
}
