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
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// TaskGraphPath is the authored plan.
const TaskGraphPath = "assurance/plan/task-graph.json"

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
	fmt.Printf("gate=task-graph ceiling=%q\n", graph.Ceiling)
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

		// Rule 5, the load-bearing one.
		if n.State == StateDone {
			checkable := 0
			for _, e := range n.Evidence {
				if !validKinds[e.Kind] {
					add("BAD_EVIDENCE_KIND", n.ID, fmt.Sprintf("evidence kind %q is not recognised", e.Kind))
					continue
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
	var g Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, fmt.Errorf("%s: %w", TaskGraphPath, err)
	}
	return &g, nil
}
