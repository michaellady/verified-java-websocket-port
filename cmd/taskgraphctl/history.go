package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// A plan can be emptied of its obligations one commit at a time, and every rule
// in main.go is satisfied by the survivors. Measured before this file existed:
// deleting all 11 `blocked` nodes gave `nodes=20 ... result=PASS`, and deleting
// all 15 `done` nodes gave `nodes=16 done=0 ... result=PASS` with the detail
// line still reading "every done node's evidence re-derived" -- vacuously true
// of an empty set. Nothing anywhere counted the plan against anything.
//
// There is no file in the tree to re-derive a node count FROM: the plan is the
// record of intent, so intent has no independent source. But it has a HISTORY.
// Every version of the plan this repository ever committed is a prior statement
// by its authors of what was outstanding, and git is a store this program can
// read without trusting the working copy. So the rule is: an id the plan once
// committed may not simply vanish.
//
// Disappearance is not always wrong -- a node gets renamed, two get merged --
// so there is an escape, and it is the declared-exemption shape this repository
// already uses four times (STALE_EXCLUSION, STALE_COVERAGE_CLAIM,
// STALE_ALLOWANCE, STALE_BLOCK): a `retired` entry may explain one id, and the
// entry is itself re-derived. A retirement for an id that is still present is
// STALE; one for an id git never committed is FICTIONAL; one naming a successor
// that does not exist is DANGLING. A declaration that nothing re-checks is a
// bypass, which is the finding that organised this whole review.

// Retirement declares that an id the plan once carried is deliberately gone.
type Retirement struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Reason       string `json:"reason"`
	SupersededBy string `json:"superseded_by,omitempty"`
}

const (
	RetireNode        = "node"
	RetireOwnerAction = "owner_action"
)

// historyUnavailableDetail is used for a refusal rather than a skip. An
// unreachable store is a refusal here for the same reason it is one in
// VerifyGovernance: a check that quietly does nothing when its source is
// missing is a check an attacker removes by removing the source.
const historyUnavailableDetail = "cannot read this plan's own git history, so a deleted node " +
	"would be undetectable; refusing rather than passing on an unreadable source"

// truncatedDetail names the remedy, because this checkout IS shallow: `git
// rev-parse --is-shallow-repository` reports true here, and actions/checkout@v4
// defaults to fetch-depth 1. Shallowness alone is harmless -- what matters is
// whether the plan file's OWN origin is readable, which is exact and needs no
// threshold. If the oldest visible commit touching the plan is not the commit
// that ADDED it, older versions declaring ids are beyond the boundary and this
// rule's "no committed version ever declared that id" would be a guess.
const truncatedDetail = "this plan's history is truncated: the oldest readable commit touching it " +
	"does not ADD it, so versions declaring ids sit beyond the clone's boundary and a deletion " +
	"there would be invisible. Deepen the checkout (`git fetch --unshallow`, or fetch-depth: 0)"

// priorIDs walks every committed version of the plan and returns, for nodes and
// for owner actions, each id ever declared mapped to the newest commit that
// declared it. It walks the FULL history deliberately: capping it would let a
// deletion age out of view.
func priorIDs(root string) (nodes, actions map[string]string, shas []string, ok bool) {
	log := exec.Command("git", "log", "--format=%H", "--", TaskGraphPath)
	log.Dir = root
	out, err := log.Output()
	if err != nil {
		return nil, nil, nil, false
	}
	shas = strings.Fields(string(out))
	if len(shas) == 0 {
		return nil, nil, nil, false
	}
	nodes, actions = map[string]string{}, map[string]string{}
	for _, sha := range shas {
		show := exec.Command("git", "show", sha+":"+TaskGraphPath)
		show.Dir = root
		blob, err := show.Output()
		if err != nil {
			// A commit that touched the path by DELETING it has no blob. That is
			// itself the deletion of the whole plan, which EMPTY_PLAN covers on
			// the current version; here it is simply not a source of ids.
			continue
		}
		var g Graph
		if json.Unmarshal(blob, &g) != nil {
			continue // an unparsable ancestor states nothing; it is not evidence
		}
		for _, n := range g.Nodes {
			if _, seen := nodes[n.ID]; !seen {
				nodes[n.ID] = sha // newest-first walk, so this is "last seen in"
			}
		}
		for _, a := range g.OwnerActions {
			if _, seen := actions[a.ID]; !seen {
				actions[a.ID] = sha
			}
		}
	}
	return nodes, actions, shas, true
}

// historyComplete reports whether the oldest readable commit touching the plan
// is the commit that created it. That is the whole question a shallow clone
// raises, asked exactly rather than by depth heuristics.
func historyComplete(root string, shas []string) bool {
	if len(shas) == 0 {
		return false
	}
	oldest := shas[len(shas)-1]

	// `--diff-filter=A` alone is NOT enough, and the test that proves it was
	// written before this line existed. Git presents a shallow GRAFT POINT as a
	// root commit: with no parent in the clone there is nothing to diff against,
	// so every file it contains looks ADDED. A depth-1 clone of a repository
	// whose plan had already dropped a node therefore reported the plan intact.
	// So the graft points are consulted directly.
	for _, graft := range shallowBoundary(root) {
		if graft == oldest {
			return false
		}
	}

	adds := exec.Command("git", "log", "--diff-filter=A", "--format=%H", "--", TaskGraphPath)
	adds.Dir = root
	out, err := adds.Output()
	if err != nil {
		return false
	}
	for _, sha := range strings.Fields(string(out)) {
		if sha == oldest {
			return true
		}
	}
	return false
}

// shallowBoundary returns the commits git has grafted, i.e. the ones whose
// parents this clone does not have. Empty for a complete clone.
func shallowBoundary(root string) []string {
	dir := exec.Command("git", "rev-parse", "--git-common-dir")
	dir.Dir = root
	out, err := dir.Output()
	if err != nil {
		return nil
	}
	gitDir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}
	raw, err := os.ReadFile(filepath.Join(gitDir, "shallow"))
	if err != nil {
		return nil // not a shallow clone
	}
	return strings.Fields(string(raw))
}

// checkHistory reports every id the plan has dropped without declaring it, and
// every retirement declaration that no longer describes this plan.
//
// It reads the plan AT ROOT rather than taking the caller's graph, and the
// distinction is load-bearing. This rule's question is "does the plan on disk
// still declare what its own history says it declared", so it must compare the
// two things it names -- a caller that verifies a SYNTHETIC graph against a real
// root is asking a different question, and taking `g` here made every real id
// look deleted to it. A root with no plan at all has no committed plan to have
// dropped anything from, so the rule does not apply there; `main` cannot reach
// that branch, because load() fails first when the file is missing.
func checkHistory(root string) []Finding {
	raw, err := os.ReadFile(filepath.Join(root, TaskGraphPath))
	if err != nil {
		return nil
	}
	var g *Graph
	parsed, err := parse(raw)
	if err != nil {
		// An unparsable working plan is refused by load() in main long before
		// this; here it means the caller handed us a scratch root.
		return nil
	}
	g = parsed
	var findings []Finding
	add := func(code, subject, detail string) {
		findings = append(findings, Finding{code, subject, detail})
	}

	priorNodes, priorActions, shas, ok := priorIDs(root)
	if !ok {
		return []Finding{{"PLAN_HISTORY_UNREADABLE", TaskGraphPath, historyUnavailableDetail}}
	}
	if !historyComplete(root, shas) {
		return []Finding{{"PLAN_HISTORY_TRUNCATED", TaskGraphPath, truncatedDetail}}
	}

	currentNodes := map[string]bool{}
	for _, n := range g.Nodes {
		currentNodes[n.ID] = true
	}
	currentActions := map[string]bool{}
	for _, a := range g.OwnerActions {
		currentActions[a.ID] = true
	}

	retiredNodes := map[string]bool{}
	retiredActions := map[string]bool{}
	for _, r := range g.Retired {
		switch r.Kind {
		case RetireNode:
			retiredNodes[r.ID] = true
		case RetireOwnerAction:
			retiredActions[r.ID] = true
		default:
			add("RETIREMENT_UNKNOWN_KIND", r.ID,
				fmt.Sprintf("kind %q is neither %q nor %q", r.Kind, RetireNode, RetireOwnerAction))
			continue
		}
		if strings.TrimSpace(r.Reason) == "" {
			add("RETIREMENT_WITHOUT_REASON", r.ID,
				"retired with no reason; a removal nobody explained is a removal nobody reviewed")
		}
		stillPresent := (r.Kind == RetireNode && currentNodes[r.ID]) ||
			(r.Kind == RetireOwnerAction && currentActions[r.ID])
		if stillPresent {
			add("STALE_RETIREMENT", r.ID,
				"declared retired but the plan still carries it; the exemption outlived what it excused")
		}
		_, everNode := priorNodes[r.ID]
		_, everAction := priorActions[r.ID]
		if (r.Kind == RetireNode && !everNode) || (r.Kind == RetireOwnerAction && !everAction) {
			add("FICTIONAL_RETIREMENT", r.ID,
				"retired, but no committed version of this plan ever declared that id")
		}
		if r.SupersededBy != "" && !currentNodes[r.SupersededBy] && !currentActions[r.SupersededBy] {
			add("DANGLING_SUCCESSOR", r.ID,
				fmt.Sprintf("superseded_by %q, which this plan does not declare", r.SupersededBy))
		}
	}

	for _, id := range sortedMissing(priorNodes, currentNodes, retiredNodes) {
		add("NODE_DISAPPEARED", id, fmt.Sprintf(
			"declared by this plan as recently as %s and absent now, with no `retired` entry explaining it",
			priorNodes[id][:12]))
	}
	for _, id := range sortedMissing(priorActions, currentActions, retiredActions) {
		add("OWNER_ACTION_DISAPPEARED", id, fmt.Sprintf(
			"declared by this plan as recently as %s and absent now, with no `retired` entry explaining it",
			priorActions[id][:12]))
	}
	return findings
}

func sortedMissing(prior map[string]string, current, retired map[string]bool) []string {
	var gone []string
	for id := range prior {
		if !current[id] && !retired[id] {
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	return gone
}
