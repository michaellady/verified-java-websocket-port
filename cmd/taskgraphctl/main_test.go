package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func codes(f []Finding) map[string]int {
	m := map[string]int{}
	for _, x := range f {
		m[x.Code]++
	}
	return m
}

// The authored plan must describe THIS tree. This is the check that makes the
// graph a gate rather than a document: it runs on every gates invocation, so a
// done node whose evidence stopped holding fails here and not in someone's head.
func TestTheCommittedPlanDescribesThisTree(t *testing.T) {
	root := repoRoot(t)
	g, err := load(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, f := range Verify(root, g) {
		t.Errorf("%s on %s: %s", f.Code, f.Subject, f.Detail)
	}
}

// A done node must cite evidence this program re-derives. `command` evidence is
// recorded for a reader and deliberately does not count -- otherwise a node could
// be declared done on a command nobody runs, which is the exact shape of every
// gate defeated in this repository on 2026-09-04.
func TestDoneOnCommandEvidenceAloneIsRefused(t *testing.T) {
	g := &Graph{Nodes: []Node{{
		ID: "T-x", Title: "x", State: StateDone,
		Evidence: []Evidence{{Kind: "command", Cmd: "make -C rust gates"}},
	}}}
	got := codes(Verify(t.TempDir(), g))
	if got["UNVERIFIABLE_DONE"] != 1 {
		t.Fatalf("a command-only done node must be refused, got %v", got)
	}
}

// And the opposite direction: one checkable item that HOLDS is enough.
func TestDoneWithCheckableEvidenceThatHoldsPasses(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "thing.txt"), []byte("present\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := &Graph{Nodes: []Node{{
		ID: "T-x", Title: "x", State: StateDone,
		Evidence: []Evidence{
			{Kind: "path_exists", Path: "thing.txt"},
			{Kind: "command", Cmd: "irrelevant"},
		},
	}}}
	if f := Verify(root, g); len(f) != 0 {
		t.Fatalf("expected no findings, got %v", f)
	}
}

func TestEvidenceThatStoppedHoldingFails(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "thing.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, ev := range map[string]Evidence{
		"missing path":   {Kind: "path_exists", Path: "absent.txt"},
		"path came back": {Kind: "path_absent", Path: "thing.txt"},
		"pattern gone":   {Kind: "grep", Path: "thing.txt", Pattern: "goodbye"},
		"pattern back":   {Kind: "grep_absent", Path: "thing.txt", Pattern: "hello"},
	} {
		g := &Graph{Nodes: []Node{{ID: "T-x", State: StateDone, Evidence: []Evidence{ev}}}}
		if codes(Verify(root, g))["EVIDENCE_NO_LONGER_HOLDS"] != 1 {
			t.Errorf("%s: must fail", name)
		}
	}
}

// The state a ruling arriving from OUTSIDE this file silently invalidates. Four
// of thirteen owner actions were ruled at once on 2026-09-04; without this the
// plan would have gone on calling their nodes blocked.
func TestBlockedOnlyOnRuledOwnerActionsIsStale(t *testing.T) {
	g := &Graph{
		OwnerActions: []OwnerAction{{ID: "OA-a", State: OwnerRuled, Ruling: "do it"}},
		Nodes:        []Node{{ID: "T-x", State: StateBlocked, BlockedBy: []string{"OA-a"}}},
	}
	if codes(Verify(t.TempDir(), g))["STALE_BLOCK"] != 1 {
		t.Fatal("a node blocked only on ruled owner actions must be reported stale")
	}
}

func TestBlockedOnAnOpenOwnerActionIsNotStale(t *testing.T) {
	g := &Graph{
		OwnerActions: []OwnerAction{
			{ID: "OA-a", State: OwnerRuled, Ruling: "do it"},
			{ID: "OA-b", State: OwnerOpen},
		},
		Nodes: []Node{{ID: "T-x", State: StateBlocked, BlockedBy: []string{"OA-a", "OA-b"}}},
	}
	if f := Verify(t.TempDir(), g); len(f) != 0 {
		t.Fatalf("one open action is enough to stay blocked, got %v", f)
	}
}

func TestReadinessIsRecomputedNotRead(t *testing.T) {
	g := &Graph{
		OwnerActions: []OwnerAction{{ID: "OA-open", State: OwnerOpen}},
		Nodes: []Node{
			{ID: "T-dep", State: StateReady},
			{ID: "T-a", State: StateReady, DependsOn: []string{"T-dep"}},
			{ID: "T-b", State: StateReady, BlockedBy: []string{"OA-open"}},
		},
	}
	got := codes(Verify(t.TempDir(), g))
	if got["READY_ON_UNFINISHED_DEPENDENCY"] != 1 {
		t.Errorf("ready on an unfinished dependency must fail: %v", got)
	}
	if got["READY_WHILE_OWNER_ACTION_OPEN"] != 1 {
		t.Errorf("ready while an owner action is open must fail: %v", got)
	}
}

func TestDanglingReferencesAndCyclesFail(t *testing.T) {
	g := &Graph{Nodes: []Node{
		{ID: "T-a", State: StateBlocked, DependsOn: []string{"T-nope"}, BlockedBy: []string{"OA-nope"}},
	}}
	got := codes(Verify(t.TempDir(), g))
	if got["DANGLING_DEPENDENCY"] != 1 || got["DANGLING_OWNER_ACTION"] != 1 {
		t.Errorf("dangling references must fail: %v", got)
	}

	cyc := &Graph{Nodes: []Node{
		{ID: "T-a", State: StateReady, DependsOn: []string{"T-b"}},
		{ID: "T-b", State: StateReady, DependsOn: []string{"T-a"}},
	}}
	if codes(Verify(t.TempDir(), cyc))["DEPENDENCY_CYCLE"] == 0 {
		t.Error("a cycle must be reported")
	}
}

// An owner action declared ruled with no ruling recorded is a decision nobody can
// act on or audit.
func TestARuledOwnerActionMustStateItsRuling(t *testing.T) {
	g := &Graph{OwnerActions: []OwnerAction{{ID: "OA-a", State: OwnerRuled}}}
	if codes(Verify(t.TempDir(), g))["RULING_WITH_NO_CONTENT"] != 1 {
		t.Fatal("a ruling with no content must fail")
	}
}

// git_tracked / git_not_tracked exist because several fixes here are claims about
// what git tracks, and citing the finding that records such a fix proves only that
// the finding exists. F011's symlink came BACK at f26e062 and this kind is what
// caught it.
func TestGitTrackingEvidenceIsAskedOfGit(t *testing.T) {
	root := repoRoot(t)
	if problem := checkEvidence(root, Evidence{Kind: "git_tracked", Path: ".gitignore"}); problem != "" {
		t.Errorf("a tracked file must read as tracked: %s", problem)
	}
	if problem := checkEvidence(root, Evidence{Kind: "git_tracked", Path: "no/such/file"}); problem == "" {
		t.Error("an untracked path must not read as tracked")
	}
	if problem := checkEvidence(root, Evidence{Kind: "git_not_tracked", Path: ".gitignore"}); problem == "" {
		t.Error("git_not_tracked must fail on a tracked file")
	}
}

// --- rule 6: evidence that cannot fail --------------------------------------

// Every case below got a `done` node past rule 5 at exit 0 in the round-2
// adversarial review. Each is TRUE of this tree and says nothing about any work.
func TestEvidenceThatCannotFailIsRefused(t *testing.T) {
	root := repoRoot(t)
	for name, ev := range map[string]Evidence{
		"empty path":            {Kind: "path_exists", Path: ""},
		"the root itself":       {Kind: "path_exists", Path: "."},
		"outside the tree":      {Kind: "path_exists", Path: "../../../etc/hostname"},
		"empty pattern":         {Kind: "grep", Path: "README.md", Pattern: ""},
		"the plan itself":       {Kind: "grep", Path: TaskGraphPath, Pattern: "ZZ_ONLY_ITS_OWN_TEXT_ZZ"},
		"anchored, no (?m)":     {Kind: "grep_absent", Path: "rust/Makefile", Pattern: "^gates:"},
		"absence never present": {Kind: "path_absent", Path: "no/such/file/ever"},
		"untracked and unknown": {Kind: "git_not_tracked", Path: "no/such/file/ever"},
	} {
		g := &Graph{Nodes: []Node{{ID: "T-x", State: StateDone, Evidence: []Evidence{ev}}}}
		got := codes(Verify(root, g))
		if got["VACUOUS_EVIDENCE"] != 1 {
			t.Errorf("%s: must be refused as vacuous, got %v", name, got)
		}
		// And it must not COUNT: a vacuous item cannot satisfy rule 5 either.
		if got["UNVERIFIABLE_DONE"] != 1 {
			t.Errorf("%s: a vacuous item must not satisfy rule 5, got %v", name, got)
		}
	}
}

// The other polarity, which is what bounds the rule: the shapes the live plan
// actually uses must stay silent.
func TestTheEvidenceShapesTheLivePlanUsesAreAccepted(t *testing.T) {
	root := repoRoot(t)
	for name, ev := range map[string]Evidence{
		"a real file":         {Kind: "path_exists", Path: "cmd/taskgraphctl/main.go"},
		"a (?m) anchor":       {Kind: "grep", Path: "rust/Makefile", Pattern: `(?m)^gates:.*plan-guard`},
		"an escaped dollar":   {Kind: "grep", Path: "rust/Makefile", Pattern: `plan-guard\$?`},
		"a negated class":     {Kind: "grep", Path: "rust/Makefile", Pattern: `plan-guard[^;]`},
		"an absence with git": {Kind: "git_not_tracked", Path: "pinconsumerctl"},
		"a command":           {Kind: "command", Cmd: "make -C rust gates"},
	} {
		if problem := evidenceShapeProblem(root, ev); problem != "" {
			t.Errorf("%s: must be accepted, got %q", name, problem)
		}
	}
}

// `done` was a total exemption from the dependency rules: rule 3 reads ready and
// in-progress, rule 4 reads blocked, and nothing read done.
func TestDoneDoesNotExemptADependency(t *testing.T) {
	root := repoRoot(t)
	g := &Graph{
		OwnerActions: []OwnerAction{{ID: "OA-a", State: OwnerOpen}},
		Nodes: []Node{
			{ID: "T-dep", State: StateBlocked, BlockedBy: []string{"OA-a"}},
			{ID: "T-x", State: StateDone, DependsOn: []string{"T-dep"},
				Evidence: []Evidence{{Kind: "path_exists", Path: "README.md"}}},
		},
	}
	if codes(Verify(root, g))["DONE_ON_UNFINISHED_DEPENDENCY"] != 1 {
		t.Fatalf("a done node standing on unfinished work must be reported: %v", Verify(root, g))
	}
}

// Rule 4 catches a NODE that has not noticed a ruling. It cannot catch the
// owner action itself: the owner's answer written into `ruling` with `state`
// left at `open` is the same rot one field earlier, and it passed at exit 0.
func TestAnOpenOwnerActionMayNotCarryARuling(t *testing.T) {
	g := &Graph{
		OwnerActions: []OwnerAction{{ID: "OA-a", State: OwnerOpen, Ruling: "do it later"}},
		Nodes:        []Node{{ID: "T-x", State: StateBlocked, BlockedBy: []string{"OA-a"}}},
	}
	if codes(Verify(t.TempDir(), g))["OPEN_WITH_A_RULING"] != 1 {
		t.Fatal("an open owner action recording a ruling must be reported")
	}
}

// Deleting every node gave `nodes=0 ... result=PASS`. gosuitectl closed the same
// shape one gate over; this one still had it.
func TestAnEmptyPlanIsRefused(t *testing.T) {
	if codes(Verify(t.TempDir(), &Graph{}))["EMPTY_PLAN"] != 1 {
		t.Fatal("a plan with no nodes must be refused")
	}
}

// --- document integrity, refused before anything is mapped ------------------

func minimalPlanJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(&Graph{
		SchemaVersion: "1.0.0",
		Ceiling:       CeilingText,
		Nodes: []Node{
			{ID: "T-a", State: StateReady},
			{ID: "T-b", State: StateReady, DependsOn: []string{"T-a"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A duplicate key is kept-last by encoding/json and reported by nothing: a
// second `"depends_on": []` deleted an edge and printed the identical census,
// and a second `"kind"` is the only way found to make a `command` evidence item
// behave as a checkable one.
func TestDuplicateKeysAreRefused(t *testing.T) {
	if _, err := parse(minimalPlanJSON(t)); err != nil {
		t.Fatalf("the control document must parse: %v", err)
	}
	for name, doctored := range map[string]string{
		"edge deleted by a repeat": strings.Replace(string(minimalPlanJSON(t)),
			`"depends_on":["T-a"]`, `"depends_on":["T-a"],"depends_on":[]`, 1),
		"same key twice at top": strings.Replace(string(minimalPlanJSON(t)),
			`"schema_version":"1.0.0"`, `"schema_version":"1.0.0","schema_version":"9"`, 1),
	} {
		if _, err := parse([]byte(doctored)); err == nil {
			t.Errorf("%s: a duplicate key must be refused", name)
		}
	}
}

// `dependsOn` is not matched by encoding/json's case-insensitive fallback -- the
// underscore differs -- so a single typo silently deleted every dependency of a
// node at exit 0.
func TestAnUnknownFieldIsRefused(t *testing.T) {
	doctored := strings.Replace(string(minimalPlanJSON(t)), `"depends_on"`, `"dependsOn"`, 1)
	if _, err := parse([]byte(doctored)); err == nil {
		t.Fatal("a misspelled key must be refused, not silently dropped")
	}
}

// A gate does not take the statement of its own limits from the artifact it
// audits: rewriting `ceiling` to claim the gate checked sufficiency exited 0 and
// the gate printed the rewrite.
func TestTheCeilingIsNotAuthoredByThePlan(t *testing.T) {
	doctored := strings.Replace(string(minimalPlanJSON(t)),
		CeilingText, "This gate verifies that every done node's evidence is SUFFICIENT.", 1)
	if _, err := parse([]byte(doctored)); err == nil {
		t.Fatal("a rewritten ceiling must be refused")
	}
}

// The cycle detector was attacked three ways and held; this pins all three, and
// the acyclic diamond that must stay silent.
func TestCyclesIncludingSelfAndThreeHop(t *testing.T) {
	root := repoRoot(t)
	self := &Graph{Nodes: []Node{{ID: "T-a", State: StateReady, DependsOn: []string{"T-a"}}}}
	if codes(Verify(root, self))["DEPENDENCY_CYCLE"] != 1 {
		t.Error("a self-dependency is a cycle")
	}
	ev := []Evidence{{Kind: "path_exists", Path: "README.md"}}
	three := &Graph{Nodes: []Node{
		{ID: "T-a", State: StateDone, DependsOn: []string{"T-b"}, Evidence: ev},
		{ID: "T-b", State: StateDone, DependsOn: []string{"T-c"}, Evidence: ev},
		{ID: "T-c", State: StateDone, DependsOn: []string{"T-a"}, Evidence: ev},
	}}
	if codes(Verify(root, three))["DEPENDENCY_CYCLE"] == 0 {
		t.Error("a three-hop cycle among done nodes is still a cycle")
	}
	diamond := &Graph{Nodes: []Node{
		{ID: "T-top", State: StateDone, Evidence: ev},
		{ID: "T-l", State: StateDone, DependsOn: []string{"T-top"}, Evidence: ev},
		{ID: "T-r", State: StateDone, DependsOn: []string{"T-top"}, Evidence: ev},
		{ID: "T-join", State: StateReady, DependsOn: []string{"T-l", "T-r"}},
	}}
	if f := Verify(root, diamond); len(f) != 0 {
		t.Errorf("an acyclic diamond must be silent, got %v", f)
	}
}
