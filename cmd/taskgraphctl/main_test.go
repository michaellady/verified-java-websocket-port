package main

import (
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
