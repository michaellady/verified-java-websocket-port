package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func planWith(nodes []Node, actions []OwnerAction, retired []Retirement) *Graph {
	return &Graph{
		SchemaVersion: "1",
		Statement:     "test plan",
		Ceiling:       CeilingText,
		Nodes:         nodes,
		OwnerActions:  actions,
		Retired:       retired,
	}
}

func doneNode(id string) Node {
	return Node{ID: id, Title: id, State: StateDone, DependsOn: []string{}, BlockedBy: []string{},
		Evidence: []Evidence{{Kind: "path_exists", Path: TaskGraphPath}}}
}

// commitPlan writes each version in turn and commits it, returning the repo.
func commitPlan(t *testing.T, versions ...*Graph) string {
	t.Helper()
	root := t.TempDir()
	git(t, root, "init", "-q", "-b", "main")
	git(t, root, "config", "user.email", "gate@example.invalid")
	git(t, root, "config", "user.name", "gate")
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(TaskGraphPath)), 0o755); err != nil {
		t.Fatal(err)
	}
	for i, g := range versions {
		g.Statement = fmt.Sprintf("test plan v%d", i) // each version must differ to commit
		writePlan(t, root, g)
		git(t, root, "add", "-A")
		git(t, root, "commit", "-q", "-m", fmt.Sprintf("plan v%d", i))
	}
	return root
}

func writePlan(t *testing.T, root string, g *Graph) {
	t.Helper()
	raw, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, TaskGraphPath), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The rule this file exists for. Before it, deleting all 11 `blocked` nodes gave
// `nodes=20 ... result=PASS`: every other rule is satisfied by the survivors, so
// a plan could be emptied of its obligations one commit at a time.
func TestADroppedNodeIsRefused(t *testing.T) {
	root := commitPlan(t,
		planWith([]Node{doneNode("T-a"), doneNode("T-b")}, nil, nil),
		planWith([]Node{doneNode("T-a")}, nil, nil))
	got := codes(checkHistory(root))
	if got["NODE_DISAPPEARED"] != 1 {
		t.Fatalf("dropping a committed node must be refused, got %v", got)
	}
}

// The opposite direction, which matters as much: a plan that drops nothing is
// silent. A rule that fires on the live plan would be worthless.
func TestAPlanThatDropsNothingIsSilent(t *testing.T) {
	root := commitPlan(t,
		planWith([]Node{doneNode("T-a")}, nil, nil),
		planWith([]Node{doneNode("T-a"), doneNode("T-b")}, nil, nil))
	if f := checkHistory(root); len(f) != 0 {
		t.Fatalf("adding a node must be silent, got %v", f)
	}
}

func TestADroppedOwnerActionIsRefused(t *testing.T) {
	oa := OwnerAction{ID: "OA-x", State: OwnerOpen, Needed: "rule on x", Blocking: "it blocks x"}
	root := commitPlan(t,
		planWith([]Node{doneNode("T-a")}, []OwnerAction{oa}, nil),
		planWith([]Node{doneNode("T-a")}, nil, nil))
	got := codes(checkHistory(root))
	if got["OWNER_ACTION_DISAPPEARED"] != 1 {
		t.Fatalf("dropping a committed owner action must be refused, got %v", got)
	}
}

// The sanctioned escape: a node may be retired, with a reason, and then it is
// gone legitimately. This is the declared-exemption shape used four times in
// this repository -- and the three tests after it are what stop it being a
// blanket bypass.
func TestARetiredNodeIsAccepted(t *testing.T) {
	root := commitPlan(t,
		planWith([]Node{doneNode("T-a"), doneNode("T-b")}, nil, nil),
		planWith([]Node{doneNode("T-a")}, nil,
			[]Retirement{{ID: "T-b", Kind: RetireNode, Reason: "folded into T-a"}}))
	if f := checkHistory(root); len(f) != 0 {
		t.Fatalf("a retired node with a reason must be accepted, got %v", f)
	}
}

// An exemption that outlives what it excused is stale. Without this the
// `retired` list becomes a permanent allowlist nobody prunes.
func TestARetirementForAPresentNodeIsStale(t *testing.T) {
	root := commitPlan(t,
		planWith([]Node{doneNode("T-a")}, nil, nil),
		planWith([]Node{doneNode("T-a")}, nil,
			[]Retirement{{ID: "T-a", Kind: RetireNode, Reason: "gone"}}))
	got := codes(checkHistory(root))
	if got["STALE_RETIREMENT"] != 1 {
		t.Fatalf("retiring a node the plan still carries must be refused, got %v", got)
	}
}

// And a retirement for an id no committed plan ever declared is fiction: it
// would otherwise let someone pre-authorise the removal of a node they are
// about to add.
func TestARetirementForAnIDGitNeverSawIsRefused(t *testing.T) {
	root := commitPlan(t,
		planWith([]Node{doneNode("T-a")}, nil, nil),
		planWith([]Node{doneNode("T-a")}, nil,
			[]Retirement{{ID: "T-never", Kind: RetireNode, Reason: "tidy"}}))
	got := codes(checkHistory(root))
	if got["FICTIONAL_RETIREMENT"] != 1 {
		t.Fatalf("retiring an id git never saw must be refused, got %v", got)
	}
}

func TestARetirementMustGiveAReasonAndAResolvableSuccessor(t *testing.T) {
	root := commitPlan(t,
		planWith([]Node{doneNode("T-a"), doneNode("T-b")}, nil, nil),
		planWith([]Node{doneNode("T-a")}, nil,
			[]Retirement{{ID: "T-b", Kind: RetireNode, Reason: "  ", SupersededBy: "T-nowhere"}}))
	got := codes(checkHistory(root))
	if got["RETIREMENT_WITHOUT_REASON"] != 1 || got["DANGLING_SUCCESSOR"] != 1 {
		t.Fatalf("a reasonless retirement naming a successor that does not exist must be refused twice, got %v", got)
	}
}

func TestARetirementOfAnUnknownKindIsRefused(t *testing.T) {
	root := commitPlan(t,
		planWith([]Node{doneNode("T-a"), doneNode("T-b")}, nil, nil),
		planWith([]Node{doneNode("T-a")}, nil,
			[]Retirement{{ID: "T-b", Kind: "whatever", Reason: "tidy"}}))
	got := codes(checkHistory(root))
	if got["RETIREMENT_UNKNOWN_KIND"] != 1 || got["NODE_DISAPPEARED"] != 1 {
		t.Fatalf("an unrecognised kind must not excuse the disappearance, got %v", got)
	}
}

// An unreadable source is a REFUSAL, not a skip -- the same rule the governance
// mirror states for an unreachable protected store. A check that quietly does
// nothing when its source is missing is a check removed by removing the source.
func TestUnreadableHistoryIsRefusedNotSkipped(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(TaskGraphPath)), 0o755); err != nil {
		t.Fatal(err)
	}
	writePlan(t, root, planWith([]Node{doneNode("T-a")}, nil, nil))
	got := codes(checkHistory(root))
	if got["PLAN_HISTORY_UNREADABLE"] != 1 {
		t.Fatalf("a plan with no readable history must be refused, got %v", got)
	}
}

// The realistic attack, and the reason historyComplete exists: THIS checkout is
// shallow (`git rev-parse --is-shallow-repository` is true) and
// actions/checkout@v4 defaults to fetch-depth 1. In a clone whose boundary cuts
// the plan's origin off, "no committed version ever declared that id" is a guess.
func TestTruncatedHistoryIsRefused(t *testing.T) {
	origin := commitPlan(t,
		planWith([]Node{doneNode("T-a"), doneNode("T-b")}, nil, nil),
		planWith([]Node{doneNode("T-a"), doneNode("T-b")}, nil, nil),
		planWith([]Node{doneNode("T-a")}, nil, nil))

	shallow := filepath.Join(t.TempDir(), "shallow")
	out, err := exec.Command("git", "clone", "-q", "--depth", "1",
		"file://"+origin, shallow).CombinedOutput()
	if err != nil {
		t.Skipf("cannot make a shallow clone here: %v\n%s", err, out)
	}
	// The deletion is real and the deep clone catches it...
	if codes(checkHistory(origin))["NODE_DISAPPEARED"] != 1 {
		t.Fatalf("the origin must see the dropped node")
	}
	// ...but the shallow clone cannot see the version that declared T-b, so it
	// must refuse rather than report the plan as intact.
	got := codes(checkHistory(shallow))
	if got["PLAN_HISTORY_TRUNCATED"] != 1 {
		t.Fatalf("a truncated history must be refused, got %v", got)
	}
	if got["NODE_DISAPPEARED"] != 0 {
		t.Fatalf("a truncated history must not also guess at disappearances, got %v", got)
	}
}

// The honest positive case, and the shape of THIS checkout: a shallow clone
// whose graft point sits BELOW the commit that added the plan still contains
// every version of the plan, so it is accepted. That is why the check asks
// where the boundary falls rather than whether the clone is shallow at all.
//
// The case that cannot be accepted is a graft point that IS the plan's oldest
// commit: a graft's parents are unknowable by construction, so "no earlier
// version declared that id" is unprovable there and the rule fails closed.
func TestAShallowCloneDeepEnoughToHoldThePlansOriginIsAccepted(t *testing.T) {
	origin := t.TempDir()
	git(t, origin, "init", "-q", "-b", "main")
	git(t, origin, "config", "user.email", "gate@example.invalid")
	git(t, origin, "config", "user.name", "gate")
	if err := os.MkdirAll(filepath.Join(origin, filepath.Dir(TaskGraphPath)), 0o755); err != nil {
		t.Fatal(err)
	}
	// One commit before the plan exists, so the graft can land below it.
	if err := os.WriteFile(filepath.Join(origin, "README"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, origin, "add", "-A")
	git(t, origin, "commit", "-q", "-m", "before the plan")
	for i, g := range []*Graph{
		planWith([]Node{doneNode("T-a")}, nil, nil),
		planWith([]Node{doneNode("T-a"), doneNode("T-b")}, nil, nil),
	} {
		g.Statement = fmt.Sprintf("test plan v%d", i)
		writePlan(t, origin, g)
		git(t, origin, "add", "-A")
		git(t, origin, "commit", "-q", "-m", fmt.Sprintf("plan v%d", i))
	}

	shallow := filepath.Join(t.TempDir(), "shallow")
	out, err := exec.Command("git", "clone", "-q", "--depth", "3",
		"file://"+origin, shallow).CombinedOutput()
	if err != nil {
		t.Skipf("cannot make a shallow clone here: %v\n%s", err, out)
	}
	if f := checkHistory(shallow); len(f) != 0 {
		t.Fatalf("a shallow clone containing the plan's origin must be accepted, got %v", f)
	}
}
