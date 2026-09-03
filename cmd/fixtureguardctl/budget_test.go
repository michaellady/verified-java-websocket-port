package main

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// rowsOf scans a source string as if it were a fixture file and renders the
// findings as the canonical rows.
func rowsOf(src string) []string {
	vs, _ := scanFile("inline.rs", src, nil)
	var out []string
	for _, v := range vs {
		out = append(out, v.Row())
	}
	sort.Strings(out)
	return out
}

// TestShapeCTellsTheTwoRolesApart pins the whole polarity fixture in test
// source as well as in the manifest, the way F004's and F005's rows are
// pinned: a reader grepping for `50_000` finds the claim next to the
// assertion.
func TestShapeCTellsTheTwoRolesApart(t *testing.T) {
	requireRows(t, "synthetic/production_budget_roles.rs", []string{
		"100|C|max_polls|9|false",
		"19|C|max_polls|50_000|false",
		"69|C|max_polls|2_000|false",
		"75|C|max_polls|250|false",
		"89|C|max_polls|8|true",
	})
}

// TestTheDiscriminatorIsTheAssertedOutcome is the discriminator's own RED, and
// it is the whole of residual 2's hard part in ten lines. The two fixtures are
// byte-identical apart from ONE assertion, and the verdict turns only on it:
// a test that asserts the budget's own exhaustion outcome is a test OF the
// budget, and a test that does not is guarding against a slow host.
func TestTheDiscriminatorIsTheAssertedOutcome(t *testing.T) {
	const guarding = `
#[test]
fn a_run_that_must_not_run_out() {
    let bounds = IoBounds { max_polls: 4_000, ..IoBounds::default() };
    drive(&bounds);
    assert_eq!(outcome(), LoopOutcome::WriteStalled);
}
`
	const measuring = `
#[test]
fn a_run_whose_budget_is_the_subject() {
    let bounds = IoBounds { max_polls: 4_000, ..IoBounds::default() };
    drive(&bounds);
    assert_eq!(outcome(), LoopOutcome::BudgetExhausted);
}
`
	if got := rowsOf(guarding); len(got) != 1 || !strings.HasSuffix(got[0], "|C|max_polls|4_000|false") {
		t.Fatalf("a liveness supply must fire, got %v", got)
	}
	if got := rowsOf(measuring); len(got) != 0 {
		t.Fatalf("a test OF the budget must stay silent, got %v", got)
	}
}

// TestShapeCFollowsARenamedForwarderParameter: the rule keys on the ASSIGNMENT
// a helper makes, not on the name of the parameter it makes it from, so
// renaming the parameter does not dodge it.
func TestShapeCFollowsARenamedForwarderParameter(t *testing.T) {
	const src = `
fn renamed_bounds(turns: u64) -> IoBounds {
    IoBounds { max_polls: turns, ..IoBounds::default() }
}
#[test]
fn a_test() {
    drive(&renamed_bounds(250));
    assert!(saw_eof());
}
`
	got := rowsOf(src)
	if len(got) != 1 || !strings.HasSuffix(got[0], "|C|max_polls|250|false") {
		t.Fatalf("a renamed forwarder parameter must still be followed, got %v", got)
	}
}

// TestShapeCReadsTheForwardedPOSITION: a helper that takes the budget second
// must have its SECOND argument read, not its first.
func TestShapeCReadsTheForwardedPosition(t *testing.T) {
	const src = `
fn bounds_for(chunk: usize, turns: u64) -> IoBounds {
    IoBounds { write_chunk: chunk, max_polls: turns, ..IoBounds::default() }
}
#[test]
fn a_test() {
    drive(&bounds_for(4096, 250));
    assert!(saw_eof());
}
`
	got := rowsOf(src)
	if len(got) != 1 || !strings.HasSuffix(got[0], "|C|max_polls|250|false") {
		t.Fatalf("the forwarded position must be the one read, got %v", got)
	}
}

// TestShapeCIsSilentOnADerivedBudget: the remedy must not be condemned. A
// detector that also fires on the fix teaches people to disable it.
func TestShapeCIsSilentOnADerivedBudget(t *testing.T) {
	const src = `
fn derived(deadline: Duration) -> IoBounds {
    IoBounds { max_polls: polls_for(deadline, READ_TIMEOUT), ..IoBounds::default() }
}
#[test]
fn a_test() {
    drive(&derived(Duration::from_secs(20)));
    assert!(saw_eof());
}
`
	if got := rowsOf(src); len(got) != 0 {
		t.Fatalf("a budget derived from a stated duration is the remedy and must be silent, got %v", got)
	}
}

// TestBudgetAnchorsMustExist is the anti-rot check. A rule that reaches across
// a file boundary has to prove the far end still exists, or it becomes a rule
// about nothing while still reporting PASS.
func TestBudgetAnchorsMustExist(t *testing.T) {
	pb := productionBudgets[0]
	present := func(string) (string, error) {
		return "fn f() { " + pb.LoopText + " { } }\nenum LoopOutcome { " + pb.Outcome + " }\n", nil
	}
	if problems := verifyBudgetAnchors("", present); len(problems) != 0 {
		t.Fatalf("an intact anchor must raise nothing: %v", problems)
	}
	movedLoop := func(string) (string, error) {
		return "enum LoopOutcome { " + pb.Outcome + " }\n", nil
	}
	if problems := verifyBudgetAnchors("", movedLoop); len(problems) != 1 {
		t.Fatalf("a moved production loop must be reported exactly once: %v", problems)
	}
	renamedOutcome := func(string) (string, error) {
		return "fn f() { " + pb.LoopText + " { } }\n", nil
	}
	if problems := verifyBudgetAnchors("", renamedOutcome); len(problems) != 1 {
		t.Fatalf("a renamed exhaustion outcome must be reported: %v", problems)
	}
	missing := func(string) (string, error) { return "", errors.New("no such file") }
	if problems := verifyBudgetAnchors("", missing); len(problems) != 1 {
		t.Fatalf("an unreadable anchor must be reported: %v", problems)
	}
}

// TestProductionAnchorsAreRealHere runs the same check against the live tree,
// so the declaration in budget.go is a claim about THIS repository and not
// documentation.
func TestProductionAnchorsAreRealHere(t *testing.T) {
	root := "../.."
	problems := verifyBudgetAnchors(root, func(rel string) (string, error) {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		return string(data), err
	})
	if len(problems) != 0 {
		t.Fatalf("the production budget table must match the tree: %v", problems)
	}
}

// TestBudgetWaiversHaveTheirOwnCeiling: admitting a shape-C backlog must never
// raise the ceiling on shapes A and B. The two counts are separate, and the
// failure names which one was breached.
func TestBudgetWaiversHaveTheirOwnCeiling(t *testing.T) {
	waived := `
#[test]
fn a_test() {
    // FIXTURE-COUNT-GUARD-ALLOWED: the wall-clock form of this bound has not landed yet
    let bounds = IoBounds { max_polls: 4_000, ..IoBounds::default() };
    drive(&bounds);
    assert_eq!(outcome(), LoopOutcome::WriteStalled);
}
`
	root := fakeRoot(t, map[string]string{
		"rust/ws-x/tests/waived.rs": waived,
		"rust/ws-x/tests/aloop.rs":  cleanFixture,
	})
	code, out := invoke(t, "-root", root)
	if code == 0 {
		t.Fatalf("a shape-C waiver over the default ceiling of 0 must fail:\n%s", out)
	}
	if !strings.Contains(out, "budget_waivers=1") || !strings.Contains(out, "shape-C waiver(s) present") {
		t.Fatalf("the failure must count shape-C waivers separately and name them:\n%s", out)
	}
	if code, out := invoke(t, "-root", root, "-max-waivers", "5"); code == 0 {
		t.Fatalf("raising the shape A/B ceiling must NOT admit a shape-C waiver:\n%s", out)
	}
	code, out = invoke(t, "-root", root, "-max-budget-waivers", "1")
	if code != 0 {
		t.Fatalf("a shape-C waiver within its own declared ceiling must pass; got exit %d\n%s", code, out)
	}
}

// TestShapeCFiresEndToEnd is the process-level RED: a tree whose only defect is
// a fixture-supplied production budget must make the gate exit nonzero.
func TestShapeCFiresEndToEnd(t *testing.T) {
	const supplied = `
#[test]
fn a_test() {
    let bounds = IoBounds { max_polls: 50_000, ..IoBounds::default() };
    drive(&bounds);
    assert_eq!(outcome(), LoopOutcome::WriteStalled);
}
`
	root := fakeRoot(t, map[string]string{
		"rust/ws-x/tests/supplied.rs": supplied,
		"rust/ws-x/tests/aloop.rs":    cleanFixture,
	})
	code, out := invoke(t, "-root", root)
	if code != 1 {
		t.Fatalf("a fixture-supplied production budget must exit 1, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "shape=C counter=max_polls bound=50_000") {
		t.Fatalf("the report must name the field and the value:\n%s", out)
	}
	if !strings.Contains(out, "while report.polls < bounds.max_polls") {
		t.Fatalf("the remedy must name the production loop the number reaches:\n%s", out)
	}
}

// TestAnchorlessTreeIsRefused is the anti-rot check at PROCESS level: a
// repository whose production loop bound has gone must fail the gate, not pass
// it silently with a rule that now points at nothing.
func TestAnchorlessTreeIsRefused(t *testing.T) {
	pb := productionBudgets[0]
	root := fakeRoot(t, map[string]string{
		"rust/ws-x/tests/aloop.rs": cleanFixture,
		pb.Anchor:                  "fn drive() {\n    while forever() {\n    }\n}\n",
	})
	code, out := invoke(t, "-root", root)
	if code != 1 {
		t.Fatalf("a tree whose production budget loop has moved must exit 1, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "step=budget-anchors result=FAIL") {
		t.Fatalf("the failure must name the anchor step:\n%s", out)
	}
	if !strings.Contains(out, "points at nothing") {
		t.Fatalf("the failure must say what rotted:\n%s", out)
	}
}
