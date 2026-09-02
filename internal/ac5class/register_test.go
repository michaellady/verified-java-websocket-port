package ac5class

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is this package's two-levels-up directory. The tests read the real
// PRD and the real rust/ sources: a register that no longer matches the
// shipped tree must fail here, not in a comment.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	return root
}

func TestTheSevenClassesComeFromThePRDAndNotFromThisFile(t *testing.T) {
	classes, err := ClassesFromPRD(repoRoot(t))
	if err != nil {
		t.Fatalf("parsing the US-020 AC5 clause: %v", err)
	}
	want := []string{
		"Java-quirk emulation", "Rust semantic defect", "event-order", "error-class",
		"close-initiator", "consumed-byte", "normalization-collision",
	}
	if len(classes) != len(want) {
		t.Fatalf("US-020 AC5 names %d classes %q, this test expects %d", len(classes), classes, len(want))
	}
	for i := range want {
		if classes[i] != want[i] {
			t.Fatalf("class %d is %q, want %q — if the PRD changed, the register must change with it",
				i, classes[i], want[i])
		}
	}
}

func TestTheRegisterIsClassCompleteAndEverySiteResolves(t *testing.T) {
	if problems := Verify(repoRoot(t)); len(problems) > 0 {
		for _, p := range problems {
			t.Errorf("US-020 AC5 class register: %s", p)
		}
	}
}

// TestEveryClassHasASeededVariant is the property the whole package exists
// for, stated on its own so its failure message names the missing class.
func TestEveryClassHasASeededVariant(t *testing.T) {
	classes, err := ClassesFromPRD(repoRoot(t))
	if err != nil {
		t.Fatalf("%v", err)
	}
	covered := map[string][]string{}
	for _, v := range Register() {
		covered[v.Class] = append(covered[v.Class], v.ID)
	}
	for _, c := range classes {
		if len(covered[c]) == 0 {
			t.Errorf("US-020 AC5 class %q has no seeded variant", c)
		}
	}
}

// --- the check's own ability to fail ---------------------------------------
//
// A check nobody has watched fail is an assertion. These four hand
// VerifyRegister a register that has lost exactly one property and assert it
// says so, naming the property.

func TestVerifyFailsWhenAClassLosesItsSeededVariant(t *testing.T) {
	root := repoRoot(t)
	full := Register()
	for _, dropped := range []string{"normalization-collision", "error-class", "close-initiator"} {
		var reduced []Variant
		for _, v := range full {
			if v.Class != dropped {
				reduced = append(reduced, v)
			}
		}
		problems := VerifyRegister(root, reduced)
		if !anyContains(problems, "class "+quote(dropped)+" has NO seeded variant") {
			t.Errorf("dropping every %q variant produced %v, expected an uncovered-class problem",
				dropped, problems)
		}
	}
}

func TestVerifyFailsWhenASeededSiteDriftsOutOfTheTree(t *testing.T) {
	root := repoRoot(t)
	reduced := append([]Variant(nil), Register()...)
	reduced[0].Match = reduced[0].Match + " // a literal that is not in the shipped tree"
	problems := VerifyRegister(root, reduced)
	if !anyContains(problems, "not found") {
		t.Errorf("a drifted site produced %v, expected a not-found problem", problems)
	}
}

func TestVerifyFailsWhenAVariantStopsDiscriminatingWithoutRegisteringTheCollision(t *testing.T) {
	root := repoRoot(t)
	reduced := append([]Variant(nil), Register()...)
	for i := range reduced {
		if len(reduced[i].Discriminates) > 0 {
			reduced[i].Discriminates = nil
			break
		}
	}
	problems := VerifyRegister(root, reduced)
	if !anyContains(problems, "no collision is registered") {
		t.Errorf("a silently non-discriminating variant produced %v, expected a collision problem",
			problems)
	}
}

func TestVerifyFailsWhenACollisionSeedHasNoOutOfBandWitness(t *testing.T) {
	root := repoRoot(t)
	reduced := append([]Variant(nil), Register()...)
	found := false
	for i := range reduced {
		if reduced[i].Collision != nil {
			c := *reduced[i].Collision
			c.Witness.MustFail = ""
			reduced[i].Collision = &c
			found = true
			break
		}
	}
	if !found {
		t.Fatal("the register has no collision seed to attack")
	}
	problems := VerifyRegister(root, reduced)
	if !anyContains(problems, "cannot be told apart from an equivalent mutant") {
		t.Errorf("a witnessless collision produced %v, expected a witness problem", problems)
	}
}

func TestVerifyFailsWhenTheDetectorIsNamedBySuiteInsteadOfByTest(t *testing.T) {
	root := repoRoot(t)
	reduced := append([]Variant(nil), Register()...)
	reduced[0].Detector.MustFail = ""
	problems := VerifyRegister(root, reduced)
	if !anyContains(problems, "no named detector") {
		t.Errorf("an unnamed detector produced %v, expected a named-detector problem", problems)
	}
}

// TestVerifyFailsWhenThePRDGrowsAnEighthClass proves the register is bound to
// the PRD text rather than to a retyped copy of it: an eighth class added to
// the clause must fail until it is seeded.
func TestVerifyFailsWhenThePRDGrowsAnEighthClass(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, PRDPath))
	if err != nil {
		t.Fatalf("%v", err)
	}
	const original = "consumed-byte, and normalization-collision variants are detected."
	const grown = "consumed-byte, normalization-collision, and mask-key-leak variants are detected."
	if !strings.Contains(string(raw), original) {
		t.Fatalf("%s no longer contains the AC5 clause this test doctors", PRDPath)
	}
	fake := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fake, filepath.Dir(PRDPath)), 0o755); err != nil {
		t.Fatalf("%v", err)
	}
	doctored := strings.Replace(string(raw), original, grown, 1)
	if err := os.WriteFile(filepath.Join(fake, PRDPath), []byte(doctored), 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	// The rust/ sources are linked so site resolution still works and the ONLY
	// difference from the real root is the eighth class.
	if err := os.Symlink(filepath.Join(root, "rust"), filepath.Join(fake, "rust")); err != nil {
		t.Fatalf("%v", err)
	}
	classes, err := ClassesFromPRD(fake)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(classes) != 8 {
		t.Fatalf("the doctored clause parsed to %d classes %q, want 8", len(classes), classes)
	}
	problems := VerifyRegister(fake, Register())
	if !anyContains(problems, "mask-key-leak") {
		t.Errorf("an eighth PRD class produced %v, expected an uncovered-class problem naming it",
			problems)
	}
}

// TestRejectedBindingsRecordWhatWasTestedAndRejected keeps the negative
// results present: the audit finding being closed is "an operator exists"
// standing in for "the class is detected", and the only defence against
// reintroducing it one level up is a written record of what was measured and
// found wanting.
func TestRejectedBindingsRecordWhatWasTestedAndRejected(t *testing.T) {
	classes, err := ClassesFromPRD(repoRoot(t))
	if err != nil {
		t.Fatalf("%v", err)
	}
	declared := map[string]bool{}
	for _, c := range classes {
		declared[c] = true
	}
	if len(RejectedBindings()) == 0 {
		t.Fatal("no rejected binding is recorded")
	}
	for _, r := range RejectedBindings() {
		if !declared[r.Class] {
			t.Errorf("rejected binding %s names class %q, which US-020 AC5 does not", r.MutantID, r.Class)
		}
		if strings.TrimSpace(r.Reason) == "" {
			t.Errorf("rejected binding %s has no reason", r.MutantID)
		}
	}
	// The three classes the criteria audit called implicit must each carry at
	// least one measured rejection or one registered variant with a measured
	// field set — never a bare claim.
	for _, c := range []string{"error-class", "close-initiator", "consumed-byte"} {
		rejected := 0
		for _, r := range RejectedBindings() {
			if r.Class == c {
				rejected++
			}
		}
		bound := 0
		for _, v := range Register() {
			if v.Class == c && len(v.Discriminates) > 0 {
				bound++
			}
		}
		if rejected == 0 && bound == 0 {
			t.Errorf("class %q carries neither a measured rejection nor a discriminating variant", c)
		}
	}
}

// TestEveryJavaQuirkSeedCitesTheLedgerRecordThatRefusesTheQuirk keeps the
// Java-quirk-emulation class bound to the ledger rather than to a reviewer's
// memory: a seed that emulates a quirk nothing recorded a decision about is
// not evidence for this class.
func TestEveryJavaQuirkSeedCitesTheLedgerRecordThatRefusesTheQuirk(t *testing.T) {
	citations := LedgerCitations()
	for _, v := range Register() {
		if v.Class != "Java-quirk emulation" {
			continue
		}
		citation, ok := citations[v.ID]
		if !ok {
			t.Errorf("%s emulates a Java quirk and cites no behavior-delta ledger record", v.ID)
			continue
		}
		if citation.Sequence <= 0 || !strings.HasPrefix(citation.SubjectRef, "semantic:") {
			t.Errorf("%s cites an unusable ledger record %+v", v.ID, citation)
		}
	}
}

func anyContains(problems []string, needle string) bool {
	for _, p := range problems {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}

func quote(s string) string { return "\"" + s + "\"" }
