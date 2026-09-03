package portplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A byte difference OUTSIDE the declarations must not be reported as a
// declaration difference. The check is a whole-file byte compare, so its
// message must say what actually differs instead of naming the nearest story.
func TestReproductionMismatchNamesWhatActuallyDiffers(t *testing.T) {
	committed, err := os.ReadFile(filepath.Join(repoRoot, EvidenceDirectory, OracleEvidenceDocument))
	if err != nil {
		t.Fatalf("read committed oracle: %v", err)
	}
	// Change ONLY the jdk_vendor line. Every declaration stays byte-identical.
	altered := strings.Replace(string(committed),
		`"jdk_vendor": "Homebrew"`, `"jdk_vendor": "Eclipse Adoptium"`, 1)
	if altered == string(committed) {
		t.Fatal("fixture assumption broken: no jdk_vendor line to alter")
	}
	msg := describeOracleMismatch([]byte(altered), committed, "oracle.json")

	if strings.Contains(msg, "the committed declarations are not what the compiler derives") {
		t.Errorf("a one-line vendor difference is reported as declaration drift:\n%s", msg)
	}
	if !strings.Contains(msg, "jdk_vendor") {
		t.Errorf("the message does not name the line that actually differs:\n%s", msg)
	}
	if !strings.Contains(msg, "differing_lines=1") {
		t.Errorf("the message does not report how many lines differ:\n%s", msg)
	}
}

// The bounded-naming branch must actually be reachable and must account for
// every differing line, so a large drift cannot be read as a small one.
func TestReproductionMismatchBoundsWhatItNamesAndCountsTheRest(t *testing.T) {
	committed := []byte("a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n")
	regenerated := []byte("A\nB\nC\nD\nE\nF\nG\nH\nI\nJ\n")

	msg := describeOracleMismatch(regenerated, committed, "oracle.json")

	if !strings.Contains(msg, "differing_lines=10") {
		t.Errorf("all ten differing lines must be counted:\n%s", msg)
	}
	if !strings.Contains(msg, "and 4 further differing line(s) not shown") {
		t.Errorf("the unshown remainder must be stated, not silently dropped:\n%s", msg)
	}
	if strings.Count(msg, "committed \"") != 6 {
		t.Errorf("exactly six lines should be named, got %d:\n%s",
			strings.Count(msg, "committed \""), msg)
	}
}

// A report that gained or lost lines entirely must not be reported as equal on
// those lines: a missing line is a difference, not an absence of one.
func TestReproductionMismatchTreatsLengthChangeAsDifference(t *testing.T) {
	committed := []byte("same\nsame\nextra\n")
	regenerated := []byte("same\nsame\n")

	msg := describeOracleMismatch(regenerated, committed, "oracle.json")

	if !strings.Contains(msg, "differing_lines=1") {
		t.Errorf("a line present in one report and absent in the other must count:\n%s", msg)
	}
	if !strings.Contains(msg, "extra") {
		t.Errorf("the message must name the line that went missing:\n%s", msg)
	}
}
