package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is two directories up from cmd/recordguardctl.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(filepath.Dir(wd))
}

// TestPolarityManifestComesOutAsDeclared is the whole claim of this tool, run
// against records extracted verbatim from git. The div05 stub F009 was filed
// about MUST fire; the 552-line record the same branch eventually carried on the
// SAME PATH must stay silent.
func TestPolarityManifestComesOutAsDeclared(t *testing.T) {
	root := repoRoot(t)
	m, err := loadManifest(root)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	firing, silent := 0, 0
	for _, c := range m.Cases {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(selfcheckRel), filepath.FromSlash(c.Path)))
		if err != nil {
			t.Fatalf("fixture %s: %v", c.Path, err)
		}
		if c.mustFire() {
			firing++
		} else {
			silent++
		}
		got := Rows(Scan(string(src)))
		if diff := rowDiff(got, c.Expect); diff != "" {
			t.Errorf("%s: %s\n  why: %s", c.Path, diff, c.Why)
		}
	}
	if firing == 0 || silent == 0 {
		t.Fatalf("the self-check needs both polarities: firing=%d silent=%d", firing, silent)
	}
	t.Logf("polarity: %d cases, %d must fire, %d must stay silent", len(m.Cases), firing, silent)
}

// TestTheMotivatingInstanceIsInTheManifest refuses a manifest that has quietly
// dropped the record this tool was built for. Without this, the polarity test
// stays green after someone deletes the one case that matters.
func TestTheMotivatingInstanceIsInTheManifest(t *testing.T) {
	root := repoRoot(t)
	m, err := loadManifest(root)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	const stubBlob = "359940cd6fa37cf158ac603fe19803724bf9578f"
	const finalBlob = "6928ddfb6e61772b8bc036ba39f20726cc4ffce4"
	var haveStub, haveFinal bool
	for _, c := range m.Cases {
		if strings.Contains(c.Provenance, stubBlob) {
			haveStub = true
			if !c.mustFire() {
				t.Errorf("the div05 stub is declared SILENT; it is the instance F009 was filed about and it must fire")
			}
		}
		if strings.Contains(c.Provenance, finalBlob) {
			haveFinal = true
			if c.mustFire() {
				t.Errorf("the finished div05 record is declared FIRING; the tool would be punishing a completed review")
			}
		}
	}
	if !haveStub {
		t.Errorf("no case cites blob %s (drafts/self-review/div05-close-overtakes-echo.md at 755b8c8): the motivating instance is gone", stubBlob)
	}
	if !haveFinal {
		t.Errorf("no case cites blob %s (the same path, finished): the differential is gone", finalBlob)
	}
}

// TestEverySignalKindIsExercisedByAFixture refuses a discriminator whose signal
// no committed record proves. A rule with no fixture behind it is an assertion.
func TestEverySignalKindIsExercisedByAFixture(t *testing.T) {
	root := repoRoot(t)
	m, err := loadManifest(root)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	seen := map[string]string{}
	for _, c := range m.Cases {
		for _, row := range c.Expect {
			parts := strings.SplitN(row, "|", 3)
			if len(parts) == 3 {
				seen[parts[1]] = c.Path
			}
		}
	}
	for _, kind := range signalKinds {
		if _, ok := seen[kind]; !ok {
			t.Errorf("signal %q is implemented but no fixture in the manifest declares it: nothing proves it fires", kind)
		}
	}
	for kind, path := range seen {
		t.Logf("signal %-18s proved by %s", kind, path)
	}
}

// TestQuotingAStubDoesNotMakeARecordAStub is the sharpest negative control the
// corpus has: F009 quotes the div05 stub's exact words. If the discriminator
// matched vocabulary rather than voice, it would refuse the finding that
// motivated it.
func TestQuotingAStubDoesNotMakeARecordAStub(t *testing.T) {
	root := repoRoot(t)
	p := filepath.Join(root, filepath.FromSlash(selfcheckRel), "real", "F009-quotes-the-stub.md")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := string(data)
	for _, want := range []string{"STATUS: IN PROGRESS", "Nothing verified yet"} {
		if !strings.Contains(src, want) {
			t.Fatalf("the control no longer contains %q; it has stopped being a control", want)
		}
	}
	if sigs := Scan(src); len(sigs) != 0 {
		t.Errorf("F009 quotes a stub and is a finished record, but the discriminator fired: %v", Rows(sigs))
	}
	// And the same words, unquoted, in the tool's own voice, must fire.
	bare := "# a record\n\nSTATUS: IN PROGRESS\n\nNothing verified yet.\n"
	if sigs := Scan(bare); len(sigs) == 0 {
		t.Errorf("the same words unquoted did not fire: quote-awareness has swallowed the signal entirely")
	}
}

// TestLengthIsNotTheDiscriminator pins the calibration finding that a length
// threshold is impossible here: the shortest real record in the tree is SHORTER
// than five of the six historical stubs.
func TestLengthIsNotTheDiscriminator(t *testing.T) {
	root := repoRoot(t)
	read := func(rel string) string {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(selfcheckRel), filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(data)
	}
	shortReal := read("real/F001-shortest-real-record.md")
	longStub := read("history/catalog-plane-correspondence-WIP.md")
	realLines := strings.Count(shortReal, "\n")
	stubLines := strings.Count(longStub, "\n")
	if realLines >= stubLines {
		t.Fatalf("the corpus no longer demonstrates the overlap: real=%d lines, unfinished=%d lines", realLines, stubLines)
	}
	if sigs := Scan(shortReal); len(sigs) != 0 {
		t.Errorf("the %d-line REAL record fired: %v", realLines, Rows(sigs))
	}
	if sigs := Scan(longStub); len(sigs) == 0 {
		t.Errorf("the %d-line UNFINISHED record stayed silent", stubLines)
	}
	t.Logf("length overlap confirmed: finished record %d lines, unfinished record %d lines", realLines, stubLines)
}

// TestTheStatusPrefixCanNeverCarryATerm converts deletion attack A9 from an
// unexplained survivor into a measured equivalence. A9 replaces the status
// signal's read of the field's VALUE with a read of the whole line, and no
// fixture catches it. The reason is that the text statusRe consumes before the
// value — optional whitespace, the decoration characters #*_+- , the literal
// word "status", and the colon — can never contain a lexicon term as a whole
// word. This test measures that over every status line in every fixture, and
// over the decoration alphabet directly, so the equivalence is checked rather
// than believed. If statusRe is ever loosened to allow words before the colon,
// this fails and A9 stops being an equivalent mutant.
func TestTheStatusPrefixCanNeverCarryATerm(t *testing.T) {
	root := repoRoot(t)
	m, err := loadManifest(root)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	checked := 0
	check := func(where, line string) {
		loc := statusRe.FindStringIndex(line)
		if loc == nil {
			return
		}
		checked++
		if terms := matchTerms(line[:loc[1]], unfinishedTerms); len(terms) != 0 {
			t.Errorf("%s: the status PREFIX %q carries lexicon terms %v — reading the whole line instead of the value is no longer equivalent, and the value-read now needs its own fixture",
				where, line[:loc[1]], terms)
		}
	}
	for _, c := range m.Cases {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(selfcheckRel), filepath.FromSlash(c.Path)))
		if err != nil {
			t.Fatalf("fixture %s: %v", c.Path, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			check(c.Path, line)
		}
	}
	// Every prefix the pattern admits, built directly from its alphabet.
	for _, deco := range []string{"", "  ", "#", "##", "**", "__", "- ", "+ ", " * ", "  ###  "} {
		for _, word := range []string{"status", "Status", "STATUS", "StAtUs"} {
			for _, gap := range []string{"", " ", "  "} {
				check("synthesised", deco+word+gap+": IN PROGRESS")
			}
		}
	}
	if checked == 0 {
		t.Fatal("no status line was examined: this test proved nothing")
	}
	t.Logf("status prefixes examined: %d, none can carry a lexicon term", checked)
}
