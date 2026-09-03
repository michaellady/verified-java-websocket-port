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

// TestAQuotationThatWrapsALineBreakStaysMasked pins a false positive found by
// running the tool on its OWN record. That record quotes F009 quoting the div05
// stub, and the closing backtick lands on the following line; with per-line
// masking the trailing fragment `... Nothing verified yet."*` was read as the
// record's own voice and a finished record was refused (exit 1, signal
// void-self-report at line 81). An inline span may wrap one line break but never
// a blank line, so the open closer is carried across lines and dropped at a
// blank line.
func TestAQuotationThatWrapsALineBreakStaysMasked(t *testing.T) {
	wrapped := "# a finished record — the differential closed\n\n" +
		"STATUS: COMPLETE.\n\n" +
		"F009 quotes the stub verbatim: `*\"STATUS: IN PROGRESS — stub pushed early to survive\n" +
		"container restarts. … Nothing verified yet.\"*`. That is a quotation, not this record.\n\n" +
		"`make -C rust gates` exit 0 at 4a2b9c6.\n"
	if sigs := Scan(wrapped); len(sigs) != 0 {
		t.Errorf("a quotation wrapping a line break was read as the record's own voice: %v", Rows(sigs))
	}
	// The carry must be dropped at a blank line, or one stray quote would mask
	// the remainder of the record and swallow every later signal.
	strayThenReal := "# a record — notes\n\n" +
		"An unbalanced \" opens here and is never closed on this line.\n\n" +
		"STATUS: IN PROGRESS.\n\n" +
		"`cited` at 4a2b9c6.\n"
	sigs := Scan(strayThenReal)
	if len(sigs) == 0 {
		t.Fatalf("a stray quote masked the rest of the record: the status declaration after the blank line was never read")
	}
	if sigs[0].Kind != "declared-status" || sigs[0].Line != 5 {
		t.Errorf("want declared-status at line 5, got %s at line %d", sigs[0].Kind, sigs[0].Line)
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

// TestSupersessionIsReadFromTheRecordAndVerifiedAgainstItsTarget: a record that
// declares itself superseded is a DIFFERENT state from one that is merely
// unfinished, and the difference matters because reading the first as the second
// invites exactly the mistake F009 filed — treating a deliberately retained
// document as work still to do. I made that mistake myself on
// normalization-collision-audit-WIP.md, whose own last lines say "**SUPERSEDED**
// by ...", and very nearly instructed an agent to rename or delete it.
//
// The declaration alone must NOT be enough. If saying "superseded by X" were
// sufficient, it would be a self-declared escape from the unfinished state, and
// this tool's whole measured ceiling is that self-declarations bind honest
// authors and nothing else. So the target must exist AND must itself read
// finished: you cannot escape by pointing at another stub.
func TestSupersessionIsReadFromTheRecordAndVerifiedAgainstItsTarget(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	finished := write("landing.md", `# Landing record

Ran `+"`make -C rust gates`"+` exit 0 at commit abc1234, digest
sha256:0000000000000000000000000000000000000000000000000000000000000000,
observed at rust/ws-core/src/lib.rs::thing. Nothing outstanding.
`)
	stub := write("other-stub.md", "# Other — WORK IN PROGRESS\n\nStatus: WIP\n")

	cases := []struct {
		name       string
		body       string
		wantTarget string
		wantOK     bool
	}{
		{
			name:       "declared and the target reads finished",
			body:       "# A — WORK IN PROGRESS\n\nStatus: WIP\n\n**SUPERSEDED** by `landing.md`.\n",
			wantTarget: "landing.md",
			wantOK:     true,
		},
		{
			name:   "declared but the target does not exist",
			body:   "# A — WORK IN PROGRESS\n\nStatus: WIP\n\n**SUPERSEDED** by `no-such-file.md`.\n",
			wantOK: false,
		},
		{
			name:   "declared but the target is itself a stub",
			body:   "# A — WORK IN PROGRESS\n\nStatus: WIP\n\n**SUPERSEDED** by `other-stub.md`.\n",
			wantOK: false,
		},
		{
			name:   "no declaration at all",
			body:   "# A — WORK IN PROGRESS\n\nStatus: WIP\n",
			wantOK: false,
		},
		{
			// NOTE: this case passes on the regex anchor alone — a leading `>`
			// is not in the allowed leading-marker class — so it does NOT prove
			// the quoted-voice exclusion. Deletion attack A2 established that by
			// surviving. Kept because it is still the behaviour we want; the
			// fenced case below is the one that binds the exclusion.
			name:   "the word appears only inside a block quotation",
			body:   "# A — WORK IN PROGRESS\n\nStatus: WIP\n\n> **SUPERSEDED** by `landing.md`.\n",
			wantOK: false,
		},
		{
			// THIS is what the voice exclusion is for. A record that SHOWS a
			// supersession line as an example — documentation of the convention,
			// or a quotation of another record's ending — is not making the
			// claim. Nothing in the regex anchor rejects it: inside a fence the
			// line is identical to a real declaration.
			name:   "the declaration appears only inside a fenced example",
			body:   "# A — WORK IN PROGRESS\n\nStatus: WIP\n\nThe convention looks like this:\n\n```\n**SUPERSEDED** by `landing.md`.\n```\n",
			wantOK: false,
		},
	}

	_ = finished
	_ = stub
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := write("subject.md", tc.body)
			target, ok, why := Supersession(p)
			if ok != tc.wantOK {
				t.Fatalf("Supersession ok = %v, want %v (target %q, why %q)", ok, tc.wantOK, target, why)
			}
			if ok && filepath.Base(target) != tc.wantTarget {
				t.Fatalf("target = %q, want base %q", target, tc.wantTarget)
			}
		})
	}
}

// TestSupersessionOnTheRealRetainedRecord: the file that prompted this check.
// Its own closing lines declare it superseded, and the record it names is the
// 359-line landing record that reads finished. If this ever stops holding, the
// tree has changed under the check and the check must be re-read, not adjusted.
func TestSupersessionOnTheRealRetainedRecord(t *testing.T) {
	const subject = "../../drafts/self-review/normalization-collision-audit-WIP.md"
	if _, err := os.Stat(subject); err != nil {
		t.Skipf("the retained record is not in this tree: %v", err)
	}
	target, ok, why := Supersession(subject)
	if !ok {
		t.Fatalf("the retained record's own SUPERSEDED declaration did not check out (target %q, why %q)", target, why)
	}
	if filepath.Base(target) != "normalization-collision-audit.md" {
		t.Fatalf("target = %q, want normalization-collision-audit.md", target)
	}
	body, err := os.ReadFile(subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(Scan(string(body))) == 0 {
		t.Fatal("the retained record no longer reads as unfinished; supersession would then be describing nothing")
	}
}

// TestTheTwoWaysASupersessionClaimFailsAreDistinguished: added because deletion
// attack A3 SURVIVED. Dropping the `err != nil` guard on the target read left
// every test green, since a missing file reads as an empty document and an empty
// document trips `cites-nothing` — so the claim failed anyway, by accident and
// with the wrong explanation. An author who typo'd the path was being told to go
// and finish a file that does not exist.
//
// Pinning the two reasons apart is what makes that branch load-bearing.
func TestTheTwoWaysASupersessionClaimFailsAreDistinguished(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("a-stub.md", "# Stub — WORK IN PROGRESS\n\nStatus: WIP\n")

	missing := write("m.md", "# A — WORK IN PROGRESS\n\nStatus: WIP\n\n**SUPERSEDED** by `absent.md`.\n")
	if _, ok, why := Supersession(missing); ok || why != SupersessionTargetMissing {
		t.Fatalf("a path that does not exist: ok=%v why=%q, want ok=false why=%q", ok, why, SupersessionTargetMissing)
	}

	stubbed := write("s.md", "# A — WORK IN PROGRESS\n\nStatus: WIP\n\n**SUPERSEDED** by `a-stub.md`.\n")
	if _, ok, why := Supersession(stubbed); ok || why != SupersessionTargetUnfinished {
		t.Fatalf("a target that is itself a stub: ok=%v why=%q, want ok=false why=%q", ok, why, SupersessionTargetUnfinished)
	}

	if SupersessionTargetMissing == SupersessionTargetUnfinished {
		t.Fatal("the two reasons must not be the same string, or the distinction is unobservable")
	}
}
