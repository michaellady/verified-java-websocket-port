package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// proseRepoRoot finds the checkout root by walking up to go.mod.
func proseRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's working directory")
		}
		dir = parent
	}
}

// mirrorTree makes a HARD-LINK mirror of the checkout so a test can mutate one
// file without touching the tree the rest of the suite reads. Hard links are
// used rather than copies because the point of these tests is to run the REAL
// rule over the REAL records — a synthetic fixture would prove the rule works on
// a fixture, which is the shape this repository files as a defect.
//
// A mutation therefore has to REMOVE the link before writing, or it would write
// through into the checkout. writeMutated does that; nothing else in this file
// opens a mirrored path for writing.
func mirrorTree(t *testing.T, src, dst string) {
	t.Helper()
	skip := map[string]bool{".git": true, ".quarantine": true, "target": true, "out": true}
	err := filepath.WalkDir(src, func(p string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(src, p)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return os.MkdirAll(dst, 0o755)
		}
		// SkipDir returned from a FILE callback skips the remaining entries of
		// the CONTAINING directory, not just that entry. In a `git worktree`
		// checkout `.git` is a file, not a directory, so the obvious version of
		// this line skipped the whole repository root after five links and every
		// mutation test then failed on a path that was never mirrored. Only a
		// directory may answer SkipDir.
		if skip[entry.Name()] {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		return os.Link(p, target)
	})
	if err != nil {
		t.Fatalf("mirroring %s: %v", src, err)
	}
}

// writeMutated replaces one substring in one mirrored file, unlinking first so
// the checkout is never written through, and FAILS if the anchor did not match.
//
// An anchor that does not match is the failure mode that made a whole round of
// deletion attacks worthless in
// drafts/self-review/supersession-is-not-unfinished.md: the sed did not fire,
// the source was never mutated, and the unchanged result was scored as a
// survivor. A mutation that did not happen is not a result.
func writeMutated(t *testing.T, root, rel, old, replacement string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	raw, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), old) {
		t.Fatalf("anchor %q is not in %s: the mutation would not have happened, "+
			"and an unmutated run proves nothing", old, rel)
	}
	if err := os.Remove(full); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(strings.Replace(string(raw), old, replacement, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// findingsFor filters a run's findings down to one field.
func findingsFor(findings []proseFinding, field string) []proseFinding {
	var out []proseFinding
	for _, finding := range findings {
		if finding.field == field {
			out = append(out, finding)
		}
	}
	return out
}

// mirrored runs the whole rule over a fresh hard-link mirror of the checkout,
// after applying mutate to it.
func mirrored(t *testing.T, mutate func(root string)) []proseFinding {
	t.Helper()
	root := t.TempDir()
	mirrorTree(t, proseRepoRoot(t), root)
	mutate(root)
	findings, _, _, err := checkProse(root)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

// TestBoundProseAgreesWithTheDocumentsItCites is the gate, run as a test. Every
// disagreement is either absent or acknowledged by a declared allowance; a NEW
// one fails here on the run it appears.
func TestBoundProseAgreesWithTheDocumentsItCites(t *testing.T) {
	findings, _, census, err := checkProse(proseRepoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		if census["agreeing"] == 0 {
			t.Fatal("no findings and nothing agreeing either: the rule checked nothing")
		}
		return
	}
	var report strings.Builder
	for _, finding := range findings {
		report.WriteString("\n  " + finding.String())
	}
	t.Fatalf("%d prose finding(s). The document is the authority and the prose is checked "+
		"against it: if the two disagree it is the prose that is wrong, and this project "+
		"corrects a record by SUPERSESSION, never by editing the number.%s",
		len(findings), report.String())
}

// TestEveryBindingLocatesItsClaimInItsRecord is the guard against the quietest
// possible failure of this file: a pattern that matches NOTHING.
//
// It is not hypothetical. In cmd/taskgraphctl's neighbourhood four patterns were
// written with `(?m)` semantics in mind and Go anchors `^` to start-of-TEXT, so
// all four silently never matched and the checks they implemented were inert
// while reading green. A pattern that never matches would here report
// CLAIM_ABSENT rather than pass — but only if the record is present, and a
// typo'd pattern plus a fail-closed absence reads as a real finding about the
// record instead of a defect in this file. So every pattern is required to
// LOCATE its claim, and the failure names which one did not.
func TestEveryBindingLocatesItsClaimInItsRecord(t *testing.T) {
	root := proseRepoRoot(t)
	sources, err := proseCorpus(root)
	if err != nil {
		t.Fatal(err)
	}
	byRel := map[string]proseSource{}
	for _, source := range sources {
		byRel[source.rel] = source
	}
	for _, claim := range proseClaims() {
		source, ok := byRel[claim.record]
		if !ok {
			t.Errorf("%s: the corpus walk does not hold %s", claim.field, claim.record)
			continue
		}
		flat, _ := flattenProse(ownVoice(source.text))
		if claim.pattern.FindStringSubmatchIndex(flat) == nil {
			t.Errorf("%s: the pattern %q matches nothing in %s, so this binding is inert",
				claim.field, claim.pattern, claim.record)
		}
	}
	for _, assertion := range proseAssertions() {
		source, ok := byRel[assertion.record]
		if !ok {
			t.Errorf("%s: the corpus walk does not hold %s", assertion.field, assertion.record)
			continue
		}
		flat, _ := flattenProse(ownVoice(source.text))
		if assertion.pattern.FindStringIndex(flat) == nil {
			t.Errorf("%s: the pattern %q matches nothing in %s, so this assertion is inert",
				assertion.field, assertion.pattern, assertion.record)
		}
	}
}

// TestEveryClaimCapturesExactlyOneValueAndCarriesADerivation refuses a claim
// whose pattern has no capture group or more than one — checkProse indexes group
// 1 — and refuses a claim with no derivation, which would be a declaration
// checked against itself.
func TestEveryClaimCapturesExactlyOneValueAndCarriesADerivation(t *testing.T) {
	claims := proseClaims()
	if len(claims) == 0 {
		t.Fatal("no bindings: the gate would pass by having nothing to check")
	}
	seen := map[string]bool{}
	for _, claim := range claims {
		if n := claim.pattern.NumSubexp(); n != 1 {
			t.Errorf("%s: pattern has %d capture groups, want exactly 1", claim.field, n)
		}
		if claim.derive == nil {
			t.Errorf("%s: no derivation, so nothing re-derives this claim", claim.field)
		}
		key := claim.record + "\x00" + claim.field
		if seen[key] {
			t.Errorf("%s on %s is declared twice; an allowance would match both", claim.field, claim.record)
		}
		seen[key] = true
	}
	for _, assertion := range proseAssertions() {
		if n := assertion.pattern.NumSubexp(); n != 0 {
			t.Errorf("%s: an assertion's pattern must have no capture group, has %d",
				assertion.field, n)
		}
		if assertion.holds == nil {
			t.Errorf("%s: no predicate, so nothing re-derives this assertion", assertion.field)
		}
	}
}

// TestMutatingTheProseGoesRedAndNamesTheField is the F017 probe, and it is the
// one test in this file that must not be replaced by a document mutation.
//
// F017 is exactly this mistake: a polarity test bound the ARTIFACT to the
// census and said nothing about the sentence quoting it, passed, and the prose
// it was supposed to protect went stale under it. So this test moves the PROSE
// and requires RED for the right reason — the field named, the two values
// printed, and the sentence quoted back.
func TestMutatingTheProseGoesRedAndNamesTheField(t *testing.T) {
	findings := mirrored(t, func(root string) {
		writeMutated(t, root,
			"drafts/self-review/findings/F001-reproduction-check-pinned-to-vendor-string.md",
			"all 969 declarations", "all 970 declarations")
	})
	hits := findingsFor(findings, "semantic_id_oracle_declarations")
	if len(hits) != 1 || hits[0].kind != "PROSE_DISAGREES_WITH_DOCUMENT" {
		t.Fatalf("moving the PROSE did not go red on that claim; got %v", findings)
	}
	for _, want := range []string{"the record says 970", "the tree derives 969",
		"evidence/intake/semantic-id-oracle.json $.declarations"} {
		if !strings.Contains(hits[0].detail, want) {
			t.Errorf("the failure does not say %q:\n  %s", want, hits[0].String())
		}
	}
}

// TestMutatingTheDocumentAlsoGoesRed is the other half, and it is what proves
// the compared value is RE-DERIVED rather than a constant sitting beside the
// claim. If the number were authored here, editing the document could not move
// it and this test would pass while the binding measured nothing.
func TestMutatingTheDocumentAlsoGoesRed(t *testing.T) {
	findings := mirrored(t, func(root string) {
		rel := "evidence/intake/semantic-id-oracle.json"
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		var declarations []json.RawMessage
		if err := json.Unmarshal(document["declarations"], &declarations); err != nil {
			t.Fatal(err)
		}
		declarations = append(declarations, declarations[0])
		encoded, err := json.Marshal(declarations)
		if err != nil {
			t.Fatal(err)
		}
		document["declarations"] = encoded
		out, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.Remove(full); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, out, 0o644); err != nil {
			t.Fatal(err)
		}
	})
	hits := findingsFor(findings, "semantic_id_oracle_declarations")
	if len(hits) != 1 || hits[0].kind != "PROSE_DISAGREES_WITH_DOCUMENT" {
		t.Fatalf("moving the DOCUMENT did not go red, so the compared value is not read "+
			"from it; got %v", findings)
	}
	if !strings.Contains(hits[0].detail, "the tree derives 970") {
		t.Errorf("the derived value did not follow the document: %s", hits[0].String())
	}
}

// TestDeletingTheSentenceIsAFailure. If a missing claim were a pass, the whole
// gate would be defeated by deleting the sentence — the cheapest possible way to
// stop a number being stale, and the move this project keeps filing.
func TestDeletingTheSentenceIsAFailure(t *testing.T) {
	findings := mirrored(t, func(root string) {
		writeMutated(t, root,
			"drafts/self-review/findings/F001-reproduction-check-pinned-to-vendor-string.md",
			"all 969 declarations", "all of the declarations")
	})
	hits := findingsFor(findings, "semantic_id_oracle_declarations")
	if len(hits) != 1 || hits[0].kind != "CLAIM_ABSENT" {
		t.Fatalf("a deleted claim did not read as absent; got %v", hits)
	}
	if !strings.Contains(hits[0].detail, "969") {
		t.Errorf("the absence report does not say what the tree derives: %s", hits[0].String())
	}
}

// TestRestatingAnAllowedClaimOrphansItsAllowance. An allowance that survived the
// finding being fixed would silently exempt whatever landed next under that
// record and field, which is a bypass wearing an exemption's name.
func TestRestatingAnAllowedClaimOrphansItsAllowance(t *testing.T) {
	findings := mirrored(t, func(root string) {
		writeMutated(t, root, "evidence/governance/decisions/README.md",
			"The 62 JSON files beside this README", "The 63 JSON files beside this README")
	})
	hits := findingsFor(findings, "governance_decision_records (opening sentence)")
	if len(hits) != 1 || hits[0].kind != "STALE_ALLOWANCE" {
		t.Fatalf("restating the prose did not orphan its allowance; got %v", hits)
	}
}

// TestEditingAnAllowedClaimToSomeOtherWrongValueIsNotCovered. The allowance pins
// the value the prose states TODAY, so it acknowledges a finding rather than an
// address: changing 62 to 61 must fail rather than inherit the acknowledgement.
func TestEditingAnAllowedClaimToSomeOtherWrongValueIsNotCovered(t *testing.T) {
	findings := mirrored(t, func(root string) {
		writeMutated(t, root, "evidence/governance/decisions/README.md",
			"The 62 JSON files beside this README", "The 61 JSON files beside this README")
	})
	kinds := map[string]bool{}
	for _, hit := range findingsFor(findings, "governance_decision_records (opening sentence)") {
		kinds[hit.kind] = true
	}
	// BOTH fire, and both are right. The edited sentence is an unallowed
	// disagreement, and the allowance that named the OLD value now names nothing
	// — an acknowledgement covers a finding, not an address.
	if !kinds["PROSE_DISAGREES_WITH_DOCUMENT"] {
		t.Errorf("a differently-wrong value inherited the allowance; got %v", kinds)
	}
	if !kinds["STALE_ALLOWANCE"] {
		t.Errorf("the allowance survived the value it pinned being edited away; got %v", kinds)
	}
}

// TestCoverageClaimFailsWhenTheCoveringAssertionVanishes. A coverage claim says
// "another checker binds this record"; if that checker stops containing the
// assertion, the claim is a lie about who is checking what.
func TestCoverageClaimFailsWhenTheCoveringAssertionVanishes(t *testing.T) {
	findings := mirrored(t, func(root string) {
		writeMutated(t, root, "internal/normcollide/recordbounds.go",
			"The 74 rows carry only (\\d+) distinct scored observations",
			"The 74 rows carry only NOTHING distinct scored observations")
	})
	var found bool
	for _, finding := range findings {
		if finding.kind == "STALE_COVERAGE_CLAIM" {
			found = true
		}
	}
	if !found {
		t.Fatalf("removing the covering assertion did not fail as STALE_COVERAGE_CLAIM; got %v", findings)
	}
}

// TestCensusRefusesAnUndispositionedClaim. The binding table is a selection and
// the census is what stops it being a HAND-PICKED one: a record landing tomorrow
// with a cardinality claim about a population this gate can enumerate fails
// until someone binds it, covers it or declares it.
func TestCensusRefusesAnUndispositionedClaim(t *testing.T) {
	findings := mirrored(t, func(root string) {
		record := "# Synthetic\n\nThe corpus `corpora/handshake/cases.jsonl` carries 4096 cases.\n"
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(recordsRel),
			"zz-synthetic-census-probe.md"), []byte(record), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	var found bool
	for _, finding := range findings {
		if finding.kind == "UNDISPOSITIONED_CLAIM" &&
			strings.Contains(finding.record, "zz-synthetic-census-probe.md") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a new record's unbound claim did not surface in the census; got %v", findings)
	}
}

// TestTheCensusSkipsAQuotedTranscript. A record quoting an old gate line is
// reporting history, not asserting a present-tense measurement, and binding
// those would make every honest history a failure. The exclusion is real and is
// pinned here so it cannot go slack.
func TestTheCensusSkipsAQuotedTranscript(t *testing.T) {
	root := proseRepoRoot(t)
	fenced := proseSource{rel: "synthetic", kind: "markdown", text: "" +
		"# Synthetic\n\n```\ngate=x records=4096 files=4096\n```\n\n" +
		"The corpus `corpora/handshake/cases.jsonl` carries 4096 cases.\n"}
	candidates, sentences := censusCandidates(root, []proseSource{fenced})
	if sentences != 1 {
		t.Fatalf("the fenced transcript was counted as the record's own voice: sentences=%d", sentences)
	}
	if len(candidates) != 1 || candidates[0].line != 7 {
		t.Fatalf("the unfenced claim was not the one seen: %v", candidates)
	}
}

// TestFlattenProseJoinsAWrappedSentenceAndKeepsUnderscores pins the two
// properties every pattern in this file depends on. Without the first, the
// governance README's `Across all\n62 records` reads as ABSENT — a failure
// against a record that is stating its claim perfectly well. Without the second,
// two asterisks defeat the gate.
func TestFlattenProseJoinsAWrappedSentenceAndKeepsUnderscores(t *testing.T) {
	flat, lineOf := flattenProse("That assessment was overstated. Across all\n**62 records** there are no credentials.")
	const want = "That assessment was overstated. Across all 62 records there are no credentials."
	if flat != want {
		t.Fatalf("flatten gave %q, want %q", flat, want)
	}
	pattern := proseClaims()[1].pattern
	location := pattern.FindStringSubmatchIndex(flat)
	if location == nil {
		t.Fatal("the wrapped sentence did not match after flattening")
	}
	if got := flat[location[2]:location[3]]; got != "62" {
		t.Fatalf("captured %q, want 62", got)
	}
	if lineOf[location[0]] != 1 {
		t.Fatalf("match reported on line %d, want 1 (the line the sentence began on)", lineOf[location[0]])
	}
	// Underscores must SURVIVE. Stripping them as markdown emphasis is the
	// mistake internal/normcollide made: sec_websocket_accept became
	// secwebsocketaccept and a correct row read as missing every key it named.
	kept, _ := flattenProse("names `sec_websocket_accept` and `final_state`")
	if !strings.Contains(kept, "sec_websocket_accept") || !strings.Contains(kept, "final_state") {
		t.Fatalf("flatten mangled an identifier: %q", kept)
	}
}

// TestEnumerableAsksTheDocumentAndNotTheSentence pins the line between a
// candidate and a sentence that merely has a number near a path. Without it,
// `18 files` beside a cited .rs file read as a claim about that file.
func TestEnumerableAsksTheDocumentAndNotTheSentence(t *testing.T) {
	root := proseRepoRoot(t)
	cases := []struct {
		cited, noun string
		want        bool
	}{
		{"evidence/java/behavior-delta-ledger.json", "records", true},
		{"evidence/java/behavior-delta-ledger.json", "rows", false},
		{"corpora/handshake/cases.jsonl", "cases", true},
		{"rust/ws-core/src/connection.rs", "files", false},
		{"evidence/governance/decisions", "files", true},
		{"evidence/does-not-exist.json", "records", false},
	}
	for _, c := range cases {
		got, _ := enumerable(root, c.cited, c.noun)
		if got != c.want {
			t.Errorf("enumerable(%q, %q) = %v, want %v", c.cited, c.noun, got, c.want)
		}
	}
}

// TestTheAssertionRefusesWhenGitCannotAnswer. `git ls-files --error-unmatch`
// exits 1 for an untracked path and 128 when there is no repository at all.
// Reading 128 as "untracked" would make the tracked-ness assertion HOLD in any
// checkout git cannot see — a fail-OPEN, and the exact shape of a refusal being
// read as a pass. It must be an error.
func TestTheAssertionRefusesWhenGitCannotAnswer(t *testing.T) {
	outside := t.TempDir()
	if _, err := gitTracked(outside, "anything"); err == nil {
		t.Fatal("gitTracked answered 'not tracked' outside a repository; " +
			"a refusal must not read as an answer")
	}
	tracked, err := gitTracked(proseRepoRoot(t), "go.mod")
	if err != nil || !tracked {
		t.Fatalf("gitTracked(go.mod) = %v, %v; want true, nil", tracked, err)
	}
}

// TestTheTrackednessAssertionSwingsBothWays is the polarity probe for the one
// NON-numeric binding. Without it the predicate could be a constant false — it
// returns false on the real tree, which is the finding, and a constant false
// would look identical there.
//
// So the same predicate is run against a repository where the mirrored records
// are NOT committed, which is the state the statement asserts, and it must
// return TRUE. Then the same files are added to the index and nothing else
// changes, and it must return FALSE.
func TestTheTrackednessAssertionSwingsBothWays(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"evidence/governance/decisions"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	body := []byte(`{"kind":"synthetic owner decision"}`)
	if err := os.WriteFile(filepath.Join(root,
		filepath.FromSlash("evidence/governance/decisions/synthetic.json")), body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	manifest := map[string]any{
		"statement": "irrelevant here; the pattern is matched elsewhere",
		"decisions": []map[string]string{{"name": "synthetic.json", "sha256": hex.EncodeToString(sum[:])}},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root,
		filepath.FromSlash("evidence/governance/owner-decision-digests.json")), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, argv := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "probe@example.invalid"},
		{"config", "user.name", "probe"},
	} {
		cmd := exec.Command("git", argv...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", argv, err, out)
		}
	}

	assertion := proseAssertions()[0]
	holds, evidence, err := assertion.holds(root)
	if err != nil {
		t.Fatal(err)
	}
	if !holds {
		t.Fatalf("with the records UNCOMMITTED the assertion must hold; it did not: %s", evidence)
	}

	add := exec.Command("git", "add", "evidence")
	add.Dir = root
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	holds, evidence, err = assertion.holds(root)
	if err != nil {
		t.Fatal(err)
	}
	if holds {
		t.Fatalf("with the same records COMMITTED the assertion must be refuted; it held: %s", evidence)
	}
	if !strings.Contains(evidence, "1 of 1 mirrored records are git-tracked") {
		t.Errorf("the refutation does not say what it measured: %s", evidence)
	}
}

// TestAQuotedStaleClaimDoesNotBindTheRecordQuotingIt. This project corrects a
// record by SUPERSESSION, and a supersession record quotes the sentence it is
// superseding, verbatim. If a binding matched inside a quotation, writing the
// correction would fail the gate — a checker nobody can document a drift under.
//
// It also stops a record's worked EXAMPLE of the bound shape being mistaken for
// the record's own claim, which is how this was found: the landing record for
// this branch explains the rule with a sentence of the bound shape, and the
// binding matched the example.
func TestAQuotedStaleClaimDoesNotBindTheRecordQuotingIt(t *testing.T) {
	const text = "We report the stale sentence:\n\n" +
		"> `evidence/java/behavior-delta-ledger.json` holds **58 records**.\n\n" +
		"and the truth:\n\n" +
		"`evidence/java/behavior-delta-ledger.json` holds **59 records**.\n"
	flat, _ := flattenProse(ownVoice(text))
	if strings.Contains(flat, "holds 58 records") {
		t.Fatalf("the quoted sentence survived voice masking: %q", flat)
	}
	if !strings.Contains(flat, "holds 59 records") {
		t.Fatalf("the record's own sentence was masked away: %q", flat)
	}
}
