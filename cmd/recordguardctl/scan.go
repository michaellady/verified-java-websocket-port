package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Signal is one reason a record is not finished, located in the record's own
// text. Every signal carries the line it was read from, so the operator can go
// and read the sentence rather than trust the verdict.
type Signal struct {
	Line int
	Kind string
	Term string
	Text string
}

// signalKinds is every signal this discriminator implements. A test refuses any
// kind here that no committed fixture proves.
var signalKinds = []string{
	"declared-status",
	"declared-title",
	"void-self-report",
	"open-checklist",
	"cites-nothing",
}

// unfinishedTerms is the lexicon a record uses to say, in its own voice, that it
// is not done. Every entry was READ OFF a record in this repository's history
// rather than imagined: `in progress` and `stub` from the div05 stub at 755b8c8,
// `work in progress` from legacy-record-adjudication at 714614b and
// oracle-rank3-independence at df5642c, `wip` from concurrency-coverage-
// disclosure at 68fbc17 and catalog-plane-correspondence at e784eb6, `started`
// from legacy-record-adjudication. `todo`, `draft`, `incomplete`, `unfinished`,
// `not started` and `pending` are the neighbouring forms and have NO instance in
// this corpus — they are declared here as a widening of the rule, and the record
// says so, so that nobody later mistakes them for calibrated.
var unfinishedTerms = []string{
	"work in progress",
	"not started",
	"in progress",
	"incomplete",
	"unfinished",
	"started",
	"pending",
	"draft",
	"stub",
	"todo",
	"wip",
}

// voidPhrases are a record reporting, in its own voice, that it holds no
// results. All four with instances here are verbatim: `nothing verified` (div05
// at 755b8c8), `no findings yet` (oracle-rank3 at df5642c), `to be filled in`
// and `nothing claimed yet` (handshake-discrimination at 2421d6f). The rest are
// the same sentence in other words and have no instance in this corpus.
var voidPhrases = []string{
	"nothing to report yet",
	"nothing claimed yet",
	"nothing measured yet",
	"to be filled in",
	"nothing verified",
	"no findings yet",
	"no evidence yet",
	"no results yet",
	"not yet written",
}

// evidenceTokens are the shapes a record uses to CITE something. A record
// carrying none of them cites nothing at all. The floor is pinned at literally
// zero, not at a fitted threshold: measured over all 82 record versions in this
// repository's history, the leanest FINISHED record carries 9 of these and the
// leanest unfinished one carries 0, so a floor anywhere above zero would be a
// number chosen to fit rather than a bound.
var evidenceTokens = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bexit(?:s|ed)?[ =]*(?:code[ =]*)?[0-9]+`),
	regexp.MustCompile(`\b[0-9a-f]{7,40}\b`),
	regexp.MustCompile("(?i)sha256|sha-256|blob id|digest"),
	regexp.MustCompile("`[^`\n]+`"),
	regexp.MustCompile(`(?i)\b(?:observed|differential|bounded)\b|proved-model|proved-production`),
	regexp.MustCompile(`\bRED\b|\bGREEN\b|deletion attack`),
}

var (
	titleRe    = regexp.MustCompile(`^#{1,6}\s+\S`)
	statusRe   = regexp.MustCompile(`(?i)^[\s]*[#*_+\-]*[\s]*status[\s]*:`)
	checkboxRe = regexp.MustCompile(`^[\s]*[-*+][\s]+\[[\s]\][\s]*(.*)$`)
	fenceRe    = regexp.MustCompile("^[\\s]*(?:```|~~~)")
	quoteRe    = regexp.MustCompile(`^[\s]*>`)
)

// Rows renders signals in the manifest's declared form, "line|kind|term",
// ordered by line then kind then term. Declaring rows rather than a count is
// what makes the removal of any single signal visible: drop the void-phrase rule
// and the status rule still fires on the same file, so a "did anything fire?"
// check would stay green.
func Rows(sigs []Signal) []string {
	ordered := append([]Signal(nil), sigs...)
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Term < b.Term
	})
	out := make([]string, 0, len(ordered))
	for _, s := range ordered {
		out = append(out, fmt.Sprintf("%d|%s|%s", s.Line, s.Kind, s.Term))
	}
	return out
}

// Scan reads a self-review record and returns every signal that it is
// unfinished.
//
// Every signal reads the record's own words. None of them is satisfied by the
// record merely existing, having a size, or having a status FIELD — the status
// signal reads the status VALUE, which is what separates the div05 stub's
// "STATUS: IN PROGRESS" from the same path's later "STATUS: COMPLETE".
func Scan(src string) []Signal {
	lines := strings.Split(src, "\n")
	masked := maskOtherVoices(lines)
	var sigs []Signal

	titleSeen := false
	for i, raw := range lines {
		n := i + 1
		m := masked[i]
		if strings.TrimSpace(m) == "" {
			continue
		}

		// The record's title, qualified: "— WORK IN PROGRESS", "(WIP)".
		if !titleSeen && titleRe.MatchString(m) {
			titleSeen = true
			for _, term := range matchTerms(m, unfinishedTerms) {
				sigs = append(sigs, Signal{Line: n, Kind: "declared-title", Term: term, Text: trim(raw)})
			}
		}

		// The record's own status declaration, read for its VALUE.
		if loc := statusRe.FindStringIndex(m); loc != nil {
			for _, term := range matchTerms(m[loc[1]:], unfinishedTerms) {
				sigs = append(sigs, Signal{Line: n, Kind: "declared-status", Term: term, Text: trim(raw)})
			}
		}

		// The record reporting that it holds nothing.
		if void := matchTerms(m, voidPhrases); len(void) > 0 {
			for _, term := range void {
				sigs = append(sigs, Signal{Line: n, Kind: "void-self-report", Term: term, Text: trim(raw)})
			}
		}

		// An unchecked task box: the record's own markdown saying "not done".
		if cm := checkboxRe.FindStringSubmatch(m); cm != nil {
			// Report the item text from the ORIGINAL line so the term keeps its
			// case, but fall back to the masked text if masking changed the
			// line's shape: a gate that panics is worse than one that is coarse.
			item := trim(cm[1])
			if rawMatch := checkboxRe.FindStringSubmatch(raw); rawMatch != nil {
				item = trim(rawMatch[1])
			}
			if item != "" {
				sigs = append(sigs, Signal{Line: n, Kind: "open-checklist", Term: item, Text: trim(raw)})
			}
		}
	}

	if countEvidence(src) == 0 {
		sigs = append(sigs, Signal{Line: 0, Kind: "cites-nothing", Term: "",
			Text: "the whole record contains no exit code, commit, digest, path, symbol or claim-vocabulary term"})
	}
	return sigs
}

// maskOtherVoices blanks out every span in which the record is quoting somebody
// else, so that a finding which QUOTES a stub is not mistaken for one. Fenced
// blocks and blockquote lines are masked whole; within an ordinary line, paired
// double quotes, typographic quotes and backticks are masked. Positions are
// preserved so line offsets stay usable.
//
// This is load-bearing rather than decorative: F009, the finding that motivated
// this tool, quotes the div05 stub as *"STATUS: IN PROGRESS … Nothing verified
// yet."* — without this, the tool would refuse the finding that asked for it.
func maskOtherVoices(lines []string) []string {
	out := make([]string, len(lines))
	inFence := false
	// carry is the closer an unclosed span on a previous line is still waiting
	// for. A markdown inline span may wrap a single line break but never a blank
	// line, so carry is dropped at a blank line — which bounds the damage an odd
	// stray quote can do to one paragraph instead of the rest of the record.
	var carry rune
	for i, raw := range lines {
		if fenceRe.MatchString(raw) {
			inFence = !inFence
			carry = 0
			out[i] = blank(raw)
			continue
		}
		if inFence || quoteRe.MatchString(raw) {
			carry = 0
			out[i] = blank(raw)
			continue
		}
		if strings.TrimSpace(raw) == "" {
			carry = 0
			out[i] = raw
			continue
		}
		out[i], carry = maskPairs(raw, carry)
	}
	return out
}

func blank(s string) string { return strings.Repeat(" ", len([]rune(s))) }

// maskPairs blanks the interior of paired quote and code spans on one line. It
// takes the closer left open by the previous line and returns the one it leaves
// open, so a quotation that wraps a line break stays masked on both lines. That
// case is not hypothetical: this tool's own record quotes F009 quoting the div05
// stub, and the closing backtick lands on the following line.
func maskPairs(s string, carry rune) (string, rune) {
	r := []rune(s)
	out := append([]rune(nil), r...)
	// When a closer was carried in, the span is already open at column 0.
	openIdx, want := 0, carry
	for i, ch := range r {
		if want == 0 {
			switch ch {
			case '"':
				openIdx, want = i, '"'
			case '“':
				openIdx, want = i, '”'
			case '`':
				openIdx, want = i, '`'
			}
			continue
		}
		if ch == want {
			for j := openIdx; j <= i; j++ {
				out[j] = ' '
			}
			want = 0
		}
	}
	// Still open: the quotation continues past this line, so mask to the end and
	// hand the closer to the next line.
	if want != 0 {
		for j := openIdx; j < len(out); j++ {
			out[j] = ' '
		}
	}
	return string(out), want
}

// matchTerms returns the distinct lexicon terms present in s as whole words,
// longest first and non-overlapping, so "work in progress" is one term and not
// also "in progress".
func matchTerms(s string, lexicon []string) []string {
	terms := append([]string(nil), lexicon...)
	sort.Slice(terms, func(i, j int) bool { return len(terms[i]) > len(terms[j]) })
	low := strings.ToLower(s)
	seen := map[string]bool{}
	var found []string
	for i := 0; i < len(low); {
		matched := ""
		for _, t := range terms {
			if strings.HasPrefix(low[i:], t) && wordEdge(low, i) && wordEdge(low, i+len(t)) {
				matched = t
				break
			}
		}
		if matched == "" {
			i++
			continue
		}
		if !seen[matched] {
			seen[matched] = true
			found = append(found, matched)
		}
		i += len(matched)
	}
	sort.Strings(found)
	return found
}

// wordEdge reports whether position i in s is a word boundary, so that "draft"
// does not match inside "drafts/self-review" and "wip" does not match inside a
// longer word.
func wordEdge(s string, i int) bool {
	before := byte(' ')
	if i > 0 {
		before = s[i-1]
	}
	after := byte(' ')
	if i < len(s) {
		after = s[i]
	}
	isWord := func(b byte) bool {
		return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
	}
	if i == 0 || i >= len(s) {
		return true
	}
	return !(isWord(before) && isWord(after))
}

func countEvidence(src string) int {
	n := 0
	for _, re := range evidenceTokens {
		n += len(re.FindAllString(src, -1))
	}
	return n
}

func trim(s string) string { return strings.TrimSpace(s) }

// supersededRe matches a record's own declaration that another record has
// replaced it. Read off drafts/self-review/normalization-collision-audit-WIP.md,
// whose closing lines are:
//
//	**SUPERSEDED** by `drafts/self-review/normalization-collision-audit.md`.
//
// The path is required and must be in backticks, because a bare prose sentence
// naming no file cannot be verified, and an unverifiable supersession claim is
// the escape hatch this whole check exists to deny.
var supersededRe = regexp.MustCompile(
	"(?i)^[\\s]*[#*_+\\-]*[\\s]*superseded[\\s]*[#*_+]*[\\s]+(?:by|in)[\\s]+`([^`]+)`")

// Supersession reports whether the record at path declares itself superseded by
// another record, and whether that claim CHECKS OUT.
//
// A declaration alone is deliberately not enough. This tool's measured ceiling
// is that self-declarations bind honest authors and nothing else — strip the
// self-declarations from the six historical stubs and only one is still caught.
// A state reachable by writing one sentence about yourself would therefore be a
// state reachable by any record that wanted it. So two further conditions are
// checked against the filesystem, not the prose:
//
//  1. the named record EXISTS, resolved relative to the declaring record's own
//     directory and then to the repository root; and
//  2. the named record ITSELF READS FINISHED, by this same Scan.
//
// Condition 2 is the load-bearing one: without it a stub could be excused by
// pointing at another stub, and a chain of mutual supersessions would launder
// every record in it.
//
// Declarations inside a block quote or a fenced block do not count, for the same
// reason the other signals ignore them: a record QUOTING a supersession, or
// showing one as an example, is not making the claim.
func Supersession(path string) (string, bool, string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false, ""
	}
	lines := strings.Split(string(raw), "\n")
	// maskOtherVoices blanks quoted and fenced lines wholly, and blanks inline
	// code SPANS within ordinary lines. The path we need lives inside such a
	// span, so the masked text cannot be matched directly. Instead the mask is
	// used only to decide WHOSE VOICE a line is in: a line the mask empties
	// entirely was a quotation or a fence, and the claim is not the record's own.
	masked := maskOtherVoices(lines)
	for i, line := range lines {
		if i < len(masked) && strings.TrimSpace(masked[i]) == "" && strings.TrimSpace(line) != "" {
			continue
		}
		m := supersededRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		named := strings.TrimSpace(m[1])
		for _, cand := range []string{
			filepath.Join(filepath.Dir(path), filepath.Base(named)),
			filepath.Join(filepath.Dir(path), named),
			named,
		} {
			body, err := os.ReadFile(cand)
			if err != nil {
				continue
			}
			if len(Scan(string(body))) != 0 {
				return cand, false, SupersessionTargetUnfinished
			}
			return cand, true, ""
		}
		return named, false, SupersessionTargetMissing
	}
	return "", false, ""
}

// The two ways a supersession claim fails. They are kept apart because a
// deletion attack found them indistinguishable and that was a real defect, not a
// stylistic one.
//
// Dropping the `err != nil` guard on the target read SURVIVED an attack: a
// missing file reads as an empty document, an empty document trips
// `cites-nothing`, and so the claim failed anyway — by accident, and with the
// wrong explanation. A record pointing at a path that DOES NOT EXIST was being
// reported as pointing at an unfinished record. The author of a typo'd path
// would have been told to go and finish a file that is not there.
//
// So the reason is now returned and printed, and the existence branch is
// load-bearing: remove it and the reason string is wrong, which a test reads.
const (
	SupersessionTargetMissing    = "the named record does not exist"
	SupersessionTargetUnfinished = "the named record exists but itself reads unfinished"
)
