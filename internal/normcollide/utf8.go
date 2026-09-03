package normcollide

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Utf8PremiseCheckID names the check that decides CAND-UTF8.
const Utf8PremiseCheckID = "NC-UTF8-PREMISE"

// The CAND-UTF8 candidate asks whether two DIFFERENT inbound octet sequences
// can produce the SAME `text` event, given that the event records the decoded
// String and utf8_bytes = len(String) rather than the octets received.
//
// It cannot be decided the way every other candidate here is decided, by
// exhibiting a pair, because the claim is that NO pair exists. An emptiness
// claim is a claim about a total function, and this package's whole standard
// is "decided by construction, not argument" — so the construction is:
//
//   - PREMISE CHECKS over the source, which fail the moment the premises stop
//     holding. This is what stops the refutation rotting silently if someone
//     swaps in a lossy decode: the emptiness would still READ true and the
//     check would go red.
//   - A DISCRIMINATING RUN. The two seeds are chosen so that a lossy decoder
//     would map them onto the SAME text event and a strict one cannot: the
//     accepted seed carries the three octets of U+FFFD itself, and the
//     rejected seed carries a lone 0xFF, which is exactly what a lossy
//     decoder turns INTO U+FFFD. If the decode were lossy, both would deliver
//     `text` = U+FFFD with utf8_bytes = 3 and the candidate would be a live
//     collision. Running them is therefore not decoration on the argument; it
//     is the experiment the argument predicts.
//
// The premise checks scan BOTH crates, not just ws-core. F007 argued the
// refutation from ws-core alone, but the `text` event is MINTED in
// ws-oracle-harness (observe.rs sets utf8_bytes from the delivered String), so
// a lossy conversion introduced there would defeat the emptiness just as
// completely. A proof is only as good as its premises, and "the decode site is
// strict" is a premise about every site that can produce the value.

// lossyPattern matches every way this tree could acquire a replacement-
// character decode. It is deliberately broader than `from_utf8_lossy`: the
// point is to catch a hand-rolled substitution too, so it also matches the
// code point written as a Rust escape, as a hex literal, as a decimal, as the
// std constant, and as the literal character itself.
//
// It is NOT a bare `fffd`: a SHA-256 digest in a source comment can contain
// those four characters, and a premise that goes red on a digest would train
// its reader to ignore it. Each alternative therefore carries its own
// prefix. TestTheNoLossyScanFindsAPlantedLossyDecode plants one of each, and
// it caught this pattern missing `0xFFFD` on its first run — which is why the
// alternatives are spelled out rather than approximated with a word boundary.
var lossyPattern = regexp.MustCompile(
	`from_utf8_lossy|to_string_lossy|to_str_lossy|REPLACEMENT_CHARACTER|` +
		`(?i:u\+fffd)|(?i:0xfffd)|(?i:\\u\{fffd\})|\x{FFFD}|65533`)

// Utf8Premise is one premise of the emptiness argument, with the measurement
// that decided whether it holds. Holds and Evidence are never authored.
type Utf8Premise struct {
	// ID is the premise's stable identifier.
	ID string `json:"id"`
	// Claim states the premise in one sentence.
	Claim string `json:"claim"`
	// Kind is "source" (a scan of the tree) or "run" (a harness answer).
	Kind string `json:"kind"`
	// Scope names what was examined — a path, or the seed ids.
	Scope string `json:"scope"`
	// Holds is MEASURED.
	Holds bool `json:"holds"`
	// Evidence is what the measurement saw, including on success, so a
	// reader can tell a real scan from a vacuous one.
	Evidence string `json:"evidence"`
}

// Utf8Emptiness is the decided record for CAND-UTF8.
type Utf8Emptiness struct {
	// ID is the check's identifier, referenced by the decided candidate.
	ID string `json:"id"`
	// Candidate names what this decides.
	Candidate string `json:"candidate"`
	// Argument is the emptiness argument the premises support.
	Argument string `json:"argument"`
	// Premises are the checks, each with its own measured verdict.
	Premises []Utf8Premise `json:"premises"`
	// RequestLines are the two lines fed to the harness for the run
	// premise, so the experiment is reproducible from the document alone.
	RequestLines []string `json:"request_lines"`
	// Status is RECOMPUTED: EMPTY when every premise holds, HYPOTHESIS
	// otherwise. A failed premise does not make the candidate a collision;
	// it makes it undecided again, which is the honest fallback.
	Status string `json:"status"`
}

// Utf8Seeds returns the two seeds of the discriminating run, in order:
// the ACCEPTED one carrying the encoded U+FFFD, and the REJECTED one carrying
// the lone 0xFF that a lossy decoder would turn into U+FFFD.
func Utf8Seeds() (accepted Seed, rejected Seed) {
	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	return Seed{ID: "ncutf8.accepted", Role: "server", Steps: []map[string]any{
			bytesStep(maskedTextFrame([]byte{0xEF, 0xBF, 0xBD}, key))}},
		Seed{ID: "ncutf8.rejected", Role: "server", Steps: []map[string]any{
			bytesStep(maskedTextFrame([]byte{0xFF}, key))}}
}

// DecideUtf8Emptiness runs every premise and reports what each one saw. It
// predicts nothing: Holds comes from the scan or the run.
func DecideUtf8Emptiness(root string, runner Runner) (Utf8Emptiness, error) {
	record := Utf8Emptiness{
		ID:        Utf8PremiseCheckID,
		Candidate: "CAND-UTF8",
		Argument: "UTF-8 is injective on valid input, so if the decode is STRICT then distinct " +
			"accepted octet sequences give distinct Strings and an invalid sequence yields no " +
			"text event at all — the candidate class is EMPTY rather than merely unwitnessed. " +
			"The argument rests entirely on strictness, so the premises below are checks that " +
			"strictness has not been swapped out, and the run is the experiment a lossy decode " +
			"would fail.",
	}

	strictSite, err := utf8StrictDecodeSitePremise(root)
	if err != nil {
		return record, err
	}
	record.Premises = append(record.Premises, strictSite)

	for _, scope := range []string{
		filepath.Join("rust", "ws-core", "src"),
		filepath.Join("rust", "ws-oracle-harness", "src"),
	} {
		premise, err := utf8NoLossyDecodePremise(root, scope)
		if err != nil {
			return record, err
		}
		record.Premises = append(record.Premises, premise)
	}

	runPremise, lines, err := utf8DiscriminatingRunPremise(runner)
	if err != nil {
		return record, err
	}
	record.Premises = append(record.Premises, runPremise)
	record.RequestLines = lines

	record.Status = StatusEmpty
	for _, premise := range record.Premises {
		if !premise.Holds {
			record.Status = StatusHypothesis
		}
	}
	return record, nil
}

// utf8StrictDecodeSitePremise reads the body of ws-core's string_utf8 and
// requires it to be the strict decode. It reads the FUNCTION BODY rather than
// grepping the file, so a strict call surviving somewhere else in the file
// while the real site turned lossy would not satisfy it.
func utf8StrictDecodeSitePremise(root string) (Utf8Premise, error) {
	const relative = "rust/ws-core/src/message.rs"
	premise := Utf8Premise{
		ID: "U8-P1",
		Claim: "ws-core's text decode site (Charsetfunctions::string_utf8) is the STRICT " +
			"String::from_utf8, mapping failure to an error rather than substituting.",
		Kind:  "source",
		Scope: relative,
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return premise, fmt.Errorf("%s: %w", premise.ID, err)
	}
	body, found := functionBody(string(raw), "pub fn string_utf8")
	if !found {
		premise.Evidence = "no `pub fn string_utf8` in " + relative +
			" — the decode site this argument is about no longer exists under that name"
		return premise, nil
	}
	strict := strings.Contains(body, "String::from_utf8(") && strings.Contains(body, "map_err")
	lossy := lossyPattern.MatchString(body)
	premise.Holds = strict && !lossy
	premise.Evidence = fmt.Sprintf("body %q; strict=%t lossy=%t",
		strings.Join(strings.Fields(body), " "), strict, lossy)
	if !premise.Holds {
		premise.Evidence = fmt.Sprintf("body %q does NOT satisfy strict decode "+
			"(String::from_utf8 + map_err present=%t, lossy marker present=%t)",
			strings.Join(strings.Fields(body), " "), strict, lossy)
	}
	return premise, nil
}

// utf8NoLossyDecodePremise scans one crate's sources for any replacement-
// character decode.
//
// The anti-vacuity guard matters more than the scan: a scan that reads ZERO
// files reports zero matches and would otherwise pass. The premise therefore
// requires the scan to have actually reached files, and records the count and
// the file list's size so a reader can see it was not empty.
func utf8NoLossyDecodePremise(root, scope string) (Utf8Premise, error) {
	premise := Utf8Premise{
		ID: "U8-P2-" + strings.ReplaceAll(filepath.ToSlash(scope), "/", "."),
		Claim: "no lossy decode and no replacement character anywhere under " +
			filepath.ToSlash(scope) + " — so no site can substitute U+FFFD for an octet " +
			"sequence it could not decode.",
		Kind:  "source",
		Scope: filepath.ToSlash(scope),
	}
	directory := filepath.Join(root, filepath.FromSlash(scope))
	var scanned []string
	var hits []string
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".rs" {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		scanned = append(scanned, filepath.ToSlash(relative))
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for number, line := range strings.Split(string(raw), "\n") {
			if lossyPattern.MatchString(line) {
				hits = append(hits, fmt.Sprintf("%s:%d: %s",
					filepath.ToSlash(relative), number+1, strings.TrimSpace(line)))
			}
		}
		return nil
	})
	if err != nil {
		return premise, fmt.Errorf("%s: %w", premise.ID, err)
	}
	sort.Strings(scanned)
	sort.Strings(hits)
	switch {
	case len(scanned) == 0:
		premise.Evidence = "scanned 0 .rs files under " + filepath.ToSlash(scope) +
			": a scan that reads nothing finds nothing, so this premise is REFUSED rather " +
			"than passed"
	case len(hits) != 0:
		premise.Evidence = fmt.Sprintf("scanned %d .rs files and found %d lossy/replacement "+
			"marker(s): %s", len(scanned), len(hits), strings.Join(hits, " | "))
	default:
		premise.Holds = true
		premise.Evidence = fmt.Sprintf("scanned %d .rs files (%s), 0 lossy/replacement markers",
			len(scanned), strings.Join(scanned, " "))
	}
	return premise, nil
}

// utf8DiscriminatingRunPremise runs the experiment a lossy decode would fail.
func utf8DiscriminatingRunPremise(runner Runner) (Utf8Premise, []string, error) {
	premise := Utf8Premise{
		ID: "U8-P3",
		Claim: "the octet sequence a lossy decoder would map ONTO U+FFFD (a lone 0xFF) " +
			"produces NO text event, while the encoded U+FFFD itself produces one — so the two " +
			"do NOT collide, which they would under a lossy decode.",
		Kind:  "run",
		Scope: "ncutf8.accepted, ncutf8.rejected",
	}
	accepted, rejected := Utf8Seeds()
	var lines []string
	for _, seed := range []Seed{accepted, rejected} {
		line, err := seed.Line()
		if err != nil {
			return premise, nil, err
		}
		lines = append(lines, line)
	}
	if lines[0] == lines[1] {
		return premise, nil, fmt.Errorf("%s: the two seeds render the same request line", premise.ID)
	}
	answers, err := runner.Run(lines)
	if err != nil {
		return premise, nil, fmt.Errorf("%s: %w", premise.ID, err)
	}
	acceptedAnswer, err := decodeResponse(answers[0])
	if err != nil {
		return premise, nil, fmt.Errorf("%s accepted: %w", premise.ID, err)
	}
	rejectedAnswer, err := decodeResponse(answers[1])
	if err != nil {
		return premise, nil, fmt.Errorf("%s rejected: %w", premise.ID, err)
	}
	acceptedText := textEvents(acceptedAnswer)
	rejectedText := textEvents(rejectedAnswer)
	premise.Holds = len(acceptedText) == 1 && len(rejectedText) == 0
	premise.Evidence = fmt.Sprintf(
		"accepted seed (EF BF BD, the encoded U+FFFD) -> outcome %q with %d text event(s) %s; "+
			"rejected seed (FF, what a lossy decode turns INTO U+FFFD) -> outcome %q, error %s, "+
			"%d text event(s). Under a lossy decode both would read text=U+FFFD utf8_bytes=3.",
		scalarString(acceptedAnswer["outcome"]), len(acceptedText), strings.Join(acceptedText, " "),
		scalarString(rejectedAnswer["outcome"]), errorSummary(rejectedAnswer), len(rejectedText))
	return premise, lines, nil
}

// textEvents renders every `text` event in a response, in order.
func textEvents(answer map[string]any) []string {
	events, ok := answer["events"].([]any)
	if !ok {
		return nil
	}
	var rendered []string
	for _, event := range events {
		object, ok := event.(map[string]any)
		if !ok {
			continue
		}
		if scalarString(object["type"]) != "text" {
			continue
		}
		encoded, err := json.Marshal(object)
		if err != nil {
			continue
		}
		rendered = append(rendered, string(encoded))
	}
	return rendered
}

func errorSummary(answer map[string]any) string {
	object, ok := answer["error"].(map[string]any)
	if !ok {
		return "(none)"
	}
	return fmt.Sprintf("%s/close %s", scalarString(object["code"]), scalarString(object["close_code"]))
}

func scalarString(value any) string {
	if value == nil {
		return "(absent)"
	}
	return fmt.Sprint(value)
}

// functionBody returns the text between the brace that opens the named
// function and its matching close. It is a brace counter, not a parser, which
// is enough for a Rust function with balanced braces and no brace inside a
// string literal — both true of string_utf8 and checked by the caller, which
// requires specific content in what comes back.
func functionBody(source, signature string) (string, bool) {
	start := strings.Index(source, signature)
	if start < 0 {
		return "", false
	}
	open := strings.Index(source[start:], "{")
	if open < 0 {
		return "", false
	}
	open += start
	depth := 0
	for i := open; i < len(source); i++ {
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[open+1 : i], true
			}
		}
	}
	return "", false
}
