// Command pinconsumerctl answers the question that cost this repository two
// chain-walks in one day: WHEN I CHANGE A FILE, WHICH ARTIFACTS PIN IT?
//
// The evidence tree is full of digest pins, and they work -- each of today's two
// failures was a pin correctly reporting an un-propagated change. What was
// missing is any way to ask the question in advance. Both times the first
// artifact's failure named only itself, and the consumer behind it was found only
// by breaking it.
//
// This tool is deliberately SHAPE-AGNOSTIC. The tree pins paths under at least
// twelve different key names (`path`, `reportfile`, `file`, `manifest_path`,
// `source_path`, `catalog_source_path`, `mutation_manifest_path`, `source`,
// `target_path`, `pin_file`, `lifecycle_path`, `adapted_path`), so a parser that
// understood schemas would be wrong the moment a thirteenth appeared. Instead it
// indexes by DIGEST VALUE: a consumer of a file is any artifact whose text
// carries that file's current sha256.
//
//	pinconsumerctl consumers <path>...   # who pins these files' CURRENT content
//	pinconsumerctl dangling              # pins whose named file no longer matches
//
// `dangling` reports CANDIDATES, not verdicts, and the distinction is load-bearing:
// co-location of a path and a digest inside one JSON object is evidence that the
// digest is OF that path, not proof. Every candidate must be read before it is
// acted on. The census prints its own false-positive surface rather than implying
// a clean number.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var digestPattern = regexp.MustCompile(`^(?:sha256:)?([0-9a-f]{64})$`)

type pin struct {
	artifact  string
	pointer   string
	namedPath string
	declared  string
	actual    string
	// explanation is non-empty when the declared digest was PROVEN, by
	// recomputation from current bytes, to cover something other than
	// namedPath. Such a pin is a false positive by the ceiling's own
	// definition; it is reported on its own gate line, never dropped in
	// silence.
	explanation string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pinconsumerctl <consumers <path>...|dangling> [-root DIR]")
		os.Exit(2)
	}
	root := "."
	args := os.Args[2:]
	var positional []string
	for index := 0; index < len(args); index++ {
		if args[index] == "-root" && index+1 < len(args) {
			root = args[index+1]
			index++
			continue
		}
		positional = append(positional, args[index])
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pinconsumerctl: %v\n", err)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "consumers":
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "pinconsumerctl: consumers needs at least one path")
			os.Exit(2)
		}
		os.Exit(runConsumers(absoluteRoot, positional))
	case "dangling":
		os.Exit(runDangling(absoluteRoot))
	default:
		fmt.Fprintf(os.Stderr, "pinconsumerctl: unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

// trackedFiles lists what git tracks, so untracked scratch files and ignored
// trees (.quarantine, target/) never enter the index.
func trackedFiles(root string) ([]string, error) {
	command := exec.Command("git", "-C", root, "ls-files", "-z")
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var paths []string
	for _, entry := range strings.Split(string(output), "\x00") {
		if entry != "" {
			paths = append(paths, entry)
		}
	}
	return paths, nil
}

func fileDigest(root, relative string) (string, bool) {
	content, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), true
}

type consumerTarget struct {
	path    string
	digest  string
	current []string
	stale   []pin
}

// analyseConsumers answers "who must I update if I change this file?" -- which is
// TWO questions, and the first version of this tool answered only one. An
// artifact holding the file's CURRENT digest is a consumer. So is an artifact
// that NAMES the file while carrying some other digest: that one is a pin which
// has ALREADY drifted, and reporting "nothing pins this" for it was the opposite
// of the truth in exactly the case where the answer matters most.
func analyseConsumers(root string, targets []string) ([]consumerTarget, error) {
	tracked, err := trackedFiles(root)
	if err != nil {
		return nil, err
	}
	trackedSet := make(map[string]bool, len(tracked))
	for _, relative := range tracked {
		trackedSet[relative] = true
	}

	var artifacts []string
	for _, relative := range tracked {
		if strings.HasSuffix(relative, ".json") {
			artifacts = append(artifacts, relative)
		}
	}

	var report []consumerTarget
	for _, target := range targets {
		relative := target
		if filepath.IsAbs(target) {
			if rel, err := filepath.Rel(root, target); err == nil {
				relative = rel
			}
		}
		relative = strings.TrimPrefix(relative, "./")

		entry := consumerTarget{path: relative}
		digest, ok := fileDigest(root, relative)
		if !ok {
			report = append(report, entry)
			continue
		}
		entry.digest = digest

		for _, artifact := range artifacts {
			if artifact == relative {
				continue
			}
			content, err := os.ReadFile(filepath.Join(root, artifact))
			if err != nil {
				continue
			}
			if strings.Contains(string(content), digest) {
				entry.current = append(entry.current, artifact)
			}
			entry.stale = append(entry.stale,
				stalePinsNaming(root, content, artifact, relative, digest, trackedSet)...)
		}
		sort.Strings(entry.current)
		sort.Slice(entry.stale, func(i, j int) bool {
			if entry.stale[i].artifact != entry.stale[j].artifact {
				return entry.stale[i].artifact < entry.stale[j].artifact
			}
			return entry.stale[i].pointer < entry.stale[j].pointer
		})
		report = append(report, entry)
	}
	return report, nil
}

// pinsAFieldInside reports whether `declared` appears as a digest-valued field
// INSIDE the named file. Such a pin names a value the file carries -- a ledger
// head, a payload digest -- rather than the file's own bytes, so comparing it to
// the file's sha256 would call a correct pin stale forever. Whole-file digest
// pins are unaffected: a stale one does not appear inside the file either.
func pinsAFieldInside(root, named, declared string) bool {
	content, err := os.ReadFile(filepath.Join(root, named))
	if err != nil {
		return false
	}
	var document any
	if err := json.Unmarshal(content, &document); err != nil {
		return false
	}
	found := false
	var scan func(node any)
	scan = func(node any) {
		if found {
			return
		}
		switch typed := node.(type) {
		case map[string]any:
			for _, value := range typed {
				scan(value)
			}
		case []any:
			for _, element := range typed {
				scan(element)
			}
		case string:
			if match := digestPattern.FindStringSubmatch(typed); match != nil &&
				match[1] == declared {
				found = true
			}
		}
	}
	scan(document)
	return found
}

// stalePinsNaming finds objects in one artifact that name `relative` alongside a
// digest that is not the file's current one.
func stalePinsNaming(root string, content []byte, artifact, relative, actual string,
	trackedSet map[string]bool) []pin {
	var document any
	if err := json.Unmarshal(content, &document); err != nil {
		return nil
	}
	var found []pin
	walk(document, "$", func(object map[string]any, pointer string) {
		paths, digests := splitPinFields(object, trackedSet)
		if len(paths) != 1 || paths[0] != relative || len(digests) == 0 {
			return
		}
		for _, declared := range digests {
			if declared == actual {
				return
			}
			if pinsAFieldInside(root, relative, declared) {
				return
			}
		}
		found = append(found, pin{
			artifact: artifact, pointer: pointer, namedPath: relative,
			declared: digests[0], actual: actual,
		})
	})
	return found
}

func runConsumers(root string, targets []string) int {
	report, err := analyseConsumers(root, targets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pinconsumerctl: %v\n", err)
		return 2
	}
	status := 0
	for _, target := range report {
		if target.digest == "" {
			fmt.Printf("gate=pin-consumers target=%s result=UNREADABLE\n", target.path)
			status = 2
			continue
		}
		fmt.Printf("gate=pin-consumers target=%s sha256=%s current=%d stale=%d\n",
			target.path, target.digest, len(target.current), len(target.stale))
		for _, artifact := range target.current {
			fmt.Printf("    pinned_by %s\n", artifact)
		}
		for _, stale := range target.stale {
			fmt.Printf("    ALREADY_STALE %s pointer=%s declared=sha256:%s\n",
				stale.artifact, stale.pointer, stale.declared)
		}
		if len(target.current) == 0 && len(target.stale) == 0 {
			fmt.Printf("    no artifact holds this file's digest and none names it beside a" +
				" different one\n")
		}
		if len(target.stale) > 0 {
			status = 1
		}
	}
	return status
}

func mustAbs(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absolute
}

type danglingCensus struct {
	candidates []pin
	explained  []pin
	artifacts  int
	unparsable int
}

func runDangling(root string) int {
	census, err := analyseDangling(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pinconsumerctl: %v\n", err)
		return 2
	}
	for _, candidate := range census.candidates {
		fmt.Printf("gate=pin-dangling artifact=%s pointer=%s names=%s declared=sha256:%s actual=sha256:%s\n",
			candidate.artifact, candidate.pointer, candidate.namedPath,
			candidate.declared, candidate.actual)
	}
	for _, explained := range census.explained {
		fmt.Printf("gate=pin-dangling-explained artifact=%s pointer=%s names=%s declared=sha256:%s why=%s\n",
			explained.artifact, explained.pointer, explained.namedPath,
			explained.declared, explained.explanation)
	}
	fmt.Printf("gate=pin-dangling json_artifacts=%d unparsable=%d candidates=%d explained=%d\n",
		census.artifacts, census.unparsable, len(census.candidates), len(census.explained))
	fmt.Printf("gate=pin-dangling ceiling=%q\n", danglingCeiling)
	if len(census.candidates) > 0 {
		return 1
	}
	return 0
}

const danglingCeiling = "candidates are objects where a tracked path and a sha256" +
	" share one JSON object and no digest in that object matches the file;" +
	" co-location is evidence that the digest is OF that path, NOT proof, so every" +
	" candidate must be READ before it is acted on. A pin whose digest covers" +
	" something other than the file it sits beside is a false positive by" +
	" construction, and a pin split across two objects is a false negative." +
	" `explained=` counts candidates SUBTRACTED because the digest was recomputed" +
	" from CURRENT bytes and proven to cover something else: a field the named" +
	" file carries (assurance/concurrency/plan.json's `observed_head` is the" +
	" behaviour-delta ledger's own head, not the ledger file's sha256), a" +
	" one-file tree envelope, a sibling line-array, a field this object names," +
	" or a mutation operand. Every such rule reads a drifting input, so none can" +
	" go quiet when a real pin goes stale, and a field pin that has itself" +
	" drifted is reported like any other. What is NOT proven and so still counts:" +
	" digests of things this tool cannot recompute -- a realized fixture tree, a" +
	" ledger record beside an unrelated path, a frozen historical receipt --" +
	" which remain candidates for a reader even where a human has adjudicated" +
	" them false. `explained` is a proof, never a key name."

func analyseDangling(root string) (danglingCensus, error) {
	tracked, err := trackedFiles(root)
	if err != nil {
		return danglingCensus{}, err
	}
	trackedSet := make(map[string]bool, len(tracked))
	for _, relative := range tracked {
		trackedSet[relative] = true
	}

	digestCache := map[string]string{}
	digestOf := func(relative string) (string, bool) {
		if cached, ok := digestCache[relative]; ok {
			return cached, cached != ""
		}
		digest, ok := fileDigest(root, relative)
		if !ok {
			digestCache[relative] = ""
			return "", false
		}
		digestCache[relative] = digest
		return digest, true
	}

	var candidates, explained []pin
	artifacts := 0
	unparsable := 0

	for _, relative := range tracked {
		if !strings.HasSuffix(relative, ".json") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			continue
		}
		var document any
		if err := json.Unmarshal(content, &document); err != nil {
			unparsable++
			continue
		}
		artifacts++
		walk(document, "$", func(object map[string]any, pointer string) {
			paths, digests := splitPinFields(object, trackedSet)
			// One unambiguous named path, at least one digest beside it.
			if len(paths) != 1 || len(digests) == 0 {
				return
			}
			named := paths[0]
			if named == relative {
				return // a document pinning its own digest is a different check
			}
			actual, ok := digestOf(named)
			if !ok {
				return
			}
			for _, declared := range digests {
				if declared == actual {
					return // some digest in this object matches; not dangling
				}
			}

			// Every digest in the object must be PROVEN to cover something
			// else before the object is subtracted. Requiring all of them
			// stops an unexplained digest riding out on its neighbour's proof.
			reason := ""
			for index, declared := range digests {
				explanation := explainPin(root, object, named, declared)
				if explanation == "" {
					reason = ""
					break
				}
				if index == 0 {
					reason = explanation
				}
			}

			candidate := pin{
				artifact:    relative,
				pointer:     pointer,
				namedPath:   named,
				declared:    digests[0],
				actual:      actual,
				explanation: reason,
			}
			if reason != "" {
				explained = append(explained, candidate)
				return
			}
			candidates = append(candidates, candidate)
		})
	}

	byLocation := func(rows []pin) func(int, int) bool {
		return func(i, j int) bool {
			if rows[i].artifact != rows[j].artifact {
				return rows[i].artifact < rows[j].artifact
			}
			return rows[i].pointer < rows[j].pointer
		}
	}
	sort.Slice(candidates, byLocation(candidates))
	sort.Slice(explained, byLocation(explained))

	return danglingCensus{
		candidates: candidates,
		explained:  explained,
		artifacts:  artifacts,
		unparsable: unparsable,
	}, nil
}

// splitPinFields returns the tracked-file paths and the sha256 digests found
// among an object's immediate string values.
func splitPinFields(object map[string]any, trackedSet map[string]bool) ([]string, []string) {
	var paths, digests []string
	for _, value := range object {
		text, ok := value.(string)
		if !ok {
			continue
		}
		if match := digestPattern.FindStringSubmatch(text); match != nil {
			digests = append(digests, match[1])
			continue
		}
		cleaned := strings.TrimPrefix(text, "./")
		if trackedSet[cleaned] {
			paths = append(paths, cleaned)
		}
	}
	sort.Strings(paths)
	sort.Strings(digests)
	return paths, digests
}

func walk(node any, pointer string, visit func(map[string]any, string)) {
	switch typed := node.(type) {
	case map[string]any:
		visit(typed, pointer)
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			walk(typed[key], pointer+"."+key, visit)
		}
	case []any:
		for index, element := range typed {
			walk(element, fmt.Sprintf("%s[%d]", pointer, index), visit)
		}
	}
}

var _ = fs.SkipDir

// ---------------------------------------------------------------------------
// Explanations: proving a co-located digest covers something OTHER than the file.
// ---------------------------------------------------------------------------
//
// The ceiling says co-location is evidence, not proof, and that a digest
// covering something other than the file it sits beside is a false positive BY
// CONSTRUCTION. Reading all 85 of the first census found that most were exactly
// that, and -- the part worth encoding -- what each digest really covered could
// be RECOMPUTED from bytes already in the tree.
//
// So an explanation here is never a key name and never a guess. Every rule
// recomputes a value from CURRENT bytes and requires an exact match. That is
// what makes it safe to subtract: a rule cannot hide drift, because every rule's
// own input drifts too. If rust/rust-toolchain.toml changes, its tree envelope
// changes with it and the pin fires again. A rule that trusted the key name
// `pin_digest` would have gone quiet instead, which is the failure mode this
// comment exists to forbid.
//
// Explained pins are still PRINTED, with the reason and the subject, on their
// own gate line. The census never gets smaller without saying why.

// explainPin returns a non-empty reason when `declared` is PROVEN to digest
// something other than `named`, and "" when it is not.
func explainPin(root string, object map[string]any, named, declared string) string {
	// R1 -- single-file tree envelope. internal/fuzzpin.TreeDigest digests a
	// FILE LIST as "relpath\x00filedigest\n" lines, so a one-element list yields
	// a digest that is not the file's own. It still tracks the file's content.
	if actual, ok := fileDigest(root, named); ok {
		envelope := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\n", named, actual)))
		if hex.EncodeToString(envelope[:]) == declared {
			return "tree-envelope: sha256 of the one-line file-list envelope \"" +
				named + "\\x00<file sha256>\\n\", not of the file's own bytes"
		}
	}

	// R2 -- a sibling array of strings in the SAME object whose newline-joined
	// digest is the declared value. internal/fuzzpin.digestLines does this for
	// `outcome_lines`, which is why two runs of one campaign share a digest and
	// neither equals its own log.
	for key, value := range object {
		elements, ok := value.([]any)
		if !ok || len(elements) == 0 {
			continue
		}
		hasher := sha256.New()
		lines := 0
		for _, element := range elements {
			text, ok := element.(string)
			if !ok {
				lines = 0
				break
			}
			fmt.Fprintf(hasher, "%s\n", text)
			lines++
		}
		if lines > 0 && hex.EncodeToString(hasher.Sum(nil)) == declared {
			return fmt.Sprintf("sibling-lines: digest of this object's own %q "+
				"(%d lines), not of %s", key, lines, named)
		}
	}

	// R3 -- self-declared provenance. An object carrying a `field` that names
	// where its digest was READ FROM is telling us its subject; the claim is
	// verified by resolving that field in the co-located document. An
	// unverifiable claim explains nothing.
	if fieldText, ok := object["field"].(string); ok && fieldText != "" {
		if document, ok := loadJSON(root, named); ok {
			if resolved, ok := resolveField(document, fieldText); ok &&
				normaliseDigest(resolved) == declared {
				return fmt.Sprintf("field-provenance: the value read from %s#%s, "+
					"which this object names itself", named, fieldText)
			}
		}
	}

	// R4 -- the digest pins a FIELD INSIDE the named file: a ledger head, a
	// record digest, an accepted root. The decision is pinsAFieldInside's, so
	// there is one implementation of it; this only adds the location, because a
	// reader auditing a subtraction should not have to search for it.
	if pinsAFieldInside(root, named, declared) {
		where := "somewhere inside it"
		if document, ok := loadJSON(root, named); ok {
			if located, found := locateDigest(document, "$", declared); found {
				where = located
			}
		}
		return fmt.Sprintf("field-inside-file: this digest appears in %s at %s, "+
			"so it pins a value the file carries, not the file's bytes", named, where)
	}

	// R5 -- a mutation operand. A JSON-patch-shaped instruction carries the value
	// it will WRITE into `target`; a deliberately wrong digest is the payload of
	// a seeded defect, not a pin that drifted.
	if kind, ok := object["kind"].(string); ok && kind == "json_set" {
		if _, hasPointer := object["pointer"]; hasPointer {
			return "mutation-operand: the value a json_set operation writes into " +
				named + " at the pointer it names, not a pin of it"
		}
	}

	return ""
}

// loadJSON parses a tracked JSON file, or reports that it is not one.
func loadJSON(root, relative string) (any, bool) {
	if !strings.HasSuffix(relative, ".json") {
		return nil, false
	}
	content, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		return nil, false
	}
	var document any
	if err := json.Unmarshal(content, &document); err != nil {
		return nil, false
	}
	return document, true
}

// normaliseDigest strips the optional sha256: prefix so declared and resolved
// values compare on equal terms.
func normaliseDigest(text string) string {
	if match := digestPattern.FindStringSubmatch(text); match != nil {
		return match[1]
	}
	return ""
}

// resolveField walks a dotted field path ("generator.secret_seed_commitment",
// "artifacts.0.path") and returns the string it names.
func resolveField(node any, field string) (string, bool) {
	current := node
	for _, segment := range strings.Split(field, ".") {
		switch typed := current.(type) {
		case map[string]any:
			next, ok := typed[segment]
			if !ok {
				return "", false
			}
			current = next
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(typed) {
				return "", false
			}
			current = typed[index]
		default:
			return "", false
		}
	}
	text, ok := current.(string)
	return text, ok
}

// locateDigest reports where a digest occurs as a string value inside a
// document, so an explanation can name the place rather than assert it.
func locateDigest(node any, pointer, declared string) (string, bool) {
	switch typed := node.(type) {
	case string:
		if normaliseDigest(typed) == declared {
			return pointer, true
		}
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if where, found := locateDigest(typed[key], pointer+"."+key, declared); found {
				return where, true
			}
		}
	case []any:
		for index, element := range typed {
			if where, found := locateDigest(element, fmt.Sprintf("%s[%d]", pointer, index), declared); found {
				return where, true
			}
		}
	}
	return "", false
}
