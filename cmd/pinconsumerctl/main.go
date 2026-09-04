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

// coverage is a DECLARED exemption: a candidate whose digest this tool cannot
// recompute, but which a NAMED check elsewhere verifies by recomputation. It is
// not "some other layer would probably notice" -- that was rejected earlier in
// this project's history and rightly. Each entry names the file and the literal
// assertion that does the verifying, and `verifyCoverage` reads them back on
// every run: if the covering assertion is gone, the gate FAILS rather than
// silently keeping the exemption. Same shape as gosuitectl's declared exclusions
// and their stale-exclusion check.
type coverageClaim struct {
	artifact      string // the artifact holding the pins
	pointerPrefix string // pointers under this prefix are covered
	checkFile     string // the file containing the covering check
	assertion     string // a literal from that check, read back every run
	why           string
}

var coverage = []coverageClaim{
	{
		artifact:      "assurance/replay/fixtures/us006-cases.json",
		pointerPrefix: "$.cases[",
		checkFile:     "internal/formalplan/backend_test.go",
		assertion:     "realized digest %s != frozen %s",
		why: "realized_tree_sha256 is CANONICAL_PATH_SHA256_V1 over the tree PRODUCED BY " +
			"applying mutation_manifest_path, not a digest of that manifest. This tool cannot " +
			"recompute it without realizing the tree, so it does not guess: the covering check " +
			"realizes every case and compares, and failing it names US006_REGENERATE=1.",
	},
	{
		artifact:      "evidence/java/legacy-record-adjudications.json",
		pointerPrefix: "$.adjudications[",
		checkFile:     "internal/deltaledger/legacy_adjudication.go",
		assertion:     "the entry binds record_digest %s; the record digests to %s",
		why: "record_digest is the digest of the LEDGER RECORD this entry adjudicates, not of " +
			"the supersession_draft path that happens to sit in the same object -- the value is " +
			"in evidence/java/behavior-delta-ledger.json, which is a different file, so the " +
			"field-inside-file rule cannot see it. The covering check recomputes every record's " +
			"digest from its own bytes and refuses any entry whose binding has moved.",
	},
}

// verifyCoverage reads every coverage claim back against the tree. A claim whose
// covering assertion has vanished is a stale exemption -- the same lie about
// coverage a stale test exclusion tells -- so it fails rather than warns.
func verifyCoverage(root string) []string {
	var stale []string
	for _, claim := range coverage {
		content, err := os.ReadFile(filepath.Join(root, claim.checkFile))
		if err != nil {
			stale = append(stale, fmt.Sprintf("%s: covering file %s is unreadable: %v",
				claim.artifact, claim.checkFile, err))
			continue
		}
		if !strings.Contains(string(content), claim.assertion) {
			stale = append(stale, fmt.Sprintf("%s: %s no longer contains the covering assertion %q",
				claim.artifact, claim.checkFile, claim.assertion))
		}
	}
	return stale
}

// coveredBy returns the claim covering this candidate, if any.
func coveredBy(artifact, pointer string) *coverageClaim {
	for index := range coverage {
		claim := &coverage[index]
		if claim.artifact == artifact && strings.HasPrefix(pointer, claim.pointerPrefix) {
			return claim
		}
	}
	return nil
}

// allowance is a DECLARED, per-row acknowledgement of a TRUE finding that cannot
// be fixed from inside the loop. It is not an explanation and not a coverage
// claim: these pins really have drifted. The point is that a NEW drift must fail
// on the run it appears, which it cannot do if the census exits 1 forever on
// eleven rows nobody can act on.
//
// Each entry pins the DECLARED digest, so it cannot survive the pin being
// edited: change the pin and the row stops matching its allowance, which makes it
// either an unallowed candidate or a stale allowance -- both of which FAIL. And
// an allowance whose row is no longer a candidate at all fails as
// STALE_ALLOWANCE, so a fixed pin cannot leave a permanent exemption behind.
type allowedPin struct {
	artifact string
	pointer  string
	declared string // pinned, so editing the pin invalidates the allowance
	owner    string // the action that would let this entry be deleted
}

var allowance = []allowedPin{
	// A DENOMINATOR. The pin equals the recorded git.blob, but the anchor 1ff89fa
	// is not an ancestor of HEAD -- it exists only on read-only
	// origin/codex/race-catchup. reconcile.go already declares it drifted.
	{"assurance/formal/obligation-catalog.json", "$.denominator_basis[1]",
		"fa75348c37f607ac27edf41f13f075a6731b925628d9e9dcda7de39f0ea236e6",
		"DENOMINATOR, HARD STOP: decide the catalog's plane correspondence. Never re-baselined here."},
	{"assurance/formal/obligation-catalog.json", "$.denominator_basis[3]",
		"0117560795fbfbe92e1c11a999bcec937c4ab27950ba6e5a1d0f0c73a286602c",
		"DENOMINATOR, HARD STOP: same anchor, same decision."},
	{"assurance/formal/obligation-catalog.json", "$.denominator_basis[4]",
		"e884fd06a785b0273a0e23b3dc6841ebcc33c2a81d1fc81fb0b1945d46421e7b",
		"DENOMINATOR, HARD STOP: same anchor, same decision."},

	// Fixtures whose mismatch IS their assertion. A rule exempting these by
	// value was tried and REFUSED by the suite: repeated-character digests are
	// how this project writes "a real drifted pin" in a fixture, so a rule
	// keyed on that shape blinded the tests that prove drift is caught.
	{"assurance/fuzz/fixtures/toolchain-pin-drift.json", "$.engines[0].toolchain",
		"1111111111111111111111111111111111111111111111111111111111111111",
		"NONE. A drift-detection fixture must carry a digest that does not match; " +
			"delete this entry only if the fixture stops asserting drift."},
	{"assurance/replay/fixtures/us006-placeholder-receipt/mutation.json", "$.operations[1].value",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"NONE. A placeholder receipt's seeded value; the same reasoning as above."},

	// Pins of bytes that exist in NO branch, so there is nothing to diff and the
	// zero-changed-line test cannot be performed at all.
	{"drafts/ledger-proposals/java-formal-binding-corroborations.json", "$.evidence_basis.projection",
		"6275808310a724f3cfb03579103751b54c67874927f870f448f2ebbbdea2bd47",
		"Owner: supply the bytes this draft was written against, or withdraw the draft. " +
			"Until then no diff is possible."},
	{"drafts/ledger-proposals/java-formal-binding-corroborations.json", "$.evidence_basis.receipt",
		"1729001791383e7c50d7083ee8eb069db016420e3632cb059d2ea5c3a2e58b04",
		"Owner: same draft as the row above, same missing bytes; both must arrive or the " +
			"draft must be withdrawn together."},

	// A DATED ATTESTATION, not a live pin: the current digests are already
	// recorded at $.review_round_5 in the same document. Rewriting these would
	// falsify what was attested at the time.
	{"evidence/governance/decisions/e3-formal-receipt.json", "$.artifacts.results_documents[0]",
		"b404378cb2527ce86246179adc9f4db4e129806c7710fc2b7604b50f86789a3d",
		"NONE, and it must NOT be updated: a dated attestation records what was true then."},
	{"evidence/governance/decisions/e3-formal-receipt.json", "$.artifacts.results_documents[1]",
		"c8ba80e07fbe309ca8a7a4c9985fc176fa764462a1f0a66338b1abc616f660c7",
		"NONE, and it must NOT be updated: same receipt."},

	// SURFACED BY CLOSING C2. denominator-reconciliation.json records, for each
	// declared basis pin, BOTH the catalog's declared digest and the file's
	// current one. The current one matched, so the object exited on the first
	// matching digest and took the drifted `catalog_declared_sha256` with it.
	// These are the SAME three findings as the three rows above -- identical
	// declared digests -- recorded at the reconciliation document, which states
	// the drift itself as `BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK`.
	{"assurance/formal/denominator-reconciliation.json", "$.catalog_declared_basis_pins[1]",
		"fa75348c37f607ac27edf41f13f075a6731b925628d9e9dcda7de39f0ea236e6",
		"DENOMINATOR, HARD STOP: the mirror of obligation-catalog.json $.denominator_basis[1]. " +
			"It is deleted when that one is, by the same plane-correspondence decision, and " +
			"never by editing this document."},
	{"assurance/formal/denominator-reconciliation.json", "$.catalog_declared_basis_pins[3]",
		"0117560795fbfbe92e1c11a999bcec937c4ab27950ba6e5a1d0f0c73a286602c",
		"DENOMINATOR, HARD STOP: the mirror of obligation-catalog.json $.denominator_basis[3], " +
			"same anchor, same decision."},
	{"assurance/formal/denominator-reconciliation.json", "$.catalog_declared_basis_pins[4]",
		"e884fd06a785b0273a0e23b3dc6841ebcc33c2a81d1fc81fb0b1945d46421e7b",
		"DENOMINATOR, HARD STOP: the mirror of obligation-catalog.json $.denominator_basis[4], " +
			"same anchor, same decision."},

	// SURFACED BY CLOSING C1. The E3 receipt's models_authored[1] names TWO
	// tracked paths, close-model.tla and its .cfg, so the whole object was
	// skipped and BOTH of its digests went unchecked. Both have drifted:
	// commit 8f19e2b ("review round 2: fix the vacuous close invariant")
	// rewrote both files. models_authored[0], the frame model, was untouched by
	// that commit and still matches exactly -- which is the control that says
	// this row is a real finding and not a rule firing on everything.
	{"evidence/governance/decisions/e3-formal-receipt.json", "$.models_authored[1]",
		"36370b0f30d0a47f942ae240312397b78aaf64b2ce2a08024b73187f4d4cd8a9," +
			"c9072fa4c03036ea20a9b63bf48c976bbe5f3b2fd5c620439b31d58ca777c3f2",
		"OWNER DECISION: unlike the two results_documents rows above, the post-round-2 " +
			"digests appear NOWHERE in this receipt, so a reader cannot tell which " +
			"CloseModel the recorded TLC run checked. Either record the round-2 digests " +
			"beside the round-1 ones the way $.review_round_5 does, or state that " +
			"models_authored describes the round-1 authored bytes only. Do not rewrite " +
			"the attested values: this is a dated attestation."},

	// F014. The execution_code_binding claims to bind the code that produced the
	// authoritative run, and both digests have moved.
	{"evidence/java/test-manifest.json", "$.authoritative_run.execution_code_binding.sources[0]",
		"863bc6d7c2b3e6d4b13332f2b883539676c206d3df283158b8a9c254713cfa42",
		"OWNER DECISION (F014): re-run the authoritative run against current code, or " +
			"record that the binding describes a historical run and stop calling it a binding."},
	{"evidence/java/test-manifest.json", "$.authoritative_run.execution_code_binding.sources[2]",
		"acb7ecd0b2cf917673342506ad25a43cbce83ab87b2ea4832cdfefd23f7374cf",
		"OWNER DECISION (F014): same manifest, same choice."},
}

// allowanceFor returns the entry acknowledging this exact candidate, matching on
// artifact, pointer AND the declared digest -- so an edited pin loses its
// allowance rather than inheriting it.
func allowanceFor(artifact, pointer, declared string) *allowedPin {
	for index := range allowance {
		entry := &allowance[index]
		if entry.artifact == artifact && entry.pointer == pointer &&
			entry.declared == declared {
			return entry
		}
	}
	return nil
}

// stalePinsNaming finds objects in one artifact that name `relative` alongside a
// digest that is not the file's current one.
//
// It carries the SAME C1/C2 fix as `dangling`, through the same
// `unaccountedDigests`: the object used to be abandoned whole the moment it
// named a second tracked path, or the moment ONE of its digests matched, or the
// moment one of them turned out to be a field inside the named file. Each of
// those exits took every other digest in the object with it, so `consumers`
// answered "nothing stale here" for a file with a drifted pin sitting one key
// away from a correct one.
func stalePinsNaming(root string, content []byte, artifact, relative, actual string,
	trackedSet map[string]bool) []pin {
	var document any
	if err := json.Unmarshal(content, &document); err != nil {
		return nil
	}
	var found []pin
	walk(document, "$", func(object map[string]any, pointer string) {
		paths, digests := splitPinFields(object, trackedSet)
		if len(digests) == 0 {
			return
		}
		names := false
		for _, candidate := range paths {
			if candidate == relative {
				names = true
			}
		}
		if !names {
			return
		}
		// Every path named here, so a digest belonging to a SIBLING path is
		// not reported against this one.
		var actuals []string
		for _, candidate := range paths {
			if current, ok := fileDigest(root, candidate); ok {
				actuals = append(actuals, current)
			}
		}
		var unaccounted []string
		for _, declared := range unaccountedDigests(digests, actuals) {
			if pinsAFieldInside(root, relative, declared) {
				continue // a value the named file carries, not its bytes
			}
			unaccounted = append(unaccounted, declared)
		}
		if len(unaccounted) == 0 {
			return
		}
		found = append(found, pin{
			artifact: artifact, pointer: pointer, namedPath: relative,
			declared: strings.Join(unaccounted, ","), actual: actual,
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
			fmt.Printf("    ALREADY_STALE %s pointer=%s declared=%s\n",
				stale.artifact, stale.pointer, digestList(stale.declared))
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

// digestList prefixes every element of a comma-joined digest list, so a row
// carrying one digest prints `sha256:a` exactly as it always did and a row
// carrying two prints `sha256:a,sha256:b` rather than prefixing only the first.
func digestList(joined string) string {
	parts := strings.Split(joined, ",")
	for index := range parts {
		parts[index] = "sha256:" + parts[index]
	}
	return strings.Join(parts, ",")
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
	// unparsablePaths names them. A tracked .json the index cannot parse is a
	// SILENT subtraction of every pin it holds: adversarial review C8 hid a real
	// drifted pin behind one trailing comma, and the census moved only from
	// `unparsable=0` to `unparsable=1` with no file named and result=PASS.
	unparsablePaths []string
	// missing holds pins whose named target git still tracks but the worktree
	// no longer holds. This is a SEPARATE count from `candidates` on purpose:
	// no digest has drifted, the thing the digest was of is gone. It was the
	// silent half of adversarial review C9 -- `digestOf` failing returned out
	// of the object before any check ran, so deleting the pinned file was a
	// clean exit 0 in a gate called `dangling`.
	missing []pin
}

func runDangling(root string) int {
	census, err := analyseDangling(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pinconsumerctl: %v\n", err)
		return 2
	}
	stale := verifyCoverage(root)
	for _, problem := range stale {
		fmt.Printf("gate=pin-dangling finding=STALE_COVERAGE_CLAIM detail=%q\n", problem)
	}
	// A tracked .json that does not parse takes every pin it holds out of the
	// census. Naming it and refusing is the only honest reading: the alternative
	// is a number moving by one with nothing said, which is what C8 exploited.
	for _, path := range census.unparsablePaths {
		fmt.Printf("gate=pin-dangling finding=UNPARSABLE_ARTIFACT artifact=%s detail=%q\n",
			path, "this tracked .json does not parse, so every pin inside it is absent "+
				"from the census rather than clean; fix the file or the census is short")
	}
	// A pin whose target git tracks but the worktree no longer holds. The pin
	// has not drifted; its subject is gone, which is strictly worse, and until
	// now it was the quietest exit in this tool.
	for _, gone := range census.missing {
		fmt.Printf("gate=pin-dangling finding=MISSING_PIN_TARGET artifact=%s pointer=%s "+
			"names=%s declared=%s detail=%q\n",
			gone.artifact, gone.pointer, gone.namedPath, digestList(gone.declared),
			"git tracks this path but the worktree does not hold it, so the digest "+
				"beside it can no longer be checked against anything; restore the file "+
				"or remove the pin")
	}

	remaining := 0
	acknowledged := map[*allowedPin]bool{}
	for _, candidate := range census.candidates {
		if claim := coveredBy(candidate.artifact, candidate.pointer); claim != nil && len(stale) == 0 {
			fmt.Printf("gate=pin-dangling-covered artifact=%s pointer=%s names=%s "+
				"declared=%s by=%s assertion=%q why=%s\n",
				candidate.artifact, candidate.pointer, candidate.namedPath,
				digestList(candidate.declared), claim.checkFile, claim.assertion, claim.why)
			continue
		}
		if entry := allowanceFor(candidate.artifact, candidate.pointer,
			candidate.declared); entry != nil {
			acknowledged[entry] = true
			fmt.Printf("gate=pin-dangling-allowed artifact=%s pointer=%s names=%s "+
				"declared=%s actual=%s owner=%q\n",
				candidate.artifact, candidate.pointer, candidate.namedPath,
				digestList(candidate.declared), digestList(candidate.actual), entry.owner)
			continue
		}
		remaining++
		fmt.Printf("gate=pin-dangling artifact=%s pointer=%s names=%s declared=%s actual=%s\n",
			candidate.artifact, candidate.pointer, candidate.namedPath,
			digestList(candidate.declared), digestList(candidate.actual))
	}

	// An allowance whose row is no longer a candidate has outlived the finding it
	// acknowledged. Left in place it would silently exempt whatever next lands at
	// that artifact and pointer, so it fails.
	var orphaned []string
	for index := range allowance {
		entry := &allowance[index]
		if !acknowledged[entry] {
			orphaned = append(orphaned, fmt.Sprintf("%s %s (declared sha256:%s)",
				entry.artifact, entry.pointer, entry.declared))
		}
	}
	for _, entry := range orphaned {
		fmt.Printf("gate=pin-dangling finding=STALE_ALLOWANCE detail=%q\n",
			entry+" is allowed but is no longer a candidate; the acknowledgement "+
				"outlived the finding and must be deleted")
	}
	for _, explained := range census.explained {
		fmt.Printf("gate=pin-dangling-explained artifact=%s pointer=%s names=%s declared=%s why=%s\n",
			explained.artifact, explained.pointer, explained.namedPath,
			digestList(explained.declared), explained.explanation)
	}
	fmt.Printf("gate=pin-dangling json_artifacts=%d unparsable=%d candidates=%d explained=%d "+
		"covered=%d allowed=%d missing_targets=%d\n",
		census.artifacts, census.unparsable, remaining, len(census.explained),
		len(census.candidates)-remaining-len(acknowledged), len(acknowledged),
		len(census.missing))
	fmt.Printf("gate=pin-dangling ceiling=%q\n", danglingCeiling)
	if reason := danglingRefusal(census, stale, orphaned, remaining); reason != "" {
		fmt.Printf("gate=pin-dangling result=FAIL reason=%q\n", reason)
		return 1
	}
	fmt.Printf("gate=pin-dangling result=PASS detail=%q\n",
		fmt.Sprintf("no undeclared drift; %d acknowledged finding(s) each naming an owner action",
			len(acknowledged)))
	return 0
}

// danglingRefusal returns the reason this run must FAIL, or "" to PASS. It is a
// separate function so every refusal can be exercised by a test even when the
// live tree has none of that condition. MISSING_PIN_TARGET was exactly that
// case: `missing_targets=0` today, so a deletion attack that neutered only the
// refusal left the whole suite green while the gate had stopped refusing.
func danglingRefusal(census danglingCensus, staleCoverage, orphaned []string,
	remaining int) string {
	if len(staleCoverage) > 0 {
		return "a coverage claim names a check that is no longer there; the exemption " +
			"outlived the check and every row it covered is unverified"
	}
	if len(census.unparsablePaths) > 0 {
		return fmt.Sprintf("%d tracked .json artifact(s) do not parse, so this census is "+
			"SHORT by however many pins they hold", len(census.unparsablePaths))
	}
	if len(census.missing) > 0 {
		return fmt.Sprintf("%d pin(s) name a tracked path the worktree no longer holds; a pin "+
			"whose subject is gone is the most dangling pin there is", len(census.missing))
	}
	if len(orphaned) > 0 {
		return "an allowance outlived the finding it acknowledged; delete it, or it will " +
			"exempt whatever next lands at that artifact and pointer"
	}
	if remaining > 0 {
		return "a pin has drifted and is not among the declared allowances; read it, then " +
			"either fix the pin or acknowledge it with the owner action it waits on"
	}
	return ""
}

const danglingCeiling = "candidates are objects where a tracked path and a sha256" +
	" share one JSON object and NO digest in that object is the CURRENT digest of" +
	" ANY tracked path named in it;" +
	" co-location is evidence that the digest is OF that path, NOT proof, so every" +
	" candidate must be READ before it is acted on. A pin whose digest covers" +
	" something other than the file it sits beside is a false positive by" +
	" construction, and a pin split across two objects is a false negative." +
	" An object naming several paths, or carrying several unaccounted digests, is" +
	" ONE row whose names=, declared= and actual= lists are each sorted and are" +
	" NOT positionally paired: it asserts that none of those digests is the current" +
	" digest of any of those paths, and which was meant for which is the reader's." +
	" In such an object an explanation may resolve against any of the paths named." +
	" TWO ASYMMETRIC HOLES IN THE PATH CORPUS, both MEASURED rather than assumed." +
	" A path here is a string git TRACKS." +
	" (1) A pin naming a path git tracks but the worktree does not hold IS" +
	" reported, as MISSING_PIN_TARGET counted in missing_targets=, and it FAILS" +
	" the gate -- git says the path is real, so nothing there is a guess." +
	" (2) A pin naming an UNTRACKED path is NOT SEEN AT ALL, and that is a" +
	" deliberate refusal, not an oversight. ITS LIVE EXAMPLE IS GONE, and by the" +
	" artifact arriving rather than by the hole closing:" +
	" obligation-catalog.json $.denominator_basis[2] names corpora/frame/codec.json," +
	" which was absent from this plane and which this census therefore never" +
	" counted; on 2026-09-04, under owner action OA-catalog-plane-denominator, that" +
	" artifact was brought onto this line byte-identically to the blob the pin" +
	" declares, so the pin now sits inside `git ls-files`, its declared digest IS" +
	" the file's current one, and reconcile.go reports it as" +
	" BASIS_PIN_MATCHES_FILE_ON_DISK. The MECHANISM is untouched, no allowance" +
	" moved, and the corpus decision is still the owner's (OA-pin-path-corpus)." +
	" Closing the hole needs a WIDER corpus and both widenings were measured when" +
	" this census read 1997 artifacts: paths git has EVER tracked added 26 rows --" +
	" 24 the vendored catalog's rust_bindings, and 2 the codec.json pin and its" +
	" reconciliation mirror -- and re-admits ignored trees, `.quarantine` being in" +
	" that set, which is F011 exactly; path-SHAPED strings added 662, most of them" +
	" version numbers like `21.0.4`. NEITHER TOTAL IS CURRENT: compare the artifact" +
	" count in the census line above with the 1997 those two were measured over." +
	" What WAS re-measured on 2026-09-04 is the part the codec.json move touches:" +
	" its 2 rows have left the ever-tracked widening, and the other 24 remain, on" +
	" all four of the source paths they name. Either widening changes what the" +
	" corpus contains and lands rows on the formal denominator's declared basis," +
	" so the hole is disclosed here instead of being closed from inside a gate fix." +
	" `explained=` counts candidates SUBTRACTED because the digest was recomputed" +
	" from CURRENT bytes and proven to cover something else: a field the named" +
	" file carries (assurance/concurrency/plan.json's `observed_head` is the" +
	" behaviour-delta ledger's own head, not the ledger file's sha256), a" +
	" one-file tree envelope, a sibling line-array, a field this object names," +
	" or a mutation operand. FOUR of the five rules read a drifting input and were" +
	" VERIFIED to by perturbing it: tree-envelope, sibling-lines, field-provenance" +
	" and field-inside-file each return their rows as candidates when the value" +
	" they recompute changes. THE MUTATION-OPERAND RULE DOES NOT AND CANNOT: a" +
	" mutation operand is a value deliberately absent from the tree, so its 4 rows" +
	" rest on a STRUCTURAL check -- the object is a json_set whose declared target" +
	" is this file and whose own `value` is this digest -- and must be read as" +
	" declared, never as measured. field-inside-file is also weaker than the" +
	" sentence it prints: the decision is whether the digest occurs ANYWHERE as a" +
	" string in the named file, not at the location the message names, so a file" +
	" that records its own former whole-file digest launders every stale pin of" +
	" itself. sibling-lines is narrow in the other direction: it digests the" +
	" object's OWN array, so by construction its rows can never re-fire on a" +
	" change to the FILE they name -- that array is their subject by intent." +
	" A field pin that has itself" +
	" drifted is reported like any other. What is NOT proven and so still counts:" +
	" digests of things this tool cannot recompute -- a realized fixture tree, a" +
	" ledger record beside an unrelated path, a frozen historical receipt --" +
	" which remain candidates for a reader even where a human has adjudicated" +
	" them false. `explained` is a proof, never a key name." +
	" `covered=` IS DIFFERENT IN KIND AND MUST NOT BE READ AS `explained=`: those" +
	" rows are DECLARED exemptions, not recomputations. This tool cannot realize a" +
	" us006 fixture tree, so it does not pretend to; a NAMED check elsewhere" +
	" (internal/formalplan/backend_test.go) realizes every case and compares, and" +
	" this gate reads that assertion back on every run -- if it is gone the claim" +
	" becomes STALE_COVERAGE_CLAIM, the gate FAILS, and every covered row returns" +
	" as a candidate. A coverage claim therefore cannot outlive the check it names," +
	" but it remains a claim about someone else's check, not a measurement here."

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

	var candidates, explained, missing []pin
	var unparsablePaths []string
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
			unparsablePaths = append(unparsablePaths, relative)
			continue
		}
		artifacts++
		walk(document, "$", func(object map[string]any, pointer string) {
			paths, digests := splitPinFields(object, trackedSet)
			if len(paths) == 0 || len(digests) == 0 {
				return
			}
			// Split the paths this object names into the ones that can be
			// digested and the ones git tracks but the worktree no longer
			// holds. Adversarial review C9 deleted a pinned target and the
			// census said nothing at all, because the second group used to
			// fall out of an `if !ok { return }` that also discarded every
			// digest beside it.
			named, actuals, absent := namedTargets(paths, relative, digestOf)
			for _, gone := range absent {
				missing = append(missing, pin{
					artifact: relative, pointer: pointer, namedPath: gone,
					declared: digests[0],
				})
			}
			if len(named) == 0 {
				return
			}

			// A digest is ACCOUNTED FOR only when it is the CURRENT digest of
			// one of the paths named right here. Adversarial review C1 added a
			// second tracked path and C2 added one correct sibling digest;
			// each made the whole object vanish, drifted digests included.
			// Neither exits the object any more: only the digest that actually
			// matches is subtracted, and only for the path it matches.
			unaccounted := unaccountedDigests(digests, actuals)
			if len(unaccounted) == 0 {
				return
			}

			// Every unaccounted digest must be PROVEN to cover something else
			// before the object is subtracted. Requiring all of them stops an
			// unexplained digest riding out on its neighbour's proof.
			reason := ""
			for index, declared := range unaccounted {
				explanation := ""
				for _, subject := range named {
					if found := explainPin(root, object, subject, declared); found != "" {
						explanation = found
						break
					}
				}
				if explanation == "" {
					reason = ""
					break
				}
				if index == 0 {
					reason = explanation
				}
			}

			// An object naming several paths or carrying several unaccounted
			// digests gets ONE row listing all of them, comma-joined. The
			// lists are each sorted and are NOT positionally paired: the
			// claim a multi-valued row makes is that none of these digests is
			// the current digest of any of these paths. A single-path,
			// single-digest row -- which is every row in the live census
			// before this change -- prints exactly as it did.
			candidate := pin{
				artifact:    relative,
				pointer:     pointer,
				namedPath:   strings.Join(named, ","),
				declared:    strings.Join(unaccounted, ","),
				actual:      strings.Join(actuals, ","),
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
	sort.Slice(missing, byLocation(missing))

	sort.Strings(unparsablePaths)
	return danglingCensus{
		candidates:      candidates,
		explained:       explained,
		missing:         missing,
		artifacts:       artifacts,
		unparsable:      unparsable,
		unparsablePaths: unparsablePaths,
	}, nil
}

// namedTargets splits the tracked paths an object names into the ones that can
// be digested now (with their current digests, positionally aligned) and the
// ones git still tracks but the worktree no longer holds. The artifact's own
// path is dropped: a document pinning its own digest is a different check.
//
// It returns the ABSENT paths instead of swallowing them. `digestOf` failing
// used to `return` out of the whole object, which is why C9 -- deleting the
// pinned file -- produced exit 0 with no line printed, in the gate whose name
// is `dangling`.
func namedTargets(paths []string, relative string,
	digestOf func(string) (string, bool)) (named, actuals, absent []string) {
	seen := map[string]bool{}
	for _, candidate := range paths {
		if candidate == relative || seen[candidate] {
			continue
		}
		seen[candidate] = true
		digest, ok := digestOf(candidate)
		if !ok {
			absent = append(absent, candidate)
			continue
		}
		named = append(named, candidate)
		actuals = append(actuals, digest)
	}
	return named, actuals, absent
}

// unaccountedDigests returns the declared digests that are NOT the current
// digest of any path named in the same object.
//
// This is the whole of the C1/C2 fix and it is deliberately one function used
// by both `dangling` and `consumers`: the previous code exited the entire
// object on the first favourable thing it found in it -- a second path it could
// not attribute, or one digest that happened to match -- and everything else in
// the object left with it.
func unaccountedDigests(digests, actuals []string) []string {
	accounted := make(map[string]bool, len(actuals))
	for _, current := range actuals {
		accounted[current] = true
	}
	var unaccounted []string
	for _, declared := range digests {
		if !accounted[declared] {
			unaccounted = append(unaccounted, declared)
		}
	}
	return unaccounted
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
	//
	// THIS RULE IS NOT A RECOMPUTATION AND CANNOT BE ONE. A mutation operand is by
	// definition a value that is NOT in the tree -- two of the four live rows write
	// a key the target does not have yet -- so there is nothing to read back and
	// nothing that drifts. It is a STRUCTURAL claim, and the printed ceiling now
	// says so instead of counting it among the recomputed rules.
	//
	// As first written it asked only for the key name `kind == "json_set"` and the
	// PRESENCE of a `pointer` key, which adversarial review C5 turned into a
	// universal laundering primitive: adding those two keys to any object made
	// every digest in it explained forever, a fresh random digest included. It now
	// requires the object to BE the operation it claims to be -- an RFC 6901
	// pointer, a `target` naming THIS file, and the declared digest being that
	// operation's own `value` -- so it can no longer be borrowed by an object that
	// merely sits beside a path.
	if kind, ok := object["kind"].(string); ok && kind == "json_set" {
		pointer, hasPointer := object["pointer"].(string)
		target, hasTarget := object["target"].(string)
		value, hasValue := object["value"].(string)
		if hasPointer && strings.HasPrefix(pointer, "/") &&
			hasTarget && strings.TrimPrefix(target, "./") == named &&
			hasValue && normaliseDigest(value) == declared {
			return "mutation-operand: STRUCTURAL, not recomputed -- the value this " +
				"json_set operation writes into its declared target " + named +
				" at " + pointer + ", not a pin of it"
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
