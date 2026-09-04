package main

// The prose of a record, bound to the documents that record cites — for N
// records rather than one.
//
// WHAT CAME BEFORE. `internal/normcollide/recordbounds.go` binds ONE record:
// it reads eleven sentences out of drafts/self-review/normalization-collision-
// audit.md and compares each stated number against the field of
// evidence/normalization-collisions/audit.json it must agree with. That
// mechanism works and it was built because the failure it catches had already
// happened — `d90308a` moved the handshake bounds from 26/27/11 to 29/23/10
// while the record went on stating the old three in the present tense, with
// every gate green, because nothing in the tree read the prose.
//
// Its author stated its own ceiling in the record that landed it: "the prose of
// every OTHER record in the tree is still pinned to nothing." This file is that
// ceiling closed as far as it can be closed, and it states its own.
//
// THE ONE DESIGN RULE. Every value this file compares against is RE-DERIVED
// from the cited document on every run. There is no table of expected numbers
// anywhere in this file, and there must never be one: a record that declares "I
// claim 62" checked against a sidecar that also says 62 is a self-consistency
// check, not a binding, and this repository has filed that shape four times
// (F014 a code binding verified against a copy of itself; F016 a gate read as
// an adjudication it never made; F011 a claim checked on one axis and false on
// another; F017 a polarity test that bound the artifact and not the prose).
// A `proseClaim` therefore carries a `derive` FUNCTION and never a value.
//
// F017 IS THE TRAP THIS FILE IS MOST LIKELY TO FALL INTO, so it is worth being
// explicit: proving that `audit.json` cannot drift from the code says nothing
// about a sentence in a markdown file that also contains that number. The tests
// beside this file mutate the PROSE and require RED. Mutating the document is
// the weaker probe and it is not sufficient.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// proseGate is the verdict name this mode prints under.
const proseGate = "record-prose"

// proseRoots are the trees the record corpus is walked out of. `drafts/self-
// review` is the same tree `census` walks, so the two counts are comparable;
// `evidence` is added because two of the three true positives this file
// currently carries live under evidence/governance/ and a corpus that walked
// only drafts/self-review would not have reached them. That widening is
// declared here rather than absorbed: it is a NEW census with a NEW denominator
// and it does not move `record-content-precondition`'s `records=` count, which
// still walks drafts/self-review alone.
var proseRoots = []string{recordsRel, "evidence"}

// A proseSource is one document whose PROSE this gate reads. Two kinds:
//
//   - "markdown": a .md record, read whole.
//   - "statement": the `statement` string field of an evidence .json document.
//     Evidence documents in this repository carry a prose `statement` that says
//     what the document means, and it is prose in exactly the sense that
//     matters here — a human-authored sentence about the tree, standing beside
//     machine-derived fields that gates DO check. `evidence/governance/owner-
//     decision-digests.json` is the case that motivated including them: its
//     digests are verified by internal/deltaledger.VerifyGovernance and its
//     statement is the one part of the file nothing re-derives.
type proseSource struct {
	rel  string
	kind string
	// text is the prose. For "statement" sources it is the field value, so a
	// line number reported against it is a line within that field.
	text string
}

// proseCorpus walks the record trees and returns every prose source, sorted.
// It is a WALK and not a list: a record added tomorrow is in the corpus without
// anyone remembering to add it, which is the only way a census can be a
// denominator rather than a selection.
func proseCorpus(root string) ([]proseSource, error) {
	var sources []proseSource
	for _, rel := range proseRoots {
		dir := filepath.Join(root, filepath.FromSlash(rel))
		if _, err := os.Stat(dir); err != nil {
			return nil, fmt.Errorf("record tree not found at %s: %w", rel, err)
		}
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, relErr := filepath.Rel(root, p)
			if relErr != nil {
				return relErr
			}
			slashed := filepath.ToSlash(rel)
			switch {
			case strings.HasSuffix(p, ".md"):
				data, readErr := os.ReadFile(p)
				if readErr != nil {
					return readErr
				}
				sources = append(sources, proseSource{rel: slashed, kind: "markdown", text: string(data)})
			case strings.HasSuffix(p, ".json"):
				data, readErr := os.ReadFile(p)
				if readErr != nil {
					return readErr
				}
				var document map[string]json.RawMessage
				if json.Unmarshal(data, &document) != nil {
					return nil // not an object; carries no statement field
				}
				raw, ok := document["statement"]
				if !ok {
					return nil
				}
				var statement string
				if json.Unmarshal(raw, &statement) != nil {
					return nil
				}
				sources = append(sources, proseSource{
					rel: slashed + "#/statement", kind: "statement", text: statement})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].rel < sources[j].rel })
	return sources, nil
}

// flattenProse renders prose as ONE line for matching and returns, for each byte
// of that line, the 1-based source line it came from.
//
// Two properties, both load-bearing, both pinned by a test:
//
//   - A sentence the author WRAPPED across a line break still matches. Without
//     this, `Across all\n62 records` reads as absent, and absence is a failure
//     here, so the check would be noise. The governance README wraps exactly
//     that sentence.
//   - `*` and a backtick are stripped, because `**62 records**` and `62 records`
//     are the same claim and a check defeated by two asterisks measures
//     typography. `_` is NOT stripped — the identical mistake in
//     internal/normcollide turned `sec_websocket_accept` into
//     `secwebsocketaccept` and made a correct row read as missing every key it
//     named. Underscores are load-bearing in the identifiers these claims cite.
func flattenProse(raw string) (string, []int) {
	var flat strings.Builder
	var lineOf []int
	line := 1
	lastWasSpace := true
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch c {
		case '\n':
			line++
			c = ' '
		case '*', '`':
			continue
		}
		if c == ' ' || c == '\t' {
			if lastWasSpace {
				continue
			}
			lastWasSpace = true
			flat.WriteByte(' ')
			lineOf = append(lineOf, line)
			continue
		}
		lastWasSpace = false
		flat.WriteByte(c)
		lineOf = append(lineOf, line)
	}
	return flat.String(), lineOf
}

// ownVoice blanks every line of a record that is a QUOTATION or a code fence,
// leaving the record's own sentences untouched, and is applied before a binding
// is matched.
//
// It is not a nicety. This record's own landing document quotes all four of the
// stale sentences it reports, verbatim, because that is how a drift is
// documented — and without this, quoting a stale claim would make the gate FAIL
// on the record that reports it. A checker that cannot be written about is a
// checker nobody can correct a record under. It also stops a binding matching an
// EXAMPLE: the same document explains the rule with a sentence of the bound
// shape, and the binding found the example before the claim.
//
// The mask decides VOICE only. A line the mask empties entirely was a quotation
// or a fence; otherwise the RAW line is kept, because maskOtherVoices also blanks
// the inline code spans the citations live in — the discipline Supersession in
// scan.go already follows and for the same reason.
func ownVoice(text string) string {
	lines := strings.Split(text, "\n")
	masked := maskOtherVoices(lines)
	out := make([]string, len(lines))
	for i, raw := range lines {
		if strings.TrimSpace(masked[i]) == "" && strings.TrimSpace(raw) != "" {
			out[i] = ""
			continue
		}
		out[i] = raw
	}
	return strings.Join(out, "\n")
}

// ---------------------------------------------------------------------------
// Derivations. Every one of these READS THE TREE. None takes an expected value.
// ---------------------------------------------------------------------------

// deriveDirFileCount counts the files with one extension in one directory. The
// governance README's subject is "the JSON files beside this README", and this
// is what "beside this README" means, resolved against the filesystem.
func deriveDirFileCount(dir, ext string) func(string) (string, string, error) {
	return func(root string) (string, string, error) {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			return "", "", err
		}
		count := 0
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ext) {
				count++
			}
		}
		return strconv.Itoa(count), dir + "/*" + ext, nil
	}
}

// deriveJSONArrayLen reads the length of one array in one JSON document. The
// KEY is what the prose's own countable noun names — the ledger "holds 58
// records" is a claim about `$.records` — so the selector is read off the
// sentence rather than invented beside it.
func deriveJSONArrayLen(document, key string) func(string) (string, string, error) {
	return func(root string) (string, string, error) {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(document)))
		if err != nil {
			return "", "", err
		}
		var parsed map[string]json.RawMessage
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return "", "", fmt.Errorf("%s: %w", document, err)
		}
		field, ok := parsed[key]
		if !ok {
			return "", "", fmt.Errorf("%s carries no %q array for this claim to be about", document, key)
		}
		var array []json.RawMessage
		if err := json.Unmarshal(field, &array); err != nil {
			return "", "", fmt.Errorf("%s $.%s is not an array: %w", document, key, err)
		}
		return strconv.Itoa(len(array)), document + " $." + key, nil
	}
}

// deriveJSONLRows counts the non-blank rows of a .jsonl corpus.
func deriveJSONLRows(document string) func(string) (string, string, error) {
	return func(root string) (string, string, error) {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(document)))
		if err != nil {
			return "", "", err
		}
		rows := 0
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.TrimSpace(line) != "" {
				rows++
			}
		}
		return strconv.Itoa(rows), document + " (rows)", nil
	}
}

// deriveOccurrences counts how many times a literal appears in a document. The
// governance README's redaction table claims a count of occurrences of a
// placeholder in a named record, and this is that claim re-derived.
func deriveOccurrences(document, literal string) func(string) (string, string, error) {
	return func(root string) (string, string, error) {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(document)))
		if err != nil {
			return "", "", err
		}
		return strconv.Itoa(strings.Count(string(raw), literal)),
			fmt.Sprintf("%s (occurrences of %s)", document, literal), nil
	}
}

// ---------------------------------------------------------------------------
// Numeric claims.
// ---------------------------------------------------------------------------

// A proseClaim ties one sentence in one record to a quantity RE-DERIVED from the
// document that sentence cites.
//
// FAIL-CLOSED ON ABSENCE, for the reason internal/normcollide states and this
// file inherits: if a missing sentence were a pass, the check would be defeated
// by deleting the sentence, which is the cheapest possible way to stop a number
// being stale.
type proseClaim struct {
	// record is the prose source, by the same name proseCorpus reports.
	record string
	// field names the derived quantity, so a failure points at what to re-read.
	field string
	// pattern must capture exactly one group: the value the prose claims.
	pattern *regexp.Regexp
	// derive returns the value RE-DERIVED FROM THE TREE and a human-readable
	// name for where it came from. It never takes an expected value.
	derive func(root string) (string, string, error)
	// why says what this binding is for, in one sentence.
	why string
}

// proseClaims is the binding table. Adding a record here is how the corpus is
// bound; the census below is what makes leaving one out visible.
func proseClaims() []proseClaim {
	return []proseClaim{
		// evidence/governance/decisions/README.md — the security assertion whose
		// denominator is smaller than its corpus. The store held 63 records at
		// b6d3c6c, the commit that WROTE this README, and holds 63 at HEAD with
		// an empty diff between, so the count was wrong on the day it was
		// written rather than drifted into. See
		// drafts/self-review/record-prose-corpus.md.
		{
			record:  "evidence/governance/decisions/README.md",
			field:   "governance_decision_records (opening sentence)",
			pattern: regexp.MustCompile(`The (\d+) JSON files beside this README`),
			derive:  deriveDirFileCount("evidence/governance/decisions", ".json"),
			why: "the README's subject is the files beside it, so the count is a " +
				"directory listing and nothing else",
		},
		{
			record:  "evidence/governance/decisions/README.md",
			field:   "governance_decision_records (no-credentials denominator)",
			pattern: regexp.MustCompile(`Across all (\d+) records there are no credentials`),
			derive:  deriveDirFileCount("evidence/governance/decisions", ".json"),
			why: "a security assertion is only as wide as its denominator; this is " +
				"the sentence a reader takes as the scope of the scan",
		},
		// The same README's redaction table, which AGREES. It is bound for the
		// same reason a passing control is run beside a failing one: a checker
		// that only ever fires is indistinguishable from a constant.
		{
			record:  "evidence/governance/decisions/README.md",
			field:   "aws_account_id_redaction_occurrences",
			pattern: regexp.MustCompile(`REDACTED-AWS-ACCOUNT-ID \((\d+) occurrence, in us008-owner-pinning-tier1.json\)`),
			derive: deriveOccurrences(
				"evidence/governance/decisions/us008-owner-pinning-tier1.json", "REDACTED-AWS-ACCOUNT-ID"),
			why: "the redaction table states where the placeholder is and how often; " +
				"both halves are re-derivable from the named record",
		},
		{
			record:  "evidence/governance/decisions/README.md",
			field:   "ec2_instance_id_redaction_occurrences",
			pattern: regexp.MustCompile(`REDACTED-EC2-INSTANCE-ID \((\d+) occurrence, in us019-native-provenance-and-ac3-owner-decision-2026-08-28.json\)`),
			derive: deriveOccurrences(
				"evidence/governance/decisions/us019-native-provenance-and-ac3-owner-decision-2026-08-28.json",
				"REDACTED-EC2-INSTANCE-ID"),
			why: "as above, on the second redacted identifier",
		},

		// drafts/self-review/story-criterion-sweep.md — three present-tense
		// statements of the ledger's size, all made when it held 58 records. It
		// holds 59 since 9946dae.
		{
			record:  "drafts/self-review/story-criterion-sweep.md",
			field:   "behavior_delta_ledger_records (holds sentence)",
			pattern: regexp.MustCompile(`evidence/java/behavior-delta-ledger.json holds (\d+) records`),
			derive:  deriveJSONArrayLen("evidence/java/behavior-delta-ledger.json", "records"),
			why:     "the sentence names the document and the array in the same breath",
		},
		{
			record: "drafts/self-review/story-criterion-sweep.md",
			field:  "behavior_delta_ledger_records (step 3 DENOMINATOR)",
			pattern: regexp.MustCompile(
				`correct denominator for step 3 is all (\d+) records`),
			derive: deriveJSONArrayLen("evidence/java/behavior-delta-ledger.json", "records"),
			why: "A DENOMINATOR. It is bound and it is NOT re-baselined here: the " +
				"allowance below records the drift and names the owner action",
		},
		{
			record:  "drafts/self-review/story-criterion-sweep.md",
			field:   "behavior_delta_ledger_records (evidence list)",
			pattern: regexp.MustCompile(`all (\d+) records by subject and disposition`),
			derive:  deriveJSONArrayLen("evidence/java/behavior-delta-ledger.json", "records"),
			why:     "the record's own evidence list, stating what it read",
		},

		// THIS RECORD'S OWN re-derived values, bound by the mechanism it
		// introduces. A record that reports a number it re-derived and is not
		// itself bound to it is the exact asymmetry this branch exists to close,
		// and it would be a strange place to make an exception.
		{
			record:  "drafts/self-review/record-prose-corpus.md",
			field:   "this_record_governance_decision_records",
			pattern: regexp.MustCompile(`the tree holds (\d+) .json files in evidence/governance/decisions/`),
			derive:  deriveDirFileCount("evidence/governance/decisions", ".json"),
			why:     "TP-1's re-derived value, stated in this record and bound to the same listing",
		},
		{
			record:  "drafts/self-review/record-prose-corpus.md",
			field:   "this_record_behavior_delta_ledger_records",
			pattern: regexp.MustCompile(`evidence/java/behavior-delta-ledger.json holds (\d+) records.`),
			derive:  deriveJSONArrayLen("evidence/java/behavior-delta-ledger.json", "records"),
			why:     "TP-3's re-derived value, bound to the same array",
		},

		// Controls that AGREE, on three different derivations, so a green run
		// is evidence that the derivations run rather than that they are absent.
		{
			record:  "drafts/self-review/us022-mutation-denominator-round-1.md",
			field:   "mutation_polarity_cases",
			pattern: regexp.MustCompile(`assurance/mutation/fixtures/cases.json — (\d+) cases through`),
			derive:  deriveJSONArrayLen("assurance/mutation/fixtures/cases.json", "cases"),
			why:     "control: a JSON array length this record states and the document carries",
		},
		{
			record:  "drafts/self-review/pin-candidate-adjudication.md",
			field:   "us006_replay_fixture_cases",
			pattern: regexp.MustCompile(`Realized fixture tree \((\d+) rows\)`),
			derive:  deriveJSONArrayLen("assurance/replay/fixtures/us006-cases.json", "cases"),
			why:     "control: the row count IS the case count of the document named in the next sentence",
		},
		{
			record:  "drafts/self-review/findings/F001-reproduction-check-pinned-to-vendor-string.md",
			field:   "semantic_id_oracle_declarations",
			pattern: regexp.MustCompile(`all (\d+) declarations, totals and javac options were identical`),
			derive:  deriveJSONArrayLen("evidence/intake/semantic-id-oracle.json", "declarations"),
			why: "the finding's whole force is that ONE line of 969 differed; if the " +
				"denominator moves, the finding has to be re-read, not carried forward",
		},
		{
			record: "drafts/self-review/ledger-58-adopt-java.md",
			field:  "owner_decision_digest_decisions",
			pattern: regexp.MustCompile(
				`owner-decision-digests.json goes from \d+ decisions to (\d+)`),
			derive: deriveJSONArrayLen("evidence/governance/owner-decision-digests.json", "decisions"),
			why: "a transition sentence, bound at its PRESENT-TENSE end: the 'from' value " +
				"is history and cannot be re-derived, the 'to' value is a claim about the " +
				"document as it stands and is",
		},
		{
			record: "drafts/self-review/oracle-hierarchy-round-1.md",
			field:  "public_transcript_rows",
			pattern: regexp.MustCompile(
				`borrow-batch-c-public-transcript.jsonl \((\d+) records, each with its own final_state\)`),
			derive: deriveJSONLRows(
				"rust/ws-oracle-harness/baseline/borrow-batch-c-public-transcript.jsonl"),
			why: "the sentence names two .jsonl files and the count belongs to the second; " +
				"the census's first-citation-wins reading would have picked the wrong one, " +
				"which is why a binding names its document explicitly",
		},
		{
			record:  "drafts/self-review/us021-fuzz-pinning-round-1.md",
			field:   "fuzz_static_pin_cases",
			pattern: regexp.MustCompile(`assurance/fuzz/fixtures/cases.json — (\d+) static-pin cases`),
			derive:  deriveJSONArrayLen("assurance/fuzz/fixtures/cases.json", "cases"),
			why:     "control: a polarity-suite size the record states and the fixture carries",
		},
		{
			record: "drafts/self-review/us021-fuzz-pinning-round-1.md",
			field:  "fuzz_campaign_runner_cases",
			pattern: regexp.MustCompile(
				`assurance/fuzz/fixtures/campaign/cases.json — (\d+) campaign-runner cases`),
			derive: deriveJSONArrayLen("assurance/fuzz/fixtures/campaign/cases.json", "cases"),
			why:    "control, second fixture in the same sentence pair",
		},
		{
			record:  "drafts/self-review/us022-mutation-denominator-round-1.md",
			field:   "e1_ws_core_curated_mutants",
			pattern: regexp.MustCompile(`mutants/e1-ws-core-manifest.json's (\d+) curated mutants`),
			derive:  deriveJSONArrayLen("mutants/e1-ws-core-manifest.json", "mutants"),
			why: "a DENOMINATOR question the record decided by exclusion; if the manifest " +
				"grows, the exclusion covers a different set than the record says it does",
		},
		{
			record: "drafts/self-review/us023-formal-coverage-review.md",
			field:  "rust_identity_verification_rows (denominator only)",
			pattern: regexp.MustCompile(
				`rust-identity-verification.json, \d+/(\d+) rows by deterministic declaration scan`),
			derive: deriveJSONArrayLen("evidence/linkage/rust-identity-verification.json", "rows"),
			why: "CEILING, stated: only the DENOMINATOR is bound. The numerator (45, the " +
				"rows the deterministic scan resolved) is a property of a scan this gate " +
				"does not run, so it stays unbound and is named here rather than implied",
		},
		{
			record:  "drafts/self-review/normalization-collision-audit.md",
			field:   "handshake_corpus_rows",
			pattern: regexp.MustCompile(`(\d+) handshake cases produce only \d+ distinct scored observations`),
			derive:  deriveJSONLRows("corpora/handshake/cases.jsonl"),
			why: "control, and the axis internal/normcollide does NOT bind: recordbounds " +
				"pins the 29 and leaves the 49 — the corpus denominator — as a literal in " +
				"its own pattern. This binds the denominator to the corpus file",
		},
	}
}

// ---------------------------------------------------------------------------
// Non-numeric assertions.
// ---------------------------------------------------------------------------

// A proseAssertion binds one FACTUAL, non-quantitative claim to a predicate
// re-derived from the tree. Finding 2 in the landing record is of this shape and
// no amount of number-matching would reach it: the claim is that a set of files
// is NOT committed, and the refutation is that git tracks all of them.
//
// A design that only handled "a number quoted from a JSON field" would catch
// the governance README and miss this, so both kinds exist.
type proseAssertion struct {
	record  string
	field   string
	pattern *regexp.Regexp // no capture group; the sentence's PRESENCE is the claim
	// holds re-derives whether the asserted claim is TRUE, and returns the
	// evidence either way.
	holds func(root string) (bool, string, error)
	why   string
}

// gitTracked reports whether git tracks a path, asking git rather than guessing
// from the filesystem: a file present in the worktree and absent from the index
// is exactly the case this predicate has to tell apart.
func gitTracked(root, rel string) (bool, error) {
	cmd := exec.Command("git", "ls-files", "--error-unmatch", "--", rel)
	cmd.Dir = root
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		// EXIT 1 means "git looked and this path is not in the index". ANY other
		// exit means git could not answer — 128 for "not a git repository" is the
		// one that matters, because reading it as "not tracked" would make the
		// assertion HOLD in every checkout git cannot see. That is a refusal
		// read as an answer, which is the shape this repository files as a
		// defect, so it is an error and not a false.
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("git ls-files could not answer for %s: %w", rel, err)
	}
	return true, nil
}

func proseAssertions() []proseAssertion {
	return []proseAssertion{
		{
			record: "evidence/governance/owner-decision-digests.json#/statement",
			field:  "owner_decision_records_are_not_committed",
			pattern: regexp.MustCompile(
				`records themselves live in the workspace orchestrator's immutable protected store and are deliberately NOT committed`),
			holds: func(root string) (bool, string, error) {
				raw, err := os.ReadFile(filepath.Join(root,
					filepath.FromSlash("evidence/governance/owner-decision-digests.json")))
				if err != nil {
					return false, "", err
				}
				var document struct {
					Decisions []struct {
						Name   string `json:"name"`
						SHA256 string `json:"sha256"`
					} `json:"decisions"`
				}
				if err := json.Unmarshal(raw, &document); err != nil {
					return false, "", err
				}
				if len(document.Decisions) == 0 {
					return false, "", fmt.Errorf(
						"owner-decision-digests.json names no decisions, so this assertion is about nothing")
				}
				tracked, matching := 0, 0
				for _, decision := range document.Decisions {
					rel := path.Join("evidence/governance/decisions", path.Base(decision.Name))
					isTracked, err := gitTracked(root, rel)
					if err != nil {
						return false, "", err
					}
					if !isTracked {
						continue
					}
					tracked++
					body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
					if err != nil {
						return false, "", err
					}
					sum := sha256.Sum256(body)
					if strings.EqualFold(hex.EncodeToString(sum[:]),
						strings.TrimPrefix(decision.SHA256, "sha256:")) {
						matching++
					}
				}
				evidence := fmt.Sprintf(
					"%d of %d mirrored records are git-tracked under evidence/governance/decisions/, "+
						"%d of them byte-identical to the digest this file mirrors",
					tracked, len(document.Decisions), matching)
				// The assertion HOLDS only if the records really are not
				// committed. One tracked record already refutes it.
				return tracked == 0, evidence, nil
			},
			why: "the statement asserts a disclosure posture the owner reversed. " +
				"internal/deltaledger.VerifyGovernance checks this file's DIGESTS and " +
				"requires the whole document to equal a derivation whose statement is the " +
				"Go constant OwnerDecisionManifestStatement — so the statement is verified " +
				"against a copy of itself and never against the tree",
		},
	}
}

// ---------------------------------------------------------------------------
// Coverage claims: a claim another checker already binds.
// ---------------------------------------------------------------------------

// A proseCoverage says "this record's numbers are bound elsewhere", and NAMES
// the assertion in the covering file. The assertion is read back out of that
// file on every run, so the coverage claim cannot outlive the check it points
// at — the same shape cmd/pinconsumerctl uses, failing as STALE_COVERAGE_CLAIM.
type proseCoverage struct {
	record    string
	checkFile string
	assertion string
	why       string
}

func proseCoverages() []proseCoverage {
	return []proseCoverage{
		{
			record:    "drafts/self-review/normalization-collision-audit.md",
			checkFile: "internal/normcollide/recordbounds.go",
			assertion: `The 74 rows carry only (\d+) distinct scored observations`,
			why: "eleven bounds and the handshake.judged surface row are bound by " +
				"CheckRecordBounds and CheckRecordSurfaceRow, in the DEFAULT go suite; " +
				"binding them a second time here would be two declarations of one claim",
		},
	}
}

// ---------------------------------------------------------------------------
// Allowances: a TRUE finding this branch declines to fix by editing a number.
// ---------------------------------------------------------------------------

// A proseAllowance is a DECLARED, per-claim acknowledgement of a finding that is
// real and that must not be closed by rewriting the sentence.
//
// It is the shape cmd/pinconsumerctl and cmd/gosuitectl already use, and it is
// used here for the reason this repository corrects records BY SUPERSESSION and
// never by edit: silently changing 62 to 63 destroys the evidence that the
// number was ever wrong, and for a DENOMINATOR it is the specific move this
// project forbids outright.
//
// Each entry pins the value the prose CURRENTLY STATES, so it cannot survive the
// sentence being edited: restate the record and the claim stops matching its
// allowance, which makes it an unallowed mismatch and FAILS. An allowance whose
// claim no longer disagrees has outlived its finding and fails as
// STALE_ALLOWANCE, so a corrected record cannot leave a permanent exemption
// behind.
type proseAllowance struct {
	record string
	field  string
	// stated is the value the prose says today, pinned so that editing the
	// prose invalidates the acknowledgement rather than inheriting it.
	stated string
	// owner is the action that would let this entry be deleted.
	owner string
}

func proseAllowances() []proseAllowance {
	return []proseAllowance{
		{
			record: "evidence/governance/decisions/README.md",
			field:  "governance_decision_records (opening sentence)",
			stated: "62",
			owner: "SUPERSEDE, do not edit: the store held 63 .json records at b6d3c6c, the " +
				"commit that wrote this README, and holds 63 at HEAD with an empty diff " +
				"between. The count was wrong when written. Correcting it is a governance " +
				"record change and belongs to the owner.",
		},
		{
			record: "evidence/governance/decisions/README.md",
			field:  "governance_decision_records (no-credentials denominator)",
			stated: "62",
			owner: "SUPERSEDE, do not edit: same sentence pair, and this one is the " +
				"DENOMINATOR of a security assertion. The assertion itself was re-derived " +
				"over all 63 and HOLDS; it is the scope that is understated by one.",
		},
		{
			record: "drafts/self-review/story-criterion-sweep.md",
			field:  "behavior_delta_ledger_records (holds sentence)",
			stated: "58",
			owner: "SUPERSEDE, do not edit: the ledger reached 59 records at 9946dae, after " +
				"this record was written. A landing record is corrected by a superseding " +
				"record, never by rewriting its measurement in place.",
		},
		{
			record: "drafts/self-review/story-criterion-sweep.md",
			field:  "behavior_delta_ledger_records (step 3 DENOMINATOR)",
			stated: "58",
			owner: "DENOMINATOR, HARD STOP: this is the stated denominator of that record's " +
				"step-3 sweep. It is reported and never re-baselined here. Whether the " +
				"sweep's conclusion survives 59 records is a re-reading the owner rules on.",
		},
		{
			record: "drafts/self-review/story-criterion-sweep.md",
			field:  "behavior_delta_ledger_records (evidence list)",
			stated: "58",
			owner:  "SUPERSEDE, do not edit: same drift, third sentence.",
		},
		{
			record: "evidence/governance/owner-decision-digests.json#/statement",
			field:  "owner_decision_records_are_not_committed",
			stated: "asserted",
			owner: "OWNER ACTION, and it is NOT a prose edit: this file must equal " +
				"BuildOwnerDecisionManifest's output, whose statement is the Go constant " +
				"internal/deltaledger.OwnerDecisionManifestStatement. Editing the JSON alone " +
				"fails ledger-gates; editing the constant restates a disclosure posture. " +
				"The publication was ruled at " +
				"governance-publish-records-owner-decision-2026-08-29.json and the " +
				"redactions were performed — this is stale prose, not a disclosure incident.",
		},
	}
}

// ---------------------------------------------------------------------------
// The census: what the binding table is measured against.
// ---------------------------------------------------------------------------

// claimNoun is the countable-noun vocabulary the census recognises. Every entry
// was READ OFF this corpus rather than imagined, in the same spirit as
// scan.go's unfinishedTerms. The optional adjective run before the noun is what
// lets `25 static-pin cases` and `76 curated mutants` read as the cardinality
// claims they are.
var claimNoun = regexp.MustCompile(`(?i)\b(\d+) (?:[a-z-]+ )?(records|rows|cases|files|entries|obligations|` +
	`observations|decisions|candidates|probes|refutations|scenarios|mutants|adjudications|digests|` +
	`declarations|supersessions|sequences|fixtures|occurrences|targets)\b`)

// citationRe finds a backticked repo-relative path in a line.
var citationRe = regexp.MustCompile("`([A-Za-z0-9_][A-Za-z0-9_./-]*\\.(?:json|jsonl|md|go|rs|toml))`")

// deicticRe finds a record naming its own directory as the population.
var deicticRe = regexp.MustCompile(`(?i)beside this README|in this directory|beside it`)

// jsonlNoun is what a .jsonl corpus can be counted in. A .jsonl has exactly one
// enumeration — its rows — so the noun only has to be one of the words this
// corpus uses for that.
var jsonlNoun = map[string]bool{
	"rows": true, "records": true, "cases": true, "entries": true,
	"scenarios": true, "observations": true,
}

// dirNoun is what a DIRECTORY can be counted in, for a deictic population.
var dirNoun = map[string]bool{"files": true, "records": true}

// enumerable reports whether this gate could COUNT the population the prose
// names, and returns a label for it.
//
// This is the line between a candidate and a sentence that merely contains a
// number near a path, and it is drawn by asking the DOCUMENT, never by reading
// the sentence harder: a .jsonl is enumerable in rows; a .json is enumerable in
// a top-level array only if the prose's own noun IS one of its array keys; a
// directory is enumerable in files. Without this rule `18 files` beside a cited
// .rs file read as a claim about that file, which it is not, and the census
// filled with sentences no derivation could ever check.
func enumerable(root, cited, noun string) (bool, string) {
	lowered := strings.ToLower(noun)
	full := filepath.Join(root, filepath.FromSlash(cited))
	info, err := os.Stat(full)
	if err != nil {
		return false, ""
	}
	switch {
	case info.IsDir():
		if dirNoun[lowered] {
			return true, cited + "/"
		}
	case strings.HasSuffix(cited, ".jsonl"):
		if jsonlNoun[lowered] {
			return true, cited + " (rows)"
		}
	case strings.HasSuffix(cited, ".json"):
		raw, readErr := os.ReadFile(full)
		if readErr != nil {
			return false, ""
		}
		var document map[string]json.RawMessage
		if json.Unmarshal(raw, &document) != nil {
			return false, ""
		}
		field, ok := document[lowered]
		if !ok {
			return false, ""
		}
		var array []json.RawMessage
		if json.Unmarshal(field, &array) != nil {
			return false, ""
		}
		return true, cited + " $." + lowered
	}
	return false, ""
}

// A claimCandidate is one line the census reads as a cardinality claim about a
// population this gate can enumerate.
type claimCandidate struct {
	record     string
	line       int
	text       string
	population string
}

// censusCandidates scans every prose source for cardinality sentences and says
// which of them name a population this gate can enumerate.
//
// WHOSE VOICE. Fenced and quoted lines are skipped, using scan.go's
// maskOtherVoices, for the reason drafts/self-review/supersession-is-not-
// unfinished.md gives: a fenced block is a TRANSCRIPT of a past run, not the
// record's own present-tense assertion, and binding a record's quotation of an
// old gate line would make every honest history a failure. The mask decides
// VOICE only; the RAW line is what gets matched, because the mask also blanks
// the inline code spans the citations live in.
//
// Every line with an enumerable population MUST be dispositioned — bound,
// covered, or allowed. The rest are counted and printed as this gate's ceiling:
// a number, not a silence.
func censusCandidates(root string, sources []proseSource) (resolvable []claimCandidate, sentences int) {
	for _, source := range sources {
		lines := strings.Split(source.text, "\n")
		masked := maskOtherVoices(lines)
		for i, raw := range lines {
			if strings.TrimSpace(masked[i]) == "" && strings.TrimSpace(raw) != "" {
				continue // a quotation or a fence: not the record's own voice
			}
			nouns := claimNoun.FindAllStringSubmatch(raw, -1)
			if len(nouns) == 0 {
				continue
			}
			sentences++
			population := ""
			var cited []string
			for _, match := range citationRe.FindAllStringSubmatch(raw, -1) {
				cited = append(cited, match[1])
			}
			if deicticRe.MatchString(raw) {
				cited = append(cited, path.Dir(strings.TrimSuffix(source.rel, "#/statement")))
			}
			for _, candidatePath := range cited {
				for _, noun := range nouns {
					if ok, label := enumerable(root, candidatePath, noun[2]); ok {
						population = label
						break
					}
				}
				if population != "" {
					break
				}
			}
			if population == "" {
				continue
			}
			resolvable = append(resolvable, claimCandidate{
				record: source.rel, line: i + 1,
				text: strings.TrimSpace(raw), population: population})
		}
	}
	return resolvable, sentences
}

// ---------------------------------------------------------------------------
// The run.
// ---------------------------------------------------------------------------

type proseFinding struct {
	kind   string
	record string
	field  string
	line   int
	detail string
}

func (f proseFinding) String() string {
	if f.line > 0 {
		return fmt.Sprintf("gate=%s finding=%s record=%s field=%q line=%d detail=%q",
			proseGate, f.kind, f.record, f.field, f.line, f.detail)
	}
	return fmt.Sprintf("gate=%s finding=%s record=%s field=%q detail=%q",
		proseGate, f.kind, f.record, f.field, f.detail)
}

// checkProse is the whole rule, returned as findings plus the census line, so
// the tests can assert on structure rather than on printed text.
func checkProse(root string) (findings []proseFinding, notes []string, census map[string]int, err error) {
	sources, err := proseCorpus(root)
	if err != nil {
		return nil, nil, nil, err
	}
	byRel := map[string]proseSource{}
	markdown, statements := 0, 0
	for _, source := range sources {
		byRel[source.rel] = source
		if source.kind == "markdown" {
			markdown++
		} else {
			statements++
		}
	}

	census = map[string]int{
		"records": len(sources), "markdown": markdown, "statements": statements,
	}

	// Coverage claims are read back against the covering file FIRST: a stale
	// coverage claim is a lie about who is checking what, and while one is stale
	// no claim may lean on it.
	staleCoverage := map[string]bool{}
	covered := map[string]string{}
	for _, coverage := range proseCoverages() {
		body, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(coverage.checkFile)))
		if readErr != nil {
			findings = append(findings, proseFinding{kind: "STALE_COVERAGE_CLAIM",
				record: coverage.record, field: coverage.checkFile,
				detail: fmt.Sprintf("covering file is unreadable: %v", readErr)})
			staleCoverage[coverage.record] = true
			continue
		}
		if !strings.Contains(string(body), coverage.assertion) {
			findings = append(findings, proseFinding{kind: "STALE_COVERAGE_CLAIM",
				record: coverage.record, field: coverage.checkFile,
				detail: fmt.Sprintf("%s no longer contains the covering assertion %q; "+
					"the coverage claim outlived the check it names",
					coverage.checkFile, coverage.assertion)})
			staleCoverage[coverage.record] = true
			continue
		}
		covered[coverage.record] = coverage.checkFile
		notes = append(notes, fmt.Sprintf(
			"gate=%s covered record=%s by=%s assertion=%q why=%q",
			proseGate, coverage.record, coverage.checkFile, coverage.assertion, coverage.why))
	}
	census["covered_records"] = len(covered)

	allowed := map[string]*proseAllowance{}
	allowances := proseAllowances()
	for index := range allowances {
		entry := &allowances[index]
		allowed[entry.record+"\x00"+entry.field] = entry
	}
	acknowledged := map[*proseAllowance]bool{}

	// Numeric claims.
	boundLines := map[string]bool{}
	claims := proseClaims()
	census["claims"] = len(claims) + len(proseAssertions())
	for _, claim := range claims {
		source, ok := byRel[claim.record]
		if !ok {
			findings = append(findings, proseFinding{kind: "BOUND_RECORD_ABSENT",
				record: claim.record, field: claim.field,
				detail: "this binding names a record the corpus walk does not hold; " +
					"a binding to a file that is gone is not a binding"})
			continue
		}
		derived, from, deriveErr := claim.derive(root)
		if deriveErr != nil {
			findings = append(findings, proseFinding{kind: "DERIVATION_FAILED",
				record: claim.record, field: claim.field,
				detail: fmt.Sprintf("the cited document could not be read: %v", deriveErr)})
			continue
		}
		flat, lineOf := flattenProse(ownVoice(source.text))
		location := claim.pattern.FindStringSubmatchIndex(flat)
		if location == nil {
			findings = append(findings, proseFinding{kind: "CLAIM_ABSENT",
				record: claim.record, field: claim.field,
				detail: fmt.Sprintf("the record no longer states this claim where this check reads it "+
					"(the tree derives %s from %s). A record that stopped stating its claim is not "+
					"a record that agrees with it", derived, from)})
			continue
		}
		stated := flat[location[2]:location[3]]
		line := lineOf[location[0]]
		boundLines[fmt.Sprintf("%s:%d", claim.record, line)] = true
		if stated == derived {
			census["agreeing"]++
			continue
		}
		if entry := allowed[claim.record+"\x00"+claim.field]; entry != nil && entry.stated == stated {
			acknowledged[entry] = true
			census["allowed"]++
			notes = append(notes, fmt.Sprintf(
				"gate=%s allowed record=%s field=%q line=%d states=%s derives=%s from=%s owner=%q",
				proseGate, claim.record, claim.field, line, stated, derived, from, entry.owner))
			continue
		}
		findings = append(findings, proseFinding{kind: "PROSE_DISAGREES_WITH_DOCUMENT",
			record: claim.record, field: claim.field, line: line,
			detail: fmt.Sprintf("the record says %s, the tree derives %s from %s | %s",
				stated, derived, from, strings.TrimSpace(flat[location[0]:location[1]]))})
	}

	// Non-numeric assertions.
	for _, assertion := range proseAssertions() {
		source, ok := byRel[assertion.record]
		if !ok {
			findings = append(findings, proseFinding{kind: "BOUND_RECORD_ABSENT",
				record: assertion.record, field: assertion.field,
				detail: "this binding names a prose source the corpus walk does not hold"})
			continue
		}
		flat, lineOf := flattenProse(ownVoice(source.text))
		location := assertion.pattern.FindStringIndex(flat)
		holds, evidence, holdErr := assertion.holds(root)
		if holdErr != nil {
			findings = append(findings, proseFinding{kind: "DERIVATION_FAILED",
				record: assertion.record, field: assertion.field,
				detail: fmt.Sprintf("the predicate could not be re-derived: %v", holdErr)})
			continue
		}
		if location == nil {
			findings = append(findings, proseFinding{kind: "CLAIM_ABSENT",
				record: assertion.record, field: assertion.field,
				detail: fmt.Sprintf("the record no longer carries this assertion where this check "+
					"reads it (the tree currently makes it %v: %s)", holds, evidence)})
			continue
		}
		line := lineOf[location[0]]
		boundLines[fmt.Sprintf("%s:%d", assertion.record, line)] = true
		if holds {
			census["agreeing"]++
			continue
		}
		if entry := allowed[assertion.record+"\x00"+assertion.field]; entry != nil && entry.stated == "asserted" {
			acknowledged[entry] = true
			census["allowed"]++
			notes = append(notes, fmt.Sprintf(
				"gate=%s allowed record=%s field=%q line=%d asserted=yes refuted_by=%q owner=%q",
				proseGate, assertion.record, assertion.field, line, evidence, entry.owner))
			continue
		}
		findings = append(findings, proseFinding{kind: "PROSE_REFUTED_BY_THE_TREE",
			record: assertion.record, field: assertion.field, line: line,
			detail: fmt.Sprintf("the record asserts this and the tree refutes it: %s", evidence)})
	}

	// An allowance whose finding is gone has outlived it. Left in place it would
	// silently exempt whatever next lands under that record and field.
	for index := range allowances {
		entry := &allowances[index]
		if acknowledged[entry] {
			continue
		}
		findings = append(findings, proseFinding{kind: "STALE_ALLOWANCE",
			record: entry.record, field: entry.field,
			detail: fmt.Sprintf("allowed at stated value %q, but that claim no longer disagrees "+
				"with the document (or no longer reads as this value); the acknowledgement "+
				"outlived the finding and must be deleted", entry.stated)})
	}

	// The census, and the undispositioned claims it surfaces.
	candidates, sentences := censusCandidates(root, sources)
	census["cardinality_sentences"] = sentences
	census["resolvable"] = len(candidates)
	census["unresolvable"] = sentences - len(candidates)
	for _, candidate := range candidates {
		if boundLines[fmt.Sprintf("%s:%d", candidate.record, candidate.line)] {
			census["bound"]++
			continue
		}
		if _, ok := covered[candidate.record]; ok {
			census["census_covered"]++
			continue
		}
		census["undispositioned"]++
		findings = append(findings, proseFinding{kind: "UNDISPOSITIONED_CLAIM",
			record: candidate.record, field: candidate.population, line: candidate.line,
			detail: fmt.Sprintf("this line states a cardinality about a population this gate can "+
				"enumerate, and no binding, coverage claim or allowance names it | %s",
				candidate.text)})
	}
	return findings, notes, census, nil
}

// runProse is the gate.
func runProse(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("prose", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	findings, notes, census, err := checkProse(*root)
	if err != nil {
		fmt.Fprintf(stderr, "gate=%s result=FAIL reason=%q\n", proseGate, err.Error())
		return 2
	}
	fmt.Fprintf(stdout, "gate=%s step=corpus records=%d markdown=%d statements=%d bindings=%d\n",
		proseGate, census["records"], census["markdown"], census["statements"], census["claims"])
	fmt.Fprintf(stdout, "gate=%s step=census cardinality_sentences=%d with_enumerable_population=%d "+
		"no_enumerable_population=%d bound=%d covered=%d undispositioned=%d\n",
		proseGate, census["cardinality_sentences"], census["resolvable"], census["unresolvable"],
		census["bound"], census["census_covered"], census["undispositioned"])
	fmt.Fprintf(stdout, "gate=%s step=bindings agreeing=%d allowed=%d covered_records=%d\n",
		proseGate, census["agreeing"], census["allowed"], census["covered_records"])

	for _, note := range notes {
		fmt.Fprintln(stdout, note)
	}
	blocking := 0
	for _, finding := range findings {
		fmt.Fprintln(stdout, finding.String())
		blocking++
	}
	// A check with nothing to check is itself a defect, and this is the cheapest
	// way to delete this gate: empty the binding table and every run goes green.
	if census["claims"] == 0 {
		fmt.Fprintf(stdout, "gate=%s result=FAIL reason=%q\n", proseGate,
			"the binding table is empty, so this gate would pass by having nothing to check")
		return 1
	}
	if blocking > 0 {
		fmt.Fprintf(stdout, "gate=%s result=FAIL blocking=%d\n", proseGate, blocking)
		return 1
	}
	fmt.Fprintf(stdout, "gate=%s result=PASS\n", proseGate)
	return 0
}
