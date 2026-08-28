package deltaledger

// The observed-disagreement set, and the computation of the ledger's
// unledgered_disagreements field FROM it.
//
// WHY THIS FILE EXISTS. Before this change, unledgered_disagreements was a
// fake gate. Three facts made it one:
//
//   - schemas/behavior-delta-ledger-1.0.0.schema.json pinned it to `const: 0`,
//     so no other value could ever validate;
//   - build.go assigned the literal 0 unconditionally, computing nothing;
//   - the only real detector, lab.DetectUnledgeredDisagreements, was reachable
//     only through cmd/labctl with a caller-supplied --observed file, and no
//     such file was committed anywhere in the repository.
//
// So the field asserted an integrity property it was structurally incapable of
// reporting a violation of. It read 0 throughout the entire period when the
// client-handshake direction (gap G3c) and the reserved-bit ready-state
// proposition were genuinely unledgered. Meanwhile internal/lab/evidence.go
// consumed it as a READINESS gate, so a hardcoded constant was an input to a
// readiness decision that could not fail.
//
// The fix has three parts, and the third is the one that matters:
//
//  1. evidence/java/observed-disagreements.json is committed: the set of
//     disagreements this plane has actually OBSERVED, each carrying the same
//     digest tuple the ledger binds, plus evidence provenance naming where the
//     observation came from.
//  2. The field is COMPUTED from that committed set against the record chain,
//     through the existing lab detector. The schema now admits any
//     non-negative integer, so the ledger can say "three disagreements are
//     unledgered" instead of being unable to say it.
//  3. The zero REQUIREMENT stays where it belongs, in the readiness gate at
//     internal/lab/evidence.go, which refuses readiness on any nonzero value.
//
// ANTI-CIRCULARITY. The observation set is generated from the definitions
// once, under an explicit gate, and then COMMITTED. The check reads the
// committed file, never a fresh regeneration. That is what gives the gate its
// polarity: delete a ledger record and the committed observation survives it,
// so the count rises and readiness refuses. A design that derived observations
// from the definitions at check time would fall back to always reporting zero,
// which is the bug being fixed, and TestUnledgeredCountReportsNonzero pins
// that it does not.
//
// The observation set is additionally bound to evidence on its other side by
// TestEveryDivergentLiveMappingRowHasAnObservation, so it cannot silently
// shrink away from the evidence it claims to enumerate.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// ObservationsRelativePath is the committed observed-disagreement set.
const ObservationsRelativePath = "evidence/java/observed-disagreements.json"

// ObservationProvenance records where one observation came from, so a reader
// can check the claim against evidence rather than trusting the digest tuple.
type ObservationProvenance struct {
	SubjectRef string   `json:"subject_ref"`
	SourceKind string   `json:"source_kind"`
	Evidence   []string `json:"evidence"`
}

// ObservationSet is the committed observed-disagreement document. The
// "observed" array is exactly the shape cmd/labctl consumes via its
// --observed flag, so the same file drives both paths.
type ObservationSet struct {
	Schema        string                     `json:"$schema"`
	SchemaVersion string                     `json:"schema_version"`
	EvidenceKind  string                     `json:"evidence_kind"`
	Statement     string                     `json:"statement"`
	Observed      []lab.ObservedDisagreement `json:"observed"`
	Provenance    []ObservationProvenance    `json:"provenance"`
}

// ObservationsSchemaRelativePath is the observation set's schema, and
// ObservationsSchemaPointer is the `$schema` value the document must carry
// (relative to the document, which lives two directories down).
const (
	ObservationsSchemaRelativePath = "schemas/observed-disagreements-1.0.0.schema.json"
	ObservationsSchemaPointer      = "../../schemas/observed-disagreements-1.0.0.schema.json"
	ObservationsEvidenceKind       = "observed-disagreement-set"
)

// ReadObservations decodes and ENVELOPE-CHECKS the committed
// observed-disagreement set.
//
// ROUND-2 FINDING 4 moved the envelope and uniqueness rules HERE from
// observations_test.go. `ledger-gates` runs no Go tests, so while those rules
// lived only in a test binary a drifted `$schema` or `evidence_kind`, or a
// duplicated subject, passed production `--check` unnoticed. Reproduced before
// the move: rewriting `$schema` to a file that does not exist and
// `evidence_kind` to "not-an-observed-disagreement-set" left both
// `deltaledgerctl --check` and `make -C rust ledger-gates` at exit 0.
func ReadObservations(root string) (ObservationSet, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ObservationsRelativePath)))
	if err != nil {
		return ObservationSet{}, err
	}
	var set ObservationSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return ObservationSet{}, err
	}
	if set.SchemaVersion != "1.0.0" {
		return ObservationSet{}, fmt.Errorf("%s: observations schema must be 1.0.0", ObservationsRelativePath)
	}
	if set.EvidenceKind != ObservationsEvidenceKind {
		return ObservationSet{}, fmt.Errorf("%s: evidence_kind drifted to %q, expected %q",
			ObservationsRelativePath, set.EvidenceKind, ObservationsEvidenceKind)
	}
	if set.Schema != ObservationsSchemaPointer {
		return ObservationSet{}, fmt.Errorf("%s: $schema pointer drifted to %q, expected %q",
			ObservationsRelativePath, set.Schema, ObservationsSchemaPointer)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(ObservationsSchemaRelativePath))); err != nil {
		return ObservationSet{}, fmt.Errorf("%s names schema %s, which does not exist: %w",
			ObservationsRelativePath, ObservationsSchemaRelativePath, err)
	}
	if len(set.Observed) == 0 {
		return ObservationSet{}, fmt.Errorf("%s: the observed set is empty; the gate would be vacuous", ObservationsRelativePath)
	}
	if len(set.Provenance) != len(set.Observed) {
		return ObservationSet{}, fmt.Errorf("%s: %d observations but %d provenance entries; every observation must say where it came from",
			ObservationsRelativePath, len(set.Observed), len(set.Provenance))
	}
	seen := map[string]bool{}
	for index, observation := range set.Observed {
		if observation.SubjectRef == "" {
			return ObservationSet{}, fmt.Errorf("%s: observation %d has no subject_ref", ObservationsRelativePath, index)
		}
		if seen[observation.SubjectRef] {
			return ObservationSet{}, fmt.Errorf("%s: observation %d duplicates subject %s; a duplicated observation "+
				"double-counts or masks an unledgered one", ObservationsRelativePath, index, observation.SubjectRef)
		}
		seen[observation.SubjectRef] = true
		if _, err := observation.Digest(); err != nil {
			return ObservationSet{}, fmt.Errorf("%s: observation %d (%s) does not digest: %w",
				ObservationsRelativePath, index, observation.SubjectRef, err)
		}
	}
	return set, nil
}

// UnledgeredSubjects returns, in sorted order, the subject_ref of every
// observed disagreement whose exact disagreement digest is absent from the
// record chain. The returned slice's length is the value the ledger's
// unledgered_disagreements field carries.
//
// The digest is the same one lab.DetectUnledgeredDisagreements matches on, so
// this reports WHICH observations are unledgered while that function reports
// only THAT one is — the two agree by construction and
// TestUnledgeredComputationAgreesWithTheLabDetector pins it.
func UnledgeredSubjects(records []lab.BehaviorLedgerRecord, observed []lab.ObservedDisagreement) ([]string, error) {
	ledgered := make(map[string]struct{}, len(records))
	for _, record := range records {
		ledgered[record.Delta.DisagreementDigest] = struct{}{}
	}
	var unledgered []string
	for index, disagreement := range observed {
		digest, err := disagreement.Digest()
		if err != nil {
			return nil, fmt.Errorf("observation %d (%s): %w", index, disagreement.SubjectRef, err)
		}
		if _, exists := ledgered[digest]; !exists {
			unledgered = append(unledgered, disagreement.SubjectRef)
		}
	}
	sort.Strings(unledgered)
	return unledgered, nil
}

// BuildObservationSet materializes the observation set from the recorded
// divergence definitions. This is the REGENERATION path only, run behind an
// explicit flag; the gate never calls it.
func BuildObservationSet(existing ObservationSet) (ObservationSet, error) {
	deltas, err := BuildDeltas()
	if err != nil {
		return ObservationSet{}, err
	}
	definitions := Definitions()
	if len(definitions) != len(deltas) {
		return ObservationSet{}, fmt.Errorf("built %d deltas for %d definitions", len(deltas), len(definitions))
	}
	built := existing
	built.Observed = make([]lab.ObservedDisagreement, 0, len(deltas))
	built.Provenance = make([]ObservationProvenance, 0, len(deltas))
	for index, definition := range definitions {
		if observationSourceKind(definition.Subject) == "" {
			return ObservationSet{}, fmt.Errorf(
				"definition %d (%s): observationSourceKind does not recognise this subject domain. Classify it "+
					"deliberately in observations.go rather than letting a default arm invent a plausible label",
				index, definition.Subject)
		}
	}
	for index, delta := range deltas {
		built.Observed = append(built.Observed, lab.ObservedDisagreement{
			SubjectRef:            delta.SubjectRef,
			RFCRefs:               delta.RFCRefs,
			RFCExpectationDigest:  delta.RFCExpectationDigest,
			RFCValueDigest:        delta.RFCValueDigest,
			JavaRef:               delta.JavaRef,
			JavaObservationDigest: delta.JavaObservationDigest,
			JavaValueDigest:       delta.JavaValueDigest,
			AutobahnRefs:          delta.AutobahnRefs,
			AutobahnResultDigest:  delta.AutobahnResultDigest,
			AutobahnValueDigest:   delta.AutobahnValueDigest,
		})
		built.Provenance = append(built.Provenance, observationProvenanceFor(delta.SubjectRef, definitions[index]))
	}
	return built, nil
}

// definitionText is the searchable text of one definition: the two free-text
// digest preimages a record carries. Both the census tests and the provenance
// derivation read citations out of it.
func definitionText(definition Definition) string {
	return definition.JavaObservation + "\n" + definition.Rationale
}

// observationProvenanceFor derives one observation's provenance from what the
// definition ALREADY cites, rather than from a hand-maintained parallel table
// that could drift away from it. The source kind comes from the subject's own
// domain segment; the evidence list is the set of artifact paths, corpus case
// ids and mapping rows the definition's own digest preimages name.
func observationProvenanceFor(subjectRef string, definition Definition) ObservationProvenance {
	text := definitionText(definition)
	evidence := map[string]struct{}{}
	for _, pattern := range provenancePatterns {
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			evidence[strings.TrimRight(match[1], ".,;")] = struct{}{}
		}
	}
	cited := make([]string, 0, len(evidence))
	for value := range evidence {
		cited = append(cited, value)
	}
	sort.Strings(cited)
	return ObservationProvenance{
		SubjectRef: subjectRef,
		SourceKind: observationSourceKind(definition.Subject),
		Evidence:   cited,
	}
}

// provenancePatterns are the evidence shapes a definition can cite. Each is a
// thing a reader can go and open, and ResolveProvenance now requires the
// in-repository ones to actually be there.
//
// TWO REGEX DEFECTS ARE FIXED HERE, both found by review BLOCKING 7 and both
// reproduced by dumping the committed provenance and stat()ing every path:
//
//   - `protected/…\.json` truncated a cited `…/transcript.jsonl` into
//     `…/transcript.json`, manufacturing 22 citations of a file that does not
//     exist under any name. The pattern now ends `\.jsonl?` and, being greedy,
//     keeps the `l`.
//   - `corpora/…\.jsonl` matched MID-STRING inside
//     `protected/us005-corpora/live/handshake/transcript.jsonl`, manufacturing
//     22 more citations of `corpora/live/handshake/transcript.jsonl` — a path
//     that has never existed in this repository, since `corpora/` holds only
//     handshake/, public/, sealed/ and hidden/. Every path pattern is now
//     preceded by a boundary group so a path may only start where a path can
//     start, and matches are taken from the capture rather than the whole hit.
//
// Group 1 of every pattern is the citation.
var provenancePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(us005\.hs\.[0-9]{4})`),
	regexp.MustCompile(`(us005\.pub\.[0-9]{4})`),
	regexp.MustCompile(`(mapping-row direction=[a-z_]+ key=HS_[A-Z0-9_]+)`),
	regexp.MustCompile(`(?:^|[\s(",])(evidence/[A-Za-z0-9/_.-]+\.jsonl?)`),
	regexp.MustCompile(`(?:^|[\s(",])(protected/[A-Za-z0-9/_.-]+\.jsonl?)`),
	regexp.MustCompile(`(?:^|[\s(",])(rust/ws-core/[A-Za-z0-9/_.-]+\.(?:rs|hex))`),
	regexp.MustCompile(`(?:^|[\s(",])(corpora/[A-Za-z0-9/_.-]+\.jsonl?)`),
	regexp.MustCompile(`(?:^|[\s(",])(internal/corpora/[A-Za-z0-9_.-]+\.go)`),
	regexp.MustCompile(`(?:^|[\s(",])(java-oracle/[A-Za-z0-9/_.-]+\.java)`),
}

// inRepositoryProvenancePrefixes are the citation prefixes that name a file
// inside this repository, and must therefore resolve on disk.
var inRepositoryProvenancePrefixes = []string{
	"evidence/", "corpora/", "rust/", "internal/", "java-oracle/", "schemas/", "drafts/",
}

// ProvenanceIsResolvable reports whether one provenance citation must resolve
// on disk, and if so whether it does.
//
// `protected/…` is deliberately EXEMPT and the exemption is stated rather than
// implied: the protected store is the workspace orchestrator's immutable
// sidecar store, which is outside this repository by design and is cited by
// path plus sha256. Its absence from a worktree is expected; a typo in such a
// path is therefore NOT caught here, and that residue is disclosed in
// VerifyObservationProvenance's error text rather than papered over.
// Non-path citations (corpus case ids, mapping-row tokens) are resolved by the
// censuses in evidence_census.go, not here.
func ProvenanceIsResolvable(root, citation string) (mustResolve bool, resolved bool) {
	for _, prefix := range inRepositoryProvenancePrefixes {
		if strings.HasPrefix(citation, prefix) {
			_, err := os.Stat(filepath.Join(root, filepath.FromSlash(citation)))
			return true, err == nil
		}
	}
	return false, true
}

// observationSourceKind classifies an observation by the subject domain the
// definition chose, so a reader can tell at a glance which evidence family
// backs it.
//
// IT FAILS CLOSED. The previous version ended in a `default:` arm returning a
// plausible-sounding label for anything, which review BLOCKING 7 correctly
// identified as unfalsifiable: no subject could ever be misclassified in a way
// a test could catch, because every subject matched. An unrecognised subject
// domain is now an empty string, which BuildObservationSet turns into a
// regeneration error naming the subject. Adding a new domain is a deliberate
// act.
func observationSourceKind(subject string) string {
	switch {
	case strings.Contains(subject, ".client-handshake."):
		return "live-handshake-mapping-row (client direction; no live corpus case exercises these keys)"
	case strings.Contains(subject, ".server-handshake."):
		return "live-handshake-exam-case-or-borrowed-seed (server direction)"
	case strings.Contains(subject, ".framing."):
		return "public-corpus-proposition-plus-reference-model"
	case strings.Contains(subject, ".closeframe.") || strings.Contains(subject, ".websocketimpl."):
		return "public-corpus-proposition-plus-pinned-java-source"
	case strings.Contains(subject, ".charsetfunctions."):
		return "public-corpus-proposition-plus-pinned-java-source"
	case strings.Contains(subject, ".oracle-adapter."):
		return "public-corpus-class-sweep-plus-pinned-java-source"
	case strings.HasSuffix(subject, ".buffer-limit-check-sites"),
		strings.HasSuffix(subject, ".no-automatic-pong"):
		// Two draft6455-level propositions that are neither framing nor
		// handshake: where the buffer-limit checks fire, and the absence of an
		// automatic pong. Named explicitly rather than swept into a default,
		// which is the point of the fail-closed switch.
		return "public-corpus-proposition-plus-pinned-java-source"
	default:
		return ""
	}
}

// ExpectedObservationProvenance derives, from the DEFINITIONS' own hashed
// digest preimages, the provenance each observation must carry. It is the same
// derivation the regeneration path uses, exposed so the GATE can compare the
// committed document against it instead of merely checking that the committed
// strings are non-empty.
func ExpectedObservationProvenance(definitions []Definition) map[string]ObservationProvenance {
	expected := make(map[string]ObservationProvenance, len(definitions))
	for _, definition := range definitions {
		subjectRef := "semantic:" + definition.Subject + ":provisional-v1"
		expected[subjectRef] = observationProvenanceFor(subjectRef, definition)
	}
	return expected
}

// VerifyObservationProvenance requires every observation's provenance to EQUAL
// the provenance derived from the evidence that observation's record cites, and
// every in-repository citation to resolve on disk.
//
// ROUND-1 (BLOCKING 7) made the citations resolve. ROUND-2 found that resolving
// was not the same as being RIGHT: the check still accepted any non-empty
// source_kind and any unrelated path that happens to exist, and the fail-closed
// classifier ran only under `--regenerate-observations`, never under `--check`.
// Reproduced before this fix by rewriting one entry's source_kind to
// "totally-unrelated-source-kind-nobody-classified" and its evidence to
// ["evidence/java/build.json"] — a real file, cited by nothing — and reading
// `deltaledgerctl --check` exit 0.
//
// The comparison is now exact and in both directions, so a substituted,
// truncated, extended or reordered provenance fails. Where an observation has
// NO definition, the provenance is not compared: that is the state the digest
// arm of unledgered_disagreements exists to report (the record was deleted
// while its committed observation outlived it), and reporting it twice, once as
// the wrong kind of failure, would obscure it.
func VerifyObservationProvenance(root string, definitions []Definition) error {
	set, err := ReadObservations(root)
	if err != nil {
		return err
	}
	expected := ExpectedObservationProvenance(definitions)
	var problems []string
	for index, provenance := range set.Provenance {
		if index >= len(set.Observed) {
			break
		}
		if provenance.SubjectRef != set.Observed[index].SubjectRef {
			problems = append(problems, fmt.Sprintf("provenance %d is for %s but observation %d is %s",
				index, provenance.SubjectRef, index, set.Observed[index].SubjectRef))
		}
		if strings.TrimSpace(provenance.SourceKind) == "" {
			problems = append(problems, fmt.Sprintf("provenance %d (%s) has no source kind; observationSourceKind "+
				"fails closed on an unrecognised subject domain rather than inventing a plausible label",
				index, provenance.SubjectRef))
		}
		if len(provenance.Evidence) == 0 {
			problems = append(problems, fmt.Sprintf("provenance %d (%s) names no evidence", index, provenance.SubjectRef))
		}
		if want, known := expected[provenance.SubjectRef]; known {
			if want.SourceKind == "" {
				problems = append(problems, fmt.Sprintf(
					"provenance %d (%s): observationSourceKind does not recognise this subject's domain, so no source "+
						"kind can be required of it. Classify the domain deliberately in observations.go rather than "+
						"letting the committed document assert an unfalsifiable label", index, provenance.SubjectRef))
			} else if provenance.SourceKind != want.SourceKind {
				problems = append(problems, fmt.Sprintf(
					"provenance %d (%s) declares source kind %q, but the classifier derives %q from the subject's own "+
						"domain. The committed provenance must EQUAL the evidence-derived provenance, not merely be "+
						"non-empty", index, provenance.SubjectRef, provenance.SourceKind, want.SourceKind))
			}
			if !equalStrings(provenance.Evidence, want.Evidence) {
				problems = append(problems, fmt.Sprintf(
					"provenance %d (%s) cites %v, but the citations in that record's own hashed digest preimages are "+
						"%v. Provenance is DERIVED evidence, so an unrelated-but-existing path is a substitution, not "+
						"a weaker claim", index, provenance.SubjectRef, provenance.Evidence, want.Evidence))
			}
		}
		for _, citation := range provenance.Evidence {
			mustResolve, resolved := ProvenanceIsResolvable(root, citation)
			if mustResolve && !resolved {
				problems = append(problems, fmt.Sprintf("provenance %d (%s) cites %s, which does not exist",
					index, provenance.SubjectRef, citation))
			}
		}
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("observation provenance (%d problem(s)):\n  %s\n"+
			"NOTE ON SCOPE, stated rather than implied: `protected/...` citations name the workspace orchestrator's "+
			"immutable store, which is outside this repository by design, so a typo in one of those paths is not "+
			"caught by the on-disk half of this check — though the derived-equality half does catch it, because a "+
			"typo cannot appear in the record's own preimages and in the derivation at once.",
			len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// equalStrings reports exact slice equality, order included. Provenance is
// derived and sorted, so order is part of the claim.
func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// EncodeObservations renders the observation set exactly as it is committed.
func EncodeObservations(set ObservationSet) ([]byte, error) {
	encoded, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
