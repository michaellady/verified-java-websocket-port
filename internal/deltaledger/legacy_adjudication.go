package deltaledger

// THE LEGACY-RECORD ADJUDICATION DOCUMENT, AND THE GATE THAT SEALS IT.
//
// WHAT WAS LEFT UNDONE. The 1.2.0 landing gave the ledger US-020 AC3's
// vocabulary — `mismatch_class`, with the three terms AC3 names — and used it on
// the seven records appended at sequences 50-56. The forty-nine records sealed
// before the field existed could not use it, because a record's digest preimage
// is the canonical JSON of its whole delta: adding a byte to any one of them
// rewrites the chain from that record on and breaks the frozen prefix at
// sequence 35 that protected/ledger-frozen-prefix-owner-decision-2026-08-28.json
// requires to stay byte-identical. So the ledger published the honest residual,
// records_without_mismatch_class = 49, and stopped there. AC3 is not met while
// forty-nine of fifty-six mismatches carry no attribution, and "we cannot write
// it into the record" is a reason the field is empty, not a reason the
// ADJUDICATION does not exist.
//
// WHY NOT SUPERSEDING RECORDS. Forty-nine superseding records would be
// concretely broken, not merely heavy. A delta's identity derives from its
// disagreement digest, so a second record about the same disagreement collides
// unless its subject is perturbed; and `supersededSubjects` marks the originals
// WITHDRAWN, which coveringDefinitionsForRow, VerifyCensusRowsAreLedgered and
// UnledgeredEvidenceDemands all refuse as coverage. Adjudicating the forty-nine
// that way would strip the handshake-mapping and public-corpus censuses of
// their coverage and drive unledgered_disagreements off zero. That analysis is
// the ledger-disposition round-1 review's, and this file does not repeat the
// mistake it prevented.
//
// WHY A SIDE DOCUMENT IS THE RIGHT SHAPE HERE AND WAS THE WRONG SHAPE THERE.
// The 1.2.0 landing rejected a document-level side table AS A REPLACEMENT FOR
// PER-RECORD FIELDS ON NEW RECORDS, because a new record's adjudication would
// then live outside the hash chain, unsealed, when the record could simply carry
// it. That argument does not reach the forty-nine: they CANNOT carry a field.
// The choice for them is not "field or side table" but "side table or nothing",
// and this file is what stops the side table from being a place to type words.
//
// HOW IT IS SEALED. Every entry is bound to the record it adjudicates by
// CONTENT, never by name:
//
//   - the entry's delta_id must equal the identity RECOMPUTED from the record's
//     own disagreement digest, so an entry cannot be attached to a record by
//     writing its number down;
//   - the entry's record_digest must equal the record's digest, so any change to
//     any byte of that record refuses every entry pointing at it;
//   - the document's pre_vocabulary_head must equal the record digest at
//     sequence 49, which, the chain being hash-linked, pins every byte of
//     records 1-49 — a superset of the frozen prefix;
//   - the entry must QUOTE its record's own hashed rationale verbatim, at least
//     MinimumRationaleQuote bytes, and the quote must appear in NO OTHER
//     record's rationale. A quote is inside the digest preimage, so it is
//     content, not a name, and the uniqueness requirement makes the shared
//     boilerplate that forty-five of the records carry unusable: an adjudication
//     cannot be written without reading the record it adjudicates;
//   - the entry's cited RFC refs must be a non-empty subset of the record's own,
//     and its cited Java ref must equal the record's;
//   - a record whose own sealed RFC-value preimage says the RFC does not
//     determine the observable may not be classed `java-quirk`, because that
//     class asserts the RFC IS determinate. This one is checked against the
//     definition preimage, not against prose;
//   - a record the CHAIN ITSELF withdraws must be adjudicated as withdrawn. The
//     supersession links are re-derived from the records' own hashed
//     rationales, so an entry for a superseded record must set
//     contests_record_basis and name the superseding sequence, and its class
//     must equal the class filed for the record that replaced it. Sequences 14,
//     15 and 16 bound an RFC basis that 45, 46 and 47 corrected; the first
//     version of this document said so only in the `argument` prose, which is
//     the one field nothing checks. A finding recorded where nothing checks it
//     is a footnote, and this is the rule that stops it being one.
//
// AND WHAT IT PUBLISHES. records_without_ac3_class is RECOMPUTED over the whole
// chain — a record is classed if it carries the field OR a sealed entry gives it
// one — and a document that understates it is refused. It is deliberately not
// pinned to zero: pinning is the fake gate unledgered_disagreements used to be.
//
// WHAT THIS FILE DOES NOT DO. It does not touch
// evidence/java/behavior-delta-ledger.json, whose own
// records_without_mismatch_class stays at 49 and keeps its exact meaning: how
// many records carry no class IN THE RECORD. That number is a true statement
// about sealed bytes which no side document can change, internal/lab recomputes
// it from the record fields alone, and redefining it would make the ledger
// document publish 0 while forty-nine of its records carry nothing — a worse
// artifact than the residual it replaced. The two counters answer two
// questions and both are recomputed.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

const (
	// LegacyAdjudicationsRelativePath is the committed adjudication document
	// and LegacyAdjudicationsSchemaRelativePath is its contract.
	LegacyAdjudicationsRelativePath       = "evidence/java/legacy-record-adjudications.json"
	LegacyAdjudicationsSchemaRelativePath = "schemas/legacy-record-adjudications-1.0.0.schema.json"
	LegacyAdjudicationsSchemaPointer      = "../../schemas/legacy-record-adjudications-1.0.0.schema.json"
	LegacyAdjudicationsSchemaVersion      = "1.0.0"
	LegacyAdjudicationsEvidenceKind       = "legacy-record-adjudications"

	// MinimumRationaleQuote is how many bytes of the record's own hashed
	// rationale an entry must reproduce verbatim. It is long enough that the
	// quote cannot be a coincidence and short enough that a record whose
	// distinctive prose is one clause can still satisfy it.
	MinimumRationaleQuote = 60
	// MinimumArgument is the floor on the adjudication's own reasoning. It is
	// a floor on EFFORT, not a check on quality — the argument is a judgement
	// and is meant to be argued with, which is why it is published rather than
	// hashed into anything.
	MinimumArgument = 160
	// MinimumBlockingQuestion is the floor on what an honestly unresolved entry
	// must name. "The evidence does not settle it" is not an answer unless it
	// says what WOULD.
	MinimumBlockingQuestion = 60
)

// The three examination verdicts. There are exactly three because there are
// exactly three honest states, and the third one exists SO THAT IT CAN BE SAID:
// a design in which "I did not look" is unrepresentable forces the author to
// misreport it as one of the other two. It is representable, it is counted
// against the published residual exactly as an unclassed record is, and the
// report says how many entries carry it.
const (
	ExaminationSettles       = "evidence-settles-it"
	ExaminationDoesNotSettle = "evidence-does-not-settle-it"
	ExaminationNotExamined   = "not-examined"
)

// ExaminationVerdicts is the closed vocabulary.
func ExaminationVerdicts() []string {
	return []string{ExaminationSettles, ExaminationDoesNotSettle, ExaminationNotExamined}
}

// indeterminateRFCValuePrefixes are the normalized RFC-value tokens by which a
// record's OWN sealed preimage says RFC 6455 does not determine the observable.
//
// These are not a guess about the records: each is the leading token of a
// committed Definition.RFCValue, which is hashed into that record's
// rfc_value_digest and therefore into its delta identity. A record carrying one
// of them cannot be a `java-quirk`, because that class asserts the RFC
// DETERMINES the observable and Java is on the other side of it — there is no
// side to be on.
var indeterminateRFCValuePrefixes = []string{
	"no-requirement:",
	"recipient-choice:",
	"unspecified:",
	"unordered:",
}

// LegacyAdjudication is one record's AC3 attribution.
type LegacyAdjudication struct {
	Sequence      int      `json:"sequence"`
	DeltaID       string   `json:"delta_id"`
	RecordDigest  string   `json:"record_digest"`
	SubjectRef    string   `json:"subject_ref"`
	Examination   string   `json:"examination"`
	MismatchClass string   `json:"mismatch_class"`
	CitedRFCRefs  []string `json:"cited_rfc_refs"`
	CitedJavaRef  string   `json:"cited_java_ref"`
	// RationaleQuote is a verbatim substring of the record's own hashed
	// rationale, unique to that record across the whole chain.
	RationaleQuote string `json:"rationale_quote"`
	// Argument is the adjudication itself, published so it can be overturned.
	Argument string `json:"argument"`
	// BlockingQuestion is what would settle a record the evidence does not.
	BlockingQuestion string `json:"blocking_question"`
	// ContestsRecordBasis marks a record whose own sealed RFC basis or Java
	// observation is contradicted by evidence recorded LATER in the chain. It
	// carries an obligation, and the obligation has exactly two discharges:
	// name a committed draft proposing the superseding record, or name the
	// sequence that ALREADY supersedes it in the chain.
	ContestsRecordBasis bool   `json:"contests_record_basis"`
	SupersessionDraft   string `json:"supersession_draft"`
	// SupersededBySequence is the sequence whose record supersedes this one.
	// It is not a label: the gate re-derives the supersession links from the
	// RECORDS' own hashed rationales and refuses a value the chain does not
	// say. Zero means the chain records no supersession for this record.
	SupersededBySequence int `json:"superseded_by_sequence,omitempty"`
}

// LegacyAdjudicationsFile mirrors the committed document field for field.
type LegacyAdjudicationsFile struct {
	Schema                 string               `json:"$schema"`
	SchemaVersion          string               `json:"schema_version"`
	EvidenceKind           string               `json:"evidence_kind"`
	AcceptedRootDigest     string               `json:"accepted_root_digest"`
	LedgerDocument         string               `json:"ledger_document"`
	PreVocabularySequence  int                  `json:"pre_vocabulary_sequence"`
	PreVocabularyHead      string               `json:"pre_vocabulary_head"`
	RecordsWithoutAC3Class int                  `json:"records_without_ac3_class"`
	Adjudications          []LegacyAdjudication `json:"adjudications"`
}

// ReadLegacyAdjudications decodes the committed document.
func ReadLegacyAdjudications(root string) (LegacyAdjudicationsFile, error) {
	var file LegacyAdjudicationsFile
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(LegacyAdjudicationsRelativePath)))
	if err != nil {
		return file, fmt.Errorf("%s: %w", LegacyAdjudicationsRelativePath, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return file, fmt.Errorf("%s: %w", LegacyAdjudicationsRelativePath, err)
	}
	return file, nil
}

// AC3ClassFor reports the US-020 AC3 mismatch class a record states ANYWHERE:
// in its own field, or in a sealed legacy adjudication bound to it. The second
// arm is only consulted for records at or before PreVocabularySequence, so the
// side document can never stand in for a field a new record is required to
// carry.
func AC3ClassFor(record lab.BehaviorLedgerRecord, byDelta map[string]LegacyAdjudication) string {
	if record.Delta.MismatchClass != "" {
		return record.Delta.MismatchClass
	}
	if record.Sequence > PreVocabularySequence {
		return ""
	}
	return byDelta[record.Delta.DeltaID].MismatchClass
}

// CountRecordsWithoutAC3Class is the published residual of the adjudication
// document: how many records in the chain make no AC3 attribution ANYWHERE.
//
// IS IT AT LEAST AS HARD TO SATISFY as the ledger's own
// records_without_mismatch_class? It is a DIFFERENT and larger obligation: that
// counter is driven down only by appending classed records, and it is silent
// about the forty-nine; this one demands an attribution for every record in the
// chain including all forty-nine. Driving THIS one down by one on a legacy
// record costs an entry that reproduces the record's identity from its
// disagreement digest, matches its record digest, quotes at least
// MinimumRationaleQuote bytes of its sealed rationale in a form no other record
// carries, cites a subset of its own RFC refs and its exact Java ref, and
// survives the RFC-determinacy rule. Setting a field on a new record costs one
// enum value in a Go literal. The claim that the new route is not the cheap one
// is argued, not measured, and it is the load-bearing claim of this design.
func CountRecordsWithoutAC3Class(records []lab.BehaviorLedgerRecord, byDelta map[string]LegacyAdjudication) int {
	count := 0
	for _, record := range records {
		if AC3ClassFor(record, byDelta) == "" {
			count++
		}
	}
	return count
}

// VerifyLegacyAdjudications is the whole rule.
func VerifyLegacyAdjudications(root string, records []lab.BehaviorLedgerRecord, definitions []Definition) error {
	file, err := ReadLegacyAdjudications(root)
	if err != nil {
		return err
	}
	var problems []string
	fail := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	// 1. THE ENVELOPE, and the chain binding that makes every later rule mean
	// something. pre_vocabulary_head is the record digest at sequence 49; the
	// chain is hash-linked, so it pins every byte of records 1-49.
	if file.SchemaVersion != LegacyAdjudicationsSchemaVersion {
		fail("schema_version is %q, not %q", file.SchemaVersion, LegacyAdjudicationsSchemaVersion)
	}
	if file.EvidenceKind != LegacyAdjudicationsEvidenceKind {
		fail("evidence_kind is %q, not %q", file.EvidenceKind, LegacyAdjudicationsEvidenceKind)
	}
	if file.Schema != LegacyAdjudicationsSchemaPointer {
		fail("$schema is %q, not %q", file.Schema, LegacyAdjudicationsSchemaPointer)
	}
	if file.LedgerDocument != LedgerRelativePath {
		fail("ledger_document is %q, not %q", file.LedgerDocument, LedgerRelativePath)
	}
	if file.PreVocabularySequence != PreVocabularySequence {
		fail("pre_vocabulary_sequence is %d, but internal/deltaledger.PreVocabularySequence is %d. This document "+
			"adjudicates exactly the records that predate the 1.2.0 vocabulary; disagreeing with the constant would "+
			"let it claim a different set", file.PreVocabularySequence, PreVocabularySequence)
	}
	if len(records) < PreVocabularySequence {
		return fmt.Errorf("the chain has %d records; the pre-vocabulary prefix through sequence %d cannot be "+
			"adjudicated", len(records), PreVocabularySequence)
	}
	head := records[PreVocabularySequence-1]
	if head.Sequence != PreVocabularySequence {
		fail("record at index %d carries sequence %d, not %d", PreVocabularySequence-1, head.Sequence,
			PreVocabularySequence)
	}
	if file.PreVocabularyHead != head.RecordDigest {
		fail("pre_vocabulary_head is %s but the record at sequence %d digests to %s. Because the chain is "+
			"hash-linked, that value pins every byte of records 1-%d, so an adjudication document that names a "+
			"different one is adjudicating a chain this repository does not have",
			file.PreVocabularyHead, PreVocabularySequence, head.RecordDigest, PreVocabularySequence)
	}

	// 1b. THE SUPERSESSION MAP, re-derived from the RECORDS rather than read
	// from the sidecar that declares it. Three of the forty-nine — 14, 15 and
	// 16 — bound an RFC basis that records 45, 46 and 47 later corrected, and
	// the correction is IN the chain. An adjudication of a withdrawn record
	// that did not say the record was withdrawn would be filing a class under a
	// basis the chain itself has already refuted, which is precisely the
	// footnote this rule refuses to let a finding become.
	supersededBy := map[int]int{}
	links, linkErr := ReadSupersessionLinks(records)
	if linkErr != nil {
		fail("the supersession links cannot be re-derived from the chain: %v", linkErr)
	}
	for _, link := range links {
		supersededBy[int(link.SupersededSequence)] = int(link.SupersedingSequence)
	}

	// 2. TOTALITY. Exactly one entry per record 1..PreVocabularySequence, in
	// order, with nothing outside that range. This is what stops the residual
	// from falling by OMISSION: a record with no entry is not silently classed,
	// it is a refusal.
	byDelta := map[string]LegacyAdjudication{}
	seen := map[int]bool{}
	for index, entry := range file.Adjudications {
		if entry.Sequence < 1 || entry.Sequence > PreVocabularySequence {
			fail("adjudication %d names sequence %d, which is outside 1..%d. Records after sequence %d are written "+
				"under a vocabulary that can say what they mean and MUST carry the field; a side entry for one of "+
				"them would be the unsealed adjudication the 1.2.0 landing rejected",
				index, entry.Sequence, PreVocabularySequence, PreVocabularySequence)
			continue
		}
		if seen[entry.Sequence] {
			fail("sequence %d is adjudicated more than once", entry.Sequence)
			continue
		}
		seen[entry.Sequence] = true
		if index > 0 && file.Adjudications[index-1].Sequence >= entry.Sequence {
			fail("adjudications are not in ascending sequence order at index %d (sequence %d follows %d)",
				index, entry.Sequence, file.Adjudications[index-1].Sequence)
		}
		byDelta[entry.DeltaID] = entry
	}
	for sequence := 1; sequence <= PreVocabularySequence; sequence++ {
		if !seen[sequence] {
			fail("sequence %d carries no adjudication. Every record that predates the 1.2.0 vocabulary must be "+
				"filed under US-020 AC3 — as a Java quirk, a Rust defect or underspecified behavior — or must say, "+
				"in an entry of its own, that the evidence does not settle it and what would", sequence)
		}
	}

	// 3-7. THE PER-ENTRY RULES.
	for _, entry := range file.Adjudications {
		if entry.Sequence < 1 || entry.Sequence > len(records) {
			continue
		}
		record := records[entry.Sequence-1]
		where := fmt.Sprintf("sequence %d", entry.Sequence)

		// 3. IDENTITY, recomputed. The entry is bound to the record's CONTENT:
		// the delta identity is a function of the disagreement digest, and the
		// record digest is a function of the whole record.
		identity, idErr := lab.BehaviorDeltaID(record.Delta.DisagreementDigest)
		if idErr != nil {
			fail("%s: the record's disagreement digest does not yield an identity: %v", where, idErr)
		} else if entry.DeltaID != identity {
			fail("%s: the entry names delta_id %s, but the identity RECOMPUTED from the record's own disagreement "+
				"digest is %s. An adjudication is attached to a record by the record's evidence, never by a name "+
				"typed beside it", where, entry.DeltaID, identity)
		}
		if entry.DeltaID != record.Delta.DeltaID {
			fail("%s: the entry names delta_id %s; the record carries %s", where, entry.DeltaID, record.Delta.DeltaID)
		}
		if entry.RecordDigest != record.RecordDigest {
			fail("%s: the entry binds record_digest %s; the record digests to %s. Any change to any byte of the "+
				"record refuses the adjudication written about it", where, entry.RecordDigest, record.RecordDigest)
		}
		if entry.SubjectRef != record.Delta.SubjectRef {
			fail("%s: the entry names subject %s; the record carries %s", where, entry.SubjectRef,
				record.Delta.SubjectRef)
		}

		// 4. THE VERDICT VOCABULARY, and what each verdict obliges.
		switch entry.Examination {
		case ExaminationSettles:
			if entry.MismatchClass == "" {
				fail("%s: examination is %q but no mismatch_class is stated. A record whose evidence settles it must "+
					"say which of AC3's three classes it falls in", where, entry.Examination)
			}
			if entry.BlockingQuestion != "" {
				fail("%s: examination is %q but a blocking_question is stated. A settled record has nothing blocking",
					where, entry.Examination)
			}
		case ExaminationDoesNotSettle:
			if entry.MismatchClass != "" {
				fail("%s: examination is %q but mismatch_class %q is stated. Either the evidence settles it or it "+
					"does not", where, entry.Examination, entry.MismatchClass)
			}
			if len(entry.BlockingQuestion) < MinimumBlockingQuestion {
				fail("%s: examination is %q but the blocking_question is %d bytes, under the %d-byte floor. "+
					"\"the evidence does not settle it\" is an answer only when it says what WOULD",
					where, entry.Examination, len(entry.BlockingQuestion), MinimumBlockingQuestion)
			}
		case ExaminationNotExamined:
			if entry.MismatchClass != "" || entry.BlockingQuestion != "" {
				fail("%s: examination is %q, so the entry may state neither a class nor a blocking question",
					where, entry.Examination)
			}
		default:
			fail("%s: examination is %q, which is outside the vocabulary %v", where, entry.Examination,
				ExaminationVerdicts())
		}
		if entry.MismatchClass != "" && !vocabularyContains(entry.MismatchClass, lab.MismatchClasses()) {
			fail("%s: mismatch_class %q is outside the US-020 AC3 vocabulary %v", where, entry.MismatchClass,
				lab.MismatchClasses())
		}

		// 5. CITATION. The refs must be the RECORD'S refs.
		if len(entry.CitedRFCRefs) == 0 {
			fail("%s: the entry cites no RFC ref", where)
		}
		for _, ref := range entry.CitedRFCRefs {
			if !vocabularyContains(ref, record.Delta.RFCRefs) {
				fail("%s: the entry cites RFC ref %q, which the record does not carry (record refs: %v)",
					where, ref, record.Delta.RFCRefs)
			}
		}
		if entry.CitedJavaRef != record.Delta.JavaRef {
			fail("%s: the entry cites Java ref %q; the record binds %q", where, entry.CitedJavaRef,
				record.Delta.JavaRef)
		}

		// 6. THE QUOTE. This is the rule that makes an adjudication impossible
		// to write without reading the record. The quote is inside the digest
		// preimage, so it is CONTENT; and requiring it to be unique across the
		// chain makes the shared retention boilerplate that forty-five records
		// carry unusable for it.
		if len(entry.RationaleQuote) < MinimumRationaleQuote {
			fail("%s: rationale_quote is %d bytes, under the %d-byte floor", where, len(entry.RationaleQuote),
				MinimumRationaleQuote)
		} else if !strings.Contains(record.Delta.Rationale, entry.RationaleQuote) {
			fail("%s: rationale_quote does not appear in the record's own hashed rationale. The quote is the "+
				"binding: it lives inside the digest preimage, so an adjudication that cannot quote its record has "+
				"not read it", where)
		} else {
			for _, other := range records {
				if other.Sequence == uint64(entry.Sequence) {
					continue
				}
				if strings.Contains(other.Delta.Rationale, entry.RationaleQuote) {
					fail("%s: rationale_quote also appears in the rationale of sequence %d, so it does not identify "+
						"this record. Quote the record's OWN prose, not the boilerplate it shares",
						where, other.Sequence)
					break
				}
			}
		}

		// 7. THE ARGUMENT. A floor on effort, not a judge of quality.
		if len(entry.Argument) < MinimumArgument {
			fail("%s: argument is %d bytes, under the %d-byte floor", where, len(entry.Argument),
				MinimumArgument)
		}

		// 8. THE RFC-DETERMINACY RULE, checked against the record's own sealed
		// preimage rather than against prose. `java-quirk` asserts the RFC
		// DETERMINES the observable and Java is on the other side of it; a
		// record whose rfc_value preimage opens with an indeterminacy token
		// says there is no side to be on.
		if entry.Sequence <= len(definitions) {
			rfcValue := definitions[entry.Sequence-1].RFCValue
			if entry.MismatchClass == lab.MismatchJavaQuirk && hasIndeterminatePrefix(rfcValue) {
				fail("%s: classed %q, but the record's own sealed rfc_value preimage opens %q — the RFC does not "+
					"determine this observable, so Java cannot be on the other side of it",
					where, entry.MismatchClass, firstToken(rfcValue))
			}
		}

		// 9. A CONTESTED RECORD OWES A CORRECTION, and there are exactly two
		// ways to owe it: a held draft proposing one, or a superseding record
		// the chain already carries. The flag is a declaration; the obligation
		// it carries is not.
		superseding := supersededBy[entry.Sequence]
		if entry.ContestsRecordBasis {
			if entry.SupersessionDraft == "" && entry.SupersededBySequence == 0 {
				fail("%s: contests_record_basis is set but the entry names neither a supersession_draft nor a "+
					"superseded_by_sequence. A legacy record whose own sealed basis is contradicted by later "+
					"evidence is a finding, and a finding this program records is one with a correction beside it "+
					"— drafted, or already in the chain", where)
			}
			if entry.SupersessionDraft != "" {
				if _, statErr := os.Stat(filepath.Join(root,
					filepath.FromSlash(entry.SupersessionDraft))); statErr != nil {
					fail("%s: supersession_draft %s does not exist: %v", where, entry.SupersessionDraft, statErr)
				} else if !strings.HasPrefix(entry.SupersessionDraft, "drafts/ledger-proposals/") {
					fail("%s: supersession_draft %s is not under drafts/ledger-proposals/. Corrections are DRAFTED "+
						"there; nothing on this path appends to the ledger", where, entry.SupersessionDraft)
				}
			}
		} else {
			if entry.SupersessionDraft != "" {
				fail("%s: a supersession_draft is named but contests_record_basis is not set", where)
			}
			if entry.SupersededBySequence != 0 {
				fail("%s: a superseded_by_sequence is named but contests_record_basis is not set", where)
			}
		}

		// 9b. THE CHAIN'S OWN SUPERSESSIONS ARE NOT OPTIONAL TO MENTION. The
		// links are re-derived from the records' hashed rationales, so this is
		// checked against sealed content and not against the sidecar that
		// declares the same links.
		if superseding != 0 {
			if !entry.ContestsRecordBasis {
				fail("%s: the chain records this record as SUPERSEDED by sequence %d, but the entry does not set "+
					"contests_record_basis. An adjudication of a withdrawn record that does not say the record was "+
					"withdrawn files a class under a basis the chain has already refuted", where, superseding)
			}
			if entry.SupersededBySequence != superseding {
				fail("%s: the entry names superseded_by_sequence %d; the chain's own hashed rationales say this "+
					"record is superseded by sequence %d", where, entry.SupersededBySequence, superseding)
			}
		} else if entry.SupersededBySequence != 0 {
			fail("%s: the entry names superseded_by_sequence %d, but the chain records no supersession of this "+
				"record at all", where, entry.SupersededBySequence)
		}

		// 9c. TWO RECORDS ABOUT ONE SUBJECT MAY NOT BE FILED UNDER TWO CLASSES.
		// A superseding record states the corrected basis for the same
		// observable; if the adjudication of the withdrawn record and the
		// adjudication of the record that replaced it disagree about where the
		// mismatch ORIGINATES, one of them is wrong and the disagreement is the
		// finding.
		if superseding != 0 && superseding <= len(records) && entry.MismatchClass != "" {
			replacement := AC3ClassFor(records[superseding-1], byDelta)
			if replacement != "" && replacement != entry.MismatchClass {
				fail("%s: filed %q, but sequence %d — the record that supersedes it, about the same observable on "+
					"the corrected basis — is filed %q. Two adjudications of one subject may not disagree about "+
					"where the mismatch originates", where, entry.MismatchClass, superseding, replacement)
			}
		}
	}

	// 10. THE RESIDUAL, recomputed. Never pinned: a schema `const: 0` here
	// would be exactly the fake gate unledgered_disagreements used to be.
	residual := CountRecordsWithoutAC3Class(records, byDelta)
	if file.RecordsWithoutAC3Class != residual {
		fail("the document publishes records_without_ac3_class=%d but %d of the %d records in the chain state no "+
			"AC3 mismatch class in either their own field or a sealed adjudication",
			file.RecordsWithoutAC3Class, residual, len(records))
	}

	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("legacy-record adjudications (%d problem(s)):\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

func hasIndeterminatePrefix(rfcValue string) bool {
	for _, prefix := range indeterminateRFCValuePrefixes {
		if strings.HasPrefix(rfcValue, prefix) {
			return true
		}
	}
	return false
}

func firstToken(value string) string {
	if index := strings.Index(value, ":"); index >= 0 {
		return value[:index+1]
	}
	return value
}
