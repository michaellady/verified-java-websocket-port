package deltaledger

// POLARITY FOR THE LEGACY-RECORD ADJUDICATION DOCUMENT.
//
// Every probe here mutates the COMMITTED document in a temporary root and runs
// VerifyLegacyAdjudications, the same exported function cmd/deltaledgerctl
// calls through VerifyIntegrity — never a reimplementation of it. A rule that
// is strong here and absent from the gate is the failure mode this repository
// keeps rediscovering, so the tests deliberately have no rules of their own.
//
// The deletion attacks — removing each rule from legacy_adjudication.go and
// proving something goes red — are recorded in
// drafts/self-review/legacy-record-adjudication-round-1.md, with the two that
// did not isolate named as such.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// legacyProbeRoot copies the two artifacts VerifyLegacyAdjudications reads into
// a temporary root and applies one mutation to the decoded document.
func legacyProbeRoot(t *testing.T, mutate func(file *LegacyAdjudicationsFile)) string {
	t.Helper()
	root := t.TempDir()
	file, err := ReadLegacyAdjudications(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed adjudications: %v", err)
	}
	if mutate != nil {
		mutate(&file)
	}
	encoded, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	encoded = append(encoded, '\n')
	target := filepath.Join(root, filepath.FromSlash(LegacyAdjudicationsRelativePath))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(target, encoded, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Every entry that names a supersession draft must find it, so the draft is
	// copied too. A probe that failed because the draft was missing would be
	// telling us nothing about the rule under attack.
	for _, entry := range file.Adjudications {
		if entry.SupersessionDraft == "" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(entry.SupersessionDraft)))
		if err != nil {
			continue
		}
		draftTarget := filepath.Join(root, filepath.FromSlash(entry.SupersessionDraft))
		if err := os.MkdirAll(filepath.Dir(draftTarget), 0o755); err != nil {
			t.Fatalf("mkdir draft: %v", err)
		}
		if err := os.WriteFile(draftTarget, raw, 0o644); err != nil {
			t.Fatalf("write draft: %v", err)
		}
	}
	return root
}

func committedChain(t *testing.T) []lab.BehaviorLedgerRecord {
	t.Helper()
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	return committed.Records
}

// TestTheCommittedLegacyAdjudicationsPassTheGate is the baseline every probe
// below is measured against. Without it a probe that goes red proves nothing:
// red could be the committed state.
func TestTheCommittedLegacyAdjudicationsPassTheGate(t *testing.T) {
	records := committedChain(t)
	if err := VerifyLegacyAdjudications(ledgerTestRepoRoot, records, Definitions()); err != nil {
		t.Fatalf("the committed adjudications must pass their own gate: %v", err)
	}
}

// TestEveryPreVocabularyRecordIsAdjudicated is the AC3 statement itself, read
// off the committed artifacts rather than asserted about them.
func TestEveryPreVocabularyRecordIsAdjudicated(t *testing.T) {
	records := committedChain(t)
	file, err := ReadLegacyAdjudications(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(file.Adjudications) != PreVocabularySequence {
		t.Fatalf("the document carries %d adjudications for %d pre-vocabulary records",
			len(file.Adjudications), PreVocabularySequence)
	}
	byDelta := map[string]LegacyAdjudication{}
	for _, entry := range file.Adjudications {
		byDelta[entry.DeltaID] = entry
	}
	unclassed := CountRecordsWithoutAC3Class(records, byDelta)
	if unclassed != file.RecordsWithoutAC3Class {
		t.Fatalf("recomputed residual %d, document publishes %d", unclassed, file.RecordsWithoutAC3Class)
	}
	// The ledger's OWN counter must be untouched by any of this: it counts
	// records with no FIELD, which no side document can change.
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	if got := CountRecordsWithoutMismatchClass(records); got != committed.RecordsWithoutMismatchClass {
		t.Fatalf("records_without_mismatch_class recomputes to %d, ledger publishes %d",
			got, committed.RecordsWithoutMismatchClass)
	}
	if got := CountRecordsWithoutMismatchClass(records); got != PreVocabularySequence {
		t.Fatalf("records_without_mismatch_class is %d; the forty-nine sealed records cannot gain a field, so it "+
			"must still be %d. A side document that moved this number would be describing a chain we do not have",
			got, PreVocabularySequence)
	}
}

// TestVerifyLegacyAdjudicationsRefusesEachWayAnEntryCanFailToBind is the
// discrimination proof. Each case breaks ONE binding and nothing else.
func TestVerifyLegacyAdjudicationsRefusesEachWayAnEntryCanFailToBind(t *testing.T) {
	records := committedChain(t)
	definitions := Definitions()

	// firstOfClass finds an entry index carrying a given class, so a probe can
	// aim at a real entry rather than at whichever one happens to be first.
	indexOfSequence := func(file *LegacyAdjudicationsFile, sequence int) int {
		for index, entry := range file.Adjudications {
			if entry.Sequence == sequence {
				return index
			}
		}
		t.Fatalf("no entry for sequence %d", sequence)
		return -1
	}

	cases := []struct {
		name   string
		mutate func(file *LegacyAdjudicationsFile)
		expect string
	}{
		{
			name: "an entry is dropped, so the residual would fall by omission",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 7)
				file.Adjudications = append(file.Adjudications[:index], file.Adjudications[index+1:]...)
			},
			expect: "sequence 7 carries no adjudication",
		},
		{
			// THE ISOLATING FORM of the probe above. Dropping an entry alone
			// goes red on the RESIDUAL recomputation, not on totality, because
			// the record it named then counts as unclassed. Correcting the
			// published residual for it removes that signal, so only the
			// totality rule is left to refuse — which is the rule that stops
			// "adjudicate 48 of 49 and publish an honest 2" from being a way
			// to make a record disappear rather than be judged.
			name: "an entry is dropped AND the residual is corrected for it, so only totality can refuse",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 7)
				file.Adjudications = append(file.Adjudications[:index], file.Adjudications[index+1:]...)
				file.RecordsWithoutAC3Class++
			},
			expect: "sequence 7 carries no adjudication",
		},
		{
			name: "an entry claims a delta_id the record's disagreement digest does not produce",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 3)
				file.Adjudications[index].DeltaID = file.Adjudications[indexOfSequence(file, 4)].DeltaID
			},
			expect: "RECOMPUTED from the record's own disagreement digest",
		},
		{
			name: "an entry binds the wrong record digest",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 5)
				file.Adjudications[index].RecordDigest =
					"sha256:0000000000000000000000000000000000000000000000000000000000000000"
			},
			expect: "the record digests to",
		},
		{
			name: "the document names a pre-vocabulary head the chain does not have",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.PreVocabularyHead =
					"sha256:1111111111111111111111111111111111111111111111111111111111111111"
			},
			expect: "pins every byte of records 1-49",
		},
		{
			name: "a quote is not in the record's own hashed rationale",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 11)
				file.Adjudications[index].RationaleQuote =
					"a sentence nobody wrote into any record of this chain, long enough to clear the floor easily"
			},
			expect: "does not appear in the record's own hashed rationale",
		},
		{
			name: "a quote is the boilerplate forty-five records share, so it identifies nothing",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 11)
				file.Adjudications[index].RationaleQuote =
					"'unresolved' because the frozen 1.0.0 vocabulary has no java-faithful term"
			},
			expect: "does not identify this record",
		},
		{
			name: "an entry cites an RFC ref its record does not carry",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 17)
				file.Adjudications[index].CitedRFCRefs = []string{"rfc6455#section-11.9"}
			},
			expect: "which the record does not carry",
		},
		{
			name: "an entry cites a Java ref its record does not bind",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 17)
				file.Adjudications[index].CitedJavaRef = "java-v1.6.0:org.java_websocket.Invented:method"
			},
			expect: "the record binds",
		},
		{
			name: "a record whose own rfc_value says the RFC does not determine it is classed java-quirk",
			mutate: func(file *LegacyAdjudicationsFile) {
				// Sequence 43's sealed rfc_value opens "unspecified:".
				index := indexOfSequence(file, 43)
				file.Adjudications[index].MismatchClass = lab.MismatchJavaQuirk
			},
			expect: "the RFC does not determine this observable",
		},
		{
			name: "an unresolved entry states no blocking question",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 19)
				file.Adjudications[index].BlockingQuestion = "dunno"
			},
			expect: "says what WOULD",
		},
		{
			name: "an entry claims both a class and that the evidence does not settle it",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 19)
				file.Adjudications[index].MismatchClass = lab.MismatchJavaQuirk
			},
			expect: "Either the evidence settles it or it does not",
		},
		{
			name: "a settled entry states no class",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 1)
				file.Adjudications[index].MismatchClass = ""
			},
			expect: "no mismatch_class is stated",
		},
		{
			name: "an entry is filed not-examined, which is representable and still counted",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 1)
				file.Adjudications[index].Examination = ExaminationNotExamined
				file.Adjudications[index].MismatchClass = ""
				// The residual is deliberately NOT updated: the point is that
				// an unexamined record raises it and the document must say so.
			},
			expect: "records_without_ac3_class",
		},
		{
			name: "an entry uses a class outside AC3's vocabulary",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 2)
				file.Adjudications[index].MismatchClass = "probably-fine"
			},
			expect: "outside the US-020 AC3 vocabulary",
		},
		{
			name: "an entry adjudicates a record that must carry the field itself",
			mutate: func(file *LegacyAdjudicationsFile) {
				extra := file.Adjudications[0]
				extra.Sequence = PreVocabularySequence + 1
				file.Adjudications = append(file.Adjudications, extra)
			},
			expect: "outside 1..49",
		},
		{
			name: "a contesting entry names neither a draft nor a superseding sequence",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 13)
				file.Adjudications[index].SupersessionDraft = ""
			},
			expect: "names neither a supersession_draft nor a superseded_by_sequence",
		},
		{
			// THE FINDING THIS RULE EXISTS FOR. Sequences 14, 15 and 16 bound an
			// RFC basis that records 45, 46 and 47 later corrected, and an
			// earlier version of this document recorded that only in the
			// argument prose.
			name: "an entry adjudicates a withdrawn record without saying it is withdrawn",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 14)
				file.Adjudications[index].ContestsRecordBasis = false
				file.Adjudications[index].SupersededBySequence = 0
			},
			expect: "the chain records this record as SUPERSEDED by sequence 45",
		},
		{
			name: "an entry names a superseding sequence the chain does not say",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Adjudications[indexOfSequence(file, 15)].SupersededBySequence = 45
			},
			expect: "the chain's own hashed rationales say this record is superseded by sequence 46",
		},
		{
			name: "an entry claims a supersession for a record the chain never withdrew",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 20)
				file.Adjudications[index].ContestsRecordBasis = true
				file.Adjudications[index].SupersededBySequence = 45
			},
			expect: "the chain records no supersession of this record at all",
		},
		{
			// Sequence 14's own sealed rfc_value opens "reject:", so the
			// determinacy rule permits java-quirk and cannot be what refuses
			// this. Only the disagreement with sequence 45 can.
			name: "a withdrawn record and the record that replaced it are filed under different classes",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Adjudications[indexOfSequence(file, 14)].MismatchClass = lab.MismatchJavaQuirk
			},
			expect: "may not disagree about where the mismatch originates",
		},
		{
			name: "a contesting entry names a draft that does not exist",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 13)
				file.Adjudications[index].SupersessionDraft = "drafts/ledger-proposals/not-written-yet.json"
			},
			expect: "does not exist",
		},
		{
			name: "the published residual understates the chain",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.RecordsWithoutAC3Class = 0
			},
			expect: "state no AC3 mismatch class in either their own field or a sealed adjudication",
		},
		{
			name: "the document claims a different pre-vocabulary set",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.PreVocabularySequence = 35
			},
			expect: "pre_vocabulary_sequence is 35",
		},
		{
			// The subject is the third of the three content bindings and had no
			// probe until this round. Naming a NEIGHBOUR's subject rather than a
			// fabricated one keeps the value well-formed, so only the binding
			// can refuse it.
			name: "an entry names the subject of a different record",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Adjudications[indexOfSequence(file, 21)].SubjectRef =
					file.Adjudications[indexOfSequence(file, 22)].SubjectRef
			},
			expect: "the entry names subject",
		},
		{
			// The effort floor on the adjudication itself. It cannot judge
			// quality — nothing mechanical can — but an entry that files a
			// record under one of AC3's three classes with nothing said is the
			// failure this whole document exists to avoid.
			name: "an entry files a class with no argument behind it",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Adjudications[indexOfSequence(file, 23)].Argument = "java does that"
			},
			expect: "under the 160-byte floor",
		},
		{
			name: "an entry cites no RFC ref at all",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Adjudications[indexOfSequence(file, 25)].CitedRFCRefs = nil
			},
			expect: "cites no RFC ref",
		},
		{
			name: "a quote is too short to be anything but a coincidence",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Adjudications[indexOfSequence(file, 27)].RationaleQuote = "DIVERGENCE"
			},
			expect: "rationale_quote is 10 bytes",
		},
		{
			// Two entries for one record, which is how a total-looking document
			// could still leave a record unjudged.
			name: "one record is adjudicated twice",
			mutate: func(file *LegacyAdjudicationsFile) {
				index := indexOfSequence(file, 29)
				duplicated := make([]LegacyAdjudication, 0, len(file.Adjudications)+1)
				duplicated = append(duplicated, file.Adjudications[:index+1]...)
				duplicated = append(duplicated, file.Adjudications[index])
				duplicated = append(duplicated, file.Adjudications[index+1:]...)
				file.Adjudications = duplicated
			},
			expect: "adjudicated more than once",
		},
		{
			name: "two entries are out of ascending order",
			mutate: func(file *LegacyAdjudicationsFile) {
				first, second := indexOfSequence(file, 31), indexOfSequence(file, 32)
				file.Adjudications[first], file.Adjudications[second] =
					file.Adjudications[second], file.Adjudications[first]
			},
			expect: "not in ascending sequence order",
		},
		{
			// A draft that EXISTS but is not a draft. Nothing on this path may
			// append to the ledger, so a "supersession draft" pointing at a
			// committed evidence document would be a correction that had already
			// happened.
			name: "a contesting entry names a real file that is not a held draft",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Adjudications[indexOfSequence(file, 13)].SupersessionDraft =
					LegacyAdjudicationsSchemaRelativePath
			},
			expect: "is not under drafts/ledger-proposals/",
		},
		{
			// The flag and the obligation are checked in both directions: a
			// contesting entry owes a draft, and a draft named without the flag
			// is an entry contesting a record without saying so.
			name: "an entry names a draft without declaring that it contests the record",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Adjudications[indexOfSequence(file, 33)].SupersessionDraft =
					"drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json"
			},
			expect: "contests_record_basis is not set",
		},
		{
			name: "a settled entry also states a blocking question",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Adjudications[indexOfSequence(file, 35)].BlockingQuestion =
					"what would settle a record this entry has just said its own evidence already settles?"
			},
			expect: "A settled record has nothing blocking",
		},
		{
			name: "an entry says it did not look and files a class anyway",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Adjudications[indexOfSequence(file, 37)].Examination = ExaminationNotExamined
			},
			expect: "may state neither a class nor a blocking question",
		},
		{
			name: "an entry uses a verdict outside the examination vocabulary",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Adjudications[indexOfSequence(file, 39)].Examination = "looks-fine-to-me"
			},
			expect: "outside the vocabulary",
		},
		{
			name: "the document declares a schema version the gate does not implement",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.SchemaVersion = "2.0.0"
			},
			expect: "schema_version is \"2.0.0\"",
		},
		{
			name: "the document declares some other evidence kind",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.EvidenceKind = "notes"
			},
			expect: "evidence_kind is \"notes\"",
		},
		{
			name: "the document points at some other schema",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.Schema = "../../schemas/behavior-delta-ledger-1.2.0.schema.json"
			},
			expect: "$schema is",
		},
		{
			// The adjudications are about ONE ledger document. A document that
			// named a different one would be adjudicating records this gate
			// never reads.
			name: "the document claims to adjudicate a different ledger",
			mutate: func(file *LegacyAdjudicationsFile) {
				file.LedgerDocument = "evidence/java/ledger-supersessions.json"
			},
			expect: "ledger_document is",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			root := legacyProbeRoot(t, testCase.mutate)
			err := VerifyLegacyAdjudications(root, records, definitions)
			if err == nil {
				t.Fatalf("the gate accepted a document in which %s", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.expect) {
				t.Fatalf("the gate refused, but not for the reason under attack.\nwanted a message containing: %s"+
					"\ngot: %v", testCase.expect, err)
			}
		})
	}
}

// TestTheRecomputedIdentityCatchesATamperedStoredDeltaID isolates the one rule
// the committed chain cannot exercise.
//
// VerifyLegacyAdjudications checks an entry's delta_id TWICE: against the
// identity recomputed from the record's own disagreement digest, and against
// the delta_id the record stores. On the committed chain those two are always
// equal — the ledger builder derives the stored value from the digest — so a
// probe that changes only the entry goes red on the cheaper comparison and
// proves nothing about the recomputation. The deletion attack recorded in this
// round's self-review says so rather than counting it.
//
// This is the probe that isolates it: the RECORD's stored delta_id is tampered
// to agree with a tampered entry, so the two agree with each other and only the
// recomputation from the disagreement digest can refuse. That is the shape a
// hand-edited ledger document has, and it is the reason the rule is not
// redundant.
func TestTheRecomputedIdentityCatchesATamperedStoredDeltaID(t *testing.T) {
	records := committedChain(t)
	const forged = "delta-" +
		"beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
	tampered := make([]lab.BehaviorLedgerRecord, len(records))
	copy(tampered, records)
	tampered[6].Delta.DeltaID = forged

	root := legacyProbeRoot(t, func(file *LegacyAdjudicationsFile) {
		for index := range file.Adjudications {
			if file.Adjudications[index].Sequence == 7 {
				file.Adjudications[index].DeltaID = forged
			}
		}
	})
	err := VerifyLegacyAdjudications(root, tampered, Definitions())
	if err == nil {
		t.Fatal("the gate accepted an entry whose delta_id agrees with a TAMPERED stored delta_id but not with " +
			"the identity the record's own disagreement digest produces")
	}
	if !strings.Contains(err.Error(), "RECOMPUTED from the record's own disagreement digest") {
		t.Fatalf("the gate refused, but not on the recomputation.\ngot: %v", err)
	}
}

// TestAChainTooShortToAdjudicateIsRefusedRatherThanIndexedInto guards the one
// rule that returns early instead of collecting a problem. It is not a
// formality: reading records[PreVocabularySequence-1] on a shorter chain would
// panic, and a gate that panics is a gate whose result nobody reads.
func TestAChainTooShortToAdjudicateIsRefusedRatherThanIndexedInto(t *testing.T) {
	records := committedChain(t)
	root := legacyProbeRoot(t, nil)
	err := VerifyLegacyAdjudications(root, records[:10], Definitions())
	if err == nil {
		t.Fatal("the gate accepted a ten-record chain against a document adjudicating forty-nine records")
	}
	if !strings.Contains(err.Error(), "cannot be adjudicated") {
		t.Fatalf("the gate refused, but not on the chain length.\ngot: %v", err)
	}
}

// TestTheStoredComparisonCatchesARecordWhoseOwnDeltaIDDrifted is the mirror of
// the probe above, and it is recorded here with its limitation stated.
//
// The two delta_id comparisons are checked in opposite directions: this one
// tampers the RECORD's stored delta_id and leaves the entry agreeing with the
// identity recomputed from the disagreement digest, so the recomputation is
// satisfied and only the stored comparison can speak. It discriminates by
// MESSAGE, not by admission: because AC3ClassFor looks a record's class up by
// the delta_id the RECORD stores, a drifted stored value also makes that record
// count as unclassed, and the residual recomputation refuses the document too.
// The round-1 self-review records that reading rather than claiming this rule
// is the only thing standing between the chain and acceptance.
func TestTheStoredComparisonCatchesARecordWhoseOwnDeltaIDDrifted(t *testing.T) {
	records := committedChain(t)
	tampered := make([]lab.BehaviorLedgerRecord, len(records))
	copy(tampered, records)
	tampered[6].Delta.DeltaID = "delta-" +
		"cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe"

	root := legacyProbeRoot(t, nil)
	err := VerifyLegacyAdjudications(root, tampered, Definitions())
	if err == nil {
		t.Fatal("the gate accepted a chain whose record 7 stores a delta_id its own entry does not name")
	}
	if !strings.Contains(err.Error(), "; the record carries ") {
		t.Fatalf("the gate refused, but not on the stored comparison.\ngot: %v", err)
	}
}

// TestAnOtherwisePerfectEntryIsStillRefusedForAPostVocabularyRecord isolates the
// range rule, which the table probe above does not.
//
// That probe copies entry 1 and renumbers it, so the identity, digest, subject
// and quote all belong to the wrong record and four other rules would refuse it
// even with the range rule gone. This one BUILDS a valid entry for sequence 50
// out of record 50's own content — recomputed identity, its record digest, its
// subject, a ninety-byte verbatim quote of its rationale that appears in no
// other record, a subset of its RFC refs and its exact Java ref — so the only
// thing wrong with it is that record 50 can carry the field itself. That is
// what the rule is for: a side entry must never become a way to leave a new
// record's adjudication outside the hash chain.
func TestAnOtherwisePerfectEntryIsStillRefusedForAPostVocabularyRecord(t *testing.T) {
	records := committedChain(t)
	const sequence = PreVocabularySequence + 1
	record := records[sequence-1]
	if record.Sequence != sequence {
		t.Fatalf("record at index %d carries sequence %d", sequence-1, record.Sequence)
	}
	identity, err := lab.BehaviorDeltaID(record.Delta.DisagreementDigest)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if len(record.Delta.Rationale) < 90 {
		t.Fatalf("record %d's rationale is %d bytes", sequence, len(record.Delta.Rationale))
	}
	quote := record.Delta.Rationale[:90]
	for _, other := range records {
		if other.Sequence != sequence && strings.Contains(other.Delta.Rationale, quote) {
			t.Fatalf("the quote chosen for the probe is not unique to sequence %d; sequence %d shares it",
				sequence, other.Sequence)
		}
	}
	if record.Delta.MismatchClass == "" {
		t.Fatalf("record %d carries no mismatch_class, so it is not a post-vocabulary record", sequence)
	}

	root := legacyProbeRoot(t, func(file *LegacyAdjudicationsFile) {
		file.Adjudications = append(file.Adjudications, LegacyAdjudication{
			Sequence:       sequence,
			DeltaID:        identity,
			RecordDigest:   record.RecordDigest,
			SubjectRef:     record.Delta.SubjectRef,
			Examination:    ExaminationSettles,
			MismatchClass:  record.Delta.MismatchClass,
			CitedRFCRefs:   record.Delta.RFCRefs[:1],
			CitedJavaRef:   record.Delta.JavaRef,
			RationaleQuote: quote,
			Argument: "This entry is correct in every respect the document can check: its identity is " +
				"recomputed from the record's own disagreement digest, its record digest and subject are the " +
				"record's, and its quote is ninety verbatim bytes of that record's hashed rationale which no " +
				"other record carries. It is refused anyway, because the record it adjudicates can carry the " +
				"field itself and an adjudication that can be sealed into the chain must be.",
		})
	})
	err = VerifyLegacyAdjudications(root, records, Definitions())
	if err == nil {
		t.Fatal("the gate accepted an entry for a record that must carry mismatch_class in its own sealed delta")
	}
	if !strings.Contains(err.Error(), "outside 1..49") {
		t.Fatalf("the gate refused, but not on the range rule.\ngot: %v", err)
	}
	if strings.Count(err.Error(), "problem(s)") == 1 && strings.Contains(err.Error(), "1 problem(s)") {
		return
	}
	t.Fatalf("the probe was meant to leave exactly one problem, so the range rule is the only rule speaking.\n"+
		"got: %v", err)
}

// TestSequence13BareLFBasisIsContradictedBySequence39 re-verifies the FINDING's
// premise from the committed chain, so the finding cannot quietly become false.
//
// Both strings are inside their records' digest preimages. If either record is
// ever rewritten this fails, and if sequence 13 is superseded the entry that
// names the draft should be revisited — which is why this test names both
// sequences rather than asserting a fact about one.
func TestSequence13BareLFBasisIsContradictedBySequence39(t *testing.T) {
	definitions := Definitions()
	if len(definitions) < 39 {
		t.Fatalf("the definition list is %d long", len(definitions))
	}
	thirteen := definitions[12].RFCExpectation
	thirtyNine := definitions[38].RFCExpectation
	if !strings.Contains(thirteen, "forbids a bare LF as a line terminator") {
		t.Fatalf("sequence 13 no longer binds the refuted reading; the finding recorded in "+
			"evidence/java/legacy-record-adjudications.json and its draft must be revisited.\ngot: %s", thirteen)
	}
	if !strings.Contains(thirtyNine, "a recipient MAY recognize a single LF as a line terminator") {
		t.Fatalf("sequence 39 no longer quotes RFC 9112 section 2.2's MAY, which is the whole basis for classing "+
			"sequence 13 underspecified-behavior.\ngot: %s", thirtyNine)
	}
	if !strings.HasPrefix(definitions[38].RFCValue, "recipient-choice:") {
		t.Fatalf("sequence 39's rfc_value no longer opens recipient-choice: %s", definitions[38].RFCValue)
	}
	if !strings.HasPrefix(definitions[12].RFCValue, "reject:") {
		t.Fatalf("sequence 13's rfc_value no longer opens reject: %s", definitions[12].RFCValue)
	}
}

// TestTheSequence13CorrectionDraftReproducesItsOwnIdentity holds the drafted
// correction to the same standard VerifyProposalDraftsAreLedgered holds the
// seven landed drafts to: its declared delta_id must be a FUNCTION of the six
// digest preimages it carries, not a value typed beside them.
//
// It deliberately does NOT require the record to be in the chain. This branch
// appends nothing, and a draft is a proposal.
func TestTheSequence13CorrectionDraftReproducesItsOwnIdentity(t *testing.T) {
	const relative = "drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json"
	disagreement, declared, err := ReadProposalDraft(ledgerTestRepoRoot, relative)
	if err != nil {
		t.Fatalf("read draft: %v", err)
	}
	digest, err := disagreement.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	identity, err := lab.BehaviorDeltaID(digest)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if declared != identity {
		t.Fatalf("the draft declares delta_id %s; its own six preimages produce %s", declared, identity)
	}
	// And it must not already be in the chain — if it were, this branch would
	// have appended, which it must not.
	records := committedChain(t)
	for _, record := range records {
		if record.Delta.DeltaID == identity {
			t.Fatalf("the drafted correction is at sequence %d in the committed chain; this branch appends nothing",
				record.Sequence)
		}
	}
}
