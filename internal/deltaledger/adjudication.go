package deltaledger

// THE DISPOSITION VOCABULARY'S GATE.
//
// WHAT WAS WRONG. schemas/behavior-delta-ledger-1.1.0.schema.json admitted two
// dispositions, "unresolved" and "rfc-governs", and build.go assigned the
// literal "unresolved" to every record it built. So all forty-nine committed
// records read "unresolved" — not because forty-nine adjudications came out
// that way, but because no definition could say anything else. Meanwhile
// US-020 AC3 requires every mismatch to be recorded "as Java quirk, Rust defect,
// or underspecified behavior", three classes the vocabulary did not contain, so
// that classification had never been made for ANY record; and seven drafted
// records sat unappended in drafts/ledger-proposals/ precisely because the
// vocabulary could not say what they turn on — whether the port ADOPTS the
// divergence, CORRECTS it deliberately, or owes a fix.
//
// WHAT REPLACED IT is two independent axes, defined in internal/lab: the
// extended `disposition` (what the program does) and the new optional
// `mismatch_class` (where the mismatch originates). This file is the rule that
// stops the second one from becoming decorative.
//
// WHY THE CLASS IS OPTIONAL AND WHY THAT IS NOT A HOLE. A record's digest
// preimage is the canonical JSON of its whole delta. A required field, or a
// field with a non-empty default, would have changed every record's bytes and
// rewritten the hash chain from sequence 1 — breaking the frozen prefix at
// sequence 35 that protected/ledger-frozen-prefix-owner-decision-2026-08-28.json
// requires to stay byte-identical. `omitempty` on an absent field contributes
// no bytes, so the forty-nine keep their digests exactly. The cost is that
// those forty-nine carry no class, and the answer to that cost is not to
// pretend otherwise: VerifyAdjudication grandfathers them EXPLICITLY, by
// sequence AND by content they already carry in their own hashed rationale, and
// the ledger publishes the size of the residual as
// records_without_mismatch_class. That number can fall and cannot silently rise.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// PreVocabularySequence is the last record appended before the 1.2.0
// disposition vocabulary existed.
//
// It is a pin on the chain, in the same shape as FrozenPrefixSequence, and it
// is what makes the grandfathering FINITE. Records 1..49 were sealed with
// disposition "unresolved" and no mismatch class because nothing else could be
// written; every record after them is written under a vocabulary that can say
// what it means, so every record after them MUST carry a class. Raising this
// number would be granting a new record the exemption, which is why it is a
// constant with this comment attached rather than "len(records) at the time".
const PreVocabularySequence = 49

// retentionStatements are the exact sentences by which a PRE-VOCABULARY record
// states its adjudication in prose, inside its own hashed rationale.
//
// THESE ARE CONTENT, NOT NAMES. Each string is part of the digest preimage of
// every record that carries it: change one byte of one and that record's digest
// changes, the chain link breaks and VerifyFrozenPrefix fires. So matching on
// them binds what the record actually says, and it cannot be satisfied by a
// record merely being in some position or having some name.
//
// There are two because the forty-nine say it two ways. Forty-five carry the
// shared owner-decision citation appended by definitions.go; sequences 33, 34,
// 35 and 49 carry a bespoke DISPOSITION NOTE written for those records. Both
// wordings assert the same thing — that "unresolved" was the frozen
// vocabulary's only retained-divergence term and the divergence is deliberately
// RETAINED — and neither can be normalized now, because normalizing prose
// inside a sealed preimage is rewriting history.
var retentionStatements = []string{
	"disposition is 'unresolved' because the frozen 1.0.0 vocabulary has no java-faithful term — the " +
		"divergence is deliberately retained under JAVA_FAITHFUL_PLUS_SAFE, not resolved toward the RFC.",
	"'unresolved' is the frozen 1.0.0 vocabulary's only retained-divergence term",
}

// AssertsRetention reports whether a record's own hashed rationale carries one
// of the pre-vocabulary retention statements.
func AssertsRetention(delta lab.BehaviorDelta) bool {
	for _, statement := range retentionStatements {
		if strings.Contains(delta.Rationale, statement) {
			return true
		}
	}
	return false
}

// CountRecordsWithoutMismatchClass is the published residual: how many records
// in the chain make no US-020 AC3 attribution.
func CountRecordsWithoutMismatchClass(records []lab.BehaviorLedgerRecord) int {
	count := 0
	for _, record := range records {
		if record.Delta.MismatchClass == "" {
			count++
		}
	}
	return count
}

// VerifyAdjudication is the whole rule, and it is TOTAL: every record in the
// chain must say something machine-readable about its own adjudication, and the
// only records excused from saying it in a FIELD are the ones that predate the
// field and said it in their hashed prose.
//
// The rules, each of which can be made to fail on its own (see
// adjudication_test.go, which deletes each in turn):
//
//  1. VOCABULARY. Every disposition and every non-empty mismatch class is in
//     the closed vocabulary. (internal/lab.BehaviorDelta.Validate enforces this
//     on the append path too; it is repeated here so a chain read from disk,
//     rather than built, is also checked.)
//  2. NO NEW RECORD IS UNCLASSED. A record after PreVocabularySequence must
//     carry a mismatch class.
//  3. AN ADJUDICATED RECORD IS CLASSED. A record whose disposition is anything
//     other than "unresolved" must carry a mismatch class: deciding what to do
//     without saying where the mismatch came from is the half-answer AC3 exists
//     to refuse.
//  4. AN UNCLASSED RECORD MUST HAVE SAID SO IN ITS OWN BYTES. A record with no
//     class must carry a retention statement in its hashed rationale. This is
//     what stops rule 2's exemption from being a bare sequence-number amnesty:
//     the grandfathered records are grandfathered because of what they SAY.
//  5. NO CONTRADICTION. A record that asserts retention must not declare
//     "fix-in-port", "intentional-correction" or "rfc-governs", because all
//     three contradict the sentence it carries. Retention and adoption agree;
//     retention and a fix do not, and neither does retention and the RFC
//     governing — which is the contradiction the retention sentence spells out
//     in its own words, "not resolved toward the RFC". See
//     contradictsRetention.
//  6. THE GRANDFATHERED SET IS THE PRE-VOCABULARY SET, BOTH WAYS. Rule 2 says
//     an unclassed record is at or before PreVocabularySequence; rule 6 says a
//     record at or before it carries no class. Adding a class to one of those
//     records would mean its sealed digest preimage gained bytes, which the
//     frozen prefix and the legacy document's pre_vocabulary_head already
//     refuse; stating it here is what turns the published residual into a
//     consequence of the chain's sequences rather than a recount of the field.
//
// It also checks the published residual, and it does NOT do so by recomputing
// the same field the builder counted and comparing the answer with itself; see
// the residual block at the end of the function.
func VerifyAdjudication(records []lab.BehaviorLedgerRecord, publishedResidual int) error {
	var problems []string
	for _, record := range records {
		delta := record.Delta
		classed := delta.MismatchClass != ""

		// 1. VOCABULARY.
		if !vocabularyContains(delta.Disposition, lab.Dispositions()) {
			problems = append(problems, fmt.Sprintf(
				"sequence %d declares disposition %q, which is outside the vocabulary %v",
				record.Sequence, delta.Disposition, lab.Dispositions()))
		}
		if classed && !vocabularyContains(delta.MismatchClass, lab.MismatchClasses()) {
			problems = append(problems, fmt.Sprintf(
				"sequence %d declares mismatch class %q, which is outside the US-020 AC3 vocabulary %v",
				record.Sequence, delta.MismatchClass, lab.MismatchClasses()))
		}

		// 2. NO NEW RECORD IS UNCLASSED.
		if !classed && record.Sequence > PreVocabularySequence {
			problems = append(problems, fmt.Sprintf(
				"sequence %d carries no mismatch_class. Only records at or before sequence %d predate the 1.2.0 "+
					"vocabulary; every record appended after it must state, in US-020 AC3's terms, whether the "+
					"mismatch it binds originates in a Java quirk, a Rust defect, or underspecified behavior",
				record.Sequence, PreVocabularySequence))
		}

		// 3. AN ADJUDICATED RECORD IS CLASSED.
		if !classed && delta.Disposition != lab.DispositionUnresolved {
			problems = append(problems, fmt.Sprintf(
				"sequence %d declares disposition %q but carries no mismatch_class. A record that says what the "+
					"program DOES must also say where the mismatch CAME FROM; only %q may stand without an "+
					"attribution, and only on a pre-vocabulary record",
				record.Sequence, delta.Disposition, lab.DispositionUnresolved))
		}

		// 4. AN UNCLASSED RECORD MUST HAVE SAID SO IN ITS OWN BYTES.
		if !classed && !AssertsRetention(delta) {
			problems = append(problems, fmt.Sprintf(
				"sequence %d carries no mismatch_class and no retention statement in its hashed rationale, so "+
					"nothing in the record itself records an adjudication. A pre-vocabulary record is excused the "+
					"FIELD because its preimage cannot be altered, not excused the STATEMENT",
				record.Sequence))
		}

		// 5. NO CONTRADICTION.
		if AssertsRetention(delta) && contradictsRetention(delta.Disposition) {
			problems = append(problems, fmt.Sprintf(
				"sequence %d declares disposition %q while its hashed rationale states the divergence is "+
					"deliberately RETAINED. The field and the prose contradict each other, and the prose is inside "+
					"the digest preimage",
				record.Sequence, delta.Disposition))
		}

		// 6. THE GRANDFATHERED SET IS THE PRE-VOCABULARY SET, BOTH WAYS.
		if classed && record.Sequence <= PreVocabularySequence {
			problems = append(problems, fmt.Sprintf(
				"sequence %d is at or before the pre-vocabulary sequence %d but carries mismatch_class %q. A "+
					"record sealed before the field existed cannot have gained it without its digest preimage "+
					"gaining bytes, so either the chain was rewritten or the boundary constant moved",
				record.Sequence, PreVocabularySequence, delta.MismatchClass))
		}
	}

	// THE PUBLISHED RESIDUAL, CHECKED AGAINST SOMETHING THAT IS NOT ITSELF.
	//
	// FOUND BY EXECUTION IN ADVERSARIAL ROUND 5, AND STATED CAREFULLY, BECAUSE
	// THE FIRST COMPARISON BELOW IS NOT DEAD AND MUST NOT BE DESCRIBED AS IF IT
	// WERE. It catches a document whose integer was edited by hand: run over
	// such a document, VerifyIntegrity refuses it naming this recount, which
	// was verified by doing it. Inside cmd/deltaledgerctl --check the refusal
	// arrives one step earlier, from the regeneration comparison, so the hand
	// edit never reaches this line — also verified, by editing the integer and
	// reading which message fired.
	//
	// What neither of those catches is a BROKEN COUNTER PLUS A REGENERATION.
	// BuildLedgerFileFrom writes the residual as
	// CountRecordsWithoutMismatchClass(records), and the first comparison below
	// recomputes it with that same function over those same records, so the two
	// sides agree with each other by construction whatever the function does.
	// Disabling the counter's body with `false &&` and regenerating made
	// `deltaledgerctl --root .` publish records_without_mismatch_class = 0 over
	// a chain where forty-nine records carry no class, left the record chain
	// head byte-identical because the counter is envelope and not preimage, and
	// left `--check` at exit 0 printing "records_without_mismatch_class
	// recomputed = 0". The word in that line that was not true is "recomputed".
	//
	// The second comparison is the fix, and it is a DERIVATION rather than a
	// recount: rules 2, 3 and 4 already prove that an unclassed record is at or
	// before PreVocabularySequence, rule 6 proves the converse, and the two
	// together make the residual a function of the SEQUENCES in the chain. A
	// sequence is assigned by lab.AppendBehaviorDelta from the record's
	// position, the prefix through 35 is pinned by VerifyFrozenPrefix and the
	// prefix through PreVocabularySequence by the legacy document's
	// pre_vocabulary_head, so this count cannot be moved by editing a field.
	// TestTheCommittedChainIsAdjudicated asserted exactly this and only in the
	// test binary; go-suite runs it and ledger-gates did not.
	residual := CountRecordsWithoutMismatchClass(records)
	if residual != publishedResidual {
		problems = append(problems, fmt.Sprintf(
			"the ledger publishes records_without_mismatch_class=%d but %d of the %d records carry no class",
			publishedResidual, residual, len(records)))
	}
	grandfathered := 0
	for _, record := range records {
		if record.Sequence <= PreVocabularySequence {
			grandfathered++
		}
	}
	if publishedResidual != grandfathered {
		problems = append(problems, fmt.Sprintf(
			"the ledger publishes records_without_mismatch_class=%d, but %d of the %d records are at or before "+
				"the pre-vocabulary sequence %d and every one of those carries no class while every record after "+
				"them carries one. The residual is a consequence of the chain's SEQUENCES, not a number to be "+
				"counted out of the same field the builder counted and compared with itself",
			publishedResidual, grandfathered, len(records), PreVocabularySequence))
	}

	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("adjudication (%d problem(s)):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// contradictsRetention reports whether a disposition says the opposite of the
// retention statements in retentionStatements.
//
// THE THIRD TERM IS THE ONE ROUND 5 FOUND MISSING. "fix-in-port" and
// "intentional-correction" were here from the start. "rfc-governs" was not, and
// it is the disposition the retention sentence rules out BY NAME: the sentence
// reads "the divergence is deliberately retained under JAVA_FAITHFUL_PLUS_SAFE,
// not resolved toward the RFC", and lab.DispositionRFCGoverns means "the RFC's
// requirement governs and the port follows the RFC rather than Java". With the
// term absent, ledger sequence 59 was made to declare rfc-governs while its own
// hashed rationale said the divergence is retained, and `make -C rust
// ledger-gates` exited 0 with every published counter unchanged; the same
// record declaring fix-in-port was refused. "unresolved" and "adopt-java" are
// the two dispositions retention AGREES with and neither is listed.
func contradictsRetention(disposition string) bool {
	switch disposition {
	case lab.DispositionFixInPort, lab.DispositionIntentionalCorrection, lab.DispositionRFCGoverns:
		return true
	}
	return false
}

func vocabularyContains(value string, vocabulary []string) bool {
	for _, term := range vocabulary {
		if value == term {
			return true
		}
	}
	return false
}
