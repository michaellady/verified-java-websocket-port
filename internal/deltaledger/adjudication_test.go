package deltaledger

// POLARITY FOR THE 1.2.0 DISPOSITION VOCABULARY.
//
// Every test here fails the check it names by CONSTRUCTING the violation and
// running the SAME exported function the gate runs, never a reimplementation.
// The corresponding deletion attacks — removing each rule from adjudication.go
// and proving something goes red — are recorded in
// drafts/self-review/ledger-disposition-round-1.md.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// buildRecord materializes one definition into a record at a chosen sequence,
// through the production builder, so a probe cannot accidentally construct a
// delta the real path would have refused.
func buildRecord(t *testing.T, sequence uint64, definition Definition) lab.BehaviorLedgerRecord {
	t.Helper()
	deltas, err := buildDeltasFrom([]Definition{definition})
	if err != nil {
		t.Fatalf("buildDeltasFrom: %v", err)
	}
	return lab.BehaviorLedgerRecord{
		SchemaVersion:  "1.0.0",
		Sequence:       sequence,
		PreviousDigest: lab.GenesisLedgerHead,
		Delta:          deltas[0],
	}
}

// probeDefinition is a minimal well-formed definition; the fields the probes
// vary are set by each caller.
func probeDefinition() Definition {
	return Definition{
		Subject:         "org.java-websocket.probe.adjudication",
		RFCRefs:         []string{"rfc6455#section-5.5.1"},
		RFCExpectation:  "the RFC expects one thing",
		RFCValue:        "rfc-value",
		JavaRef:         "org.java_websocket.WebSocketImpl:close",
		JavaObservation: "shipped Java does another",
		JavaValue:       "java-value",
		AutobahnRefs:    []string{"autobahn-v25.10.1:7.1.1"},
		Rationale:       "a probe rationale with no retention statement in it.",
	}
}

// retentionRationale is a probe rationale that carries one of the two
// pre-vocabulary retention statements verbatim.
func retentionRationale() string {
	return "a probe rationale that also says: " + retentionStatements[0]
}

func TestVerifyAdjudicationRefusesEachWayARecordCanSayNothing(t *testing.T) {
	t.Run("a record after the pre-vocabulary sequence with no class", func(t *testing.T) {
		definition := probeDefinition()
		// It carries a retention statement, so ONLY the sequence rule can
		// refuse it. Without rule 2 this record would pass.
		definition.Rationale = retentionRationale()
		record := buildRecord(t, PreVocabularySequence+1, definition)
		err := VerifyAdjudication([]lab.BehaviorLedgerRecord{record}, 1)
		if err == nil {
			t.Fatal("a record appended AFTER the vocabulary existed carried no mismatch_class and was accepted")
		}
		if !strings.Contains(err.Error(), "carries no mismatch_class. Only records at or before sequence") {
			t.Fatalf("refused, but not on the pre-vocabulary boundary: %v", err)
		}
	})

	t.Run("an adjudicated record with no class", func(t *testing.T) {
		definition := probeDefinition()
		definition.Disposition = lab.DispositionAdoptJava
		// Pre-vocabulary sequence AND a retention statement, so rules 2 and 4
		// are both satisfied and only rule 3 can refuse it.
		definition.Rationale = retentionRationale()
		record := buildRecord(t, 1, definition)
		err := VerifyAdjudication([]lab.BehaviorLedgerRecord{record}, 1)
		if err == nil {
			t.Fatal("a record that says what the program DOES was accepted without saying where the mismatch " +
				"came from")
		}
		if !strings.Contains(err.Error(), "must also say where the mismatch CAME FROM") {
			t.Fatalf("refused, but not on the adjudicated-implies-classed rule: %v", err)
		}
	})

	t.Run("an unclassed pre-vocabulary record that never states retention", func(t *testing.T) {
		definition := probeDefinition() // rationale carries no retention statement
		record := buildRecord(t, 1, definition)
		err := VerifyAdjudication([]lab.BehaviorLedgerRecord{record}, 1)
		if err == nil {
			t.Fatal("an unclassed record whose own hashed bytes record no adjudication was accepted. The " +
				"grandfathering must rest on what a record SAYS, not on its sequence alone")
		}
		if !strings.Contains(err.Error(), "no retention statement in its hashed rationale") {
			t.Fatalf("refused, but not on the missing retention statement: %v", err)
		}
	})

	t.Run("a record whose field contradicts its own hashed prose", func(t *testing.T) {
		definition := probeDefinition()
		definition.Disposition = lab.DispositionFixInPort
		definition.MismatchClass = lab.MismatchRustDefect
		definition.Rationale = retentionRationale()
		record := buildRecord(t, 1, definition)
		err := VerifyAdjudication([]lab.BehaviorLedgerRecord{record}, 0)
		if err == nil {
			t.Fatal("a record declaring fix-in-port while its hashed rationale says the divergence is " +
				"deliberately RETAINED was accepted")
		}
		if !strings.Contains(err.Error(), "contradict each other") {
			t.Fatalf("refused, but not on the contradiction: %v", err)
		}
	})

	t.Run("a record declaring rfc-governs while its prose says the divergence is retained", func(t *testing.T) {
		// ROUND 5. Rule 5 listed "fix-in-port" and "intentional-correction"
		// and not "rfc-governs", which is the disposition the retention
		// sentence excludes by name — "not resolved toward the RFC". The whole
		// tree passed `deltaledgerctl --check` at exit 0 with ledger sequence
		// 59 in exactly this state, every published counter unchanged.
		definition := probeDefinition()
		definition.Disposition = lab.DispositionRFCGoverns
		definition.MismatchClass = lab.MismatchJavaQuirk
		definition.Rationale = retentionRationale()
		record := buildRecord(t, 1, definition)
		err := VerifyAdjudication([]lab.BehaviorLedgerRecord{record}, 0)
		if err == nil {
			t.Fatal("a record declaring rfc-governs while its hashed rationale says the divergence is " +
				"deliberately RETAINED, and NOT resolved toward the RFC, was accepted")
		}
		if !strings.Contains(err.Error(), "contradict each other") {
			t.Fatalf("refused, but not on the contradiction: %v", err)
		}
		if !strings.Contains(err.Error(), string(lab.DispositionRFCGoverns)) {
			t.Fatalf("refused without naming the disposition it refused: %v", err)
		}
	})

	t.Run("a pre-vocabulary record that carries a class", func(t *testing.T) {
		// Rule 6, the converse of rule 2. It is what makes the residual a
		// function of the chain's sequences.
		definition := probeDefinition()
		definition.MismatchClass = lab.MismatchJavaQuirk
		record := buildRecord(t, PreVocabularySequence, definition)
		err := VerifyAdjudication([]lab.BehaviorLedgerRecord{record}, 1)
		if err == nil {
			t.Fatal("a record sealed before the mismatch_class field existed carried one and was accepted")
		}
		if !strings.Contains(err.Error(), "is at or before the pre-vocabulary sequence") {
			t.Fatalf("refused, but not on the grandfathered-set boundary: %v", err)
		}
	})

	t.Run("a residual that agrees with a broken recount", func(t *testing.T) {
		// ROUND 5, THE OTHER HALF. The residual used to be checked ONLY by
		// recounting the same field the builder counted, so the two could only
		// ever agree: disabling the body of CountRecordsWithoutMismatchClass
		// made `deltaledgerctl --root .` publish
		// records_without_mismatch_class = 0 over a chain with forty-nine
		// unclassed records, left the chain head byte-identical, and left
		// --check at exit 0. Here the published number and the recount agree at
		// zero and the SEQUENCES say otherwise.
		grandfathered := probeDefinition()
		grandfathered.Rationale = retentionRationale()
		classed := probeDefinition()
		classed.Subject = "org.java-websocket.probe.adjudication-two"
		classed.Disposition = lab.DispositionAdoptJava
		classed.MismatchClass = lab.MismatchJavaQuirk
		records := []lab.BehaviorLedgerRecord{
			buildRecord(t, 1, grandfathered),
			buildRecord(t, PreVocabularySequence+1, classed),
		}
		// One record is at or before the boundary, so the honest residual is 1.
		err := VerifyAdjudication(records, 0)
		if err == nil {
			t.Fatal("a published residual of zero was accepted over a chain with a pre-vocabulary record in it")
		}
		if !strings.Contains(err.Error(), "The residual is a consequence of the chain's SEQUENCES") {
			t.Fatalf("refused, but not on the sequence-derived residual: %v", err)
		}
	})

	t.Run("a published residual that understates the chain", func(t *testing.T) {
		definition := probeDefinition()
		definition.Rationale = retentionRationale()
		record := buildRecord(t, 1, definition)
		// One unclassed record, published as zero.
		err := VerifyAdjudication([]lab.BehaviorLedgerRecord{record}, 0)
		if err == nil {
			t.Fatal("the ledger published records_without_mismatch_class=0 over a chain with an unclassed " +
				"record and was accepted; the residual would then be a number nobody checks")
		}
		if !strings.Contains(err.Error(), "records_without_mismatch_class=0 but 1 of the 1 records carry no class") {
			t.Fatalf("refused, but not on the residual recomputation: %v", err)
		}
	})

	t.Run("the well-formed shapes are accepted", func(t *testing.T) {
		// Otherwise every probe above would pass for the wrong reason.
		classed := probeDefinition()
		classed.Disposition = lab.DispositionIntentionalCorrection
		classed.MismatchClass = lab.MismatchUnderspecified
		grandfathered := probeDefinition()
		grandfathered.Subject = "org.java-websocket.probe.adjudication-two"
		grandfathered.Rationale = retentionRationale()
		records := []lab.BehaviorLedgerRecord{
			buildRecord(t, 1, grandfathered),
			buildRecord(t, PreVocabularySequence+1, classed),
		}
		if err := VerifyAdjudication(records, 1); err != nil {
			t.Fatalf("a grandfathered record and a fully adjudicated one must both pass: %v", err)
		}
	})
}

// TestTheDeltaVocabularyIsClosed pins the internal/lab half. Without it a
// disposition or class outside the vocabulary would reach the chain and only
// the JSON schema would object, on the document rather than on the append.
func TestTheDeltaVocabularyIsClosed(t *testing.T) {
	for _, probe := range []struct {
		name          string
		disposition   string
		mismatchClass string
		want          string
	}{
		{"an invented disposition", "java-faithful", lab.MismatchJavaQuirk, "$.disposition"},
		{"an invented mismatch class", lab.DispositionAdoptJava, "port-quirk", "$.mismatch_class"},
		{"the foundation schema's spelling, which is NOT this vocabulary", "PRESERVE", "", "$.disposition"},
	} {
		t.Run(probe.name, func(t *testing.T) {
			definition := probeDefinition()
			definition.Disposition = probe.disposition
			definition.MismatchClass = probe.mismatchClass
			_, err := buildDeltasFrom([]Definition{definition})
			if err == nil {
				t.Fatalf("%q / %q was accepted into a delta", probe.disposition, probe.mismatchClass)
			}
			if !strings.Contains(err.Error(), probe.want) {
				t.Fatalf("refused, but not at %s: %v", probe.want, err)
			}
		})
	}
}

// TestTheCommittedChainIsAdjudicated runs the gate's own function over the
// committed document, and pins the two facts a reader of the audit finding
// needs: the residual is exactly the pre-vocabulary records, and every record
// after them carries a class.
func TestTheCommittedChainIsAdjudicated(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read the committed ledger: %v", err)
	}
	if err := VerifyAdjudication(committed.Records, committed.RecordsWithoutMismatchClass); err != nil {
		t.Fatalf("the committed chain: %v", err)
	}
	if committed.RecordsWithoutMismatchClass != PreVocabularySequence {
		t.Fatalf("records_without_mismatch_class = %d, want %d: the residual is exactly the records sealed before "+
			"the vocabulary existed, and a different number means either a pre-vocabulary record was rewritten or a "+
			"new record was appended without an attribution",
			committed.RecordsWithoutMismatchClass, PreVocabularySequence)
	}
	for _, record := range committed.Records {
		if record.Sequence <= PreVocabularySequence {
			if record.Delta.MismatchClass != "" {
				t.Fatalf("sequence %d is pre-vocabulary but carries a class, so its digest preimage moved",
					record.Sequence)
			}
			continue
		}
		if record.Delta.MismatchClass == "" {
			t.Fatalf("sequence %d carries no mismatch_class", record.Sequence)
		}
	}
}

// TestTheSevenAppendedRecordsCarryTheAdjudicationsTheyArgue binds each of the
// seven to its EXACT pair, by delta identity rather than by name or by count.
// A count would pass if two records swapped adjudications.
func TestTheSevenAppendedRecordsCarryTheAdjudicationsTheyArgue(t *testing.T) {
	want := map[string][2]string{
		"delta-516914f1e75aaf2c86bd082772a98b204ee217f86b54cecca648826688e40b82": {
			lab.DispositionAdoptJava, lab.MismatchJavaQuirk},
		"delta-6505983eb4eea7cd99d6d9ff497da1c95e8a5e2c490824504216625cf510d163": {
			lab.DispositionFixInPort, lab.MismatchRustDefect},
		"delta-fd4695dfb08c42f2fd9797a1bee4232305059db86f5c4e93ffc0414601916567": {
			lab.DispositionFixInPort, lab.MismatchRustDefect},
		"delta-7677db91f7b6267d3614468f70abebcb7c119d539297cd58c697e9bc7b7b8dfa": {
			lab.DispositionUnresolved, lab.MismatchJavaQuirk},
		"delta-02e2846c025deec4fd7e279956a7b997c6cab42aa57d0e91df2acb4107c4afb8": {
			lab.DispositionFixInPort, lab.MismatchRustDefect},
		"delta-34db0ad7c9378f88a8b9ddd66d76f9d7323c46a13e89ca04bfac51ea6f273830": {
			lab.DispositionUnresolved, lab.MismatchUnderspecified},
		"delta-64f32dd26e5b0a555b8a69def312ac8305b2579c4a488b91bd35a021cc898674": {
			lab.DispositionIntentionalCorrection, lab.MismatchUnderspecified},
	}
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read the committed ledger: %v", err)
	}
	seen := map[string]bool{}
	for _, record := range committed.Records {
		pair, expected := want[record.Delta.DeltaID]
		if !expected {
			continue
		}
		seen[record.Delta.DeltaID] = true
		got := [2]string{record.Delta.Disposition, record.Delta.MismatchClass}
		if got != pair {
			t.Fatalf("sequence %d (%s) carries %v, the record argues %v",
				record.Sequence, record.Delta.SubjectRef, got, pair)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("%d of the %d drafted deltas are in the chain", len(seen), len(want))
	}
	// All three AC3 classes and three of the five dispositions are in USE. A
	// vocabulary term nothing uses is a term nobody has had to defend.
	usedClasses := map[string]bool{}
	usedDispositions := map[string]bool{}
	for _, pair := range want {
		usedDispositions[pair[0]] = true
		usedClasses[pair[1]] = true
	}
	for _, class := range lab.MismatchClasses() {
		if !usedClasses[class] {
			t.Fatalf("no appended record uses the mismatch class %q", class)
		}
	}
	for _, disposition := range []string{lab.DispositionAdoptJava, lab.DispositionFixInPort,
		lab.DispositionIntentionalCorrection} {
		if !usedDispositions[disposition] {
			t.Fatalf("the vocabulary added %q and no appended record uses it", disposition)
		}
	}
}

func TestVerifyProposalDraftsAreLedgeredBindsContentNotNames(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read the committed ledger: %v", err)
	}
	if err := VerifyProposalDraftsAreLedgered(ledgerTestRepoRoot, committed.Records); err != nil {
		t.Fatalf("the committed drafts and chain must agree: %v", err)
	}

	t.Run("one edited byte of one draft preimage", func(t *testing.T) {
		root := mirrorDraftsForProbe(t)
		relative := "drafts/ledger-proposals/divergence-sweep-1.json"
		path := filepath.Join(root, filepath.FromSlash(relative))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read the mirrored draft: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode: %v", err)
		}
		preimages := document["digest_preimages"].(map[string]any)
		// One character. The subject, the delta_id and every reference are
		// untouched, so nothing that binds by NAME can notice this.
		preimages["java_value_digest"] = preimages["java_value_digest"].(string) + "."
		edited, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := os.WriteFile(path, edited, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		err = VerifyProposalDraftsAreLedgered(root, committed.Records)
		if err == nil {
			t.Fatal("a draft whose digest preimage was edited still 'agreed' with its ledger record. The binding " +
				"is then by name, which is the failure this check exists to refuse")
		}
		if !strings.Contains(err.Error(), "declares delta_id") {
			t.Fatalf("refused, but not on the recomputed identity: %v", err)
		}
	})

	t.Run("a drafted record missing from the chain", func(t *testing.T) {
		var withoutOne []lab.BehaviorLedgerRecord
		for _, record := range committed.Records {
			if record.Delta.DeltaID == "delta-64f32dd26e5b0a555b8a69def312ac8305b2579c4a488b91bd35a021cc898674" {
				continue
			}
			withoutOne = append(withoutOne, record)
		}
		err := VerifyProposalDraftsAreLedgered(ledgerTestRepoRoot, withoutOne)
		if err == nil {
			t.Fatal("a held draft with no record in the chain was accepted as landed")
		}
		if !strings.Contains(err.Error(), "which no record in the committed chain carries") {
			t.Fatalf("refused, but not on the missing record: %v", err)
		}
	})

	t.Run("a landed draft whose record makes no attribution", func(t *testing.T) {
		stripped := make([]lab.BehaviorLedgerRecord, len(committed.Records))
		copy(stripped, committed.Records)
		for index := range stripped {
			if stripped[index].Delta.DeltaID == "delta-516914f1e75aaf2c86bd082772a98b204ee217f86b54cecca648826688e40b82" {
				stripped[index].Delta.MismatchClass = ""
			}
		}
		err := VerifyProposalDraftsAreLedgered(ledgerTestRepoRoot, stripped)
		if err == nil {
			t.Fatal("a record that came from a draft held FOR WANT OF THE VOCABULARY was accepted without using it")
		}
		if !strings.Contains(err.Error(), "carries no mismatch_class") {
			t.Fatalf("refused, but not on the missing attribution: %v", err)
		}
	})

	t.Run("a draft with nothing to recompute", func(t *testing.T) {
		root := mirrorDraftsForProbe(t)
		path := filepath.Join(root, filepath.FromSlash("drafts/ledger-proposals/server-close-parity.json"))
		if err := os.WriteFile(path, []byte(`{"proposed_record":{"delta":{"delta_id":"delta-`+
			strings.Repeat("0", 64)+`"}}}`), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		err := VerifyProposalDraftsAreLedgered(root, committed.Records)
		if err == nil {
			t.Fatal("a draft carrying no preimages at all was accepted; a draft this check cannot rebuild " +
				"proves nothing about the record beside it")
		}
		if !strings.Contains(err.Error(), "carries neither a digest_preimages block nor a proposed_definition") {
			t.Fatalf("refused, but not on the unrebuildable draft: %v", err)
		}
	})
}

// mirrorDraftsForProbe copies the WHOLE drafts/ledger-proposals/ directory into
// a scratch root so a probe never edits the repository.
//
// It used to copy the seven paths the hardcoded list named, which would now be a
// probe against a different population than the one the rule derives: the four
// unlisted files decide three classifications and one exemption between them,
// and a mirror missing them would make every probe below pass for the wrong
// reason.
func mirrorDraftsForProbe(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(ProposalDraftsDir)), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(ProposalDraftsDir)))
	if err != nil {
		t.Fatalf("read the draft directory: %v", err)
	}
	copied := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		relative := ProposalDraftsDir + "/" + entry.Name()
		raw, err := os.ReadFile(filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(relative)), raw, 0o644); err != nil {
			t.Fatalf("write %s: %v", relative, err)
		}
		copied++
	}
	if copied == 0 {
		t.Fatal("mirrored no drafts at all, so every probe built on this root would pass over an empty population")
	}
	return root
}

// TestTheFrozenPrefixAndTheWholePreVocabularyTailSurvivedTheFieldAddition is
// the one that would have caught a REQUIRED mismatch_class. Adding a field to
// the delta struct changes every record's digest preimage unless the field is
// omitted when empty, and the frozen-prefix check alone would only have caught
// it for records 1-35.
func TestTheFrozenPrefixAndTheWholePreVocabularyTailSurvivedTheFieldAddition(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read the committed ledger: %v", err)
	}
	if err := VerifyFrozenPrefix(committed.Records); err != nil {
		t.Fatalf("frozen prefix: %v", err)
	}
	// The record digest at sequence 49 is the head the chain had BEFORE this
	// landing, so pinning it pins every byte of records 1-49 through the hash
	// links, exactly as FrozenPrefixHead pins 1-35.
	const headBeforeThisLanding = "sha256:eaa6eac8795ec8f6083e945ff8d6ec1778b37dd099c8acfaa6d4da36f1c01bbc"
	if len(committed.Records) < PreVocabularySequence {
		t.Fatalf("the chain has %d records", len(committed.Records))
	}
	last := committed.Records[PreVocabularySequence-1]
	if last.Sequence != PreVocabularySequence || last.RecordDigest != headBeforeThisLanding {
		t.Fatalf("sequence %d now digests to %s, but the chain's head before this landing was %s. Adding "+
			"mismatch_class to the delta must contribute ZERO preimage bytes to a record that does not carry one",
			last.Sequence, last.RecordDigest, headBeforeThisLanding)
	}
	if committed.Records[PreVocabularySequence-1].Delta.MismatchClass != "" {
		t.Fatal("the last pre-vocabulary record carries a class")
	}
}

// TestTheHeldDraftPopulationIsDerivedAndItsExemptionIsRECHECKED is the polarity
// suite for the 2026-09-04 correction under OA-held-draft-legacy-13.
//
// Two things are proved here and they are different things. The first is that
// the population is really the DIRECTORY: the rule now sees eleven files, holds
// eight of them to the full binding, and names the other three by the kind they
// declare. The second is that the one declared exemption is an EXEMPTION and
// not a bypass -- every arm of its staleness check is fired below, and the arm
// that matters most is the last one: an exemption does not excuse the draft from
// rebuilding its own identity, only from being in the chain.
//
// The list this replaced could not have failed any of these. That is the point.
func TestTheHeldDraftPopulationIsDerivedAndItsExemptionIsRECHECKED(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read the committed ledger: %v", err)
	}

	t.Run("the derivation sees every file in the directory", func(t *testing.T) {
		census, err := ClassifyProposalDrafts(ledgerTestRepoRoot)
		if err != nil {
			t.Fatalf("classify: %v", err)
		}
		entries, err := os.ReadDir(filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(ProposalDraftsDir)))
		if err != nil {
			t.Fatalf("read the directory: %v", err)
		}
		onDisk := 0
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
				onDisk++
			}
		}
		// The population is the directory or it is a list again. Comparing
		// against a recount of the directory rather than against the number 11
		// is deliberate: a hardcoded 11 is the same defect one size larger.
		if len(census.Files) != onDisk {
			t.Fatalf("the derivation classified %d file(s) and the directory holds %d .json file(s); a population "+
				"that is not the directory is a list", len(census.Files), onDisk)
		}
		for _, file := range census.Files {
			if file.Problem != "" {
				t.Fatalf("%s: %s", file.Relative, file.Problem)
			}
			if !file.RecordProposal && file.Why == "" {
				t.Fatalf("%s is out of the population with no reason stated", file.Relative)
			}
		}
		if len(census.Proposals()) < len(heldDraftExemptions)+1 {
			t.Fatalf("derived %d record proposal(s), which cannot both carry the exemptions and check anything",
				len(census.Proposals()))
		}
	})

	t.Run("removing the exemption fails the draft it excuses", func(t *testing.T) {
		defer restoreHeldDraftExemptions(t)()
		heldDraftExemptions = nil
		err := VerifyProposalDraftsAreLedgered(ledgerTestRepoRoot, committed.Records)
		if err == nil {
			t.Fatal("with no exemption declared, the unledgered draft was still accepted, so the derivation is " +
				"not reaching it and the exemption is decorative")
		}
		if !strings.Contains(err.Error(), "legacy-13-bare-lf-server-basis-correction.json") ||
			!strings.Contains(err.Error(), "which no record in the committed chain carries") {
			t.Fatalf("refused, but not on the draft the exemption is about: %v", err)
		}
	})

	t.Run("an exemption whose draft IS in the chain is stale", func(t *testing.T) {
		defer restoreHeldDraftExemptions(t)()
		// server-close-parity is genuinely ledgered, so an exemption for it
		// excuses a finding that no longer exists. This is the shape a real
		// stale entry takes: the owner appends the record and nobody deletes
		// the acknowledgement.
		heldDraftExemptions = []HeldDraftExemption{{
			Relative:        "drafts/ledger-proposals/server-close-parity.json",
			DeclaredDeltaID: "delta-516914f1e75aaf2c86bd082772a98b204ee217f86b54cecca648826688e40b82",
			Owner:           "probe",
		}}
		err := VerifyProposalDraftsAreLedgered(ledgerTestRepoRoot, committed.Records)
		if err == nil {
			t.Fatal("an exemption for a draft the chain already carries was accepted; an exemption nothing " +
				"re-checks is a bypass")
		}
		if !strings.Contains(err.Error(), "STALE_EXEMPTION") ||
			!strings.Contains(err.Error(), "The acknowledgement outlived the finding and must be deleted") {
			t.Fatalf("refused, but not as a stale exemption: %v", err)
		}
	})

	t.Run("an exemption whose pinned identity moved is stale", func(t *testing.T) {
		defer restoreHeldDraftExemptions(t)()
		moved := heldDraftExemptions[0]
		moved.DeclaredDeltaID = strings.TrimSuffix(moved.DeclaredDeltaID, "6") + "7"
		heldDraftExemptions = []HeldDraftExemption{moved}
		err := VerifyProposalDraftsAreLedgered(ledgerTestRepoRoot, committed.Records)
		if err == nil {
			t.Fatal("an exemption pinning an identity the draft does not declare was accepted, so the draft " +
				"could be edited under its own exemption")
		}
		if !strings.Contains(err.Error(), "The draft was edited under its own exemption") {
			t.Fatalf("refused, but not on the moved pin: %v", err)
		}
	})

	t.Run("an exemption naming a file the derivation does not see is stale", func(t *testing.T) {
		defer restoreHeldDraftExemptions(t)()
		heldDraftExemptions = []HeldDraftExemption{{
			Relative:        ProposalDraftsDir + "/a-draft-that-was-deleted.json",
			DeclaredDeltaID: "delta-" + strings.Repeat("0", 64),
			Owner:           "probe",
		}}
		err := VerifyProposalDraftsAreLedgered(ledgerTestRepoRoot, committed.Records)
		if err == nil {
			t.Fatal("an exemption for a file that does not exist was accepted, so it would exempt whatever " +
				"next took that path")
		}
		if !strings.Contains(err.Error(), "does not see at all") {
			t.Fatalf("refused, but not on the vanished subject: %v", err)
		}
	})

	t.Run("an exemption for a file that stopped being a record proposal is stale", func(t *testing.T) {
		defer restoreHeldDraftExemptions(t)()
		root := mirrorDraftsForProbe(t)
		// Gutted into a declared NON-proposal: the escape route an exemption
		// must not survive, because the file it was written about is gone in
		// every sense but the name.
		path := filepath.Join(root, filepath.FromSlash(heldDraftExemptions[0].Relative))
		if err := os.WriteFile(path, []byte(`{"draft_kind":"divergence-closure-record"}`), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		err := VerifyProposalDraftsAreLedgered(root, committed.Records)
		if err == nil {
			t.Fatal("an exemption survived its subject being rewritten into something else entirely")
		}
		if !strings.Contains(err.Error(), "no longer classifies this file as one") {
			t.Fatalf("refused, but not on the changed classification: %v", err)
		}
	})

	t.Run("the exemption does not excuse the draft from rebuilding its own identity", func(t *testing.T) {
		root := mirrorDraftsForProbe(t)
		relative := heldDraftExemptions[0].Relative
		path := filepath.Join(root, filepath.FromSlash(relative))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read the mirrored draft: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode: %v", err)
		}
		preimages := document["digest_preimages"].(map[string]any)
		preimages["java_value_digest"] = preimages["java_value_digest"].(string) + "."
		edited, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := os.WriteFile(path, edited, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		// THE HALF THE EXEMPTION MUST NOT REACH. The draft is exempt from being
		// in the chain. It is not exempt from being evidence.
		err = VerifyProposalDraftsAreLedgered(root, committed.Records)
		if err == nil {
			t.Fatal("an exempted draft whose preimages no longer produce its declared identity was accepted; the " +
				"exemption is then excusing the recomputation, which is the whole binding")
		}
		if !strings.Contains(err.Error(), "declares delta_id") {
			t.Fatalf("refused, but not on the recomputed identity: %v", err)
		}
	})

	t.Run("a file that declares no kind this rule classifies fails", func(t *testing.T) {
		root := mirrorDraftsForProbe(t)
		path := filepath.Join(root, filepath.FromSlash(ProposalDraftsDir+"/unclassified.json"))
		if err := os.WriteFile(path, []byte(`{"note":"not a kind anyone declared"}`), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		err := VerifyProposalDraftsAreLedgered(root, committed.Records)
		if err == nil {
			t.Fatal("a file in the draft directory that is neither a record proposal nor a declared non-proposal " +
				"was silently ignored, which is how the four unlisted drafts escaped the list")
		}
		if !strings.Contains(err.Error(), "declares no kind this rule classifies") {
			t.Fatalf("refused, but not on the unclassified file: %v", err)
		}
	})

	t.Run("an empty population is not a pass", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(ProposalDraftsDir)), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		err := VerifyProposalDraftsAreLedgered(root, committed.Records)
		if err == nil {
			t.Fatal("a derivation over an empty directory reported agreement; a derived population that can be " +
				"emptied buys silence the hardcoded list could not")
		}
		if !strings.Contains(err.Error(), "contains no record proposal at all") {
			t.Fatalf("refused, but not on the empty population: %v", err)
		}
	})
}

// restoreHeldDraftExemptions saves the declared table and returns the restore.
// The probes swap a package-level var, so a probe that forgot to put it back
// would leave every later test running against a table nobody declared.
func restoreHeldDraftExemptions(t *testing.T) func() {
	t.Helper()
	saved := append([]HeldDraftExemption(nil), heldDraftExemptions...)
	return func() { heldDraftExemptions = saved }
}
