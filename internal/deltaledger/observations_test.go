package deltaledger

// THE POLARITY PROOF for unledgered_disagreements, plus the evidence bindings
// that keep the observed-disagreement set honest.
//
// THE POINT OF THIS FILE. A fix that yields zero because everything happens to
// be ledgered is indistinguishable from the bug it replaces — the old field
// yielded zero too, and could yield nothing else. So the deliverable is not
// "the count is 0"; it is a demonstration that the count CAN be nonzero, for
// BOTH failure modes it claims to report, and that the readiness gate refuses
// when it is.
//
// THE PREVIOUS VERSION OF THIS FILE DID NOT DEMONSTRATE THAT, and review
// 01a0495e (BLOCKING 2) was right about why. It hand-constructed a degraded
// document and set `document.UnledgeredDisagreements = len(orphaned)` itself,
// never calling BuildLedgerFile. Reverting the production assignment in
// build.go to the literal `0` was executed on this branch before the fix and
// READ PASSING: the whole deltaledger suite stayed green and `deltaledgerctl
// --check` still reported ok. The tests below call BuildLedgerFileFrom — the
// single production assignment — so that revert now fails them.
//
// And review BLOCKING 1 was right that even a working record-deletion proof
// could not reach the failure that actually happened. Observations were built
// one-per-Definition, so they were 1:1 with the records by construction and a
// NEW divergence with no definition produced neither side. Appending a
// `divergent: true` row to the live mapping was executed on this branch before
// the fix and READ PASSING at count 0. TestTheCountRisesForANewlyObservedDivergence
// is the leg that closes it, and it fails if the evidence arm is removed.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// degradedRootArtifacts are the committed artifacts every integrity rule reads.
// A degraded root is a copy of them, so an attack can mutate evidence without
// touching the worktree.
var degradedRootArtifacts = []string{
	LedgerRelativePath,
	LedgerSchemaRelativePath,
	ObservationsRelativePath,
	ObservationsSchemaRelativePath,
	SupersessionsRelativePath,
	SupersessionsSchemaRelativePath,
	LiveMappingRelativePath,
	CensusRelativePath,
	CensusSchemaRelativePath,
	HandshakeCorpusRelativePath,
	PublicCorpusRelativePath,
	PublicCorpusManifestRelativePath,
	OwnerDecisionManifestRelativePath,
	OwnerDecisionManifestSchemaRelativePath,
	LegacyAdjudicationsRelativePath,
	LegacyAdjudicationsSchemaRelativePath,
	// The one draft a committed adjudication entry names. It is copied because
	// VerifyLegacyAdjudications STATS it: a contesting entry that names a
	// supersession draft which does not exist is refused, and a degraded root
	// that silently lacked the file would turn that rule into noise on every
	// unrelated probe.
	"drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json",
}

// withProtectedStore points VJWP_PROTECTED_STORE at the real governance store
// for the duration of a test.
//
// A degraded root is a temporary directory, so the store discovery that works
// from the worktree cannot work from it. Configuring the variable is the
// SUPPORTED way to point the gate at the store, and it is used here rather than
// skipping: round-2 finding 5 is precisely that an unreachable store used to
// mean a silent pass, and a test suite that quietly skips the governance gate
// when it cannot find the store would reintroduce that at the test layer. If
// the store cannot be resolved from the worktree, this FAILS.
func withProtectedStore(t *testing.T) {
	t.Helper()
	resolution, err := ResolveProtectedStore(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("the governance store is required by the integrity gate and could not be resolved: %v", err)
	}
	t.Setenv(ProtectedStoreEnv, resolution.Path)
}

// degradedRoot materializes a temporary repository root holding a copy of every
// committed artifact the rules read, then applies one mutation to it. The rules
// are then run against the REAL production entry points over that root, so a
// discrimination test exercises the shipping code path rather than a re-stated
// copy of it.
func degradedRoot(t *testing.T, degrade func(root string)) string {
	t.Helper()
	withProtectedStore(t)
	root := t.TempDir()
	for _, relative := range degradedRootArtifacts {
		source := filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(relative))
		raw, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		target := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", relative, err)
		}
		if err := os.WriteFile(target, raw, 0o644); err != nil {
			t.Fatalf("write %s: %v", relative, err)
		}
	}
	if degrade != nil {
		degrade(root)
	}
	return root
}

// TestCommittedObservationSetIsWellFormed fails closed on an empty, truncated
// or provenance-less observation set, so the gate can never become vacuous by
// the file quietly degrading.
//
// The rules themselves moved into ReadObservations under round-2 finding 4 —
// they used to live only here, and `ledger-gates` runs no Go tests — so this
// test now exercises the production reader rather than restating what it should
// have checked. TestTheGateRefusesADriftedObservationEnvelope and
// TestTheGateRefusesADuplicatedObservation are the discrimination halves.
func TestCommittedObservationSetIsWellFormed(t *testing.T) {
	set, err := ReadObservations(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	if set.EvidenceKind != ObservationsEvidenceKind || set.SchemaVersion != "1.0.0" {
		t.Fatalf("observation envelope drifted: kind=%q version=%q", set.EvidenceKind, set.SchemaVersion)
	}
	if set.Schema != ObservationsSchemaPointer {
		t.Fatalf("observation schema pointer drifted: %q", set.Schema)
	}
	if len(set.Observed) == 0 || len(set.Provenance) != len(set.Observed) {
		t.Fatalf("observation set is %d observations and %d provenance entries",
			len(set.Observed), len(set.Provenance))
	}
}

// TestObservationProvenanceResolvesOnDisk is the discrimination proof for
// review BLOCKING 7.
//
// The previous check required only a non-empty evidence list and a non-empty
// source-kind string, and it passed against a committed set in which 44
// citations named files that do not exist — including
// `corpora/live/handshake/transcript.jsonl` and
// `corpora/live/public/transcript.jsonl`, which the repository has never had,
// manufactured by a regex matching mid-string inside
// `protected/us005-corpora/live/…`, and
// `protected/us005-corpora/live/handshake/transcript.json`, manufactured by a
// regex truncating a `.jsonl` path.
func TestObservationProvenanceResolvesOnDisk(t *testing.T) {
	if err := VerifyObservationProvenance(ledgerTestRepoRoot, Definitions()); err != nil {
		t.Fatalf("observation provenance: %v", err)
	}
	root := degradedRoot(t, func(root string) {
		path := filepath.Join(root, filepath.FromSlash(ObservationsRelativePath))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read observations: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode observations: %v", err)
		}
		provenance, _ := document["provenance"].([]any)
		if len(provenance) == 0 {
			t.Fatal("no provenance entries to degrade")
		}
		entry, _ := provenance[0].(map[string]any)
		entry["evidence"] = []any{"evidence/a-file-that-does-not-exist.json"}
		encoded, _ := json.MarshalIndent(document, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write observations: %v", err)
		}
	})
	err := VerifyObservationProvenance(root, Definitions())
	if err == nil {
		t.Fatal("provenance verification accepted a citation of a file that does not exist")
	}
	if !strings.Contains(err.Error(), "a-file-that-does-not-exist.json") {
		t.Fatalf("refused, but not on the unresolvable citation; got: %v", err)
	}
}

// TestProvenanceMustEqualTheEvidenceDerivedProvenance is the discrimination
// proof for round-2 finding 3.
//
// THE ATTACK, reproduced against the previous rule and READ PASSING before the
// fix: rewrite one entry's `source_kind` to an invented label and its `evidence`
// to ["evidence/java/build.json"] — a file that exists, cited by nothing.
// The old check required only a non-empty source kind and paths that resolve, so
// `deltaledgerctl --check` returned exit 0. The fail-closed classifier ran only
// under `--regenerate-observations`, never under `--check`.
//
// Each leg below is a different member of the same class, because the finding is
// "an unrelated but resolvable value is accepted", not one specific string.
func TestProvenanceMustEqualTheEvidenceDerivedProvenance(t *testing.T) {
	for _, attack := range []struct {
		name      string
		degrade   func(entry map[string]any)
		mustMatch string
	}{
		{
			name: "an invented source kind",
			degrade: func(entry map[string]any) {
				entry["source_kind"] = "totally-unrelated-source-kind-nobody-classified"
			},
			mustMatch: "but the classifier derives",
		},
		{
			name: "an unrelated but existing evidence path",
			degrade: func(entry map[string]any) {
				entry["evidence"] = []any{"evidence/java/build.json"}
			},
			mustMatch: "an unrelated-but-existing path is a substitution",
		},
		{
			name: "a truncated evidence list",
			degrade: func(entry map[string]any) {
				citations, _ := entry["evidence"].([]any)
				if len(citations) > 1 {
					entry["evidence"] = citations[:1]
				}
			},
			mustMatch: "an unrelated-but-existing path is a substitution",
		},
		{
			name: "an extra plausible citation nobody's record makes",
			degrade: func(entry map[string]any) {
				citations, _ := entry["evidence"].([]any)
				entry["evidence"] = append(append([]any{}, citations...), "evidence/java/build.json")
			},
			mustMatch: "an unrelated-but-existing path is a substitution",
		},
	} {
		t.Run(attack.name, func(t *testing.T) {
			root := degradedRoot(t, func(root string) {
				path := filepath.Join(root, filepath.FromSlash(ObservationsRelativePath))
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read observations: %v", err)
				}
				var document map[string]any
				if err := json.Unmarshal(raw, &document); err != nil {
					t.Fatalf("decode observations: %v", err)
				}
				provenance, _ := document["provenance"].([]any)
				if len(provenance) == 0 {
					t.Fatal("no provenance entries to degrade")
				}
				entry, _ := provenance[0].(map[string]any)
				attack.degrade(entry)
				encoded, _ := json.MarshalIndent(document, "", "  ")
				if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
					t.Fatalf("write observations: %v", err)
				}
			})
			err := VerifyObservationProvenance(root, Definitions())
			if err == nil {
				t.Fatal("provenance verification accepted a substituted provenance. The gate must compare the " +
					"COMMITTED provenance with the EVIDENCE-DERIVED expected provenance, not merely check that the " +
					"committed strings are non-empty and resolve")
			}
			if !strings.Contains(err.Error(), attack.mustMatch) {
				t.Fatalf("refused, but not on the substitution; got: %v", err)
			}
		})
	}
}

// TestTheGateRefusesADriftedObservationEnvelope is the discrimination proof for
// round-2 finding 4's observation half.
//
// The envelope and uniqueness rules lived only in this test file, and
// `ledger-gates` runs no Go tests. Reproduced before the rules moved into
// ReadObservations: rewriting `$schema` to a file that does not exist and
// `evidence_kind` to "not-an-observed-disagreement-set" left both
// `deltaledgerctl --check` and `make -C rust ledger-gates` at exit 0. The rules
// now run wherever the observation set is read, which is inside the gate.
func TestTheGateRefusesADriftedObservationEnvelope(t *testing.T) {
	for _, attack := range []struct {
		field, value, mustMatch string
	}{
		{"$schema", "../../schemas/a-schema-that-does-not-exist-9.9.9.schema.json", "$schema pointer drifted"},
		{"evidence_kind", "not-an-observed-disagreement-set", "evidence_kind drifted"},
	} {
		t.Run(attack.field, func(t *testing.T) {
			root := degradedRoot(t, func(root string) {
				path := filepath.Join(root, filepath.FromSlash(ObservationsRelativePath))
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read observations: %v", err)
				}
				var document map[string]any
				if err := json.Unmarshal(raw, &document); err != nil {
					t.Fatalf("decode observations: %v", err)
				}
				document[attack.field] = attack.value
				encoded, _ := json.MarshalIndent(document, "", "  ")
				if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
					t.Fatalf("write observations: %v", err)
				}
			})
			err := VerifyIntegrity(root)
			if err == nil {
				t.Fatal("the integrity gate accepted a drifted observation envelope")
			}
			if !strings.Contains(err.Error(), attack.mustMatch) {
				t.Fatalf("the gate refused, but not on the drifted envelope; got: %v", err)
			}
		})
	}
}

// TestTheGateRefusesADuplicatedObservation pins the uniqueness rule in the same
// place. A duplicated subject either double-counts or masks an unledgered one.
func TestTheGateRefusesADuplicatedObservation(t *testing.T) {
	root := degradedRoot(t, func(root string) {
		path := filepath.Join(root, filepath.FromSlash(ObservationsRelativePath))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read observations: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode observations: %v", err)
		}
		observed, _ := document["observed"].([]any)
		provenance, _ := document["provenance"].([]any)
		if len(observed) == 0 || len(provenance) == 0 {
			t.Fatal("no observations to duplicate")
		}
		document["observed"] = append(append([]any{}, observed...), observed[0])
		document["provenance"] = append(append([]any{}, provenance...), provenance[0])
		encoded, _ := json.MarshalIndent(document, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write observations: %v", err)
		}
	})
	err := VerifyIntegrity(root)
	if err == nil {
		t.Fatal("the integrity gate accepted a duplicated observation")
	}
	if !strings.Contains(err.Error(), "duplicates subject") {
		t.Fatalf("the gate refused, but not on the duplicate; got: %v", err)
	}
}

// TestObservationSourceKindFailsClosed pins that the classifier can be wrong in
// a way something catches. Its previous `default:` arm returned a
// plausible-sounding label for every possible subject, so misclassification was
// unfalsifiable.
func TestObservationSourceKindFailsClosed(t *testing.T) {
	if observationSourceKind("org.java-websocket.some-domain-nobody-classified.thing") != "" {
		t.Fatal("observationSourceKind still invents a label for an unrecognised subject domain")
	}
	for _, definition := range Definitions() {
		if observationSourceKind(definition.Subject) == "" {
			t.Errorf("%s has no source kind; classify its domain deliberately", definition.Subject)
		}
	}
}

// TestCommittedLedgerCountsItsUnledgeredDisagreements pins that the committed
// field is the COMPUTED value rather than a constant that happens to agree.
func TestCommittedLedgerCountsItsUnledgeredDisagreements(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	subjects, demands, err := UnledgeredDisagreements(ledgerTestRepoRoot, committed.Records, Definitions())
	if err != nil {
		t.Fatalf("compute unledgered: %v", err)
	}
	if committed.UnledgeredDisagreements != len(subjects)+len(demands) {
		t.Fatalf("committed unledgered_disagreements is %d but the recomputation says %d (%v / %v)",
			committed.UnledgeredDisagreements, len(subjects)+len(demands), subjects, demands)
	}
}

// TestTheLedgerHasNoUnledgeredObservedDisagreements is the REQUIREMENT: at rest,
// every observed disagreement must have a record. It is deliberately a separate
// test from the computation above, because the computation being correct and
// the count being zero are two different claims, and conflating them is how the
// original fake gate read clean.
func TestTheLedgerHasNoUnledgeredObservedDisagreements(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	subjects, demands, err := UnledgeredDisagreements(ledgerTestRepoRoot, committed.Records, Definitions())
	if err != nil {
		t.Fatalf("compute unledgered: %v", err)
	}
	if len(subjects) != 0 {
		t.Errorf("%d observed disagreements have no ledger record: %v", len(subjects), subjects)
	}
	if len(demands) != 0 {
		t.Errorf("%d evidence-derived divergences have no ledger record: %v", len(demands), demands)
	}
	set, err := ReadObservations(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	if err := lab.DetectUnledgeredDisagreements(committed.Records, set.Observed); err != nil {
		t.Fatalf("the lab detector disagrees with the committed ledger: %v", err)
	}
}

// TestUnledgeredComputationAgreesWithTheLabDetector pins that this package's
// digest-arm computation and the canonical detector cannot drift apart: the
// detector says THAT something is unledgered, this package says WHICH, and they
// must agree on every prefix of the record chain.
func TestUnledgeredComputationAgreesWithTheLabDetector(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	set, err := ReadObservations(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	for cut := 0; cut <= len(committed.Records); cut++ {
		records := committed.Records[:cut]
		unledgered, err := UnledgeredSubjects(records, set.Observed)
		if err != nil {
			t.Fatalf("cut %d: compute unledgered: %v", cut, err)
		}
		detectorErr := lab.DetectUnledgeredDisagreements(records, set.Observed)
		if (len(unledgered) == 0) != (detectorErr == nil) {
			t.Fatalf("cut %d: computation reports %d unledgered but the detector returned %v",
				cut, len(unledgered), detectorErr)
		}
	}
}

// TestUnledgeredCountReportsNonzeroAndTheReadinessGateRefuses IS THE POLARITY
// PROOF FOR THE DIGEST ARM, and it goes through the production assignment.
//
// It builds the ledger document from the real definitions MINUS the last one,
// with the committed observation set intact, and asserts three things:
//
//  1. BuildLedgerFileFrom — the one place the field is assigned — emits 1;
//  2. the serialized document carries that nonzero value, where the old
//     schema's `const: 0` forbade it;
//  3. internal/lab.VerifyBaselineEvidence REFUSES readiness on that document
//     with UNLEDGERED_BEHAVIOR_DISAGREEMENT.
//
// Building from the intact definitions returns the count to 0, so the gate is
// proven to discriminate rather than merely to agree.
func TestUnledgeredCountReportsNonzeroAndTheReadinessGateRefuses(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	definitions := Definitions()
	if len(definitions) < 2 {
		t.Fatal("polarity proof needs at least two definitions")
	}

	// Baseline through the production path: the intact tree reports zero.
	intact, err := BuildLedgerFileFrom(ledgerTestRepoRoot, committed, definitions)
	if err != nil {
		t.Fatalf("build the intact ledger: %v", err)
	}
	if intact.UnledgeredDisagreements != 0 {
		t.Fatalf("polarity proof needs a clean baseline, the production build reports %d",
			intact.UnledgeredDisagreements)
	}

	// Remove ONE record whose removal isolates the digest arm.
	//
	// The record chosen is the handshake field-emission-order record, sequence
	// 56. It is not a superseding correction, no divergent mapping row is
	// covered by it, and no public-corpus scenario depends on it being the
	// record that names it — so removing it orphans exactly its own committed
	// observation and nothing else, which is what makes the expected count
	// exactly 1 rather than a number this test would have to derive from the
	// thing it is testing.
	//
	// IT MUST ALSO SIT AFTER EVERY SUPERSEDED SEQUENCE, and that constraint is
	// new. This test names sequence 17 until the stale-port corrections at 57
	// and 58 were appended; a Supersession names its target BY SEQUENCE as well
	// as by delta id, so removing a definition that sits BEFORE a superseded
	// record renumbers that record and the link stops resolving — a loud,
	// correct refusal, but a different one from the digest-arm failure under
	// test, and it masked it. Sequence 56 is after 55, the last superseded
	// sequence, so removing it renumbers nothing that is named. If a future
	// change makes it load-bearing, or appends a supersession of a record after
	// it, this test fails loudly and a different isolated record should be
	// named here.
	const isolated = "org.java-websocket.handshake.field-emission-order"
	var removed Definition
	var truncated []Definition
	for _, definition := range definitions {
		if definition.Subject == isolated {
			removed = definition
			continue
		}
		truncated = append(truncated, definition)
	}
	if removed.Subject == "" {
		t.Fatalf("%s is no longer in the definition set; name another isolated record", isolated)
	}

	degradedDocument, err := BuildLedgerFileFrom(ledgerTestRepoRoot, committed, truncated)
	if err != nil {
		t.Fatalf("build the truncated ledger: %v", err)
	}
	if degradedDocument.UnledgeredDisagreements != 1 {
		t.Fatalf("removing one record must make the PRODUCTION assignment emit 1, it emitted %d. If this reads 0, "+
			"BuildLedgerFileFrom is not computing the field.", degradedDocument.UnledgeredDisagreements)
	}

	// It must be the removed subject that is orphaned, not something else.
	subjects, demands, err := UnledgeredDisagreements(ledgerTestRepoRoot, degradedDocument.Records, truncated)
	if err != nil {
		t.Fatalf("compute unledgered on the truncated chain: %v", err)
	}
	if len(demands) != 0 {
		t.Fatalf("removing the tail record should orphan a digest-arm observation, not an evidence demand: %v", demands)
	}
	if len(subjects) != 1 || subjects[0] != "semantic:"+removed.Subject+":provisional-v1" {
		t.Fatalf("orphaned subjects are %v, expected exactly the removed definition %s", subjects, removed.Subject)
	}

	// The canonical detector must refuse the same chain.
	set, err := ReadObservations(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	if err := lab.DetectUnledgeredDisagreements(degradedDocument.Records, set.Observed); err == nil {
		t.Fatal("the lab detector accepted a chain missing a record for a committed observation")
	}

	raw, err := json.Marshal(degradedDocument)
	if err != nil {
		t.Fatalf("marshal degraded ledger: %v", err)
	}
	if !strings.Contains(string(raw), `"unledgered_disagreements":1`) {
		t.Fatal("the serialized ledger document does not carry the nonzero count")
	}
	assertReadinessRefusesUnledgered(t, raw)
}

// TestTheCountRisesForANewlyObservedDivergence IS THE POLARITY PROOF FOR THE
// EVIDENCE ARM, and it is the leg the previous design could not have.
//
// Review BLOCKING 1: because observations were derived one-per-Definition, a
// divergence that no definition described produced neither an observation nor a
// record, and the count read zero. That is exactly the G3c failure this plane
// actually suffered — six divergent `server_response` mapping rows with no
// record at all, while `unledgered_disagreements` read 0 throughout.
//
// This test appends a `divergent: true` row to a COPY of the committed live
// mapping and requires the production build to report it. The row is invented
// by the test, not by any definition, so nothing on the definition side can
// make it go away.
func TestTheCountRisesForANewlyObservedDivergence(t *testing.T) {
	root := degradedRoot(t, func(root string) {
		path := filepath.Join(root, filepath.FromSlash(LiveMappingRelativePath))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read live mapping: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode live mapping: %v", err)
		}
		entries, _ := document["entries"].([]any)
		if len(entries) == 0 {
			t.Fatal("live mapping has no entries")
		}
		document["entries"] = append(entries, map[string]any{
			"direction":       "server_response",
			"key":             "HS_LIMIT_HEADER_COUNT_NEWLY_OBSERVED",
			"rfc_verdict":     "reject",
			"java_observable": "conditional",
			"divergent":       true,
			"basis":           []any{"a divergence observed today that nobody has written a definition for"},
		})
		encoded, _ := json.MarshalIndent(document, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write live mapping: %v", err)
		}
	})

	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}

	// Sanity: the unmutated copy reports zero through the same path, so the
	// nonzero below is the new row and not an artifact of the temp root.
	clean := degradedRoot(t, nil)
	cleanDocument, err := BuildLedgerFileFrom(clean, committed, Definitions())
	if err != nil {
		t.Fatalf("build over the clean copy: %v", err)
	}
	if cleanDocument.UnledgeredDisagreements != 0 {
		t.Fatalf("the unmutated copy reports %d; the temp root is not equivalent to the worktree",
			cleanDocument.UnledgeredDisagreements)
	}

	built, err := BuildLedgerFileFrom(root, committed, Definitions())
	if err != nil {
		t.Fatalf("build over the degraded copy: %v", err)
	}
	if built.UnledgeredDisagreements != 1 {
		t.Fatalf("a NEWLY OBSERVED divergence with no definition left unledgered_disagreements at %d. This is the "+
			"G3c failure mode: the field must be able to report a divergence nobody wrote down, not only a record "+
			"someone deleted.", built.UnledgeredDisagreements)
	}
	_, demands, err := UnledgeredDisagreements(root, built.Records, Definitions())
	if err != nil {
		t.Fatalf("compute unledgered over the degraded copy: %v", err)
	}
	if len(demands) != 1 || !strings.Contains(demands[0].ID, "HS_LIMIT_HEADER_COUNT_NEWLY_OBSERVED") {
		t.Fatalf("the unledgered demand is %v, expected the newly observed mapping row", demands)
	}

	raw, err := json.Marshal(built)
	if err != nil {
		t.Fatalf("marshal degraded ledger: %v", err)
	}
	assertReadinessRefusesUnledgered(t, raw)
}

// TestTheCountRisesForANewlyObservedCorpusScenario is the same proof for the
// other evidence arm: a public-corpus scenario that falls in the
// protocol-rejection class and that no record discusses.
func TestTheCountRisesForANewlyObservedCorpusScenario(t *testing.T) {
	root := degradedRoot(t, func(root string) {
		path := filepath.Join(root, filepath.FromSlash(PublicCorpusRelativePath))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read public corpus: %v", err)
		}
		// The appended scenario is a REAL executable scenario whose recorded
		// expectation is DERIVED from its own steps, not a hand-written
		// summary. Round 3 made ReadPublicScenarios require every committed
		// line to equal its re-derivation, so a fabricated line is refused
		// before the class predicate sees it — which means this test's
		// degraded corpus has to be a corpus, not a sketch of one.
		core := corpora.ScenarioCore{
			Role:         "server",
			InitialState: "open",
			Limits: corpora.Limits{
				MaxInputBytes: 65536, MaxBufferedBytes: 65536, MaxActions: 64,
				MaxFrames: 64, MaxOutputBytes: 4194304,
			},
			Steps: []corpora.Step{{Kind: "bytes", DataBase64: "oYN0s9jSCOmF"}},
		}
		expected, _, err := corpora.DeriveExpectedAndFailingStep(core)
		if err != nil {
			t.Fatalf("derive the appended scenario: %v", err)
		}
		encoded, err := corpora.Scenario{
			ScenarioID: "us005.pub.0099", Tier: "public", Family: "rsv-bit", SeedIndex: 0,
			Core: core, Expected: expected,
			ExpectationBasis:  []string{"rfc6455.section-5-2"},
			ExpectationStatus: corpora.ExpectationStatusReferenceModel,
		}.CanonicalLine()
		if err != nil {
			t.Fatalf("render the appended scenario: %v", err)
		}
		if err := os.WriteFile(path, append(raw, append(encoded, '\n')...), 0o644); err != nil {
			t.Fatalf("write public corpus: %v", err)
		}
	})
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	built, err := BuildLedgerFileFrom(root, committed, Definitions())
	if err != nil {
		t.Fatalf("build over the degraded copy: %v", err)
	}
	if built.UnledgeredDisagreements != 1 {
		t.Fatalf("a new public-corpus scenario in the protocol-rejection class that no record discusses left "+
			"unledgered_disagreements at %d", built.UnledgeredDisagreements)
	}
	if err := VerifyProtocolRejectionClass(root, Definitions()); err == nil {
		t.Fatal("the class completeness rule accepted a corpus scenario that the census does not enroll")
	}
}

// assertReadinessRefusesUnledgered feeds the degraded ledger document to the
// real readiness gate alongside the other committed baseline documents and
// requires an UNLEDGERED_BEHAVIOR_DISAGREEMENT refusal.
func assertReadinessRefusesUnledgered(t *testing.T, degradedLedger []byte) {
	t.Helper()
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(ledgerTestRepoRoot, "evidence", "java", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return raw
	}
	var envelope struct {
		AcceptedRootDigest string `json:"accepted_root_digest"`
	}
	if err := json.Unmarshal(degradedLedger, &envelope); err != nil {
		t.Fatalf("decode degraded ledger envelope: %v", err)
	}
	_, err := lab.VerifyBaselineEvidence(envelope.AcceptedRootDigest, lab.BaselineEvidenceDocuments{
		Build:    read("build.json"),
		Adapter:  read("adapter-baseline.json"),
		Tests:    read("test-manifest.json"),
		Autobahn: read("autobahn-baseline.json"),
		Ledger:   degradedLedger,
	})
	if err == nil {
		t.Fatal("readiness gate accepted a ledger reporting an unledgered disagreement")
	}
	if !strings.Contains(err.Error(), "UNLEDGERED_BEHAVIOR_DISAGREEMENT") {
		// The gate may refuse earlier for an unrelated reason (for example the
		// Autobahn baseline is BLOCKED on this plane). Say so explicitly
		// rather than letting a coincidental refusal masquerade as the proof.
		t.Fatalf("readiness refused, but not on the unledgered-disagreement finding; got: %v", err)
	}
}
