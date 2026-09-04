package deltaledger

// THE EVIDENCE-DERIVED DIVERGENCE UNIVERSE.
//
// WHY THIS FILE IS NOT A _test.go FILE, AND WHY IT DOES NOT READ Definitions().
//
// The predecessor of this file was two `_test.go` censuses plus an observation
// set built by BuildObservationSet from Definitions(). Independent review
// (session 01a0495e, BLOCKING 1/3/4/5/6) established three defects, each of
// which was reproduced by executing the attack before it was fixed:
//
//  1. CIRCULARITY. Observations were derived one-per-Definition, and the same
//     Definitions produce the ledger records, so observations and records were
//     1:1 BY CONSTRUCTION. `unledgered_disagreements` could only move if a
//     record was deleted or drifted. A genuinely NEW divergence that nobody had
//     written a definition for — which is exactly the G3c failure that actually
//     occurred on this plane — produced neither an observation nor a record and
//     read zero. Reproduced: appending a `divergent: true` row to
//     evidence/us005-handshake-live-mapping.json left `deltaledgerctl --check`
//     passing at count 0 and every unledgered test green.
//
//  2. NOT WIRED. The censuses were assertions in a Go test binary. Nothing in
//     the release or readiness path ran them: rust/Makefile's `gates` target
//     has no `go test`, there is no root Makefile, no workflow runs them, and
//     `deltaledgerctl --check` only compared the ledger to its regeneration.
//
//  3. COVERAGE BY EXISTENCE RATHER THAN BY MEANING. "Ledgered" meant a delta id
//     appeared somewhere in the chain, and mapping-row coverage meant a literal
//     token appeared somewhere in free prose. Reproduced: repointing EVERY
//     census row at the unrelated sequence-1 record left all three census tests
//     green, and deleting the six meaningful client-handshake records while
//     pasting their six citation tokens into an unrelated record's prose left
//     the mapping census green.
//
// So this file is ORDINARY PRODUCTION CODE that reads COMMITTED EVIDENCE and
// derives, independently of the definition set, the divergences that MUST be
// ledgered. cmd/deltaledgerctl calls it (both under --check and when writing),
// BuildLedgerFile folds its result into `unledgered_disagreements`, and the
// tests in this package call the same exported functions rather than
// reimplementing them, so a test and the gate cannot drift apart.
//
// THE UNIVERSE HAS TWO ARMS, both swept mechanically from committed evidence:
//
//   - HANDSHAKE MAPPING ROWS: every `divergent: true` row of
//     evidence/us005-handshake-live-mapping.json.
//   - PUBLIC-CORPUS PROTOCOL REJECTIONS: every scenario of
//     corpora/public/scenarios.jsonl in the protocol-rejection-readystate
//     class, by the CAUSE predicate below.
//
// Neither arm can be satisfied by writing a definition; both are read from
// artifacts a definition does not control. That is what makes a demand with no
// covering record able to exist at all.

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
)

// LiveMappingRelativePath is the committed live handshake verdict mapping. It
// is rendered from corpora.HandshakeVerdictMapping and pinned byte-identical to
// that rendering by internal/corpora.TestHandshakeLiveMappingEvidenceDocument,
// so reading the artifact here reads the same evidence the acceptance audit
// read.
const LiveMappingRelativePath = "evidence/us005-handshake-live-mapping.json"

// HandshakeCorpusRelativePath is the live handshake corpus.
const HandshakeCorpusRelativePath = "corpora/handshake/cases.jsonl"

// PublicCorpusRelativePath is the public scenario corpus.
const PublicCorpusRelativePath = "corpora/public/scenarios.jsonl"

// CensusRelativePath is the committed public-corpus RFC-divergence census.
const CensusRelativePath = "evidence/us005-public-rfc-divergence-census.json"

// CensusSchemaRelativePath is the census document's schema. Review BLOCKING 5
// found the census pointing at this path while no such file existed and the
// decoder ignored both `$schema` and `census_id`, so the missing contract was
// undetectable. The file now exists and ReadCensus enforces the pointer.
const CensusSchemaRelativePath = "schemas/public-rfc-divergence-census-1.0.0.schema.json"

// ProtocolRejectionClass is the class whose membership is decided mechanically.
const ProtocolRejectionClass = "protocol-rejection-readystate"

// ProtocolRejectionClassDerivation is the ONE statement of how membership in
// that class is decided, and it is the text every census row in the class must
// carry verbatim.
//
// IT IS A CONSTANT IN CODE BECAUSE OF ROUND-3 FINDING 1. The census rows and
// the class record went on describing membership as the AGGREGATE
// `counts.input_bytes>0` rule for a whole round after round 2 replaced it with
// the failing-step derivation: the code was fixed, the description of the code
// was not, and nothing compared them, because `derivation` was decoded into the
// struct and never read. Reproduced before this fix by rewriting a row's
// derivation to "MECHANICAL SWEEP by whether the scenario id is even. Also the
// moon is made of cheese." and reading `deltaledgerctl --check` at exit 0.
// VerifyCensusRowsMatchEvidence now requires equality with this constant, so
// the authoritative artifact cannot describe a rule the gate does not run.
const ProtocolRejectionClassDerivation = "MECHANICAL SWEEP of corpora/public/scenarios.jsonl BY CAUSE, not by " +
	"result shape and not by any recorded aggregate: expected.outcome==error AND " +
	"expected.error.code==JAVA_INVALID_DATA (the pinned Java decoder's typed rejection) AND " +
	"expected.final_state=='open' AND the step the run STOPPED ON is a `bytes` step — that is, the rejection was " +
	"raised while decoding INBOUND wire data rather than by a local API call. THE FAILING STEP IS DERIVED BY " +
	"EXECUTION: internal/corpora.DeriveExpectedAndFailingStep runs the scenario's own role, initial_state, limits " +
	"and steps under the reference model and reports the index of the step whose execution raised the error. " +
	"expected.counts is NOT consulted, and there is no fallback to it; a scenario whose steps the model cannot " +
	"execute is refused rather than classified. internal/deltaledger.ReadPublicScenarios additionally requires every " +
	"committed corpus line to EQUAL its own re-derivation, so a recorded expectation that disagrees with the " +
	"scenario's execution is refused before any predicate reads it. Complete over the 74-scenario public tier by " +
	"that predicate, re-derived on every run of cmd/deltaledgerctl --check. TWO EARLIER PREDICATES WERE WRONG AND " +
	"ARE NAMED HERE SO THE CORRECTION STAYS VISIBLE: the first selected on close_code in {1002,1007,1009}, a result " +
	"shape, and wrongly enrolled us005.pub.0000; the second selected on the aggregate counts.input_bytes>0, which a " +
	"valid inbound frame followed by a rejected local send_close satisfies, and the third derived the failing step " +
	"from those same counts, which let a scenario understate its own action count and choose the answer. See this " +
	"document's completeness field."

// MappingRowCitation matches the explicit citation token a ledger record uses
// to claim a divergent mapping row that no corpus case exercises.
var MappingRowCitation = regexp.MustCompile(`mapping-row direction=([a-z_]+) key=(HS_[A-Z0-9_]+)`)

// handshakeCaseCitation matches a live handshake corpus case id.
var handshakeCaseCitation = regexp.MustCompile(`us005\.hs\.[0-9]{4}`)

// publicScenarioCitation matches a public corpus scenario id.
var publicScenarioCitation = regexp.MustCompile(`us005\.pub\.[0-9]{4}`)

// parsingRoleForDirection maps a handshake message DIRECTION to the subject
// segment of the endpoint that PARSES that message. A `client_request` is
// parsed by the server, so its records live under `server-handshake.`; a
// `server_response` is parsed by the client, so its records live under
// `client-handshake.`. This is the binding that makes coverage mean "this
// record is about this row" rather than "this token appears somewhere".
var parsingRoleForDirection = map[string]string{
	"client_request":  "server-handshake",
	"server_response": "client-handshake",
}

// MappingRow identifies one row of the live handshake verdict mapping.
type MappingRow struct {
	Direction string
	Key       string
}

func (r MappingRow) String() string {
	return fmt.Sprintf("direction=%s key=%s", r.Direction, r.Key)
}

// CitationToken is the literal token a record writes to claim this row.
func (r MappingRow) CitationToken() string {
	return fmt.Sprintf("mapping-row direction=%s key=%s", r.Direction, r.Key)
}

type liveMappingDocument struct {
	Entries []struct {
		Direction      string `json:"direction"`
		Key            string `json:"key"`
		RFCVerdict     string `json:"rfc_verdict"`
		JavaObservable string `json:"java_observable"`
		Divergent      bool   `json:"divergent"`
	} `json:"entries"`
}

// HandshakeCase is one live handshake corpus case.
type HandshakeCase struct {
	CaseID    string `json:"case_id"`
	Direction string `json:"direction"`
	Family    string `json:"family"`
	Expected  struct {
		RejectCode string `json:"reject_code"`
	} `json:"expected"`
}

// ScenarioStep is one step of a public-corpus scenario. `kind` is "bytes" (the
// harness feeds these bytes to the decoder as INBOUND wire data) or "action"
// (the harness makes a LOCAL API call). Which of the two the recorded run
// stopped on is what distinguishes an inbound decode rejection from a locally
// caused error, so the field is load-bearing rather than descriptive.
type ScenarioStep struct {
	Kind       string `json:"kind"`
	Action     string `json:"action"`
	DataBase64 string `json:"data_base64"`
}

// PublicScenario is one public-corpus scenario, decoded to exactly the fields
// the class predicate and the census binding need, plus the raw `expected`
// object so a census row's JSON pointer can be resolved against it.
type PublicScenario struct {
	ScenarioID string         `json:"scenario_id"`
	Tier       string         `json:"tier"`
	Family     string         `json:"family"`
	SeedIndex  int            `json:"seed_index"`
	Steps      []ScenarioStep `json:"steps"`
	// Core is the scenario's EXECUTABLE portion — role, initial state, limits
	// and steps — decoded into the reference model's own type. It is what makes
	// the failing step derivable by EXECUTION rather than by reading the
	// summary counts recorded beside the claim (round-3 finding 2).
	Core              corpora.ScenarioCore `json:"-"`
	ExpectationBasis  []string             `json:"expectation_basis"`
	ExpectationStatus string               `json:"expectation_status"`
	Expected          struct {
		Outcome    string `json:"outcome"`
		FinalState string `json:"final_state"`
		Counts     struct {
			Actions       int `json:"actions"`
			InputBytes    int `json:"input_bytes"`
			ConsumedBytes int `json:"consumed_bytes"`
		} `json:"counts"`
		Error *struct {
			Code      string `json:"code"`
			CloseCode int    `json:"close_code"`
		} `json:"error"`
	} `json:"expected"`
	// ExpectedRaw is the scenario's `expected` object exactly as committed. It
	// is populated by ReadPublicScenarios and exists so a census row's
	// `pointer` is resolved against the recorded evidence rather than against
	// the handful of fields this struct happens to name.
	ExpectedRaw json.RawMessage `json:"-"`
	// CommittedLine is the scenario's committed JSONL line, kept so the
	// re-derivation can be compared to the committed bytes rather than to a
	// re-encoding of the fields this struct happens to name.
	CommittedLine string `json:"-"`
}

// CensusStatement and CensusCompleteness are the census document's two prose
// claims, held in code and required to match the committed artifact.
//
// They are here for the same reason ProtocolRejectionClassDerivation is. Round-3
// finding 1 was a stale DESCRIPTION surviving a fixed IMPLEMENTATION, and the
// mechanism that let it survive was simply that nothing compared the two.
// `statement`, `completeness` and `derivation` were all decoded into the struct
// and none was read. Pinning them means the document's account of itself is a
// checked claim.
const CensusStatement = "Public-corpus propositions where this port follows the pinned Java oracle over an " +
	"RFC-strict reading, with the ledger record that discloses each one. It exists because the reserved-bit " +
	"ready-state divergence was found by a cross-plane audit reading another plane's manifest by hand, and no gate " +
	"of ours would have found it — nor the seventeen sibling instances the same mechanism produces. Rows are swept " +
	"from the committed corpus by CAUSE, every row must carry the derivation this gate actually runs, and every row " +
	"must name a ledger record that actually discusses its scenario; internal/deltaledger.VerifyIntegrity enforces " +
	"all three, and cmd/deltaledgerctl --check runs it, so this is a gate rather than a document."

// CensusCompleteness is the census's completeness claim.
const CensusCompleteness = "The protocol-rejection-readystate class is COMPLETE over the 74-scenario public tier " +
	"by the CAUSE predicate stated in every row's `derivation` field, and internal/deltaledger re-derives it from " +
	"the corpus on every run, so a new scenario that falls in the class fails the gate until it is enrolled here " +
	"and ledgered. THREE PREDICATES HAVE BEEN WRONG AND EACH CORRECTION IS RECORDED HERE RATHER THAN QUIETLY " +
	"APPLIED. (1) The original selected on error.close_code in {1002,1007,1009}, a RESULT SHAPE. It enrolled " +
	"us005.pub.0000, a locally initiated send_close(999) with no inbound byte decoded at all. RFC 6455 section " +
	"7.1.7 requires closing only where another algorithm or provision requires Failing the WebSocket Connection, " +
	"and an invalid local API call is not such a provision, so this document's claim that the RFC-strict state " +
	"there was 'closed' was wrong; that scenario is ledgered separately and correctly at ledger sequence 35, which " +
	"records that the RFC behaviour remains OPEN because no Close frame was ever sent. That correction is why the " +
	"count went from nineteen to eighteen. (2) Its replacement selected on the AGGREGATE counts.input_bytes>0, " +
	"which a valid inbound frame followed by a rejected local send_close also satisfies — the same mistake one " +
	"level less obvious. (3) Its replacement derived the failing step FROM those same counts, so a scenario that " +
	"understated its own action count made the bytes prefix the unique match and was enrolled anyway; the evidence " +
	"that decided membership was supplied by the thing membership was meant to constrain. The failing step is now " +
	"derived by EXECUTING each scenario's own steps under the reference model, and every committed corpus line " +
	"must equal its own re-derivation. The close-code set is an asserted CONSISTENCY property of the class rather " +
	"than its boundary: a future member carrying some other code fails the gate and forces a decision instead of " +
	"being silently excluded. Completeness is claimed for THIS CLASS ONLY. Other Java-over-RFC propositions exist " +
	"in the corpus (consumed-byte rejection sites, error-site offsets, the absent automatic pong) and no mechanical " +
	"predicate sweeps them."

// CensusEntry is one row of the public-corpus RFC-divergence census.
type CensusEntry struct {
	ScenarioID           string   `json:"scenario_id"`
	Pointer              string   `json:"pointer"`
	Family               string   `json:"family"`
	Class                string   `json:"class"`
	Derivation           string   `json:"derivation"`
	RFCClauses           []string `json:"rfc_clauses"`
	RFCStrictExpectation string   `json:"rfc_strict_expectation"`
	RecordedObservable   string   `json:"recorded_observable"`
	RecordedCloseCode    int      `json:"recorded_close_code"`
	PortFollows          string   `json:"port_follows"`
	JavaEntryPointNote   string   `json:"java_entry_point_note"`
	LedgerDeltaID        string   `json:"ledger_delta_id"`
	Evidence             []string `json:"evidence"`
}

// CensusDocument is the committed census.
type CensusDocument struct {
	Schema        string        `json:"$schema"`
	SchemaVersion string        `json:"schema_version"`
	EvidenceKind  string        `json:"evidence_kind"`
	CensusID      string        `json:"census_id"`
	Statement     string        `json:"statement"`
	Completeness  string        `json:"completeness"`
	Entries       []CensusEntry `json:"entries"`
}

// PublicCorpusManifestRelativePath holds the seed both committed corpora derive
// from, and HandshakeCorpusManifestRelativePath is the handshake corpus's own
// manifest, which declares the same seed and describes its own artifact.
const (
	PublicCorpusManifestRelativePath    = "corpora/public/manifest.json"
	HandshakeCorpusManifestRelativePath = "corpora/handshake/manifest.json"
)

// corpusManifest is the part of a corpus manifest this file re-derives: the
// seed the corpus is generated from, and the manifest's own description of the
// bytes it ships beside it.
type corpusManifest struct {
	Generator struct {
		PublicSeed string `json:"public_seed"`
	} `json:"generator"`
	Artifacts []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Bytes  int    `json:"bytes"`
	} `json:"artifacts"`
}

func readCorpusManifest(root, relative string) (corpusManifest, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return corpusManifest{}, err
	}
	var manifest corpusManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return corpusManifest{}, fmt.Errorf("decode %s: %w", relative, err)
	}
	return manifest, nil
}

// VerifyCommittedCorporaReDerive is the PRODUCTION identity check between the
// committed corpus files and their derivation from the committed seed.
//
// WHY IT IS HERE AND NOT ONLY IN A TEST (found in this branch's own adversarial
// pass, same class as round-3 finding 2). Both committed corpora are INPUTS to
// the divergence measurement: corpora/public/scenarios.jsonl supplies the
// protocol-rejection class, and corpora/handshake/cases.jsonl supplies the
// family slug that decides whether a ledger record is ABOUT a mapping row. The
// only thing binding either file to its generator was
// internal/corpora/committed_test.go, a test binary no release path runs — the
// exact criticism round 3 made of the public corpus, applied to the file that
// decides coverage semantics.
//
// WHAT ROUND 5 ADDED, AND WHY IT IS NOT DECORATION. The first version of this
// function re-derived the two corpus FILES and asked nothing at all about the
// manifests beside them, including the one whose seed it took as its input.
// Three states were reachable with `make -C rust ledger-gates` at exit 0 and
// the whole internal/corpora test package green, each reproduced by execution
// before this paragraph was written:
//
//   - corpora/public/manifest.json declaring bytes 1 for a 342167-byte corpus;
//   - corpora/handshake/manifest.json declaring an all-zero sha256 and bytes 2
//     for the corpus this function re-derives byte-for-byte;
//   - corpora/handshake/manifest.json declaring a generator.public_seed the
//     handshake corpus was never derived from, while the public manifest's seed
//     — the one actually used — stayed correct.
//
// The public manifest's artifact digest was reconciled, but only by
// internal/corpora/committed_test.go, which is go-suite's to run and not this
// gate's; its `bytes` and the handshake manifest were reconciled by nothing.
// The corpus is not the only committed artifact that describes the corpus, and
// a manifest that both seeds a derivation and misdescribes its result is the
// shape this file exists to refuse.
func VerifyCommittedCorporaReDerive(root string) error {
	manifest, err := readCorpusManifest(root, PublicCorpusManifestRelativePath)
	if err != nil {
		return err
	}
	if manifest.Generator.PublicSeed == "" {
		return fmt.Errorf("%s names no generator.public_seed, so the committed corpora cannot be re-derived and "+
			"this refuses rather than skipping", PublicCorpusManifestRelativePath)
	}
	derivedPublic, derivedHandshake, err := corpora.RenderCommittedCorpora(manifest.Generator.PublicSeed)
	if err != nil {
		return fmt.Errorf("re-derive the committed corpora from the committed seed: %w", err)
	}
	for _, one := range []struct {
		relative string
		manifest string
		derived  []byte
	}{
		{PublicCorpusRelativePath, PublicCorpusManifestRelativePath, derivedPublic},
		{HandshakeCorpusRelativePath, HandshakeCorpusManifestRelativePath, derivedHandshake},
	} {
		committed, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(one.relative)))
		if err != nil {
			return err
		}
		if string(committed) != string(one.derived) {
			return fmt.Errorf("%s does not re-derive from the committed seed in %s. This corpus is an INPUT to the "+
				"divergence measurement, so an edit to it moves what the gate is able to demand; the identity check "+
				"used to run only in a test binary, which is not a gate",
				one.relative, PublicCorpusManifestRelativePath)
		}
		if err := verifyCorpusManifestDescribes(root, one.manifest, one.relative,
			manifest.Generator.PublicSeed, one.derived); err != nil {
			return err
		}
	}
	return nil
}

// verifyCorpusManifestDescribes re-derives a corpus manifest's own claims about
// the corpus: the seed it says the bytes come from, and the path, digest and
// length it says those bytes have.
//
// It takes the DERIVED bytes rather than the committed ones on purpose. The
// caller has already refused a corpus that is not byte-identical to its
// derivation, so the two are equal here; passing the derivation makes this a
// statement about what the generator produces rather than a digest of a file
// compared against a digest of the same file.
func verifyCorpusManifestDescribes(root, manifestRelative, corpusRelative, seed string, derived []byte) error {
	manifest, err := readCorpusManifest(root, manifestRelative)
	if err != nil {
		return err
	}
	if manifest.Generator.PublicSeed != seed {
		return fmt.Errorf("%s declares generator.public_seed %q, but %s is derived from the seed %q that %s "+
			"declares. Two manifests naming two seeds for one derivation means one of them describes a corpus "+
			"this repository does not hold",
			manifestRelative, manifest.Generator.PublicSeed, corpusRelative, seed, PublicCorpusManifestRelativePath)
	}
	base := path.Base(corpusRelative)
	if len(manifest.Artifacts) != 1 {
		return fmt.Errorf("%s lists %d artifacts; it describes exactly one file, %s, and this rule re-derives "+
			"only that file, so a second entry would be a claim about bytes nothing here checks",
			manifestRelative, len(manifest.Artifacts), base)
	}
	artifact := manifest.Artifacts[0]
	if artifact.Path != base {
		return fmt.Errorf("%s describes an artifact at %q, but the corpus it seeds is %s",
			manifestRelative, artifact.Path, corpusRelative)
	}
	wantDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(derived))
	if artifact.SHA256 != wantDigest {
		return fmt.Errorf("%s declares %s at %s, but the corpus derived from the committed seed digests to %s. "+
			"The manifest is the artifact that says what the corpus IS; a manifest that seeds the derivation and "+
			"then misdescribes its result was accepted by this gate until round 5",
			manifestRelative, base, artifact.SHA256, wantDigest)
	}
	if artifact.Bytes != len(derived) {
		return fmt.Errorf("%s declares %s at %d bytes, but the corpus derived from the committed seed is %d bytes",
			manifestRelative, base, artifact.Bytes, len(derived))
	}
	return nil
}

// VerifyLiveMappingIsBoundToItsSourceTable requires the committed live
// handshake mapping to be byte-identical to the table it is rendered from.
//
// FOUND IN THIS BRANCH'S OWN ADVERSARIAL PASS, in the class round 3 named, and
// reproduced by execution before the fix: flipping ONE `divergent: true` row of
// evidence/us005-handshake-live-mapping.json to false — client_request
// HS_MISSING_HOST — silently removed a demand from the measurement's universe
// and left `deltaledgerctl --check` at exit 0. It went unnoticed because only
// the six server_response rows are claimed by the literal `mapping-row` token,
// so the fail-closed "cites a row the evidence does not record as divergent"
// arm never fires for the thirteen client_request rows. The document is
// rendered from corpora.HandshakeVerdictMapping(), and until now the only thing
// that said so was internal/corpora/handshake_live_test.go — a test binary no
// release path runs, which is round-1 finding 3's shape and round-3 finding 2's
// second half.
//
// IT IS A SEPARATE VERIFICATION RATHER THAN A CHECK INSIDE
// ReadDivergentMappingRows, deliberately. "Is this artifact authentic" and
// "what does this artifact say" are different questions, and the polarity
// proofs for the measurement need to feed it a mapping with a divergence nobody
// has written down — which is how a new divergence genuinely arrives, via the
// source table and a regeneration. Folding the binding into the reader would
// make those proofs impossible to state, and a measurement whose polarity
// cannot be demonstrated is the defect this whole file exists to remove. Both
// checks run in VerifyIntegrity, so the production gate refuses either failure.
func VerifyLiveMappingIsBoundToItsSourceTable(root string) error {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(LiveMappingRelativePath)))
	if err != nil {
		return err
	}
	rendered, err := corpora.RenderHandshakeLiveMappingDocument()
	if err != nil {
		return fmt.Errorf("render the live handshake mapping from its source table: %w", err)
	}
	if string(raw) != string(rendered) {
		return fmt.Errorf("%s is not byte-identical to corpora.HandshakeVerdictMapping(), the source-derived "+
			"table it is rendered from. This document decides which handshake divergences the measurement can "+
			"DEMAND a record for, so an edit to it shrinks the universe the gate checks; it is re-derived here "+
			"rather than believed", LiveMappingRelativePath)
	}
	return nil
}

// ReadDivergentMappingRows returns every `divergent: true` row of the committed
// live handshake mapping. It fails closed on an empty document or an empty row,
// so the census can never run vacuously against a truncated artifact. The
// artifact's authenticity is VerifyLiveMappingIsBoundToItsSourceTable's job.
func ReadDivergentMappingRows(root string) ([]MappingRow, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(LiveMappingRelativePath)))
	if err != nil {
		return nil, err
	}
	var document liveMappingDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode %s: %w", LiveMappingRelativePath, err)
	}
	if len(document.Entries) == 0 {
		return nil, fmt.Errorf("%s yielded no entries; the census cannot run fail-open", LiveMappingRelativePath)
	}
	var rows []MappingRow
	for _, entry := range document.Entries {
		if !entry.Divergent {
			continue
		}
		if entry.Direction == "" || entry.Key == "" {
			return nil, fmt.Errorf("%s has a divergent row with an empty direction or key", LiveMappingRelativePath)
		}
		rows = append(rows, MappingRow{Direction: entry.Direction, Key: entry.Key})
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s recorded no divergent rows; the census cannot run fail-open", LiveMappingRelativePath)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].String() < rows[j].String() })
	return rows, nil
}

// ReadHandshakeCorpusCases decodes the live handshake corpus.
func ReadHandshakeCorpusCases(root string) ([]HandshakeCase, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(HandshakeCorpusRelativePath)))
	if err != nil {
		return nil, err
	}
	var cases []HandshakeCase
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var parsed HandshakeCase
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			return nil, fmt.Errorf("decode a line of %s: %w", HandshakeCorpusRelativePath, err)
		}
		cases = append(cases, parsed)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("%s yielded no cases", HandshakeCorpusRelativePath)
	}
	return cases, nil
}

// FamilyForRow derives the FAMILY SLUG for one mapping row FROM THE CORPUS,
// rather than from a hand-maintained table that could drift away from the
// evidence. The slug is the segment a ledger subject must carry for a record to
// count as being ABOUT that row (review BLOCKING 6).
//
// It resolves in the row's OWN direction first, because one reject code can
// legitimately mean different things on the two sides of the handshake — the
// corpus maps HS_MISSING_UPGRADE to `missing-upgrade` on client_request and to
// `response-missing-upgrade` on server_response. When the row's direction has no
// corpus case at all — which is the situation for all six divergent
// `server_response` rows, the very hole gap G3c named — it falls back to the
// family the code carries in the other direction, and only when that is
// unambiguous. Ambiguity is an error rather than a silently chosen winner,
// because a wrong slug would silently weaken the coverage rule.
func FamilyForRow(cases []HandshakeCase, row MappingRow) (string, error) {
	sameDirection := map[string]bool{}
	anyDirection := map[string]bool{}
	for _, one := range cases {
		if one.Expected.RejectCode != row.Key || one.Family == "" {
			continue
		}
		anyDirection[one.Family] = true
		if one.Direction == row.Direction {
			sameDirection[one.Family] = true
		}
	}
	pick := func(candidates map[string]bool) string {
		for family := range candidates {
			return family
		}
		return ""
	}
	switch {
	case len(sameDirection) == 1:
		return pick(sameDirection), nil
	case len(sameDirection) > 1:
		return "", fmt.Errorf("%s maps reject code %s in direction %s to %d families; the subject-slug binding "+
			"needs exactly one", HandshakeCorpusRelativePath, row.Key, row.Direction, len(sameDirection))
	case len(anyDirection) == 1:
		return pick(anyDirection), nil
	case len(anyDirection) > 1:
		return "", fmt.Errorf("%s has no case for reject code %s in direction %s, and the code carries %d different "+
			"families in the other direction, so no unambiguous subject slug can be required for row %s",
			HandshakeCorpusRelativePath, row.Key, row.Direction, len(anyDirection), row)
	default:
		return "", fmt.Errorf("reject code %s (mapping row %s) has no family anywhere in %s, so no subject slug can "+
			"be required for it; the coverage rule refuses to fall back to a token-only match",
			row.Key, row, HandshakeCorpusRelativePath)
	}
}

// ReadPublicScenarios decodes the public corpus AND re-derives every scenario's
// recorded expectation from that scenario's own steps, refusing the corpus if
// any committed line is not what executing its steps produces.
//
// WHY THE RE-DERIVATION LIVES HERE (round-3 finding 2). Every consumer of the
// public corpus in this package goes through this function, so binding the
// committed expectation to a re-derivation at this one chokepoint means no
// consumer can read a scenario whose recorded summary was never checked against
// its own program. The identity check used to exist only in
// internal/corpora/committed_test.go — a test binary the release path does not
// run — which is the same "rule that is not a gate" shape as round-1 finding 3.
//
// The comparison is on the COMMITTED BYTES: the line is rebuilt from the fields
// the corpus itself carries, with `expected` replaced by the reference model's
// derivation over `role`, `initial_state`, `limits` and `steps`, and rendered
// through the same canonical writer that wrote the corpus. So a forged count, a
// forged final state or a forged error code is a byte difference, not a matter
// of which fields somebody remembered to compare.
func ReadPublicScenarios(root string) ([]PublicScenario, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(PublicCorpusRelativePath)))
	if err != nil {
		return nil, err
	}
	var scenarios []PublicScenario
	var problems []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var scenario PublicScenario
		if err := json.Unmarshal([]byte(line), &scenario); err != nil {
			return nil, fmt.Errorf("decode a line of %s: %w", PublicCorpusRelativePath, err)
		}
		var envelope struct {
			Expected json.RawMessage `json:"expected"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			return nil, fmt.Errorf("decode the expected object of a line of %s: %w", PublicCorpusRelativePath, err)
		}
		if err := json.Unmarshal([]byte(line), &scenario.Core); err != nil {
			return nil, fmt.Errorf("decode the executable core of a line of %s: %w", PublicCorpusRelativePath, err)
		}
		scenario.ExpectedRaw = envelope.Expected
		scenario.CommittedLine = line
		if err := verifyScenarioReDerives(scenario); err != nil {
			problems = append(problems, err.Error())
		}
		scenarios = append(scenarios, scenario)
	}
	if len(scenarios) == 0 {
		return nil, fmt.Errorf("%s yielded no scenarios", PublicCorpusRelativePath)
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return nil, fmt.Errorf("public corpus re-derivation (%d scenario(s) do not equal what executing their own "+
			"steps produces):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return scenarios, nil
}

// verifyScenarioReDerives rebuilds one committed line with `expected` recomputed
// from the scenario's own steps and requires byte equality.
func verifyScenarioReDerives(scenario PublicScenario) error {
	expected, _, err := corpora.DeriveExpectedAndFailingStep(scenario.Core)
	if err != nil {
		return fmt.Errorf("%s: the reference model refuses to execute this scenario's own steps, so its recorded "+
			"expectation cannot be checked against them: %w", scenario.ScenarioID, err)
	}
	rebuilt, err := corpora.Scenario{
		ScenarioID:        scenario.ScenarioID,
		Tier:              scenario.Tier,
		Family:            scenario.Family,
		SeedIndex:         scenario.SeedIndex,
		Core:              scenario.Core,
		Expected:          expected,
		ExpectationBasis:  scenario.ExpectationBasis,
		ExpectationStatus: scenario.ExpectationStatus,
	}.CanonicalLine()
	if err != nil {
		return fmt.Errorf("%s: the re-derived scenario does not render canonically: %w", scenario.ScenarioID, err)
	}
	if string(rebuilt) != scenario.CommittedLine {
		return fmt.Errorf("%s: the committed line is NOT what executing its own steps produces. The recorded "+
			"expectation is evidence supplied alongside the scenario, and class membership turns on it, so it is "+
			"re-derived rather than believed.\n    committed:  %s\n    re-derived: %s",
			scenario.ScenarioID, scenario.CommittedLine, string(rebuilt))
	}
	return nil
}

// FailingStep derives WHICH STEP the recorded run stopped on BY EXECUTING THE
// SCENARIO'S OWN STEPS under the reference model. It is the discriminator the
// class predicate needs, and it is now derived from the scenario PROGRAM rather
// than from the summary recorded beside it.
//
// WHAT ROUND 3 FOUND, and why the previous derivation had to go. The prior
// implementation reconstructed the executed prefix from `expected.counts`: the
// unique prefix of the step list whose byte total and action count equal the
// recorded totals, with a refusal when the prefix was ambiguous. That is a
// derivation from evidence — but from evidence THE SAME PARTY SUPPLIES. The
// reviewer's attack: a VALID inbound 5-byte frame followed by a rejected local
// `send_close(999)`, recorded as `input_bytes=5, actions=0`. The true counts of
// that run are `input_bytes=5, actions=1`; understating the action count makes
// the bytes prefix the UNIQUE match, so the ambiguity refusal never fires, the
// failing step is reported as the `bytes` step, and a locally caused rejection
// is enrolled as an inbound decode rejection. Reproduced before this fix:
// `FailingStep` returned index 0 kind "bytes", `InProtocolRejectionClass`
// returned true, `LocallyCausedRejections` returned nothing, and with the
// scenario enrolled in the census and named by the class record
// `deltaledgerctl --check` exited 0.
//
// THE FIX IS TO STOP READING THE ANSWER FROM THE CLAIM. The reference model in
// internal/corpora executes `role`, `initial_state`, `limits` and `steps` and
// reports the index of the step whose execution raised the error. Counts are
// not consulted, so the party writing the scenario no longer supplies the fact
// that decides membership; they supply only the program, and the program is
// run. ReadPublicScenarios additionally requires each committed line to EQUAL
// its re-derivation, so a scenario whose recorded expectation disagrees with
// its own execution is refused before any predicate sees it.
//
// IF THE SCENARIO'S OWN STEPS CANNOT SETTLE IT, THIS REFUSES. A step vocabulary
// the reference model does not know, a role or limit outside the model's space,
// or undecodable step data all produce an error rather than a fallback to the
// counts. There is deliberately no fallback: the counts are exactly the input
// the attack controls.
//
// It returns index -1 with no error when the run did not stop at all — the
// scenario's outcome is `ok`, so there is no failing step to find.
func FailingStep(scenario PublicScenario) (int, ScenarioStep, error) {
	derived, index, err := corpora.DeriveExpectedAndFailingStep(scenario.Core)
	if err != nil {
		return 0, ScenarioStep{}, fmt.Errorf("%s: the failing step cannot be derived by executing this scenario's "+
			"own steps, and this refuses rather than falling back to the recorded counts, which are supplied by "+
			"whoever writes the scenario: %w", scenario.ScenarioID, err)
	}
	if err := failingStepEvidenceAgrees(scenario, derived); err != nil {
		return 0, ScenarioStep{}, err
	}
	if index < 0 {
		return -1, ScenarioStep{}, nil
	}
	if index >= len(scenario.Steps) {
		return 0, ScenarioStep{}, fmt.Errorf("%s: execution stopped on step %d but the committed step list has %d "+
			"step(s)", scenario.ScenarioID, index, len(scenario.Steps))
	}
	return index, scenario.Steps[index], nil
}

// failingStepEvidenceAgrees requires the scenario's RECORDED expectation to
// agree with what executing its steps produces, on every field the class
// predicate and the census read. ReadPublicScenarios enforces the stronger
// whole-line equality; this keeps FailingStep safe when it is called on a
// scenario that did not come through that path, so the discriminator can never
// be used against an expectation nobody checked.
func failingStepEvidenceAgrees(scenario PublicScenario, derived corpora.Expected) error {
	mismatch := func(field string, recorded, executed any) error {
		return fmt.Errorf("%s: recorded %s is %v but executing the scenario's own steps produces %v. The recorded "+
			"expectation is supplied alongside the scenario and class membership turns on it, so a disagreement is "+
			"refused rather than resolved in favour of the record", scenario.ScenarioID, field, recorded, executed)
	}
	if scenario.Expected.Outcome != derived.Outcome {
		return mismatch("outcome", scenario.Expected.Outcome, derived.Outcome)
	}
	if scenario.Expected.FinalState != derived.FinalState {
		return mismatch("final_state", scenario.Expected.FinalState, derived.FinalState)
	}
	if (scenario.Expected.Error == nil) != (derived.Error == nil) {
		return mismatch("error presence", scenario.Expected.Error != nil, derived.Error != nil)
	}
	if scenario.Expected.Error != nil && derived.Error != nil {
		if scenario.Expected.Error.Code != derived.Error.Code {
			return mismatch("error.code", scenario.Expected.Error.Code, derived.Error.Code)
		}
		// error.close_code is DELIBERATELY not compared here. It is not a
		// membership input — the close-code set is a derived consistency
		// assertion in VerifyProtocolRejectionClass, never a filter — and
		// binding it here would make it impossible to state, as a test does,
		// that a hypothetical member carrying another code is still IN the
		// class. It is bound in production all the same, by
		// ReadPublicScenarios' whole-line re-derivation, which compares every
		// recorded field including this one.
	}
	if derived.Counts == nil {
		return fmt.Errorf("%s: executing the scenario's own steps produced no counts", scenario.ScenarioID)
	}
	if scenario.Expected.Counts.InputBytes != derived.Counts.InputBytes {
		return mismatch("counts.input_bytes", scenario.Expected.Counts.InputBytes, derived.Counts.InputBytes)
	}
	if scenario.Expected.Counts.Actions != derived.Counts.Actions {
		return mismatch("counts.actions", scenario.Expected.Counts.Actions, derived.Counts.Actions)
	}
	if scenario.Expected.Counts.ConsumedBytes != derived.Counts.ConsumedBytes {
		return mismatch("counts.consumed_bytes", scenario.Expected.Counts.ConsumedBytes, derived.Counts.ConsumedBytes)
	}
	return nil
}

// InProtocolRejectionClass is the class predicate, selecting by the stated
// CAUSE rather than by result shape.
//
// THE CLASS, stated exactly: an INBOUND FRAME DECODE that the pinned Java
// decoder rejects with an InvalidDataException, where the recorded ready state
// nevertheless stays OPEN because the oracle adapter never routes through
// WebSocketImpl.decodeFrames and therefore never reaches its close ladder.
//
// The predicate is therefore:
//
//	outcome == error
//	AND error.code == JAVA_INVALID_DATA   (the decoder's typed rejection: the CAUSE)
//	AND final_state == open               (the observable the class is about)
//	AND the FAILING STEP is a `bytes` step (the rejection was raised while
//	                                        decoding inbound wire data)
//
// There is deliberately NO conjunct on `counts`. An earlier version carried a
// redundant `counts.input_bytes > 0` alongside the failing-step test; it is
// removed rather than kept, because a redundant conjunct that reads like the
// rejected aggregate rule is exactly what let the artifacts go on describing
// the rejected rule (round-3 finding 1). What a bytes step is, and whether the
// run stopped on one, is now settled by execution.
//
// WHAT CHANGED IN ROUND 1 (review 01a0495e BLOCKING 4). The original predicate
// selected on `error.close_code in {1002,1007,1009}` — a result shape, not a
// cause. It enrolled us005.pub.0000, a LOCALLY INITIATED `send_close(999)` with
// input_bytes 0: no inbound byte was ever decoded. RFC 6455 section 7.1.7
// requires closing only where some other algorithm or provision requires _Fail
// the WebSocket Connection_, and an application making an invalid local API
// call is not such a provision, so the census's claim that the RFC-strict state
// there is `closed` was wrong. That scenario is separately and correctly
// ledgered at sequence 35 (websocketimpl.rejected-local-close-readystate).
//
// WHAT CHANGED IN ROUND 2, and why the first fix was not enough. The round-1
// predicate replaced the close-code shape with an AGGREGATE over the whole
// scenario — "some inbound byte arrived somewhere" — rather than a fact about
// the step that failed. Review round 2 named the hole exactly: a VALID inbound
// frame followed by a local `send_close(999)` carries inbound bytes and
// JAVA_INVALID_DATA and final_state open, so it satisfied every conjunct while
// its error is locally caused — the identical mistake us005.pub.0000 was, one
// level less obvious. Reproduced before that fix by appending exactly that
// scenario to the corpus, enrolling it, and reading `deltaledgerctl --check`
// exit 0 with the class record claiming it.
//
// WHAT CHANGED IN ROUND 3, and why the SECOND fix was not enough either. Round
// 2 made membership turn on the failing step, but derived that step from
// `expected.counts` — the summary the scenario's own author writes. Recording
// `input_bytes=5, actions=0` for a run that really executed a valid frame and
// then a rejected local close makes the bytes prefix the unique match, so the
// ambiguity refusal never fires and the local failure is enrolled anyway.
// Reproduced by execution before this fix. The step is now derived by EXECUTING
// the scenario's steps under the reference model (see FailingStep), and the
// counts decide nothing.
//
// The close-code set is not the boundary and is not a filter. It survives as a
// derived CONSISTENCY ASSERTION (VerifyProtocolRejectionClass): every member
// must in fact carry 1002, 1007 or 1009, so a future member arriving with
// another code fails loudly instead of being silently excluded.
//
// The three error/open scenarios excluded for cause — us005.pub.0030
// (ACTION_LIMIT_EXCEEDED), 0032 (FRAME_LIMIT_EXCEEDED) and 0044
// (INPUT_LIMIT_EXCEEDED) — are harness envelope-limit refusals, not decoder
// rejections; their error.code is not JAVA_INVALID_DATA.
func InProtocolRejectionClass(scenario PublicScenario) (bool, error) {
	expected := scenario.Expected
	if expected.Outcome != "error" || expected.FinalState != "open" {
		return false, nil
	}
	if expected.Error == nil || expected.Error.Code != "JAVA_INVALID_DATA" {
		return false, nil
	}
	index, step, err := FailingStep(scenario)
	if err != nil {
		return false, err
	}
	if index < 0 {
		return false, nil
	}
	return step.Kind == "bytes", nil
}

// LocallyCausedRejection is one scenario that carries every CAUSE marker of the
// protocol-rejection class except the failing-step one: the decoder's typed
// rejection code and a final state of open, but with the run stopping on a
// LOCAL action rather than on inbound wire data.
type LocallyCausedRejection struct {
	ScenarioID string
	StepIndex  int
	StepKind   string
	Action     string
}

func (r LocallyCausedRejection) String() string {
	return fmt.Sprintf("%s (stopped on step %d, kind %q, action %q)", r.ScenarioID, r.StepIndex, r.StepKind, r.Action)
}

// LocallyCausedRejections returns those scenarios.
//
// They are surfaced rather than silently dropped. A scenario in this shape is a
// real proposition about a locally caused rejection that leaves the endpoint
// open — the sequence-35 proposition — and the point of round 2's finding is
// that the gate must be able to tell the two apart out loud, not merely stop
// enrolling one of them.
//
// ROUND-3 CHANGE: this used to be scoped by `counts.input_bytes > 0`, which
// excluded us005.pub.0000 (a pure local close with no inbound byte) by an
// AGGREGATE the scenario supplies. The scoping is gone: every locally caused
// rejection is returned, and VerifyProtocolRejectionClass decides which of them
// are already answered by an authoritative ledger record. Exclusion by "a
// record says so" is checkable; exclusion by "the counts say so" was one more
// place the constrained party supplied the constraint's input.
func LocallyCausedRejections(scenarios []PublicScenario) ([]LocallyCausedRejection, error) {
	var locally []LocallyCausedRejection
	for _, scenario := range scenarios {
		expected := scenario.Expected
		if expected.Outcome != "error" || expected.FinalState != "open" {
			continue
		}
		if expected.Error == nil || expected.Error.Code != "JAVA_INVALID_DATA" {
			continue
		}
		index, step, err := FailingStep(scenario)
		if err != nil {
			return nil, err
		}
		if index >= 0 && step.Kind != "bytes" {
			locally = append(locally, LocallyCausedRejection{
				ScenarioID: scenario.ScenarioID, StepIndex: index, StepKind: step.Kind, Action: step.Action})
		}
	}
	sort.Slice(locally, func(i, j int) bool { return locally[i].ScenarioID < locally[j].ScenarioID })
	return locally, nil
}

// protocolRejectionCloseCodes is the derived consistency assertion described
// above, never a membership filter.
var protocolRejectionCloseCodes = map[int]bool{1002: true, 1007: true, 1009: true}

// ReadCensus decodes and envelope-checks the committed census. Unlike its
// predecessor it enforces the `$schema` pointer and `census_id`, and requires
// the schema file to exist, so a document naming a contract that is not there
// fails instead of passing silently.
func ReadCensus(root string) (CensusDocument, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(CensusRelativePath)))
	if err != nil {
		return CensusDocument{}, err
	}
	var document CensusDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return CensusDocument{}, fmt.Errorf("decode %s: %w", CensusRelativePath, err)
	}
	if document.SchemaVersion != "1.0.0" || document.EvidenceKind != "public-rfc-divergence-census" {
		return CensusDocument{}, fmt.Errorf("%s envelope drifted: version=%q kind=%q",
			CensusRelativePath, document.SchemaVersion, document.EvidenceKind)
	}
	if document.CensusID != "us005-public-rfc-divergence-census" {
		return CensusDocument{}, fmt.Errorf("%s census_id drifted: %q", CensusRelativePath, document.CensusID)
	}
	if document.Schema != "../schemas/public-rfc-divergence-census-1.0.0.schema.json" {
		return CensusDocument{}, fmt.Errorf("%s $schema pointer drifted: %q", CensusRelativePath, document.Schema)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(CensusSchemaRelativePath))); err != nil {
		return CensusDocument{}, fmt.Errorf("%s names schema %s, which does not exist: %w",
			CensusRelativePath, CensusSchemaRelativePath, err)
	}
	if len(document.Entries) == 0 {
		return CensusDocument{}, fmt.Errorf("%s has no entries; the gate would be vacuous", CensusRelativePath)
	}
	if document.Statement != CensusStatement {
		return CensusDocument{}, fmt.Errorf("%s `statement` is not the statement this gate makes. The document's "+
			"account of itself is pinned to internal/deltaledger.CensusStatement, because a prose field that is "+
			"decoded and never compared is how the rejected counts.input_bytes>0 rule survived a round after the "+
			"code replaced it.\n    committed: %q", CensusRelativePath, document.Statement)
	}
	if document.Completeness != CensusCompleteness {
		return CensusDocument{}, fmt.Errorf("%s `completeness` is not the completeness claim this gate supports. It "+
			"is pinned to internal/deltaledger.CensusCompleteness.\n    committed: %q",
			CensusRelativePath, document.Completeness)
	}
	return document, nil
}

// EvidenceDemand is one divergence the COMMITTED EVIDENCE records, expressed
// independently of whether any definition or ledger record exists for it. The
// point of the type is that a demand can exist with nothing on the ledger side
// answering it — which is the state the previous design could not represent.
type EvidenceDemand struct {
	// ID is the stable demand identity, e.g.
	// "mapping-row direction=server_response key=HS_BARE_LF" or
	// "public-scenario us005.pub.0005 /final_state".
	ID string
	// Kind is "handshake-mapping-row" or "public-corpus-protocol-rejection".
	Kind string
	// Source is the committed artifact the demand was swept from.
	Source string
}

func (d EvidenceDemand) String() string { return d.Kind + ": " + d.ID }

// EvidenceDemands sweeps both arms of the evidence-derived universe.
func EvidenceDemands(root string) ([]EvidenceDemand, error) {
	rows, err := ReadDivergentMappingRows(root)
	if err != nil {
		return nil, err
	}
	demands := make([]EvidenceDemand, 0, len(rows))
	for _, row := range rows {
		demands = append(demands, EvidenceDemand{
			ID:     row.CitationToken(),
			Kind:   "handshake-mapping-row",
			Source: LiveMappingRelativePath,
		})
	}
	scenarios, err := ReadPublicScenarios(root)
	if err != nil {
		return nil, err
	}
	for _, scenario := range scenarios {
		member, err := InProtocolRejectionClass(scenario)
		if err != nil {
			return nil, err
		}
		if !member {
			continue
		}
		demands = append(demands, EvidenceDemand{
			ID:     "public-scenario " + scenario.ScenarioID + " /final_state",
			Kind:   "public-corpus-protocol-rejection",
			Source: PublicCorpusRelativePath,
		})
	}
	sort.Slice(demands, func(i, j int) bool { return demands[i].String() < demands[j].String() })
	return demands, nil
}

// coveringDefinitionsForRow returns the definitions that cover one divergent
// mapping row SEMANTICALLY. All three conditions must hold:
//
//  1. the definition's subject names the endpoint ROLE that parses this
//     direction (`server-handshake.` for client_request, `client-handshake.`
//     for server_response);
//  2. the definition's subject carries the FAMILY SLUG the corpus assigns to
//     this reject code (derived from corpora/handshake/cases.jsonl, not from a
//     hand table);
//  3. the definition CITES the row, either by the literal
//     `mapping-row direction=<dir> key=<KEY>` token, or by naming a handshake
//     corpus case whose own (direction, reject_code) is exactly this row.
//
// Condition 3 alone was the previous rule, and review BLOCKING 6 reproduced its
// failure: pasting six citation tokens into an unrelated record's prose kept
// coverage after the six meaningful records were deleted. Conditions 1 and 2
// are what refuse that, because the unrelated record's subject names neither
// the role nor the family.
func coveringDefinitionsForRow(row MappingRow, definitions []Definition,
	cases []HandshakeCase, casesByRow map[MappingRow][]string) ([]string, error) {
	role, known := parsingRoleForDirection[row.Direction]
	if !known {
		return nil, fmt.Errorf("mapping row %s has no known parsing role; add the direction to "+
			"parsingRoleForDirection and bind it to a subject segment", row)
	}
	family, err := FamilyForRow(cases, row)
	if err != nil {
		return nil, err
	}
	citedCases := map[string]bool{}
	for _, id := range casesByRow[row] {
		citedCases[id] = true
	}
	// A SUPERSEDED record does not cover anything. Sequences 14-16 bound a
	// wrong RFC basis and are superseded by 45-47; a row whose only claimant is
	// a withdrawn record is an UNCOVERED row, and saying so is the point of
	// making supersession machine-visible at all (review BLOCKING 8).
	superseded := supersededSubjects(definitions)
	var covering []string
	for _, definition := range definitions {
		if superseded[definition.Subject] {
			continue
		}
		if !subjectHasSegment(definition.Subject, role) || !subjectHasSegment(definition.Subject, family) {
			continue
		}
		text := definitionText(definition)
		cites := strings.Contains(text, row.CitationToken())
		if !cites {
			for _, id := range handshakeCaseCitation.FindAllString(text, -1) {
				if citedCases[id] {
					cites = true
					break
				}
			}
		}
		if cites {
			covering = append(covering, definition.Subject)
		}
	}
	sort.Strings(covering)
	return covering, nil
}

// subjectHasSegment reports whether a dot-separated SEGMENT of a subject equals
// the given token.
//
// It replaces `strings.Contains(subject, "."+token)`, found in this branch's own
// adversarial pass. That test had no trailing boundary, so the family slug
// `missing-host` also matched a subject segment `missing-hostname`, and the role
// test `"."+role+"."` matched a segment that merely CONTAINED the role. Both are
// the substring-standing-in-for-a-parse shape the two rounds before this one
// were about, in the check whose whole purpose is to decide whether a record is
// ABOUT a row. Segment equality is the parse.
func subjectHasSegment(subject, segment string) bool {
	if segment == "" {
		return false
	}
	for _, part := range strings.Split(subject, ".") {
		if part == segment {
			return true
		}
	}
	return false
}

// VerifyHandshakeMappingCensus is the evidence-side census: every divergent row
// of the committed live mapping must be covered by exactly one ledger record
// that is demonstrably ABOUT it, and no record may cite a row that the evidence
// does not record as divergent.
func VerifyHandshakeMappingCensus(root string, definitions []Definition) error {
	rows, err := ReadDivergentMappingRows(root)
	if err != nil {
		return err
	}
	cases, err := ReadHandshakeCorpusCases(root)
	if err != nil {
		return err
	}
	casesByRow := map[MappingRow][]string{}
	for _, one := range cases {
		if one.Expected.RejectCode == "" {
			continue
		}
		key := MappingRow{Direction: one.Direction, Key: one.Expected.RejectCode}
		casesByRow[key] = append(casesByRow[key], one.CaseID)
	}

	var problems []string
	divergent := map[MappingRow]bool{}
	for _, row := range rows {
		divergent[row] = true
	}
	for _, row := range rows {
		covering, err := coveringDefinitionsForRow(row, definitions, cases, casesByRow)
		if err != nil {
			return err
		}
		if len(covering) == 0 {
			problems = append(problems, fmt.Sprintf(
				"divergent live-mapping row %s has NO authoritative ledger record about it. A record covers this row "+
					"only if it is not itself superseded, its subject names the parsing role for direction %s AND "+
					"carries the corpus family slug for %s, AND it cites the row (literal `%s`, or a handshake corpus "+
					"case with that exact direction and reject code). Evidence in, coverage required out: the "+
					"source-side quirk census cannot see a divergence the shipped sources do not name with a Q-token.",
				row, row.Direction, row.Key, row.CitationToken()))
		}
	}
	// Fail-closed other half: a record may not claim a row the evidence does
	// not record as divergent, so the census cannot be satisfied by inventing
	// a token.
	for _, definition := range definitions {
		for _, match := range MappingRowCitation.FindAllStringSubmatch(definitionText(definition), -1) {
			row := MappingRow{Direction: match[1], Key: match[2]}
			if !divergent[row] {
				problems = append(problems, fmt.Sprintf(
					"%s cites mapping row %s, which is not a `divergent: true` row of %s",
					definition.Subject, row, LiveMappingRelativePath))
			}
		}
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("handshake mapping census (%d problem(s)):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// VerifyProtocolRejectionClass re-derives the class from the committed corpus
// and requires the census to enumerate exactly it, then asserts the derived
// close-code consistency property described on InProtocolRejectionClass.
//
// It takes the definitions because the locally-caused arm now asks whether an
// AUTHORITATIVE ledger record names the scenario, rather than excluding it by
// an aggregate count the scenario itself supplies.
func VerifyProtocolRejectionClass(root string, definitions []Definition) error {
	document, err := ReadCensus(root)
	if err != nil {
		return err
	}
	scenarios, err := ReadPublicScenarios(root)
	if err != nil {
		return err
	}
	derived := map[string]PublicScenario{}
	for _, scenario := range scenarios {
		member, err := InProtocolRejectionClass(scenario)
		if err != nil {
			return err
		}
		if member {
			derived[scenario.ScenarioID] = scenario
		}
	}
	if len(derived) == 0 {
		return fmt.Errorf("the class predicate matched nothing in %s; it cannot be validating anything",
			PublicCorpusRelativePath)
	}
	enrolled := map[string]bool{}
	for _, entry := range document.Entries {
		if entry.Class == ProtocolRejectionClass {
			enrolled[entry.ScenarioID] = true
		}
	}
	var problems []string
	for id := range derived {
		if !enrolled[id] {
			problems = append(problems, fmt.Sprintf(
				"public-corpus scenario %s is in the %s class but is ABSENT from %s (predicate: outcome==error AND "+
					"error.code==JAVA_INVALID_DATA AND final_state==open AND the step the run stopped on, derived by "+
					"EXECUTING the scenario's own steps, is a `bytes` step)",
				id, ProtocolRejectionClass, CensusRelativePath))
		}
	}
	for id := range enrolled {
		if _, in := derived[id]; !in {
			problems = append(problems, fmt.Sprintf("%s enrolls %s, which is NOT in the class by the cause predicate",
				CensusRelativePath, id))
		}
	}
	for id, scenario := range derived {
		if scenario.Expected.Error == nil || !protocolRejectionCloseCodes[scenario.Expected.Error.CloseCode] {
			code := 0
			if scenario.Expected.Error != nil {
				code = scenario.Expected.Error.CloseCode
			}
			problems = append(problems, fmt.Sprintf(
				"%s is in the %s class but carries close code %d, outside the recorded {1002,1007,1009}. This is a "+
					"derived consistency property, not a membership filter: a new member with another code is a "+
					"decision to be made and ledgered, not a row to be silently excluded",
				id, ProtocolRejectionClass, code))
		}
	}
	// A scenario that carries every CAUSE marker of the class but stopped on a
	// LOCAL action is not a member — and is not silently dropped either. It is a
	// different proposition (a locally caused rejection that leaves the endpoint
	// open, which sequence 35 ledgers) and it has to be decided deliberately,
	// exactly as a member arriving with an unrecorded close code does. The one
	// way out is an AUTHORITATIVE ledger record that names the scenario; a
	// superseded record does not answer for anything.
	locally, err := LocallyCausedRejections(scenarios)
	if err != nil {
		return err
	}
	classCovering := map[string]bool{}
	for _, entry := range document.Entries {
		if entry.Class == ProtocolRejectionClass && entry.LedgerDeltaID != "" {
			classCovering[entry.LedgerDeltaID] = true
		}
	}
	authoritativelyNamed, err := scenariosNamedByAuthoritativeRecords(definitions, classCovering)
	if err != nil {
		return err
	}
	for _, one := range locally {
		if authoritativelyNamed[one.ScenarioID] {
			continue
		}
		problems = append(problems, fmt.Sprintf(
			"%s carries the %s cause markers (error.code JAVA_INVALID_DATA, final_state open) but the run STOPPED ON "+
				"A LOCAL ACTION, so its error is locally caused and it is NOT a member of the class. It is the "+
				"sequence-35 proposition, not this one, and no authoritative ledger record names it. Ledger it "+
				"deliberately or remove it; it is reported rather than filtered away, because an aggregate "+
				"whole-scenario byte test used to enrol exactly this shape", one, ProtocolRejectionClass))
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("protocol-rejection class completeness (%d problem(s)):\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// scenariosNamedByAuthoritativeRecords is the set of public-corpus scenario ids
// that some NOT-SUPERSEDED definition's hashed preimages discuss, EXCLUDING the
// records that cover class rows.
//
// WHY THE EXCLUSION (found in this branch's own adversarial pass). The escape
// hatch for a locally caused rejection is "an authoritative record names it",
// and naming is a token appearing in the record's hashed text. The CLASS record
// names non-members too, in the sentence that says why they are excluded —
// us005.pub.0000 appears in exactly such a sentence at sequence 48. Letting the
// class record answer for a scenario the class excludes would make the class's
// own exclusion note double as the authority for the excluded scenario, which
// is circular: the record that defines the class cannot also be the record that
// speaks for something outside it. A non-member is a different proposition and
// needs a record of its own, which is what sequence 35 is for us005.pub.0000.
//
// `classCovering` is the set of delta ids the census names for class rows, so
// the exclusion is DERIVED from the committed census rather than naming a
// record by hand.
func scenariosNamedByAuthoritativeRecords(definitions []Definition, classCovering map[string]bool) (
	map[string]bool, error) {
	deltas, err := buildDeltasFrom(definitions)
	if err != nil {
		return nil, err
	}
	if len(deltas) != len(definitions) {
		return nil, fmt.Errorf("built %d deltas for %d definitions", len(deltas), len(definitions))
	}
	superseded := supersededSubjects(definitions)
	named := map[string]bool{}
	for index, definition := range definitions {
		if superseded[definition.Subject] || classCovering[deltas[index].DeltaID] {
			continue
		}
		for _, id := range publicScenarioCitation.FindAllString(definitionText(definition), -1) {
			named[id] = true
		}
	}
	return named, nil
}

// censusClasses and censusPortFollows are the closed vocabularies a census row
// may use. They are closed on purpose: a field checked only for non-emptiness
// accepts an unrelated but plausible value, which is the shape of three of this
// review's six findings.
var (
	censusClasses     = map[string]bool{ProtocolRejectionClass: true}
	censusPortFollows = map[string]bool{"java-adapter-path": true}
)

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// ClassObservablePointer is the pointer the protocol-rejection class is ABOUT.
// The class proposition is a statement about the RESULTING READY STATE, so a
// row that enrols in the class and points somewhere else is not making the
// class's claim at all.
const ClassObservablePointer = "/final_state"

// ResolveExpectedPointer resolves an RFC 6901 JSON pointer against a scenario's
// committed `expected` object and renders the value the way the census writes
// it. An unresolvable pointer is an error, never an empty string: the census
// asserts a proposition AT a pointer, and a proposition about a location that
// does not exist is not a weaker claim, it is an unverifiable one.
func ResolveExpectedPointer(scenario PublicScenario, pointer string) (string, error) {
	if len(scenario.ExpectedRaw) == 0 {
		return "", fmt.Errorf("%s carries no recorded `expected` object", scenario.ScenarioID)
	}
	if pointer == "" {
		return "", fmt.Errorf("%s: the census row names no pointer, so it asserts its observable of nothing",
			scenario.ScenarioID)
	}
	if !strings.HasPrefix(pointer, "/") {
		return "", fmt.Errorf("%s: %q is not an RFC 6901 JSON pointer into the recorded expectation",
			scenario.ScenarioID, pointer)
	}
	var value any
	if err := json.Unmarshal(scenario.ExpectedRaw, &value); err != nil {
		return "", fmt.Errorf("%s: decode the recorded expectation: %w", scenario.ScenarioID, err)
	}
	for _, token := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch container := value.(type) {
		case map[string]any:
			next, exists := container[token]
			if !exists {
				return "", fmt.Errorf("%s: pointer %q does not resolve against the recorded expectation (no member %q)",
					scenario.ScenarioID, pointer, token)
			}
			value = next
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(container) {
				return "", fmt.Errorf("%s: pointer %q does not resolve against the recorded expectation "+
					"(bad array index %q)", scenario.ScenarioID, pointer, token)
			}
			value = container[index]
		default:
			return "", fmt.Errorf("%s: pointer %q descends into a scalar at %q",
				scenario.ScenarioID, pointer, token)
		}
	}
	switch rendered := value.(type) {
	case string:
		return rendered, nil
	case bool:
		return strconv.FormatBool(rendered), nil
	case float64:
		if rendered == float64(int64(rendered)) {
			return strconv.FormatInt(int64(rendered), 10), nil
		}
		return strconv.FormatFloat(rendered, 'g', -1, 64), nil
	case nil:
		return "null", nil
	default:
		return "", fmt.Errorf("%s: pointer %q resolves to a composite value, which a census row's "+
			"recorded_observable cannot state", scenario.ScenarioID, pointer)
	}
}

// VerifyCensusRowsMatchEvidence binds every census row to the corpus facts it
// claims, so the census cannot drift into a story of its own.
//
// ROUND-2 FINDING, reproduced before it was fixed: the observable comparison
// was guarded by `entry.Pointer == "/final_state"` and NOTHING required that
// pointer, so rewriting a row's pointer to any other syntactically valid string
// skipped the comparison entirely while enrollment and ledger coverage still
// passed by scenario id. Reading `/counts/wire_buffered_bytes` with a
// recorded_observable of free prose left `deltaledgerctl --check` at exit 0.
// Every row's pointer must now RESOLVE against the recorded expectation and its
// recorded_observable must equal the value found there, and a row enrolled in
// the protocol-rejection class must additionally point at the observable that
// class is about.
func VerifyCensusRowsMatchEvidence(root string) error {
	document, err := ReadCensus(root)
	if err != nil {
		return err
	}
	scenarios, err := ReadPublicScenarios(root)
	if err != nil {
		return err
	}
	byID := map[string]PublicScenario{}
	for _, scenario := range scenarios {
		byID[scenario.ScenarioID] = scenario
	}
	var problems []string
	for _, entry := range document.Entries {
		scenario, exists := byID[entry.ScenarioID]
		if !exists {
			problems = append(problems, fmt.Sprintf("census cites %s, which is not in the public corpus", entry.ScenarioID))
			continue
		}
		// The row's own account of HOW it was selected has to be the account
		// the gate actually runs. Round-3 finding 1: `derivation` was decoded
		// and never read, so eighteen committed rows went on stating the
		// aggregate predicate round 2 had already replaced.
		if entry.Class == ProtocolRejectionClass && entry.Derivation != ProtocolRejectionClassDerivation {
			problems = append(problems, fmt.Sprintf(
				"%s: the row's `derivation` is not the derivation this gate runs. A census row states how it was "+
					"selected; if that statement is not compared to the selection, the authoritative artifact can "+
					"describe a rule the code no longer implements — which is exactly what happened to the "+
					"counts.input_bytes>0 wording. The required text is "+
					"internal/deltaledger.ProtocolRejectionClassDerivation.\n    committed: %q",
				entry.ScenarioID, entry.Derivation))
		}
		if entry.Class == ProtocolRejectionClass && entry.Pointer != ClassObservablePointer {
			problems = append(problems, fmt.Sprintf(
				"%s: the row enrols in the %s class but points at %q. That class is a proposition about the RESULTING "+
					"READY STATE, so a member row must assert it at %s; pointing elsewhere makes a different claim "+
					"under the class's name",
				entry.ScenarioID, ProtocolRejectionClass, entry.Pointer, ClassObservablePointer))
		}
		recorded, err := ResolveExpectedPointer(scenario, entry.Pointer)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v. A census row asserts recorded_observable %q AT a pointer; "+
				"the pointer must resolve against the committed expectation or the assertion binds nothing",
				entry.ScenarioID, err, entry.RecordedObservable))
		} else if recorded != entry.RecordedObservable {
			problems = append(problems, fmt.Sprintf("%s%s: census records %q but the corpus expectation is %q",
				entry.ScenarioID, entry.Pointer, entry.RecordedObservable, recorded))
		}
		if entry.Family != scenario.Family {
			problems = append(problems, fmt.Sprintf("%s: census family %q != corpus family %q",
				entry.ScenarioID, entry.Family, scenario.Family))
		}
		if scenario.Expected.Error != nil && entry.RecordedCloseCode != scenario.Expected.Error.CloseCode {
			problems = append(problems, fmt.Sprintf("%s: census close code %d != corpus close code %d",
				entry.ScenarioID, entry.RecordedCloseCode, scenario.Expected.Error.CloseCode))
		}
		if strings.TrimSpace(entry.JavaEntryPointNote) == "" {
			problems = append(problems, fmt.Sprintf("%s: every row must carry the java_entry_point_note; flattening "+
				"this divergence back into a binary RFC-versus-Java split is the specific misreading the note exists "+
				"to prevent", entry.ScenarioID))
		}
		if len(entry.RFCClauses) == 0 || len(entry.Evidence) == 0 {
			problems = append(problems, fmt.Sprintf("%s: row names no RFC clause or no evidence", entry.ScenarioID))
		}
		// The same class of defect the pointer had, applied to the row's other
		// resolvable fields: a value that is merely non-empty, or merely
		// syntactically fine, is not a checked claim. `class` and `port_follows`
		// come from closed vocabularies, and an in-repository evidence citation
		// has to be a file a reader can open — the same rule the observation
		// provenance already lives under.
		if !censusClasses[entry.Class] {
			problems = append(problems, fmt.Sprintf("%s: class %q is outside the recorded vocabulary %v. A new class "+
				"needs its own derivation and its own gate, not a new string in this field",
				entry.ScenarioID, entry.Class, sortedKeys(censusClasses)))
		}
		if !censusPortFollows[entry.PortFollows] {
			problems = append(problems, fmt.Sprintf("%s: port_follows %q is outside the recorded vocabulary %v",
				entry.ScenarioID, entry.PortFollows, sortedKeys(censusPortFollows)))
		}
		for _, citation := range entry.Evidence {
			if mustResolve, resolved := ProvenanceIsResolvable(root, citation); mustResolve && !resolved {
				problems = append(problems, fmt.Sprintf("%s: row cites evidence %s, which does not exist",
					entry.ScenarioID, citation))
			}
		}
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("census rows versus committed evidence (%d problem(s)):\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// VerifyCensusRowsAreLedgered is the coverage gate, and it now checks the RIGHT
// record rather than merely SOME record.
//
// Review BLOCKING 5 reproduced the old rule's failure: repointing every census
// row at the unrelated sequence-1 record (a server-handshake missing-Host
// divergence) left the census green, because membership in the delta-id set was
// the whole test. The rule below additionally requires the record named by
// `ledger_delta_id` to NAME THE SCENARIO in its own hashed digest preimage, so
// a record can only cover rows it actually discusses. A catch-all class record
// is still allowed — that is a legitimate shape when nineteen scenarios share
// one mechanism — but it has to enumerate the scenarios it claims.
func VerifyCensusRowsAreLedgered(root string, definitions []Definition) error {
	document, err := ReadCensus(root)
	if err != nil {
		return err
	}
	deltas, err := buildDeltasFrom(definitions)
	if err != nil {
		return err
	}
	if len(deltas) != len(definitions) {
		return fmt.Errorf("built %d deltas for %d definitions", len(deltas), len(definitions))
	}
	definitionByDelta := map[string]Definition{}
	for index, delta := range deltas {
		definitionByDelta[delta.DeltaID] = definitions[index]
	}
	superseded := supersededSubjects(definitions)
	var problems []string
	for _, entry := range document.Entries {
		if entry.LedgerDeltaID == "" {
			problems = append(problems, fmt.Sprintf("%s%s names no ledger record", entry.ScenarioID, entry.Pointer))
			continue
		}
		definition, exists := definitionByDelta[entry.LedgerDeltaID]
		if !exists {
			problems = append(problems, fmt.Sprintf(
				"%s%s names ledger record %s, which is not in the chain",
				entry.ScenarioID, entry.Pointer, entry.LedgerDeltaID))
			continue
		}
		// A WITHDRAWN record covers nothing. Found in this branch's own
		// adversarial pass: this rule checked that the named record exists and
		// discusses the scenario, but not that it is still the authoritative
		// statement of its subject, so a census row could be answered by a
		// record the chain itself records as superseded.
		if superseded[definition.Subject] {
			problems = append(problems, fmt.Sprintf(
				"%s%s names ledger record %s (%s), which the chain records as SUPERSEDED. A withdrawn record stays "+
					"in the chain with its digest intact, but it is no longer the authoritative statement of its "+
					"subject and so it covers nothing",
				entry.ScenarioID, entry.Pointer, entry.LedgerDeltaID, definition.Subject))
			continue
		}
		named := false
		for _, id := range publicScenarioCitation.FindAllString(definitionText(definition), -1) {
			if id == entry.ScenarioID {
				named = true
				break
			}
		}
		if !named {
			problems = append(problems, fmt.Sprintf(
				"%s%s names ledger record %s (%s), but that record's digest preimages never mention %s. Coverage "+
					"must be by MEANING: a record covers a census row only if it says something about that scenario.",
				entry.ScenarioID, entry.Pointer, entry.LedgerDeltaID, definition.Subject, entry.ScenarioID))
		}
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("census coverage by the ledger (%d problem(s)):\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// UnledgeredEvidenceDemands returns every evidence-derived demand that no ledger
// record answers. THIS is the arm that can report the G3c failure mode: a
// divergence recorded in evidence with no definition anywhere produces a demand
// and no coverage, so the count rises even though nothing on the definition side
// changed.
func UnledgeredEvidenceDemands(root string, definitions []Definition) ([]EvidenceDemand, error) {
	demands, err := EvidenceDemands(root)
	if err != nil {
		return nil, err
	}
	cases, err := ReadHandshakeCorpusCases(root)
	if err != nil {
		return nil, err
	}
	casesByRow := map[MappingRow][]string{}
	for _, one := range cases {
		if one.Expected.RejectCode == "" {
			continue
		}
		key := MappingRow{Direction: one.Direction, Key: one.Expected.RejectCode}
		casesByRow[key] = append(casesByRow[key], one.CaseID)
	}
	// A SUPERSEDED record answers no demand. This mirrors what
	// coveringDefinitionsForRow already does on the handshake arm; found in this
	// branch's own adversarial pass, where the public-corpus arm was still
	// counting withdrawn records as coverage — the round-2 finding about
	// supersession being invisible to a consumer, surviving in one arm of the
	// measurement it was added to protect.
	superseded := supersededSubjects(definitions)
	namedScenarios := map[string]bool{}
	for _, definition := range definitions {
		if superseded[definition.Subject] {
			continue
		}
		for _, id := range publicScenarioCitation.FindAllString(definitionText(definition), -1) {
			namedScenarios[id] = true
		}
	}

	var unledgered []EvidenceDemand
	for _, demand := range demands {
		switch demand.Kind {
		case "handshake-mapping-row":
			match := MappingRowCitation.FindStringSubmatch(demand.ID)
			if match == nil {
				return nil, fmt.Errorf("malformed mapping-row demand %q", demand.ID)
			}
			row := MappingRow{Direction: match[1], Key: match[2]}
			covering, err := coveringDefinitionsForRow(row, definitions, cases, casesByRow)
			if err != nil {
				// An unmappable row is itself an unanswered demand rather than
				// a hard error here: the count must be able to report it.
				unledgered = append(unledgered, demand)
				continue
			}
			if len(covering) == 0 {
				unledgered = append(unledgered, demand)
			}
		case "public-corpus-protocol-rejection":
			id := publicScenarioCitation.FindString(demand.ID)
			if id == "" || !namedScenarios[id] {
				unledgered = append(unledgered, demand)
			}
		default:
			return nil, fmt.Errorf("unknown evidence demand kind %q", demand.Kind)
		}
	}
	sort.Slice(unledgered, func(i, j int) bool { return unledgered[i].String() < unledgered[j].String() })
	return unledgered, nil
}
