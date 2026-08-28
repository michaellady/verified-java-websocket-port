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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	Family     string         `json:"family"`
	Steps      []ScenarioStep `json:"steps"`
	Expected   struct {
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
}

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

// ReadDivergentMappingRows returns every `divergent: true` row of the committed
// live handshake mapping. It fails closed on an empty document or an empty row,
// so the census can never run vacuously against a truncated artifact.
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

// ReadPublicScenarios decodes the public corpus.
func ReadPublicScenarios(root string) ([]PublicScenario, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(PublicCorpusRelativePath)))
	if err != nil {
		return nil, err
	}
	var scenarios []PublicScenario
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var scenario PublicScenario
		if err := json.Unmarshal([]byte(line), &scenario); err != nil {
			return nil, fmt.Errorf("decode a line of %s: %w", PublicCorpusRelativePath, err)
		}
		var raw struct {
			Expected json.RawMessage `json:"expected"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("decode the expected object of a line of %s: %w", PublicCorpusRelativePath, err)
		}
		scenario.ExpectedRaw = raw.Expected
		scenarios = append(scenarios, scenario)
	}
	if len(scenarios) == 0 {
		return nil, fmt.Errorf("%s yielded no scenarios", PublicCorpusRelativePath)
	}
	return scenarios, nil
}

// FailingStep derives WHICH STEP the recorded run stopped on, from the
// committed counts alone. It is the discriminator the class predicate needs and
// it is derived from the evidence rather than declared beside it.
//
// THE DERIVATION. The harness executes a scenario's steps in order. A `bytes`
// step contributes its decoded length to expected.counts.input_bytes; an
// `action` step contributes one to expected.counts.actions. An error STOPS the
// run at the step that raised it, and that step has already been counted — the
// committed corpus shows both halves of this: us005.pub.0000 is a single
// erroring `send_close` action and records actions=1, and us005.pub.0005 is a
// single erroring 9-byte `bytes` step and records input_bytes=9.
//
// So the executed prefix is the unique prefix of the step list whose byte total
// and action count equal the recorded totals, and the failing step is that
// prefix's LAST step. Uniqueness is REQUIRED rather than assumed: if two
// prefixes match, or none does, the evidence does not determine which step
// failed and this function returns an error instead of guessing. A guess here
// would silently decide class membership, which is the whole thing the
// predicate is supposed to be able to get right.
//
// It returns index -1 with no error in two cases. First, when the scenario did
// not fail at all: `outcome` is not `error`, so there is no failing step to
// find, and a zero-length `bytes` step in such a scenario (us005.pub.0017 and
// us005.pub.0045 are the committed instances) is genuinely indistinguishable
// from a step that did not run — which does not matter, because nothing failed.
// Second, when the run DID fail but the executed prefix is EMPTY, which is the
// recorded shape of the harness envelope refusals that reject an input before
// feeding it (us005.pub.0015 and us005.pub.0044 both carry a `bytes` step with
// input_bytes 0). No step was reached, so no step can be the cause.
func FailingStep(scenario PublicScenario) (int, ScenarioStep, error) {
	if scenario.Expected.Outcome != "error" {
		return -1, ScenarioStep{}, nil
	}
	wantBytes := scenario.Expected.Counts.InputBytes
	wantActions := scenario.Expected.Counts.Actions
	var matches []int
	if wantBytes == 0 && wantActions == 0 {
		matches = append(matches, 0)
	}
	bytesSoFar, actionsSoFar := 0, 0
	for index, step := range scenario.Steps {
		switch step.Kind {
		case "bytes":
			decoded, err := base64.StdEncoding.DecodeString(step.DataBase64)
			if err != nil {
				return 0, ScenarioStep{}, fmt.Errorf("%s step %d: data_base64 does not decode, so the failing step "+
					"cannot be derived: %w", scenario.ScenarioID, index, err)
			}
			bytesSoFar += len(decoded)
		case "action":
			actionsSoFar++
		default:
			return 0, ScenarioStep{}, fmt.Errorf("%s step %d: unknown step kind %q. The failing-step derivation "+
				"refuses to classify a scenario whose step vocabulary it does not know, because a silent default "+
				"would decide protocol-rejection-class membership by accident", scenario.ScenarioID, index, step.Kind)
		}
		if bytesSoFar == wantBytes && actionsSoFar == wantActions {
			matches = append(matches, index+1)
		}
	}
	if len(matches) != 1 {
		return 0, ScenarioStep{}, fmt.Errorf("%s: the recorded counts (input_bytes=%d, actions=%d) match %d step "+
			"prefixes of %d, so the committed evidence does not determine which step failed. Membership in the %s "+
			"class turns on that step, so this is refused rather than guessed",
			scenario.ScenarioID, wantBytes, wantActions, len(matches), len(scenario.Steps), ProtocolRejectionClass)
	}
	executed := matches[0]
	if executed == 0 {
		return -1, ScenarioStep{}, nil
	}
	return executed - 1, scenario.Steps[executed-1], nil
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
// predicate replaced the close-code shape with `counts.input_bytes > 0`, which
// is an AGGREGATE over the whole scenario rather than a fact about the step
// that failed. Review round 2 named the hole exactly: a VALID inbound frame
// followed by a local `send_close(999)` records input_bytes > 0 and
// JAVA_INVALID_DATA and final_state open, so it satisfied every conjunct while
// its error is locally caused — the identical mistake us005.pub.0000 was, one
// level less obvious. Reproduced before this fix by appending exactly that
// scenario to the corpus, enrolling it, and reading `deltaledgerctl --check`
// exit 0 with the class record claiming it.
//
// Membership now turns on FailingStep: the step the run actually stopped on
// must be a `bytes` step. An aggregate cannot say which step failed; the step
// list and the counts together can, and they are both committed evidence.
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
	if expected.Counts.InputBytes <= 0 {
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

// LocallyCausedRejections returns the scenarios that satisfy every CAUSE
// conjunct of the class EXCEPT the failing-step one: the decoder's typed
// rejection code, inbound bytes somewhere in the scenario, and a final state of
// open, but with the run stopping on a LOCAL action rather than on inbound
// bytes.
//
// They are surfaced rather than silently dropped. A scenario in this shape is a
// real proposition about a locally caused rejection that leaves the endpoint
// open — the sequence-35 proposition — and the point of round 2's finding is
// that the gate must be able to tell the two apart out loud, not merely stop
// enrolling one of them.
func LocallyCausedRejections(scenarios []PublicScenario) ([]string, error) {
	var locally []string
	for _, scenario := range scenarios {
		expected := scenario.Expected
		if expected.Outcome != "error" || expected.FinalState != "open" {
			continue
		}
		if expected.Error == nil || expected.Error.Code != "JAVA_INVALID_DATA" {
			continue
		}
		if expected.Counts.InputBytes <= 0 {
			continue
		}
		index, step, err := FailingStep(scenario)
		if err != nil {
			return nil, err
		}
		if index >= 0 && step.Kind != "bytes" {
			locally = append(locally, fmt.Sprintf("%s (stopped on step %d, kind %q, action %q)",
				scenario.ScenarioID, index, step.Kind, step.Action))
		}
	}
	sort.Strings(locally)
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
		if !strings.Contains(definition.Subject, "."+role+".") {
			continue
		}
		if !strings.Contains(definition.Subject, "."+family) {
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
func VerifyProtocolRejectionClass(root string) error {
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
				"public-corpus scenario %s is in the %s class but is ABSENT from %s "+
					"(predicate: outcome==error AND error.code==JAVA_INVALID_DATA AND counts.input_bytes>0 AND "+
					"final_state==open)", id, ProtocolRejectionClass, CensusRelativePath))
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
	// exactly as a member arriving with an unrecorded close code does.
	locally, err := LocallyCausedRejections(scenarios)
	if err != nil {
		return err
	}
	for _, one := range locally {
		problems = append(problems, fmt.Sprintf(
			"%s carries the %s cause markers (error.code JAVA_INVALID_DATA, final_state open, inbound bytes somewhere "+
				"in the scenario) but the run STOPPED ON A LOCAL ACTION, so its error is locally caused and it is NOT a "+
				"member of the class. It is the sequence-35 proposition, not this one. Ledger it deliberately or remove "+
				"it; it is reported rather than filtered away, because an aggregate input_bytes>0 test used to enrol "+
				"exactly this shape", one, ProtocolRejectionClass))
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("protocol-rejection class completeness (%d problem(s)):\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	return nil
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
	namedScenarios := map[string]bool{}
	for _, definition := range definitions {
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
