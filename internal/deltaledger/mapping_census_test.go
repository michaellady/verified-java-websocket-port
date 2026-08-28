package deltaledger

// Evidence-side census for the behavior-delta ledger.
//
// WHY THIS FILE EXISTS. The source-side census in ledger_test.go
// (TestEveryShippedQuirkWithAnRFCCounterpartIsLedgered) drives coverage from
// the Q-series quirk tokens written into rust/ws-core/src. That rule is
// necessary but NOT sufficient, and the acceptance audit found the exact hole
// it leaves open: a whole DIRECTION of recorded divergence can go unledgered
// while the source-side census stays green, because the source need not carry
// a Q-token for it at all. Concretely, every one of the sixteen original
// handshake records cited a `client_request`-direction case (the SERVER
// slice), no record covered the `server_response` direction (the CLIENT
// slice), and the source-side census could not notice: the only Q-tokens in
// rust/ws-core/src/handshake/client.rs are Q9 and Q28, and both are
// allowlisted.
//
// The rule below closes that hole by inverting the direction of the census.
// It reads the committed live handshake evidence document
// (evidence/us005-handshake-live-mapping.json) and requires that EVERY row
// recorded there as `divergent: true` be covered by a ledger record —
// regardless of whether any Q-token, any source comment, or any corpus case
// names it. Evidence in, coverage required out.
//
// A divergent row is covered in exactly one of two ways:
//
//  1. CORPUS-CASE COVERAGE. A handshake corpus case exists with the same
//     direction and the same `expected.reject_code`, and some ledger record
//     cites that case id. This is how the sixteen original handshake records
//     cover the thirteen divergent `client_request` rows, so the rule adds no
//     churn to the committed hash-chain prefix.
//
//  2. EXPLICIT MAPPING-ROW COVERAGE. Some ledger record cites the row
//     literally, as `mapping-row direction=<direction> key=<KEY>`. This is
//     the only route available for a divergent row that no corpus case
//     exercises — which is the situation for all six divergent
//     `server_response` rows: the ten `server_response` corpus cases carry the
//     reject codes HS_STATUS_NOT_101, HS_MISSING_ACCEPT, HS_ACCEPT_MISMATCH
//     and HS_MISSING_UPGRADE, none of which is a divergent key.
//
// The rule is fail-closed in both directions: an explicit mapping-row citation
// that does not resolve to a genuinely divergent row in the committed evidence
// is itself an error, so the gate cannot be satisfied with an invented token.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// liveMappingRelativePath is the committed live handshake evidence document
// this census reads. It is rendered from corpora.HandshakeVerdictMapping and
// pinned byte-identical to that rendering by
// internal/corpora.TestHandshakeLiveMappingEvidenceDocument, so reading the
// artifact here reads the same evidence the audit read.
const liveMappingRelativePath = "evidence/us005-handshake-live-mapping.json"

// handshakeCorpusRelativePath is the live handshake corpus.
const handshakeCorpusRelativePath = "corpora/handshake/cases.jsonl"

// mappingRowCitation matches the explicit mapping-row citation token a ledger
// record uses to claim a divergent row that no corpus case exercises.
var mappingRowCitation = regexp.MustCompile(`mapping-row direction=([a-z_]+) key=(HS_[A-Z0-9_]+)`)

type liveMappingDocument struct {
	Entries []struct {
		Direction      string `json:"direction"`
		Key            string `json:"key"`
		RFCVerdict     string `json:"rfc_verdict"`
		JavaObservable string `json:"java_observable"`
		Divergent      bool   `json:"divergent"`
	} `json:"entries"`
}

type handshakeCorpusCase struct {
	CaseID    string `json:"case_id"`
	Direction string `json:"direction"`
	Expected  struct {
		RejectCode string `json:"reject_code"`
	} `json:"expected"`
}

// mappingRow identifies one row of the live handshake verdict mapping.
type mappingRow struct {
	Direction string
	Key       string
}

func (r mappingRow) String() string {
	return fmt.Sprintf("direction=%s key=%s", r.Direction, r.Key)
}

func readDivergentMappingRows(t *testing.T) []mappingRow {
	t.Helper()
	path := filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(liveMappingRelativePath))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", liveMappingRelativePath, err)
	}
	var document liveMappingDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode %s: %v", liveMappingRelativePath, err)
	}
	if len(document.Entries) == 0 {
		t.Fatalf("%s yielded no entries; the census cannot run fail-open", liveMappingRelativePath)
	}
	var rows []mappingRow
	for _, entry := range document.Entries {
		if !entry.Divergent {
			continue
		}
		if entry.Direction == "" || entry.Key == "" {
			t.Fatalf("%s has a divergent row with an empty direction or key", liveMappingRelativePath)
		}
		rows = append(rows, mappingRow{Direction: entry.Direction, Key: entry.Key})
	}
	if len(rows) == 0 {
		t.Fatalf("%s recorded no divergent rows; the census cannot run fail-open", liveMappingRelativePath)
	}
	return rows
}

func readHandshakeCorpusCases(t *testing.T) []handshakeCorpusCase {
	t.Helper()
	path := filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(handshakeCorpusRelativePath))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", handshakeCorpusRelativePath, err)
	}
	var cases []handshakeCorpusCase
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var parsed handshakeCorpusCase
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			t.Fatalf("decode a line of %s: %v", handshakeCorpusRelativePath, err)
		}
		cases = append(cases, parsed)
	}
	if len(cases) == 0 {
		t.Fatalf("%s yielded no cases", handshakeCorpusRelativePath)
	}
	return cases
}

// citedMappingRows returns the rows the ledger records claim explicitly.
func citedMappingRows() map[mappingRow]bool {
	cited := map[mappingRow]bool{}
	for _, definition := range Definitions() {
		for _, match := range mappingRowCitation.FindAllStringSubmatch(definitionText(definition), -1) {
			cited[mappingRow{Direction: match[1], Key: match[2]}] = true
		}
	}
	return cited
}

// TestEveryDivergentLiveMappingRowIsLedgered is the evidence-side census. It
// is the rule the source-side quirk census cannot express: a divergence
// recorded in the live handshake mapping must have a ledger record whether or
// not any Q-token in the shipped sources names it.
func TestEveryDivergentLiveMappingRowIsLedgered(t *testing.T) {
	rows := readDivergentMappingRows(t)
	corpusCases := readHandshakeCorpusCases(t)
	explicit := citedMappingRows()

	// Which handshake corpus case ids do the ledger records cite?
	casePattern := regexp.MustCompile(`us005\.hs\.[0-9]{4}`)
	citedCases := map[string]bool{}
	for _, definition := range Definitions() {
		for _, id := range casePattern.FindAllString(definitionText(definition), -1) {
			citedCases[id] = true
		}
	}

	// Which (direction, reject_code) rows does a cited corpus case exercise?
	byCorpusCase := map[mappingRow][]string{}
	for _, corpusCase := range corpusCases {
		if corpusCase.Expected.RejectCode == "" || !citedCases[corpusCase.CaseID] {
			continue
		}
		row := mappingRow{Direction: corpusCase.Direction, Key: corpusCase.Expected.RejectCode}
		byCorpusCase[row] = append(byCorpusCase[row], corpusCase.CaseID)
	}

	var uncovered []string
	coveredDirections := map[string]bool{}
	divergentDirections := map[string]bool{}
	for _, row := range rows {
		divergentDirections[row.Direction] = true
		switch {
		case len(byCorpusCase[row]) != 0:
			coveredDirections[row.Direction] = true
		case explicit[row]:
			coveredDirections[row.Direction] = true
		default:
			uncovered = append(uncovered, row.String())
		}
	}
	sort.Strings(uncovered)
	if len(uncovered) != 0 {
		t.Errorf("divergent live-mapping rows with no ledger record (%d):\n  %s\n"+
			"coverage rule: every `divergent: true` row of %s must be covered by a ledger record, either by a record "+
			"citing a handshake corpus case with the same direction and reject_code, or by a record citing the row "+
			"literally as `mapping-row direction=<direction> key=<KEY>`. This rule is evidence-driven on purpose: the "+
			"source-side quirk census cannot see a divergence the shipped sources do not name with a Q-token.",
			len(uncovered), strings.Join(uncovered, "\n  "), liveMappingRelativePath)
	}

	// The blind spot the audit found was direction-shaped: an entire
	// direction of divergence had zero records. Name that failure directly
	// rather than leaving it to be inferred from the row list.
	var missingDirections []string
	for direction := range divergentDirections {
		if !coveredDirections[direction] {
			missingDirections = append(missingDirections, direction)
		}
	}
	sort.Strings(missingDirections)
	if len(missingDirections) != 0 {
		t.Errorf("entire handshake direction(s) with divergent rows and ZERO ledger records: %v "+
			"(this is the exact shape of the gap the acceptance audit found: the client-handshake direction "+
			"`server_response` had 6 divergent rows and no record, and the source-side quirk census could not "+
			"catch it because client.rs's only Q-tokens, Q9 and Q28, are both allowlisted)", missingDirections)
	}
}

// TestExplicitMappingRowCitationsResolve is the fail-closed other half: a
// record may not claim a mapping row that is not recorded as divergent in the
// committed evidence, so the census above cannot be satisfied with an invented
// citation token.
func TestExplicitMappingRowCitationsResolve(t *testing.T) {
	divergent := map[mappingRow]bool{}
	for _, row := range readDivergentMappingRows(t) {
		divergent[row] = true
	}
	for _, definition := range Definitions() {
		for _, match := range mappingRowCitation.FindAllStringSubmatch(definitionText(definition), -1) {
			row := mappingRow{Direction: match[1], Key: match[2]}
			if !divergent[row] {
				t.Errorf("%s cites mapping row %s, which is not a `divergent: true` row of %s",
					definition.Subject, row, liveMappingRelativePath)
			}
		}
	}
}
