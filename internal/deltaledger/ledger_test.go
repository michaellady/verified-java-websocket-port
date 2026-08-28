package deltaledger

// Deterministic validation of the committed behavior-delta ledger:
//  1. the committed evidence document is exactly the chain regenerated from
//     the recorded divergence definitions (hash-chained through internal/lab);
//  2. the committed record chain verifies record-by-record;
//  3. every cited corpus case, seed, quirk, and ws_core source path resolves
//     inside the repository (referential integrity);
//  4. the coverage rule: every Q-series quirk token in the shipped
//     rust/ws-core sources is either ledgered or explicitly allowlisted as
//     having no RFC counterpart.

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

const ledgerTestRepoRoot = "../.."

// mandatedHandshakeCases are the 16 live-recorded RFC-reject-but-Java-accept
// handshake divergences (evidence/us005-handshake-live-mapping.json; AC
// closure dossier E13). Every one must be cited by exactly one ledger record.
var mandatedHandshakeCases = []string{
	"us005.hs.0013", "us005.hs.0014", "us005.hs.0015", "us005.hs.0016", "us005.hs.0017",
	"us005.hs.0019", "us005.hs.0020", "us005.hs.0021", "us005.hs.0022", "us005.hs.0027",
	"us005.hs.0029", "us005.hs.0030", "us005.hs.0034", "us005.hs.0046", "us005.hs.0047",
	"us005.hs.0048",
}

// quirkAllowlist names the Q-series quirks that deliberately have NO ledger
// record, each with the reason there is no Java-vs-RFC divergence to ledger.
var quirkAllowlist = map[string]string{
	"Q9": "client-side basicAccept gates Upgrade/Connection on the NOT_MATCHED reject channel; the live exam recorded " +
		"REJECT verdicts matching the RFC for these inputs (Java-channel granularity only, no accept divergence)",
	"Q16": "JAVA_NOT_SENDABLE is the local send-path DFA refusal vocabulary; it produces no wire behavior and has no " +
		"RFC counterpart clause",
	"Q24": "the max_buffered_bytes+14 wire-buffer slack is implementation-internal limit arithmetic; RFC 6455 " +
		"section 10.4 prescribes no limit arithmetic, so there is no RFC counterpart",
	"Q26": "requireOpen/closed-state gates are local state-machine refusals whose wire-facing effect (refuse traffic " +
		"after terminal close) matches the RFC; the EOF/post-close close-vocabulary divergence itself is ledgered in " +
		"the Q20 record",
	"Q28": "the deterministic mask-key seam replaces Java's RNG for replay; pinned Java itself conforms to the RFC " +
		"randomness requirement and mask keys are never observable in the oracle protocol, so this is a port seam, " +
		"not a Java-vs-RFC divergence",
}

func TestCommittedLedgerMatchesTheRecordedDivergenceDefinitions(t *testing.T) {
	records, head, err := BuildLedger()
	if err != nil {
		t.Fatalf("BuildLedger: %v", err)
	}
	if len(records) != len(Definitions()) {
		t.Fatalf("built %d records for %d definitions", len(records), len(Definitions()))
	}
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	if committed.Schema != "../../schemas/behavior-delta-ledger-1.0.0.schema.json" ||
		committed.SchemaVersion != "1.0.0" ||
		committed.EvidenceKind != "behavior-delta-ledger" ||
		committed.NormativeAuthority != "rfc6455" ||
		committed.AppendImplementation != "hash-chained-cas" ||
		committed.Production || committed.Publication {
		t.Fatalf("committed envelope drifted: %+v", committed)
	}
	// The ledger's aggregate READY gate (internal/lab.VerifyBaselineEvidence)
	// additionally requires the build/adapter/tests/Autobahn baselines to be
	// PASS, and the Autobahn baseline is BLOCKED (0/247 both modes,
	// NO_FURTHER_RERUNS_AUTHORIZED). Populating the divergence records
	// therefore must NOT flip the status; an honest status change requires
	// that baseline to land first.
	if committed.Status != "BLOCKED_PENDING_BASELINE" {
		t.Fatalf("committed status %q; the aggregate baseline gate (Autobahn BLOCKED) still holds", committed.Status)
	}
	if len(committed.Records) != len(records) {
		t.Fatalf("committed ledger has %d records, the recorded divergence definitions build %d",
			len(committed.Records), len(records))
	}
	for index := range records {
		if !reflect.DeepEqual(committed.Records[index], records[index]) {
			t.Fatalf("committed record %d (%s) differs from the regenerated record (%s)",
				index+1, committed.Records[index].Delta.SubjectRef, records[index].Delta.SubjectRef)
		}
	}
	if committed.Head != head {
		t.Fatalf("committed head %s != regenerated head %s", committed.Head, head)
	}
	// unledgered_disagreements is COMPUTED from the committed observation set
	// (see observations.go); the envelope check therefore compares it against
	// the recomputation rather than against the literal 0 it used to be.
	observations, err := ReadObservations(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	unledgered, err := UnledgeredSubjects(records, observations.Observed)
	if err != nil {
		t.Fatalf("compute unledgered: %v", err)
	}
	if committed.UnledgeredDisagreements != len(unledgered) {
		t.Fatalf("committed unledgered_disagreements %d != computed %d (%v)",
			committed.UnledgeredDisagreements, len(unledgered), unledgered)
	}
}

func TestCommittedLedgerChainVerifies(t *testing.T) {
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	previous := lab.GenesisLedgerHead
	seen := map[string]bool{}
	for index, record := range committed.Records {
		if err := record.Validate(); err != nil {
			t.Fatalf("record %d invalid: %v", index+1, err)
		}
		if record.Sequence != uint64(index+1) || record.PreviousDigest != previous {
			t.Fatalf("record %d breaks the chain (sequence %d, previous %s, want previous %s)",
				index+1, record.Sequence, record.PreviousDigest, previous)
		}
		if seen[record.Delta.DeltaID] {
			t.Fatalf("record %d duplicates delta %s", index+1, record.Delta.DeltaID)
		}
		seen[record.Delta.DeltaID] = true
		previous = record.RecordDigest
	}
	if committed.Head != previous {
		t.Fatalf("committed head %s != verified chain head %s", committed.Head, previous)
	}
}

func TestLedgerRecordsResolveTheirCitedEvidence(t *testing.T) {
	handshakeIDs := identifierSet(t, filepath.Join(ledgerTestRepoRoot, "corpora", "handshake", "cases.jsonl"),
		regexp.MustCompile(`us005\.hs\.[0-9]{4}`))
	publicIDs := identifierSet(t, filepath.Join(ledgerTestRepoRoot, "corpora", "public", "scenarios.jsonl"),
		regexp.MustCompile(`us005\.pub\.[0-9]{4}`))
	sourceQuirks := shippedQuirkTokens(t)

	hsPattern := regexp.MustCompile(`us005\.hs\.[0-9]{4}`)
	pubPattern := regexp.MustCompile(`us005\.pub\.[0-9]{4}`)
	quirkPattern := regexp.MustCompile(`Q[0-9]+`)
	pathPattern := regexp.MustCompile(`rust/ws-core/[A-Za-z0-9/_.-]+`)

	citedHandshake := map[string]int{}
	for _, definition := range Definitions() {
		text := definitionText(definition)
		for _, id := range hsPattern.FindAllString(text, -1) {
			if !handshakeIDs[id] {
				t.Errorf("%s cites handshake case %s which does not exist in corpora/handshake/cases.jsonl",
					definition.Subject, id)
			}
			citedHandshake[id]++
		}
		for _, id := range pubPattern.FindAllString(text, -1) {
			if !publicIDs[id] {
				t.Errorf("%s cites public corpus case %s which does not exist in corpora/public/scenarios.jsonl",
					definition.Subject, id)
			}
		}
		for _, quirk := range quirkPattern.FindAllString(text, -1) {
			if !sourceQuirks[quirk] {
				t.Errorf("%s cites quirk %s which does not appear in the shipped rust/ws-core sources",
					definition.Subject, quirk)
			}
		}
		for _, cited := range pathPattern.FindAllString(text, -1) {
			cleaned := strings.TrimRight(cited, ".")
			if _, err := os.Stat(filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(cleaned))); err != nil {
				t.Errorf("%s cites path %s which does not resolve: %v", definition.Subject, cleaned, err)
			}
		}
	}
	for _, id := range mandatedHandshakeCases {
		if citedHandshake[id] == 0 {
			t.Errorf("mandated live handshake divergence %s has no ledger record citation", id)
		}
	}
}

func TestEveryShippedQuirkWithAnRFCCounterpartIsLedgered(t *testing.T) {
	sourceQuirks := shippedQuirkTokens(t)
	quirkPattern := regexp.MustCompile(`Q[0-9]+`)
	recorded := map[string]bool{}
	for _, definition := range Definitions() {
		for _, quirk := range quirkPattern.FindAllString(definitionText(definition), -1) {
			recorded[quirk] = true
		}
	}
	for quirk := range quirkAllowlist {
		if recorded[quirk] {
			t.Errorf("quirk %s is allowlisted as having no RFC counterpart but a ledger record cites it; "+
				"remove it from one side", quirk)
		}
	}
	var missing []string
	for quirk := range sourceQuirks {
		if !recorded[quirk] && quirkAllowlist[quirk] == "" {
			missing = append(missing, quirk)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("shipped quirks with no ledger record and no allowlist justification: %v "+
			"(coverage rule: every Q-series quirk token in rust/ws-core/src must be ledgered or allowlisted)", missing)
	}
}

func identifierSet(t *testing.T, path string, pattern *regexp.Regexp) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	set := map[string]bool{}
	for _, id := range pattern.FindAllString(string(raw), -1) {
		set[id] = true
	}
	if len(set) == 0 {
		t.Fatalf("%s yielded no identifiers", path)
	}
	return set
}

func shippedQuirkTokens(t *testing.T) map[string]bool {
	t.Helper()
	pattern := regexp.MustCompile(`Q[0-9]+`)
	set := map[string]bool{}
	root := filepath.Join(ledgerTestRepoRoot, "rust", "ws-core", "src")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".rs") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, quirk := range pattern.FindAllString(string(raw), -1) {
			set[quirk] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(set) == 0 {
		t.Fatal("no quirk tokens found in the shipped sources")
	}
	return set
}
