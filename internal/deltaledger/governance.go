package deltaledger

// GOVERNANCE ARTIFACTS, MIRRORED AS DIGESTS AND VERIFIED BY A GATE.
//
// THE DEFECT (round-2 finding 5). The owner decisions that AUTHORIZE this work
// live in the workspace orchestrator's protected store, outside this
// repository. Nothing in the repo bound them. VerifyCitedOwnerDecisions
// recomputed their digests only when VJWP_PROTECTED_STORE happened to be set,
// and returned success otherwise, so the governance layer was the least
// protected thing in the project. Reproduced before this file existed: with the
// variable unset, `rm` of
// protected/ledger-frozen-prefix-owner-decision-2026-08-28.json — the ruling
// that authorizes the whole supersede-do-not-rewrite design — left
// `make -C rust ledger-gates` at exit 0.
//
// THE OWNER RULING, protected/governance-mirroring-and-record-schema-owner-decision-2026-08-28.json
// (sha256 e6837006a722b71f6b7137b82be31f4a9e8d802f0ef4c0614dbd4016f27c361f,
// decided 2026-08-28T20:05:00Z): MIRROR DIGESTS ONLY. Commit a manifest of each
// decision record's sha256; the record CONTENTS stay out, because
// repos/public/verified-java-websocket-port-claude is a PUBLIC repository and
// those records carry internal deliberation, cost figures and infrastructure
// identifiers. A digest manifest gets the tamper-detection without the
// disclosure.
//
// Its implementation notes are binding and are implemented here:
//
//   - The manifest is verified by something that RUNS. VerifyGovernance is
//     called from VerifyIntegrity, which cmd/deltaledgerctl --check calls and
//     rust/Makefile's `ledger-gates` target invokes. A rule living only in a
//     _test.go file was finding 3 of round one and does not count as a gate.
//
//   - A MISSING STORE MUST NOT SILENTLY PASS, and absence is distinguished from
//     a matching digest rather than skipped. The three outcomes this file can
//     report are distinct and none of them is silence: STORE_UNREACHABLE,
//     RECORD_ABSENT / RECORD_DRIFTED, and VERIFIED with a count. Skipping when
//     VJWP_PROTECTED_STORE is unset is the exact shape of the defect being
//     closed, so the store is also DISCOVERED (see ResolveProtectedStore) and an
//     unresolvable store is a refusal, not a note.
//
// THE MANIFEST IS DERIVED, NOT MAINTAINED. Its entries come from the ledger's
// own hashed rationales — the digests the records already assert — plus the
// decisions this repository's gate design itself rests on. deltaledgerctl writes
// it on the write path exactly as it writes the supersessions sidecar, and
// --check requires the committed file to equal that derivation. So the manifest
// cannot become a separate story from the evidence it mirrors.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// OwnerDecisionManifestRelativePath is the committed digest mirror, and
// OwnerDecisionManifestSchemaRelativePath is its contract.
const (
	OwnerDecisionManifestRelativePath       = "evidence/governance/owner-decision-digests.json"
	OwnerDecisionManifestSchemaRelativePath = "schemas/owner-decision-digests-1.0.0.schema.json"
	OwnerDecisionManifestSchemaPointer      = "../../schemas/owner-decision-digests-1.0.0.schema.json"
	OwnerDecisionManifestEvidenceKind       = "owner-decision-digest-manifest"
)

// ProtectedStoreEnv names the environment variable that points at the workspace
// orchestrator's immutable protected store.
const ProtectedStoreEnv = "VJWP_PROTECTED_STORE"

// protectedStoreSuffix is the conventional location of this plane's protected
// store relative to an ancestor of the checkout. The store is discovered as
// well as configured, because a check that runs only when someone remembers to
// export a variable is a check that does not run.
var protectedStoreSuffix = filepath.Join("workspace", "orchestrator", "verified-java-websocket-port-claude", "protected")

// GOVERNANCE CITATIONS ARE RECOGNISED BY WHAT THEY ARE (round-3 finding 3).
//
// THE DEFECT. The recogniser was one phrasing: a record name followed by the
// literal "(workspace orchestrator protected store, sha256 <hex>". Forty-eight
// of the fifty-one committed citations happen to use that wording. Three do
// not, and one of those three is the ONLY citation of
// us012-us016-owner-decisions-2026-08-28-formal.json — the ruling that mandates
// the sequence-35 record — which is cited at sequence 35 as
// "protected/<name>.json (sha256 <hex>, verified at read)". Sequence 35 is in
// the FROZEN prefix, so that wording cannot be normalised; it has to be parsed.
// The consequence was exactly what the mirror exists to prevent: that decision
// was absent from the manifest, so deleting it from the protected store left
// the gate green. Reproduced before this fix against a scratch copy of the
// store with the file removed: "3 governance record digest(s) recomputed from
// the protected store and matched", exit 0.
//
// WHAT A GOVERNANCE CITATION IS, structurally, with NO naming convention in it:
// a reference to a record IN THE PROTECTED STORE — a bare `<name>.json` or an
// explicitly `protected/`-prefixed one, and nothing under any other directory —
// immediately followed by a CITATION CLAUSE that ASSERTS THAT RECORD'S SHA256.
// The clause opens with ` (` or `, `, contains no `(`, `)` or `.` (so it cannot
// run past a sentence boundary or across a second file name into somebody
// else's digest), and ends in `sha256 <64 hex>`. The DIGEST is the marker,
// because asserting a record's digest is what makes a citation load-bearing;
// the file's name is not consulted. All three committed phrasings parse:
//
//	<name>.json (workspace orchestrator protected store, sha256 <hex>, …
//	protected/<name>.json (sha256 <hex>, verified at read)
//	(owner decision <name>.json, sha256 <hex>)
//
// AND THE RECOGNISER IS FAIL-CLOSED, which matters more than the pattern.
// ownerDecisionCitationCompleteness independently finds every occurrence of a
// name matching this plane's decision-record naming convention and requires
// each one to have been parsed into a (name, digest) pair. A citation form the
// parser does not understand therefore FAILS THE GATE instead of being quietly
// omitted from the mirror. That arm IS convention-based, and it is the weaker
// of the two on purpose: the primary recogniser above has no convention in it
// at all, and this exists only to report when a decision is NAMED with no
// digest attributable to it — the other way the mirror could go silently
// incomplete.
var (
	// ownerDecisionRecordName is the naming convention of this plane's
	// protected decision records, used ONLY by the completeness arm. Evidence
	// receipts (…-receipt.json), transcripts and corpora do not match it.
	ownerDecisionRecordName = regexp.MustCompile(
		`((?:[A-Za-z0-9._-]+/)*)([A-Za-z0-9._-]*owner-(?:decisions?|authorizations?|rulings?)[A-Za-z0-9._-]*\.jsonl?)`)
	// ownerDecisionCitation is a protected-store record name followed by a
	// clause asserting its digest. The optional leading path is captured rather
	// than assumed so it can be REQUIRED to be empty or `protected/`: an
	// in-repository path that happens to end in a `.json` name must not be
	// mirrored as if it lived in the protected store.
	ownerDecisionCitation = regexp.MustCompile(
		`((?:[A-Za-z0-9._-]+/)*)([A-Za-z0-9._-]+\.jsonl?)(?: \(|, )[^().]{0,120}?sha256 ([0-9a-f]{64})`)
)

// protectedStorePrefixIsAllowed reports whether a citation's captured path
// prefix denotes the protected store.
func protectedStorePrefixIsAllowed(prefix string) bool {
	return prefix == "" || prefix == "protected/"
}

// ownerDecisionCitationCompleteness refuses any record that NAMES a governance
// decision record without the parser being able to attribute a digest to it.
func ownerDecisionCitationCompleteness(records []lab.BehaviorLedgerRecord) error {
	var problems []string
	for _, record := range records {
		parsed := map[int]bool{}
		for _, span := range ownerDecisionCitation.FindAllStringSubmatchIndex(record.Delta.Rationale, -1) {
			parsed[span[4]] = true
		}
		for _, span := range ownerDecisionRecordName.FindAllStringSubmatchIndex(record.Delta.Rationale, -1) {
			if parsed[span[4]] {
				continue
			}
			prefix := record.Delta.Rationale[span[2]:span[3]]
			if !protectedStorePrefixIsAllowed(prefix) {
				continue
			}
			name := record.Delta.Rationale[span[4]:span[5]]
			problems = append(problems, fmt.Sprintf(
				"sequence %d names governance record %s but no sha256 could be attributed to it there. Every "+
					"citation of a protected decision record must assert that record's digest in the same citation "+
					"clause, so the digest mirror covers it. A citation form the parser does not understand is "+
					"refused rather than silently omitted from the mirror — silent omission is how deleting "+
					"us012-us016-owner-decisions-2026-08-28-formal.json used to leave this gate green.",
				record.Sequence, name))
		}
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("governance citation completeness (%d problem(s)):\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// gateDesignOwnerDecisions are the decisions this repository's GATE DESIGN
// rests on but that no divergence record cites. Without them, deleting the very
// ruling that mandates the digest mirror would fail nothing — which is the
// defect one level up.
var gateDesignOwnerDecisions = map[string]string{
	"governance-mirroring-and-record-schema-owner-decision-2026-08-28.json": "e6837006a722b71f6b7137b82be31f4a9e8d802f0ef4c0614dbd4016f27c361f",
}

// OwnerDecisionEntry is one mirrored governance record.
type OwnerDecisionEntry struct {
	Name string `json:"name"`
	// SHA256 is the digest asserted by the evidence that cites it. It is a bare
	// hex digest, matching how the records quote it.
	SHA256 string `json:"sha256"`
	// CitedBySequences are the ledger sequences whose hashed rationales assert
	// this digest. Empty means the decision is cited by the gate design rather
	// than by a record, and Basis says so.
	CitedBySequences []uint64 `json:"cited_by_sequences"`
	Basis            string   `json:"basis"`
}

// OwnerDecisionManifest is the committed digest mirror.
type OwnerDecisionManifest struct {
	Schema        string               `json:"$schema"`
	SchemaVersion string               `json:"schema_version"`
	EvidenceKind  string               `json:"evidence_kind"`
	Statement     string               `json:"statement"`
	Store         string               `json:"store"`
	Decisions     []OwnerDecisionEntry `json:"decisions"`
}

// OwnerDecisionManifestStatement is held here so the artifact and the code that
// validates it cannot drift.
const OwnerDecisionManifestStatement = "Digest mirror of the owner decisions that govern this project. The records " +
	"themselves live in the workspace orchestrator's immutable protected store and are deliberately NOT committed: " +
	"this repository is public and those records carry internal deliberation, cost figures and infrastructure " +
	"identifiers. Committing their sha256 gets tamper-detection without the disclosure, under the owner ruling " +
	"governance-mirroring-and-record-schema-owner-decision-2026-08-28.json. Every entry is DERIVED — from the digests " +
	"the ledger records' own hashed rationales already assert, plus the decisions this repository's gate design rests " +
	"on — and internal/deltaledger.VerifyGovernance requires the committed file to equal that derivation AND requires " +
	"the protected store to be reachable and every mirrored digest to recompute. An unreachable store is a refusal, " +
	"not a skip. CITATIONS ARE RECOGNISED STRUCTURALLY, not by phrasing: a protected-store record name (bare or " +
	"explicitly under protected/, and under no other directory) followed by a clause asserting that record's sha256. " +
	"The digest is the marker, because asserting a record's digest is what makes a citation load-bearing. An earlier " +
	"version recognised one wording and therefore omitted the only citation of " +
	"us012-us016-owner-decisions-2026-08-28-formal.json, which sits in the frozen prefix and cannot be reworded, so " +
	"deleting that ruling from the store failed nothing. A second, deliberately weaker arm refuses any record that " +
	"NAMES a decision record without a digest attributable to it, so a citation form the parser does not understand " +
	"fails the gate rather than being quietly left out of the mirror."

// OwnerDecisionManifestStore describes where the mirrored records live.
const OwnerDecisionManifestStore = "workspace orchestrator protected store for the verified-java-websocket-port-claude " +
	"plane; set " + ProtectedStoreEnv + " to point at it explicitly, or leave it unset and let ResolveProtectedStore " +
	"discover " + "workspace/orchestrator/verified-java-websocket-port-claude/protected above the checkout"

// BuildOwnerDecisionManifest derives the manifest from the committed record
// chain plus the gate-design decisions.
func BuildOwnerDecisionManifest(records []lab.BehaviorLedgerRecord) (OwnerDecisionManifest, error) {
	if err := ownerDecisionCitationCompleteness(records); err != nil {
		return OwnerDecisionManifest{}, err
	}
	digests := map[string]string{}
	sequences := map[string][]uint64{}
	for _, record := range records {
		for _, match := range ownerDecisionCitation.FindAllStringSubmatch(record.Delta.Rationale, -1) {
			prefix, name, digest := match[1], match[2], match[3]
			// A citation under any directory other than the protected store is
			// not a governance citation, whatever it asserts about itself.
			if !protectedStorePrefixIsAllowed(prefix) {
				continue
			}
			if existing, seen := digests[name]; seen && existing != digest {
				return OwnerDecisionManifest{}, fmt.Errorf(
					"the record chain asserts two different digests for %s (%s at an earlier record, %s at sequence %d); "+
						"a governance record cannot have been two things at once", name, existing, digest, record.Sequence)
			}
			digests[name] = digest
			if last := len(sequences[name]) - 1; last < 0 || sequences[name][last] != record.Sequence {
				sequences[name] = append(sequences[name], record.Sequence)
			}
		}
	}
	basis := map[string]string{}
	for name := range digests {
		basis[name] = "cited by the hashed rationale of the ledger records listed in cited_by_sequences"
	}
	for name, digest := range gateDesignOwnerDecisions {
		if existing, seen := digests[name]; seen && existing != digest {
			return OwnerDecisionManifest{}, fmt.Errorf(
				"%s is asserted as %s by the record chain and as %s by the gate design", name, existing, digest)
		}
		digests[name] = digest
		basis[name] = "no divergence record cites it; it is the ruling this repository's gate design itself rests on, " +
			"mirrored so that deleting the authority for the mirror fails the gate too"
	}
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	sort.Strings(names)
	decisions := make([]OwnerDecisionEntry, 0, len(names))
	for _, name := range names {
		cited := sequences[name]
		if cited == nil {
			cited = []uint64{}
		}
		decisions = append(decisions, OwnerDecisionEntry{
			Name:             name,
			SHA256:           digests[name],
			CitedBySequences: cited,
			Basis:            basis[name],
		})
	}
	if len(decisions) == 0 {
		return OwnerDecisionManifest{}, fmt.Errorf("no owner decision was derived from the chain or the gate design; " +
			"an empty governance mirror would be a vacuous gate")
	}
	return OwnerDecisionManifest{
		Schema:        OwnerDecisionManifestSchemaPointer,
		SchemaVersion: "1.0.0",
		EvidenceKind:  OwnerDecisionManifestEvidenceKind,
		Statement:     OwnerDecisionManifestStatement,
		Store:         OwnerDecisionManifestStore,
		Decisions:     decisions,
	}, nil
}

// EncodeOwnerDecisionManifest renders the manifest exactly as it is committed.
func EncodeOwnerDecisionManifest(manifest OwnerDecisionManifest) ([]byte, error) {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// ReadOwnerDecisionManifest decodes the committed mirror.
func ReadOwnerDecisionManifest(root string) (OwnerDecisionManifest, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(OwnerDecisionManifestRelativePath)))
	if err != nil {
		return OwnerDecisionManifest{}, err
	}
	var manifest OwnerDecisionManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return OwnerDecisionManifest{}, fmt.Errorf("decode %s: %w", OwnerDecisionManifestRelativePath, err)
	}
	if manifest.SchemaVersion != "1.0.0" || manifest.EvidenceKind != OwnerDecisionManifestEvidenceKind {
		return OwnerDecisionManifest{}, fmt.Errorf("%s envelope drifted: version=%q kind=%q",
			OwnerDecisionManifestRelativePath, manifest.SchemaVersion, manifest.EvidenceKind)
	}
	if manifest.Schema != OwnerDecisionManifestSchemaPointer {
		return OwnerDecisionManifest{}, fmt.Errorf("%s $schema pointer drifted: %q",
			OwnerDecisionManifestRelativePath, manifest.Schema)
	}
	if len(manifest.Decisions) == 0 {
		return OwnerDecisionManifest{}, fmt.Errorf("%s mirrors no decisions; the gate would be vacuous",
			OwnerDecisionManifestRelativePath)
	}
	return manifest, nil
}

// ProtectedStoreResolution says WHERE the store was found and HOW, so a reader
// of a failure can tell an unset variable from a moved store.
type ProtectedStoreResolution struct {
	Path   string
	Source string
}

// ResolveProtectedStore finds the protected store: the environment variable if
// it is set, otherwise the conventional location above the checkout.
//
// An environment variable that points at nothing is an ERROR rather than a
// fallback. Silently falling back would let a typo in the variable produce the
// same green gate as a correct setting, which is the failure mode this whole
// file exists to remove.
func ResolveProtectedStore(root string) (ProtectedStoreResolution, error) {
	if configured := strings.TrimSpace(os.Getenv(ProtectedStoreEnv)); configured != "" {
		info, err := os.Stat(configured)
		if err != nil || !info.IsDir() {
			return ProtectedStoreResolution{}, fmt.Errorf("%s is set to %q, which is not a readable directory. A "+
				"misconfigured store is a configuration error, not an absence: it is refused rather than silently "+
				"falling back to discovery", ProtectedStoreEnv, configured)
		}
		return ProtectedStoreResolution{Path: configured, Source: ProtectedStoreEnv}, nil
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return ProtectedStoreResolution{}, err
	}
	for directory := absolute; ; {
		candidate := filepath.Join(directory, protectedStoreSuffix)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return ProtectedStoreResolution{Path: candidate, Source: "discovered above the checkout"}, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	return ProtectedStoreResolution{}, fmt.Errorf(
		"THE PROTECTED GOVERNANCE STORE IS NOT REACHABLE. %s is unset and no %s directory exists above %s. This is a "+
			"REFUSAL, not a skip: the owner ruling governance-mirroring-and-record-schema-owner-decision-2026-08-28.json "+
			"requires that a missing store be distinguished from a matching digest rather than passing quietly, because "+
			"a gate that skips when a variable is unset is exactly how deleting a load-bearing owner decision used to "+
			"leave this branch green. Point %s at the store to run this gate.",
		ProtectedStoreEnv, protectedStoreSuffix, absolute, ProtectedStoreEnv)
}

// VerifyGovernance is the whole governance gate: the committed mirror must
// equal the derivation from the evidence, the store must be reachable, and
// every mirrored digest must recompute from the file it names.
func VerifyGovernance(root string, records []lab.BehaviorLedgerRecord) (verified int, err error) {
	built, err := BuildOwnerDecisionManifest(records)
	if err != nil {
		return 0, err
	}
	committed, err := ReadOwnerDecisionManifest(root)
	if err != nil {
		return 0, err
	}
	expected, err := EncodeOwnerDecisionManifest(built)
	if err != nil {
		return 0, err
	}
	actual, err := EncodeOwnerDecisionManifest(committed)
	if err != nil {
		return 0, err
	}
	if string(expected) != string(actual) {
		return 0, fmt.Errorf("%s does not equal the manifest derived from the committed evidence (%d decision(s) "+
			"derived). The mirror is generated by cmd/deltaledgerctl on the write path, exactly as the supersession "+
			"sidecar is, so it cannot be edited into a separate story from the digests the records assert",
			OwnerDecisionManifestRelativePath, len(built.Decisions))
	}

	resolution, err := ResolveProtectedStore(root)
	if err != nil {
		return 0, err
	}
	var problems []string
	for _, decision := range committed.Decisions {
		path := filepath.Join(resolution.Path, decision.Name)
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			problems = append(problems, fmt.Sprintf(
				"RECORD_ABSENT %s: mirrored at sha256 %s but not readable in the protected store at %s (%s): %v",
				decision.Name, decision.SHA256, resolution.Path, resolution.Source, readErr))
			continue
		}
		sum := sha256.Sum256(raw)
		got := hex.EncodeToString(sum[:])
		if got != decision.SHA256 {
			problems = append(problems, fmt.Sprintf(
				"RECORD_DRIFTED %s: the committed mirror and the evidence that cites it assert sha256 %s, the file in "+
					"the protected store is %s", decision.Name, decision.SHA256, got))
			continue
		}
		verified++
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return verified, fmt.Errorf("governance records (%d problem(s), %d verified):\n  %s",
			len(problems), verified, strings.Join(problems, "\n  "))
	}
	return verified, nil
}

// VerifyCitedOwnerDecisions is the name the ledger's own hashed rationales use
// for the recomputation, kept stable because those preimages cannot be edited
// without changing record digests. It is now the full governance gate.
func VerifyCitedOwnerDecisions(root string, records []lab.BehaviorLedgerRecord) (int, error) {
	return VerifyGovernance(root, records)
}
