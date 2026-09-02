// Package fuzzpin verifies the US-021 AC3 fuzz-target pinning record against
// the repository it describes.
//
// AC3 verbatim: "Each target has a pinned engine/toolchain, dictionary/corpus
// digest, minimum bounded campaign, timeout/OOM/crash policy, artifact
// capture, replay command, and exact target manifest; unavailable tooling
// blocks instead of skipping."
//
// The defect class this package exists to stop is EXISTENCE STANDING IN FOR
// IDENTITY: a seed corpus on disk is not a campaign, a property test is not a
// fuzz target, and a replay command nobody ran is a string. So every field the
// manifest asserts is re-derived from the tree:
//
//   - a declared entrypoint must be a `fn <name>` that really exists in the
//     named source file, under a real `#[test]` attribute;
//   - the declared case count must appear VERBATIM as the loop literal in that
//     source, so the manifest cannot claim a 10_000-case campaign over a
//     10-case loop;
//   - the corpus digest is recomputed from the files on disk;
//   - the engine's generator source and the toolchain pin are digest-bound;
//   - an engine whose probe command cannot run is UNAVAILABLE, and an
//     unavailable engine BLOCKS. It may never be recorded as skipped, absent,
//     or passed. This mirrors internal/formalplan's
//     UNAVAILABLE_REPRESENTED_AS_SKIP and UNAVAILABLE_BACKEND_CLAIM findings
//     and the ledger gate's refusal when VJWP_PROTECTED_STORE is unreachable.
//
// Liveness guards (finding F005, third sighting of the class): a campaign's
// guard against non-termination is a wall-clock deadline. A guard declared as
// an iteration/poll/case count is a host-speed measurement dressed as a bound
// and BLOCKS here. The deterministic case count is WORK, recorded separately;
// it may never be the liveness guard.
package fuzzpin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DigestScheme is the repo-incumbent canonical tree digest (see
// assurance/replay/fixtures/us006-cases.json, which uses the same scheme):
// sha256 over "relative-path\x00sha256(file-bytes)\n" lines in sorted
// relative-path order.
const DigestScheme = "CANONICAL_PATH_SHA256_V1"

// Dispositions. BLOCK is the only failing disposition; NOTE is visible and
// non-failing. There is deliberately no SKIP.
const (
	Block = "BLOCK"
	Note  = "NOTE"
)

// Target statuses.
const (
	// StatusPinned: a real generative target exists and every AC3 field is
	// present and verified.
	StatusPinned = "PINNED"
	// StatusSharedNoDedicatedTarget: the family's inputs are generated, but
	// only inside another family's target. Honest coverage, not a dedicated
	// target with its own campaign bound and corpus.
	StatusSharedNoDedicatedTarget = "SHARED_NO_DEDICATED_TARGET"
	// StatusAbsent: no generative target exists for this AC2 family.
	StatusAbsent = "ABSENT"
	// StatusBlockedUnavailable: a target whose engine is not installed here.
	StatusBlockedUnavailable = "BLOCKED_UNAVAILABLE"
)

// Engine kinds.
const (
	EngineInRepoDeterministic = "in_repo_deterministic"
	EngineCoverageGuided      = "coverage_guided"
)

// Finding codes.
const (
	FindingManifestSchemaInvalid     = "FUZZ_MANIFEST_SCHEMA_INVALID"
	FindingTargetAbsent              = "FUZZ_TARGET_ABSENT"
	FindingEntrypointMissing         = "FUZZ_ENTRYPOINT_MISSING"
	FindingCampaignLiteralDrift      = "FUZZ_CAMPAIGN_LITERAL_DRIFT"
	FindingCampaignTotalMismatch     = "FUZZ_CAMPAIGN_TOTAL_MISMATCH"
	FindingCampaignEmpty             = "FUZZ_CAMPAIGN_EMPTY"
	FindingLivenessDeadlineAbsent    = "LIVENESS_GUARD_DEADLINE_ABSENT"
	FindingCorpusDigestMismatch      = "FUZZ_CORPUS_DIGEST_MISMATCH"
	FindingEngineSourceDigestDrift   = "FUZZ_ENGINE_SOURCE_DIGEST_DRIFT"
	FindingToolchainPinDrift         = "FUZZ_TOOLCHAIN_PIN_DRIFT"
	FindingEngineUnavailable         = "FUZZ_ENGINE_UNAVAILABLE"
	FindingUnavailableAsSkip         = "UNAVAILABLE_REPRESENTED_AS_SKIP"
	FindingUnavailableAsSuccess      = "UNAVAILABLE_REPRESENTED_AS_SUCCESS"
	FindingLivenessGuardNotWallClock = "LIVENESS_GUARD_NOT_WALL_CLOCK"
	FindingReplayCommandAbsent       = "FUZZ_REPLAY_COMMAND_ABSENT"
	FindingPolicyIncomplete          = "FUZZ_POLICY_INCOMPLETE"
	FindingArtifactCaptureAbsent     = "FUZZ_ARTIFACT_CAPTURE_ABSENT"
	FindingFamilyUnmapped            = "FUZZ_AC2_FAMILY_UNMAPPED"
	FindingUnknownEngineReference    = "FUZZ_UNKNOWN_ENGINE_REFERENCE"
	FindingSharedTargetNotDedicated  = "FUZZ_FAMILY_HAS_NO_DEDICATED_TARGET"
)

// AC2Families is the target set AC2 names, verbatim order:
// "handshake client/server, frame decode, message/UTF-8, fragment/control
// sequences, close/EOF, and owner-driver command/byte schedules".
// handshake client and handshake server are carried separately because they
// are two distinct parsers with two distinct seed corpora.
var AC2Families = []string{
	"handshake-client",
	"handshake-server",
	"frame-decode",
	"message-utf8",
	"fragment-control-sequences",
	"close-eof",
	"owner-driver-command-byte-schedules",
}

// Manifest is the AC3 "exact target manifest".
type Manifest struct {
	SchemaVersion string   `json:"schema_version"`
	Story         string   `json:"story"`
	AC            int      `json:"ac"`
	ACVerbatim    string   `json:"ac_verbatim"`
	DigestScheme  string   `json:"digest_scheme"`
	Note          string   `json:"note"`
	Engines       []Engine `json:"engines"`
	Targets       []Target `json:"targets"`
	Claim         Claim    `json:"claim"`
}

// Engine pins one generator, its toolchain, and how availability is decided.
type Engine struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// ProbeCommand decides availability. It MUST be present for every engine:
	// an engine whose availability cannot be decided is unavailable.
	ProbeCommand []string  `json:"probe_command"`
	ProbeDir     string    `json:"probe_dir"`
	Toolchain    Toolchain `json:"toolchain"`
	// SourceFiles are the generator sources, digest-pinned so the engine
	// cannot be swapped underneath the manifest.
	SourceFiles  []string `json:"source_files"`
	SourceDigest string   `json:"source_digest"`
}

// Toolchain pins the compiler the campaign runs under.
type Toolchain struct {
	Channel   string `json:"channel"`
	PinFile   string `json:"pin_file"`
	PinDigest string `json:"pin_digest"`
}

// Target is one AC2 family's record.
type Target struct {
	ID          string       `json:"id"`
	AC2Family   string       `json:"ac2_family"`
	Status      string       `json:"status"`
	Engine      string       `json:"engine"`
	Rationale   string       `json:"rationale"`
	Entrypoints []Entrypoint `json:"entrypoints"`
	Corpus      Corpus       `json:"corpus"`
	Campaign    Campaign     `json:"campaign"`
	Policy      Policy       `json:"policy"`
	Artifacts   Artifacts    `json:"artifacts"`
	Replay      Replay       `json:"replay"`
}

// Entrypoint is one test function that consumes generated input.
type Entrypoint struct {
	File string `json:"file"`
	Test string `json:"test"`
	// Cases is the declared deterministic case count.
	Cases int `json:"cases"`
	// CaseLiteral must appear VERBATIM in File. This is the identity binding:
	// without it the manifest could claim any campaign size over any loop.
	CaseLiteral string `json:"case_literal"`
	// Seed is the generator seed literal, also required verbatim in File.
	Seed string `json:"seed"`
}

// Corpus is the dictionary/corpus AC3 requires a digest for.
type Corpus struct {
	Paths     []string `json:"paths"`
	FileCount int      `json:"file_count"`
	Digest    string   `json:"digest"`
	Note      string   `json:"note,omitempty"`
}

// Campaign is the "minimum bounded campaign".
type Campaign struct {
	Kind          string        `json:"kind"`
	TotalCases    int           `json:"total_cases"`
	LivenessGuard LivenessGuard `json:"liveness_guard"`
}

// LivenessGuard is F005's rule made mechanical: kind must be "wall_clock".
type LivenessGuard struct {
	Kind            string `json:"kind"`
	DeadlineSeconds int    `json:"deadline_seconds"`
	Note            string `json:"note"`
}

// Policy is the timeout/OOM/crash policy.
type Policy struct {
	Crash   string `json:"crash"`
	Timeout string `json:"timeout"`
	OOM     string `json:"oom"`
}

// Artifacts is the artifact-capture record.
type Artifacts struct {
	Dir string `json:"dir"`
}

// Replay is the replay command. Command must be non-empty for a PINNED target.
type Replay struct {
	Dir     string   `json:"dir"`
	Command []string `json:"command"`
}

// Claim is the manifest's own verdict. It may not claim AC2/AC3 met while any
// BLOCK finding stands; asserting otherwise is itself a BLOCK.
type Claim struct {
	AC2Met      bool   `json:"ac2_met"`
	AC3Met      bool   `json:"ac3_met"`
	ClaimGrade  string `json:"claim_grade"`
	HonestState string `json:"honest_state"`
}

// Finding is one typed verdict line.
type Finding struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
	Target      string `json:"target"`
	Detail      string `json:"detail"`
}

// EngineProbe is one availability probe outcome.
type EngineProbe struct {
	Engine    string `json:"engine"`
	Command   string `json:"command"`
	Exit      int    `json:"exit"`
	ExitText  string `json:"exit_text"`
	Available bool   `json:"available"`
}

// Verdict is the check result.
type Verdict struct {
	State              string        `json:"state"`
	Findings           []Finding     `json:"findings"`
	EngineAvailability []EngineProbe `json:"engine_availability"`
}

// LoadManifest reads and decodes a manifest, rejecting unknown fields so a
// typo cannot silently drop a required pin.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &manifest, nil
}

// TreeDigest computes CANONICAL_PATH_SHA256_V1 over every regular file under
// the given roots, relative to base. Roots that do not exist are an error:
// a missing corpus is not an empty corpus.
func TreeDigest(base string, roots []string) (string, int, error) {
	type entry struct {
		rel    string
		digest string
	}
	var entries []entry
	appendFile := func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		entries = append(entries, entry{rel: filepath.ToSlash(rel), digest: hex.EncodeToString(sum[:])})
		return nil
	}
	for _, root := range roots {
		abs := filepath.Join(base, root)
		info, err := os.Stat(abs)
		if err != nil {
			return "", 0, fmt.Errorf("corpus root %s: %w", root, err)
		}
		if !info.IsDir() {
			if err := appendFile(abs); err != nil {
				return "", 0, err
			}
			continue
		}
		err = filepath.Walk(abs, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			return appendFile(path)
		})
		if err != nil {
			return "", 0, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	hasher := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(hasher, "%s\x00%s\n", e.rel, e.digest)
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), len(entries), nil
}
