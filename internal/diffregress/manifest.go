package diffregress

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
)

// EvidenceDir is the repository-relative home of the committed regression set.
const EvidenceDir = "evidence/differential-regression"

// Committed artifact file names.
const (
	ProbesFile   = "probes.jsonl"
	JavaArmFile  = "java-arm.jsonl"
	RustArmFile  = "rust-arm.jsonl"
	ManifestFile = "manifest.json"
)

// ProbeRecord is the per-probe committed record: identity, provenance, and the
// observed values from BOTH arms.
type ProbeRecord struct {
	RequestID     string   `json:"request_id"`
	Class         Class    `json:"class"`
	Origin        Origin   `json:"origin"`
	Role          string   `json:"role"`
	InitialState  string   `json:"initial_state"`
	Rationale     string   `json:"rationale"`
	RequestDigest string   `json:"request_digest"`
	ChunkSizes    []int    `json:"chunk_sizes"`
	Java          ArmView  `json:"java"`
	Rust          ArmView  `json:"rust"`
	Verdict       Verdict  `json:"verdict"`
	DiffPaths     []string `json:"diff_paths,omitempty"`
	Agree         bool     `json:"behaviorally_agrees"`
}

// ArmView is the behavioral projection recorded for one arm. It is derived from
// that arm's recorded transcript, never predicted.
type ArmView struct {
	Outcome       string `json:"outcome"`
	ErrorCode     any    `json:"error_code"`
	CloseCode     any    `json:"close_code"`
	ConsumedBytes any    `json:"consumed_bytes"`
	InputBytes    any    `json:"input_bytes"`
	Frames        any    `json:"frames"`
	FinalState    any    `json:"final_state"`
}

// Manifest is the committed regression-set record.
type Manifest struct {
	SchemaVersion    string            `json:"schema_version"`
	Kind             string            `json:"kind"`
	RecordedAt       string            `json:"recorded_at"`
	RecordedAtSource string            `json:"recorded_at_provenance"`
	BoundHead        string            `json:"bound_repo_head"`
	Purpose          string            `json:"purpose"`
	Provenance       map[string]string `json:"provenance"`
	OracleIdentity   map[string]string `json:"oracle_identity"`
	Artifacts        map[string]string `json:"artifact_sha256"`
	Counts           map[string]int    `json:"counts"`
	Probes           []ProbeRecord     `json:"probes"`
	Nonclaims        []string          `json:"nonclaims"`
}

func armView(response map[string]any) ArmView {
	view := ArmView{}
	if outcome, ok := response["outcome"].(string); ok {
		view.Outcome = outcome
	}
	if errObject, ok := response["error"].(map[string]any); ok {
		view.ErrorCode = errObject["code"]
		view.CloseCode = errObject["close_code"]
	}
	if counts, ok := response["counts"].(map[string]any); ok {
		view.ConsumedBytes = counts["consumed_bytes"]
		view.InputBytes = counts["input_bytes"]
		view.Frames = counts["frames"]
	}
	view.FinalState = response["final_state"]
	return view
}

// BuildManifest assembles the manifest from the catalog and the two RECORDED
// arms. It reads both transcripts off disk; it never synthesizes a value for
// either arm.
func BuildManifest(dir, recordedAt, recordedAtSource, head string, provenance, oracle map[string]string) (*Manifest, error) {
	javaByID, _, err := LoadTranscript(filepath.Join(dir, JavaArmFile))
	if err != nil {
		return nil, err
	}
	rustByID, _, err := LoadTranscript(filepath.Join(dir, RustArmFile))
	if err != nil {
		return nil, err
	}
	manifest := &Manifest{
		SchemaVersion:    "1.0.0",
		Kind:             "corpus-invisible-differential-regression-set",
		RecordedAt:       recordedAt,
		RecordedAtSource: recordedAtSource,
		BoundHead:        head,
		Purpose: "Committed differential regression evidence for oracle requests that are " +
			"deliberately NOT in the 74-scenario public corpus, covering the three Rust defect " +
			"classes enumerated by the cross-plane defect audit. Both arms are recorded: the " +
			"Java arm from the real pinned Java-WebSocket 1.6.0 oracle, the Rust arm from the " +
			"ws_core harness built at the bound head.",
		Provenance:     provenance,
		OracleIdentity: oracle,
		Artifacts:      map[string]string{},
		Counts:         map[string]int{},
		Nonclaims: []string{
			"These probes bound the risk on three defect classes at points the public corpus does not reach; they are a hand-chosen set, not a saturating search, and they do not eliminate risk for all inputs.",
			"error.detail is compared and reported. A divergence confined to error.detail alone is classified identical_except_error_detail because the adapter protocol documents that field as a non-semantic diagnostic and the corpus evaluator never compares it.",
			"Every Java-side value in this manifest was read from a recorded run of the real pinned oracle. No Java value was predicted, derived, or copied from the Rust arm.",
		},
	}
	byClass := map[Class]int{}
	byOrigin := map[Origin]int{}
	for _, probe := range Catalog() {
		request, err := RequestObject(probe)
		if err != nil {
			return nil, err
		}
		javaResponse, ok := javaByID[probe.ID]
		if !ok {
			return nil, fmt.Errorf("probe %s has no recorded Java arm", probe.ID)
		}
		rustResponse, ok := rustByID[probe.ID]
		if !ok {
			return nil, fmt.Errorf("probe %s has no recorded Rust arm", probe.ID)
		}
		comparison := CompareResponses(javaResponse, rustResponse)
		sizes := make([]int, 0, len(probe.Chunks))
		for _, chunk := range probe.Chunks {
			sizes = append(sizes, len(chunk))
		}
		digest, _ := request["request_digest"].(string)
		manifest.Probes = append(manifest.Probes, ProbeRecord{
			RequestID:     probe.ID,
			Class:         probe.Class,
			Origin:        probe.Origin,
			Role:          probe.Role,
			InitialState:  probe.InitialState,
			Rationale:     probe.Rationale,
			RequestDigest: digest,
			ChunkSizes:    sizes,
			Java:          armView(javaResponse),
			Rust:          armView(rustResponse),
			Verdict:       comparison.Verdict,
			DiffPaths:     comparison.DiffPaths,
			Agree:         comparison.Verdict != Divergent,
		})
		byClass[probe.Class]++
		byOrigin[probe.Origin]++
	}
	for _, name := range []string{ProbesFile, JavaArmFile, RustArmFile} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		manifest.Artifacts[name] = corpora.DigestSHA256(data)
	}
	divergent := 0
	for _, record := range manifest.Probes {
		if !record.Agree {
			divergent++
		}
	}
	manifest.Counts["probes"] = len(manifest.Probes)
	manifest.Counts["behaviorally_divergent"] = divergent
	for class, n := range byClass {
		manifest.Counts["class_"+string(class)] = n
	}
	for origin, n := range byOrigin {
		manifest.Counts["origin_"+string(origin)] = n
	}
	// Probe records stay in catalog order: recovered probes first, then the
	// widening set, so the committed manifest reads in provenance order.
	return manifest, nil
}

// Encode renders the manifest as indented JSON with a trailing newline.
func (m *Manifest) Encode() ([]byte, error) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
