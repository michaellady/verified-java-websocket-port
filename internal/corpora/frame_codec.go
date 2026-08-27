package corpora

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

const (
	frameCodecProjectionPath = "corpora/frame/codec.json"
	frameCodecEvidencePath   = "evidence/us012-frame-codec.json"
)

// FrameCodecProjection is the compact, source-bound US-012 frame corpus.
// Frozen cases reference immutable US-005 bytes instead of duplicating large
// payloads, while additive vectors carry only literals absent from that source.
type FrameCodecProjection struct {
	Schema            string                     `json:"$schema"`
	SchemaVersion     string                     `json:"schema_version"`
	CorpusID          string                     `json:"corpus_id"`
	Authority         FrameCodecAuthority        `json:"authority"`
	FrozenSource      FrameCodecFrozenSource     `json:"frozen_source"`
	FrozenCases       []FrameCodecFrozenCase     `json:"frozen_cases"`
	AdditiveVectors   []FrameCodecAdditiveVector `json:"additive_vectors"`
	Autobahn          FrameCodecAutobahn         `json:"autobahn"`
	Properties        FrameCodecProperties       `json:"properties"`
	Fuzz              FrameCodecFuzz             `json:"fuzz"`
	RuntimeAssertions []string                   `json:"runtime_assertions"`
	Nonclaims         []string                   `json:"nonclaims"`
	Assurance         FrameCodecAssurance        `json:"assurance"`
}

type FrameCodecAuthority struct {
	Priority            []string `json:"priority"`
	PublicExpectation   string   `json:"public_expectation_mode"`
	JavaObservationMode string   `json:"java_observation_mode"`
	StrictnessRule      string   `json:"strictness_rule"`
}

type FrameCodecFrozenSource struct {
	ManifestPath string `json:"manifest_path"`
	ManifestSHA  string `json:"manifest_sha256"`
	ArtifactPath string `json:"artifact_path"`
	ArtifactSHA  string `json:"artifact_sha256"`
}

type FrameCodecFrozenCase struct {
	CaseID           string   `json:"case_id"`
	SourceScenarioID string   `json:"source_scenario_id"`
	Family           string   `json:"family"`
	Role             string   `json:"role"`
	WireSource       string   `json:"wire_source"`
	Expected         string   `json:"expected"`
	RFCBasis         []string `json:"rfc_basis"`
}

type FrameCodecAdditiveVector struct {
	ID        string                    `json:"id"`
	Kind      string                    `json:"kind"`
	Role      string                    `json:"role"`
	RawBase64 string                    `json:"raw_base64,omitempty"`
	Values    []uint64                  `json:"values"`
	Expected  string                    `json:"expected"`
	Java      FrameCodecJavaObservation `json:"java_source_observation"`
	Autobahn  []string                  `json:"autobahn_family_tags"`
}

type FrameCodecJavaObservation struct {
	Observable string   `json:"observable"`
	Divergent  bool     `json:"divergent"`
	Condition  string   `json:"condition"`
	Basis      []string `json:"basis"`
}

type FrameCodecAutobahn struct {
	BaselinePath  string   `json:"baseline_path"`
	BaselineSHA   string   `json:"baseline_sha256"`
	Families      []string `json:"selected_family_declarations"`
	LinkMode      string   `json:"link_mode"`
	ExecutedCases int      `json:"executed_cases"`
	ResultCount   int      `json:"result_count"`
	ResultClaimed bool     `json:"result_claimed"`
}

type FrameCodecProperties struct {
	MaskKeys                     int    `json:"mask_keys"`
	MaskOffsets                  int    `json:"mask_offsets"`
	PayloadLengths               int    `json:"payload_lengths"`
	ChunkSchedules               int    `json:"chunk_schedules"`
	MaskGridExecutionsPerProfile int    `json:"mask_grid_executions_per_profile"`
	ExecutionID                  string `json:"execution_id"`
}

type FrameCodecFuzz struct {
	SeedCount int    `json:"seed_count"`
	Mode      string `json:"mode"`
}

type FrameCodecAssurance struct {
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	Production               bool   `json:"production"`
	Publication              bool   `json:"publication"`
	Signing                  bool   `json:"signing"`
}

type frameCodecScenario struct {
	ScenarioID string `json:"scenario_id"`
	Family     string `json:"family"`
	Role       string `json:"role"`
	Outcome    struct {
		Outcome string `json:"outcome"`
		Error   *struct {
			Code string `json:"code"`
		} `json:"error"`
		Frames []struct {
			Direction string `json:"direction"`
		} `json:"frames"`
	} `json:"expected"`
	Steps []struct {
		Kind       string `json:"kind"`
		DataBase64 string `json:"data_base64"`
	} `json:"steps"`
}

type frozenFrameExpectation struct {
	family        string
	role          string
	outcome       string
	inboundFrames int
	expected      string
}

var exactFrameFrozenCases = map[string]frozenFrameExpectation{
	"us005.pub.0001": {"fragmented-binary", "server", "ok", 2, "Frames(Binary(nonfinal,1),Continuation(final,12))"},
	"us005.pub.0002": {"ping-inbound", "client", "ok", 1, "Frame(Ping,58,unmasked)"},
	"us005.pub.0003": {"text-single", "client", "ok", 1, "Frame(Text,6,unmasked)"},
	"us005.pub.0004": {"payload-64bit", "server", "ok", 1, "Frame(Binary,65536,masked)"},
	"us005.pub.0005": {"rsv-bit", "server", "error", 0, "FrameFailure::ReservedBits"},
	"us005.pub.0011": {"payload-16bit", "server", "ok", 1, "Frame(Binary,126,masked)"},
	"us005.pub.0016": {"pong-inbound", "server", "ok", 1, "Frame(Pong,30,masked)"},
	"us005.pub.0020": {"control-nonfin", "server", "error", 0, "FrameFailure::FragmentedControl"},
	"us005.pub.0026": {"close-remote", "client", "ok", 1, "Frame(Close,2,unmasked)"},
	"us005.pub.0029": {"rsv-bit", "server", "error", 0, "FrameFailure::ReservedBits"},
	"us005.pub.0031": {"buffer-limit-frame", "server", "error", 0, "LimitExceeded::FrameBytes(80>64)"},
	"us005.pub.0036": {"bad-opcode", "server", "error", 0, "FrameFailure::ReservedOpcode(4)"},
	"us005.pub.0043": {"multi-frame-chunk", "server", "ok", 2, "Frames(Text(final,6),Binary(final,10))"},
	"us005.pub.0057": {"control-oversize", "server", "error", 0, "FrameFailure::ControlPayloadTooLarge(165)"},
	"us005.pub.0058": {"rsv-bit", "server", "error", 0, "FrameFailure::ReservedBits"},
	"us005.pub.0059": {"control-oversize", "server", "error", 0, "FrameFailure::ControlPayloadTooLarge(126)"},
	"us005.pub.0065": {"bad-opcode", "server", "error", 0, "FrameFailure::ReservedOpcode(3)"},
}

var exactFrameAdditiveVectors = []FrameCodecAdditiveVector{
	{ID: "add.length.canonical", Kind: "canonical-length-classes", Role: "both", Values: []uint64{0, 1, 124, 125, 126, 127, 65534, 65535, 65536}, Expected: "canonical encode/decode roundtrip", Java: javaFrame("accept", false, "canonical complete frame", "Draft_6455.java:478-525", "Draft_6455.java:528-575"), Autobahn: []string{"1.*", "3.*"}},
	{ID: "add.opcode.reserved", Kind: "reserved-opcodes", Role: "both", Values: []uint64{5, 6, 7, 11, 12, 13, 14, 15}, Expected: "FrameFailure::ReservedOpcode", Java: javaFrame("reject", false, "complete base header", "Draft_6455.java:871-888"), Autobahn: []string{"1.*"}},
	{ID: "add.role.server-unmasked", Kind: "invalid-role-mask", Role: "server", RawBase64: "gQA=", Values: []uint64{}, Expected: "FrameFailure::IncorrectMasking{expected_masked:true,actual_masked:false}", Java: javaFrame("accept", true, "complete unmasked frame", "Draft_6455.java:542-566"), Autobahn: []string{"1.*"}},
	{ID: "add.role.client-masked", Kind: "invalid-role-mask", Role: "client", RawBase64: "gYAAAAAA", Values: []uint64{}, Expected: "FrameFailure::IncorrectMasking{expected_masked:false,actual_masked:true}", Java: javaFrame("accept", true, "complete masked frame", "Draft_6455.java:542-562"), Autobahn: []string{"1.*"}},
	{ID: "add.length.noncanonical16", Kind: "noncanonical-length", Role: "client", RawBase64: "gn4AfQ==", Values: []uint64{125}, Expected: "FrameFailure::NonCanonicalLength16(125)", Java: javaFrame("accept", true, "125 payload bytes follow the header", "Draft_6455.java:621-627"), Autobahn: []string{"1.*"}},
	{ID: "add.length.noncanonical64", Kind: "noncanonical-length", Role: "client", RawBase64: "gn8AAAAAAAD//w==", Values: []uint64{65535}, Expected: "FrameFailure::NonCanonicalLength64(65535)", Java: javaFrame("accept", true, "65535 payload bytes follow the header within cap", "Draft_6455.java:628-639"), Autobahn: []string{"1.*"}},
	{ID: "add.length.high-bit", Kind: "invalid-64-bit-high-bit", Role: "client", RawBase64: "gn+AAAAAAAAAAA==", Values: []uint64{1 << 63}, Expected: "FrameFailure::PayloadLengthHighBitSet", Java: javaFrame("reject", false, "complete extended header", "Draft_6455.java:631-658"), Autobahn: []string{"1.*"}},
	{ID: "add.control.boundary", Kind: "control-length-boundary", Role: "client", RawBase64: "iX0=", Values: []uint64{125, 126}, Expected: "125 accepted; 126 FrameFailure::ControlPayloadTooLarge", Java: javaFrame("reject-over-125", false, "complete control frame", "Draft_6455.java:617-620"), Autobahn: []string{"4.*"}},
	{ID: "add.limits.boundaries", Kind: "allocation-and-event-caps", Role: "both", Values: []uint64{64, 65, 1, 2}, Expected: "frame/total exact accepted; +1 rejected before allocation; second event preserves first", Java: javaFrame("bounded-by-maxFrameSize", false, "declared payload available", "Draft_6455.java:648-658"), Autobahn: []string{"10.*"}},
	{ID: "add.eof.boundaries", Kind: "incomplete-header-and-payload", Role: "server", RawBase64: "gv8AAAAAAAEAAAECAwQ=", Values: []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, Expected: "header cuts 0..13 and first-payload cut 14 produce FrameFailure::UnexpectedEof", Java: javaFrame("incomplete", false, "prefix ends before declared frame", "Draft_6455.java:724-777"), Autobahn: []string{"1.*", "10.*"}},
}

func javaFrame(observable string, divergent bool, condition string, basis ...string) FrameCodecJavaObservation {
	return FrameCodecJavaObservation{Observable: observable, Divergent: divergent, Condition: condition, Basis: basis}
}

var exactFrameRuntimeAssertions = []string{
	"retained frame header bytes never exceed fourteen",
	"payload reservation occurs only after the complete header and cap admission",
	"frame and total retained bytes remain within checked configuration",
	"emitted frame events remain within the checked event-entry limit",
	"a failing frame closes once and emits no event for that frame",
}

var exactFrameNonclaims = []string{
	"no live Java committed-corpus execution",
	"no Autobahn execution result or conformance claim",
	"no Java parity; source-derived quirks are classified",
	"no text or binary message delivery or UTF-8 validation",
	"no fragmentation sequence validation or reassembly",
	"no automatic ping pong or control callback policy",
	"no close-payload interpretation close handshake or between-frame EOF semantics",
	"no extensions compression or reserved-bit negotiation",
	"no ambient randomness or cryptographic-randomness claim",
	"no Kani CBMC or unbounded production proof",
	"no independent review",
	"no release publication production signing or benchmark readiness",
}

// LoadAndVerifyFrameCodecProjection verifies the compact projection against
// immutable public bytes and exact, source-derived strictness classifications.
func LoadAndVerifyFrameCodecProjection(root string) (FrameCodecProjection, error) {
	raw, err := readUS010Artifact(root, frameCodecProjectionPath)
	if err != nil {
		return FrameCodecProjection{}, err
	}
	var projection FrameCodecProjection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&projection); err != nil {
		return FrameCodecProjection{}, fmt.Errorf("decode frame codec projection: %w", err)
	}
	if decoder.Decode(&struct{}{}) == nil {
		return FrameCodecProjection{}, fmt.Errorf("frame codec projection has trailing JSON")
	}
	if err := verifyFrameProjectionIdentity(projection); err != nil {
		return FrameCodecProjection{}, err
	}
	if err := verifyFrameFrozenSource(root, projection); err != nil {
		return FrameCodecProjection{}, err
	}
	if !frameVectorsEqual(projection.AdditiveVectors, exactFrameAdditiveVectors) {
		return FrameCodecProjection{}, fmt.Errorf("frame additive vector inventory drifted")
	}
	return projection, nil
}

func verifyFrameProjectionIdentity(projection FrameCodecProjection) error {
	if projection.Schema != "../../schemas/frame-codec-corpus-1.0.0.schema.json" ||
		projection.SchemaVersion != "1.0.0" || projection.CorpusID != "us012-frame-codec" ||
		!stringSlicesEqual(projection.Authority.Priority, []string{"RFC 6455", "frozen US-005 public reference corpus", "Java-WebSocket v1.6.0 source"}) ||
		projection.Authority.PublicExpectation != "REFERENCE_MODEL_DERIVED_PENDING_ORACLE_CONFIRMATION" ||
		projection.Authority.JavaObservationMode != "SOURCE_DERIVED_NO_LIVE_EXECUTION" ||
		projection.Authority.StrictnessRule != "Java leniency never lowers the RFC 6455 acceptance boundary" {
		return fmt.Errorf("frame projection identity or authority is invalid")
	}
	if projection.Autobahn.BaselinePath != "evidence/java/autobahn-baseline.json" ||
		projection.Autobahn.BaselineSHA != "sha256:54fac3c5166e6530ffb4e34ccd5a05d8122d2b2fae4fc4bc1708ac05779ff04d" ||
		!stringSlicesEqual(projection.Autobahn.Families, []string{"1.*", "3.*", "4.*", "10.*"}) ||
		projection.Autobahn.LinkMode != "REQUIREMENT_FAMILY_TAG_ONLY" || projection.Autobahn.ExecutedCases != 0 ||
		projection.Autobahn.ResultCount != 0 || projection.Autobahn.ResultClaimed {
		return fmt.Errorf("frame projection overstates Autobahn evidence")
	}
	if projection.Properties != (FrameCodecProperties{3, 4, 17, 1, 204, "us012-formal-mask-grid-v1"}) ||
		projection.Fuzz != (FrameCodecFuzz{20, "EXECUTABLE_INERT_REPLAY_SEEDS"}) ||
		!stringSlicesEqual(projection.RuntimeAssertions, exactFrameRuntimeAssertions) ||
		!stringSlicesEqual(projection.Nonclaims, exactFrameNonclaims) ||
		projection.Assurance != (FrameCodecAssurance{"OWNER_ATTESTED_NOT_INDEPENDENT", false, false, false, false}) {
		return fmt.Errorf("frame projection execution or assurance inventory drifted")
	}
	return nil
}

func verifyFrameFrozenSource(root string, projection FrameCodecProjection) error {
	if projection.FrozenSource != (FrameCodecFrozenSource{
		ManifestPath: "corpora/public/manifest.json", ManifestSHA: "sha256:202a3e0d0c84c41cc635adc41a8d2eb3c1e62962c1e343697987ef8f0c69c54b",
		ArtifactPath: "corpora/public/scenarios.jsonl", ArtifactSHA: "sha256:fe1735bc42c11f66afe2965a7449fc6cad31cca3e2048305388241c781501e5f",
	}) {
		return fmt.Errorf("frame frozen source identity drifted")
	}
	for _, item := range []struct{ path, digest string }{
		{projection.FrozenSource.ManifestPath, projection.FrozenSource.ManifestSHA},
		{projection.FrozenSource.ArtifactPath, projection.FrozenSource.ArtifactSHA},
		{projection.Autobahn.BaselinePath, projection.Autobahn.BaselineSHA},
	} {
		raw, err := readUS010Artifact(root, item.path)
		if err != nil || DigestSHA256(raw) != item.digest {
			return fmt.Errorf("frame source digest mismatch: %s", item.path)
		}
	}
	raw, err := readUS010Artifact(root, projection.FrozenSource.ArtifactPath)
	if err != nil {
		return err
	}
	scenarios := make(map[string]frameCodecScenario)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 512*1024)
	for scanner.Scan() {
		var item frameCodecScenario
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			return err
		}
		scenarios[item.ScenarioID] = item
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(projection.FrozenCases) != len(exactFrameFrozenCases) {
		return fmt.Errorf("frame frozen inventory requires exactly %d cases", len(exactFrameFrozenCases))
	}
	seen := make(map[string]bool, len(projection.FrozenCases))
	for _, projected := range projection.FrozenCases {
		expected, allowed := exactFrameFrozenCases[projected.SourceScenarioID]
		source, present := scenarios[projected.SourceScenarioID]
		if !allowed || !present || seen[projected.SourceScenarioID] || projected.CaseID != "frame."+projected.SourceScenarioID ||
			projected.Family != expected.family || projected.Role != expected.role || projected.WireSource != "steps[].data_base64" ||
			projected.Expected != expected.expected || source.Family != expected.family || source.Role != expected.role ||
			source.Outcome.Outcome != expected.outcome || len(projected.RFCBasis) == 0 {
			return fmt.Errorf("frozen frame case drifted: %s", projected.SourceScenarioID)
		}
		inbound := 0
		for _, frame := range source.Outcome.Frames {
			if frame.Direction == "inbound" {
				inbound++
			}
		}
		if inbound != expected.inboundFrames || len(source.Steps) == 0 {
			return fmt.Errorf("frozen source observation drifted: %s", projected.SourceScenarioID)
		}
		for _, step := range source.Steps {
			if step.Kind != "bytes" || (step.DataBase64 == "" && expected.inboundFrames != 0) {
				return fmt.Errorf("frozen frame case lacks exact wire bytes: %s", projected.SourceScenarioID)
			}
		}
		seen[projected.SourceScenarioID] = true
	}
	return nil
}

func frameVectorsEqual(left, right []FrameCodecAdditiveVector) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

type frameCodecEvidence struct {
	Schema        string `json:"$schema"`
	SchemaVersion string `json:"schema_version"`
	EvidenceID    string `json:"evidence_id"`
	StoryID       string `json:"story_id"`
	Status        string `json:"status"`
	Corpus        struct {
		ProjectionPath       string `json:"projection_path"`
		ProjectionSHA        string `json:"projection_sha256"`
		SchemaPath           string `json:"schema_path"`
		SchemaSHA            string `json:"schema_sha256"`
		EvidenceSchemaPath   string `json:"evidence_schema_path"`
		FrozenCases          int    `json:"frozen_cases"`
		AcceptedFrames       int    `json:"accepted_frames"`
		FrozenRejects        int    `json:"frozen_rejects"`
		AdditiveVectorGroups int    `json:"additive_vector_families"`
		FuzzSeedCount        int    `json:"fuzz_seed_count"`
	} `json:"corpus"`
	RustBinding struct {
		Commit            string `json:"commit"`
		CrateTree         string `json:"crate_tree"`
		TreeListingSHA256 string `json:"crate_tree_listing_sha256"`
		Path              string `json:"path"`
	} `json:"rust_binding"`
	Tests struct {
		Debug struct {
			Command string `json:"command"`
			Passed  int    `json:"passed"`
			Failed  int    `json:"failed"`
		} `json:"debug"`
		Release struct {
			Command string `json:"command"`
			Passed  int    `json:"passed"`
			Failed  int    `json:"failed"`
		} `json:"release"`
		FrameCodecTests int   `json:"frame_codec_tests_per_profile"`
		FuzzSeeds       int   `json:"fuzz_seeds_per_profile"`
		MaskGrid        int   `json:"mask_grid_executions_per_profile"`
		Runtime         int   `json:"runtime_assertions"`
		Obligation      []int `json:"obligation_counts_per_profile"`
	} `json:"tests"`
	Autobahn struct {
		BaselinePath  string   `json:"baseline_path"`
		Families      []string `json:"families"`
		ExecutedCases int      `json:"executed_cases"`
		ResultCount   int      `json:"result_count"`
		ResultClaimed bool     `json:"result_claimed"`
	} `json:"autobahn"`
	Formal struct {
		ResultPath          string `json:"result_path"`
		ResultSHA           string `json:"result_sha256"`
		DeclaredObligations int    `json:"declared_obligations"`
	} `json:"formal"`
	Compatibility struct {
		SurfaceIDs      []string               `json:"surface_ids"`
		CutoverIDs      []string               `json:"cutover_obligation_ids"`
		DossierSeams    int                    `json:"dossier_seams"`
		SharedArtifacts []frameArtifactBinding `json:"shared_artifact_digests"`
	} `json:"compatibility"`
	EvidenceDAG struct {
		Path      string `json:"path"`
		SHA256    string `json:"sha256"`
		RootClaim string `json:"root_claim"`
	} `json:"evidence_dag"`
	PendingFinalBindings []framePendingBinding `json:"pending_final_bindings"`
	PredecessorRefresh   []string              `json:"predecessor_refresh"`
	Nonclaims            []string              `json:"nonclaims"`
	Assurance            FrameCodecAssurance   `json:"assurance"`
}

type framePendingBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Reason string `json:"reason"`
}

type frameArtifactBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// VerifyFrameCodecEvidence validates the closed receipt against the finalized
// Rust crate, formal result, shared intake artifacts, and evidence DAG.
func VerifyFrameCodecEvidence(root string) error {
	raw, err := readUS010Artifact(root, frameCodecEvidencePath)
	if err != nil {
		return err
	}
	var evidence frameCodecEvidence
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return fmt.Errorf("decode frame codec evidence: %w", err)
	}
	if err := verifyFrameCodecEvidenceClaims(evidence); err != nil {
		return err
	}
	if _, err := LoadAndVerifyFrameCodecProjection(root); err != nil {
		return err
	}
	for _, artifact := range []struct{ path, digest string }{
		{evidence.Corpus.ProjectionPath, evidence.Corpus.ProjectionSHA},
		{evidence.Corpus.SchemaPath, evidence.Corpus.SchemaSHA},
		{evidence.Formal.ResultPath, evidence.Formal.ResultSHA},
		{evidence.EvidenceDAG.Path, evidence.EvidenceDAG.SHA256},
	} {
		value, err := readUS010Artifact(root, artifact.path)
		if err != nil || DigestSHA256(value) != artifact.digest {
			return fmt.Errorf("frame evidence artifact digest mismatch: %s", artifact.path)
		}
	}
	for _, artifact := range evidence.Compatibility.SharedArtifacts {
		value, err := readUS010Artifact(root, artifact.Path)
		if err != nil || DigestSHA256(value) != artifact.SHA256 {
			return fmt.Errorf("frame evidence shared artifact digest mismatch: %s", artifact.Path)
		}
	}
	if err := verifyFrameRustBinding(root, evidence); err != nil {
		return err
	}
	return verifyFrameEvidenceDAG(root, evidence)
}

func verifyFrameCodecEvidenceClaims(evidence frameCodecEvidence) error {
	if evidence.Schema != "../schemas/frame-codec-evidence-1.0.0.schema.json" ||
		evidence.SchemaVersion != "1.0.0" || evidence.EvidenceID != "evidence.us-012-frame-codec" ||
		evidence.StoryID != "US-012" || evidence.Status != "CLOSED" {
		return fmt.Errorf("frame evidence identity is invalid")
	}
	if evidence.Corpus.ProjectionPath != frameCodecProjectionPath ||
		evidence.Corpus.ProjectionSHA != "sha256:984e59e8533d909bd50c9042bfc1a7503cdc098e5be4e32f287be140b1b4d606" ||
		evidence.Corpus.SchemaPath != "schemas/frame-codec-corpus-1.0.0.schema.json" ||
		evidence.Corpus.SchemaSHA != "sha256:387bc5ea0d6fcf83e8ba1c0bc30e379bf088ee9635c9561e7ddb232bd1437d52" ||
		evidence.Corpus.EvidenceSchemaPath != "schemas/frame-codec-evidence-1.0.0.schema.json" ||
		evidence.Corpus.FrozenCases != 17 || evidence.Corpus.AcceptedFrames != 10 || evidence.Corpus.FrozenRejects != 9 ||
		evidence.Corpus.AdditiveVectorGroups != 10 || evidence.Corpus.FuzzSeedCount != 20 {
		return fmt.Errorf("frame evidence corpus inventory drifted")
	}
	if evidence.RustBinding.Commit != "f1b6883e2df536d9dd50476c56e1d45564c81662" ||
		evidence.RustBinding.CrateTree != "1a5e188ce055b526cd0ea6ce341eb371f0295af2" ||
		evidence.RustBinding.TreeListingSHA256 != "sha256:cc6cdddd744c137e463539e295a78a31329eff899cf5fc578be3c8a09bdaf0f3" ||
		evidence.RustBinding.Path != "rust/connection-core" {
		return fmt.Errorf("frame evidence Rust binding drifted")
	}
	if evidence.Tests.Debug.Command != "make -C rust test" || evidence.Tests.Debug.Passed != 127 || evidence.Tests.Debug.Failed != 0 ||
		evidence.Tests.Release.Command != "make -C rust test-release" || evidence.Tests.Release.Passed != 127 || evidence.Tests.Release.Failed != 0 ||
		evidence.Tests.FrameCodecTests != 16 || evidence.Tests.FuzzSeeds != 20 || evidence.Tests.MaskGrid != 204 ||
		evidence.Tests.Runtime != 5 || !intSlicesEqual(evidence.Tests.Obligation, []int{6, 6, 3, 126, 2, 4, 1632, 204}) {
		return fmt.Errorf("frame evidence test inventory drifted")
	}
	if evidence.Autobahn.BaselinePath != "evidence/java/autobahn-baseline.json" ||
		!stringSlicesEqual(evidence.Autobahn.Families, []string{"1.*", "3.*", "4.*", "10.*"}) ||
		evidence.Autobahn.ExecutedCases != 0 || evidence.Autobahn.ResultCount != 0 || evidence.Autobahn.ResultClaimed {
		return fmt.Errorf("frame evidence overstates Autobahn execution")
	}
	if evidence.Formal.ResultPath != "assurance/formal/frame-results.json" ||
		evidence.Formal.ResultSHA != "sha256:e03b5aee644a2294cfcffbba8d46542947e2ed8a8697cc457f404634646f2cea" ||
		evidence.Formal.DeclaredObligations != 8 {
		return fmt.Errorf("frame formal result binding is not exact")
	}
	if !stringSlicesEqual(evidence.Compatibility.SurfaceIDs, []string{
		"surface.framing.frame-octets", "surface.framing.masking", "surface.errors.protocol-fault", "surface.limits.allocation",
	}) || !stringSlicesEqual(evidence.Compatibility.CutoverIDs, []string{
		"cutover.surface-framing-frame-octets", "cutover.surface-framing-masking", "cutover.surface-errors-protocol-fault", "cutover.surface-limits-allocation",
	}) || evidence.Compatibility.DossierSeams != 15 || !artifactBindingsEqual(evidence.Compatibility.SharedArtifacts, []frameArtifactBinding{
		{"evidence/intake/semantic-id-migration-map.json", "sha256:e884fd06a785b0273a0e23b3dc6841ebcc33c2a81d1fc81fb0b1945d46421e7b"},
		{"evidence/intake/compatibility-surface.json", "sha256:0117560795fbfbe92e1c11a999bcec937c4ab27950ba6e5a1d0f0c73a286602c"},
		{"evidence/intake/port-seam-dossier.json", "sha256:5e117e4300bb5c68a1ce255e1e4af6c8bd93af132cd6c2144a881fad95d1d854"},
		{"evidence/intake/cutover-contract.json", "sha256:ea6d6148dd67b705e74db48056dd5f17f22626fda48d148aef01f37de2d46f76"},
	}) {
		return fmt.Errorf("frame compatibility inventory drifted")
	}
	if evidence.EvidenceDAG.Path != "assurance/us012-evidence-dag.json" ||
		evidence.EvidenceDAG.SHA256 != "sha256:4c19bdbc585ea411f1d2994bcebf0506a18091503b2e9dc7d3623577ef0467a6" ||
		evidence.EvidenceDAG.RootClaim != "claim-us012-frame-codec" ||
		len(evidence.PendingFinalBindings) != 0 ||
		!stringSlicesEqual(evidence.PredecessorRefresh, []string{
			"evidence/us010-client-handshake.json current-HEAD support digests",
			"evidence/us011-server-handshake.json current-HEAD support digests",
			"US-006 formal qualification snapshot and fixture catalog",
		}) || !stringSlicesEqual(evidence.Nonclaims, exactFrameNonclaims) ||
		evidence.Assurance != (FrameCodecAssurance{"OWNER_ATTESTED_NOT_INDEPENDENT", false, false, false, false}) {
		return fmt.Errorf("frame evidence pending work or assurance drifted")
	}
	return nil
}

func verifyFrameRustBinding(root string, evidence frameCodecEvidence) error {
	object, err := exec.Command("git", "-C", root, "rev-parse", evidence.RustBinding.Commit+":"+evidence.RustBinding.Path).Output()
	if err != nil || strings.TrimSpace(string(object)) != evidence.RustBinding.CrateTree {
		return fmt.Errorf("frame Rust crate tree does not match the recorded commit")
	}
	listing, err := exec.Command("git", "-C", root, "ls-tree", "-r", evidence.RustBinding.Commit+":"+evidence.RustBinding.Path).Output()
	if err != nil || DigestSHA256(listing) != evidence.RustBinding.TreeListingSHA256 {
		return fmt.Errorf("frame Rust crate listing digest mismatch")
	}
	return nil
}

func verifyFrameEvidenceDAG(root string, evidence frameCodecEvidence) error {
	var dag struct {
		Root  string `json:"root_node_id"`
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
		Edges []struct {
			From string `json:"from"`
			To   string `json:"to"`
			Kind string `json:"kind"`
		} `json:"edges"`
	}
	raw, err := readUS010Artifact(root, evidence.EvidenceDAG.Path)
	if err != nil || json.Unmarshal(raw, &dag) != nil || dag.Root != evidence.EvidenceDAG.RootClaim {
		return fmt.Errorf("frame evidence DAG root is invalid")
	}
	rust, formal, receipt := false, false, false
	for _, node := range dag.Nodes {
		if strings.Contains(node.ID, "pending") {
			return fmt.Errorf("frame evidence DAG retains a pending node")
		}
	}
	for _, edge := range dag.Edges {
		if edge.Kind == "pending" {
			return fmt.Errorf("frame evidence DAG retains a pending edge")
		}
		rust = rust || edge.From == dag.Root && edge.To == "evidence-us012-rust-f1b6883" && edge.Kind == "supports"
		formal = formal || edge.From == dag.Root && edge.To == "evidence-us012-formal-69c6cd5" && edge.Kind == "supports"
		receipt = receipt || edge.From == dag.Root && edge.To == "evidence-us012-receipt-closed-69c6cd5" && edge.Kind == "supports"
	}
	if !rust || !formal || !receipt {
		return fmt.Errorf("frame evidence DAG finalized support is incomplete")
	}
	return nil
}

func artifactBindingsEqual(left, right []frameArtifactBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func intSlicesEqual(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
