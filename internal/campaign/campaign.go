// Package campaign verifies the closed US-021 property, fuzz, and runtime evidence.
package campaign

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maximumDocument = 8 << 20
	rustc195        = "rustc 1.95.0 (59807616e 2026-04-14)"
)

var manifestPaths = []string{
	"evidence/property/manifest.json",
	"evidence/fuzz/manifest.json",
	"evidence/runtime/manifest.json",
}

var schemaDigests = map[string]string{
	"schemas/us021-campaign-common-1.0.0.schema.json":   "sha256:39746291a9eb21718f2103fdc19117ea724ea334fb6e6068f2b992b2fad5a8b9",
	"schemas/us021-fuzz-manifest-1.0.0.schema.json":     "sha256:feb7e03b5382709c5614769c75f91a469ac5b5b50c92e0ed50d6ab8239ea4bed",
	"schemas/us021-property-manifest-1.0.0.schema.json": "sha256:37cc233913ba34fc7e88709602acb33c97296ad2e2013d08459930beaa703080",
	"schemas/us021-runtime-manifest-1.0.0.schema.json":  "sha256:a65e678fe6c6d2d39d76fb011a3a9408a77c21ce5724537abe503095945d9c8d",
}

var exactTargets = map[string][]string{
	"property": {
		"adversarial-properties",
		"allocation-before-admission",
		"canonical-length-roundtrip",
		"chunk-boundary-invariance",
		"close-terminal-at-most-once",
		"fragment-control-ordering",
		"mask-equation-involution",
		"owner-schedule-replay",
		"strict-utf8",
	},
	"fuzz": {
		"client-handshake",
		"close-eof",
		"fragment-control",
		"frame-decode",
		"message-utf8",
		"owner-command-byte-schedule",
		"server-handshake",
	},
}

type targetContract struct {
	command     []string
	sourcePaths []string
	seedRoots   []string
	cases       uint64
	testsPassed uint64
}

var targetContracts = map[string]targetContract{
	"property/adversarial-properties": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "adversarial_properties"}, sourcePaths: []string{"rust/connection-core/tests/adversarial_properties.rs"}, cases: 168579, testsPassed: 6,
	},
	"property/allocation-before-admission": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "frame_codec", "encoder_role_control_and_limit_rejections_precede_allocation", "--", "--exact"}, sourcePaths: []string{"rust/connection-core/tests/frame_codec.rs"}, cases: 7, testsPassed: 1,
	},
	"property/canonical-length-roundtrip": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "frame_codec", "canonical_length_classes_have_exact_headers_and_streaming_round_trips", "--", "--exact"}, sourcePaths: []string{"rust/connection-core/tests/frame_codec.rs"}, cases: 18, testsPassed: 1,
	},
	"property/chunk-boundary-invariance": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "frame_codec", "every_cut_and_multi_frame_tail_preserve_wire_order", "--", "--exact"}, sourcePaths: []string{"rust/connection-core/tests/frame_codec.rs"}, cases: 12, testsPassed: 1,
	},
	"property/close-terminal-at-most-once": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "close_eof", "close_chunking_and_trailing_partial_bytes_are_deterministic", "--", "--exact"}, sourcePaths: []string{"rust/connection-core/tests/close_eof.rs"}, cases: 11, testsPassed: 1,
	},
	"property/fragment-control-ordering": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "fragmentation", "deterministic_segment_and_transport_schedule_property_preserves_byte_model", "--", "--exact"}, sourcePaths: []string{"rust/connection-core/tests/fragmentation.rs"}, cases: 270, testsPassed: 1,
	},
	"property/mask-equation-involution": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "frame_codec", "mask_equation_involution_offsets_chunks_and_rfc_literal_hold", "--", "--exact"}, sourcePaths: []string{"rust/connection-core/tests/frame_codec.rs"}, cases: 204, testsPassed: 1,
	},
	"property/owner-schedule-replay": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-driver", "--test", "concurrency", "bounded_actor_interleavings_execute_and_replay_with_honest_metrics", "--", "--exact"}, sourcePaths: []string{"rust/websocket-driver/tests/concurrency.rs"}, cases: 512, testsPassed: 1,
	},
	"property/strict-utf8": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "messages", "sampled_unicode_scalar_property_matches_the_standard_string_invariant", "--", "--exact"}, sourcePaths: []string{"rust/connection-core/tests/messages.rs"}, cases: 8862, testsPassed: 1,
	},
	"fuzz/client-handshake": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "client_handshake"}, sourcePaths: []string{"rust/connection-core/tests/client_handshake.rs"}, seedRoots: []string{"rust/connection-core/fuzz-seeds/us010"}, cases: 11, testsPassed: 15,
	},
	"fuzz/server-handshake": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "server_handshake"}, sourcePaths: []string{"rust/connection-core/tests/server_handshake.rs"}, seedRoots: []string{"rust/connection-core/fuzz-seeds/us011"}, cases: 17, testsPassed: 23,
	},
	"fuzz/frame-decode": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "frame_codec"}, sourcePaths: []string{"rust/connection-core/tests/frame_codec.rs"}, seedRoots: []string{"rust/connection-core/fuzz-seeds/us012"}, cases: 20, testsPassed: 17,
	},
	"fuzz/message-utf8": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "messages"}, sourcePaths: []string{"rust/connection-core/tests/messages.rs"}, seedRoots: []string{"rust/connection-core/fuzz-seeds/us013"}, cases: 20, testsPassed: 13,
	},
	"fuzz/fragment-control": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "fragmentation", "--test", "ping_pong"}, sourcePaths: []string{"rust/connection-core/tests/fragmentation.rs", "rust/connection-core/tests/ping_pong.rs"}, seedRoots: []string{"rust/connection-core/fuzz-seeds/us014", "rust/connection-core/fuzz-seeds/us015"}, cases: 30, testsPassed: 25,
	},
	"fuzz/close-eof": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-core", "--test", "close_eof"}, sourcePaths: []string{"rust/connection-core/tests/close_eof.rs"}, seedRoots: []string{"rust/connection-core/fuzz-seeds/us016"}, cases: 6, testsPassed: 20,
	},
	"fuzz/owner-command-byte-schedule": {
		command: []string{"cargo", "test", "--locked", "-p", "websocket-driver"}, sourcePaths: []string{"rust/websocket-driver/tests/concurrency.rs", "rust/websocket-driver/tests/driver_contract.rs", "rust/websocket-driver/tests/refinement_contract.rs"}, seedRoots: []string{"rust/websocket-driver/fuzz-seeds/us017"}, cases: 6, testsPassed: 22,
	},
}

// Verify checks every committed US-021 manifest and all repository identities it binds.
func Verify(repositoryRoot string) error {
	root, err := canonicalRoot(repositoryRoot)
	if err != nil {
		return err
	}
	if err := verifySchemas(root); err != nil {
		return err
	}
	seenKinds := map[string]bool{}
	for _, relative := range manifestPaths {
		raw, err := readRepositoryFile(root, relative, maximumDocument)
		if err != nil {
			return err
		}
		tree, err := decodeJSONTree(raw)
		if err != nil {
			return finding("INVALID_CAMPAIGN_EVIDENCE", relative, err.Error())
		}
		if err := verifyManifestShape(tree); err != nil {
			return finding("INVALID_CAMPAIGN_EVIDENCE", relative, err.Error())
		}
		var manifest Manifest
		if err := decodeStrict(raw, &manifest); err != nil {
			return finding("INVALID_CAMPAIGN_EVIDENCE", relative, err.Error())
		}
		if seenKinds[manifest.Kind] {
			return finding("DUPLICATE_CAMPAIGN_KIND", relative, manifest.Kind)
		}
		seenKinds[manifest.Kind] = true
		if err := verifyManifest(root, relative, manifest); err != nil {
			return err
		}
	}
	for _, kind := range []string{"property", "fuzz", "runtime"} {
		if !seenKinds[kind] {
			return finding("CAMPAIGN_KIND_MISSING", "$", kind)
		}
	}
	return nil
}

func verifyManifestShape(value any) error {
	root, err := jsonObject(value, "$")
	if err != nil {
		return err
	}
	kind, ok := root["kind"].(string)
	if !ok || (kind != "property" && kind != "fuzz" && kind != "runtime") {
		return errors.New("$.kind must identify a campaign kind")
	}
	top := []string{"$schema", "schema_version", "evidence_id", "story_id", "kind", "status", "assurance", "independent_review_claimed", "production", "publication", "signing", "repository_anchor", "rustc_version", "targets", "platforms", "external_tools", "remediations", "counts", "nonclaims"}
	if kind != "runtime" {
		top = append(top, "engine")
	}
	if err := requireObjectKeys(root, "$", top); err != nil {
		return err
	}
	if kind != "runtime" {
		engine, err := jsonObject(root["engine"], "$.engine")
		if err != nil {
			return err
		}
		if err := requireObjectKeys(engine, "$.engine", []string{"id", "seed", "minimum_cases", "repetitions", "deterministic"}); err != nil {
			return err
		}
	}
	targets, err := jsonArray(root["targets"], "$.targets")
	if err != nil {
		return err
	}
	for index, value := range targets {
		path := fmt.Sprintf("$.targets[%d]", index)
		target, err := jsonObject(value, path)
		if err != nil {
			return err
		}
		if err := requireObjectKeys(target, path, []string{"id", "invariant", "sources", "test_name", "command", "replay_command", "generator_domain", "shrinker", "cases", "seed_roots", "seed_count", "corpus_sha256", "timeout_seconds", "oom_policy", "crash_policy", "observations"}); err != nil {
			return err
		}
		if err := verifyObjectArrayShape(target["sources"], path+".sources", []string{"path", "sha256"}); err != nil {
			return err
		}
		if err := verifyObjectArrayShape(target["observations"], path+".observations", []string{"platform", "profile", "repeat", "status", "exit_code", "timed_out", "tests_passed", "tests_failed"}); err != nil {
			return err
		}
	}
	platforms, err := jsonArray(root["platforms"], "$.platforms")
	if err != nil {
		return err
	}
	for index, value := range platforms {
		path := fmt.Sprintf("$.platforms[%d]", index)
		platform, err := jsonObject(value, path)
		if err != nil {
			return err
		}
		if err := requireObjectKeys(platform, path, []string{"id", "execution_kind", "rustc_version", "source_tree", "debug", "release", "file_descriptor_cleanup", "process_cleanup", "flakes", "unresolved"}); err != nil {
			return err
		}
		sourceTree, err := jsonObject(platform["source_tree"], path+".source_tree")
		if err != nil {
			return err
		}
		if err := requireObjectKeys(sourceTree, path+".source_tree", []string{"commit", "tree"}); err != nil {
			return err
		}
		commandKeys := []string{"repeat", "command", "status", "exit_code", "timed_out", "tests_passed", "tests_failed", "panics", "hangs", "leaks"}
		if err := verifyObjectArrayShape(platform["debug"], path+".debug", commandKeys); err != nil {
			return err
		}
		if err := verifyObjectArrayShape(platform["release"], path+".release", commandKeys); err != nil {
			return err
		}
	}
	if err := verifyObjectArrayShape(root["external_tools"], "$.external_tools", []string{"id", "status", "claimed_pass", "evidence"}); err != nil {
		return err
	}
	if err := verifyObjectArrayShape(root["remediations"], "$.remediations", []string{"id", "platform", "original_command", "failure_class", "minimized_command", "inferred_boundary", "fix_commit", "closure_replays", "status"}); err != nil {
		return err
	}
	counts, err := jsonObject(root["counts"], "$.counts")
	if err != nil {
		return err
	}
	if err := requireObjectKeys(counts, "$.counts", []string{"targets", "cases", "observations", "platforms", "runtime_commands", "remediations", "failures", "timeouts", "panics", "hangs", "leaks", "flakes", "unresolved"}); err != nil {
		return err
	}
	_, err = jsonArray(root["nonclaims"], "$.nonclaims")
	return err
}

func verifyObjectArrayShape(value any, path string, keys []string) error {
	values, err := jsonArray(value, path)
	if err != nil {
		return err
	}
	for index, value := range values {
		itemPath := fmt.Sprintf("%s[%d]", path, index)
		object, err := jsonObject(value, itemPath)
		if err != nil {
			return err
		}
		if err := requireObjectKeys(object, itemPath, keys); err != nil {
			return err
		}
	}
	return nil
}

func requireObjectKeys(object map[string]any, path string, expected []string) error {
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			return fmt.Errorf("%s.%s is required", path, key)
		}
	}
	if len(object) != len(expected) {
		return fmt.Errorf("%s has %d fields, want %d", path, len(object), len(expected))
	}
	return nil
}

func jsonObject(value any, path string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", path)
	}
	return object, nil
}

func jsonArray(value any, path string) ([]any, error) {
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", path)
	}
	return array, nil
}

func decodeJSONTree(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder, "$")
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON value")
	}
	return value, nil
}

func decodeJSONValue(decoder *json.Decoder, path string) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("%s has a non-string key", path)
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("%s.%s is duplicated", path, key)
			}
			child, err := decodeJSONValue(decoder, path+"."+key)
			if err != nil {
				return nil, err
			}
			object[key] = child
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
			return nil, fmt.Errorf("%s object is not closed", path)
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			child, err := decodeJSONValue(decoder, fmt.Sprintf("%s[%d]", path, len(array)))
			if err != nil {
				return nil, err
			}
			array = append(array, child)
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
			return nil, fmt.Errorf("%s array is not closed", path)
		}
		return array, nil
	default:
		return nil, fmt.Errorf("%s has unexpected delimiter", path)
	}
}

func verifySchemas(root string) error {
	paths := make([]string, 0, len(schemaDigests))
	for path := range schemaDigests {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		expectedDigest := schemaDigests[path]
		raw, err := readRepositoryFile(root, path, maximumDocument)
		if err != nil {
			return err
		}
		var document any
		if err := json.Unmarshal(raw, &document); err != nil {
			return finding("INVALID_CAMPAIGN_SCHEMA", path, err.Error())
		}
		if digest(raw) != expectedDigest {
			return finding("CAMPAIGN_SCHEMA_DRIFT", path, "closed schema content differs")
		}
		if err := verifySchemaReferences(path, document); err != nil {
			return err
		}
	}
	return nil
}

func verifySchemaReferences(path string, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "$ref" {
				reference, ok := child.(string)
				if !ok || (!strings.HasPrefix(reference, "#/") && reference != "us021-campaign-common-1.0.0.schema.json") {
					return finding("UNSAFE_CAMPAIGN_SCHEMA_REFERENCE", path, fmt.Sprint(child))
				}
			}
			if err := verifySchemaReferences(path, child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := verifySchemaReferences(path, child); err != nil {
				return err
			}
		}
	}
	return nil
}

// CorpusIdentity returns the exact sorted path/content identity used by fuzz manifests.
func CorpusIdentity(repositoryRoot string, seedRoots []string) (string, uint64, error) {
	root, err := canonicalRoot(repositoryRoot)
	if err != nil {
		return "", 0, err
	}
	return digestSeedRoots(root, "", seedRoots)
}

// Manifest is the closed common envelope shared by the three US-021 evidence layers.
type Manifest struct {
	Schema                   string         `json:"$schema"`
	SchemaVersion            string         `json:"schema_version"`
	EvidenceID               string         `json:"evidence_id"`
	StoryID                  string         `json:"story_id"`
	Kind                     string         `json:"kind"`
	Status                   string         `json:"status"`
	Assurance                string         `json:"assurance"`
	IndependentReviewClaimed bool           `json:"independent_review_claimed"`
	Production               bool           `json:"production"`
	Publication              bool           `json:"publication"`
	Signing                  bool           `json:"signing"`
	RepositoryAnchor         string         `json:"repository_anchor"`
	RustcVersion             string         `json:"rustc_version"`
	Engine                   *Engine        `json:"engine,omitempty"`
	Targets                  []Target       `json:"targets"`
	Platforms                []Platform     `json:"platforms"`
	ExternalTools            []ExternalTool `json:"external_tools"`
	Remediations             []Remediation  `json:"remediations"`
	Counts                   Counts         `json:"counts"`
	Nonclaims                []string       `json:"nonclaims"`
}

// Engine binds the finite in-tree campaign algorithm.
type Engine struct {
	ID            string `json:"id"`
	Seed          uint64 `json:"seed"`
	MinimumCases  uint64 `json:"minimum_cases"`
	Repetitions   uint64 `json:"repetitions"`
	Deterministic bool   `json:"deterministic"`
}

// Target binds one property or fuzz seam to executable Rust tests and corpora.
type Target struct {
	ID              string        `json:"id"`
	Invariant       string        `json:"invariant"`
	Sources         []Artifact    `json:"sources"`
	TestName        string        `json:"test_name"`
	Command         []string      `json:"command"`
	ReplayCommand   []string      `json:"replay_command"`
	GeneratorDomain string        `json:"generator_domain"`
	Shrinker        string        `json:"shrinker"`
	Cases           uint64        `json:"cases"`
	SeedRoots       []string      `json:"seed_roots"`
	SeedCount       uint64        `json:"seed_count"`
	CorpusSHA256    string        `json:"corpus_sha256"`
	TimeoutSeconds  uint64        `json:"timeout_seconds"`
	OOMPolicy       string        `json:"oom_policy"`
	CrashPolicy     string        `json:"crash_policy"`
	Observations    []Observation `json:"observations"`
}

// Artifact is one regular repository file and its exact content identity.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Observation is one completed bounded target repetition.
type Observation struct {
	Platform    string `json:"platform"`
	Profile     string `json:"profile"`
	Repeat      uint64 `json:"repeat"`
	Status      string `json:"status"`
	ExitCode    int    `json:"exit_code"`
	TimedOut    bool   `json:"timed_out"`
	TestsPassed uint64 `json:"tests_passed"`
	TestsFailed uint64 `json:"tests_failed"`
}

// Platform binds one native blocking-platform runtime gate.
type Platform struct {
	ID                    string           `json:"id"`
	ExecutionKind         string           `json:"execution_kind"`
	RustcVersion          string           `json:"rustc_version"`
	SourceTree            SourceTree       `json:"source_tree"`
	Debug                 []RuntimeCommand `json:"debug"`
	Release               []RuntimeCommand `json:"release"`
	FileDescriptorCleanup string           `json:"file_descriptor_cleanup"`
	ProcessCleanup        string           `json:"process_cleanup"`
	Flakes                uint64           `json:"flakes"`
	Unresolved            uint64           `json:"unresolved"`
}

// SourceTree binds runtime receipts to an immutable Git commit and tree.
type SourceTree struct {
	Commit string `json:"commit"`
	Tree   string `json:"tree"`
}

// RuntimeCommand is one full-workspace runtime repetition.
type RuntimeCommand struct {
	Repeat      uint64   `json:"repeat"`
	Command     []string `json:"command"`
	Status      string   `json:"status"`
	ExitCode    int      `json:"exit_code"`
	TimedOut    bool     `json:"timed_out"`
	TestsPassed uint64   `json:"tests_passed"`
	TestsFailed uint64   `json:"tests_failed"`
	Panics      uint64   `json:"panics"`
	Hangs       uint64   `json:"hangs"`
	Leaks       uint64   `json:"leaks"`
}

// ExternalTool records an exact supported/unavailable boundary.
type ExternalTool struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	ClaimedPass bool   `json:"claimed_pass"`
	Evidence    string `json:"evidence"`
}

// Remediation retains one discovered failure and its bounded closure evidence.
type Remediation struct {
	ID               string   `json:"id"`
	Platform         string   `json:"platform"`
	OriginalCommand  []string `json:"original_command"`
	FailureClass     string   `json:"failure_class"`
	MinimizedCommand []string `json:"minimized_command"`
	InferredBoundary string   `json:"inferred_boundary"`
	FixCommit        string   `json:"fix_commit"`
	ClosureReplays   uint64   `json:"closure_replays"`
	Status           string   `json:"status"`
}

// Counts reconciles one manifest without inferring success from empty arrays.
type Counts struct {
	Targets         uint64 `json:"targets"`
	Cases           uint64 `json:"cases"`
	Observations    uint64 `json:"observations"`
	Platforms       uint64 `json:"platforms"`
	RuntimeCommands uint64 `json:"runtime_commands"`
	Remediations    uint64 `json:"remediations"`
	Failures        uint64 `json:"failures"`
	Timeouts        uint64 `json:"timeouts"`
	Panics          uint64 `json:"panics"`
	Hangs           uint64 `json:"hangs"`
	Leaks           uint64 `json:"leaks"`
	Flakes          uint64 `json:"flakes"`
	Unresolved      uint64 `json:"unresolved"`
}

func verifyManifest(root, relative string, manifest Manifest) error {
	expectedSchema := "../../schemas/us021-" + manifest.Kind + "-manifest-1.0.0.schema.json"
	if manifest.Schema != expectedSchema || manifest.SchemaVersion != "1.0.0" || manifest.EvidenceID != "evidence.us-021-"+manifest.Kind || manifest.StoryID != "US-021" {
		return finding("CAMPAIGN_IDENTITY_MISMATCH", relative, "schema or evidence identity differs")
	}
	if manifest.Status != "PASS_OWNER_RELAXED" || manifest.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || manifest.IndependentReviewClaimed || manifest.Production || manifest.Publication || manifest.Signing {
		return finding("CAMPAIGN_OVERCLAIM", relative, "status or assurance exceeds owner-relaxed evidence")
	}
	if len(manifest.RepositoryAnchor) != 40 || strings.Trim(manifest.RepositoryAnchor, "0123456789abcdef") != "" || manifest.RustcVersion != rustc195 {
		return finding("CAMPAIGN_TOOLCHAIN_MISMATCH", relative, "repository or Rust toolchain identity differs")
	}
	if _, err := repositoryTree(root, manifest.RepositoryAnchor); err != nil {
		return err
	}
	if err := verifyExternalTools(relative, manifest.Kind, manifest.ExternalTools); err != nil {
		return err
	}
	if len(manifest.Nonclaims) == 0 || !contains(manifest.Nonclaims, "no unbounded proof or race-freedom claim") || !contains(manifest.Nonclaims, "no live Autobahn or Docker/wstest conformance rerun") {
		return finding("CAMPAIGN_NONCLAIM_MISSING", relative, "required nonclaims absent")
	}
	if manifest.Kind == "runtime" {
		return verifyRuntime(root, relative, manifest)
	}
	return verifyTargets(root, relative, manifest)
}

func verifyTargets(root, relative string, manifest Manifest) error {
	expected, ok := exactTargets[manifest.Kind]
	if !ok || manifest.Engine == nil || manifest.Engine.ID != "in-tree-deterministic-v1" || manifest.Engine.Seed != 0x6455_2026_0821 || manifest.Engine.MinimumCases == 0 || manifest.Engine.Repetitions != 2 || !manifest.Engine.Deterministic {
		return finding("CAMPAIGN_ENGINE_MISMATCH", relative, "engine identity or bounds differ")
	}
	if len(manifest.Targets) != len(expected) || len(manifest.Platforms) != 0 || len(manifest.Remediations) != 0 {
		return finding("CAMPAIGN_TARGET_MISMATCH", relative, "target or platform cardinality differs")
	}
	ids := make([]string, 0, len(manifest.Targets))
	var cases, observations uint64
	for _, target := range manifest.Targets {
		ids = append(ids, target.ID)
		if err := verifyTarget(root, manifest.RepositoryAnchor, relative, manifest.Kind, target); err != nil {
			return err
		}
		cases += target.Cases
		observations += uint64(len(target.Observations))
	}
	sort.Strings(ids)
	if !equalStrings(ids, expected) {
		return finding("CAMPAIGN_TARGET_MISMATCH", relative, "fixed target inventory differs")
	}
	counts := manifest.Counts
	if counts.Targets != uint64(len(manifest.Targets)) || counts.Cases != cases || counts.Observations != observations || counts.Platforms != 0 || counts.RuntimeCommands != 0 || counts.Remediations != 0 || anyFailure(counts) {
		return finding("CAMPAIGN_COUNT_MISMATCH", relative, "target counts do not reconcile")
	}
	return nil
}

func verifyTarget(root, anchor, manifestPath, kind string, target Target) error {
	if target.ID == "" || target.Invariant == "" || target.TestName == "" || len(target.Sources) == 0 || target.GeneratorDomain == "" || target.Shrinker == "" || target.Cases == 0 || target.TimeoutSeconds == 0 || target.OOMPolicy != "FAIL_AND_CAPTURE" || target.CrashPolicy != "FAIL_MINIMIZE_AND_REPLAY" {
		return finding("INVALID_CAMPAIGN_TARGET", manifestPath, target.ID)
	}
	contract, ok := targetContracts[kind+"/"+target.ID]
	if !ok || !equalStrings(target.Command, contract.command) || !equalStrings(target.ReplayCommand, contract.command) || !equalStrings(target.SeedRoots, contract.seedRoots) || target.Cases != contract.cases {
		return finding("CAMPAIGN_TARGET_CONTRACT_MISMATCH", manifestPath, target.ID)
	}
	seenSources := map[string]bool{}
	sourcePaths := make([]string, 0, len(target.Sources))
	for _, source := range target.Sources {
		if seenSources[source.Path] {
			return finding("DUPLICATE_CAMPAIGN_SOURCE", manifestPath, source.Path)
		}
		seenSources[source.Path] = true
		sourcePaths = append(sourcePaths, source.Path)
		if err := verifyArtifact(root, anchor, source); err != nil {
			return err
		}
	}
	if !equalStrings(sourcePaths, contract.sourcePaths) {
		return finding("CAMPAIGN_TARGET_CONTRACT_MISMATCH", manifestPath, target.ID)
	}
	if err := verifyCommand(target.Command); err != nil || verifyCommand(target.ReplayCommand) != nil {
		return finding("INVALID_REPLAY_COMMAND", manifestPath, target.ID)
	}
	if len(target.Observations) != 2 {
		return finding("CAMPAIGN_REPETITION_MISMATCH", manifestPath, target.ID)
	}
	for index, observation := range target.Observations {
		if observation.Platform != "darwin/arm64" || observation.Profile != "debug" || observation.Repeat != uint64(index+1) || observation.Status != "PASS" || observation.ExitCode != 0 || observation.TimedOut || observation.TestsPassed != contract.testsPassed || observation.TestsFailed != 0 {
			return finding("CAMPAIGN_OBSERVATION_FAILED", manifestPath, target.ID)
		}
	}
	digest, count, err := digestSeedRoots(root, anchor, target.SeedRoots)
	if err != nil {
		return err
	}
	if target.SeedCount != count || target.CorpusSHA256 != digest {
		return finding("CAMPAIGN_CORPUS_DRIFT", manifestPath, target.ID)
	}
	return nil
}

func verifyRuntime(root, relative string, manifest Manifest) error {
	if manifest.Engine != nil || len(manifest.Targets) != 0 || len(manifest.Platforms) != 2 {
		return finding("RUNTIME_PLATFORM_MISMATCH", relative, "runtime evidence requires exactly two platforms")
	}
	ids := make([]string, 0, 2)
	var commands, tests uint64
	tree, err := repositoryTree(root, manifest.RepositoryAnchor)
	if err != nil {
		return err
	}
	for _, platform := range manifest.Platforms {
		ids = append(ids, platform.ID)
		if platform.ExecutionKind != "NATIVE" || platform.RustcVersion != rustc195 || platform.FileDescriptorCleanup != "PASS" || platform.ProcessCleanup != "PASS" || platform.Flakes != 0 || platform.Unresolved != 0 || len(platform.Debug) != 2 || len(platform.Release) != 2 {
			return finding("RUNTIME_PLATFORM_FAILED", relative, platform.ID)
		}
		if platform.SourceTree.Commit != manifest.RepositoryAnchor || platform.SourceTree.Tree != tree {
			return finding("RUNTIME_SOURCE_TREE_MISMATCH", relative, platform.ID)
		}
		groups := []struct {
			commands []RuntimeCommand
			expected []string
		}{
			{platform.Debug, []string{"cargo", "test", "--workspace", "--all-targets", "--locked"}},
			{platform.Release, []string{"cargo", "test", "--workspace", "--all-targets", "--locked", "--release"}},
		}
		for _, group := range groups {
			for index, command := range group.commands {
				if command.Repeat != uint64(index+1) || !equalStrings(command.Command, group.expected) || verifyCommand(command.Command) != nil || command.Status != "PASS" || command.ExitCode != 0 || command.TimedOut || command.TestsPassed != 181 || command.TestsFailed != 0 || command.Panics != 0 || command.Hangs != 0 || command.Leaks != 0 {
					return finding("RUNTIME_COMMAND_FAILED", relative, platform.ID)
				}
				commands++
				tests += command.TestsPassed
			}
		}
	}
	sort.Strings(ids)
	if !equalStrings(ids, []string{"darwin/arm64", "linux/arm64"}) {
		return finding("RUNTIME_PLATFORM_MISMATCH", relative, "exact native platform set differs")
	}
	if err := verifyRuntimeRemediation(relative, manifest); err != nil {
		return err
	}
	counts := manifest.Counts
	if counts.Targets != 0 || counts.Cases != tests || counts.Observations != 0 || counts.Platforms != 2 || counts.RuntimeCommands != commands || counts.Remediations != uint64(len(manifest.Remediations)) || anyFailure(counts) {
		return finding("CAMPAIGN_COUNT_MISMATCH", relative, "runtime counts do not reconcile")
	}
	return nil
}

func verifyRuntimeRemediation(path string, manifest Manifest) error {
	if len(manifest.Remediations) != 1 {
		return finding("RUNTIME_REMEDIATION_MISSING", path, "exactly one discovered failure must be retained")
	}
	remediation := manifest.Remediations[0]
	original := []string{"cargo", "test", "--workspace", "--all-targets", "--locked"}
	minimized := []string{"cargo", "test", "--locked", "-p", "websocket-testee", "--test", "process", "server_process_binds_one_loopback_peer_and_exits", "--", "--exact"}
	if remediation.ID != "us021-linux-tcp-reset" || remediation.Platform != "linux/arm64" || !equalStrings(remediation.OriginalCommand, original) || remediation.FailureClass != "INTERMITTENT_CONNECTION_RESET_AFTER_COMPLETE_SERVER_RESPONSE" || !equalStrings(remediation.MinimizedCommand, minimized) || remediation.InferredBoundary == "" || remediation.FixCommit != manifest.RepositoryAnchor || remediation.ClosureReplays != 8 || remediation.Status != "CLOSED" {
		return finding("RUNTIME_REMEDIATION_INVALID", path, remediation.ID)
	}
	return nil
}

func repositoryTree(root, commit string) (string, error) {
	if len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" {
		return "", finding("CAMPAIGN_GIT_IDENTITY_INVALID", "$", commit)
	}
	output, err := exec.Command("git", "-C", root, "rev-parse", "--verify", commit+"^{tree}").Output()
	if err != nil {
		return "", finding("CAMPAIGN_GIT_IDENTITY_INVALID", "$", commit)
	}
	tree := strings.TrimSpace(string(output))
	if len(tree) != 40 || strings.Trim(tree, "0123456789abcdef") != "" {
		return "", finding("CAMPAIGN_GIT_IDENTITY_INVALID", "$", commit)
	}
	return tree, nil
}

func readGitFile(root, commit, relative string, maximum int) ([]byte, error) {
	clean, err := safeRelative(relative)
	if err != nil {
		return nil, err
	}
	objectOutput, err := exec.Command("git", "-C", root, "rev-parse", "--verify", commit+":"+clean).Output()
	object := strings.TrimSpace(string(objectOutput))
	if err != nil || len(object) != 40 || strings.Trim(object, "0123456789abcdef") != "" {
		return nil, finding("CAMPAIGN_ANCHOR_PATH_MISSING", relative, commit)
	}
	typeOutput, err := exec.Command("git", "-C", root, "cat-file", "-t", object).Output()
	if err != nil || strings.TrimSpace(string(typeOutput)) != "blob" {
		return nil, finding("CAMPAIGN_ANCHOR_PATH_INVALID", relative, "object is not a blob")
	}
	sizeOutput, err := exec.Command("git", "-C", root, "cat-file", "-s", object).Output()
	var size int
	if err != nil {
		return nil, finding("CAMPAIGN_ANCHOR_PATH_INVALID", relative, "blob size unavailable")
	}
	if _, err := fmt.Sscan(strings.TrimSpace(string(sizeOutput)), &size); err != nil || size < 0 || size > maximum {
		return nil, finding("CAMPAIGN_ANCHOR_PATH_INVALID", relative, "blob size outside bounds")
	}
	data, err := exec.Command("git", "-C", root, "cat-file", "blob", object).Output()
	if err != nil || len(data) != size {
		return nil, finding("CAMPAIGN_ANCHOR_PATH_INVALID", relative, "blob read failed")
	}
	return data, nil
}

func verifyExternalTools(path, kind string, tools []ExternalTool) error {
	ids := make([]string, 0, len(tools))
	for _, tool := range tools {
		ids = append(ids, tool.ID)
		if tool.ID == "" || tool.Evidence == "" || (tool.Status != "PASS" && tool.Status != "UNAVAILABLE") || (tool.Status == "UNAVAILABLE" && tool.ClaimedPass) || (tool.Status == "PASS") != tool.ClaimedPass {
			return finding("EXTERNAL_TOOL_OVERCLAIM", path, tool.ID)
		}
	}
	if len(ids) != len(unique(ids)) {
		return finding("DUPLICATE_EXTERNAL_TOOL", path, "tool IDs repeat")
	}
	sort.Strings(ids)
	expected := map[string][]string{
		"property": {},
		"fuzz":     {"cargo-fuzz", "miri"},
		"runtime":  {"miri", "sanitizers", "thread-sanitizer"},
	}[kind]
	if !equalStrings(ids, expected) {
		return finding("EXTERNAL_TOOL_INVENTORY_MISMATCH", path, kind)
	}
	return nil
}

func verifyArtifact(root, anchor string, artifact Artifact) error {
	data, err := readRepositoryFile(root, artifact.Path, maximumDocument)
	if err != nil {
		return err
	}
	if artifact.SHA256 != digest(data) {
		return finding("CAMPAIGN_SOURCE_DRIFT", artifact.Path, "content digest differs")
	}
	committed, err := readGitFile(root, anchor, artifact.Path, maximumDocument)
	if err != nil {
		return err
	}
	if artifact.SHA256 != digest(committed) {
		return finding("CAMPAIGN_ANCHOR_DRIFT", artifact.Path, anchor)
	}
	return nil
}

func digestSeedRoots(root, anchor string, roots []string) (string, uint64, error) {
	if len(roots) == 0 {
		return digest(nil), 0, nil
	}
	entries := make([]string, 0)
	paths := make([]string, 0)
	for _, relativeRoot := range roots {
		clean, err := safeRelative(relativeRoot)
		if err != nil {
			return "", 0, err
		}
		absolute := filepath.Join(root, filepath.FromSlash(clean))
		info, err := os.Lstat(absolute)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", 0, finding("INVALID_CAMPAIGN_PATH", relativeRoot, "seed root is not a real directory")
		}
		err = filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == absolute || entry.IsDir() {
				return nil
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return finding("INVALID_CAMPAIGN_PATH", path, "seed is not a regular file")
			}
			data, err := os.ReadFile(path)
			if err != nil || len(data) > maximumDocument {
				return finding("INVALID_CAMPAIGN_PATH", path, "seed cannot be read safely")
			}
			relative, _ := filepath.Rel(root, path)
			repositoryPath := filepath.ToSlash(relative)
			if anchor != "" {
				committed, err := readGitFile(root, anchor, repositoryPath, maximumDocument)
				if err != nil {
					return err
				}
				if digest(data) != digest(committed) {
					return finding("CAMPAIGN_ANCHOR_DRIFT", repositoryPath, anchor)
				}
			}
			paths = append(paths, repositoryPath)
			entries = append(entries, repositoryPath+" "+digest(data))
			return nil
		})
		if err != nil {
			return "", 0, err
		}
	}
	sort.Strings(entries)
	sort.Strings(paths)
	if anchor != "" {
		committedPaths, err := gitSeedPaths(root, anchor, roots)
		if err != nil {
			return "", 0, err
		}
		if !equalStrings(paths, committedPaths) {
			return "", 0, finding("CAMPAIGN_ANCHOR_CORPUS_DRIFT", "$", anchor)
		}
	}
	return digest([]byte(strings.Join(entries, "\n") + "\n")), uint64(len(entries)), nil
}

func gitSeedPaths(root, anchor string, roots []string) ([]string, error) {
	arguments := []string{"-C", root, "ls-tree", "-r", "--name-only", "-z", anchor, "--"}
	for _, relative := range roots {
		clean, err := safeRelative(relative)
		if err != nil {
			return nil, err
		}
		arguments = append(arguments, clean)
	}
	output, err := exec.Command("git", arguments...).Output()
	if err != nil || len(output) > maximumDocument {
		return nil, finding("CAMPAIGN_ANCHOR_CORPUS_INVALID", "$", anchor)
	}
	parts := bytes.Split(output, []byte{0})
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		path := string(part)
		if _, err := safeRelative(path); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, nil
}

func verifyCommand(command []string) error {
	if len(command) < 2 || len(command) > 16 {
		return errors.New("command token count outside fixed bounds")
	}
	for _, token := range command {
		if token == "" || strings.ContainsAny(token, "\x00\r\n") || strings.ContainsAny(token, ";|&`$<>") {
			return errors.New("unsafe command token")
		}
	}
	return nil
}

func canonicalRoot(root string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", finding("INVALID_REPOSITORY_ROOT", root, "root must be absolute and clean")
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil || real != root {
		return "", finding("INVALID_REPOSITORY_ROOT", root, "root must be a canonical real directory")
	}
	return root, nil
}

func readRepositoryFile(root, relative string, maximum int) ([]byte, error) {
	clean, err := safeRelative(relative)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, filepath.FromSlash(clean))
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > int64(maximum) {
		return nil, finding("INVALID_CAMPAIGN_PATH", relative, "file is absent, linked, special, or oversized")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > maximum {
		return nil, finding("INVALID_CAMPAIGN_PATH", relative, "file read failed")
	}
	return data, nil
}

func safeRelative(path string) (string, error) {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.ToSlash(path) != path || path == "." || strings.HasPrefix(path, "../") {
		return "", finding("INVALID_CAMPAIGN_PATH", path, "path must be canonical and repository-relative")
	}
	return path, nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bufio.NewReader(strings.NewReader(string(data))))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func finding(code, path, detail string) error {
	return fmt.Errorf("%s at %s: %s", code, path, detail)
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
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

func unique(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func anyFailure(counts Counts) bool {
	return counts.Failures != 0 || counts.Timeouts != 0 || counts.Panics != 0 || counts.Hangs != 0 || counts.Leaks != 0 || counts.Flakes != 0 || counts.Unresolved != 0
}
