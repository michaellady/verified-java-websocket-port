package corpora

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ServerHandshakeProjection binds US-011 to the immutable client-request
// corpus, independent nonce/accept literals, inert fuzz seeds, and closure
// artifacts without mutating the US-005 source corpus.
type ServerHandshakeProjection struct {
	Schema         string                        `json:"$schema"`
	SchemaVersion  string                        `json:"schema_version"`
	CorpusID       string                        `json:"corpus_id"`
	Authority      ServerHandshakeAuthority      `json:"authority"`
	FrozenSource   ClientHandshakeFrozenSource   `json:"frozen_source"`
	FrozenCases    []ServerHandshakeCase         `json:"frozen_cases"`
	Additive       []string                      `json:"additive_vectors"`
	Properties     ServerHandshakeProperties     `json:"properties"`
	NonceVectors   []ServerHandshakeNonceVector  `json:"nonce_vectors"`
	FuzzSeeds      []ClientHandshakeFuzzSeed     `json:"fuzz_seeds"`
	Reconciliation ServerHandshakeReconciliation `json:"reconciliation"`
	Nonclaims      []string                      `json:"nonclaims"`
	Assurance      ClientHandshakeAssurance      `json:"assurance"`
}

// ServerHandshakeAuthority records the deliberate RFC-over-Java priority.
type ServerHandshakeAuthority struct {
	Priority            []string `json:"priority"`
	JavaObservationMode string   `json:"java_observation_mode"`
	StrictnessRule      string   `json:"strictness_rule"`
}

// ServerHandshakeCase is one exact RFC verdict projected into a typed Rust
// outcome. The raw fixture remains single-sourced in cases.jsonl.
type ServerHandshakeCase struct {
	CaseID       string                         `json:"case_id"`
	RFCVerdict   string                         `json:"rfc_verdict"`
	RFCReject    string                         `json:"rfc_reject_code,omitempty"`
	RustExpected string                         `json:"rust_expected"`
	Java         ServerHandshakeJavaObservation `json:"java_source_observation"`
}

// ServerHandshakeJavaObservation makes the source-derived Java comparison a
// per-case claim. It is intentionally not a live-execution or parity claim.
type ServerHandshakeJavaObservation struct {
	MappingKey    string   `json:"mapping_key"`
	Observable    string   `json:"observable"`
	Divergent     bool     `json:"divergent"`
	RejectChannel string   `json:"reject_channel,omitempty"`
	Condition     string   `json:"condition,omitempty"`
	Basis         []string `json:"basis"`
}

// ServerHandshakeProperties records only executions required by the story.
type ServerHandshakeProperties struct {
	ValidCases              int      `json:"valid_cases"`
	TwoChunkExecutions      int      `json:"two_chunk_executions_per_profile"`
	BytewiseExecutions      int      `json:"bytewise_executions_per_profile"`
	MultiChunkExecutions    int      `json:"multi_chunk_executions_per_profile"`
	NonceVectors            int      `json:"nonce_vectors"`
	DeterministicProperties []string `json:"deterministic_properties"`
	ExecutionID             string   `json:"execution_id"`
}

// ServerHandshakeNonceVector is an independently recomputed literal oracle.
type ServerHandshakeNonceVector struct {
	NonceHex string `json:"nonce_hex"`
	Key      string `json:"key"`
	Accept   string `json:"accept"`
}

// ServerHandshakeReconciliation connects the corpus to each acceptance lane.
type ServerHandshakeReconciliation struct {
	MigrationSlice    string   `json:"migration_slice"`
	PropertyIDs       []string `json:"property_ids"`
	FuzzHarness       string   `json:"fuzz_harness"`
	RuntimeAssertions []string `json:"runtime_assertions"`
	DeltaLedger       string   `json:"delta_ledger"`
	EvidenceReceipt   string   `json:"evidence_receipt"`
}

type serverFrozenExpectation struct {
	verdict           string
	reject            string
	rust              string
	javaObservable    string
	javaDivergent     bool
	javaRejectChannel string
}

var frozenServerExpectations = map[string]serverFrozenExpectation{
	"us005.hs.0000": {"accept", "", "Open", "accept", false, ""},
	"us005.hs.0001": {"accept", "", "Open", "accept", false, ""},
	"us005.hs.0002": {"accept", "", "Open", "accept", false, ""},
	"us005.hs.0003": {"accept", "", "Open", "accept", false, ""},
	"us005.hs.0004": {"accept", "", "Open", "accept", false, ""},
	"us005.hs.0005": {"accept", "", "Open", "accept", false, ""},
	"us005.hs.0009": {"reject", "HS_METHOD_NOT_GET", "MethodNotGet", "reject", false, "invalid_handshake"},
	"us005.hs.0010": {"reject", "HS_METHOD_NOT_GET", "MethodNotGet", "reject", false, "invalid_handshake"},
	"us005.hs.0011": {"reject", "HS_HTTP_VERSION", "HttpVersionNot11", "reject", false, "invalid_handshake"},
	"us005.hs.0012": {"reject", "HS_HTTP_VERSION", "HttpVersionNot11", "reject", false, "invalid_handshake"},
	"us005.hs.0013": {"reject", "HS_MISSING_HOST", "MissingHost", "accept", true, ""},
	"us005.hs.0014": {"reject", "HS_MISSING_UPGRADE", "MissingUpgrade", "accept", true, ""},
	"us005.hs.0015": {"reject", "HS_UPGRADE_VALUE", "InvalidUpgrade", "accept", true, ""},
	"us005.hs.0016": {"reject", "HS_MISSING_CONNECTION", "MissingConnection", "accept", true, ""},
	"us005.hs.0017": {"reject", "HS_CONNECTION_VALUE", "InvalidConnection", "accept", true, ""},
	"us005.hs.0018": {"reject", "HS_MISSING_KEY", "MissingKey", "reject", false, "invalid_handshake"},
	"us005.hs.0019": {"reject", "HS_KEY_NOT_BASE64", "InvalidKeyEncoding", "accept", true, ""},
	"us005.hs.0020": {"reject", "HS_KEY_NOT_BASE64", "InvalidKeyEncoding", "accept", true, ""},
	"us005.hs.0021": {"reject", "HS_KEY_LENGTH", "InvalidKeyLength(15)", "accept", true, ""},
	"us005.hs.0022": {"reject", "HS_KEY_LENGTH", "InvalidKeyLength(17)", "accept", true, ""},
	"us005.hs.0023": {"reject", "HS_MISSING_VERSION", "MissingVersion", "reject", false, "not_matched"},
	"us005.hs.0024": {"reject", "HS_VERSION_UNSUPPORTED", "UnsupportedVersion", "reject", false, "not_matched"},
	"us005.hs.0025": {"reject", "HS_VERSION_UNSUPPORTED", "UnsupportedVersion", "reject", false, "not_matched"},
	"us005.hs.0026": {"reject", "HS_VERSION_UNSUPPORTED", "UnsupportedVersion", "reject", false, "not_matched"},
	"us005.hs.0027": {"reject", "HS_DUPLICATE_HEADER", "DuplicateHeader", "accept", true, ""},
	"us005.hs.0028": {"reject", "HS_DUPLICATE_HEADER", "DuplicateHeader", "reject", false, "not_matched"},
	"us005.hs.0029": {"reject", "HS_HEADER_NAME_NOT_TOKEN", "InvalidHeaderName", "accept", true, ""},
	"us005.hs.0030": {"reject", "HS_HEADER_NAME_NOT_TOKEN", "InvalidHeaderName", "accept", true, ""},
	"us005.hs.0031": {"reject", "HS_MALFORMED_REQUEST_LINE", "MalformedRequestLine", "reject", false, "invalid_handshake"},
	"us005.hs.0032": {"reject", "HS_MALFORMED_REQUEST_LINE", "MalformedRequestLine", "reject", false, "invalid_handshake"},
	"us005.hs.0033": {"reject", "HS_OBS_FOLD", "ObsoleteLineFolding", "reject", false, "invalid_handshake"},
	"us005.hs.0034": {"reject", "HS_BARE_LF", "BareLineEnding", "accept", true, ""},
	"us005.hs.0042": {"incomplete", "", "IncompleteThenUnexpectedEof", "incomplete", false, ""},
	"us005.hs.0043": {"incomplete", "", "IncompleteThenUnexpectedEof", "incomplete", false, ""},
	"us005.hs.0044": {"incomplete", "", "IncompleteThenUnexpectedEof", "incomplete", false, ""},
	"us005.hs.0045": {"incomplete", "", "IncompleteThenUnexpectedEof", "incomplete", false, ""},
	"us005.hs.0046": {"reject", "HS_LIMIT_TOTAL_BYTES", "HandshakeBytes(173>172)", "accept", true, ""},
	"us005.hs.0047": {"reject", "HS_LIMIT_HEADER_COUNT", "HandshakeHeaderCount(3>2)", "accept", true, ""},
	"us005.hs.0048": {"reject", "HS_LIMIT_HEADER_LINE_BYTES", "HandshakeHeaderLineBytes(9>8)", "accept", true, ""},
}

var exactServerProperties = []string{
	"six accepted frozen requests open at every two-chunk split including empty endpoints",
	"six accepted frozen requests open byte-at-a-time",
	"six accepted frozen requests open under three deterministic multi-chunk plans",
	"256 deterministic nonce keys produce independently computed literal accepts",
	"required header-name and token-member ASCII casing preserves accepted meaning",
	"mutations, negotiation fields, framing fields, suffixes, limits, and EOF fail before Open",
}

var exactServerAdditiveVectors = []string{
	"lowercase-method", "extra-request-line-token", "absolute-form-target", "asterisk-form-target",
	"fragment-target", "invalid-host", "required-token-placement", "version-plus-13",
	"version-leading-zero", "base64-alphabet-boundary", "base64-padding-boundary",
	"base64-pad-bit-mutation", "request-line-control-and-del", "header-name-control-and-del",
	"header-value-control-and-del", "case-insensitive-duplicate", "content-length",
	"transfer-encoding", "unexpected-extension", "unexpected-subprotocol", "partial-eof",
	"valid-plus-suffix", "total-limit", "line-limit", "count-limit", "response-capacity",
}

var exactServerNonclaims = []string{
	"no frame coding or application data",
	"no live Java committed-corpus execution",
	"no Autobahn execution or conformance",
	"no extension or subprotocol negotiation",
	"no complete WebSocket conformance or Java parity",
	"no independent review",
	"no release publication production signing or benchmark readiness",
}

var exactServerFuzzSeeds = map[string]fuzzSeedExpectation{
	"rust/connection-core/fuzz-seeds/us011/bare-lf.hex":                 {"sha256:1786608589889a6cf640807d5a5fbef8cb983b20a83112d2f577287135241488", "BareLineEnding", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/obs-fold.hex":                {"sha256:1b9511afb3ccef7a3a9c1c94cd92f386efee16354bda1b04a06069e985416a77", "ObsoleteLineFolding", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/invalid-header-name.hex":     {"sha256:8362a1a0d7350287263351898e0db95108f86c8b296eec7663b12929da9a97fb", "InvalidHeaderName", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/forbidden-value-control.hex": {"sha256:75b59cdc8ee9871443a8097c24ef9442f0e427d9e6221ab411751c3bec6b8bbe", "InvalidHeaderValueOctet", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/malformed-request-line.hex":  {"sha256:cd73cbb0a0103d938730a2c495609cebfd485e0dcf8b561f84d0ba3b9e7595de", "MalformedRequestLine", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/duplicate-casing.hex":        {"sha256:83f5c122ccebfa380514a6c01121bc5750495aca815163609c70a7c9efb41749", "DuplicateHeader", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/content-length.hex":          {"sha256:28e009264ecbf95f7e993e261e226b7879e0afb8b3bb91f2b4bfa7899cd814d2", "UnexpectedContentLength", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/transfer-encoding.hex":       {"sha256:cb5537915d6f2e8b7069352ae5d3256e9ea835e9f51dd0bb3b480a8421bff1e4", "UnexpectedTransferEncoding", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/noncanonical-key.hex":        {"sha256:0693339904423d7afb702467eef34fd0d07d0fb05ed47c0b66cef2d51bb4074c", "InvalidKeyEncoding", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/wrong-key-length.hex":        {"sha256:825c828f13a725d430e83d9aee695b3cb5203994549496d3ef3be88e1e4003c8", "InvalidKeyLength(3)", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/extension.hex":               {"sha256:c230ece6b31e75a12e160977b10169ab92c16f117903d37ee138ec7d381de88f", "UnexpectedExtension", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/subprotocol.hex":             {"sha256:74721d58d72c2acf5320c3bb370ac619fafa1d7829a74bfd7d571cd8d02b44eb", "UnexpectedSubprotocol", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/incomplete-crlf.hex":         {"sha256:2428429aebab64d2d3fff3f20e058bfe784ae241562b22d9236214e8c15dc5d9", "UnexpectedEof", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/valid-plus-suffix.hex":       {"sha256:e76f152f20bef869918bc570a98fee277b381457793f6d9c5cd6de92ad114202", "TrailingData(1)", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us011/total-limit.hex":             {"sha256:6f485fcff1516c95bceb470e201f16f2ee96fdc98c5d21d507574b43b82d6f0f", "HandshakeBytes(9>8)", HandshakeConfig{8, 32, 8}},
	"rust/connection-core/fuzz-seeds/us011/line-limit.hex":              {"sha256:6f485fcff1516c95bceb470e201f16f2ee96fdc98c5d21d507574b43b82d6f0f", "HandshakeHeaderLineBytes(9>8)", HandshakeConfig{16, 32, 8}},
	"rust/connection-core/fuzz-seeds/us011/count-limit.hex":             {"sha256:c1e6da0a17e2b60d1f61216fe6616dbf645d1f0eec0b974a02494ff99eaa18fc", "HandshakeHeaderCount(3>2)", HandshakeConfig{128, 2, 64}},
}

// LoadAndVerifyServerHandshakeProjection verifies frozen source verdicts,
// independent nonce accepts, executable fuzz bindings, Java differential
// coverage, and the owner-only/non-production posture.
func LoadAndVerifyServerHandshakeProjection(root string) (ServerHandshakeProjection, error) {
	raw, err := readUS010Artifact(root, "corpora/handshake/server.json")
	if err != nil {
		return ServerHandshakeProjection{}, err
	}
	var projection ServerHandshakeProjection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&projection); err != nil {
		return ServerHandshakeProjection{}, fmt.Errorf("decode server projection: %w", err)
	}
	if projection.SchemaVersion != "1.0.0" || projection.CorpusID != "us011-server-handshake" {
		return ServerHandshakeProjection{}, fmt.Errorf("unexpected server projection identity")
	}
	if err := verifyServerAuthority(projection.Authority); err != nil {
		return ServerHandshakeProjection{}, err
	}
	if err := verifyServerProjectionNonclaims(projection); err != nil {
		return ServerHandshakeProjection{}, err
	}
	if projection.FrozenSource.Artifact != "corpora/handshake/cases.jsonl" ||
		projection.FrozenSource.SHA256 != "sha256:64d6dea5d63c6eb7d4698dccbe485f0ce249b511109df657848c511f0177e605" {
		return ServerHandshakeProjection{}, fmt.Errorf("server frozen source is not exact")
	}
	source, err := readUS010Artifact(root, projection.FrozenSource.Artifact)
	if err != nil || DigestSHA256(source) != projection.FrozenSource.SHA256 {
		return ServerHandshakeProjection{}, fmt.Errorf("server frozen source digest mismatch")
	}
	cases, err := clientRequestCases(source)
	if err != nil {
		return ServerHandshakeProjection{}, err
	}
	if err := verifyFrozenServerProjection(projection, cases); err != nil {
		return ServerHandshakeProjection{}, err
	}
	if err := verifyServerFrozenRustFixture(root, projection, cases); err != nil {
		return ServerHandshakeProjection{}, err
	}
	if err := verifyServerPropertyClaims(projection); err != nil {
		return ServerHandshakeProjection{}, err
	}
	if err := verifyServerNonceVectors(root, projection.NonceVectors); err != nil {
		return ServerHandshakeProjection{}, err
	}
	if err := verifyServerFuzzProjection(root, projection.FuzzSeeds); err != nil {
		return ServerHandshakeProjection{}, err
	}
	if err := verifyServerJavaMapping(root, cases, projection.FrozenCases); err != nil {
		return ServerHandshakeProjection{}, err
	}
	if projection.Assurance.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" ||
		projection.Assurance.IndependentReviewClaimed || projection.Assurance.AutobahnExecutions != 0 ||
		projection.Assurance.Production || projection.Assurance.Publication {
		return ServerHandshakeProjection{}, fmt.Errorf("server projection overstates assurance")
	}
	return projection, nil
}

func verifyServerAuthority(authority ServerHandshakeAuthority) error {
	if !stringSlicesEqual(authority.Priority, []string{
		"RFC 6455 and applicable HTTP grammar", "independent Go RFC evaluator", "Java-WebSocket v1.6.0 source-derived observations",
	}) || authority.JavaObservationMode != "SOURCE_DERIVED_NO_LIVE_COMMITTED_CORPUS_EXECUTION" ||
		authority.StrictnessRule != "Java leniency never lowers the RFC 6455 acceptance boundary" {
		return fmt.Errorf("server projection authority is incomplete or reversed")
	}
	return nil
}

func verifyServerProjectionNonclaims(projection ServerHandshakeProjection) error {
	return verifyExactServerNonclaims("projection", projection.Nonclaims)
}

func verifyServerEvidenceNonclaims(evidence serverHandshakeEvidence) error {
	return verifyExactServerNonclaims("receipt", evidence.Nonclaims)
}

func verifyExactServerNonclaims(artifact string, actual []string) error {
	if !stringSlicesEqual(actual, exactServerNonclaims) {
		return fmt.Errorf("US-011 %s nonclaims differ from the exact ordered allowlist", artifact)
	}
	return nil
}

func clientRequestCases(raw []byte) (map[string]HandshakeCase, error) {
	cases := make(map[string]HandshakeCase)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		var item HandshakeCase
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			return nil, err
		}
		if item.Direction == "client_request" {
			cases[item.CaseID] = item
		}
	}
	return cases, scanner.Err()
}

func verifyFrozenServerProjection(projection ServerHandshakeProjection, source map[string]HandshakeCase) error {
	if len(projection.FrozenCases) != 39 || len(projection.FrozenSource.SelectedCaseIDs) != 39 || len(source) != 39 {
		return fmt.Errorf("server projection requires exactly 39 frozen client requests")
	}
	seen := make(map[string]bool, 39)
	for _, projected := range projection.FrozenCases {
		expected, allowed := frozenServerExpectations[projected.CaseID]
		if !allowed || seen[projected.CaseID] || projected.RFCVerdict != expected.verdict ||
			projected.RFCReject != expected.reject || projected.RustExpected != expected.rust {
			return fmt.Errorf("case %s is outside the exact frozen server allowlist", projected.CaseID)
		}
		seen[projected.CaseID] = true
		item, ok := source[projected.CaseID]
		if !ok || item.Direction != "client_request" || item.Expected.Verdict != expected.verdict ||
			item.Expected.RejectCode != expected.reject {
			return fmt.Errorf("case %s differs from its immutable source verdict", projected.CaseID)
		}
		raw, err := base64.StdEncoding.DecodeString(item.RawBase64)
		if err != nil {
			return fmt.Errorf("case %s has invalid source Base64: %w", projected.CaseID, err)
		}
		derived, err := DeriveHandshake(item.Direction, raw, item.Config, item.Context)
		if err != nil || derived.Verdict != item.Expected.Verdict ||
			derived.RejectCode != item.Expected.RejectCode ||
			derived.SecWebSocketAccept != item.Expected.SecWebSocketAccept ||
			!stringSlicesEqual(derived.Basis, item.Expected.Basis) {
			return fmt.Errorf("case %s no longer matches the independent RFC evaluator", projected.CaseID)
		}
	}
	for _, id := range projection.FrozenSource.SelectedCaseIDs {
		if !seen[id] {
			return fmt.Errorf("selected frozen case %s is not projected", id)
		}
	}
	return nil
}

const us011FrozenRustFixturePath = "rust/connection-core/tests/data/us011_frozen_cases.rs"

func verifyServerFrozenRustFixture(root string, projection ServerHandshakeProjection, source map[string]HandshakeCase) error {
	raw, err := readUS010Artifact(root, us011FrozenRustFixturePath)
	if err != nil {
		return err
	}
	return verifyServerFrozenRustFixtureBytes(raw, projection, source)
}

func verifyServerFrozenRustFixtureBytes(raw []byte, projection ServerHandshakeProjection, source map[string]HandshakeCase) error {
	expected, err := renderServerFrozenRustFixture(projection, source)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, expected) {
		return fmt.Errorf("Rust frozen server fixture differs from its deterministic Go corpus projection")
	}
	return nil
}

func renderServerFrozenRustFixture(projection ServerHandshakeProjection, source map[string]HandshakeCase) ([]byte, error) {
	var accepted, rejected, limited, incomplete strings.Builder
	for _, id := range projection.FrozenSource.SelectedCaseIDs {
		item, ok := source[id]
		expectation, expected := frozenServerExpectations[id]
		if !ok || !expected {
			return nil, fmt.Errorf("render frozen Rust fixture: missing case %s", id)
		}
		raw, err := base64.StdEncoding.DecodeString(item.RawBase64)
		if err != nil {
			return nil, fmt.Errorf("render frozen Rust fixture case %s: %w", id, err)
		}
		request := rustByteStringLiteral(raw)
		switch item.Expected.Verdict {
		case "accept":
			target, host, err := frozenRequestTargetAndHost(raw)
			if err != nil {
				return nil, fmt.Errorf("render frozen Rust fixture case %s: %w", id, err)
			}
			fmt.Fprintf(&accepted, "    AcceptedCase {\n        id: %q,\n        request: %s,\n        target: %q,\n        host: %q,\n        accept: %q,\n    },\n", id, request, target, host, item.Expected.SecWebSocketAccept)
		case "incomplete":
			fmt.Fprintf(&incomplete, "    (%q, %s),\n", id, request)
		case "reject":
			if strings.HasPrefix(id, "us005.hs.004") {
				limit, err := frozenLimitFailure(item, raw)
				if err != nil {
					return nil, fmt.Errorf("render frozen Rust fixture case %s: %w", id, err)
				}
				fmt.Fprintf(&limited, "    LimitRejectedCase { id: %q, request: %s, limits: (%d, %d, %d), expected: %s },\n", id, request, item.Config.MaxHandshakeBytes, item.Config.MaxHeaderCount, item.Config.MaxHeaderLineBytes, limit)
				continue
			}
			expectedFailure, err := frozenRustFailure(expectation.rust)
			if err != nil {
				return nil, fmt.Errorf("render frozen Rust fixture case %s: %w", id, err)
			}
			fmt.Fprintf(&rejected, "    RejectedCase { id: %q, request: %s, expected: %s },\n", id, request, expectedFailure)
		default:
			return nil, fmt.Errorf("render frozen Rust fixture case %s: unsupported verdict %s", id, item.Expected.Verdict)
		}
	}

	var output strings.Builder
	output.WriteString("// Generated-style executable projection of the immutable US-005 client-request corpus.\n")
	output.WriteString("// Keep these bytes, configs, IDs, and typed outcomes byte-for-byte bound by the Go verifier.\n\n")
	output.WriteString("struct AcceptedCase {\n    id: &'static str,\n    request: &'static [u8],\n    target: &'static str,\n    host: &'static str,\n    accept: &'static str,\n}\n\n")
	output.WriteString("struct RejectedCase {\n    id: &'static str,\n    request: &'static [u8],\n    expected: HandshakeFailure,\n}\n\n")
	output.WriteString("struct LimitRejectedCase {\n    id: &'static str,\n    request: &'static [u8],\n    limits: (u64, u64, u64),\n    expected: FailureKind,\n}\n\n")
	output.WriteString("const FROZEN_ACCEPTED: &[AcceptedCase] = &[\n")
	output.WriteString(accepted.String())
	output.WriteString("];\n\nconst FROZEN_REJECTED: &[RejectedCase] = &[\n")
	output.WriteString(rejected.String())
	output.WriteString("];\n\nconst FROZEN_LIMIT_REJECTED: &[LimitRejectedCase] = &[\n")
	output.WriteString(limited.String())
	output.WriteString("];\n\nconst FROZEN_INCOMPLETE: &[(&str, &[u8])] = &[\n")
	output.WriteString(incomplete.String())
	output.WriteString("];\n")
	return []byte(output.String()), nil
}

func rustByteStringLiteral(raw []byte) string {
	var result strings.Builder
	result.WriteString("b\"")
	for _, value := range raw {
		switch value {
		case '\\':
			result.WriteString("\\\\")
		case '"':
			result.WriteString("\\\"")
		case '\r':
			result.WriteString("\\r")
		case '\n':
			result.WriteString("\\n")
		case '\t':
			result.WriteString("\\t")
		default:
			if value >= 0x20 && value <= 0x7e {
				result.WriteByte(value)
			} else {
				fmt.Fprintf(&result, "\\x%02x", value)
			}
		}
	}
	result.WriteByte('"')
	return result.String()
}

func frozenRequestTargetAndHost(raw []byte) (string, string, error) {
	lines := bytes.Split(raw, []byte("\r\n"))
	parts := bytes.Split(lines[0], []byte(" "))
	if len(parts) != 3 {
		return "", "", fmt.Errorf("accepted request line is malformed")
	}
	host := ""
	for _, line := range lines[1:] {
		name, value, found := bytes.Cut(line, []byte(":"))
		if found && strings.EqualFold(string(name), "host") {
			host = strings.TrimSpace(string(value))
			break
		}
	}
	if host == "" {
		return "", "", fmt.Errorf("accepted request has no Host")
	}
	return string(parts[1]), host, nil
}

func frozenRustFailure(expected string) (string, error) {
	if strings.HasPrefix(expected, "InvalidKeyLength(") && strings.HasSuffix(expected, ")") {
		decoded := strings.TrimSuffix(strings.TrimPrefix(expected, "InvalidKeyLength("), ")")
		if _, err := strconv.ParseUint(decoded, 10, 64); err != nil {
			return "", err
		}
		return "HandshakeFailure::InvalidKeyLength { decoded: " + decoded + " }", nil
	}
	allowed := map[string]bool{
		"MethodNotGet": true, "HttpVersionNot11": true, "MissingHost": true,
		"MissingUpgrade": true, "InvalidUpgrade": true, "MissingConnection": true,
		"InvalidConnection": true, "MissingKey": true, "InvalidKeyEncoding": true,
		"MissingVersion": true, "UnsupportedVersion": true, "DuplicateHeader": true,
		"InvalidHeaderName": true, "MalformedRequestLine": true,
		"ObsoleteLineFolding": true, "BareLineEnding": true,
	}
	if !allowed[expected] {
		return "", fmt.Errorf("unsupported Rust handshake failure %s", expected)
	}
	return "HandshakeFailure::" + expected, nil
}

func frozenLimitFailure(item HandshakeCase, raw []byte) (string, error) {
	switch item.Expected.RejectCode {
	case "HS_LIMIT_TOTAL_BYTES":
		return fmt.Sprintf("FailureKind::LimitExceeded { limit: LimitKind::HandshakeBytes, attempted: %d, maximum: %d }", len(raw), item.Config.MaxHandshakeBytes), nil
	case "HS_LIMIT_HEADER_COUNT":
		return fmt.Sprintf("FailureKind::LimitExceeded { limit: LimitKind::HandshakeHeaderCount, attempted: %d, maximum: %d }", item.Config.MaxHeaderCount+1, item.Config.MaxHeaderCount), nil
	case "HS_LIMIT_HEADER_LINE_BYTES":
		return fmt.Sprintf("FailureKind::LimitExceeded { limit: LimitKind::HandshakeHeaderLineBytes, attempted: %d, maximum: %d }", item.Config.MaxHeaderLineBytes+1, item.Config.MaxHeaderLineBytes), nil
	default:
		return "", fmt.Errorf("unsupported frozen limit code %s", item.Expected.RejectCode)
	}
}

func verifyServerPropertyClaims(projection ServerHandshakeProjection) error {
	p := projection.Properties
	if p.ValidCases != 6 || p.TwoChunkExecutions != 1092 || p.BytewiseExecutions != 6 ||
		p.MultiChunkExecutions != 18 || p.NonceVectors != 256 ||
		p.ExecutionID != "us011-server-handshake-deterministic-v1" ||
		!stringSlicesEqual(p.DeterministicProperties, exactServerProperties) ||
		!stringSlicesEqual(projection.Additive, exactServerAdditiveVectors) {
		return fmt.Errorf("server deterministic-property claims exceed the executed allowlist")
	}
	r := projection.Reconciliation
	if r.MigrationSlice != "slice.server-handshake" ||
		!stringSlicesEqual(r.PropertyIDs, []string{"property.handshake.key-accept-roundtrip", "property.handshake.server-response-total"}) ||
		r.FuzzHarness != "rust/connection-core/tests/server_handshake.rs" ||
		r.DeltaLedger != "evidence/java/behavior-delta-ledger.json" ||
		r.EvidenceReceipt != "evidence/us011-server-handshake.json" || len(r.RuntimeAssertions) < 4 {
		return fmt.Errorf("server corpus is not reconciled to every acceptance lane")
	}
	return nil
}

func verifyServerNonceVectors(root string, vectors []ServerHandshakeNonceVector) error {
	if len(vectors) != 256 {
		return fmt.Errorf("server projection requires 256 nonce/accept literals")
	}
	testSource, err := readUS010Artifact(root, "rust/connection-core/tests/server_handshake.rs")
	if err != nil {
		return err
	}
	if !bytes.Contains(testSource, []byte(`include!("data/us011_nonce_vectors.rs");`)) {
		return fmt.Errorf("Rust server harness does not include the bound nonce literals")
	}
	literalSource, err := readUS010Artifact(root, "rust/connection-core/tests/data/us011_nonce_vectors.rs")
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(vectors))
	for index, vector := range vectors {
		nonce, err := hex.DecodeString(vector.NonceHex)
		if err != nil || len(nonce) != 16 || seen[vector.NonceHex] {
			return fmt.Errorf("nonce vector %d is invalid or duplicated", index)
		}
		for byteIndex := range nonce {
			want := byte(byteIndex)
			if byteIndex == 0 {
				want = byte(index)
			}
			if nonce[byteIndex] != want {
				return fmt.Errorf("nonce vector %d is out of the declared deterministic order", index)
			}
		}
		seen[vector.NonceHex] = true
		if base64.StdEncoding.EncodeToString(nonce) != vector.Key || ComputeAccept(vector.Key) != vector.Accept {
			return fmt.Errorf("nonce vector %d does not match the independent Go evaluator", index)
		}
		literal := []byte("(\"" + vector.Key + "\", \"" + vector.Accept + "\")")
		if bytes.Count(literalSource, literal) != 1 {
			return fmt.Errorf("nonce vector %d accept is not bound exactly once in the Rust harness", index)
		}
	}
	return nil
}

func verifyServerFuzzProjection(root string, seeds []ClientHandshakeFuzzSeed) error {
	if len(seeds) != len(exactServerFuzzSeeds) {
		return fmt.Errorf("server fuzz seed inventory is incomplete")
	}
	testSource, err := readUS010Artifact(root, "rust/connection-core/tests/server_handshake.rs")
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(seeds))
	for _, seed := range seeds {
		expected, allowed := exactServerFuzzSeeds[seed.Path]
		if !allowed || seen[seed.Path] || seed.SHA256 != expected.digest ||
			seed.Expected != expected.expected || seed.Config != expected.config {
			return fmt.Errorf("server fuzz seed %q is outside the exact allowlist", seed.Path)
		}
		seen[seed.Path] = true
		raw, err := readUS010Artifact(root, seed.Path)
		if err != nil || DigestSHA256(raw) != seed.SHA256 {
			return fmt.Errorf("server seed digest mismatch: %s", seed.Path)
		}
		text := string(raw)
		compact := strings.ReplaceAll(strings.TrimSuffix(text, "\n"), "\n", "")
		decoded, decodeErr := hex.DecodeString(compact)
		if decodeErr != nil || len(decoded) == 0 || !strings.HasSuffix(text, "\n") ||
			text != strings.ToLower(text) || strings.ContainsAny(text, " \t\r") {
			return fmt.Errorf("server seed is not canonical lowercase hex: %s", seed.Path)
		}
		include := "include_str!(\"../fuzz-seeds/us011/" + filepath.Base(seed.Path) + "\")"
		if !bytes.Contains(testSource, []byte(include)) {
			return fmt.Errorf("server seed is absent from the executable Rust harness: %s", seed.Path)
		}
	}
	return nil
}

type serverJavaMappingEntry struct {
	Direction      string   `json:"direction"`
	Key            string   `json:"key"`
	RFCVerdict     string   `json:"rfc_verdict"`
	JavaObservable string   `json:"java_observable"`
	RejectChannel  string   `json:"reject_channel"`
	Divergent      bool     `json:"divergent"`
	Condition      string   `json:"condition"`
	Basis          []string `json:"basis"`
	Note           string   `json:"note"`
}

func verifyServerJavaMapping(root string, source map[string]HandshakeCase, projected []ServerHandshakeCase) error {
	raw, err := readUS010Artifact(root, "evidence/us005-handshake-live-mapping.json")
	if err != nil {
		return err
	}
	var mapping struct {
		Entries []serverJavaMappingEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &mapping); err != nil {
		return err
	}
	available := make(map[string]serverJavaMappingEntry)
	for _, entry := range mapping.Entries {
		if entry.Direction == "client_request" {
			if _, duplicate := available[entry.Key]; duplicate {
				return fmt.Errorf("duplicate source-derived Java mapping key %s", entry.Key)
			}
			available[entry.Key] = entry
		}
	}
	if len(projected) != len(source) {
		return fmt.Errorf("source-derived Java projection inventory is incomplete")
	}
	for _, item := range projected {
		sourceCase, ok := source[item.CaseID]
		if !ok {
			return fmt.Errorf("case %s is absent from the frozen source", item.CaseID)
		}
		expected := frozenServerExpectations[item.CaseID]
		key := sourceCase.Expected.RejectCode
		if key == "" {
			key = sourceCase.Expected.Verdict
		}
		entry, ok := available[key]
		if !ok || entry.RFCVerdict != sourceCase.Expected.Verdict || len(entry.Basis) == 0 {
			return fmt.Errorf("case %s is not covered by an exact source-derived Java mapping", item.CaseID)
		}
		java := item.Java
		if java.MappingKey != key || java.Observable != expected.javaObservable ||
			java.Divergent != expected.javaDivergent || java.RejectChannel != expected.javaRejectChannel ||
			java.Condition != entry.Condition || !stringSlicesEqual(java.Basis, entry.Basis) {
			return fmt.Errorf("case %s has drifted from its exact source-derived Java observation", item.CaseID)
		}
		if entry.JavaObservable != "conditional" {
			if java.Observable != entry.JavaObservable || java.Divergent != entry.Divergent ||
				java.RejectChannel != entry.RejectChannel || java.Condition != "" {
				return fmt.Errorf("case %s contradicts the source-derived Java mapping", item.CaseID)
			}
		} else if entry.Condition == "" || !entry.Divergent {
			return fmt.Errorf("conditional Java mapping %s lacks its divergence condition", key)
		}
		if err := verifyDuplicateJavaResolution(item.CaseID, sourceCase, entry, java); err != nil {
			return err
		}
	}
	return nil
}

func verifyDuplicateJavaResolution(caseID string, source HandshakeCase, entry serverJavaMappingEntry, java ServerHandshakeJavaObservation) error {
	if caseID != "us005.hs.0027" && caseID != "us005.hs.0028" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(source.RawBase64)
	if err != nil {
		return fmt.Errorf("decode duplicate-header case %s: %w", caseID, err)
	}
	lower := bytes.ToLower(raw)
	keyHeaders := bytes.Count(lower, []byte("sec-websocket-key:"))
	versionHeaders := bytes.Count(lower, []byte("sec-websocket-version:"))
	if entry.Key != "HS_DUPLICATE_HEADER" ||
		!strings.Contains(entry.Note, "seed 0 (key) is a divergent Java accept") ||
		!strings.Contains(entry.Note, "seed 1 (version) rejects NOT_MATCHED") {
		return fmt.Errorf("duplicate-header Java mapping no longer supports its two exact outcomes")
	}
	if caseID == "us005.hs.0027" && (keyHeaders != 2 || versionHeaders != 1 ||
		java.Observable != "accept" || !java.Divergent || java.RejectChannel != "") {
		return fmt.Errorf("duplicated-key case lost its divergent Java accept")
	}
	if caseID == "us005.hs.0028" && (keyHeaders != 1 || versionHeaders != 2 ||
		java.Observable != "reject" || java.Divergent || java.RejectChannel != "not_matched") {
		return fmt.Errorf("duplicated-version case lost its Java NOT_MATCHED rejection")
	}
	return nil
}

type serverHandshakeEvidence struct {
	Schema        string `json:"$schema"`
	SchemaVersion string `json:"schema_version"`
	EvidenceID    string `json:"evidence_id"`
	StoryID       string `json:"story_id"`
	Source        struct {
		BindingMode         string             `json:"binding_mode"`
		ImplementationFiles []evidenceArtifact `json:"implementation_files"`
	} `json:"source"`
	Toolchain struct {
		RustcArtifactID string `json:"rustc_artifact_id"`
		RustcSHA256     string `json:"rustc_sha256"`
		CargoSHA256     string `json:"cargo_sha256"`
		ValidationTime  string `json:"validation_time"`
		RustAnalyzer    struct {
			HistoricalUS009ReceiptPreserved bool   `json:"historical_us009_receipt_preserved"`
			PinnedArtifactID                string `json:"pinned_artifact_id"`
			PinnedSHA256                    string `json:"pinned_sha256"`
			FreshUS011Resolution            string `json:"fresh_us011_resolution"`
			ProxyIsNotAcceptedAsResolver    bool   `json:"proxy_is_not_accepted_as_resolver"`
		} `json:"rust_analyzer"`
	} `json:"toolchain"`
	Tests struct {
		Debug                  evidenceTestRun `json:"debug"`
		Release                evidenceTestRun `json:"release"`
		ServerHandshakeTests   int             `json:"server_handshake_tests_per_profile"`
		FrozenRequestCases     int             `json:"frozen_client_request_cases"`
		TwoChunkExecutions     int             `json:"two_chunk_executions_per_profile"`
		FrozenRejectSplits     int             `json:"frozen_reject_two_chunk_executions_per_profile"`
		FrozenLimitSplits      int             `json:"frozen_limit_two_chunk_executions_per_profile"`
		FrozenIncompleteSplits int             `json:"frozen_incomplete_two_chunk_executions_per_profile"`
		AdditiveFailureSplits  int             `json:"additive_failure_two_chunk_executions_per_profile"`
		AdditiveEOFSplits      int             `json:"additive_partial_eof_two_chunk_executions_per_profile"`
		BytewiseExecutions     int             `json:"bytewise_executions_per_profile"`
		MultiChunkExecutions   int             `json:"multi_chunk_executions_per_profile"`
		NonceVectors           int             `json:"nonce_vectors_per_profile"`
		FuzzSeedsReplayed      int             `json:"fuzz_seeds_replayed_per_profile"`
		RuntimeAssertions      []string        `json:"runtime_assertions"`
	} `json:"tests"`
	Corpus struct {
		ProjectionPath       string `json:"projection_path"`
		ProjectionSHA256     string `json:"projection_sha256"`
		SchemaPath           string `json:"schema_path"`
		SchemaSHA256         string `json:"schema_sha256"`
		EvidenceSchemaPath   string `json:"evidence_schema_path"`
		EvidenceSchemaSHA256 string `json:"evidence_schema_sha256"`
		FrozenSourceSHA256   string `json:"frozen_source_sha256"`
		AdditiveVectors      int    `json:"public_additive_vectors"`
		FuzzSeedCount        int    `json:"fuzz_seed_count"`
		NonceVectorCount     int    `json:"nonce_vector_count"`
	} `json:"corpus"`
	Symbols struct {
		MigrationMapPath       string                `json:"migration_map_path"`
		MigrationMapSHA256     string                `json:"migration_map_sha256"`
		NewResolverVerified    int                   `json:"new_resolver_verified_identities"`
		JavaShapedAliasesAdded int                   `json:"java_shaped_aliases_added"`
		Bindings               []serverSymbolBinding `json:"bindings"`
	} `json:"symbols"`
	Compatibility struct {
		SurfaceID                  string   `json:"surface_id"`
		CutoverObligationID        string   `json:"cutover_obligation_id"`
		EvidenceIDs                []string `json:"evidence_ids"`
		JavaObservationMode        string   `json:"java_observation_mode"`
		JavaMappingPath            string   `json:"java_mapping_path"`
		JavaMappingSHA256          string   `json:"java_mapping_sha256"`
		CompatibilitySurfaceSHA256 string   `json:"compatibility_surface_sha256"`
		PortSeamDossierSHA256      string   `json:"port_seam_dossier_sha256"`
		CutoverContractSHA256      string   `json:"cutover_contract_sha256"`
	} `json:"compatibility"`
	DeltaLedger struct {
		Path               string `json:"path"`
		SHA256             string `json:"sha256"`
		RecordsAdded       int    `json:"records_added"`
		Reason             string `json:"reason"`
		AutobahnCategory0  string `json:"autobahn_category_0"`
		AutobahnExecutions int    `json:"autobahn_executions"`
	} `json:"delta_ledger"`
	EvidenceDAGClaim  string                  `json:"evidence_dag_claim"`
	EvidenceDAGPath   string                  `json:"evidence_dag_path"`
	EvidenceDAGSHA256 string                  `json:"evidence_dag_sha256"`
	Nonclaims         []string                `json:"nonclaims"`
	Assurance         serverEvidenceAssurance `json:"assurance"`
}

type evidenceTestRun struct {
	Command string `json:"command"`
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
}

type serverSymbolBinding struct {
	RustSemanticID string `json:"rust_semantic_id"`
	Source         string `json:"source"`
	Status         string `json:"status"`
}

type serverEvidenceAssurance struct {
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	Production               bool   `json:"production"`
	Publication              bool   `json:"publication"`
	Signing                  bool   `json:"signing"`
}

var us011SourceArtifactPaths = []string{
	"rust/connection-core/src/lib.rs",
	"rust/connection-core/src/connection.rs",
	"rust/connection-core/src/handshake.rs",
	"rust/connection-core/src/handshake/http.rs",
	"rust/connection-core/src/handshake/crypto.rs",
	"rust/connection-core/src/handshake/server.rs",
	"rust/connection-core/tests/server_handshake.rs",
	us011FrozenRustFixturePath,
	"rust/connection-core/tests/data/us011_nonce_vectors.rs",
	"rust/connection-core/tests/connection_contract.rs",
	"internal/corpora/server_handshake.go",
	"internal/corpora/server_handshake_test.go",
	"internal/corpora/us010_artifact.go",
	"internal/corpora/schemas.go",
	"schemas/server-handshake-corpus-1.0.0.schema.json",
	"schemas/server-handshake-evidence-1.0.0.schema.json",
	"internal/portplan/slices.go",
	"internal/portplan/build_documents.go",
	"internal/portplan/validate.go",
	"internal/portplan/us011_server_handshake_test.go",
	"docs/rust-workspace.md",
}

const (
	us011ReceiptPath         = "evidence/us011-server-handshake.json"
	us011ProjectionPath      = "corpora/handshake/server.json"
	us011CorpusSchemaPath    = "schemas/server-handshake-corpus-1.0.0.schema.json"
	us011EvidenceSchemaPath  = "schemas/server-handshake-evidence-1.0.0.schema.json"
	us011MigrationMapPath    = "evidence/intake/semantic-id-migration-map.json"
	us011CompatibilityPath   = "evidence/intake/compatibility-surface.json"
	us011PortSeamDossierPath = "evidence/intake/port-seam-dossier.json"
	us011CutoverContractPath = "evidence/intake/cutover-contract.json"
	us011JavaMappingPath     = "evidence/us005-handshake-live-mapping.json"
	us011DeltaLedgerPath     = "evidence/java/behavior-delta-ledger.json"
	us011EvidenceDAGPath     = "assurance/us011-evidence-dag.json"
)

// VerifyServerHandshakeEvidence closes the story against checkout HEAD. It
// deliberately reuses the hardened US-010 reader instead of adding another
// filesystem/provenance implementation.
func VerifyServerHandshakeEvidence(root string) error {
	if err := verifyUS011CheckoutHeadArtifact(root, us011ReceiptPath, ""); err != nil {
		return err
	}
	raw, err := readUS010Artifact(root, us011ReceiptPath)
	if err != nil {
		return err
	}
	var evidence serverHandshakeEvidence
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return fmt.Errorf("decode US-011 evidence: %w", err)
	}
	if evidence.EvidenceID != "evidence.us-011-server-handshake" || evidence.StoryID != "US-011" ||
		evidence.Source.BindingMode != "CHECKOUT_HEAD_EXACT_BLOBS" {
		return fmt.Errorf("invalid US-011 evidence identity or source binding")
	}
	if err := verifyUS011AncillaryPaths(evidence); err != nil {
		return err
	}
	if err := verifyUS011SourceInventory(evidence.Source.ImplementationFiles); err != nil {
		return err
	}
	if err := verifyUS010GitSourceBinding(root, evidence.Source.ImplementationFiles); err != nil {
		return err
	}
	for _, artifact := range evidence.Source.ImplementationFiles {
		if err := verifyEvidenceArtifact(root, artifact); err != nil {
			return err
		}
	}
	if evidence.Toolchain.RustcArtifactID != "rustc-1.95.0-aarch64-apple-darwin" ||
		evidence.Toolchain.RustcSHA256 != "sha256:b829b733131d4e1673eeebd1f34d06ae1e9ff4977b051313cf42e2a9e79ecf1c" ||
		evidence.Toolchain.CargoSHA256 != "sha256:c512bff73c86143b557463f021d0c3d5b0490d97d65040ba59ea2b3427784758" ||
		evidence.Toolchain.ValidationTime == "" || !evidence.Toolchain.RustAnalyzer.HistoricalUS009ReceiptPreserved ||
		evidence.Toolchain.RustAnalyzer.PinnedArtifactID != "rust-analyzer-2026-08-17.4-aarch64-apple-darwin" ||
		evidence.Toolchain.RustAnalyzer.PinnedSHA256 != "sha256:5142e0d6d0a48bc8ba0638125eaa68296defba7d32628362175eff967d12e145" ||
		evidence.Toolchain.RustAnalyzer.FreshUS011Resolution != "NOT_PERFORMED_EXACT_PIN_NOT_LOCALLY_AVAILABLE" ||
		!evidence.Toolchain.RustAnalyzer.ProxyIsNotAcceptedAsResolver {
		return fmt.Errorf("US-011 toolchain binding is incomplete or overstated")
	}
	if evidence.Tests.Debug.Command != "make -C rust test" || evidence.Tests.Release.Command != "make -C rust test-release" ||
		evidence.Tests.Debug.Passed != 59 || evidence.Tests.Release.Passed != 59 ||
		evidence.Tests.Debug.Failed != 0 || evidence.Tests.Release.Failed != 0 ||
		evidence.Tests.ServerHandshakeTests != 23 || evidence.Tests.FrozenRequestCases != 39 ||
		evidence.Tests.TwoChunkExecutions != 1092 || evidence.Tests.BytewiseExecutions != 6 ||
		evidence.Tests.FrozenRejectSplits != 4496 || evidence.Tests.FrozenLimitSplits != 522 ||
		evidence.Tests.FrozenIncompleteSplits != 265 || evidence.Tests.AdditiveFailureSplits != 4557 ||
		evidence.Tests.AdditiveEOFSplits != 42 ||
		evidence.Tests.MultiChunkExecutions != 18 || evidence.Tests.NonceVectors != 256 ||
		evidence.Tests.FuzzSeedsReplayed != 17 || len(evidence.Tests.RuntimeAssertions) < 4 {
		return fmt.Errorf("US-011 test counts do not match the committed harness")
	}
	projection, err := LoadAndVerifyServerHandshakeProjection(root)
	if err != nil {
		return err
	}
	for _, artifact := range []evidenceArtifact{
		{Path: us011ProjectionPath, SHA256: evidence.Corpus.ProjectionSHA256},
		{Path: us011CorpusSchemaPath, SHA256: evidence.Corpus.SchemaSHA256},
		{Path: us011EvidenceSchemaPath, SHA256: evidence.Corpus.EvidenceSchemaSHA256},
		{Path: us011MigrationMapPath, SHA256: evidence.Symbols.MigrationMapSHA256},
		{Path: us011JavaMappingPath, SHA256: evidence.Compatibility.JavaMappingSHA256},
		{Path: us011CompatibilityPath, SHA256: evidence.Compatibility.CompatibilitySurfaceSHA256},
		{Path: us011PortSeamDossierPath, SHA256: evidence.Compatibility.PortSeamDossierSHA256},
		{Path: us011CutoverContractPath, SHA256: evidence.Compatibility.CutoverContractSHA256},
		{Path: us011DeltaLedgerPath, SHA256: evidence.DeltaLedger.SHA256},
		{Path: us011EvidenceDAGPath, SHA256: evidence.EvidenceDAGSHA256},
	} {
		if err := verifyUS011CheckoutHeadArtifact(root, artifact.Path, artifact.SHA256); err != nil {
			return err
		}
	}
	if evidence.Corpus.FrozenSourceSHA256 != projection.FrozenSource.SHA256 ||
		evidence.Corpus.AdditiveVectors != len(exactServerAdditiveVectors) || evidence.Corpus.FuzzSeedCount != 17 ||
		evidence.Corpus.NonceVectorCount != 256 || evidence.Symbols.NewResolverVerified != 0 ||
		evidence.Symbols.JavaShapedAliasesAdded != 0 {
		return fmt.Errorf("US-011 corpus or resolver claims are inconsistent")
	}
	if err := verifyUS011MigrationBindings(root, evidence.Symbols.Bindings); err != nil {
		return err
	}
	if evidence.Compatibility.SurfaceID != "surface.handshake.server-response" ||
		evidence.Compatibility.CutoverObligationID != "cutover.surface-handshake-server-response" ||
		!stringSlicesEqual(evidence.Compatibility.EvidenceIDs, []string{"evidence.us-011-server-handshake"}) ||
		evidence.Compatibility.JavaObservationMode != "SOURCE_DERIVED_NO_LIVE_COMMITTED_CORPUS_EXECUTION" ||
		evidence.DeltaLedger.RecordsAdded != 0 ||
		evidence.DeltaLedger.Reason != "No live Java execution for US-011 additive strictness subjects was performed; no disagreement or unrelated Autobahn reference is fabricated." ||
		evidence.DeltaLedger.AutobahnCategory0 != "NO_REGISTERED_CATEGORY_0_AT_PIN" ||
		evidence.DeltaLedger.AutobahnExecutions != 0 {
		return fmt.Errorf("US-011 compatibility or delta nonclaims are inconsistent")
	}
	if err := verifyServerEvidenceNonclaims(evidence); err != nil {
		return err
	}
	if err := verifyUS011DAGCutoverAndMigration(root, evidence); err != nil {
		return err
	}
	if evidence.Assurance.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" ||
		evidence.Assurance.IndependentReviewClaimed || evidence.Assurance.Production || evidence.Assurance.Publication ||
		evidence.Assurance.Signing {
		return fmt.Errorf("US-011 evidence overstates assurance")
	}
	return nil
}

func verifyUS011AncillaryPaths(evidence serverHandshakeEvidence) error {
	if evidence.Corpus.ProjectionPath != us011ProjectionPath ||
		evidence.Corpus.SchemaPath != us011CorpusSchemaPath ||
		evidence.Corpus.EvidenceSchemaPath != us011EvidenceSchemaPath ||
		evidence.Symbols.MigrationMapPath != us011MigrationMapPath ||
		evidence.Compatibility.JavaMappingPath != us011JavaMappingPath ||
		evidence.DeltaLedger.Path != us011DeltaLedgerPath ||
		evidence.EvidenceDAGPath != us011EvidenceDAGPath {
		return fmt.Errorf("US-011 receipt substituted a non-allowlisted support artifact path")
	}
	return nil
}

func verifyUS011CheckoutHeadArtifact(root, path, digest string) error {
	working, err := readUS010Artifact(root, path)
	if err != nil {
		return err
	}
	if digest != "" && DigestSHA256(working) != digest {
		return fmt.Errorf("US-011 working artifact digest mismatch: %s", path)
	}
	output, err := exec.Command("git", "-C", root, "rev-parse", "HEAD:"+path).Output()
	object := strings.TrimSpace(string(output))
	if err != nil || len(object) != 40 {
		return fmt.Errorf("US-011 artifact is absent from checkout HEAD: %s", path)
	}
	if _, err := hex.DecodeString(object); err != nil {
		return fmt.Errorf("US-011 checkout HEAD artifact is not a blob ID: %s", path)
	}
	committed, err := readUS010GitBlob(root, object)
	if err != nil || !bytes.Equal(working, committed) || (digest != "" && DigestSHA256(committed) != digest) {
		return fmt.Errorf("US-011 artifact is dirty or stale against checkout HEAD: %s", path)
	}
	return nil
}

func verifyUS011SourceInventory(artifacts []evidenceArtifact) error {
	if len(artifacts) != len(us011SourceArtifactPaths) {
		return fmt.Errorf("US-011 source artifact inventory is incomplete")
	}
	expected := make(map[string]bool, len(us011SourceArtifactPaths))
	for _, path := range us011SourceArtifactPaths {
		expected[path] = false
	}
	for _, artifact := range artifacts {
		seen, allowed := expected[artifact.Path]
		if !allowed || seen {
			return fmt.Errorf("unexpected or duplicate US-011 source artifact: %s", artifact.Path)
		}
		expected[artifact.Path] = true
	}
	return nil
}

func verifyUS011MigrationBindings(root string, bindings []serverSymbolBinding) error {
	expected := map[string]bool{
		"websocket_core::ConnectionCore": false, "websocket_core::ServerRequestDescriptor": false,
		"websocket_core::HandshakeFailure": false, "websocket_core::SemanticEvent": false,
	}
	for _, binding := range bindings {
		if _, ok := expected[binding.RustSemanticID]; !ok || expected[binding.RustSemanticID] {
			return fmt.Errorf("unexpected or duplicate US-011 symbol binding %s", binding.RustSemanticID)
		}
		expected[binding.RustSemanticID] = true
		path, lineText, found := strings.Cut(binding.Source, ":")
		line, parseErr := strconv.Atoi(lineText)
		raw, readErr := readUS010Artifact(root, path)
		name := strings.TrimPrefix(binding.RustSemanticID, "websocket_core::")
		lines := bytes.Split(raw, []byte("\n"))
		if !found || parseErr != nil || readErr != nil || line < 1 || line > len(lines) ||
			!bytes.Contains(lines[line-1], []byte(name)) {
			return fmt.Errorf("US-011 binding lacks an exact source line: %s", binding.RustSemanticID)
		}
		wantStatus := "SOURCE_BOUND_RESOLVER_UNAVAILABLE"
		if name == "ConnectionCore" {
			wantStatus = "RESOLVER_VERIFIED_BY_IMMUTABLE_US009_RECEIPT"
		}
		if binding.Status != wantStatus {
			return fmt.Errorf("US-011 binding overstates resolver status: %s", binding.RustSemanticID)
		}
	}
	for id, present := range expected {
		if !present {
			return fmt.Errorf("missing US-011 symbol binding %s", id)
		}
	}
	return nil
}

func verifyUS011DAGCutoverAndMigration(root string, evidence serverHandshakeEvidence) error {
	if evidence.EvidenceDAGClaim != "claim-us011-server-handshake" ||
		evidence.EvidenceDAGPath != "assurance/us011-evidence-dag.json" {
		return fmt.Errorf("US-011 additive evidence DAG identity is wrong")
	}
	var dag struct {
		Root  string                            `json:"root_node_id"`
		Edges []struct{ From, To, Kind string } `json:"edges"`
	}
	raw, err := readUS010Artifact(root, evidence.EvidenceDAGPath)
	if err != nil || json.Unmarshal(raw, &dag) != nil || dag.Root != evidence.EvidenceDAGClaim {
		return fmt.Errorf("US-011 evidence DAG claim is not closed")
	}
	edge := false
	for _, item := range dag.Edges {
		edge = edge || item.From == evidence.EvidenceDAGClaim && item.To == "evidence-us011-server-handshake" && item.Kind == "supports"
	}
	if !edge {
		return fmt.Errorf("US-011 evidence DAG receipt edge is absent")
	}
	var cutover struct {
		Obligations []struct {
			ID, Status  string
			EvidenceIDs []string `json:"evidence_ids"`
		} `json:"obligations"`
	}
	raw, err = readUS010Artifact(root, "evidence/intake/cutover-contract.json")
	if err != nil || json.Unmarshal(raw, &cutover) != nil {
		return fmt.Errorf("read US-011 cutover contract")
	}
	found := false
	for _, obligation := range cutover.Obligations {
		if obligation.ID == evidence.Compatibility.CutoverObligationID {
			found = true
			if obligation.Status != "DECLARED" || len(obligation.EvidenceIDs) != 0 {
				return fmt.Errorf("US-011 cutover promoted without governance")
			}
		}
	}
	if !found {
		return fmt.Errorf("US-011 cutover obligation is absent")
	}
	return verifyUS011MigrationRows(root)
}

func verifyUS011MigrationRows(root string) error {
	var migration struct {
		Rows []struct {
			RustSemanticID string `json:"rust_semantic_id"`
			PortSlices     []struct {
				PortSliceID string   `json:"port_slice_id"`
				EvidenceIDs []string `json:"evidence_ids"`
			} `json:"port_slices"`
		} `json:"rows"`
	}
	raw, err := readUS010Artifact(root, "evidence/intake/semantic-id-migration-map.json")
	if err != nil || json.Unmarshal(raw, &migration) != nil {
		return fmt.Errorf("read US-011 migration rows")
	}
	count := 0
	for _, row := range migration.Rows {
		for _, binding := range row.PortSlices {
			if binding.PortSliceID == "slice.server-handshake" {
				count++
				if strings.Contains(row.RustSemanticID, "ws_core") || strings.Contains(row.RustSemanticID, "ServerHandshake") ||
					strings.Contains(row.RustSemanticID, "HandshakeImpl1Server") {
					return fmt.Errorf("stale or fabricated server-handshake Rust identity survived: %s", row.RustSemanticID)
				}
				if !stringSlicesEqual(binding.EvidenceIDs, []string{"evidence.us-011-server-handshake"}) {
					return fmt.Errorf("US-011 migration binding carries generic evidence")
				}
			}
		}
	}
	if count != 10 {
		return fmt.Errorf("US-011 migration slice row count = %d, want 10", count)
	}
	return nil
}
