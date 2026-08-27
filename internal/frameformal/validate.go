package frameformal

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const maxEvidenceBytes = int64(8 << 20)

var exactReplayArgv = []string{
	"cargo", "test", "-p", "websocket-core", "--test", "frame_codec",
	"us012_formal_actual_code_obligations", "--", "--exact", "--nocapture",
}

var exactReplayEnvironment = []string{"CARGO_NET_OFFLINE=true", "LANG=C", "LC_ALL=C"}

var exactNormalizedOutput = "US012_ACTUAL_CODE_COUNTS control_fin_and_length=6 length_canonical_16=6 length_canonical_64_high_bit_zero=3 length_canonical_7=126 preallocation_cap=2 role_masking=4 mask_equation=1632 mask_involution=204\n"

type collector struct {
	findings []Finding
}

func (value *collector) add(reason, path, message string) {
	value.findings = append(value.findings, Finding{Reason: reason, Path: path, Message: message})
}

func (value *collector) normalized() []Finding {
	sort.Slice(value.findings, func(i, j int) bool {
		left, right := value.findings[i], value.findings[j]
		return left.Reason+"\x00"+left.Path+"\x00"+left.Message < right.Reason+"\x00"+right.Path+"\x00"+right.Message
	})
	result := make([]Finding, 0, len(value.findings))
	for _, finding := range value.findings {
		if len(result) == 0 || result[len(result)-1] != finding {
			result = append(result, finding)
		}
	}
	return result
}

func Validate(ctx context.Context, request Request) (Verdict, error) {
	if err := ctx.Err(); err != nil {
		return Verdict{}, err
	}
	rootPath := request.RootPath
	if rootPath == "" {
		rootPath = "."
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return Verdict{}, err
	}
	defer root.Close()

	findings := &collector{}
	receiptData, err := readRegular(root, ReceiptPath, maxEvidenceBytes)
	if err != nil {
		findings.add("MISSING_REQUIRED_ARTIFACT", ReceiptPath, err.Error())
		return makeVerdict(receipt{}, findings), nil
	}
	schemaData, err := readRegular(root, SchemaPath, maxEvidenceBytes)
	if err != nil {
		findings.add("MISSING_REQUIRED_ARTIFACT", SchemaPath, err.Error())
	}
	if bytes.Contains(receiptData, []byte("PENDING_")) {
		findings.add("PENDING_BINDING", ReceiptPath, "receipt contains an unfinished digest, count, or execution binding")
	}

	var value receipt
	if err := decodeStrict(receiptData, &value); err != nil {
		findings.add(decodeReason(err), ReceiptPath, err.Error())
		return makeVerdict(value, findings), nil
	}
	if schemaData != nil {
		validateSchema(schemaData, receiptData, findings)
	}
	validatePosture(&value, findings)
	validateBindings(root, &value, findings)
	validateBounds(value.Bounds, findings)
	validateObligations(value.Obligations, findings)
	validateCanaries(value.Targets, value.SourceMutationCanaries, findings)
	validateReplay(value.Obligations, value.Outputs, value.Replay, findings)
	return makeVerdict(value, findings), nil
}

func makeVerdict(value receipt, findings *collector) Verdict {
	normalized := findings.normalized()
	state := value.State
	if state == "" {
		state = "BLOCKED"
	}
	assurance := value.Assurance
	if assurance == "" {
		assurance = "OWNER_ATTESTED_NOT_INDEPENDENT"
	}
	return Verdict{
		Valid:                    len(normalized) == 0,
		State:                    state,
		ClaimScope:               value.ClaimScope,
		AggregateFormalState:     value.AggregateFormalState,
		Findings:                 normalized,
		Assurance:                assurance,
		IndependentReviewClaimed: value.IndependentReviewClaimed,
	}
}

func validatePosture(value *receipt, findings *collector) {
	if value.Schema != "../../schemas/frame-formal-results-1.0.0.schema.json" || value.SchemaVersion != "1.0.0" ||
		value.EvidenceKind != "US012_FRAME_ACTUAL_CODE_BOUNDED_RESULTS" || value.StoryID != "US-012" {
		findings.add("SCHEMA_VIOLATION", ReceiptPath, "receipt identity is not the fixed US-012 frame evidence contract")
	}
	if value.State != "PASS" || value.ClaimScope != "BOUNDED_TEST_EVIDENCE" || value.AggregateFormalState != "BLOCKED" ||
		value.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || value.IndependentReviewClaimed ||
		value.Production || value.Signing || value.Publication {
		findings.add("INFLATED_CLAIM", ReceiptPath, "finite evidence must remain bounded, aggregate-blocked, owner-attested, non-independent, non-production, unsigned, and unpublished")
	}
	exactLimitations := []string{
		"Finite test evidence is not exhaustive proof.",
		"Kani and CBMC were not executed.",
		"Production, differential, and conformance consumers remain unlinked.",
		"The disposable mutation runner was ephemeral and is not a shipped qualification tool.",
	}
	if !reflect.DeepEqual(value.Limitations, exactLimitations) {
		findings.add("INFLATED_CLAIM", "$.limitations", "the exact bounded-test, backend, and pending-consumer nonclaims are required")
	}
}

func validateBindings(root *os.Root, value *receipt, findings *collector) {
	type exactTarget struct {
		ID, Symbol, Source, SHA256, GitBlob, Token string
	}
	expected := []exactTarget{
		{"target.frame-header-decoder", "websocket_core::frame::decode::FrameHeaderDecoder::decode_header", "rust/connection-core/src/frame/decode.rs", "sha256:2d3b9d8cbda6ce8deea03b21e1e2beeab7ebf00195757ec3ef7dcff75e844da2", "08ab31cb7fa28dfe8451a70d4633fb18a21567d7", "pub fn decode_header"},
		{"target.frame-mask", "websocket_core::frame::mask::apply_mask_in_place", "rust/connection-core/src/frame/mask.rs", "sha256:04908fc1452ac9d219ebd23eb636d8676d987123365b594e1bfa6d987b31f2fd", "309038147fd825fee401cfe47eb09f31c7932658", "pub fn apply_mask_in_place"},
	}
	if len(value.Targets) != len(expected) {
		findings.add("SOURCE_BINDING_INVALID", "$.targets", "the exact two actual-code target bindings are required")
	}
	seen := map[string]bool{}
	for index, target := range value.Targets {
		itemPath := fmt.Sprintf("$.targets[%d]", index)
		if seen[target.TargetID] {
			findings.add("DUPLICATE_IDENTIFIER", itemPath+".target_id", "target identifier is duplicated")
		}
		seen[target.TargetID] = true
		var wanted *exactTarget
		for candidateIndex := range expected {
			if expected[candidateIndex].ID == target.TargetID {
				wanted = &expected[candidateIndex]
			}
		}
		if wanted == nil || target.Symbol != wanted.Symbol || target.Source.Path != wanted.Source || target.Source.SHA256 != wanted.SHA256 || target.Source.GitBlob != wanted.GitBlob {
			findings.add("SOURCE_BINDING_INVALID", itemPath, "target must bind the exact symbol and physical Rust source path")
			continue
		}
		data, ok := validateArtifact(root, target.Source, itemPath+".source", "SOURCE_BINDING_INVALID", findings)
		if ok && !bytes.Contains(data, []byte(wanted.Token)) {
			findings.add("SOURCE_BINDING_INVALID", itemPath+".source", "bound source does not contain the exact shipped item token")
		}
	}
	if value.Harness.TestName != "us012_formal_actual_code_obligations" || value.Harness.Source != (artifactBinding{Path: "rust/connection-core/tests/frame_codec.rs", SHA256: "sha256:7ad9e7b9caf82804a1764f9e7ea9e5ebc95ae56998d621c65e8dd347ebb936bb", GitBlob: "d39d79b4694771316ec4dfcae767f929148760ff"}) {
		findings.add("HARNESS_BINDING_INVALID", "$.harness", "receipt must bind the exact actual-code Rust test harness")
	} else if data, ok := validateArtifact(root, value.Harness.Source, "$.harness.source", "HARNESS_BINDING_INVALID", findings); ok {
		for _, token := range []string{"fn us012_formal_actual_code_obligations", "FrameHeaderDecoder::decode_header", "apply_mask_in_place"} {
			if !bytes.Contains(data, []byte(token)) {
				findings.add("HARNESS_BINDING_INVALID", "$.harness.source", "harness is missing required actual-code token: "+token)
			}
		}
	}
	if value.Toolchain.RustcVersion != "rustc 1.95.0 (59807616e 2026-04-14)" ||
		value.Toolchain.CargoVersion != "cargo 1.95.0 (f2d3ce0bd 2026-03-21)" ||
		value.Toolchain.TargetTriple != "aarch64-apple-darwin" ||
		value.Toolchain.RustcSHA256 != "sha256:b829b733131d4e1673eeebd1f34d06ae1e9ff4977b051313cf42e2a9e79ecf1c" ||
		value.Toolchain.CargoSHA256 != "sha256:c512bff73c86143b557463f021d0c3d5b0490d97d65040ba59ea2b3427784758" {
		findings.add("TOOLCHAIN_BINDING_INVALID", "$.toolchain", "receipt must retain the exact pinned Rust 1.95 toolchain identity")
	}
	if value.Toolchain.Pins != (artifactBinding{Path: "evidence/intake/toolchain-pins.json", SHA256: "sha256:0f5b3b8418d33d3ede7331199e572b5879719d36d4b5193fac926eb99118c717", GitBlob: "a6ce6a9574053e736b8fde87ff0b68ce168f435c"}) {
		findings.add("TOOLCHAIN_BINDING_INVALID", "$.toolchain.pins", "toolchain pins path is not canonical")
	} else {
		validateArtifact(root, value.Toolchain.Pins, "$.toolchain.pins", "TOOLCHAIN_BINDING_INVALID", findings)
	}
	if value.Toolchain.CargoLock != (artifactBinding{Path: "rust/Cargo.lock", SHA256: "sha256:b138978c2eca55cde701c3e9171ad69786779e83d6035fdd0a54917973209c83", GitBlob: "92b4f300f93afffc88c3e8828c1b8649cedda374"}) {
		findings.add("TOOLCHAIN_BINDING_INVALID", "$.toolchain.cargo_lock", "Cargo.lock path is not canonical")
	} else {
		validateArtifact(root, value.Toolchain.CargoLock, "$.toolchain.cargo_lock", "TOOLCHAIN_BINDING_INVALID", findings)
	}
}

func validateBounds(actual finiteBounds, findings *collector) {
	expected := finiteBounds{
		Header: headerBounds{
			Canonical7: rangeValues(0, 125), Canonical16: []uint64{126, 127, 255, 256, 65534, 65535},
			Canonical64: []uint64{65536, 65537, 1048576}, Noncanonical16: []uint64{125},
			Noncanonical64: []uint64{65535}, HighBit64: []string{"8000000000000000"},
			ControlCases: 6, RoleMaskCases: 4, PreallocationCases: 2,
		},
		Mask: maskBounds{
			Keys: []string{"00000000", "37fa213d", "ff55aa11"}, Offsets: []int{0, 1, 2, 3},
			MinimumLength: 0, MaximumLength: 16, InvolutionCases: 204, ByteEquationCases: 1632,
		},
	}
	if !reflect.DeepEqual(actual, expected) {
		findings.add("BOUND_DRIFT", "$.bounds", "finite header and mask domains differ from the exact executed harness bounds")
	}
}

func validateObligations(actual []obligationResult, findings *collector) {
	expected := exactObligations()
	if len(actual) != len(expected) {
		findings.add("ZERO_OBLIGATIONS", "$.obligations", "the exact eight nonzero obligation results are required")
	}
	seen := map[string]bool{}
	for index, item := range actual {
		itemPath := fmt.Sprintf("$.obligations[%d]", index)
		if seen[item.ObligationID] {
			findings.add("DUPLICATE_IDENTIFIER", itemPath+".obligation_id", "obligation result is duplicated")
		}
		seen[item.ObligationID] = true
		wanted, ok := expected[item.ObligationID]
		if !ok || item.TargetSymbol != wanted.TargetSymbol || item.CaseCount != wanted.CaseCount || item.Outcome != "PASS" {
			reason := "OBLIGATION_RESULT_MISMATCH"
			if item.CaseCount <= 0 {
				reason = "ZERO_OBLIGATIONS"
			}
			findings.add(reason, itemPath, "obligation must bind its exact actual-code target and nonzero finite count")
		}
	}
	if !sortedByObligation(actual) {
		findings.add("NONCANONICAL_SET_ORDER", "$.obligations", "obligation results must be sorted by obligation_id")
	}
}

func validateCanaries(targets []targetBinding, actual []mutationCanary, findings *collector) {
	targetsBySymbol := map[string]targetBinding{}
	for _, target := range targets {
		targetsBySymbol[target.Symbol] = target
	}
	expected := exactCanaries()
	if len(actual) != len(expected) {
		findings.add("MISSING_SOURCE_MUTATION", "$.source_mutation_canaries", "the exact eight shipped-source mutation canaries are required")
	}
	seen := map[string]bool{}
	for index, canary := range actual {
		itemPath := fmt.Sprintf("$.source_mutation_canaries[%d]", index)
		if seen[canary.CanaryID] {
			findings.add("DUPLICATE_IDENTIFIER", itemPath+".canary_id", "source mutation canary is duplicated")
		}
		seen[canary.CanaryID] = true
		wanted, ok := expected[canary.CanaryID]
		target, targetOK := targetsBySymbol[canary.TargetSymbol]
		if !ok || !targetOK || canary.Mutation != wanted.Mutation || !reflect.DeepEqual(canary.ObligationIDs, wanted.ObligationIDs) || canary.BaselineSHA256 != target.Source.SHA256 || canary.MutatedSourceSHA256 != wanted.MutatedSHA256 || canary.DiagnosticSHA256 != wanted.DiagnosticSHA256 || canary.TestExitCode != 101 {
			findings.add("SOURCE_MUTATION_INVALID", itemPath, "canary does not bind the exact shipped source, mutation, and obligation set")
		}
		if canary.Outcome != "KILLED" || canary.TestExitCode == 0 || !validDigest(canary.DiagnosticSHA256) || !validDigest(canary.MutatedSourceSHA256) || canary.MutatedSourceSHA256 == canary.BaselineSHA256 {
			findings.add("KNOWN_BAD_CANARY_SURVIVED", itemPath, "source mutation must retain a distinct mutant digest, failing test exit, diagnostic digest, and KILLED outcome")
		}
	}
	if !sort.SliceIsSorted(actual, func(i, j int) bool { return actual[i].CanaryID < actual[j].CanaryID }) {
		findings.add("NONCANONICAL_SET_ORDER", "$.source_mutation_canaries", "source mutations must be sorted by canary_id")
	}
}

func validateReplay(obligations []obligationResult, outputs []retainedOutput, replay replayEvidence, findings *collector) {
	outputByID := map[string]retainedOutput{}
	for index, output := range outputs {
		itemPath := fmt.Sprintf("$.outputs[%d]", index)
		if outputByID[output.OutputID].OutputID != "" {
			findings.add("DUPLICATE_IDENTIFIER", itemPath+".output_id", "retained output identifier is duplicated")
		}
		outputByID[output.OutputID] = output
		if digestBytes([]byte(output.Content)) != output.SHA256 {
			findings.add("OUTPUT_BINDING_INVALID", itemPath+".sha256", "output digest does not bind its exact retained content")
		}
		if strings.Contains(output.OutputID, ".raw.") && output.Kind != "RAW" || strings.Contains(output.OutputID, ".normalized.") && output.Kind != "NORMALIZED" {
			findings.add("OUTPUT_BINDING_INVALID", itemPath+".kind", "output identifier and kind disagree")
		}
	}
	if len(outputs) != 4 || !sort.SliceIsSorted(outputs, func(i, j int) bool { return outputs[i].OutputID < outputs[j].OutputID }) {
		findings.add("OUTPUT_BINDING_INVALID", "$.outputs", "exactly four sorted raw/normalized replay outputs are required")
	}
	if !reflect.DeepEqual(replay.Argv, exactReplayArgv) || !reflect.DeepEqual(replay.Environment, exactReplayEnvironment) || replay.WorkingDirectory != "rust" {
		findings.add("REPLAY_MISMATCH", "$.replay", "replay must use the exact offline, locale-stable cargo test command")
	}
	if replay.RepeatCount != 2 || len(replay.Runs) != 2 || !replay.ReconciledIdentically || replay.SemanticOutputDigest != digestBytes([]byte(exactNormalizedOutput)) {
		findings.add("REPLAY_MISMATCH", "$.replay", "two reconciled replay observations must bind the exact semantic output")
	}
	seenRuns := map[string]bool{}
	for index, run := range replay.Runs {
		itemPath := fmt.Sprintf("$.replay.runs[%d]", index)
		if seenRuns[run.RunID] || run.RunID != fmt.Sprintf("replay.%d", index+1) || run.ExitCode != 0 || !reflect.DeepEqual(run.ObligationCounts, obligations) {
			findings.add("REPLAY_MISMATCH", itemPath, "run identity, exit, or obligation results differ from the retained receipt")
		}
		seenRuns[run.RunID] = true
		raw, rawOK := outputByID[run.RawOutputID]
		normalized, normalizedOK := outputByID[run.NormalizedOutputID]
		if !rawOK || raw.Kind != "RAW" || !strings.Contains(raw.Content, exactNormalizedOutput) || !strings.Contains(raw.Content, "us012_formal_actual_code_obligations") ||
			!normalizedOK || normalized.Kind != "NORMALIZED" || normalized.Content != exactNormalizedOutput || normalized.SHA256 != replay.SemanticOutputDigest {
			findings.add("REPLAY_MISMATCH", itemPath, "run must reference its own raw output and exact normalized obligation line")
		}
	}
}

type canaryContract struct {
	Mutation         string
	ObligationIDs    []string
	MutatedSHA256    string
	DiagnosticSHA256 string
}

func exactCanaries() map[string]canaryContract {
	return map[string]canaryContract{
		"canary.source.preallocation-boundary-changed": {"change shipped decoder frame cap from greater-than to greater-than-or-equal", []string{"obligation.preallocation-cap"}, "sha256:7e070ad9d151a1dfaf45762f666e43f5453863bf984a63d57f94d5c73ecaa00e", "sha256:f4cdc8c5f3bc173c4a338dfcae148c0b6d159aa309dc7ca72b84cfc9a2bcc98a"},
		"canary.source.control-validation-removed":     {"remove shipped decoder control FIN and length rejection", []string{"obligation.control-fin-and-length"}, "sha256:402a27a809caf5f502963de9c901861776ba53cc75c09435bd05e8b0248ad073", "sha256:24817b2fb960ab32124b6b84e14373e67d9c1048b6bd4e8c96c1c61f8c17e85f"},
		"canary.source.high-bit-check-removed":         {"remove shipped decoder 64-bit high-bit rejection", []string{"obligation.length-canonical-64-high-bit-zero"}, "sha256:1e1c86d1f2c770a7bd6149f4f43f749bdbf3afea144f3c76c1a851807f50c2ad", "sha256:c73c3a20fa2bf1b5d4faa2f93db17f3327d80639ff7c72287825f4b9ca26d889"},
		"canary.source.mask-index-offset-removed":      {"ignore payload offset in shipped mask index", []string{"obligation.mask-equation"}, "sha256:6c71e2ed0a69a4eaf57e523e85fdab9719c0c10c5ef296323c612f266af02c14", "sha256:aae59d79d78990fb190d1af8507266e521c4a370360cec4538b71a24c6890bf0"},
		"canary.source.mask-xor-replaced":              {"replace XOR with wrapping addition in shipped mask", []string{"obligation.mask-equation", "obligation.mask-involution"}, "sha256:e3cdf44c7747ffba7c97b7122030a74043feebc1907df29b96896bafac36d969", "sha256:2a3832db08e2c23cae62937a6d9242671aa506c9a747006de376516c6178bded"},
		"canary.source.noncanonical-16-check-removed":  {"remove shipped decoder noncanonical 16-bit rejection", []string{"obligation.length-canonical-16"}, "sha256:197ce9d9ab598d96fc47aea2d9a2f7ee9e8e274e9f0d579de56043d174dc6059", "sha256:73544852d41d1c3eb228811bbf637e12177006ee55cc5340ffa8c265c7eaf0d5"},
		"canary.source.noncanonical-64-check-removed":  {"remove shipped decoder noncanonical 64-bit rejection", []string{"obligation.length-canonical-64-high-bit-zero"}, "sha256:dd006dddd4d85e1e3bcfcf6b6b9d96adcb6e7c99dc615cd10f0924f459d92829", "sha256:66ae618d58a2bd2c4333699fdc1d8c59ef376766acfe8962c9866d30bc046504"},
		"canary.source.role-mask-check-removed":        {"remove shipped decoder role mask rejection", []string{"obligation.role-masking"}, "sha256:e3f76be3fc83d93df024f879f73248320e0b8d0594ec1bb6048b5847a4898fc6", "sha256:0838ad618d3cba87e8f7420ecedebb16b59f78b92370a6ba5c90fd38a6179741"},
	}
}

func exactObligations() map[string]obligationResult {
	decode := "websocket_core::frame::decode::FrameHeaderDecoder::decode_header"
	mask := "websocket_core::frame::mask::apply_mask_in_place"
	return map[string]obligationResult{
		"obligation.control-fin-and-length":            {"obligation.control-fin-and-length", decode, 6, "PASS"},
		"obligation.length-canonical-16":               {"obligation.length-canonical-16", decode, 6, "PASS"},
		"obligation.length-canonical-64-high-bit-zero": {"obligation.length-canonical-64-high-bit-zero", decode, 3, "PASS"},
		"obligation.length-canonical-7":                {"obligation.length-canonical-7", decode, 126, "PASS"},
		"obligation.mask-equation":                     {"obligation.mask-equation", mask, 1632, "PASS"},
		"obligation.mask-involution":                   {"obligation.mask-involution", mask, 204, "PASS"},
		"obligation.preallocation-cap":                 {"obligation.preallocation-cap", decode, 2, "PASS"},
		"obligation.role-masking":                      {"obligation.role-masking", decode, 4, "PASS"},
	}
}

func sortedByObligation(values []obligationResult) bool {
	return sort.SliceIsSorted(values, func(i, j int) bool { return values[i].ObligationID < values[j].ObligationID })
}

func rangeValues(first, last uint64) []uint64 {
	values := make([]uint64, 0, last-first+1)
	for value := first; value <= last; value++ {
		values = append(values, value)
	}
	return values
}

func validateArtifact(root *os.Root, binding artifactBinding, findingPath, reason string, findings *collector) ([]byte, bool) {
	if _, err := canonicalPath(binding.Path); err != nil || !validDigest(binding.SHA256) || !validGitBlob(binding.GitBlob) {
		findings.add(reason, findingPath, "artifact requires a canonical path, SHA-256 digest, and Git blob identity")
		return nil, false
	}
	data, err := readRegular(root, binding.Path, maxEvidenceBytes)
	if err != nil {
		findings.add(reason, findingPath, err.Error())
		return nil, false
	}
	if digestBytes(data) != binding.SHA256 || artifactGitBlob(data) != binding.GitBlob {
		findings.add(reason, findingPath, "snapshotted bytes do not match the declared SHA-256 and Git blob identities")
		return data, false
	}
	return data, true
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validGitBlob(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func artifactGitBlob(data []byte) string {
	hash := sha1.New()
	_, _ = fmt.Fprintf(hash, "blob %d%c", len(data), byte(0))
	_, _ = hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

func decodeStrict(data []byte, target any) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("INVALID_UTF8: JSON input is not valid UTF-8")
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("NULL_JSON_DOCUMENT: top-level null is not a document")
	}
	return vendorprotocol.DecodeStrict(data, target)
}

func decodeReason(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "DUPLICATE_JSON_FIELD"), strings.Contains(message, "duplicate JSON object key"):
		return "DUPLICATE_JSON_MEMBER"
	case strings.Contains(message, "UNKNOWN_JSON_FIELD"), strings.Contains(message, "unknown field"):
		return "UNKNOWN_JSON_MEMBER"
	case strings.Contains(message, "TRAILING_JSON_VALUE"), strings.Contains(message, "multiple JSON values"):
		return "TRAILING_JSON_VALUE"
	case strings.Contains(message, "NULL_JSON_DOCUMENT"):
		return "NULL_JSON_DOCUMENT"
	case strings.Contains(message, "INVALID_UTF8"):
		return "INVALID_UTF8"
	default:
		return "INVALID_JSON"
	}
}

func validateSchema(schemaData, documentData []byte, findings *collector) {
	var schemaDocument any
	if err := decodeStrict(schemaData, &schemaDocument); err != nil {
		findings.add("SCHEMA_INVALID", SchemaPath, err.Error())
		return
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.AssertContent()
	if err := compiler.AddResource("mem:///"+SchemaPath, schemaDocument); err != nil {
		findings.add("SCHEMA_INVALID", SchemaPath, err.Error())
		return
	}
	schema, err := compiler.Compile("mem:///" + SchemaPath)
	if err != nil {
		findings.add("SCHEMA_INVALID", SchemaPath, err.Error())
		return
	}
	var document any
	if err := json.Unmarshal(documentData, &document); err != nil {
		return
	}
	if err := schema.Validate(document); err != nil {
		findings.add("SCHEMA_VIOLATION", ReceiptPath, err.Error())
	}
}

func canonicalPath(name string) (string, error) {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.HasPrefix(name, "./") || strings.Contains(name, "//") {
		return "", fmt.Errorf("path must be canonical and slash-relative")
	}
	clean := path.Clean(name)
	if clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") || clean != name {
		return "", fmt.Errorf("path escapes root or is noncanonical")
	}
	return clean, nil
}

type fileIdentity struct {
	device uint64
	inode  uint64
	links  uint64
}

func readRegular(root *os.Root, name string, limit int64) ([]byte, error) {
	canonical, err := canonicalPath(name)
	if err != nil {
		return nil, err
	}
	before, err := root.Lstat(canonical)
	if err != nil {
		return nil, err
	}
	beforeID, ok := identityOf(before)
	if !ok || !before.Mode().IsRegular() || before.Mode()&fs.ModeSymlink != 0 || beforeID.links != 1 {
		return nil, fmt.Errorf("%s is not a stable single-link regular file", canonical)
	}
	file, err := root.Open(canonical)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	openedID, ok := identityOf(opened)
	if !ok || openedID != beforeID || opened.Size() != before.Size() || !opened.ModTime().Equal(before.ModTime()) {
		return nil, fmt.Errorf("%s changed while being opened", canonical)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", canonical, limit)
	}
	after, err := root.Lstat(canonical)
	if err != nil {
		return nil, err
	}
	afterID, ok := identityOf(after)
	if !ok || afterID != beforeID || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, fmt.Errorf("%s changed while being read", canonical)
	}
	return data, nil
}

func identityOf(info fs.FileInfo) (fileIdentity, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, false
	}
	return fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), links: uint64(stat.Nlink)}, true
}
