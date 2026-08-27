package frameformal

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestUS012ValidBoundedActualCodeReceipt(t *testing.T) {
	root, value := validFixture(t)
	writeReceipt(t, root, value)
	verdict, err := Validate(context.Background(), Request{RootPath: root})
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Valid || verdict.State != "PASS" || verdict.ClaimScope != "BOUNDED_TEST_EVIDENCE" || verdict.AggregateFormalState != "BLOCKED" || len(verdict.Findings) != 0 {
		t.Fatalf("verdict = %#v", verdict)
	}
}

func TestUS012RepositoryReceiptBindsFinalShippedSources(t *testing.T) {
	verdict, err := Validate(context.Background(), Request{RootPath: repositoryRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Valid || verdict.State != "PASS" || verdict.AggregateFormalState != "BLOCKED" {
		t.Fatalf("repository verdict = %#v", verdict)
	}
}

func TestUS012HostileBoundedEvidenceMatrix(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		mutate func(*testing.T, string, *receipt)
	}{
		{"missing source binding", "SOURCE_BINDING_INVALID", func(_ *testing.T, _ string, value *receipt) { value.Targets[0].Source.SHA256 = "" }},
		{"zero counts", "ZERO_OBLIGATIONS", func(_ *testing.T, _ string, value *receipt) { value.Obligations[0].CaseCount = 0 }},
		{"replay mismatch", "REPLAY_MISMATCH", func(_ *testing.T, _ string, value *receipt) { value.Replay.Runs[1].ObligationCounts[0].CaseCount++ }},
		{"surviving canary", "KNOWN_BAD_CANARY_SURVIVED", func(_ *testing.T, _ string, value *receipt) { value.SourceMutationCanaries[0].Outcome = "SURVIVED" }},
		{"fabricated killed canary", "SOURCE_MUTATION_INVALID", func(_ *testing.T, _ string, value *receipt) {
			value.SourceMutationCanaries[0].DiagnosticSHA256 = digest([]byte("invented diagnostic"))
		}},
		{"source substitution", "SOURCE_BINDING_INVALID", func(t *testing.T, root string, value *receipt) {
			path := filepath.Join(root, value.Targets[0].Source.Path)
			if err := os.WriteFile(path, []byte("pub fn substituted() {}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			value.Targets[0].Source = bindFile(t, root, value.Targets[0].Source.Path)
		}},
		{"harness substitution", "HARNESS_BINDING_INVALID", func(t *testing.T, root string, value *receipt) {
			path := filepath.Join(root, value.Harness.Source.Path)
			if err := os.WriteFile(path, []byte("#[test] fn substituted() {}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			value.Harness.Source = bindFile(t, root, value.Harness.Source.Path)
		}},
		{"inflated claim", "INFLATED_CLAIM", func(_ *testing.T, _ string, value *receipt) { value.ClaimScope = "PROVED_PRODUCTION_CODE" }},
		{"placeholder", "PENDING_BINDING", func(_ *testing.T, _ string, value *receipt) { value.Toolchain.RustcSHA256 = "PENDING_FINAL_DIGEST" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, value := validFixture(t)
			test.mutate(t, root, &value)
			writeReceipt(t, root, value)
			verdict, err := Validate(context.Background(), Request{RootPath: root})
			if err != nil {
				t.Fatal(err)
			}
			if verdict.Valid || !hasReason(verdict.Findings, test.reason) {
				t.Fatalf("verdict = %#v, want %s", verdict, test.reason)
			}
		})
	}
}

func TestUS012StrictClosedJSON(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		root, value := validFixture(t)
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.Replace(string(data), `"publication":false`, `"publication":false,"unknown":true`, 1))
		writeRawReceipt(t, root, data)
		verdict, err := Validate(context.Background(), Request{RootPath: root})
		if err != nil {
			t.Fatal(err)
		}
		if !hasReason(verdict.Findings, "UNKNOWN_JSON_MEMBER") {
			t.Fatalf("findings = %#v", verdict.Findings)
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		root, value := validFixture(t)
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.Replace(string(data), `"publication":false`, `"publication":false,"publication":false`, 1))
		writeRawReceipt(t, root, data)
		verdict, err := Validate(context.Background(), Request{RootPath: root})
		if err != nil {
			t.Fatal(err)
		}
		if !hasReason(verdict.Findings, "DUPLICATE_JSON_MEMBER") {
			t.Fatalf("findings = %#v", verdict.Findings)
		}
	})
}

func validFixture(t *testing.T) (string, receipt) {
	t.Helper()
	root := t.TempDir()
	repository := repositoryRoot(t)
	files := []string{
		"rust/connection-core/src/frame/decode.rs",
		"rust/connection-core/src/frame/mask.rs",
		"rust/connection-core/tests/frame_codec.rs",
		"evidence/intake/toolchain-pins.json",
		"rust/Cargo.lock",
	}
	for _, name := range files {
		content, err := os.ReadFile(filepath.Join(repository, name))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(ReceiptPath)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(SchemaPath)), 0o700); err != nil {
		t.Fatal(err)
	}
	schemaData, err := os.ReadFile(filepath.Join(repository, SchemaPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, SchemaPath), schemaData, 0o600); err != nil {
		t.Fatal(err)
	}

	targets := []targetBinding{
		{TargetID: "target.frame-header-decoder", Symbol: "websocket_core::frame::decode::FrameHeaderDecoder::decode_header", Source: bindFile(t, root, "rust/connection-core/src/frame/decode.rs")},
		{TargetID: "target.frame-mask", Symbol: "websocket_core::frame::mask::apply_mask_in_place", Source: bindFile(t, root, "rust/connection-core/src/frame/mask.rs")},
	}
	counts := expectedObligations()
	normalized := expectedNormalizedOutput(counts)
	outputs := []retainedOutput{
		newOutput("output.normalized.1", "NORMALIZED", normalized),
		newOutput("output.normalized.2", "NORMALIZED", normalized),
		newOutput("output.raw.1", "RAW", "test us012_formal_actual_code_obligations ... ok\n"+normalized),
		newOutput("output.raw.2", "RAW", "test us012_formal_actual_code_obligations ... ok\n"+normalized),
	}
	sort.Slice(outputs, func(i, j int) bool { return outputs[i].OutputID < outputs[j].OutputID })
	canaries := expectedCanaries(targets)
	return root, receipt{
		Schema: "../../schemas/frame-formal-results-1.0.0.schema.json", SchemaVersion: "1.0.0",
		EvidenceKind: "US012_FRAME_ACTUAL_CODE_BOUNDED_RESULTS", StoryID: "US-012", State: "PASS",
		ClaimScope: "BOUNDED_TEST_EVIDENCE", AggregateFormalState: "BLOCKED", Targets: targets,
		Harness:   harnessBinding{TestName: "us012_formal_actual_code_obligations", Source: bindFile(t, root, "rust/connection-core/tests/frame_codec.rs")},
		Toolchain: toolchainBinding{RustcVersion: "rustc 1.95.0 (59807616e 2026-04-14)", CargoVersion: "cargo 1.95.0 (f2d3ce0bd 2026-03-21)", TargetTriple: "aarch64-apple-darwin", RustcSHA256: "sha256:b829b733131d4e1673eeebd1f34d06ae1e9ff4977b051313cf42e2a9e79ecf1c", CargoSHA256: "sha256:c512bff73c86143b557463f021d0c3d5b0490d97d65040ba59ea2b3427784758", Pins: bindFile(t, root, "evidence/intake/toolchain-pins.json"), CargoLock: bindFile(t, root, "rust/Cargo.lock")},
		Bounds:    expectedBounds(), Obligations: counts, SourceMutationCanaries: canaries, Outputs: outputs,
		Replay:      replayEvidence{Argv: []string{"cargo", "test", "-p", "websocket-core", "--test", "frame_codec", "us012_formal_actual_code_obligations", "--", "--exact", "--nocapture"}, Environment: []string{"CARGO_NET_OFFLINE=true", "LANG=C", "LC_ALL=C"}, WorkingDirectory: "rust", RepeatCount: 2, ReconciledIdentically: true, SemanticOutputDigest: digest([]byte(normalized)), Runs: []replayRun{{RunID: "replay.1", ExitCode: 0, RawOutputID: "output.raw.1", NormalizedOutputID: "output.normalized.1", ObligationCounts: cloneObligations(counts)}, {RunID: "replay.2", ExitCode: 0, RawOutputID: "output.raw.2", NormalizedOutputID: "output.normalized.2", ObligationCounts: cloneObligations(counts)}}},
		Limitations: []string{"Finite test evidence is not exhaustive proof.", "Kani and CBMC were not executed.", "Production, differential, and conformance consumers remain unlinked.", "The disposable mutation runner was ephemeral and is not a shipped qualification tool."},
		Assurance:   "OWNER_ATTESTED_NOT_INDEPENDENT",
	}
}

func expectedBounds() finiteBounds {
	return finiteBounds{Header: headerBounds{Canonical7: rangeUint64(0, 125), Canonical16: []uint64{126, 127, 255, 256, 65534, 65535}, Canonical64: []uint64{65536, 65537, 1048576}, Noncanonical16: []uint64{125}, Noncanonical64: []uint64{65535}, HighBit64: []string{"8000000000000000"}, ControlCases: 6, RoleMaskCases: 4, PreallocationCases: 2}, Mask: maskBounds{Keys: []string{"00000000", "37fa213d", "ff55aa11"}, Offsets: []int{0, 1, 2, 3}, MinimumLength: 0, MaximumLength: 16, InvolutionCases: 204, ByteEquationCases: 1632}}
}

func expectedObligations() []obligationResult {
	decode := "websocket_core::frame::decode::FrameHeaderDecoder::decode_header"
	mask := "websocket_core::frame::mask::apply_mask_in_place"
	return []obligationResult{{"obligation.control-fin-and-length", decode, 6, "PASS"}, {"obligation.length-canonical-16", decode, 6, "PASS"}, {"obligation.length-canonical-64-high-bit-zero", decode, 3, "PASS"}, {"obligation.length-canonical-7", decode, 126, "PASS"}, {"obligation.mask-equation", mask, 1632, "PASS"}, {"obligation.mask-involution", mask, 204, "PASS"}, {"obligation.preallocation-cap", decode, 2, "PASS"}, {"obligation.role-masking", decode, 4, "PASS"}}
}

func expectedCanaries(targets []targetBinding) []mutationCanary {
	decode, mask := targets[0], targets[1]
	return []mutationCanary{
		{CanaryID: "canary.source.control-validation-removed", TargetSymbol: decode.Symbol, Mutation: "remove shipped decoder control FIN and length rejection", BaselineSHA256: decode.Source.SHA256, MutatedSourceSHA256: "sha256:402a27a809caf5f502963de9c901861776ba53cc75c09435bd05e8b0248ad073", TestExitCode: 101, DiagnosticSHA256: "sha256:24817b2fb960ab32124b6b84e14373e67d9c1048b6bd4e8c96c1c61f8c17e85f", ObligationIDs: []string{"obligation.control-fin-and-length"}, Outcome: "KILLED"},
		{CanaryID: "canary.source.high-bit-check-removed", TargetSymbol: decode.Symbol, Mutation: "remove shipped decoder 64-bit high-bit rejection", BaselineSHA256: decode.Source.SHA256, MutatedSourceSHA256: "sha256:1e1c86d1f2c770a7bd6149f4f43f749bdbf3afea144f3c76c1a851807f50c2ad", TestExitCode: 101, DiagnosticSHA256: "sha256:c73c3a20fa2bf1b5d4faa2f93db17f3327d80639ff7c72287825f4b9ca26d889", ObligationIDs: []string{"obligation.length-canonical-64-high-bit-zero"}, Outcome: "KILLED"},
		{CanaryID: "canary.source.mask-index-offset-removed", TargetSymbol: mask.Symbol, Mutation: "ignore payload offset in shipped mask index", BaselineSHA256: mask.Source.SHA256, MutatedSourceSHA256: "sha256:6c71e2ed0a69a4eaf57e523e85fdab9719c0c10c5ef296323c612f266af02c14", TestExitCode: 101, DiagnosticSHA256: "sha256:aae59d79d78990fb190d1af8507266e521c4a370360cec4538b71a24c6890bf0", ObligationIDs: []string{"obligation.mask-equation"}, Outcome: "KILLED"},
		{CanaryID: "canary.source.mask-xor-replaced", TargetSymbol: mask.Symbol, Mutation: "replace XOR with wrapping addition in shipped mask", BaselineSHA256: mask.Source.SHA256, MutatedSourceSHA256: "sha256:e3cdf44c7747ffba7c97b7122030a74043feebc1907df29b96896bafac36d969", TestExitCode: 101, DiagnosticSHA256: "sha256:2a3832db08e2c23cae62937a6d9242671aa506c9a747006de376516c6178bded", ObligationIDs: []string{"obligation.mask-equation", "obligation.mask-involution"}, Outcome: "KILLED"},
		{CanaryID: "canary.source.noncanonical-16-check-removed", TargetSymbol: decode.Symbol, Mutation: "remove shipped decoder noncanonical 16-bit rejection", BaselineSHA256: decode.Source.SHA256, MutatedSourceSHA256: "sha256:197ce9d9ab598d96fc47aea2d9a2f7ee9e8e274e9f0d579de56043d174dc6059", TestExitCode: 101, DiagnosticSHA256: "sha256:73544852d41d1c3eb228811bbf637e12177006ee55cc5340ffa8c265c7eaf0d5", ObligationIDs: []string{"obligation.length-canonical-16"}, Outcome: "KILLED"},
		{CanaryID: "canary.source.noncanonical-64-check-removed", TargetSymbol: decode.Symbol, Mutation: "remove shipped decoder noncanonical 64-bit rejection", BaselineSHA256: decode.Source.SHA256, MutatedSourceSHA256: "sha256:dd006dddd4d85e1e3bcfcf6b6b9d96adcb6e7c99dc615cd10f0924f459d92829", TestExitCode: 101, DiagnosticSHA256: "sha256:66ae618d58a2bd2c4333699fdc1d8c59ef376766acfe8962c9866d30bc046504", ObligationIDs: []string{"obligation.length-canonical-64-high-bit-zero"}, Outcome: "KILLED"},
		{CanaryID: "canary.source.preallocation-boundary-changed", TargetSymbol: decode.Symbol, Mutation: "change shipped decoder frame cap from greater-than to greater-than-or-equal", BaselineSHA256: decode.Source.SHA256, MutatedSourceSHA256: "sha256:7e070ad9d151a1dfaf45762f666e43f5453863bf984a63d57f94d5c73ecaa00e", TestExitCode: 101, DiagnosticSHA256: "sha256:f4cdc8c5f3bc173c4a338dfcae148c0b6d159aa309dc7ca72b84cfc9a2bcc98a", ObligationIDs: []string{"obligation.preallocation-cap"}, Outcome: "KILLED"},
		{CanaryID: "canary.source.role-mask-check-removed", TargetSymbol: decode.Symbol, Mutation: "remove shipped decoder role mask rejection", BaselineSHA256: decode.Source.SHA256, MutatedSourceSHA256: "sha256:e3f76be3fc83d93df024f879f73248320e0b8d0594ec1bb6048b5847a4898fc6", TestExitCode: 101, DiagnosticSHA256: "sha256:0838ad618d3cba87e8f7420ecedebb16b59f78b92370a6ba5c90fd38a6179741", ObligationIDs: []string{"obligation.role-masking"}, Outcome: "KILLED"},
	}
}

func bindFile(t *testing.T, root, name string) artifactBinding {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return artifactBinding{Path: name, SHA256: digest(data), GitBlob: gitBlob(data)}
}
func newOutput(id, kind, content string) retainedOutput {
	return retainedOutput{OutputID: id, Kind: kind, Content: content, SHA256: digest([]byte(content))}
}
func cloneObligations(values []obligationResult) []obligationResult {
	return append([]obligationResult(nil), values...)
}
func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func gitBlob(data []byte) string {
	hash := sha1.New()
	_, _ = fmt.Fprintf(hash, "blob %d%c", len(data), byte(0))
	_, _ = hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}
func rangeUint64(first, last uint64) []uint64 {
	values := make([]uint64, 0, last-first+1)
	for value := first; value <= last; value++ {
		values = append(values, value)
	}
	return values
}
func expectedNormalizedOutput([]obligationResult) string {
	return "US012_ACTUAL_CODE_COUNTS control_fin_and_length=6 length_canonical_16=6 length_canonical_64_high_bit_zero=3 length_canonical_7=126 preallocation_cap=2 role_masking=4 mask_equation=1632 mask_involution=204\n"
}
func writeReceipt(t *testing.T, root string, value receipt) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeRawReceipt(t, root, append(data, '\n'))
}
func writeRawReceipt(t *testing.T, root string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ReceiptPath), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
func hasReason(findings []Finding, reason string) bool {
	for _, finding := range findings {
		if finding.Reason == reason {
			return true
		}
	}
	return false
}
func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
