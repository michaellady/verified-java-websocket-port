// Command kanidriver executes and verifies owner-attested Kani evidence for the
// shipped WebSocket frame decoder and masking symbols.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	evidenceKind = "KANI_PRODUCTION_SYMBOL_EVIDENCE"
	claimScope   = "OWNER_EXECUTED_KANI_PRODUCTION_SYMBOLS"
	assurance    = "OWNER_ATTESTED_NOT_INDEPENDENT"
	maxFileSize  = int64(8 << 20)
)

var (
	resultPattern = regexp.MustCompile(`(?m)^ \*\* ([0-9]+) of ([0-9]+) failed( \(([0-9]+) unreachable\))?$`)
	timePattern   = regexp.MustCompile(`(?m)^Verification Time: [^\r\n]+$`)
	finishPattern = regexp.MustCompile(`(?m)(target\(s\) in) [0-9.]+s$`)
	hexDigest     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hexCommit     = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type sourceBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type subjectInfo struct {
	Commit        string          `json:"commit"`
	Tree          string          `json:"tree"`
	ObjectFormat  string          `json:"object_format"`
	CleanCheckout bool            `json:"clean_checkout"`
	Sources       []sourceBinding `json:"sources"`
}

type toolInfo struct {
	KaniVersion        string `json:"kani_version"`
	KaniSourceCommit   string `json:"kani_source_commit"`
	KaniSourceTree     string `json:"kani_source_tree"`
	CargoKaniSHA256    string `json:"cargo_kani_sha256"`
	KaniCompilerSHA256 string `json:"kani_compiler_sha256"`
	CBMCVersion        string `json:"cbmc_version"`
	CBMCSHA256         string `json:"cbmc_sha256"`
	RustcVersion       string `json:"rustc_version"`
	RustcSHA256        string `json:"rustc_sha256"`
	DriverSHA256       string `json:"driver_sha256"`
}

type harnessPlan struct {
	HarnessID      string   `json:"harness_id"`
	TargetSymbol   string   `json:"target_symbol"`
	SourcePath     string   `json:"source_path"`
	ObligationIDs  []string `json:"obligation_ids"`
	Unwind         int      `json:"unwind"`
	SymbolicDomain []string `json:"symbolic_domain"`
}

type kaniResult struct {
	Status            string   `json:"status"`
	ExitCode          int      `json:"exit_code"`
	FailedChecks      int      `json:"failed_checks"`
	TotalChecks       int      `json:"total_checks"`
	UnreachableChecks int      `json:"unreachable_checks"`
	RawOutputSHA256   string   `json:"raw_output_sha256"`
	NormalizedLog     artifact `json:"normalized_log"`
}

type harnessResult struct {
	HarnessID string `json:"harness_id"`
	kaniResult
}

type replayRun struct {
	RunID                    string          `json:"run_id"`
	Results                  []harnessResult `json:"results"`
	SemanticProjectionSHA256 string          `json:"semantic_projection_sha256"`
}

type mutationResult struct {
	CanaryID             string   `json:"canary_id"`
	HarnessID            string   `json:"harness_id"`
	SourcePath           string   `json:"source_path"`
	Mutation             string   `json:"mutation"`
	BaselineSourceSHA256 string   `json:"baseline_source_sha256"`
	MutatedSourceSHA256  string   `json:"mutated_source_sha256"`
	ObligationIDs        []string `json:"obligation_ids"`
	kaniResult
}

type executionInfo struct {
	GOOS                     string           `json:"goos"`
	GOARCH                   string           `json:"goarch"`
	PointerWidth             int              `json:"pointer_width"`
	Environment              []string         `json:"environment"`
	Harnesses                []harnessPlan    `json:"harnesses"`
	RepeatCount              int              `json:"repeat_count"`
	Runs                     []replayRun      `json:"runs"`
	SemanticallyIdentical    bool             `json:"semantically_identical"`
	SemanticProjectionSHA256 string           `json:"semantic_projection_sha256"`
	MutationCanaries         []mutationResult `json:"mutation_canaries"`
	MutationSurvivors        int              `json:"mutation_survivors"`
	UnsupportedConstructs    []string         `json:"unsupported_constructs"`
}

type receipt struct {
	Schema                   string        `json:"$schema"`
	SchemaVersion            string        `json:"schema_version"`
	EvidenceKind             string        `json:"evidence_kind"`
	Subject                  subjectInfo   `json:"subject"`
	Toolchain                toolInfo      `json:"toolchain"`
	Execution                executionInfo `json:"execution"`
	Status                   string        `json:"status"`
	ClaimScope               string        `json:"claim_scope"`
	Limitations              []string      `json:"limitations"`
	Assurance                string        `json:"assurance"`
	IndependentReviewClaimed bool          `json:"independent_review_claimed"`
	Production               bool          `json:"production"`
	Signing                  bool          `json:"signing"`
	Publication              bool          `json:"publication"`
}

type mutationPlan struct {
	CanaryID    string
	HarnessID   string
	SourcePath  string
	Find        string
	Replace     string
	Description string
	Obligations []string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		usage(stderr)
		return 2
	}
	switch arguments[0] {
	case "run":
		flags := flag.NewFlagSet("run", flag.ContinueOnError)
		flags.SetOutput(stderr)
		root := flags.String("root", "", "clean repository root")
		cargoKani := flags.String("cargo-kani", "", "absolute cargo-kani executable")
		kaniCompiler := flags.String("kani-compiler", "", "absolute kani compiler executable")
		cbmc := flags.String("cbmc", "", "absolute CBMC executable")
		rustc := flags.String("rustc", "", "absolute Rust compiler executable")
		kaniSourceRoot := flags.String("kani-source-root", "", "clean pinned Kani source checkout")
		work := flags.String("work", "", "empty disposable work directory")
		out := flags.String("out", "", "empty evidence output directory")
		timeout := flags.Duration("timeout", 5*time.Minute, "per-harness timeout")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 ||
			*root == "" || *cargoKani == "" || *kaniCompiler == "" || *cbmc == "" ||
			*rustc == "" || *kaniSourceRoot == "" || *work == "" || *out == "" {
			return 2
		}
		value, err := generate(context.Background(), generateRequest{
			Root: *root, CargoKani: *cargoKani, KaniCompiler: *kaniCompiler,
			CBMC: *cbmc, Rustc: *rustc, KaniSourceRoot: *kaniSourceRoot,
			Work: *work, Out: *out, Timeout: *timeout,
		})
		if err != nil {
			fmt.Fprintf(stderr, "kanidriver: %v\n", err)
			return 1
		}
		return encode(stdout, map[string]any{"status": value.Status, "summary": filepath.Join(*out, "summary.json"), "semantic_projection_sha256": value.Execution.SemanticProjectionSHA256})
	case "verify":
		flags := flag.NewFlagSet("verify", flag.ContinueOnError)
		flags.SetOutput(stderr)
		root := flags.String("root", "", "repository root")
		summary := flags.String("summary", "", "repository-relative summary path")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *root == "" || *summary == "" {
			return 2
		}
		value, err := verify(*root, *summary)
		if err != nil {
			_ = encode(stdout, map[string]string{"status": "ERROR", "error": err.Error()})
			return 1
		}
		return encode(stdout, map[string]any{"status": "PASS", "claim_scope": value.ClaimScope, "harnesses": len(value.Execution.Harnesses), "mutations_killed": len(value.Execution.MutationCanaries), "repeat_count": value.Execution.RepeatCount})
	case "project-coverage":
		flags := flag.NewFlagSet("project-coverage", flag.ContinueOnError)
		flags.SetOutput(stderr)
		root := flags.String("root", "", "clean repository root")
		summary := flags.String("summary", "", "repository-relative Kani summary path")
		out := flags.String("out", "", "new repository-relative coverage path")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *root == "" || *summary == "" || *out == "" || !safeRelativePath(*out) {
			return 2
		}
		absoluteRoot, err := filepath.Abs(*root)
		if err != nil {
			fmt.Fprintf(stderr, "kanidriver: %v\n", err)
			return 1
		}
		if err := requireCleanSubject(absoluteRoot); err != nil {
			fmt.Fprintf(stderr, "kanidriver: %v\n", err)
			return 1
		}
		value, err := buildCoverageProjection(absoluteRoot, *summary)
		if err != nil {
			fmt.Fprintf(stderr, "kanidriver: %v\n", err)
			return 1
		}
		if err := writeCoverageProjection(absoluteRoot, *out, value); err != nil {
			fmt.Fprintf(stderr, "kanidriver: %v\n", err)
			return 1
		}
		return encode(stdout, map[string]any{"status": value.Status, "coverage": *out, "required": value.Counts.Required, "rust_satisfied": value.Counts.RustSatisfied, "mutation_satisfied": value.Counts.MutationSatisfied, "aggregate_satisfied": value.Counts.AggregateSatisfied})
	case "verify-coverage":
		flags := flag.NewFlagSet("verify-coverage", flag.ContinueOnError)
		flags.SetOutput(stderr)
		root := flags.String("root", "", "repository root")
		coverage := flags.String("coverage", "", "repository-relative coverage path")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *root == "" || *coverage == "" {
			return 2
		}
		value, err := verifyCoverage(*root, *coverage)
		if err != nil {
			_ = encode(stdout, map[string]string{"status": "ERROR", "error": err.Error()})
			return 1
		}
		return encode(stdout, map[string]any{"status": value.Status, "claim_scope": value.ClaimScope, "required": value.Counts.Required, "rust_satisfied": value.Counts.RustSatisfied, "mutation_satisfied": value.Counts.MutationSatisfied, "aggregate_satisfied": value.Counts.AggregateSatisfied})
	default:
		usage(stderr)
		return 2
	}
}

func usage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: kanidriver run --root DIR --cargo-kani FILE --kani-compiler FILE --cbmc FILE --rustc FILE --kani-source-root DIR --work DIR --out DIR | kanidriver verify --root DIR --summary PATH | kanidriver project-coverage --root DIR --summary PATH --out PATH | kanidriver verify-coverage --root DIR --coverage PATH")
}

func encode(writer io.Writer, value any) int {
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		return 1
	}
	return 0
}

type generateRequest struct {
	Root, CargoKani, KaniCompiler, CBMC, Rustc, KaniSourceRoot, Work, Out string
	Timeout                                                               time.Duration
}

func generate(ctx context.Context, request generateRequest) (receipt, error) {
	if request.Timeout <= 0 || request.Timeout > 15*time.Minute {
		return receipt{}, errors.New("timeout must be within (0, 15m]")
	}
	root, err := filepath.Abs(request.Root)
	if err != nil {
		return receipt{}, err
	}
	for name, candidate := range map[string]string{"cargo-kani": request.CargoKani, "kani-compiler": request.KaniCompiler, "cbmc": request.CBMC, "rustc": request.Rustc} {
		if err := requireExecutable(candidate); err != nil {
			return receipt{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := requireCleanSubject(root); err != nil {
		return receipt{}, err
	}
	if err := ensureEmptyDirectory(request.Work); err != nil {
		return receipt{}, fmt.Errorf("work directory: %w", err)
	}
	if err := ensureEmptyDirectory(request.Out); err != nil {
		return receipt{}, fmt.Errorf("output directory: %w", err)
	}
	stagedRoot := filepath.Join(request.Work, "subject")
	if err := os.MkdirAll(stagedRoot, 0o755); err != nil {
		return receipt{}, err
	}
	if err := copyTree(filepath.Join(root, "rust"), filepath.Join(stagedRoot, "rust")); err != nil {
		return receipt{}, fmt.Errorf("stage Rust workspace: %w", err)
	}

	commit, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return receipt{}, err
	}
	tree, err := gitOutput(root, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return receipt{}, err
	}
	objectFormat, err := gitOutput(root, "rev-parse", "--show-object-format")
	if err != nil {
		return receipt{}, err
	}
	plans := harnessPlans()
	sources, err := bindSources(root, plans)
	if err != nil {
		return receipt{}, err
	}
	tools, err := bindTools(request)
	if err != nil {
		return receipt{}, err
	}

	value := receipt{
		Schema:        "../../../schemas/kani-production-evidence-1.0.0.schema.json",
		SchemaVersion: "1.0.0", EvidenceKind: evidenceKind,
		Subject:   subjectInfo{Commit: commit, Tree: tree, ObjectFormat: objectFormat, CleanCheckout: true, Sources: sources},
		Toolchain: tools,
		Execution: executionInfo{
			GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, PointerWidth: strconv.IntSize,
			Environment: []string{"LANG=C", "LC_ALL=C", "KANI_OUTPUT_FORMAT=terse", "CARGO_KANI_JOBS=1"},
			Harnesses:   plans, RepeatCount: 2,
			UnsupportedConstructs: []string{"caller_location (reported globally, unreachable from every retained harness)", "foreign function (reported globally, unreachable from every retained harness)"},
		},
		Status: "RUNNING", ClaimScope: claimScope,
		Limitations: exactLimitations(), Assurance: assurance,
	}

	for runIndex := 1; runIndex <= value.Execution.RepeatCount; runIndex++ {
		runID := fmt.Sprintf("run-%d", runIndex)
		current := replayRun{RunID: runID}
		for _, plan := range plans {
			observed, runErr := executeHarness(ctx, request, stagedRoot, request.Out, runID, plan.HarnessID, plan.HarnessID)
			if runErr != nil {
				return receipt{}, fmt.Errorf("%s %s: %w", runID, plan.HarnessID, runErr)
			}
			if observed.Status != "PASS" || observed.ExitCode != 0 || observed.FailedChecks != 0 {
				return receipt{}, fmt.Errorf("%s %s did not pass", runID, plan.HarnessID)
			}
			current.Results = append(current.Results, harnessResult{HarnessID: plan.HarnessID, kaniResult: observed})
		}
		current.SemanticProjectionSHA256, err = semanticProjection(current.Results)
		if err != nil {
			return receipt{}, err
		}
		value.Execution.Runs = append(value.Execution.Runs, current)
	}
	value.Execution.SemanticallyIdentical = value.Execution.Runs[0].SemanticProjectionSHA256 == value.Execution.Runs[1].SemanticProjectionSHA256
	if !value.Execution.SemanticallyIdentical {
		return receipt{}, errors.New("baseline replay projections differ")
	}
	value.Execution.SemanticProjectionSHA256 = value.Execution.Runs[0].SemanticProjectionSHA256

	for _, mutation := range mutationPlans() {
		observed, mutationErr := executeMutation(ctx, request, stagedRoot, request.Out, mutation)
		if mutationErr != nil {
			return receipt{}, fmt.Errorf("mutation %s: %w", mutation.CanaryID, mutationErr)
		}
		value.Execution.MutationCanaries = append(value.Execution.MutationCanaries, observed)
		if observed.Status != "COUNTEREXAMPLE" || observed.ExitCode == 0 || observed.FailedChecks == 0 {
			value.Execution.MutationSurvivors++
		}
	}
	if value.Execution.MutationSurvivors != 0 {
		return receipt{}, fmt.Errorf("%d mutation canaries survived", value.Execution.MutationSurvivors)
	}
	value.Status = "PASS"
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return receipt{}, err
	}
	body = append(body, '\n')
	if bytes.Contains(body, []byte("/Users/")) || bytes.Contains(body, []byte("/private/tmp/")) {
		return receipt{}, errors.New("portable summary contains a host-local absolute path")
	}
	if err := validateSchema(root, body); err != nil {
		return receipt{}, fmt.Errorf("generated summary schema validation: %w", err)
	}
	if err := validateReceipt(root, request.Out, value); err != nil {
		return receipt{}, fmt.Errorf("generated receipt validation: %w", err)
	}
	if err := os.WriteFile(filepath.Join(request.Out, "summary.json"), body, 0o644); err != nil {
		return receipt{}, err
	}
	return value, nil
}

func harnessPlans() []harnessPlan {
	const decode = "websocket_core::frame::decode::FrameHeaderDecoder::decode_header"
	const mask = "websocket_core::frame::mask::apply_mask_in_place"
	const closeCode = "websocket_core::close::validate_code"
	const utf8 = "websocket_core::utf8::Utf8Validator::feed+finish"
	return []harnessPlan{
		{HarnessID: "frame::decode::proofs::prove_header_safety", TargetSymbol: decode, SourcePath: "rust/connection-core/src/frame/decode.rs", ObligationIDs: []string{"obligation.checked-header-arithmetic"}, Unwind: 12, SymbolicDomain: []string{"all 14-byte prefixes", "all prefix lengths 0..14", "both endpoint roles", "all usize retained-byte counts"}},
		{HarnessID: "frame::decode::proofs::prove_control_fin_and_length", TargetSymbol: decode, SourcePath: "rust/connection-core/src/frame/decode.rs", ObligationIDs: []string{"obligation.control-fin-and-length"}, Unwind: 12, SymbolicDomain: []string{"all defined control opcodes", "both FIN states", "all 7-bit length codes"}},
		{HarnessID: "frame::decode::proofs::prove_length_canonical_16", TargetSymbol: decode, SourcePath: "rust/connection-core/src/frame/decode.rs", ObligationIDs: []string{"obligation.length-canonical-16"}, Unwind: 12, SymbolicDomain: []string{"all u16 encoded lengths"}},
		{HarnessID: "frame::decode::proofs::prove_length_canonical_64_and_high_bit", TargetSymbol: decode, SourcePath: "rust/connection-core/src/frame/decode.rs", ObligationIDs: []string{"obligation.length-canonical-64-high-bit-zero"}, Unwind: 12, SymbolicDomain: []string{"all u64 encoded lengths"}},
		{HarnessID: "frame::decode::proofs::prove_length_canonical_7", TargetSymbol: decode, SourcePath: "rust/connection-core/src/frame/decode.rs", ObligationIDs: []string{"obligation.length-canonical-7"}, Unwind: 12, SymbolicDomain: []string{"all payload lengths 0..125"}},
		{HarnessID: "frame::decode::proofs::prove_preallocation_cap", TargetSymbol: decode, SourcePath: "rust/connection-core/src/frame/decode.rs", ObligationIDs: []string{"obligation.preallocation-cap"}, Unwind: 12, SymbolicDomain: []string{"all u16 payload lengths", "all u16 retained-byte counts", "frame cap 256", "total cap 512"}},
		{HarnessID: "frame::decode::proofs::prove_role_masking", TargetSymbol: decode, SourcePath: "rust/connection-core/src/frame/decode.rs", ObligationIDs: []string{"obligation.role-masking"}, Unwind: 12, SymbolicDomain: []string{"both endpoint roles", "both wire mask states"}},
		{HarnessID: "frame::mask::proofs::prove_mask_equation", TargetSymbol: mask, SourcePath: "rust/connection-core/src/frame/mask.rs", ObligationIDs: []string{"obligation.mask-equation"}, Unwind: 5, SymbolicDomain: []string{"all four-byte payloads", "all four-byte keys", "all usize offsets"}},
		{HarnessID: "frame::mask::proofs::prove_mask_involution", TargetSymbol: mask, SourcePath: "rust/connection-core/src/frame/mask.rs", ObligationIDs: []string{"obligation.mask-involution"}, Unwind: 9, SymbolicDomain: []string{"all four-byte payloads", "all four-byte keys", "all usize offsets"}},
		{HarnessID: "close::proofs::prove_close_code_classification", TargetSymbol: closeCode, SourcePath: "rust/connection-core/src/close.rs", ObligationIDs: []string{"surface.close.status-code"}, Unwind: 2, SymbolicDomain: []string{"all u16 close codes", "both sender roles"}},
		{HarnessID: "utf8::proofs::prove_strict_utf8_exact_len_le_4", TargetSymbol: utf8, SourcePath: "rust/connection-core/src/utf8.rs", ObligationIDs: []string{"surface.messages.text-utf8"}, Unwind: 6, SymbolicDomain: []string{"all byte sequences of exact lengths 0..4"}},
	}
}

func mutationPlans() []mutationPlan {
	const decode = "rust/connection-core/src/frame/decode.rs"
	const mask = "rust/connection-core/src/frame/mask.rs"
	const closeCode = "rust/connection-core/src/close.rs"
	const utf8 = "rust/connection-core/src/utf8.rs"
	return []mutationPlan{
		{CanaryID: "canary.bad-header-overflow", HarnessID: "frame::decode::proofs::prove_header_safety", SourcePath: decode, Find: "let retained_total = retained_payload_bytes\n                .checked_add(payload_length)\n                .ok_or(FailureKind::Frame(FrameFailure::ArithmeticOverflow))?;", Replace: "let retained_total = retained_payload_bytes + payload_length;", Description: "replace checked retained-byte addition with overflowing addition", Obligations: []string{"obligation.checked-header-arithmetic"}},
		{CanaryID: "canary.bad-control-fragmented", HarnessID: "frame::decode::proofs::prove_control_fin_and_length", SourcePath: decode, Find: "if opcode.is_control() && !fin {", Replace: "if opcode.is_control() && fin {", Description: "invert the control-frame FIN rejection", Obligations: []string{"obligation.control-fin-and-length"}},
		{CanaryID: "canary.bad-control-oversized", HarnessID: "frame::decode::proofs::prove_control_fin_and_length", SourcePath: decode, Find: "if opcode.is_control() && length_code > 125 {", Replace: "if opcode.is_control() && length_code > 126 {", Description: "admit control length code 126 past the early bound", Obligations: []string{"obligation.control-fin-and-length"}},
		{CanaryID: "canary.bad-length-noncanonical-16", HarnessID: "frame::decode::proofs::prove_length_canonical_16", SourcePath: decode, Find: "if length_code == 126 && payload_length_u64 < 126 {", Replace: "if length_code == 126 && payload_length_u64 < 125 {", Description: "admit noncanonical 16-bit length 125", Obligations: []string{"obligation.length-canonical-16"}},
		{CanaryID: "canary.bad-length-high-bit-64", HarnessID: "frame::decode::proofs::prove_length_canonical_64_and_high_bit", SourcePath: decode, Find: "if bytes[0] & 0x80 != 0 {", Replace: "if bytes[0] & 0x80 == 0 {", Description: "invert the 64-bit payload high-bit rejection", Obligations: []string{"obligation.length-canonical-64-high-bit-zero"}},
		{CanaryID: "canary.bad-length-noncanonical-64", HarnessID: "frame::decode::proofs::prove_length_canonical_64_and_high_bit", SourcePath: decode, Find: "if length_code == 127 && payload_length_u64 <= u64::from(u16::MAX) {", Replace: "if length_code == 127 && payload_length_u64 < u64::from(u16::MAX) {", Description: "admit noncanonical 64-bit length 65535", Obligations: []string{"obligation.length-canonical-64-high-bit-zero"}},
		{CanaryID: "canary.bad-length-inline-7", HarnessID: "frame::decode::proofs::prove_length_canonical_7", SourcePath: decode, Find: "value => u64::from(value),", Replace: "value => u64::from(value).wrapping_add(1),", Description: "increment every inline 7-bit payload length", Obligations: []string{"obligation.length-canonical-7"}},
		{CanaryID: "canary.bad-allocation-before-cap", HarnessID: "frame::decode::proofs::prove_preallocation_cap", SourcePath: decode, Find: "if payload_length > config.frame_bytes() {", Replace: "if payload_length >= config.frame_bytes() {", Description: "reject the exact admitted frame-cap boundary", Obligations: []string{"obligation.preallocation-cap"}},
		{CanaryID: "canary.bad-role-masking", HarnessID: "frame::decode::proofs::prove_role_masking", SourcePath: decode, Find: "if masked != expected_masked {", Replace: "if masked == expected_masked {", Description: "invert inbound role-mask validation", Obligations: []string{"obligation.role-masking"}},
		{CanaryID: "canary.bad-mask-key-index", HarnessID: "frame::mask::proofs::prove_mask_equation", SourcePath: mask, Find: "key[payload_offset.wrapping_add(index) % key.len()]", Replace: "key[payload_offset.wrapping_add(index).wrapping_add(1) % key.len()]", Description: "shift the RFC mask-key index by one", Obligations: []string{"obligation.mask-equation"}},
		{CanaryID: "canary.bad-mask-non-involutive", HarnessID: "frame::mask::proofs::prove_mask_involution", SourcePath: mask, Find: "*byte ^= key[payload_offset.wrapping_add(index) % key.len()];", Replace: "*byte = (*byte).wrapping_add(key[payload_offset.wrapping_add(index) % key.len()]);", Description: "replace mask XOR with non-involutive wrapping addition", Obligations: []string{"obligation.mask-involution"}},
		{CanaryID: "canary.bad-close-code-sender-role", HarnessID: "close::proofs::prove_close_code_classification", SourcePath: closeCode, Find: "1010 if sender == Role::Server => Some(CloseCodeRejection::WrongSenderRole),", Replace: "1010 if sender == Role::Client => Some(CloseCodeRejection::WrongSenderRole),", Description: "invert which sender role may transmit close code 1010", Obligations: []string{"surface.close.status-code"}},
		{CanaryID: "canary.bad-utf8-surrogate", HarnessID: "utf8::proofs::prove_strict_utf8_exact_len_le_4", SourcePath: utf8, Find: "0xed => self.expect(2, 0x80, 0x9f, FirstContinuationRule::NoSurrogate),", Replace: "0xed => self.expect(2, 0x80, 0xbf, FirstContinuationRule::NoSurrogate),", Description: "admit UTF-8 encodings of surrogate code points", Obligations: []string{"surface.messages.text-utf8"}},
	}
}

func legacyMutationPlans() []mutationPlan {
	result := make([]mutationPlan, 0, 11)
	for _, plan := range mutationPlans() {
		if plan.CanaryID == "canary.bad-length-inline-7" || plan.CanaryID == "canary.bad-mask-non-involutive" {
			continue
		}
		result = append(result, plan)
	}
	return result
}

func mutationPlansForReceipt(results []mutationResult) ([]mutationPlan, bool) {
	for _, plans := range [][]mutationPlan{mutationPlans(), legacyMutationPlans()} {
		if len(results) == len(plans) {
			return plans, true
		}
	}
	return nil, false
}

func executeHarness(ctx context.Context, request generateRequest, stagedRoot, outRoot, group, harnessID, logID string) (kaniResult, error) {
	arguments := []string{"--manifest-path", filepath.Join(stagedRoot, "rust", "Cargo.toml"), "--package", "websocket-core", "--harness", harnessID, "--output-format", "terse"}
	processCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	command := exec.CommandContext(processCtx, request.CargoKani, arguments...)
	command.Dir = stagedRoot
	command.Env = controlledEnvironment(request)
	output, runErr := command.CombinedOutput()
	if processCtx.Err() != nil {
		return kaniResult{}, processCtx.Err()
	}
	exitCode := 0
	if runErr != nil {
		var exitError *exec.ExitError
		if !errors.As(runErr, &exitError) {
			return kaniResult{}, runErr
		}
		exitCode = exitError.ExitCode()
	}
	normalized := normalizeLog(output, filepath.Dir(stagedRoot))
	directory := filepath.Join(outRoot, group)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return kaniResult{}, err
	}
	name := safeHarnessName(logID) + ".out"
	if err := os.WriteFile(filepath.Join(directory, name), []byte(normalized), 0o644); err != nil {
		return kaniResult{}, err
	}
	logBinding := artifact{Path: filepath.ToSlash(filepath.Join(group, name)), SHA256: digestBytes([]byte(normalized))}
	observed, err := parseKaniResult(output, exitCode)
	if err != nil {
		return kaniResult{}, fmt.Errorf("%w; normalized diagnostic retained at %s", err, logBinding.Path)
	}
	observed.RawOutputSHA256 = digestBytes(output)
	observed.NormalizedLog = logBinding
	return observed, nil
}

func executeMutation(ctx context.Context, request generateRequest, stagedRoot, outRoot string, plan mutationPlan) (mutationResult, error) {
	path := filepath.Join(stagedRoot, filepath.FromSlash(plan.SourcePath))
	baseline, err := os.ReadFile(path)
	if err != nil {
		return mutationResult{}, err
	}
	mutated, err := applyExactMutation(baseline, plan.Find, plan.Replace)
	if err != nil {
		return mutationResult{}, err
	}
	if err := os.WriteFile(path, mutated, 0o644); err != nil {
		return mutationResult{}, err
	}
	defer func() { _ = os.WriteFile(path, baseline, 0o644) }()
	observed, err := executeHarness(ctx, request, stagedRoot, outRoot, "mutations", plan.HarnessID, plan.CanaryID)
	if err != nil {
		return mutationResult{}, err
	}
	return mutationResult{
		CanaryID: plan.CanaryID, HarnessID: plan.HarnessID, SourcePath: plan.SourcePath,
		Mutation: plan.Description, BaselineSourceSHA256: digestBytes(baseline),
		MutatedSourceSHA256: digestBytes(mutated), ObligationIDs: plan.Obligations,
		kaniResult: observed,
	}, nil
}

func parseKaniResult(output []byte, exitCode int) (kaniResult, error) {
	matches := resultPattern.FindAllSubmatch(output, -1)
	if len(matches) != 1 {
		return kaniResult{}, fmt.Errorf("expected exactly one Kani result summary, found %d", len(matches))
	}
	failed, _ := strconv.Atoi(string(matches[0][1]))
	total, _ := strconv.Atoi(string(matches[0][2]))
	unreachable := 0
	if len(matches[0][4]) != 0 {
		unreachable, _ = strconv.Atoi(string(matches[0][4]))
	}
	success := bytes.Count(output, []byte("VERIFICATION:- SUCCESSFUL"))
	failure := bytes.Count(output, []byte("VERIFICATION:- FAILED"))
	observed := kaniResult{ExitCode: exitCode, FailedChecks: failed, TotalChecks: total, UnreachableChecks: unreachable}
	switch {
	case success == 1 && failure == 0 && exitCode == 0 && failed == 0 && total > 0:
		observed.Status = "PASS"
	case success == 0 && failure == 1 && exitCode != 0 && failed > 0 && total > 0:
		observed.Status = "COUNTEREXAMPLE"
	default:
		return kaniResult{}, fmt.Errorf("inconsistent Kani verdict exit=%d failed=%d total=%d success_markers=%d failure_markers=%d", exitCode, failed, total, success, failure)
	}
	return observed, nil
}

func normalizeLog(output []byte, volatileRoot string) string {
	value := strings.ReplaceAll(string(output), "\r\n", "\n")
	value = strings.ReplaceAll(value, filepath.ToSlash(volatileRoot), "<staged-workspace>")
	value = strings.ReplaceAll(value, volatileRoot, "<staged-workspace>")
	value = timePattern.ReplaceAllString(value, "Verification Time: <elapsed>")
	value = finishPattern.ReplaceAllString(value, "$1 <elapsed>")
	return value
}

func applyExactMutation(source []byte, find, replace string) ([]byte, error) {
	if count := bytes.Count(source, []byte(find)); count != 1 {
		return nil, fmt.Errorf("mutation anchor occurs %d times, want exactly 1", count)
	}
	return bytes.Replace(source, []byte(find), []byte(replace), 1), nil
}

func controlledEnvironment(request generateRequest) []string {
	pathParts := []string{filepath.Dir(request.CargoKani), filepath.Dir(request.CBMC), "/opt/homebrew/bin", os.Getenv("PATH"), "/usr/bin", "/bin"}
	environment := []string{
		"LANG=C",
		"LC_ALL=C",
		"KANI_OUTPUT_FORMAT=terse",
		"CARGO_KANI_JOBS=1",
		"PATH=" + strings.Join(pathParts, string(os.PathListSeparator)),
	}
	for _, name := range []string{"HOME", "CARGO_HOME", "RUSTUP_HOME"} {
		if value, ok := os.LookupEnv(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

func bindTools(request generateRequest) (toolInfo, error) {
	kaniSourceRoot, err := filepath.Abs(request.KaniSourceRoot)
	if err != nil {
		return toolInfo{}, err
	}
	for _, candidate := range []string{request.CargoKani, request.KaniCompiler} {
		inside, insideErr := pathWithin(kaniSourceRoot, candidate)
		if insideErr != nil || !inside {
			return toolInfo{}, errors.New("Kani scripts and compiler must resolve inside the pinned Kani source checkout")
		}
	}
	kaniCommit, err := gitOutput(kaniSourceRoot, "rev-parse", "HEAD")
	if err != nil {
		return toolInfo{}, err
	}
	kaniTree, err := gitOutput(kaniSourceRoot, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return toolInfo{}, err
	}
	trackedStatus, err := gitOutput(kaniSourceRoot, "status", "--porcelain", "--untracked-files=no")
	if err != nil || trackedStatus != "" {
		return toolInfo{}, errors.New("pinned Kani source checkout has tracked modifications")
	}
	driver, err := os.Executable()
	if err != nil {
		return toolInfo{}, err
	}
	kaniVersion, err := commandVersion(request.CargoKani, "--version")
	if err != nil {
		return toolInfo{}, err
	}
	cbmcVersion, err := commandVersion(request.CBMC, "--version")
	if err != nil {
		return toolInfo{}, err
	}
	rustcVersion, err := commandVersion(request.Rustc, "--version", "--verbose")
	if err != nil {
		return toolInfo{}, err
	}
	values := []string{request.CargoKani, request.KaniCompiler, request.CBMC, request.Rustc, driver}
	digests := make([]string, len(values))
	for index, candidate := range values {
		digests[index], err = digestFile(candidate)
		if err != nil {
			return toolInfo{}, err
		}
	}
	return toolInfo{
		KaniVersion: kaniVersion, KaniSourceCommit: kaniCommit, KaniSourceTree: kaniTree,
		CargoKaniSHA256: digests[0], KaniCompilerSHA256: digests[1],
		CBMCVersion: cbmcVersion, CBMCSHA256: digests[2],
		RustcVersion: rustcVersion, RustcSHA256: digests[3], DriverSHA256: digests[4],
	}, nil
}

func bindSources(root string, plans []harnessPlan) ([]sourceBinding, error) {
	seen := map[string]bool{}
	var result []sourceBinding
	for _, plan := range plans {
		if seen[plan.SourcePath] {
			continue
		}
		seen[plan.SourcePath] = true
		digest, err := digestFile(filepath.Join(root, filepath.FromSlash(plan.SourcePath)))
		if err != nil {
			return nil, err
		}
		result = append(result, sourceBinding{Path: plan.SourcePath, SHA256: digest})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func semanticProjection(results []harnessResult) (string, error) {
	type projected struct {
		HarnessID         string `json:"harness_id"`
		Status            string `json:"status"`
		FailedChecks      int    `json:"failed_checks"`
		TotalChecks       int    `json:"total_checks"`
		UnreachableChecks int    `json:"unreachable_checks"`
	}
	values := make([]projected, 0, len(results))
	for _, result := range results {
		values = append(values, projected{result.HarnessID, result.Status, result.FailedChecks, result.TotalChecks, result.UnreachableChecks})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].HarnessID < values[j].HarnessID })
	body, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return digestBytes(body), nil
}

func verify(rootPath, relativeSummary string) (receipt, error) {
	if !safeRelativePath(relativeSummary) {
		return receipt{}, errors.New("summary must be a safe repository-relative path")
	}
	root, err := filepath.Abs(rootPath)
	if err != nil {
		return receipt{}, err
	}
	summaryPath := filepath.Join(root, filepath.FromSlash(relativeSummary))
	body, err := readBoundedRegular(summaryPath)
	if err != nil {
		return receipt{}, err
	}
	if bytes.Contains(body, []byte("/Users/")) || bytes.Contains(body, []byte("/private/tmp/")) {
		return receipt{}, errors.New("summary contains a host-local absolute path")
	}
	var value receipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return receipt{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return receipt{}, errors.New("summary contains trailing JSON")
	}
	if err := validateSchema(root, body); err != nil {
		return receipt{}, fmt.Errorf("schema validation: %w", err)
	}
	if err := validateReceipt(root, filepath.Dir(summaryPath), value); err != nil {
		return receipt{}, err
	}
	return value, nil
}

func validateReceipt(root, summaryDirectory string, value receipt) error {
	if value.Schema != "../../../schemas/kani-production-evidence-1.0.0.schema.json" || value.SchemaVersion != "1.0.0" || value.EvidenceKind != evidenceKind {
		return errors.New("receipt identity is not canonical")
	}
	if value.Status != "PASS" || value.ClaimScope != claimScope || value.Assurance != assurance ||
		value.IndependentReviewClaimed || value.Production || value.Signing || value.Publication ||
		!equalStrings(value.Limitations, exactLimitations()) {
		return errors.New("receipt posture is inflated or incomplete")
	}
	if !hexCommit.MatchString(value.Subject.Commit) || !hexCommit.MatchString(value.Subject.Tree) || value.Subject.ObjectFormat != "sha1" || !value.Subject.CleanCheckout {
		return errors.New("subject identity is invalid")
	}
	observedTree, err := gitOutput(root, "rev-parse", value.Subject.Commit+"^{tree}")
	if err != nil || observedTree != value.Subject.Tree {
		return errors.New("subject commit/tree binding is unavailable or inconsistent")
	}
	if len(value.Subject.Sources) != 4 {
		return errors.New("exactly four production source bindings are required")
	}
	expectedSources := map[string]bool{
		"rust/connection-core/src/close.rs":        false,
		"rust/connection-core/src/frame/decode.rs": false,
		"rust/connection-core/src/frame/mask.rs":   false,
		"rust/connection-core/src/utf8.rs":         false,
	}
	sourceBodies := make(map[string][]byte, len(expectedSources))
	sourceDigests := make(map[string]string, len(expectedSources))
	for _, source := range value.Subject.Sources {
		if !safeRelativePath(source.Path) || !hexDigest.MatchString(source.SHA256) {
			return errors.New("source binding is invalid")
		}
		if _, ok := expectedSources[source.Path]; !ok || expectedSources[source.Path] {
			return fmt.Errorf("source binding path is unexpected or duplicated: %s", source.Path)
		}
		body, showErr := gitBytes(root, "show", value.Subject.Commit+":"+source.Path)
		if showErr != nil || digestBytes(body) != source.SHA256 {
			return fmt.Errorf("source binding failed for %s", source.Path)
		}
		expectedSources[source.Path] = true
		sourceBodies[source.Path] = body
		sourceDigests[source.Path] = source.SHA256
	}
	for _, digest := range []string{value.Toolchain.CargoKaniSHA256, value.Toolchain.KaniCompilerSHA256, value.Toolchain.CBMCSHA256, value.Toolchain.RustcSHA256, value.Toolchain.DriverSHA256} {
		if !hexDigest.MatchString(digest) {
			return errors.New("toolchain digest is invalid")
		}
	}
	if value.Toolchain.KaniVersion == "" || !hexCommit.MatchString(value.Toolchain.KaniSourceCommit) || !hexCommit.MatchString(value.Toolchain.KaniSourceTree) ||
		!strings.Contains(value.Toolchain.CBMCVersion, "6.11.0") || value.Toolchain.RustcVersion == "" {
		return errors.New("toolchain identity is incomplete")
	}
	expectedPlans := harnessPlans()
	expectedMutations, mutationsOK := mutationPlansForReceipt(value.Execution.MutationCanaries)
	if !equalHarnessPlans(value.Execution.Harnesses, expectedPlans) || value.Execution.RepeatCount != 2 ||
		len(value.Execution.Runs) != 2 || !value.Execution.SemanticallyIdentical ||
		!hexDigest.MatchString(value.Execution.SemanticProjectionSHA256) || value.Execution.MutationSurvivors != 0 ||
		!mutationsOK {
		return errors.New("execution denominator or replay posture is invalid")
	}
	for runIndex, run := range value.Execution.Runs {
		if run.RunID != fmt.Sprintf("run-%d", runIndex+1) {
			return errors.New("baseline run identifiers are not canonical")
		}
		if len(run.Results) != len(expectedPlans) {
			return errors.New("baseline run has the wrong harness count")
		}
		projection, projectionErr := semanticProjection(run.Results)
		if projectionErr != nil || projection != run.SemanticProjectionSHA256 || projection != value.Execution.SemanticProjectionSHA256 {
			return errors.New("baseline semantic replay does not reconcile")
		}
		for resultIndex, result := range run.Results {
			if result.HarnessID != expectedPlans[resultIndex].HarnessID || !hexDigest.MatchString(result.RawOutputSHA256) {
				return errors.New("baseline harness identity or raw digest is invalid")
			}
			if result.Status != "PASS" || result.ExitCode != 0 || result.FailedChecks != 0 || result.TotalChecks <= 0 {
				return fmt.Errorf("baseline harness %s did not pass", result.HarnessID)
			}
			if err := verifyLog(summaryDirectory, result.NormalizedLog); err != nil {
				return err
			}
		}
	}
	for index, result := range value.Execution.MutationCanaries {
		expected := expectedMutations[index]
		if result.CanaryID != expected.CanaryID || result.HarnessID != expected.HarnessID || result.SourcePath != expected.SourcePath ||
			result.Mutation != expected.Description || !equalStrings(result.ObligationIDs, expected.Obligations) ||
			result.Status != "COUNTEREXAMPLE" || result.ExitCode == 0 || result.FailedChecks <= 0 || result.TotalChecks <= 0 || !hexDigest.MatchString(result.RawOutputSHA256) ||
			!hexDigest.MatchString(result.BaselineSourceSHA256) || !hexDigest.MatchString(result.MutatedSourceSHA256) ||
			result.BaselineSourceSHA256 == result.MutatedSourceSHA256 {
			return fmt.Errorf("mutation result %d is invalid", index)
		}
		if result.BaselineSourceSHA256 != sourceDigests[result.SourcePath] {
			return fmt.Errorf("mutation %s baseline is not the bound production source", result.CanaryID)
		}
		mutated, mutationErr := applyExactMutation(sourceBodies[result.SourcePath], expected.Find, expected.Replace)
		if mutationErr != nil || digestBytes(mutated) != result.MutatedSourceSHA256 {
			return fmt.Errorf("mutation %s source transformation does not reconcile", result.CanaryID)
		}
		if err := verifyLog(summaryDirectory, result.NormalizedLog); err != nil {
			return err
		}
	}
	return nil
}

func validateSchema(root string, document []byte) error {
	schemaBody, err := readBoundedRegular(filepath.Join(root, "schemas", "kani-production-evidence-1.0.0.schema.json"))
	if err != nil {
		return err
	}
	schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBody))
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource("mem:///kani-production-evidence.json", schemaValue); err != nil {
		return err
	}
	schema, err := compiler.Compile("mem:///kani-production-evidence.json")
	if err != nil {
		return err
	}
	documentValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(document))
	if err != nil {
		return err
	}
	return schema.Validate(documentValue)
}

func verifyLog(summaryDirectory string, binding artifact) error {
	if !safeRelativePath(binding.Path) || !hexDigest.MatchString(binding.SHA256) {
		return errors.New("normalized log binding is invalid")
	}
	body, err := readBoundedRegular(filepath.Join(summaryDirectory, filepath.FromSlash(binding.Path)))
	if err != nil || digestBytes(body) != binding.SHA256 {
		return fmt.Errorf("normalized log binding failed for %s", binding.Path)
	}
	if bytes.Contains(body, []byte("/Users/")) || bytes.Contains(body, []byte("/private/tmp/")) {
		return fmt.Errorf("normalized log %s contains a host-local path", binding.Path)
	}
	return nil
}

func exactLimitations() []string {
	return []string{
		"The proofs cover the exact retained symbolic domains and unwind bounds, not every WebSocket behavior.",
		"The Kani execution is owner-attested on one darwin/arm64 host and is not independent-host evidence.",
		"Normalized logs retain semantic results and raw-output digests but intentionally omit host paths and elapsed times.",
		"No sbx isolation, production deployment, signing, publication, or cutover is claimed.",
		"The reported unsupported constructs were unreachable from every retained harness; reachable unsupported constructs would fail verification.",
	}
}

func requireCleanSubject(root string) error {
	output, err := gitBytes(root, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" || line == "?? .file-locks.json" {
			continue
		}
		return fmt.Errorf("subject is not clean: %s", line)
	}
	return nil
}

func ensureEmptyDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(path, 0o755)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a real directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("directory is not empty")
	}
	return nil
}

func copyTree(source, destination string) error {
	var totalBytes int64
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if entry.IsDir() && entry.Name() == "target" {
			return filepath.SkipDir
		}
		target := filepath.Join(destination, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink rejected while staging: %s", path)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular file rejected while staging: %s", path)
		}
		if info.Size() > 64<<20 {
			return fmt.Errorf("staged source file exceeds 64 MiB: %s", path)
		}
		totalBytes += info.Size()
		if totalBytes > 512<<20 {
			return errors.New("staged Rust workspace exceeds 512 MiB")
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, info.Mode().Perm())
	})
}

func safeHarnessName(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}

func safeRelativePath(value string) bool {
	if value == "" || filepath.IsAbs(value) || filepath.Clean(value) != filepath.FromSlash(value) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func requireExecutable(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("executable path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("path is not a regular executable")
	}
	return nil
}

func pathWithin(root, candidate string) (bool, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false, err
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return false, err
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedCandidate)
	if err != nil {
		return false, err
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)), nil
}

func commandVersion(path string, arguments ...string) (string, error) {
	command := exec.Command(path, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s version: %w: %s", filepath.Base(path), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func gitOutput(root string, arguments ...string) (string, error) {
	body, err := gitBytes(root, arguments...)
	return strings.TrimSpace(string(body)), err
}

func gitBytes(root string, arguments ...string) ([]byte, error) {
	all := append([]string{"-C", root}, arguments...)
	command := exec.Command("git", all...)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(arguments, " "), err)
	}
	return output, nil
}

func digestFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("path is not a regular file")
	}
	if info.Size() > 1<<30 {
		return "", errors.New("file exceeds one-gibibyte digest bound")
	}
	handle, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = handle.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, handle); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func readBoundedRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("path is not a regular file")
	}
	if info.Size() > maxFileSize {
		return nil, errors.New("file exceeds bounded intake")
	}
	return os.ReadFile(path)
}

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
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

func equalHarnessPlans(left, right []harnessPlan) bool {
	leftBody, leftErr := json.Marshal(left)
	rightBody, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBody, rightBody)
}
