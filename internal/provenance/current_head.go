// Package provenance validates commit-bound qualification receipts without
// rewriting historical evidence to match a later checkout.
package provenance

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	qualificationSchema    = "../schemas/us020-current-head-qualification-1.0.0.schema.json"
	qualificationEvidence  = "evidence.us-020-current-head-qualification"
	qualificationStatus    = "PASS_OWNER_ATTESTED_CURRENT_HEAD_NONNETWORK"
	qualificationAssurance = "OWNER_ATTESTED_NOT_INDEPENDENT"
	qualificationScope     = "CURRENT_SOURCE_TEST_QUALIFICATION_ONLY"
	maximumBlobBytes       = 8 * 1024 * 1024

	// CurrentHeadQualificationPath is the sole current-source qualification
	// receipt. Historical story receipts remain immutable records of their own
	// execution eras.
	CurrentHeadQualificationPath = "evidence/us020-current-head-qualification.json"
)

var (
	hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64 = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// QualificationSummary is the validated identity needed by US-020.
type QualificationSummary struct {
	QualifiedCommit string
	BindingCount    int
}

type qualificationReceipt struct {
	Schema           string                 `json:"$schema"`
	SchemaVersion    string                 `json:"schema_version"`
	EvidenceID       string                 `json:"evidence_id"`
	StoryID          string                 `json:"story_id"`
	Status           string                 `json:"status"`
	Assurance        string                 `json:"assurance"`
	HeadAtExecution  string                 `json:"head_at_execution"`
	SourceTree       string                 `json:"source_tree"`
	ValidationTime   string                 `json:"validation_time"`
	Toolchain        qualificationToolchain `json:"toolchain"`
	Bindings         []qualificationBinding `json:"bindings"`
	Commands         []qualificationCommand `json:"commands"`
	PredecessorScope []string               `json:"predecessor_scope"`
	ClaimScope       string                 `json:"claim_scope"`
	Network          bool                   `json:"network"`
	LiveJava         bool                   `json:"live_java"`
	Docker           bool                   `json:"docker"`
	Autobahn         bool                   `json:"autobahn"`
	Nonclaims        []string               `json:"nonclaims"`
}

type qualificationToolchain struct {
	Rustc string `json:"rustc"`
	Host  string `json:"host"`
}

type qualificationBinding struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	GitBlob string `json:"git_blob"`
}

type qualificationCommand struct {
	Argv             []string `json:"argv"`
	WorkingDirectory string   `json:"working_directory"`
	ExitCode         int      `json:"exit_code"`
	Result           string   `json:"result"`
}

// HistoricalBinding is an immutable path/blob/content identity at a declared
// Git commit. It deliberately contains no working-tree identity.
type HistoricalBinding struct {
	Path    string
	SHA256  string
	GitBlob string
}

// ValidateCurrentHeadQualification validates one current-head-at-execution
// receipt against immutable Git objects in repositoryRoot.
func ValidateCurrentHeadQualification(repositoryRoot string, document []byte) (QualificationSummary, error) {
	receipt, summary, err := validateCurrentHeadQualification(repositoryRoot, document)
	_ = receipt
	return summary, err
}

// LoadAndValidateCurrentHeadQualification reads the fixed receipt, validates
// its immutable execution commit, and then proves that every closed binding is
// still identical at the repository's current committed HEAD. The receipt may
// be committed after the qualified commit; it cannot bind itself.
func LoadAndValidateCurrentHeadQualification(repositoryRoot string) (QualificationSummary, error) {
	document, err := readQualificationFile(repositoryRoot, CurrentHeadQualificationPath)
	if err != nil {
		return QualificationSummary{}, fmt.Errorf("QUALIFICATION_MISSING: %w", err)
	}
	receipt, summary, err := validateCurrentHeadQualification(repositoryRoot, document)
	if err != nil {
		return QualificationSummary{}, err
	}
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return QualificationSummary{}, fmt.Errorf("QUALIFICATION_ROOT_INVALID: %w", err)
	}
	head, err := gitOutput(root, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return QualificationSummary{}, fmt.Errorf("QUALIFICATION_CURRENT_HEAD_MISSING")
	}
	for _, binding := range receipt.Bindings {
		object, objectErr := gitOutput(root, "rev-parse", "--verify", head+":"+binding.Path)
		if objectErr != nil || object != binding.GitBlob {
			return QualificationSummary{}, fmt.Errorf("CURRENT_BINDING_STALE: %s", binding.Path)
		}
	}
	return summary, nil
}

func validateCurrentHeadQualification(repositoryRoot string, document []byte) (qualificationReceipt, QualificationSummary, error) {
	var receipt qualificationReceipt
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFICATION_DECODE_FAILED: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFICATION_TRAILING_DATA")
	}
	if receipt.Schema != qualificationSchema || receipt.SchemaVersion != "1.0.0" ||
		receipt.EvidenceID != qualificationEvidence || receipt.StoryID != "US-020" ||
		receipt.Status != qualificationStatus || receipt.Assurance != qualificationAssurance ||
		receipt.ClaimScope != qualificationScope {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFICATION_IDENTITY_MISMATCH")
	}
	if !hex40.MatchString(receipt.HeadAtExecution) || !hex40.MatchString(receipt.SourceTree) {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFICATION_GIT_IDENTITY_INVALID")
	}
	if _, err := time.Parse(time.RFC3339, receipt.ValidationTime); err != nil {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFICATION_TIME_INVALID: %w", err)
	}
	if receipt.Toolchain.Rustc == "" || receipt.Toolchain.Host != "aarch64-apple-darwin" {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFICATION_TOOLCHAIN_INVALID")
	}
	if receipt.Network || receipt.LiveJava || receipt.Docker || receipt.Autobahn {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFICATION_SCOPE_INFLATED")
	}
	if !reflect.DeepEqual(receipt.PredecessorScope, expectedPredecessorScope()) ||
		!reflect.DeepEqual(receipt.Nonclaims, expectedNonclaims()) ||
		!reflect.DeepEqual(receipt.Commands, expectedCommands()) {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFICATION_CLAIMS_NOT_CLOSED")
	}

	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFICATION_ROOT_INVALID: %w", err)
	}
	commit, err := gitOutput(root, "rev-parse", "--verify", receipt.HeadAtExecution+"^{commit}")
	if err != nil || commit != receipt.HeadAtExecution {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFIED_COMMIT_MISSING")
	}
	tree, err := gitOutput(root, "rev-parse", "--verify", receipt.HeadAtExecution+"^{tree}")
	if err != nil || tree != receipt.SourceTree {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFIED_TREE_MISMATCH")
	}
	expectedPaths := expectedQualificationPaths()
	if len(receipt.Bindings) != len(expectedPaths) {
		return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFICATION_BINDING_COUNT_INVALID")
	}
	previous := ""
	for index, binding := range receipt.Bindings {
		if !validQualificationPath(binding.Path) || binding.Path <= previous ||
			binding.Path != expectedPaths[index] || !hex40.MatchString(binding.GitBlob) || !hex64.MatchString(binding.SHA256) {
			return qualificationReceipt{}, QualificationSummary{}, fmt.Errorf("QUALIFICATION_BINDING_INVALID: %s", binding.Path)
		}
		previous = binding.Path
	}
	historical := make([]HistoricalBinding, len(receipt.Bindings))
	for index, binding := range receipt.Bindings {
		historical[index] = HistoricalBinding(binding)
	}
	if err := ValidateHistoricalBindings(root, receipt.HeadAtExecution, historical); err != nil {
		return qualificationReceipt{}, QualificationSummary{}, err
	}
	return receipt, QualificationSummary{
		QualifiedCommit: receipt.HeadAtExecution,
		BindingCount:    len(receipt.Bindings),
	}, nil
}

// ResolveHistoricalArtifactCommit finds the earliest commit that introduced
// the exact retained artifact bytes. A later restoration commit therefore
// cannot silently move a historical receipt to a newer era.
func ResolveHistoricalArtifactCommit(repositoryRoot, artifactPath string, document []byte) (string, error) {
	if !validHistoricalPath(artifactPath) {
		return "", fmt.Errorf("HISTORICAL_PATH_INVALID: %s", artifactPath)
	}
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return "", fmt.Errorf("HISTORICAL_ROOT_INVALID: %w", err)
	}
	wanted := gitBlobID(document)
	output, err := exec.Command("git", "-C", root, "log", "--reverse", "--format=%H", "HEAD", "--", artifactPath).Output()
	if err != nil {
		return "", fmt.Errorf("HISTORICAL_COMMIT_LOG_FAILED: %w", err)
	}
	commits := strings.Fields(string(output))
	if len(commits) > 4096 {
		return "", fmt.Errorf("HISTORICAL_COMMIT_LOG_TOO_LARGE")
	}
	for _, commit := range commits {
		if !hex40.MatchString(commit) {
			return "", fmt.Errorf("HISTORICAL_COMMIT_INVALID")
		}
		object, objectErr := gitOutput(root, "rev-parse", "--verify", commit+":"+artifactPath)
		if objectErr == nil && object == wanted {
			return commit, nil
		}
	}
	return "", fmt.Errorf("HISTORICAL_ARTIFACT_COMMIT_NOT_FOUND: %s", artifactPath)
}

// ValidateHistoricalBindings validates path-to-blob and blob-to-content chains
// at one immutable commit. It never compares those historical bytes with the
// working tree or current HEAD.
func ValidateHistoricalBindings(repositoryRoot, commit string, bindings []HistoricalBinding) error {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return fmt.Errorf("HISTORICAL_ROOT_INVALID: %w", err)
	}
	if !hex40.MatchString(commit) {
		return fmt.Errorf("HISTORICAL_COMMIT_INVALID")
	}
	resolved, err := gitOutput(root, "rev-parse", "--verify", commit+"^{commit}")
	if err != nil || resolved != commit {
		return fmt.Errorf("HISTORICAL_COMMIT_INVALID")
	}
	seen := make(map[string]bool, len(bindings))
	for _, binding := range bindings {
		if !validHistoricalPath(binding.Path) || seen[binding.Path] ||
			!hex40.MatchString(binding.GitBlob) || !hex64.MatchString(binding.SHA256) {
			return fmt.Errorf("HISTORICAL_BINDING_INVALID: %s", binding.Path)
		}
		seen[binding.Path] = true
		object, objectErr := gitOutput(root, "rev-parse", "--verify", commit+":"+binding.Path)
		if objectErr != nil || object != binding.GitBlob {
			return fmt.Errorf("COMMIT_BLOB_MISMATCH: %s", binding.Path)
		}
		content, readErr := gitBlob(root, object)
		if readErr != nil {
			return fmt.Errorf("QUALIFICATION_BLOB_READ_FAILED: %s", binding.Path)
		}
		digest := sha256.Sum256(content)
		if "sha256:"+hex.EncodeToString(digest[:]) != binding.SHA256 {
			return fmt.Errorf("BLOB_SHA256_MISMATCH: %s", binding.Path)
		}
	}
	return nil
}

// ReadHistoricalArtifact returns bounded bytes only after validating the
// commit/path identity. Callers remain responsible for comparing a declared
// SHA-256 when no Git blob is stored in the historical format.
func ReadHistoricalArtifact(repositoryRoot, commit, artifactPath string) ([]byte, error) {
	if !validHistoricalPath(artifactPath) || !hex40.MatchString(commit) {
		return nil, fmt.Errorf("HISTORICAL_IDENTITY_INVALID")
	}
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return nil, err
	}
	object, err := gitOutput(root, "rev-parse", "--verify", commit+":"+artifactPath)
	if err != nil || !hex40.MatchString(object) {
		return nil, fmt.Errorf("HISTORICAL_ARTIFACT_MISSING: %s", artifactPath)
	}
	return gitBlob(root, object)
}

func validQualificationPath(path string) bool {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.ContainsAny(path, `:\`) || strings.HasPrefix(path, "-") {
		return false
	}
	return strings.HasPrefix(path, "rust/") || strings.HasPrefix(path, "cmd/rustgate/") ||
		strings.HasPrefix(path, "internal/rustgate/") || path == "docs/rust-workspace.md"
}

func validHistoricalPath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.Clean(path) == path &&
		!strings.ContainsAny(path, `:\`) && !strings.HasPrefix(path, "-") &&
		path != "." && !strings.HasPrefix(path, "../")
}

func gitOutput(root string, arguments ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func gitBlob(root, object string) ([]byte, error) {
	objectType, err := gitOutput(root, "cat-file", "-t", object)
	if err != nil || objectType != "blob" {
		return nil, fmt.Errorf("object is not a blob")
	}
	sizeText, err := gitOutput(root, "cat-file", "-s", object)
	if err != nil {
		return nil, err
	}
	var size int
	if _, err := fmt.Sscan(sizeText, &size); err != nil || size < 0 || size > maximumBlobBytes {
		return nil, fmt.Errorf("blob size is outside qualification bounds")
	}
	return exec.Command("git", "-C", root, "cat-file", "blob", object).Output()
}

func gitBlobID(content []byte) string {
	hash := sha1.New()
	_, _ = fmt.Fprintf(hash, "blob %d%c", len(content), byte(0))
	_, _ = hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

func readQualificationFile(repositoryRoot, name string) ([]byte, error) {
	root, err := os.OpenRoot(repositoryRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("qualification is not a regular file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return nil, fmt.Errorf("qualification is not a single-link file")
	}
	if info.Size() < 0 || info.Size() > maximumBlobBytes {
		return nil, fmt.Errorf("qualification exceeds byte limit")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximumBlobBytes+1))
	if err != nil || len(data) > maximumBlobBytes {
		return nil, fmt.Errorf("qualification read failed or exceeded byte limit")
	}
	return data, nil
}

func expectedQualificationPaths() []string {
	paths := []string{
		"cmd/rustgate/main.go", "cmd/rustgate/main_test.go", "docs/rust-workspace.md",
		"internal/rustgate/rustlex.go", "internal/rustgate/toml.go", "internal/rustgate/verify.go",
		"rust/Cargo.lock", "rust/Cargo.toml", "rust/connection-core/Cargo.toml",
		"rust/connection-core/src/close.rs", "rust/connection-core/src/connection.rs",
		"rust/connection-core/src/control.rs", "rust/connection-core/src/fragment.rs",
		"rust/connection-core/src/frame/decode.rs", "rust/connection-core/src/frame/encode.rs",
		"rust/connection-core/src/frame/mask.rs", "rust/connection-core/src/frame/mod.rs",
		"rust/connection-core/src/handshake.rs", "rust/connection-core/src/handshake/client.rs",
		"rust/connection-core/src/handshake/crypto.rs", "rust/connection-core/src/handshake/http.rs",
		"rust/connection-core/src/handshake/server.rs", "rust/connection-core/src/lib.rs",
		"rust/connection-core/src/message.rs", "rust/connection-core/src/utf8.rs",
		"rust/connection-core/tests/client_handshake.rs", "rust/connection-core/tests/close_eof.rs",
		"rust/connection-core/tests/connection_contract.rs",
		"rust/connection-core/tests/data/us011_frozen_cases.rs",
		"rust/connection-core/tests/data/us011_nonce_vectors.rs",
		"rust/connection-core/tests/fragmentation.rs", "rust/connection-core/tests/frame_codec.rs",
		"rust/connection-core/tests/messages.rs", "rust/connection-core/tests/outbound_commands.rs",
		"rust/connection-core/tests/ping_pong.rs", "rust/connection-core/tests/scaffold_smoke.rs",
		"rust/connection-core/tests/server_handshake.rs", "rust/dependency-inventory.toml",
		"rust/dependency-policy.toml", "rust/websocket-driver/Cargo.toml",
		"rust/websocket-driver/src/lib.rs", "rust/websocket-driver/tests/concurrency.rs",
		"rust/websocket-driver/tests/driver_contract.rs", "rust/websocket-testee/Cargo.toml",
		"rust/websocket-testee/src/client.rs", "rust/websocket-testee/src/io_loop.rs",
		"rust/websocket-testee/src/lib.rs", "rust/websocket-testee/src/main.rs",
		"rust/websocket-testee/src/neutral.rs", "rust/websocket-testee/src/server.rs",
		"rust/websocket-testee/tests/loopback.rs", "rust/websocket-testee/tests/process.rs",
	}
	sort.Strings(paths)
	return paths
}

func expectedPredecessorScope() []string {
	return []string{"US-010", "US-011", "US-012", "US-013", "US-014", "US-015", "US-016", "US-017", "US-018", "US-019"}
}

func expectedNonclaims() []string {
	return []string{
		"historical predecessor receipts are preserved and not rewritten",
		"no predecessor result is rerun or upgraded",
		"no live Java Docker Autobahn Linux network production publication signing or independent review claim",
	}
}

func expectedCommands() []qualificationCommand {
	return []qualificationCommand{
		{Argv: []string{"cargo", "test", "--locked", "-p", "websocket-core"}, WorkingDirectory: "rust", Result: "PASS"},
		{Argv: []string{"cargo", "test", "--locked", "-p", "websocket-driver"}, WorkingDirectory: "rust", Result: "PASS"},
		{Argv: []string{"cargo", "test", "--locked", "-p", "websocket-testee", "--lib"}, WorkingDirectory: "rust", Result: "PASS"},
		{Argv: []string{"cargo", "test", "--locked", "-p", "websocket-testee", "--test", "process", "neutral_oracle"}, WorkingDirectory: "rust", Result: "PASS"},
		{Argv: []string{"cargo", "fmt", "--all", "--", "--check"}, WorkingDirectory: "rust", Result: "PASS"},
		{Argv: []string{"cargo", "clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"}, WorkingDirectory: "rust", Result: "PASS"},
		{Argv: []string{"go", "test", "./cmd/rustgate", "-count=1"}, WorkingDirectory: ".", Result: "PASS"},
	}
}
