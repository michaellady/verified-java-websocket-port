package provenance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// CurrentHeadMaterialization records the already-executed qualification gate
// identity. The currentheadctl transport owns command execution; this module
// owns only Git-bound receipt construction.
type CurrentHeadMaterialization struct {
	ValidationTime time.Time
	Rustc          string
	Host           string
}

// MaterializeCurrentHeadQualification writes a receipt for the exact clean
// committed source/test denominator at HEAD. Untracked files are outside the
// denominator; tracked or staged drift fails closed.
func MaterializeCurrentHeadQualification(repositoryRoot string, input CurrentHeadMaterialization) error {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil || filepath.Clean(root) != root {
		return fmt.Errorf("QUALIFICATION_ROOT_INVALID")
	}
	if input.ValidationTime.IsZero() || input.Rustc == "" || input.Host != "aarch64-apple-darwin" {
		return fmt.Errorf("QUALIFICATION_MATERIALIZATION_INPUT_INVALID")
	}
	if !gitTreeClean(root) {
		return fmt.Errorf("QUALIFICATION_TRACKED_TREE_DIRTY")
	}
	head, err := gitOutput(root, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || !hex40.MatchString(head) {
		return fmt.Errorf("QUALIFICATION_CURRENT_HEAD_MISSING")
	}
	tree, err := gitOutput(root, "rev-parse", "--verify", head+"^{tree}")
	if err != nil || !hex40.MatchString(tree) {
		return fmt.Errorf("QUALIFICATION_CURRENT_TREE_MISSING")
	}
	paths, err := expectedQualificationPaths(root, head)
	if err != nil {
		return fmt.Errorf("QUALIFICATION_MEMBERSHIP_UNAVAILABLE: %w", err)
	}
	bindings := make([]qualificationBinding, 0, len(paths))
	for _, path := range paths {
		blob, blobErr := gitOutput(root, "rev-parse", "--verify", head+":"+path)
		if blobErr != nil || !hex40.MatchString(blob) {
			return fmt.Errorf("QUALIFICATION_BLOB_MISSING: %s", path)
		}
		committed, blobErr := gitBlob(root, blob)
		if blobErr != nil {
			return fmt.Errorf("QUALIFICATION_BLOB_READ_FAILED: %s", path)
		}
		working, readErr := readQualificationFile(root, path)
		if readErr != nil || !bytes.Equal(working, committed) {
			return fmt.Errorf("QUALIFICATION_WORKTREE_DRIFT: %s", path)
		}
		digest := sha256.Sum256(committed)
		bindings = append(bindings, qualificationBinding{
			Path: path, SHA256: "sha256:" + hex.EncodeToString(digest[:]), GitBlob: blob,
		})
	}
	receipt := qualificationReceipt{
		Schema: qualificationSchema, SchemaVersion: qualificationVersion,
		EvidenceID: qualificationEvidence, StoryID: "US-020", Status: qualificationStatus,
		Assurance: qualificationAssurance, HeadAtExecution: head, SourceTree: tree,
		ValidationTime: input.ValidationTime.UTC().Format(time.RFC3339),
		Toolchain:      qualificationToolchain{Rustc: input.Rustc, Host: input.Host},
		Bindings:       bindings, Commands: expectedCommands(), PredecessorScope: expectedPredecessorScope(),
		ClaimScope: qualificationScope, Network: false, LiveJava: false, Docker: false, Autobahn: false,
		Nonclaims: expectedNonclaims(),
	}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("QUALIFICATION_ENCODE_FAILED: %w", err)
	}
	raw = append(raw, '\n')
	if _, err := ValidateCurrentHeadQualification(root, raw); err != nil {
		return fmt.Errorf("QUALIFICATION_SELF_VALIDATION_FAILED: %w", err)
	}
	if !gitTreeClean(root) {
		return fmt.Errorf("QUALIFICATION_TRACKED_TREE_CHANGED_DURING_MATERIALIZATION")
	}
	return writeQualificationAtomically(root, raw)
}

func gitTreeClean(root string) bool {
	for _, arguments := range [][]string{{"diff", "--quiet", "--"}, {"diff", "--cached", "--quiet", "--"}} {
		if err := execGit(root, arguments...); err != nil {
			return false
		}
	}
	return true
}

func execGit(root string, arguments ...string) error {
	return execCommand("git", append([]string{"-C", root}, arguments...)...)
}

var execCommand = func(name string, arguments ...string) error {
	return exec.Command(name, arguments...).Run()
}

func writeQualificationAtomically(root string, raw []byte) error {
	directory := filepath.Join(root, "evidence")
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("QUALIFICATION_OUTPUT_DIRECTORY_INVALID")
	}
	temporary, err := os.CreateTemp(directory, ".us020-current-head-qualification-*.tmp")
	if err != nil {
		return fmt.Errorf("QUALIFICATION_TEMP_CREATE_FAILED: %w", err)
	}
	temporaryPath := temporary.Name()
	remove := true
	defer func() {
		_ = temporary.Close()
		if remove {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return fmt.Errorf("QUALIFICATION_TEMP_CHMOD_FAILED: %w", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		return fmt.Errorf("QUALIFICATION_TEMP_WRITE_FAILED: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("QUALIFICATION_TEMP_SYNC_FAILED: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("QUALIFICATION_TEMP_CLOSE_FAILED: %w", err)
	}
	target := filepath.Join(root, CurrentHeadQualificationPath)
	if err := os.Rename(temporaryPath, target); err != nil {
		return fmt.Errorf("QUALIFICATION_RENAME_FAILED: %w", err)
	}
	remove = false
	return nil
}
