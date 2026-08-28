package projection

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const maxFileBytes = 1 << 20

type failureCode string

const (
	failureInput            failureCode = "INPUT_INVALID"
	failureInputDrift       failureCode = "INPUT_DRIFT"
	failureArtifactDrift    failureCode = "ARTIFACT_DRIFT"
	failurePartialBundle    failureCode = "PARTIAL_BUNDLE"
	failureCaptureLocked    failureCode = "CAPTURE_LOCKED"
	failureProjectionUnsafe failureCode = "PUBLIC_PROJECTION_UNSAFE"
	failureSchema           failureCode = "SCHEMA_VALIDATION_FAILED"
)

type failure struct {
	code failureCode
	err  error
}

func (f *failure) Error() string { return fmt.Sprintf("%s: %v", f.code, f.err) }
func (f *failure) Unwrap() error { return f.err }

func fail(code failureCode, format string, values ...any) error {
	return &failure{code: code, err: fmt.Errorf(format, values...)}
}

type secureRepository struct {
	root *os.Root
}

var evaluatorSchemas = []inputBinding{
	{Path: "schemas/us027-receipt-1.0.0.schema.json", SHA256: "sha256:ba2c8767ab6c2ab24f0469fdadd2fbcb96bc8b435302feb7e91398cb2220d019", Bytes: 3410},
	{Path: "schemas/us027-independent-replay-1.0.0.schema.json", SHA256: "sha256:59ad48b5726c11545b1cbb2913d79aad291f2bbc2b3c217c77140ffc422c72d8", Bytes: 4388},
	{Path: "schemas/us027-public-snapshot-1.0.0.schema.json", SHA256: "sha256:7ad7c110c6135e0dd170f6c653aa9846e0438ff1dc681ba7cf86144160a045b0", Bytes: 2353},
}

func openRepository(path string) (*secureRepository, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := validateRootAncestry(absolute)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, fail(failureInput, "open repository root: %v", err)
	}
	held, err := root.Stat(".")
	if err != nil || !os.SameFile(info, held) {
		_ = root.Close()
		return nil, fail(failureInput, "repository root changed while opening")
	}
	return &secureRepository{root: root}, nil
}

func validateRootAncestry(absolute string) (os.FileInfo, error) {
	clean := filepath.Clean(absolute)
	volume := filepath.VolumeName(clean)
	remainder := strings.TrimPrefix(clean[len(volume):], string(os.PathSeparator))
	current := volume + string(os.PathSeparator)
	var final os.FileInfo
	for _, component := range strings.Split(remainder, string(os.PathSeparator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, fail(failureInput, "repository root component %s: %v", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fail(failureInput, "repository root component %s is not a directory", current)
		}
		final = info
	}
	if final == nil {
		return nil, fail(failureInput, "repository root is not a concrete directory")
	}
	return final, nil
}

func (repository *secureRepository) close() { _ = repository.root.Close() }

func validateRelative(name string) error {
	clean := filepath.ToSlash(filepath.Clean(name))
	if clean != name || name == "." || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.Contains(name, "//") {
		return fail(failureInput, "path %q is not canonical repository-relative", name)
	}
	return nil
}

func (repository *secureRepository) validateAncestors(name string) error {
	if err := validateRelative(name); err != nil {
		return err
	}
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		prefix := strings.Join(parts[:i], "/")
		info, err := repository.root.Lstat(prefix)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fail(failureInput, "%s is absent", prefix)
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fail(failureInput, "%s is not a directory", prefix)
		}
	}
	return nil
}

func (repository *secureRepository) read(name string) ([]byte, error) {
	if err := repository.validateAncestors(name); err != nil {
		return nil, err
	}
	before, err := repository.root.Lstat(name)
	if err != nil {
		return nil, fail(failureInput, "%s: %v", name, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxFileBytes {
		return nil, fail(failureInput, "%s is not a bounded regular file", name)
	}
	file, err := repository.root.Open(name)
	if err != nil {
		return nil, fail(failureInput, "open %s: %v", name, err)
	}
	defer file.Close()
	held, err := file.Stat()
	if err != nil || !os.SameFile(before, held) || !held.Mode().IsRegular() {
		return nil, fail(failureInputDrift, "%s changed while opening", name)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(held, after) || before.Size() != after.Size() || int64(len(raw)) != after.Size() {
		return nil, fail(failureInputDrift, "%s changed while reading", name)
	}
	return raw, nil
}

func canonicalInputBindings(repository *secureRepository) ([]inputBinding, map[string][]byte, error) {
	bindings := make([]inputBinding, len(canonicalInputs))
	held := make(map[string][]byte, len(canonicalInputs))
	seen := map[string]bool{}
	for i, expected := range canonicalInputs {
		if err := validateRelative(expected.Path); err != nil || seen[expected.Path] {
			return nil, nil, fail(failureInput, "duplicate or invalid canonical input %s", expected.Path)
		}
		seen[expected.Path] = true
		raw, err := repository.read(expected.Path)
		if err != nil {
			return nil, nil, err
		}
		if got := digest(raw); got != expected.SHA256 || len(raw) != expected.Bytes {
			return nil, nil, fail(failureInputDrift, "%s identity is %s/%d, want %s/%d", expected.Path, got, len(raw), expected.SHA256, expected.Bytes)
		}
		bindings[i] = expected
		held[expected.Path] = raw
	}
	return bindings, held, nil
}

func (repository *secureRepository) ensureDirectory(name string) error {
	if err := validateRelative(name); err != nil {
		return err
	}
	info, err := repository.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		parent := filepath.ToSlash(filepath.Dir(name))
		if parent != "." {
			if err := repository.ensureDirectory(parent); err != nil {
				return err
			}
		}
		if err := repository.root.Mkdir(name, 0o700); err != nil {
			return err
		}
		return repository.syncDirectory(parent)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fail(failureInput, "%s is not a directory", name)
	}
	return nil
}

func (repository *secureRepository) syncDirectory(name string) error {
	directory, err := repository.root.Open(name)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func tempName(path string) string {
	directory, base := filepath.Split(path)
	return filepath.ToSlash(filepath.Join(directory, "."+base+".us027.tmp"))
}

func (repository *secureRepository) publishNoReplace(artifact namedArtifact) (resultErr error) {
	temporary := tempName(artifact.path)
	parent := filepath.ToSlash(filepath.Dir(artifact.path))
	file, err := repository.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fail(failureCaptureLocked, "temporary %s: %v", temporary, err)
	}
	temporaryOwned := true
	defer func() {
		if !temporaryOwned {
			return
		}
		removeErr := repository.root.Remove(temporary)
		if resultErr == nil && removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			resultErr = removeErr
		}
		if resultErr == nil {
			resultErr = repository.syncDirectory(parent)
		}
	}()
	written, writeErr := file.Write(artifact.bytes)
	if writeErr == nil && written != len(artifact.bytes) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := repository.root.Link(temporary, artifact.path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fail(failureArtifactDrift, "%s appeared during publication", artifact.path)
		}
		return err
	}
	if err := repository.syncDirectory(parent); err != nil {
		return err
	}
	if err := repository.root.Remove(temporary); err != nil {
		return err
	}
	temporaryOwned = false
	return repository.syncDirectory(parent)
}

func (repository *secureRepository) preflight(set artifactSet) (int, error) {
	existing := 0
	for _, artifact := range set.artifacts {
		info, err := repository.root.Lstat(artifact.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		existing++
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return 0, fail(failureArtifactDrift, "%s is not a regular artifact", artifact.path)
		}
		current, err := repository.read(artifact.path)
		if err != nil {
			return 0, err
		}
		if !bytes.Equal(current, artifact.bytes) {
			return 0, fail(failureArtifactDrift, "%s differs from deterministic derivation", artifact.path)
		}
	}
	if existing != 0 && existing != len(set.artifacts) {
		return 0, fail(failurePartialBundle, "found %d of %d artifacts", existing, len(set.artifacts))
	}
	return existing, nil
}

func (repository *secureRepository) validateSchemas(set artifactSet) error {
	artifactByPath := make(map[string][]byte, len(set.artifacts))
	for _, artifact := range set.artifacts {
		artifactByPath[artifact.path] = artifact.bytes
	}
	artifactsBySchema := map[string][]string{
		"schemas/us027-receipt-1.0.0.schema.json": {
			"assurance/receipts/human.json",
			"assurance/receipts/codex.json",
			"assurance/receipts/reality.json",
		},
		"schemas/us027-independent-replay-1.0.0.schema.json": {"assurance/independent-replay.json"},
		"schemas/us027-public-snapshot-1.0.0.schema.json":    {"public/snapshot.json"},
	}
	for _, expected := range evaluatorSchemas {
		schemaRaw, err := repository.read(expected.Path)
		if err != nil {
			return err
		}
		if digest(schemaRaw) != expected.SHA256 || len(schemaRaw) != expected.Bytes {
			return fail(failureSchema, "%s identity drift", expected.Path)
		}
		schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
		if err != nil {
			return fail(failureSchema, "%s parse: %v", expected.Path, err)
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		resource := "https://verified-java-websocket-port.invalid/" + filepath.Base(expected.Path)
		if err := compiler.AddResource(resource, schemaValue); err != nil {
			return fail(failureSchema, "%s resource: %v", expected.Path, err)
		}
		compiled, err := compiler.Compile(resource)
		if err != nil {
			return fail(failureSchema, "%s compile: %v", expected.Path, err)
		}
		for _, artifactPath := range artifactsBySchema[expected.Path] {
			raw, ok := artifactByPath[artifactPath]
			if !ok {
				return fail(failureSchema, "schema target %s absent", artifactPath)
			}
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				return fail(failureSchema, "%s parse: %v", artifactPath, err)
			}
			if err := compiled.Validate(value); err != nil {
				return fail(failureSchema, "%s: %v", artifactPath, err)
			}
		}
	}
	return nil
}

func (repository *secureRepository) writeBundle(set artifactSet) (resultErr error) {
	if err := repository.validateSchemas(set); err != nil {
		return err
	}
	lockName := ".us027-projection.lock"
	lock, err := repository.root.OpenFile(lockName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fail(failureCaptureLocked, "exclusive capture lock: %v", err)
	}
	lockClosed := false
	defer func() {
		if !lockClosed {
			if closeErr := lock.Close(); resultErr == nil && closeErr != nil {
				resultErr = closeErr
			}
		}
		removeErr := repository.root.Remove(lockName)
		if resultErr == nil && removeErr != nil {
			resultErr = removeErr
		}
		if resultErr == nil {
			resultErr = repository.syncDirectory(".")
		}
	}()
	if _, err := lock.Write([]byte("US-027 exclusive local capture\n")); err != nil {
		return err
	}
	if err := lock.Sync(); err != nil {
		return err
	}
	if err := lock.Close(); err != nil {
		return err
	}
	lockClosed = true
	if err := repository.syncDirectory("."); err != nil {
		return err
	}

	existing, err := repository.preflight(set)
	if err != nil {
		return err
	}
	if existing == 0 {
		for _, directory := range []string{"assurance", "assurance/receipts", "public"} {
			if err := repository.ensureDirectory(directory); err != nil {
				return err
			}
		}
		for _, artifact := range set.artifacts {
			if err := repository.publishNoReplace(artifact); err != nil {
				return err
			}
		}
	}
	return repository.verifySet(set)
}

func (repository *secureRepository) verifySet(set artifactSet) error {
	if err := repository.validateSchemas(set); err != nil {
		return err
	}
	for _, artifact := range set.artifacts {
		current, err := repository.read(artifact.path)
		if err != nil {
			return err
		}
		if err := validateArtifact(artifact.path, current); err != nil {
			return err
		}
		if !bytes.Equal(current, artifact.bytes) {
			return fail(failureArtifactDrift, "%s differs from deterministic derivation", artifact.path)
		}
	}
	return repository.scanPublicTree()
}

func validateArtifact(path string, raw []byte) error {
	switch path {
	case "assurance/receipts/human.json", "assurance/receipts/codex.json", "assurance/receipts/reality.json":
		var value receipt
		if err := strictDecode(raw, &value); err != nil {
			return fail(failureSchema, "%s: %v", path, err)
		}
		if value.Subject.Commit != SubjectCommit || value.Subject.Tree != SubjectTree || value.CandidateRoot != CandidateRoot || value.ProjectionContractSHA256 != ContractSHA256 || value.MechanicsStatus != MechanicsPass || value.AcceptanceState != AcceptanceBlocked || value.Independent || value.Accepted || value.ProtectedAccess || value.Assurance != Assurance {
			return fail(failureSchema, "%s exceeds the fixed receipt ceiling", path)
		}
		if path == "assurance/receipts/human.json" && (value.Role != "HUMAN_REVIEWER" || value.Status != "NOT_EXECUTED" || value.Provider != nil || value.Model != nil || value.ReasoningEffort != nil) {
			return fail(failureSchema, "human receipt invents execution or identity")
		}
	case "assurance/independent-replay.json":
		var value replayDocument
		if err := strictDecode(raw, &value); err != nil {
			return fail(failureSchema, "%s: %v", path, err)
		}
		if value.MechanicsStatus != MechanicsPass || value.AcceptanceState != AcceptanceBlocked || value.ChildStoryCount != 26 || value.ChildMechanicsPassed != 26 || value.StrongChildAccepted != 0 || value.FormalObligations != 24 || value.FormalStrongAccepted != 0 || value.FormalBlocked != 24 || value.ProtectedReplay != "NOT_EXECUTED" || value.HumanReview != "NOT_EXECUTED" || value.IndependentCustodian != "NOT_BOUND" || value.Assurance != Assurance || value.IndependentReviewClaimed || len(value.Blockers) != 13 || len(value.Nonclaims) != 6 {
			return fail(failureSchema, "independent replay ceiling or counts drift")
		}
	case "public/snapshot.json":
		var value publicSnapshot
		if err := strictDecode(raw, &value); err != nil {
			return fail(failureSchema, "%s: %v", path, err)
		}
		if value.Badge != publicBadge || value.Freshness != publicFreshness || value.JavaFallback != publicJavaFallback || value.Supersession != publicSupersession || value.Revocation != publicRevocation || value.Publication != publicPublication || value.AcceptanceState != AcceptanceBlocked || value.StrongChildAccepted != 0 || value.FormalStrongAccepted != 0 {
			return fail(failureSchema, "public snapshot claim ceiling drift")
		}
	}
	return nil
}

func (repository *secureRepository) scanPublicTree() error {
	info, err := repository.root.Lstat("public")
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fail(failureProjectionUnsafe, "public is not a concrete directory")
	}
	directory, err := repository.root.Open("public")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	allowed := map[string]bool{"README.md": true, "formal-coverage.md": true, "snapshot.json": true}
	if len(entries) != len(allowed) {
		return fail(failureProjectionUnsafe, "public contains %d entries, want %d", len(entries), len(allowed))
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fail(failureProjectionUnsafe, "unclassified public descendant %s", entry.Name())
		}
		raw, err := repository.read("public/" + entry.Name())
		if err != nil {
			return err
		}
		if err := scanPublicBytes(raw); err != nil {
			return fail(failureProjectionUnsafe, "%s: %v", entry.Name(), err)
		}
	}
	return nil
}

func scanPublicBytes(raw []byte) error {
	for _, value := range raw {
		if value < 0x20 && value != '\n' && value != '\t' {
			return fmt.Errorf("control byte present")
		}
	}
	lower := strings.ToLower(string(raw))
	prohibited := []string{
		"synthetic_cache_state", "synthetic_token_value", "synthetic_golden_answer",
		"synthetic_session_identifier", "synthetic_protected_canary", "synthetic_raw_trace",
		"case_id", "expected_output", "stdout", "stderr", "machine_identity",
		"invocation_transcript", "http://", "https://", "cutover_ready",
	}
	for _, marker := range prohibited {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("prohibited marker %q", marker)
		}
	}
	return nil
}

// ArtifactPaths returns the complete ordered US-027 bundle.
func ArtifactPaths() []string {
	result := make([]string, 0, 7)
	for _, path := range []string{
		"assurance/receipts/human.json",
		"assurance/receipts/codex.json",
		"assurance/receipts/reality.json",
		"assurance/independent-replay.json",
		"public/snapshot.json",
		"public/formal-coverage.md",
		"public/README.md",
	} {
		result = append(result, path)
	}
	return result
}

// Capture derives and publishes exactly seven deterministic local artifacts.
func Capture(root string) (Summary, error) {
	repository, err := openRepository(root)
	if err != nil {
		return Summary{}, err
	}
	defer repository.close()
	bindings, inputs, err := canonicalInputBindings(repository)
	if err != nil {
		return Summary{}, err
	}
	set, err := deriveArtifacts(bindings, inputs)
	if err != nil {
		return Summary{}, err
	}
	if err := repository.writeBundle(set); err != nil {
		return Summary{}, err
	}
	return set.summary, nil
}

// Verify rederives, schema-checks, scans, and exact-compares all seven outputs.
func Verify(root string) (Summary, error) {
	repository, err := openRepository(root)
	if err != nil {
		return Summary{}, err
	}
	defer repository.close()
	bindings, inputs, err := canonicalInputBindings(repository)
	if err != nil {
		return Summary{}, err
	}
	set, err := deriveArtifacts(bindings, inputs)
	if err != nil {
		return Summary{}, err
	}
	if err := repository.verifySet(set); err != nil {
		return Summary{}, err
	}
	return set.summary, nil
}
