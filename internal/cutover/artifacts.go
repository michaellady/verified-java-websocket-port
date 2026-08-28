package cutover

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxArtifactBytes = 4 << 20

var canonicalInputs = []inputBinding{
	{Path: "evidence/intake/cutover-contract.json", SHA256: "sha256:ea6d6148dd67b705e74db48056dd5f17f22626fda48d148aef01f37de2d46f76", Bytes: 6127},
	{Path: "assurance/candidate-manifest.json", SHA256: "sha256:ab24fb6cbc3b811ef1d08c46c3c1b4925b03595836f5ccd65f0858fea66c9925", Bytes: 227339},
	{Path: "evidence/refinement-replay.json", SHA256: "sha256:3482e63dd0b5e31a244bdc82d5cd491ebeb3c22e5b345b434d709d1d27463853", Bytes: 74487},
	{Path: "evidence/performance.json", SHA256: "sha256:645b18936d8939fdbf21c9877f29f7627c7a40aae7f3ab05bfd6129a0c10cd22", Bytes: 2675},
	{Path: "evidence/intake/java-intake-manifest.json", SHA256: "sha256:fa21240329e3eea761743adcb7a0bb30ae966c307b7da4df49891385a9439b71", Bytes: 12002},
	{Path: "java-oracle/pom.xml", SHA256: "sha256:607a3de79e47d3a68564ca5c64da649b90a6febe3bf9f8dcdfe98a2c2e12b5b3", Bytes: 4335},
}

type secureRepository struct {
	root *os.Root
}

func openRepository(path string) (*secureRepository, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := validateRepositoryRootAncestry(absolute)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, err
	}
	held, err := root.Stat(".")
	if err != nil || !os.SameFile(info, held) {
		_ = root.Close()
		return nil, fail(FailureInputSymlinkOrNonregular, "repository root changed while opening")
	}
	return &secureRepository{root: root}, nil
}

func validateRepositoryRootAncestry(absolute string) (os.FileInfo, error) {
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
			if errors.Is(err, os.ErrNotExist) {
				return nil, fail(FailureInputAbsent, "repository root component %s is absent", current)
			}
			return nil, fail(FailureInputSymlinkOrNonregular, "repository root component %s cannot be validated: %v", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fail(FailureInputSymlinkOrNonregular, "repository root component %s is not a regular directory", current)
		}
		final = info
	}
	if final == nil {
		final, _ = os.Lstat(clean)
	}
	return final, nil
}

func (repository *secureRepository) close() { _ = repository.root.Close() }

func (repository *secureRepository) validatePathComponents(name string) error {
	clean := filepath.ToSlash(filepath.Clean(name))
	if clean != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") {
		return fail(FailureInputSymlinkOrNonregular, "path %q is not canonical repository-relative", name)
	}
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		prefix := strings.Join(parts[:i], "/")
		info, err := repository.root.Lstat(prefix)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fail(FailureInputAbsent, "%s is absent", prefix)
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fail(FailureInputSymlinkOrNonregular, "%s is not a regular directory", prefix)
		}
	}
	return nil
}

func (repository *secureRepository) read(name string) ([]byte, error) {
	if err := repository.validatePathComponents(name); err != nil {
		return nil, err
	}
	before, err := repository.root.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fail(FailureInputAbsent, "%s is absent", name)
		}
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxArtifactBytes {
		return nil, fail(FailureInputSymlinkOrNonregular, "%s is not a bounded regular file", name)
	}
	file, err := repository.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	held, err := file.Stat()
	if err != nil || !os.SameFile(before, held) || !held.Mode().IsRegular() {
		return nil, fail(FailureInputSymlinkOrNonregular, "%s changed while opening", name)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(held, after) || before.Size() != after.Size() || int64(len(raw)) != after.Size() {
		return nil, fail(FailureArtifactDrift, "%s changed while reading", name)
	}
	return raw, nil
}

func canonicalInputBindings(repository *secureRepository) ([]inputBinding, error) {
	bindings := make([]inputBinding, len(canonicalInputs))
	for i, expected := range canonicalInputs {
		if expected.Path == "assurance/developer-tools/cutover-contract.json" {
			return nil, fail(FailureContractMismatch, "developer fixture cannot be authoritative")
		}
		raw, err := repository.read(expected.Path)
		if err != nil {
			return nil, err
		}
		if got := digest(raw); got != expected.SHA256 || len(raw) != expected.Bytes {
			return nil, fail(FailureInputDigestMismatch, "%s identity is %s/%d, want %s/%d", expected.Path, got, len(raw), expected.SHA256, expected.Bytes)
		}
		if expected.Path == "evidence/intake/java-intake-manifest.json" {
			var manifest struct {
				Source struct {
					SHA256               string `json:"sha256"`
					ProductionSourceRoot string `json:"production_source_root"`
				} `json:"source"`
			}
			if err := json.Unmarshal(raw, &manifest); err != nil || manifest.Source.SHA256 != "sha256:f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4" || manifest.Source.ProductionSourceRoot != "src/main/java" {
				return nil, fail(FailureInputDigestMismatch, "%s does not declare the bound Java source", expected.Path)
			}
		}
		bindings[i] = expected
	}
	return bindings, nil
}

func validatePhaseArtifact(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt phaseReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return fail(FailureArtifactDrift, "phase receipt decode: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fail(FailureArtifactDrift, "phase receipt has trailing content")
	}
	if receipt.ResourceEvidenceKind != "SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT" {
		return fail(FailureResourceFixturePromoted, "phase %s resource label is %q", receipt.Phase, receipt.ResourceEvidenceKind)
	}
	if receipt.CutoverReadyReached {
		return fail(FailureCutoverReadyForbidden, "phase %s reached CUTOVER_READY", receipt.Phase)
	}
	if len(receipt.Runs) != 2 {
		return fail(FailureStateSkipOrReorder, "phase %s has %d runs", receipt.Phase, len(receipt.Runs))
	}
	for i, expected := range [][]string{nominalTrace, mismatchTrace} {
		states := receipt.Runs[i].States
		for _, state := range states {
			if state == "CUTOVER_READY" {
				return fail(FailureCutoverReadyForbidden, "phase %s contains CUTOVER_READY", receipt.Phase)
			}
		}
		if !sameStates(states, expected) {
			return fail(FailureStateSkipOrReorder, "phase %s run %s state trace drift", receipt.Phase, receipt.Runs[i].RunID)
		}
	}
	if receipt.Phase == "canary" {
		if len(receipt.Runs[1].FailedAttempts) != 1 || !receipt.Runs[1].FailedAttempts[0].Preserved {
			return fail(FailureFailedAttemptNotRetained, "seeded mismatch attempt is not retained")
		}
	}
	return nil
}

func sameStates(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (repository *secureRepository) ensureDirectory(name string) error {
	info, err := repository.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err := repository.root.Mkdir(name, 0o700); err != nil {
			return err
		}
		return repository.syncDirectory(".")
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fail(FailureInputSymlinkOrNonregular, "%s is not a regular directory", name)
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
	return filepath.ToSlash(filepath.Join(directory, "."+base+".us026.tmp"))
}

func (repository *secureRepository) publishNoReplace(artifact namedArtifact) (resultErr error) {
	temporary := tempName(artifact.path)
	parent := filepath.ToSlash(filepath.Dir(artifact.path))
	file, err := repository.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fail(FailureCaptureLocked, "retained temporary artifact %s: %v", temporary, err)
	}
	temporaryOwned := true
	defer func() {
		if !temporaryOwned {
			return
		}
		removeErr := repository.root.Remove(temporary)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && resultErr == nil {
			resultErr = removeErr
		}
		if syncErr := repository.syncDirectory(parent); resultErr == nil && syncErr != nil {
			resultErr = syncErr
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
			return fail(FailureArtifactDrift, "%s appeared during no-replace publication", artifact.path)
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

func (repository *secureRepository) writeBundle(set artifactSet) (resultErr error) {
	if err := repository.ensureDirectory("cutover"); err != nil {
		return err
	}
	if err := repository.ensureDirectory("evidence"); err != nil {
		return err
	}
	lockName := "cutover/.capture.lock"
	lock, err := repository.root.OpenFile(lockName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fail(FailureCaptureLocked, "exclusive capture lock: %v", err)
	}
	if _, err := lock.Write([]byte("US-026 retained exclusive capture\n")); err != nil {
		_ = lock.Close()
		return err
	}
	if err := lock.Sync(); err != nil {
		_ = lock.Close()
		return err
	}
	if err := lock.Close(); err != nil {
		return err
	}
	preserveLock := true
	defer func() {
		if !preserveLock {
			if err := repository.root.Remove(lockName); resultErr == nil && err != nil {
				resultErr = err
			}
			if resultErr == nil {
				resultErr = repository.syncDirectory("cutover")
			}
		}
	}()

	existing := 0
	for _, artifact := range set.artifacts {
		info, statErr := repository.root.Lstat(artifact.path)
		if statErr == nil {
			existing++
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fail(FailureInputSymlinkOrNonregular, "%s is not a regular artifact", artifact.path)
			}
			current, err := repository.read(artifact.path)
			if err != nil {
				return err
			}
			if !bytes.Equal(current, artifact.bytes) {
				return fail(FailureArtifactDrift, "%s differs from deterministic derivation", artifact.path)
			}
			continue
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
	}
	if existing != 0 && existing != len(set.artifacts) {
		return fail(FailureArtifactDrift, "partial artifact bundle contains %d of %d destinations", existing, len(set.artifacts))
	}

	if existing == 0 {
		for _, artifact := range set.artifacts {
			if err := repository.publishNoReplace(artifact); err != nil {
				return err
			}
		}
	}
	for _, artifact := range set.artifacts {
		current, err := repository.read(artifact.path)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, artifact.bytes) {
			return fail(FailureArtifactDrift, "%s changed after capture", artifact.path)
		}
	}
	preserveLock = false
	return nil
}

// Capture derives and atomically writes the six deterministic US-026 fixture artifacts.
func Capture(root string) (Summary, error) {
	repository, err := openRepository(root)
	if err != nil {
		return Summary{}, err
	}
	defer repository.close()
	inputs, err := canonicalInputBindings(repository)
	if err != nil {
		return Summary{}, err
	}
	set, err := deriveArtifacts(inputs)
	if err != nil {
		return Summary{}, err
	}
	if err := repository.writeBundle(set); err != nil {
		return Summary{}, err
	}
	return set.summary, nil
}

// Verify rederives all six artifacts and requires byte-for-byte identity.
func Verify(root string) (Summary, error) {
	repository, err := openRepository(root)
	if err != nil {
		return Summary{}, err
	}
	defer repository.close()
	inputs, err := canonicalInputBindings(repository)
	if err != nil {
		return Summary{}, err
	}
	set, err := deriveArtifacts(inputs)
	if err != nil {
		return Summary{}, err
	}
	for _, artifact := range set.artifacts {
		current, err := repository.read(artifact.path)
		if err != nil {
			return Summary{}, err
		}
		if strings.HasPrefix(artifact.path, "cutover/") && artifact.path != "cutover/contract.json" {
			if err := validatePhaseArtifact(current); err != nil {
				return Summary{}, err
			}
		}
		if !bytes.Equal(current, artifact.bytes) {
			return Summary{}, fail(FailureArtifactDrift, "%s differs from deterministic derivation", artifact.path)
		}
	}
	return set.summary, nil
}
