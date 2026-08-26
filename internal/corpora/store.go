package corpora

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Protected store layout under the orchestrator protected root.
const (
	ProtectedDirName        = "us005-corpora"
	protectedHiddenLines    = ProtectedDirName + "/hidden/scenarios.jsonl"
	protectedSealedLines    = ProtectedDirName + "/sealed/scenarios.jsonl"
	protectedCanaryFile     = ProtectedDirName + "/canary-inventory.json"
	protectedPolicyFile     = ProtectedDirName + "/custodian/policy.json"
	protectedLedgerFile     = ProtectedDirName + "/custodian/ledger.json"
	protectedSecretFile     = ProtectedDirName + "/secrets/master-secret.hex"
	repoCorporaDir          = "corpora"
	manifestSchemaReference = "../../schemas/corpus-manifest-1.0.0.schema.json"
)

// ProtectedLedgerPath locates the custodian ledger under a protected root.
func ProtectedLedgerPath(protectedRoot string) string {
	return filepath.Join(protectedRoot, protectedLedgerFile)
}

// Finding is one fail-closed verification finding.
type Finding struct {
	Code   string `json:"code"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

func scenarioLines(scenarios []Scenario) ([]byte, error) {
	var out bytes.Buffer
	for _, sc := range scenarios {
		line, err := sc.CanonicalLine()
		if err != nil {
			return nil, err
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

func handshakeLines(cases []HandshakeCase) ([]byte, error) {
	var out bytes.Buffer
	for _, c := range cases {
		line, err := c.CanonicalLine()
		if err != nil {
			return nil, err
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// CommitmentRoot binds every held-out line under a secret-derived salt:
// c_i = sha256(salt_i || line_i) with salt_i = stream(secret,
// "commitment-salt|tier|scenario_id"), root = sha256(concat c_i). The root is
// committed publicly before any reveal; salts stay derivable only with the
// protected secret, so the commitment cannot be brute-forced from the repo.
func CommitmentRoot(secret, tier string, scenarios []Scenario) (string, error) {
	var concat []byte
	for _, sc := range scenarios {
		line, err := sc.CanonicalLine()
		if err != nil {
			return "", err
		}
		salt := NewStream(secret, "commitment-salt|"+tier+"|"+sc.ScenarioID).Bytes(32)
		commitment := DigestSHA256(append(append([]byte{}, salt...), line...))
		concat = append(concat, []byte(commitment)...)
	}
	return DigestSHA256(concat), nil
}

func countsMap(plan PlanCount) map[string]any {
	return map[string]any{
		"expected":  plan.Expected,
		"selected":  plan.Selected,
		"executed":  0,
		"passed":    0,
		"failed":    0,
		"skipped":   0,
		"filtered":  plan.Filtered,
		"timed_out": 0,
	}
}

func assuranceLabels() map[string]any {
	return map[string]any{
		"assurance":                  "OWNER_ATTESTED_NOT_INDEPENDENT",
		"independent_review_claimed": false,
		"production":                 false,
		"signing":                    false,
		"publication":                false,
	}
}

// buildManifests derives the four tier manifests from generated content.
func buildManifests(input GenerationInput, g *GeneratedCorpora,
	publicBytes, handshakeBytes, hiddenBytes, sealedBytes []byte,
	policyDigest string) (map[string]map[string]any, error) {
	manifests := map[string]map[string]any{}

	publicTiers := []struct {
		tier, corpusID, artifactPath, format string
		plan                                 PlanCount
		content                              []byte
	}{
		{"public", "us005-behavior-public", "scenarios.jsonl",
			"corpus-scenario-1.0.0.schema.json", g.PlanCounts["public"], publicBytes},
		{"handshake", "us005-handshake", "cases.jsonl",
			"corpus-handshake-case-1.0.0.schema.json", g.PlanCounts["handshake"], handshakeBytes},
	}
	for _, t := range publicTiers {
		manifest := map[string]any{
			"$schema":         manifestSchemaReference,
			"schema_version":  "1.0.0",
			"evidence_kind":   "corpus-manifest",
			"corpus_id":       t.corpusID,
			"tier":            t.tier,
			"scenario_format": t.format,
			"generator": map[string]any{
				"tool":            "corporactl",
				"seed_visibility": "public",
				"public_seed":     input.PublicSeed,
			},
			"counts":           countsMap(t.plan),
			"execution_status": "NOT_EXECUTED_PENDING_LIVE_CALIBRATION",
			"artifacts": []any{map[string]any{
				"path":           t.artifactPath,
				"sha256":         DigestSHA256(t.content),
				"bytes":          len(t.content),
				"classification": "PUBLIC",
				"stored_in_repo": true,
			}},
		}
		for k, v := range assuranceLabels() {
			manifest[k] = v
		}
		manifests[t.tier] = manifest
	}

	heldOut := []struct {
		tier, corpusID, protectedPath string
		plan                          PlanCount
		scenarios                     []Scenario
		content                       []byte
	}{
		{"hidden", "us005-behavior-hidden", protectedHiddenLines,
			g.PlanCounts["hidden"], g.Hidden, hiddenBytes},
		{"sealed", "us005-behavior-sealed", protectedSealedLines,
			g.PlanCounts["sealed"], g.Sealed, sealedBytes},
	}
	for _, t := range heldOut {
		root, err := CommitmentRoot(input.Secret, t.tier, t.scenarios)
		if err != nil {
			return nil, err
		}
		manifest := map[string]any{
			"$schema":         manifestSchemaReference,
			"schema_version":  "1.0.0",
			"evidence_kind":   "corpus-manifest",
			"corpus_id":       t.corpusID,
			"tier":            t.tier,
			"scenario_format": "corpus-scenario-1.0.0.schema.json",
			"generator": map[string]any{
				"tool":                   "corporactl",
				"seed_visibility":        "protected-secret",
				"secret_seed_commitment": DigestSHA256([]byte(input.Secret)),
				"epoch":                  input.Epoch,
			},
			"counts":           countsMap(t.plan),
			"execution_status": "NOT_EXECUTED_PENDING_LIVE_CALIBRATION",
			"artifacts": []any{map[string]any{
				"path":           t.protectedPath,
				"sha256":         DigestSHA256(t.content),
				"bytes":          len(t.content),
				"classification": "PROTECTED_HELD_OUT",
				"stored_in_repo": false,
			}},
			"commitments": map[string]any{
				"scheme":                   "sha256(salt || canonical_line); salt = stream(secret, commitment-salt|tier|scenario_id)",
				"scenario_commitment_root": root,
				"committed_line_count":     len(t.scenarios),
			},
			"custodian": map[string]any{
				"policy_digest": policyDigest,
				"canary_count":  len(g.CanaryIDs[t.tier]),
			},
			"sealing": map[string]any{
				"mechanism":  "digest-committed-before-reveal",
				"storage":    "protected-custodian-store",
				"disclosure": "the sole owner can technically read the protected store; these mechanics prove process, not independence",
			},
		}
		for k, v := range assuranceLabels() {
			manifest[k] = v
		}
		manifests[t.tier] = manifest
	}
	return manifests, nil
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	rendered, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(rendered, '\n'), 0o644)
}

func writeRawFile(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, mode)
}

// EnsureSecret loads the protected master secret, creating it with
// crypto/rand on first use. The secret never enters the repository.
func EnsureSecret(protectedRoot string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(ProtectedLedgerPath(protectedRoot)), 0o755); err != nil {
		return "", err
	}
	unlock, err := acquireFileLock(ProtectedLedgerPath(protectedRoot) + ".lock")
	if err != nil {
		return "", fmt.Errorf("custodian ledger lock: %w", err)
	}
	defer unlock()

	path := filepath.Join(protectedRoot, protectedSecretFile)
	if raw, err := os.ReadFile(path); err == nil {
		secret := strings.TrimSpace(string(raw))
		if decoded, err := hex.DecodeString(secret); err != nil || len(decoded) != 32 {
			return "", fmt.Errorf("protected master secret is malformed")
		}
		return secret, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(buf)
	if err := writeRawFile(path, []byte(secret+"\n"), 0o600); err != nil {
		return "", err
	}
	return secret, nil
}

func buildCanaryInventory(input GenerationInput, g *GeneratedCorpora) ([]byte, error) {
	inventory := map[string]any{
		"schema_version": "1.0.0",
		"epoch":          input.Epoch,
		"tiers":          map[string]any{},
	}
	tiersMap := inventory["tiers"].(map[string]any)
	for _, tier := range []string{"hidden", "sealed"} {
		ids := make([]any, 0, len(g.CanaryIDs[tier]))
		tokens := map[string]any{}
		for _, id := range g.CanaryIDs[tier] {
			ids = append(ids, id)
			tokens[id] = g.CanaryTokens[id]
		}
		tiersMap[tier] = map[string]any{"ids": ids, "tokens": tokens}
	}
	return CanonicalJSON(inventory)
}

type generatedStateFile struct {
	path string
	data []byte
	mode os.FileMode
}

func renderedJSON(value any) ([]byte, error) {
	rendered, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(rendered, '\n'), nil
}

// replaceGeneratedState stages every file before replacing any path. All
// supported readers share the custodian lock, so they observe either the old
// complete state or the new complete state. Ordinary rename failures roll the
// already-applied paths back to their snapshots before the lock is released.
func replaceGeneratedState(files []generatedStateFile) error {
	type stagedFile struct {
		generatedStateFile
		temporary string
		existed   bool
		oldData   []byte
		oldMode   os.FileMode
	}
	staged := make([]stagedFile, 0, len(files))
	cleanup := func() {
		for _, file := range staged {
			if file.temporary != "" {
				_ = os.Remove(file.temporary)
			}
		}
	}
	for _, file := range files {
		if err := os.MkdirAll(filepath.Dir(file.path), 0o755); err != nil {
			cleanup()
			return err
		}
		entry := stagedFile{generatedStateFile: file}
		if info, err := os.Stat(file.path); err == nil {
			entry.existed = true
			entry.oldMode = info.Mode().Perm()
			entry.oldData, err = os.ReadFile(file.path)
			if err != nil {
				cleanup()
				return err
			}
		} else if !os.IsNotExist(err) {
			cleanup()
			return err
		}
		temporary, err := os.CreateTemp(filepath.Dir(file.path), ".corporactl-state-*")
		if err != nil {
			cleanup()
			return err
		}
		entry.temporary = temporary.Name()
		if err := temporary.Chmod(file.mode); err != nil {
			_ = temporary.Close()
			staged = append(staged, entry)
			cleanup()
			return err
		}
		if _, err := temporary.Write(file.data); err != nil {
			_ = temporary.Close()
			staged = append(staged, entry)
			cleanup()
			return err
		}
		if err := temporary.Sync(); err != nil {
			_ = temporary.Close()
			staged = append(staged, entry)
			cleanup()
			return err
		}
		if err := temporary.Close(); err != nil {
			staged = append(staged, entry)
			cleanup()
			return err
		}
		staged = append(staged, entry)
	}
	for index := range staged {
		if err := os.Rename(staged[index].temporary, staged[index].path); err != nil {
			for rollback := index - 1; rollback >= 0; rollback-- {
				if staged[rollback].existed {
					_ = writeRawFile(staged[rollback].path, staged[rollback].oldData,
						staged[rollback].oldMode)
				} else {
					_ = os.Remove(staged[rollback].path)
				}
			}
			cleanup()
			return err
		}
		staged[index].temporary = ""
	}
	return nil
}

func storedEpoch(path string) (int, error) {
	document, err := readManifest(path)
	if err != nil {
		return 0, err
	}
	epoch, ok := gateCounter(document, "epoch")
	if !ok || epoch < 1 {
		return 0, fmt.Errorf("epoch is missing or non-integral")
	}
	return epoch, nil
}

func storedManifestEpoch(path string) (int, error) {
	manifest, err := readManifest(path)
	if err != nil {
		return 0, err
	}
	generator, _ := manifest["generator"].(map[string]any)
	epoch, ok := gateCounter(generator, "epoch")
	if !ok || epoch < 1 {
		return 0, fmt.Errorf("generator epoch is missing or non-integral")
	}
	return epoch, nil
}

func verifyStoredEpochState(root, protectedRoot string, epoch int) error {
	policy, err := CustodianPolicyDocument(DefaultCustodianPolicy(), epoch)
	if err != nil {
		return err
	}
	policyRaw, err := os.ReadFile(filepath.Join(protectedRoot, protectedPolicyFile))
	if err != nil || !bytes.Equal(policyRaw, append(policy, '\n')) {
		return fmt.Errorf("stored custodian policy is inconsistent with ledger epoch %d", epoch)
	}
	canaryEpoch, err := storedEpoch(filepath.Join(protectedRoot, protectedCanaryFile))
	if err != nil || canaryEpoch != epoch {
		return fmt.Errorf("stored canary epoch is inconsistent with ledger epoch %d", epoch)
	}
	for _, tier := range []string{"hidden", "sealed"} {
		manifestEpoch, err := storedManifestEpoch(
			filepath.Join(root, repoCorporaDir, tier, "manifest.json"))
		if err != nil || manifestEpoch != epoch {
			return fmt.Errorf("stored %s manifest epoch is inconsistent with ledger epoch %d",
				tier, epoch)
		}
	}
	return nil
}

// WriteAll writes repo manifests and public content plus protected held-out
// content, canary inventory, custodian policy, and ledger genesis.
func WriteAll(root, protectedRoot string, input GenerationInput, g *GeneratedCorpora) error {
	if g == nil || g.Epoch != input.Epoch || g.PublicSeed != input.PublicSeed {
		return fmt.Errorf("generated corpora disagree with generation input")
	}
	publicBytes, err := scenarioLines(g.Public)
	if err != nil {
		return err
	}
	handshakeBytes, err := handshakeLines(g.Handshake)
	if err != nil {
		return err
	}
	hiddenBytes, err := scenarioLines(g.Hidden)
	if err != nil {
		return err
	}
	sealedBytes, err := scenarioLines(g.Sealed)
	if err != nil {
		return err
	}
	policyDocument, err := CustodianPolicyDocument(DefaultCustodianPolicy(), input.Epoch)
	if err != nil {
		return err
	}
	inventoryBytes, err := buildCanaryInventory(input, g)
	if err != nil {
		return err
	}
	manifests, err := buildManifests(input, g, publicBytes, handshakeBytes,
		hiddenBytes, sealedBytes, DigestSHA256(policyDocument))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ProtectedLedgerPath(protectedRoot)), 0o755); err != nil {
		return err
	}
	unlock, err := acquireFileLock(ProtectedLedgerPath(protectedRoot) + ".lock")
	if err != nil {
		return fmt.Errorf("custodian ledger lock: %w", err)
	}
	defer unlock()

	existingSecretPath := filepath.Join(protectedRoot, protectedSecretFile)
	if raw, err := os.ReadFile(existingSecretPath); err == nil {
		if strings.TrimSpace(string(raw)) != input.Secret {
			return fmt.Errorf("protected master secret disagrees with generation input")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	ledgerPath := filepath.Join(protectedRoot, protectedLedgerFile)
	var ledger *Ledger
	if ledgerRaw, err := os.ReadFile(ledgerPath); err == nil {
		ledger, err = LoadLedger(ledgerRaw)
		if err != nil {
			return fmt.Errorf("existing custodian ledger is invalid: %w", err)
		}
		if err := verifyStoredEpochState(root, protectedRoot, ledger.Epoch()); err != nil {
			return err
		}
		if ledger.policy != DefaultCustodianPolicy() {
			return fmt.Errorf("existing ledger policy disagrees with committed custodian policy")
		}
		if input.Epoch < ledger.Epoch() {
			return fmt.Errorf("generation epoch %d is behind active ledger epoch %d",
				input.Epoch, ledger.Epoch())
		}
		if input.Epoch > ledger.Epoch() {
			if err := ledger.Rotate(input.Epoch); err != nil {
				return err
			}
		}
	} else if os.IsNotExist(err) {
		for _, path := range []string{
			filepath.Join(protectedRoot, protectedPolicyFile),
			filepath.Join(protectedRoot, protectedCanaryFile),
			filepath.Join(protectedRoot, protectedHiddenLines),
			filepath.Join(protectedRoot, protectedSealedLines),
		} {
			if _, stateErr := os.Stat(path); stateErr == nil {
				return fmt.Errorf("protected generation state exists without a custodian ledger")
			} else if !os.IsNotExist(stateErr) {
				return stateErr
			}
		}
		ledger, err = NewLedger(DefaultCustodianPolicy(), input.Epoch)
		if err != nil {
			return err
		}
	} else {
		return err
	}
	ledgerBytes, err := ledger.Serialize()
	if err != nil {
		return err
	}

	files := []generatedStateFile{
		{existingSecretPath, []byte(input.Secret + "\n"), 0o600},
		{filepath.Join(root, repoCorporaDir, "public/scenarios.jsonl"), publicBytes, 0o644},
		{filepath.Join(root, repoCorporaDir, "handshake/cases.jsonl"), handshakeBytes, 0o644},
		{filepath.Join(protectedRoot, protectedHiddenLines), hiddenBytes, 0o644},
		{filepath.Join(protectedRoot, protectedSealedLines), sealedBytes, 0o644},
		{filepath.Join(protectedRoot, protectedCanaryFile), append(inventoryBytes, '\n'), 0o644},
		{filepath.Join(protectedRoot, protectedPolicyFile), append(policyDocument, '\n'), 0o644},
		{ledgerPath, ledgerBytes, 0o644},
	}
	for _, tier := range []string{"public", "handshake", "hidden", "sealed"} {
		rendered, err := renderedJSON(manifests[tier])
		if err != nil {
			return err
		}
		files = append(files, generatedStateFile{
			filepath.Join(root, repoCorporaDir, tier, "manifest.json"), rendered, 0o644})
	}
	return replaceGeneratedState(files)
}

func readManifest(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

// VerifyAll regenerates every tier from the committed seeds and the protected
// secret, then reconciles all repo and protected artifacts byte-for-byte and
// every manifest field-for-field. Any mismatch blocks.
func VerifyAll(root, protectedRoot string) ([]Finding, error) {
	if err := os.MkdirAll(filepath.Dir(ProtectedLedgerPath(protectedRoot)), 0o755); err != nil {
		return nil, err
	}
	unlock, err := acquireFileLock(ProtectedLedgerPath(protectedRoot) + ".lock")
	if err != nil {
		return nil, fmt.Errorf("custodian ledger lock: %w", err)
	}
	defer unlock()
	return verifyAllLocked(root, protectedRoot)
}

func verifyAllLocked(root, protectedRoot string) ([]Finding, error) {
	var findings []Finding
	fail := func(code, path, detail string) {
		findings = append(findings, Finding{Code: code, Path: path, Detail: detail})
	}

	publicManifest, err := readManifest(filepath.Join(root, repoCorporaDir, "public/manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("public manifest: %w", err)
	}
	hiddenManifest, err := readManifest(filepath.Join(root, repoCorporaDir, "hidden/manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("hidden manifest: %w", err)
	}
	generator, _ := publicManifest["generator"].(map[string]any)
	publicSeed, _ := generator["public_seed"].(string)
	heldOutGenerator, _ := hiddenManifest["generator"].(map[string]any)
	epoch, epochOK := gateCounter(heldOutGenerator, "epoch")
	if !epochOK || epoch < 1 {
		return nil, fmt.Errorf("hidden manifest generator epoch is missing or non-integral")
	}

	secretRaw, err := os.ReadFile(filepath.Join(protectedRoot, protectedSecretFile))
	if err != nil {
		return nil, fmt.Errorf("protected master secret: %w", err)
	}
	input := GenerationInput{
		PublicSeed: publicSeed,
		Secret:     strings.TrimSpace(string(secretRaw)),
		Epoch:      epoch,
	}
	generated, err := GenerateAll(input)
	if err != nil {
		return nil, fmt.Errorf("regeneration: %w", err)
	}

	publicBytes, err := scenarioLines(generated.Public)
	if err != nil {
		return nil, err
	}
	handshakeBytes, err := handshakeLines(generated.Handshake)
	if err != nil {
		return nil, err
	}
	hiddenBytes, err := scenarioLines(generated.Hidden)
	if err != nil {
		return nil, err
	}
	sealedBytes, err := scenarioLines(generated.Sealed)
	if err != nil {
		return nil, err
	}

	compareFile := func(path string, want []byte, code string) {
		got, err := os.ReadFile(path)
		if err != nil {
			fail(code, path, err.Error())
			return
		}
		if !bytes.Equal(got, want) {
			fail(code, path, "content does not reconcile with deterministic regeneration")
		}
	}
	compareFile(filepath.Join(root, repoCorporaDir, "public/scenarios.jsonl"),
		publicBytes, "PUBLIC_CONTENT_MISMATCH")
	compareFile(filepath.Join(root, repoCorporaDir, "handshake/cases.jsonl"),
		handshakeBytes, "HANDSHAKE_CONTENT_MISMATCH")
	compareFile(filepath.Join(protectedRoot, protectedHiddenLines),
		hiddenBytes, "HIDDEN_CONTENT_MISMATCH")
	compareFile(filepath.Join(protectedRoot, protectedSealedLines),
		sealedBytes, "SEALED_CONTENT_MISMATCH")

	policyDocument, err := CustodianPolicyDocument(DefaultCustodianPolicy(), input.Epoch)
	if err != nil {
		return nil, err
	}
	compareFile(filepath.Join(protectedRoot, protectedPolicyFile),
		append(append([]byte{}, policyDocument...), '\n'), "CUSTODIAN_POLICY_MISMATCH")

	manifests, err := buildManifests(input, generated, publicBytes, handshakeBytes,
		hiddenBytes, sealedBytes, DigestSHA256(policyDocument))
	if err != nil {
		return nil, err
	}
	for tier, want := range manifests {
		path := filepath.Join(root, repoCorporaDir, tier, "manifest.json")
		got, err := readManifest(path)
		if err != nil {
			fail("MANIFEST_UNREADABLE", path, err.Error())
			continue
		}
		// A live run may record execution state (schema-validated
		// separately); the deterministic core must still reconcile exactly.
		got = manifestDeterministicCore(got)
		wantCanonical, err := canonicalizeJSONValue(manifestDeterministicCore(want))
		if err != nil {
			return nil, err
		}
		gotCanonical, err := canonicalizeJSONValue(got)
		if err != nil {
			fail("MANIFEST_NOT_CANONICALIZABLE", path, err.Error())
			continue
		}
		if !bytes.Equal(wantCanonical, gotCanonical) {
			fail("MANIFEST_MISMATCH", path,
				"manifest does not reconcile with deterministic regeneration")
		}
	}

	// Held-out bytes must never appear under the repository corpora tree.
	for _, tier := range []string{"hidden", "sealed"} {
		entries, err := os.ReadDir(filepath.Join(root, repoCorporaDir, tier))
		if err != nil {
			fail("HELD_OUT_DIR_UNREADABLE", tier, err.Error())
			continue
		}
		for _, entry := range entries {
			if entry.Name() != "manifest.json" {
				fail("HELD_OUT_LEAK", filepath.Join(repoCorporaDir, tier, entry.Name()),
					"held-out tier directories may contain only the manifest")
			}
		}
	}

	// Canary inventory must re-derive and canary tokens must not appear in
	// any public repo artifact.
	canaryRaw, err := os.ReadFile(filepath.Join(protectedRoot, protectedCanaryFile))
	if err != nil {
		fail("CANARY_INVENTORY_UNREADABLE", protectedCanaryFile, err.Error())
	} else {
		wantCanary, inventoryErr := buildCanaryInventory(input, generated)
		if inventoryErr != nil {
			return nil, inventoryErr
		}
		if !bytes.Equal(canaryRaw, append(wantCanary, '\n')) {
			fail("CANARY_INVENTORY_MISMATCH", protectedCanaryFile,
				"inventory does not reconcile with the active generation epoch")
		}
		// The leak scan covers every repository file (not just corpus
		// artifacts), skipping only .git and the quarantine store.
		for _, finding := range scanRepoForCanaryLeaks(root, generated.CanaryTokens) {
			fail(finding.Code, finding.Path, finding.Detail)
		}
		for id, token := range generated.CanaryTokens {
			if !bytes.Contains(canaryRaw, []byte(token)) || !bytes.Contains(canaryRaw, []byte(id)) {
				fail("CANARY_INVENTORY_MISMATCH", protectedCanaryFile,
					"inventory does not list derived canary "+id)
			}
		}
	}

	// The custodian ledger must chain-verify.
	ledgerRaw, err := os.ReadFile(filepath.Join(protectedRoot, protectedLedgerFile))
	if err != nil {
		fail("LEDGER_UNREADABLE", protectedLedgerFile, err.Error())
	} else if ledger, err := LoadLedger(ledgerRaw); err != nil {
		fail("LEDGER_INVALID", protectedLedgerFile, err.Error())
	} else {
		if ledger.Epoch() != input.Epoch {
			fail("LEDGER_EPOCH_MISMATCH", protectedLedgerFile, fmt.Sprintf(
				"ledger active epoch %d does not match manifest/policy/canary epoch %d",
				ledger.Epoch(), input.Epoch))
		}
		policy := DefaultCustodianPolicy()
		if ledger.policy != policy {
			fail("LEDGER_POLICY_MISMATCH", protectedLedgerFile,
				"ledger policy does not match the committed custodian policy")
		}
	}

	// The live portion of the evidence contract: recorded executions and
	// gate results must reconcile semantically and against protected
	// artifacts.
	liveFindings, err := VerifyLiveEvidence(root, protectedRoot)
	if err != nil {
		return nil, err
	}
	findings = append(findings, liveFindings...)

	return findings, nil
}

// manifestDeterministicCore strips the live-execution recording fields from a
// manifest so reconciliation compares the regenerable commitment: execution
// status and evidence are removed and the execution counters reset, while
// expected/selected/filtered, digests, commitments, custodian, and sealing
// remain load-bearing.
func manifestDeterministicCore(manifest map[string]any) map[string]any {
	core := map[string]any{}
	for key, value := range manifest {
		if key == "execution_status" || key == "execution_evidence" {
			continue
		}
		core[key] = value
	}
	if counts, isMap := core["counts"].(map[string]any); isMap {
		reset := map[string]any{}
		for key, value := range counts {
			reset[key] = value
		}
		for _, key := range []string{"executed", "passed", "failed", "skipped", "timed_out"} {
			reset[key] = 0
		}
		core["counts"] = reset
	}
	return core
}

// scanRepoForCanaryLeaks scans every regular file under the repository root
// for secret-derived canary tokens, skipping .git and the quarantine store.
// Any hit means held-out bytes escaped the protected boundary.
func scanRepoForCanaryLeaks(root string, tokens map[string]string) []Finding {
	var findings []Finding
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			findings = append(findings, Finding{Code: "CANARY_SCAN_UNREADABLE",
				Path: path, Detail: err.Error()})
			return nil
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".quarantine":
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			findings = append(findings, Finding{Code: "CANARY_SCAN_UNREADABLE",
				Path: path, Detail: readErr.Error()})
			return nil
		}
		for id, token := range tokens {
			if bytes.Contains(content, []byte(token)) {
				relative, relErr := filepath.Rel(root, path)
				if relErr != nil {
					relative = path
				}
				findings = append(findings, Finding{Code: "CANARY_LEAK", Path: relative,
					Detail: "repository file contains held-out canary " + id})
			}
		}
		return nil
	})
	return findings
}

// canonicalizeJSONValue renders any JSON-decoded value canonically,
// normalizing integral float64 values to integers.
func canonicalizeJSONValue(value any) ([]byte, error) {
	normalized, err := normalizeJSON(value)
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(normalized)
}

func normalizeJSON(value any) (any, error) {
	switch typed := value.(type) {
	case float64:
		asInt := int(typed)
		if float64(asInt) != typed {
			return nil, fmt.Errorf("non-integral number %v", typed)
		}
		return asInt, nil
	case map[string]any:
		out := map[string]any{}
		for k, v := range typed {
			normalized, err := normalizeJSON(v)
			if err != nil {
				return nil, err
			}
			out[k] = normalized
		}
		return out, nil
	case []any:
		out := make([]any, len(typed))
		for i, v := range typed {
			normalized, err := normalizeJSON(v)
			if err != nil {
				return nil, err
			}
			out[i] = normalized
		}
		return out, nil
	default:
		return value, nil
	}
}
