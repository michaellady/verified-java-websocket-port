// Package rustgate verifies the deterministic, dependency-free safe-Rust
// scaffold used by the WebSocket port.
package rustgate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const policyPath = "security/rust-scaffold-policy.json"

var requiredOfflineCommands = []string{
	"cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings",
	"cargo metadata --locked --offline --format-version 1",
	"cargo test --workspace --all-targets --all-features --locked --offline",
}

// Finding is one deterministic policy violation.
type Finding struct {
	Code   string `json:"code"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

// Report is the stable output of a scaffold verification.
type Report struct {
	OK       bool      `json:"ok"`
	Findings []Finding `json:"findings"`
}

type scaffoldPolicy struct {
	SchemaVersion             int      `json:"schema_version"`
	WorkspaceRoot             string   `json:"workspace_root"`
	LicensePath               string   `json:"license_path"`
	LicenseSPDX               string   `json:"license_spdx"`
	LicenseSHA256             string   `json:"license_sha256"`
	ToolchainPinPath          string   `json:"toolchain_pin_path"`
	ToolchainArtifactID       string   `json:"toolchain_artifact_id"`
	ToolchainVersion          string   `json:"toolchain_version"`
	DependencyUnsafeInventory string   `json:"dependency_unsafe_inventory"`
	OfflineCommands           []string `json:"offline_commands"`
}

type dependencyInventory struct {
	SchemaVersion     int                `json:"schema_version"`
	CargoLockPath     string             `json:"cargo_lock_path"`
	CargoLockSHA256   string             `json:"cargo_lock_sha256"`
	ExternalPackages  []inventoryPackage `json:"external_packages"`
	BuildScripts      []inventoryPath    `json:"build_scripts"`
	ProcMacroCrates   []string           `json:"proc_macro_crates"`
	BuildDependencies []inventoryPackage `json:"build_dependencies"`
}

type inventoryPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
	SHA256  string `json:"sha256"`
}

type inventoryPath struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type toolchainPins struct {
	SchemaVersion        string                `json:"schema_version"`
	Company              string                `json:"company"`
	Project              string                `json:"project"`
	LaboratoryID         string                `json:"laboratory_id"`
	GeneratedAt          string                `json:"generated_at"`
	ExecutionState       string                `json:"execution_state"`
	QualificationSandbox qualificationSandbox  `json:"qualification_sandbox"`
	Executables          []qualifiedExecutable `json:"executables"`
	Container            qualifiedContainer    `json:"container"`
}

type qualificationSandbox struct {
	RequiredRole    string   `json:"required_role"`
	RequestedAccess []string `json:"requested_access"`
	ForbiddenAccess []string `json:"forbidden_access"`
	Disposable      bool     `json:"disposable"`
	Secrets         string   `json:"secrets"`
	Publication     bool     `json:"publication"`
}

type qualifiedExecutable struct {
	ArtifactID                 string            `json:"artifact_id"`
	Platform                   string            `json:"platform"`
	Version                    string            `json:"version"`
	BinaryDigests              map[string]string `json:"binary_digests"`
	LockGraph                  []string          `json:"lock_graph"`
	SBOMComponentID            string            `json:"sbom_component_id"`
	VulnerabilityObservationID string            `json:"vulnerability_observation_id"`
	License                    string            `json:"license"`
	Provenance                 string            `json:"provenance"`
	MirrorOrReplay             string            `json:"mirror_or_replay"`
	ExpiresAt                  string            `json:"expires_at"`
	Rotation                   string            `json:"rotation"`
	Revocation                 string            `json:"revocation"`
	AssuranceMode              string            `json:"assurance_mode,omitempty"`
	QualificationStatus        string            `json:"qualification_status,omitempty"`
}

type qualifiedContainer struct {
	Reference                string `json:"reference"`
	Platform                 string `json:"platform"`
	ManifestDigest           string `json:"manifest_digest"`
	ConfigDigest             string `json:"config_digest"`
	CompressedLayerBytes     int64  `json:"compressed_layer_bytes"`
	FloatingTagSatisfiesGate bool   `json:"floating_tag_satisfies_gate"`
	Executed                 bool   `json:"executed"`
}

type crate struct {
	Member   string
	Name     string
	Version  string
	Manifest tomlDocument
}

type verifier struct {
	root     string
	options  Options
	findings []Finding
}

// Options are explicit runtime inputs that cannot be inferred from receipt
// syntax alone.
type Options struct {
	// ValidationTime is the caller-provided UTC clock observation used for
	// deterministic receipt-expiry validation.
	ValidationTime time.Time
	// ToolchainBinDir selects the installed rustc, rustdoc, and cargo binaries
	// whose bytes must match the intake receipt.
	ToolchainBinDir string
}

// Verify checks the Rust scaffold rooted at repositoryRoot. It performs only
// deterministic local reads; it never invokes Cargo, Rust, the network, or a
// sandbox.
func Verify(repositoryRoot string, options Options) Report {
	absRoot, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return Report{Findings: []Finding{{Code: "ROOT_INVALID", Path: ".", Detail: err.Error()}}}
	}
	canonicalRoot, err := filepath.EvalSymlinks(filepath.Clean(absRoot))
	if err != nil {
		return Report{Findings: []Finding{{Code: "ROOT_INVALID", Path: ".", Detail: err.Error()}}}
	}
	info, err := os.Stat(canonicalRoot)
	if err != nil || !info.IsDir() {
		detail := "repository root must be a readable directory"
		if err != nil {
			detail = err.Error()
		}
		return Report{Findings: []Finding{{Code: "ROOT_INVALID", Path: ".", Detail: detail}}}
	}
	v := &verifier{root: filepath.Clean(canonicalRoot), options: options}
	v.verify()
	sort.Slice(v.findings, func(i, j int) bool {
		left, right := v.findings[i], v.findings[j]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		return left.Detail < right.Detail
	})
	return Report{OK: len(v.findings) == 0, Findings: v.findings}
}

func (v *verifier) verify() {
	var policy scaffoldPolicy
	if !v.readJSON(policyPath, &policy, "POLICY_INVALID") {
		return
	}
	v.verifyPolicy(policy)
	v.verifyExecutionSurfaces()

	workspaceManifestPath := filepath.ToSlash(filepath.Join(policy.WorkspaceRoot, "Cargo.toml"))
	workspaceManifest, ok := v.readTOML(workspaceManifestPath)
	if !ok {
		return
	}
	members, ok := workspaceManifest.stringArray("workspace", "members")
	if !ok || len(members) == 0 {
		v.add("WORKSPACE_MEMBERS_INVALID", workspaceManifestPath, "workspace.members must be a non-empty literal string array")
		return
	}
	workspaceVersion, _ := workspaceManifest.stringValue("workspace.package", "version")
	workspaceRustVersion, _ := workspaceManifest.stringValue("workspace.package", "rust-version")
	workspaceLicense, _ := workspaceManifest.stringValue("workspace.package", "license")
	if lint, ok := workspaceManifest.stringValue("workspace.lints.rust", "unsafe_code"); !ok || lint != "forbid" {
		v.add("WORKSPACE_UNSAFE_LINT_MISSING", workspaceManifestPath, "[workspace.lints.rust] unsafe_code must equal \"forbid\"")
	}

	crates := v.verifyWorkspaceMembers(policy.WorkspaceRoot, members, workspaceVersion, workspaceRustVersion, workspaceLicense)
	v.verifyWorkspaceManifestClosure(policy.WorkspaceRoot, members)
	v.verifyLicense(policy, workspaceLicense)
	v.verifyToolchain(policy, workspaceRustVersion)
	v.verifyDependencies(policy, workspaceManifestPath, crates)
	v.verifySources(policy.WorkspaceRoot, crates)
}

func (v *verifier) verifyPolicy(policy scaffoldPolicy) {
	if policy.SchemaVersion != 1 {
		v.add("POLICY_INVALID", policyPath, "schema_version must equal 1")
	}
	for field, value := range map[string]string{
		"workspace_root":              policy.WorkspaceRoot,
		"license_path":                policy.LicensePath,
		"license_spdx":                policy.LicenseSPDX,
		"license_sha256":              policy.LicenseSHA256,
		"toolchain_pin_path":          policy.ToolchainPinPath,
		"toolchain_artifact_id":       policy.ToolchainArtifactID,
		"toolchain_version":           policy.ToolchainVersion,
		"dependency_unsafe_inventory": policy.DependencyUnsafeInventory,
	} {
		if strings.TrimSpace(value) == "" {
			v.add("POLICY_INVALID", policyPath, field+" must be non-empty")
		}
	}
	actual := append([]string(nil), policy.OfflineCommands...)
	sort.Strings(actual)
	if !equalStrings(actual, requiredOfflineCommands) {
		v.add("OFFLINE_REPRODUCIBILITY_METADATA_INVALID", policyPath,
			"offline_commands must be the exact locked/offline metadata, test, and Clippy command set")
	}
}

func (v *verifier) verifyWorkspaceMembers(workspaceRoot string, members []string, workspaceVersion, workspaceRustVersion, workspaceLicense string) []crate {
	seen := make(map[string]bool)
	crates := make([]crate, 0, len(members))
	for _, rawMember := range members {
		member := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rawMember)))
		if member == "." || member == ".." || strings.HasPrefix(member, "../") || filepath.IsAbs(rawMember) || strings.ContainsAny(rawMember, "*?[") {
			v.add("WORKSPACE_MEMBER_INVALID", filepath.ToSlash(filepath.Join(workspaceRoot, "Cargo.toml")), "workspace member must be a unique literal relative directory: "+rawMember)
			continue
		}
		if seen[member] {
			v.add("WORKSPACE_MEMBER_INVALID", filepath.ToSlash(filepath.Join(workspaceRoot, "Cargo.toml")), "duplicate workspace member: "+member)
			continue
		}
		seen[member] = true
		manifestPath := filepath.ToSlash(filepath.Join(workspaceRoot, member, "Cargo.toml"))
		manifest, ok := v.readTOML(manifestPath)
		if !ok {
			continue
		}
		v.verifyNoCustomBuild(manifestPath, manifest)
		name, nameOK := manifest.stringValue("package", "name")
		version, versionOK := inheritedString(manifest, "package", "version", workspaceVersion)
		rustVersion, rustOK := inheritedString(manifest, "package", "rust-version", workspaceRustVersion)
		license, licenseOK := inheritedString(manifest, "package", "license", workspaceLicense)
		if !nameOK || name == "" || !versionOK || version == "" {
			v.add("PACKAGE_IDENTITY_INVALID", manifestPath, "package name and resolved version must be non-empty")
		}
		if !rustOK || rustVersion != workspaceRustVersion {
			v.add("TOOLCHAIN_MISMATCH", manifestPath, "package rust-version must inherit or equal the workspace rust-version")
		}
		if !licenseOK || license != workspaceLicense {
			v.add("LICENSE_MISMATCH", manifestPath, "package license must inherit or equal the workspace SPDX expression")
		}
		if optIn, ok := manifest.boolValue("lints", "workspace"); !ok || !optIn {
			v.add("PACKAGE_LINT_OPT_IN_MISSING", manifestPath, "[lints] workspace must equal true")
		}
		crates = append(crates, crate{Member: member, Name: name, Version: version, Manifest: manifest})
	}
	return crates
}

func (v *verifier) verifyNoCustomBuild(path string, document tomlDocument) {
	if _, exists := document.rawValueAt("package", 0, "build"); exists {
		v.add("BUILD_SCRIPT_NOT_ALLOWED", path, "[package] build is forbidden; build scripts are not part of the dependency-free host path")
	}
}

func (v *verifier) verifyExecutionSurfaces() {
	err := filepath.WalkDir(v.root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == v.root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.Name() == "build.rs" || entry.Name() == ".cargo" {
				relative, _ := filepath.Rel(v.root, path)
				v.add("UNSAFE_PATH", filepath.ToSlash(relative), "Cargo execution inputs may not contain symlink components")
			}
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "target") {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(v.root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.Name() == "build.rs" {
			v.add("BUILD_SCRIPT_NOT_ALLOWED", relative, "build.rs is forbidden anywhere in the repository")
		}
		if (entry.Name() == "config" || entry.Name() == "config.toml") && filepath.Base(filepath.Dir(path)) == ".cargo" {
			v.add("CARGO_CONFIG_NOT_ALLOWED", relative, "repository Cargo configuration and executable hooks are forbidden")
		}
		return nil
	})
	if err != nil {
		v.add("WORKSPACE_UNREADABLE", ".", err.Error())
	}
}

func (v *verifier) verifyWorkspaceManifestClosure(workspaceRoot string, members []string) {
	want := map[string]bool{"Cargo.toml": true}
	for _, member := range members {
		want[filepath.ToSlash(filepath.Join(filepath.Clean(filepath.FromSlash(member)), "Cargo.toml"))] = true
	}
	base, ok := v.safePath(workspaceRoot)
	if !ok {
		return
	}
	found := make(map[string]bool)
	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && entry.Name() == "target" {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			rel, _ := filepath.Rel(v.root, path)
			v.add("UNSAFE_PATH", filepath.ToSlash(rel), "symlinks are not allowed in the Rust workspace")
			return nil
		}
		if entry.Name() == "Cargo.toml" {
			rel, err := filepath.Rel(base, path)
			if err != nil {
				return err
			}
			found[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		v.add("WORKSPACE_UNREADABLE", workspaceRoot, err.Error())
		return
	}
	for path := range found {
		if !want[path] {
			v.add("WORKSPACE_MEMBER_MISMATCH", filepath.ToSlash(filepath.Join(workspaceRoot, path)), "manifest is not declared by workspace.members")
		}
	}
	for path := range want {
		if !found[path] {
			v.add("WORKSPACE_MEMBER_MISMATCH", filepath.ToSlash(filepath.Join(workspaceRoot, path)), "declared workspace manifest is missing")
		}
	}
}

func (v *verifier) verifyLicense(policy scaffoldPolicy, workspaceLicense string) {
	if workspaceLicense != policy.LicenseSPDX {
		v.add("LICENSE_MISMATCH", filepath.ToSlash(filepath.Join(policy.WorkspaceRoot, "Cargo.toml")), "workspace package license does not match policy SPDX expression")
	}
	body, ok := v.readRegular(policy.LicensePath)
	if ok && digest(body) != policy.LicenseSHA256 {
		v.add("LICENSE_DIGEST_MISMATCH", policy.LicensePath, "license bytes do not match the policy digest")
	}
}

func (v *verifier) verifyToolchain(policy scaffoldPolicy, workspaceRustVersion string) {
	if workspaceRustVersion != policy.ToolchainVersion {
		v.add("TOOLCHAIN_MISMATCH", filepath.ToSlash(filepath.Join(policy.WorkspaceRoot, "Cargo.toml")), "workspace rust-version does not match policy")
	}
	toolchainPath := filepath.ToSlash(filepath.Join(policy.WorkspaceRoot, "rust-toolchain.toml"))
	document, ok := v.readTOML(toolchainPath)
	if ok {
		channel, exists := document.stringValue("toolchain", "channel")
		if !exists || channel != policy.ToolchainVersion || channel != workspaceRustVersion {
			v.add("TOOLCHAIN_MISMATCH", toolchainPath, "toolchain channel, policy version, and workspace rust-version must agree exactly")
		}
	}
	var pins toolchainPins
	if !v.readJSON(policy.ToolchainPinPath, &pins, "TOOLCHAIN_PIN_INVALID") {
		return
	}
	if pins.SchemaVersion != "1.0.0" {
		v.add("TOOLCHAIN_PIN_INVALID", policy.ToolchainPinPath, "canonical toolchain pin schema_version must equal 1.0.0")
	}
	matched := 0
	var selected qualifiedExecutable
	for _, executable := range pins.Executables {
		if executable.ArtifactID == policy.ToolchainArtifactID && executable.Version == policy.ToolchainVersion {
			matched++
			selected = executable
			if !qualifiedRustExecutable(executable) {
				v.add("TOOLCHAIN_PIN_MISMATCH", policy.ToolchainPinPath, "qualified Rust executable record is incomplete, revoked, or has malformed binary digests")
			}
		}
	}
	if matched != 1 {
		v.add("TOOLCHAIN_PIN_MISMATCH", policy.ToolchainPinPath, "exactly one qualified executable must match the policy artifact id/version")
		return
	}
	v.verifyToolchainRuntime(policy.ToolchainPinPath, pins.GeneratedAt, selected)
}

func (v *verifier) verifyToolchainRuntime(receiptPath, generatedAt string, executable qualifiedExecutable) {
	if v.options.ValidationTime.IsZero() {
		v.add("VALIDATION_TIME_INVALID", receiptPath, "an explicit nonzero validation timestamp is required")
		return
	}
	generated, err := time.Parse(time.RFC3339, generatedAt)
	if err != nil {
		v.add("TOOLCHAIN_PIN_INVALID", receiptPath, "generated_at must be an RFC3339 timestamp")
		return
	}
	expires, err := time.Parse(time.RFC3339, executable.ExpiresAt)
	if err != nil {
		v.add("TOOLCHAIN_PIN_INVALID", receiptPath, "expires_at must be an RFC3339 timestamp")
		return
	}
	validationTime := v.options.ValidationTime.UTC()
	if validationTime.Before(generated) {
		v.add("VALIDATION_TIME_INVALID", receiptPath, "validation timestamp predates receipt generation")
	}
	if !validationTime.Before(expires) {
		v.add("TOOLCHAIN_PIN_EXPIRED", receiptPath, "selected Rust toolchain receipt is expired at the validation timestamp")
	}

	if strings.TrimSpace(v.options.ToolchainBinDir) == "" {
		v.add("TOOLCHAIN_BINARY_MISMATCH", receiptPath, "an installed toolchain bin directory is required")
		return
	}
	for _, binary := range []struct {
		name       string
		receiptKey string
	}{
		{name: "rustc", receiptKey: "rustc/bin/rustc"},
		{name: "rustdoc", receiptKey: "rustc/bin/rustdoc"},
		{name: "cargo", receiptKey: "cargo/bin/cargo"},
	} {
		path := filepath.Join(v.options.ToolchainBinDir, binary.name)
		body, ok := v.readInstalledExecutable(path, receiptPath)
		if !ok {
			continue
		}
		if digest(body) != executable.BinaryDigests[binary.receiptKey] {
			v.add("TOOLCHAIN_BINARY_MISMATCH", receiptPath, binary.name+" bytes do not match the canonical intake receipt")
		}
	}
}

func (v *verifier) readInstalledExecutable(path, receiptPath string) ([]byte, bool) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		v.add("TOOLCHAIN_BINARY_MISMATCH", receiptPath, err.Error())
		return nil, false
	}
	canonicalPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		v.add("TOOLCHAIN_BINARY_MISMATCH", receiptPath, err.Error())
		return nil, false
	}
	if filepath.Clean(absPath) != filepath.Clean(canonicalPath) {
		v.add("UNSAFE_PATH", receiptPath, "installed toolchain path contains a symlink component: "+path)
		return nil, false
	}
	info, err := os.Lstat(canonicalPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		v.add("TOOLCHAIN_BINARY_MISMATCH", receiptPath, "installed toolchain binary must be a regular executable: "+path)
		return nil, false
	}
	body, err := os.ReadFile(canonicalPath)
	if err != nil {
		v.add("TOOLCHAIN_BINARY_MISMATCH", receiptPath, err.Error())
		return nil, false
	}
	return body, true
}

func qualifiedRustExecutable(executable qualifiedExecutable) bool {
	if executable.Platform != "aarch64-apple-darwin" || executable.Revocation != "ACTIVE_AT_SNAPSHOT" ||
		len(executable.LockGraph) == 0 || executable.SBOMComponentID == "" ||
		executable.VulnerabilityObservationID == "" || executable.License == "" ||
		executable.Provenance == "" || executable.MirrorOrReplay == "" ||
		executable.ExpiresAt == "" || executable.Rotation == "" {
		return false
	}
	required := []string{"rustc/bin/rustc", "rustc/bin/rustdoc", "cargo/bin/cargo"}
	if len(executable.BinaryDigests) != len(required) {
		return false
	}
	for _, path := range required {
		if !validSHA256(executable.BinaryDigests[path]) {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func (v *verifier) verifyDependencies(policy scaffoldPolicy, workspaceManifestPath string, crates []crate) {
	var inventory dependencyInventory
	if !v.readJSON(policy.DependencyUnsafeInventory, &inventory, "DEPENDENCY_INVENTORY_INVALID") {
		return
	}
	if inventory.SchemaVersion != 1 {
		v.add("DEPENDENCY_INVENTORY_INVALID", policy.DependencyUnsafeInventory, "schema_version must equal 1")
	}
	if len(inventory.ExternalPackages)+len(inventory.BuildScripts)+len(inventory.ProcMacroCrates)+len(inventory.BuildDependencies) != 0 {
		v.add("DEPENDENCY_UNSAFE_INVENTORY_NOT_EMPTY", policy.DependencyUnsafeInventory, "US-009 requires an explicitly empty dependency-unsafe inventory")
	}
	expectedLockPath := filepath.ToSlash(filepath.Join(policy.WorkspaceRoot, "Cargo.lock"))
	if inventory.CargoLockPath != expectedLockPath {
		v.add("DEPENDENCY_INVENTORY_INVALID", policy.DependencyUnsafeInventory, "cargo_lock_path must identify the workspace lockfile")
	}
	lockBody, lockOK := v.readRegular(expectedLockPath)
	if !lockOK {
		return
	}
	if digest(lockBody) != inventory.CargoLockSHA256 {
		v.add("LOCKFILE_DIGEST_MISMATCH", expectedLockPath, "Cargo.lock bytes do not match the dependency inventory binding")
	}
	lock, err := parseTOML(lockBody)
	if err != nil {
		v.add("LOCKFILE_INVALID", expectedLockPath, err.Error())
		return
	}
	version, ok := lock.integerValue("", "version")
	if !ok || version != 4 {
		v.add("LOCKFILE_INVALID", expectedLockPath, "Cargo.lock version must equal 4")
	}
	wantPackages := make(map[string]string, len(crates))
	for _, item := range crates {
		wantPackages[item.Name] = item.Version
	}
	gotPackages := lock.packageIdentities()
	if !equalStringMap(wantPackages, gotPackages) {
		v.add("LOCKFILE_PACKAGE_MISMATCH", expectedLockPath, fmt.Sprintf("lock packages %v do not equal workspace packages %v", gotPackages, wantPackages))
	}
	workspaceManifest, ok := v.readTOML(workspaceManifestPath)
	if ok {
		v.verifyDependencyTables(workspaceManifestPath, workspaceManifest)
	}
	for _, item := range crates {
		manifestPath := filepath.ToSlash(filepath.Join(policy.WorkspaceRoot, item.Member, "Cargo.toml"))
		v.verifyDependencyTables(manifestPath, item.Manifest)
		if procMacro, exists := item.Manifest.boolValue("lib", "proc-macro"); exists && procMacro {
			v.add("PROC_MACRO_NOT_ALLOWED", manifestPath, "US-009 first-party crates may not be proc macros")
		}
		buildPath := filepath.ToSlash(filepath.Join(policy.WorkspaceRoot, item.Member, "build.rs"))
		if v.regularFileExists(buildPath) {
			v.add("BUILD_SCRIPT_NOT_ALLOWED", buildPath, "US-009 requires an empty build-script inventory")
		}
	}
}

func (v *verifier) verifyDependencyTables(path string, document tomlDocument) {
	for _, entry := range document.entries {
		section := entry.Section
		if section == "dependencies" || section == "dev-dependencies" || section == "build-dependencies" || strings.HasSuffix(section, ".dependencies") || strings.HasSuffix(section, ".dev-dependencies") || strings.HasSuffix(section, ".build-dependencies") {
			code := "DEPENDENCY_NOT_ALLOWED"
			if section == "build-dependencies" || strings.HasSuffix(section, ".build-dependencies") {
				code = "BUILD_DEPENDENCY_NOT_ALLOWED"
			}
			v.add(code, path, fmt.Sprintf("dependency %q appears in [%s]", entry.Key, section))
		}
	}
}

func (v *verifier) verifySources(workspaceRoot string, crates []crate) {
	for _, item := range crates {
		crateRoot := filepath.ToSlash(filepath.Join(workspaceRoot, item.Member))
		roots := sourceRoots(item.Manifest)
		for _, directory := range []string{"tests", "examples", "benches"} {
			pattern := filepath.Join(v.root, filepath.FromSlash(crateRoot), directory, "*.rs")
			matches, _ := filepath.Glob(pattern)
			for _, match := range matches {
				relative, err := filepath.Rel(filepath.Join(v.root, filepath.FromSlash(crateRoot)), match)
				if err == nil {
					roots = append(roots, filepath.ToSlash(relative))
				}
			}
		}
		sort.Strings(roots)
		for _, relative := range roots {
			path := filepath.ToSlash(filepath.Join(crateRoot, relative))
			body, ok := v.readRegular(path)
			if ok && !bytes.Contains(body, []byte("#![forbid(unsafe_code)]")) {
				v.add("SOURCE_UNSAFE_ATTRIBUTE_MISSING", path, "every first-party crate target root must contain the literal #![forbid(unsafe_code)] attribute")
			}
		}
		sourceDir := filepath.ToSlash(filepath.Join(crateRoot, "src"))
		base, ok := v.safePath(sourceDir)
		if !ok {
			continue
		}
		err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				rel, _ := filepath.Rel(v.root, path)
				v.add("UNSAFE_PATH", filepath.ToSlash(rel), "symlinks are not allowed in production Rust source")
				return nil
			}
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".rs" {
				return nil
			}
			rel, _ := filepath.Rel(v.root, path)
			relPath := filepath.ToSlash(rel)
			body, ok := v.readRegular(relPath)
			if ok {
				v.scanProductionSource(relPath, body)
			}
			return nil
		})
		if err != nil {
			v.add("SOURCE_UNREADABLE", sourceDir, err.Error())
		}
	}
}

func (v *verifier) scanProductionSource(path string, body []byte) {
	tokens := rustCodeTokens(body)
	for index, token := range tokens {
		if (token == "todo" || token == "unimplemented" || token == "panic") && tokenAt(tokens, index+1) == "!" {
			v.add("PROTOCOL_STUB", path, token+"! is not allowed in production protocol source")
		}
		if token == "Fn" || token == "FnMut" || token == "FnOnce" || (token == "fn" && tokenAt(tokens, index+1) == "(") {
			v.add("CALLBACK_SURFACE", path, "callback surface "+token+" is forbidden in the Sans-I/O core")
		}
		if token != "std" {
			continue
		}
		if allowedMPSCImport(path, tokens, index) {
			continue
		}
		v.add("FORBIDDEN_CORE_SURFACE", path, "explicit std access is forbidden except the exact use std::sync::mpsc; import in connection-core/src/channel.rs")
	}
}

func allowedMPSCImport(path string, tokens []string, index int) bool {
	if !strings.HasSuffix(filepath.ToSlash(path), "/connection-core/src/channel.rs") {
		return false
	}
	return tokenAt(tokens, index-1) == "use" &&
		tokenAt(tokens, index+1) == "::" &&
		tokenAt(tokens, index+2) == "sync" &&
		tokenAt(tokens, index+3) == "::" &&
		tokenAt(tokens, index+4) == "mpsc" &&
		tokenAt(tokens, index+5) == ";"
}

func sourceRoots(manifest tomlDocument) []string {
	roots := make(map[string]bool)
	if path, ok := manifest.stringValue("lib", "path"); ok {
		roots[path] = true
	} else {
		roots["src/lib.rs"] = true
	}
	if manifest.hasSection("bin") {
		for _, instance := range manifest.sectionInstances("bin") {
			if path, ok := manifest.stringValueAt("bin", instance, "path"); ok {
				roots[path] = true
			}
		}
	}
	for _, section := range []string{"test", "example", "bench"} {
		for _, instance := range manifest.sectionInstances(section) {
			if path, ok := manifest.stringValueAt(section, instance, "path"); ok {
				roots[path] = true
			}
		}
	}
	result := make([]string, 0, len(roots))
	for root := range roots {
		result = append(result, filepath.ToSlash(filepath.Clean(filepath.FromSlash(root))))
	}
	sort.Strings(result)
	return result
}

func inheritedString(document tomlDocument, section, key, inherited string) (string, bool) {
	if value, ok := document.stringValue(section, key); ok {
		return value, true
	}
	if value, ok := document.boolValue(section, key+".workspace"); ok && value {
		return inherited, true
	}
	return "", false
}

func (v *verifier) readTOML(relative string) (tomlDocument, bool) {
	body, ok := v.readRegular(relative)
	if !ok {
		return tomlDocument{}, false
	}
	document, err := parseTOML(body)
	if err != nil {
		v.add("TOML_INVALID", relative, err.Error())
		return tomlDocument{}, false
	}
	return document, true
}

func (v *verifier) readJSON(relative string, destination any, code string) bool {
	body, ok := v.readRegular(relative)
	if !ok {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		v.add(code, relative, err.Error())
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		v.add(code, relative, "document must contain exactly one JSON value")
		return false
	}
	return true
}

func (v *verifier) readRegular(relative string) ([]byte, bool) {
	path, ok := v.safePath(relative)
	if !ok {
		return nil, false
	}
	info, err := os.Lstat(path)
	if err != nil {
		v.add("FILE_UNREADABLE", filepath.ToSlash(relative), err.Error())
		return nil, false
	}
	if !info.Mode().IsRegular() {
		v.add("UNSAFE_PATH", filepath.ToSlash(relative), "required input must be a regular file")
		return nil, false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		v.add("FILE_UNREADABLE", filepath.ToSlash(relative), err.Error())
		return nil, false
	}
	return body, true
}

func (v *verifier) regularFileExists(relative string) bool {
	path, ok := v.safePath(relative)
	if !ok {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func (v *verifier) safePath(relative string) (string, bool) {
	if filepath.IsAbs(relative) {
		v.add("UNSAFE_PATH", filepath.ToSlash(relative), "absolute paths are not allowed")
		return "", false
	}
	clean := filepath.Clean(filepath.FromSlash(relative))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		v.add("UNSAFE_PATH", filepath.ToSlash(relative), "path escapes repository root")
		return "", false
	}
	path := filepath.Join(v.root, clean)
	contained, err := filepath.Rel(v.root, path)
	if err != nil || contained == ".." || strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
		v.add("UNSAFE_PATH", filepath.ToSlash(relative), "path escapes canonical repository root")
		return "", false
	}
	current := v.root
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				break
			}
			v.add("UNSAFE_PATH", filepath.ToSlash(relative), err.Error())
			return "", false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			v.add("UNSAFE_PATH", filepath.ToSlash(relative), "path contains symlink component "+component)
			return "", false
		}
	}
	return path, true
}

func (v *verifier) add(code, path, detail string) {
	v.findings = append(v.findings, Finding{Code: code, Path: filepath.ToSlash(path), Detail: detail})
}

func digest(body []byte) string {
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

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func tokenAt(tokens []string, index int) string {
	if index < 0 || index >= len(tokens) {
		return ""
	}
	return tokens[index]
}
