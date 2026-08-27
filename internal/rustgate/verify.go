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
	Artifacts []struct {
		ArtifactID string `json:"artifact_id"`
		Version    string `json:"version"`
	} `json:"artifacts"`
}

type crate struct {
	Member   string
	Name     string
	Version  string
	Manifest tomlDocument
}

type verifier struct {
	root     string
	findings []Finding
}

// Verify checks the Rust scaffold rooted at repositoryRoot. It performs only
// deterministic local reads; it never invokes Cargo, Rust, the network, or a
// sandbox.
func Verify(repositoryRoot string) Report {
	absRoot, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return Report{Findings: []Finding{{Code: "ROOT_INVALID", Path: ".", Detail: err.Error()}}}
	}
	v := &verifier{root: filepath.Clean(absRoot)}
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
	matched := false
	for _, artifact := range pins.Artifacts {
		if artifact.ArtifactID == policy.ToolchainArtifactID && artifact.Version == policy.ToolchainVersion {
			matched = true
		}
	}
	if !matched {
		v.add("TOOLCHAIN_PIN_MISMATCH", policy.ToolchainPinPath, "qualified artifact id/version does not match scaffold policy")
	}
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
		if token != "std" || tokenAt(tokens, index+1) != "::" {
			continue
		}
		next := tokenAt(tokens, index+2)
		if forbiddenStdModule(next) {
			v.add("FORBIDDEN_CORE_SURFACE", path, "std::"+next+" is forbidden in the Sans-I/O core")
		} else if next == "{" {
			for cursor := index + 3; cursor < len(tokens) && tokens[cursor] != "}" && tokens[cursor] != ";"; cursor++ {
				if forbiddenStdModule(tokens[cursor]) {
					v.add("FORBIDDEN_CORE_SURFACE", path, "std::{"+tokens[cursor]+"} is forbidden in the Sans-I/O core")
				}
			}
		}
	}
}

func forbiddenStdModule(token string) bool {
	switch token {
	case "fs", "io", "net", "process", "thread", "time":
		return true
	default:
		return false
	}
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
	return filepath.Join(v.root, clean), true
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
