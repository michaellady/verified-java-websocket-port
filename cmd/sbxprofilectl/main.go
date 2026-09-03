// Command sbxprofilectl validates and renders the repository's blocked Docker
// SBX agent profiles. It never creates, starts, stops, or removes a sandbox.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const catalogPath = "sbx/profiles.json"

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
)

type catalog struct {
	SchemaVersion           string            `json:"schema_version"`
	ObservedAt              string            `json:"observed_at"`
	InstalledSBXVersion     string            `json:"installed_sbx_version"`
	MinimumStableSBXVersion string            `json:"minimum_stable_sbx_version"`
	LaunchReady             bool              `json:"launch_ready"`
	ContractPath            string            `json:"contract_path"`
	ContractSHA256          string            `json:"contract_sha256"`
	KitFilesSHA256          map[string]string `json:"kit_files_sha256"`
	AMD64BootstrapCommand   string            `json:"amd64_bootstrap_command"`
	Profiles                []profile         `json:"profiles"`
}

type profile struct {
	ID                string   `json:"id"`
	Agent             string   `json:"agent"`
	Lane              string   `json:"lane"`
	Platform          string   `json:"platform"`
	TemplateIndex     string   `json:"template_index"`
	TemplateManifest  string   `json:"template_manifest"`
	TemplateReference string   `json:"template_reference"`
	SandboxName       string   `json:"sandbox_name"`
	CacheNamespace    string   `json:"cache_namespace"`
	Kits              []string `json:"kits"`
	WorkspaceMode     string   `json:"workspace_mode"`
	SharedSkills      bool     `json:"shared_skills"`
	HostStdioMCP      bool     `json:"host_stdio_mcp"`
	StaticMCPServers  []string `json:"static_mcp_servers"`
	PublishedPorts    []string `json:"published_ports"`
	BootstrapCommand  string   `json:"bootstrap_command"`
	LaunchStatus      string   `json:"launch_status"`
	Blockers          []string `json:"blockers"`
	LaunchArgv        []string `json:"launch_argv"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		usage(stderr)
		return 2
	}
	flags := flag.NewFlagSet(arguments[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	profileID := flags.String("id", "", "profile identifier")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	value, err := loadCatalog(*root)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	switch arguments[0] {
	case "verify":
		return encode(stdout, struct {
			OK          bool `json:"ok"`
			Profiles    int  `json:"profiles"`
			LaunchReady bool `json:"launch_ready"`
		}{OK: true, Profiles: len(value.Profiles), LaunchReady: value.LaunchReady})
	case "show-command":
		if *profileID == "" {
			fmt.Fprintln(stderr, "show-command requires --id")
			return 2
		}
		for _, item := range value.Profiles {
			if item.ID == *profileID {
				fmt.Fprintf(stdout, "# %s: %s\n", item.LaunchStatus, strings.Join(item.Blockers, ","))
				fmt.Fprintln(stdout, strings.Join(item.LaunchArgv, " "))
				return 0
			}
		}
		fmt.Fprintf(stderr, "unknown profile %q\n", *profileID)
		return 1
	default:
		usage(stderr)
		return 2
	}
}

func usage(output io.Writer) {
	fmt.Fprintln(output, "usage: sbxprofilectl verify --root DIR")
	fmt.Fprintln(output, "       sbxprofilectl show-command --root DIR --id PROFILE")
}

func encode(output io.Writer, value any) int {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return 1
	}
	return 0
}

func loadCatalog(root string) (catalog, error) {
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return catalog{}, err
	}
	rootPath, err = filepath.EvalSymlinks(rootPath)
	if err != nil {
		return catalog{}, fmt.Errorf("resolve repository root: %w", err)
	}
	profilePath, err := resolveRegularFile(rootPath, catalogPath)
	if err != nil {
		return catalog{}, fmt.Errorf("profile catalog: %w", err)
	}
	body, err := os.ReadFile(profilePath)
	if err != nil {
		return catalog{}, fmt.Errorf("read profile catalog: %w", err)
	}
	var value catalog
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return catalog{}, fmt.Errorf("decode profile catalog: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return catalog{}, err
	}
	if err := validateCatalog(rootPath, value); err != nil {
		return catalog{}, err
	}
	return value, nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing profile data: %w", err)
	}
	return errors.New("profile catalog contains multiple JSON values")
}

func validateCatalog(root string, value catalog) error {
	if value.SchemaVersion != "1.0.0" {
		return errors.New("profile catalog schema_version must be 1.0.0")
	}
	if value.LaunchReady {
		return errors.New("profile catalog must remain launch_ready=false while blockers exist")
	}
	if !versionLess(value.InstalledSBXVersion, value.MinimumStableSBXVersion) {
		return errors.New("profile catalog no longer describes an installed SBX below the stable isolation baseline")
	}
	if err := verifyFileDigest(root, value.ContractPath, value.ContractSHA256); err != nil {
		return fmt.Errorf("contract: %w", err)
	}
	if len(value.Profiles) != 6 {
		return fmt.Errorf("profile catalog must contain six agent/lane profiles, got %d", len(value.Profiles))
	}

	wantMatrix := map[string]bool{
		"codex/development": false, "claude/development": false, "muse-code/development": false,
		"codex/authoritative-formal": false, "claude/authoritative-formal": false, "muse-code/authoritative-formal": false,
	}
	seenID := make(map[string]bool)
	seenSandbox := make(map[string]bool)
	seenCache := make(map[string]bool)
	for _, item := range value.Profiles {
		if err := validateProfile(root, value, item); err != nil {
			return fmt.Errorf("profile %s: %w", item.ID, err)
		}
		matrixKey := item.Agent + "/" + item.Lane
		if _, ok := wantMatrix[matrixKey]; !ok || wantMatrix[matrixKey] {
			return fmt.Errorf("duplicate or unexpected agent/lane %s", matrixKey)
		}
		wantMatrix[matrixKey] = true
		if seenID[item.ID] || seenSandbox[item.SandboxName] || seenCache[item.CacheNamespace] {
			return errors.New("profile IDs, sandbox names, and cache namespaces must be unique")
		}
		seenID[item.ID], seenSandbox[item.SandboxName], seenCache[item.CacheNamespace] = true, true, true
	}
	if err := validateKitBindings(root, value); err != nil {
		return err
	}
	return nil
}

func validateKitBindings(root string, value catalog) error {
	wantKits := make(map[string]bool)
	for _, item := range value.Profiles {
		for _, kit := range item.Kits {
			wantKits[kit] = true
		}
	}
	seenFiles := make(map[string]bool)
	for kit := range wantKits {
		directory, err := resolveDirectory(root, kit)
		if err != nil {
			return fmt.Errorf("kit %s: %w", kit, err)
		}
		if err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("kit path %s is a symlink", path)
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf("kit path %s is not a regular file", path)
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			digest, ok := value.KitFilesSHA256[relative]
			if !ok {
				return fmt.Errorf("kit file %s has no digest binding", relative)
			}
			if err := verifyFileDigest(root, relative, digest); err != nil {
				return fmt.Errorf("kit file %s: %w", relative, err)
			}
			seenFiles[relative] = true
			return nil
		}); err != nil {
			return err
		}
	}
	if len(value.KitFilesSHA256) != len(seenFiles) {
		return errors.New("kit_files_sha256 must bind every and only referenced kit file")
	}
	return nil
}

func verifyFileDigest(root, relative, expected string) error {
	if !digestPattern.MatchString(expected) {
		return errors.New("expected SHA-256 must be a lowercase sha256 digest")
	}
	path, err := resolveRegularFile(root, relative)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	if "sha256:"+hex.EncodeToString(digest[:]) != expected {
		return errors.New("content digest does not match")
	}
	return nil
}

func validateProfile(root string, catalogValue catalog, item profile) error {
	if !idPattern.MatchString(item.ID) || !idPattern.MatchString(item.SandboxName) || !idPattern.MatchString(item.CacheNamespace) {
		return errors.New("id, sandbox_name, and cache_namespace must be bounded lowercase identifiers")
	}
	if item.WorkspaceMode != "clone" || item.SharedSkills || item.HostStdioMCP || len(item.StaticMCPServers) != 0 || len(item.PublishedPorts) != 0 {
		return errors.New("least-privilege workspace, skill, MCP, or port invariant failed")
	}
	if item.LaunchStatus != "BLOCKED" || len(item.Blockers) == 0 {
		return errors.New("profile must remain BLOCKED with explicit blockers")
	}
	if !hasString(item.Blockers, "SBX_STABLE_ISOLATION_BASELINE_UNMET") {
		return errors.New("stable SBX isolation blocker is required")
	}
	if !digestPattern.MatchString(item.TemplateIndex) || !digestPattern.MatchString(item.TemplateManifest) || !strings.HasSuffix(item.TemplateReference, "@"+item.TemplateManifest) {
		return errors.New("template index, manifest, and reference binding is invalid")
	}
	if item.Lane == "development" {
		if item.Platform != "linux/arm64" || item.BootstrapCommand != "" || !hasString(item.Blockers, "ARM64_PORT_TOOLCHAIN_UNBOUND") {
			return errors.New("development lane must remain arm64 with its authoritative toolchain blocked")
		}
	} else if item.Lane == "authoritative-formal" {
		if item.Platform != "linux/amd64" || item.BootstrapCommand != catalogValue.AMD64BootstrapCommand {
			return errors.New("formal lane must use linux/amd64 and the shared bootstrap")
		}
	} else {
		return errors.New("lane is not supported")
	}
	if item.Agent == "muse-code" {
		if !hasString(item.Blockers, "MUSE_AUTH_AND_INFERENCE_UNWIRED") || !hasString(item.Blockers, "MUSE_PRODUCTION_IMAGE_UNBUILT") {
			return errors.New("Muse profile must retain authentication and image-provenance blockers")
		}
		if !equalStrings(item.Kits, []string{"sbx/kits/muse-code", "sbx/kits/port-contract"}) || !strings.HasPrefix(item.TemplateReference, "docker.io/docker/sandbox-templates:shell-docker@") {
			return errors.New("Muse profile must compose the Muse and port-contract kits over shell-docker")
		}
	} else if item.Agent == "codex" || item.Agent == "claude" {
		if !hasString(item.Blockers, "HOST_STDIO_MCP_DENY_UNVERIFIED") {
			return errors.New("built-in agent must retain the host-stdio MCP blocker")
		}
		if !equalStrings(item.Kits, []string{"sbx/kits/port-contract"}) {
			return errors.New("built-in agent must compose the shared port-contract kit")
		}
		wantTemplate := "docker.io/docker/sandbox-templates:codex-docker@"
		if item.Agent == "claude" {
			wantTemplate = "docker.io/docker/sandbox-templates:claude-code-docker@"
		}
		if !strings.HasPrefix(item.TemplateReference, wantTemplate) {
			return errors.New("built-in agent template family is invalid")
		}
	} else {
		return errors.New("agent is not supported")
	}
	seenBlocker := make(map[string]bool)
	for _, blocker := range item.Blockers {
		if !idPattern.MatchString(strings.ToLower(strings.ReplaceAll(blocker, "_", "-"))) || seenBlocker[blocker] {
			return errors.New("blockers must be unique bounded identifiers")
		}
		seenBlocker[blocker] = true
	}
	for _, kit := range item.Kits {
		if _, err := resolveRegularFile(root, filepath.Join(kit, "spec.yaml")); err != nil {
			return fmt.Errorf("kit %s: %w", kit, err)
		}
	}
	wantArgv := canonicalLaunch(item)
	if !equalStrings(item.LaunchArgv, wantArgv) {
		return fmt.Errorf("launch_argv does not match the closed profile; got %q, want %q", item.LaunchArgv, wantArgv)
	}
	for _, argument := range item.LaunchArgv {
		switch argument {
		case "--publish", "-p", "--static-mcp", "--env", "-e", "--env-file", "--profile":
			return fmt.Errorf("launch_argv contains forbidden host integration flag %s", argument)
		}
	}
	return nil
}

func canonicalLaunch(item profile) []string {
	arguments := []string{"sbx", "run", "--clone", "--no-share-skills"}
	for _, kit := range item.Kits {
		arguments = append(arguments, "--kit", kit)
	}
	arguments = append(arguments, "--name", item.SandboxName)
	if item.Agent != "muse-code" {
		arguments = append(arguments, "--template", item.TemplateReference)
	}
	return append(arguments, item.Agent, ".")
}

func resolveRegularFile(root, relative string) (string, error) {
	path, info, err := resolvePath(root, relative)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("path is not a regular file")
	}
	return path, nil
}

func resolveDirectory(root, relative string) (string, error) {
	path, info, err := resolvePath(root, relative)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	return path, nil
}

func resolvePath(root, relative string) (string, os.FileInfo, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", nil, errors.New("path must be repository-relative")
	}
	clean := filepath.Clean(relative)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", nil, errors.New("path escapes repository root")
	}
	path := filepath.Join(root, clean)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, err
	}
	if resolved != path {
		return "", nil, errors.New("path contains a symlink")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", nil, errors.New("path is a symlink")
	}
	return path, info, nil
}

func versionLess(left, right string) bool {
	leftParts, leftOK := versionParts(left)
	rightParts, rightOK := versionParts(right)
	if !leftOK || !rightOK {
		return false
	}
	for index := range leftParts {
		if leftParts[index] != rightParts[index] {
			return leftParts[index] < rightParts[index]
		}
	}
	return false
}

func versionParts(value string) ([3]int, bool) {
	var result [3]int
	parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
	if len(parts) != len(result) {
		return result, false
	}
	for index, part := range parts {
		parsed, err := strconv.Atoi(part)
		if err != nil || parsed < 0 {
			return result, false
		}
		result[index] = parsed
	}
	return result, true
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
