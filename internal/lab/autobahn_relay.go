package lab

import (
	"context"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	AutobahnRelaySourceDigest = "sha256:1ede338207f0668565be26567420895258f34d2722d7e14b32c4db064d85d2eb"
	AutobahnRelayGoVersion    = "go version go1.25.5 darwin/arm64"
	AutobahnRelayGoRootDigest = "sha256:f6fcd3d9f790196201d629cb9c1a2f46fc019d829910a578a1c25a802b824c94"
	AutobahnRelayBinaryDigest = "sha256:8ab747807e13e969fca07f8058f56230df9b696b46690052e808c81548f0da8e"
)

type AutobahnRelayBuildConfig struct {
	SourcePath    string
	GoRoot        string
	WorkDirectory string
}

type AutobahnNeutralizedVolume struct {
	ContainerPath string `json:"container_path"`
	ContentDigest string `json:"content_digest"`
	ReadOnly      bool   `json:"read_only"`
}

type AutobahnRelayReceipt struct {
	SchemaVersion            string                      `json:"schema_version"`
	Assurance                string                      `json:"assurance"`
	IndependentReviewClaimed bool                        `json:"independent_review_claimed"`
	Qualification            string                      `json:"qualification"`
	Source                   AutobahnArtifactBinding     `json:"source"`
	GoExecutable             AutobahnArtifactBinding     `json:"go_executable"`
	GoVersion                string                      `json:"go_version"`
	GoRootDigest             string                      `json:"go_root_digest"`
	Binary                   AutobahnArtifactBinding     `json:"binary"`
	NeutralizedVolumes       []AutobahnNeutralizedVolume `json:"neutralized_volumes"`
	EmptyMountsVerified      bool                        `json:"empty_mounts_verified"`
	emptyConfigDirectory     string                      `json:"-"`
	emptyReportsDirectory    string                      `json:"-"`
	RepeatableBuild          bool                        `json:"repeatable_build"`
	LinuxAMD64StaticELF      bool                        `json:"linux_amd64_static_elf"`
	SourceUnchanged          bool                        `json:"source_unchanged"`
	ToolchainUnchanged       bool                        `json:"toolchain_unchanged"`
}

func BuildAutobahnRelay(ctx context.Context, config AutobahnRelayBuildConfig) (AutobahnRelayReceipt, error) {
	if ctx == nil {
		return AutobahnRelayReceipt{}, finding("INVALID_AUTOBAHN_RELAY_CONFIG", "$", "context is required")
	}
	root, err := cleanAbsoluteDirectory(config.GoRoot, "$.go_root")
	if err != nil {
		return AutobahnRelayReceipt{}, err
	}
	work, err := cleanAbsoluteDirectory(config.WorkDirectory, "$.work_directory")
	if err != nil {
		return AutobahnRelayReceipt{}, err
	}
	if !filepath.IsAbs(config.SourcePath) || filepath.Clean(config.SourcePath) != config.SourcePath || strings.ContainsRune(config.SourcePath, 0) {
		return AutobahnRelayReceipt{}, finding("INVALID_PATH", "$.source_path", "relay source path must be clean and absolute")
	}
	if err := requireRealDirectory(root); err != nil {
		return AutobahnRelayReceipt{}, err
	}
	source, err := boundArtifact("autobahn-single-session-relay-source", config.SourcePath, AutobahnRelaySourceDigest, 1<<20)
	if err != nil {
		return AutobahnRelayReceipt{}, err
	}
	goExecutable, err := boundArtifactAnyDigest("go-1.25.5-darwin-arm64-owner-qualified", filepath.Join(root, "bin", "go"), 256<<20)
	if err != nil {
		return AutobahnRelayReceipt{}, err
	}
	rootBefore, _, err := digestTree(root, true)
	if err != nil || rootBefore != AutobahnRelayGoRootDigest {
		return AutobahnRelayReceipt{}, finding("AUTOBAHN_RELAY_TOOLCHAIN_MISMATCH", "$.go_root", "Go toolchain tree differs from its owner-qualified digest")
	}
	if err := os.Mkdir(work, 0o700); err != nil {
		return AutobahnRelayReceipt{}, finding("WORK_DIRECTORY_NOT_EMPTY", work, "relay build requires a fresh private work directory")
	}
	versionEnvironment := relayBuildEnvironment(root, filepath.Join(work, "version-cache"), filepath.Join(work, "version-home"), filepath.Join(work, "version-tmp"))
	for _, directory := range []string{filepath.Join(work, "version-cache"), filepath.Join(work, "version-home"), filepath.Join(work, "version-tmp")} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return AutobahnRelayReceipt{}, finding("AUTOBAHN_RELAY_BUILD_FAILED", directory, err.Error())
		}
	}
	versionOutput, err := runBounded(ctx, work, versionEnvironment, goExecutable.Path, "version")
	if err != nil || strings.TrimSpace(string(versionOutput)) != AutobahnRelayGoVersion {
		return AutobahnRelayReceipt{}, finding("AUTOBAHN_RELAY_TOOLCHAIN_MISMATCH", "$.go_version", boundedDetail(versionOutput, err))
	}
	first, err := buildRelayOnce(ctx, root, work, goExecutable.Path, source.Path, "first")
	if err != nil {
		return AutobahnRelayReceipt{}, err
	}
	second, err := buildRelayOnce(ctx, root, work, goExecutable.Path, source.Path, "second")
	if err != nil {
		return AutobahnRelayReceipt{}, err
	}
	if first.Digest != second.Digest || first.Digest != AutobahnRelayBinaryDigest {
		return AutobahnRelayReceipt{}, finding("AUTOBAHN_RELAY_BUILD_NONDETERMINISTIC", "$.binary", "two clean offline builds differ or leave the qualified binary digest")
	}
	if err := verifyStaticLinuxAMD64(first.Path); err != nil {
		return AutobahnRelayReceipt{}, err
	}
	emptyConfig := filepath.Join(work, "empty-config")
	emptyReports := filepath.Join(work, "empty-reports")
	for _, directory := range []string{emptyConfig, emptyReports} {
		if err := os.Mkdir(directory, 0o555); err != nil {
			return AutobahnRelayReceipt{}, finding("AUTOBAHN_RELAY_BUILD_FAILED", directory, "fixed empty image-volume override could not be created")
		}
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			return AutobahnRelayReceipt{}, finding("AUTOBAHN_RELAY_BUILD_FAILED", directory, "fixed image-volume override is not an empty directory")
		}
	}
	rootAfter, _, err := digestTree(root, true)
	if err != nil || rootAfter != rootBefore {
		return AutobahnRelayReceipt{}, finding("AUTOBAHN_RELAY_TOOLCHAIN_DRIFT", "$.go_root", "Go toolchain changed during relay build")
	}
	if _, err := boundArtifact("autobahn-single-session-relay-source", source.Path, AutobahnRelaySourceDigest, 1<<20); err != nil {
		return AutobahnRelayReceipt{}, err
	}
	return AutobahnRelayReceipt{
		SchemaVersion: "1.0.0", Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT", IndependentReviewClaimed: false,
		Qualification: "QUALIFIED_NOT_PROMOTED", Source: source, GoExecutable: goExecutable, GoVersion: AutobahnRelayGoVersion,
		GoRootDigest: rootBefore, Binary: first, RepeatableBuild: true, LinuxAMD64StaticELF: true, SourceUnchanged: true, ToolchainUnchanged: true,
		NeutralizedVolumes: []AutobahnNeutralizedVolume{
			{ContainerPath: "/config", ContentDigest: intake.DigestBytes(nil), ReadOnly: true},
			{ContainerPath: "/reports", ContentDigest: intake.DigestBytes(nil), ReadOnly: true},
		},
		EmptyMountsVerified: true, emptyConfigDirectory: emptyConfig, emptyReportsDirectory: emptyReports,
	}, nil
}

func buildRelayOnce(ctx context.Context, goRoot, work, goExecutable, source, name string) (AutobahnArtifactBinding, error) {
	directory := filepath.Join(work, name)
	cache := filepath.Join(directory, "cache")
	home := filepath.Join(directory, "home")
	temporary := filepath.Join(directory, "tmp")
	if err := os.Mkdir(directory, 0o700); err != nil {
		return AutobahnArtifactBinding{}, finding("AUTOBAHN_RELAY_BUILD_FAILED", directory, err.Error())
	}
	for _, path := range []string{cache, home, temporary} {
		if err := os.Mkdir(path, 0o700); err != nil {
			return AutobahnArtifactBinding{}, finding("AUTOBAHN_RELAY_BUILD_FAILED", path, err.Error())
		}
	}
	output := filepath.Join(directory, "autobahn-relay-linux-amd64")
	environment := relayBuildEnvironment(goRoot, cache, home, temporary)
	result, err := runBounded(ctx, directory, environment, goExecutable,
		"build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", output, source)
	if err != nil {
		return AutobahnArtifactBinding{}, finding("AUTOBAHN_RELAY_BUILD_FAILED", "$.go_build", boundedDetail(result, err))
	}
	return boundArtifactAnyDigest("autobahn-single-session-relay-linux-amd64", output, 32<<20)
}

func relayBuildEnvironment(goRoot, cache, home, temporary string) []string {
	return []string{
		"CGO_ENABLED=0", "GO111MODULE=off", "GOARCH=amd64", "GOENV=off", "GOOS=linux", "GOAMD64=v1",
		"GOCACHE=" + cache, "GOPROXY=off", "GOROOT=" + goRoot, "GOSUMDB=off", "GOTOOLCHAIN=local",
		"HOME=" + home, "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=" + filepath.Join(goRoot, "bin"),
		"SOURCE_DATE_EPOCH=0", "TMPDIR=" + temporary, "TZ=UTC",
	}
}

func verifyStaticLinuxAMD64(path string) error {
	file, err := elf.Open(path)
	if err != nil {
		return finding("AUTOBAHN_RELAY_BINARY_MISMATCH", path, "relay output is not ELF")
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_X86_64 || file.Type != elf.ET_EXEC || file.OSABI != elf.ELFOSABI_NONE {
		return finding("AUTOBAHN_RELAY_BINARY_MISMATCH", path, "relay output is not a linux/amd64 executable")
	}
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP || program.Type == elf.PT_DYNAMIC {
			return finding("AUTOBAHN_RELAY_BINARY_MISMATCH", path, "relay output depends on a dynamic loader")
		}
	}
	if libraries, err := file.ImportedLibraries(); err == nil && len(libraries) != 0 {
		return finding("AUTOBAHN_RELAY_BINARY_MISMATCH", path, fmt.Sprintf("relay imports dynamic libraries: %v", libraries))
	}
	return nil
}
