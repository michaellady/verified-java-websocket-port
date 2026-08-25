package lab

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	AutobahnRunnerSourceDigest = "sha256:ce4cc2c799002aba787bc3df946f71c164d56a024508339e706497c1ca0c0055"
	AutobahnRunnerBinaryDigest = "sha256:63154648244571e92f000698d92573e841114a387bbddf8351b7d35a8123e2b9"
	AutobahnWSTestPath         = "/opt/pypy/bin/wstest"
	AutobahnWSTestDigest       = "sha256:d8acff20961f3fc8d396944e4d38f3d06ddb11301f123670f557d6284b6ea632"
	AutobahnPyPyPath           = "/opt/pypy/bin/pypy"
	AutobahnPyPyDigest         = "sha256:14c4d94ca4b7feee06acf12cf7d74e3e6fc63114d2886e5f0c45afce84250a6c"
)

type AutobahnRunnerBuildConfig struct {
	SourcePath    string
	GoRoot        string
	WorkDirectory string
}

type AutobahnRunnerReceipt struct {
	SchemaVersion            string                  `json:"schema_version"`
	Assurance                string                  `json:"assurance"`
	IndependentReviewClaimed bool                    `json:"independent_review_claimed"`
	Qualification            string                  `json:"qualification"`
	Source                   AutobahnArtifactBinding `json:"source"`
	GoExecutable             AutobahnArtifactBinding `json:"go_executable"`
	GoVersion                string                  `json:"go_version"`
	GoRootDigest             string                  `json:"go_root_digest"`
	Binary                   AutobahnArtifactBinding `json:"binary"`
	WSTestPath               string                  `json:"wstest_path"`
	WSTestDigest             string                  `json:"wstest_digest"`
	InterpreterPath          string                  `json:"interpreter_path"`
	InterpreterDigest        string                  `json:"interpreter_digest"`
	RepeatableBuild          bool                    `json:"repeatable_build"`
	LinuxAMD64StaticELF      bool                    `json:"linux_amd64_static_elf"`
	SourceUnchanged          bool                    `json:"source_unchanged"`
	ToolchainUnchanged       bool                    `json:"toolchain_unchanged"`
}

func BuildAutobahnRunner(ctx context.Context, config AutobahnRunnerBuildConfig) (AutobahnRunnerReceipt, error) {
	if ctx == nil {
		return AutobahnRunnerReceipt{}, finding("INVALID_AUTOBAHN_RUNNER_CONFIG", "$", "context is required")
	}
	root, err := cleanAbsoluteDirectory(config.GoRoot, "$.go_root")
	if err != nil {
		return AutobahnRunnerReceipt{}, err
	}
	work, err := cleanAbsoluteDirectory(config.WorkDirectory, "$.work_directory")
	if err != nil {
		return AutobahnRunnerReceipt{}, err
	}
	if !filepath.IsAbs(config.SourcePath) || filepath.Clean(config.SourcePath) != config.SourcePath || strings.ContainsRune(config.SourcePath, 0) {
		return AutobahnRunnerReceipt{}, finding("INVALID_PATH", "$.source_path", "runner source path must be clean and absolute")
	}
	if err := requireRealDirectory(root); err != nil {
		return AutobahnRunnerReceipt{}, err
	}
	source, err := boundArtifact("autobahn-fixed-supervisor-source", config.SourcePath, AutobahnRunnerSourceDigest, 1<<20)
	if err != nil {
		return AutobahnRunnerReceipt{}, err
	}
	goExecutable, err := boundArtifactAnyDigest("go-1.25.5-darwin-arm64-owner-qualified", filepath.Join(root, "bin", "go"), 256<<20)
	if err != nil {
		return AutobahnRunnerReceipt{}, err
	}
	rootBefore, _, err := digestTree(root, true)
	if err != nil || rootBefore != AutobahnRelayGoRootDigest {
		return AutobahnRunnerReceipt{}, finding("AUTOBAHN_RUNNER_TOOLCHAIN_MISMATCH", "$.go_root", "Go toolchain tree differs from its owner-qualified digest")
	}
	if err := os.Mkdir(work, 0o700); err != nil {
		return AutobahnRunnerReceipt{}, finding("WORK_DIRECTORY_NOT_EMPTY", work, "runner build requires a fresh private work directory")
	}
	versionCache, versionHome, versionTemporary := filepath.Join(work, "version-cache"), filepath.Join(work, "version-home"), filepath.Join(work, "version-tmp")
	for _, directory := range []string{versionCache, versionHome, versionTemporary} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return AutobahnRunnerReceipt{}, finding("AUTOBAHN_RUNNER_BUILD_FAILED", directory, err.Error())
		}
	}
	versionOutput, err := runBounded(ctx, work, relayBuildEnvironment(root, versionCache, versionHome, versionTemporary), goExecutable.Path, "version")
	if err != nil || strings.TrimSpace(string(versionOutput)) != AutobahnRelayGoVersion {
		return AutobahnRunnerReceipt{}, finding("AUTOBAHN_RUNNER_TOOLCHAIN_MISMATCH", "$.go_version", boundedDetail(versionOutput, err))
	}
	first, err := buildRunnerOnce(ctx, root, work, goExecutable.Path, source.Path, "first")
	if err != nil {
		return AutobahnRunnerReceipt{}, err
	}
	second, err := buildRunnerOnce(ctx, root, work, goExecutable.Path, source.Path, "second")
	if err != nil {
		return AutobahnRunnerReceipt{}, err
	}
	if first.Digest != second.Digest || first.Digest != AutobahnRunnerBinaryDigest {
		return AutobahnRunnerReceipt{}, finding("AUTOBAHN_RUNNER_BUILD_NONDETERMINISTIC", "$.binary", "two clean offline builds differ or leave the qualified binary digest")
	}
	if err := verifyStaticLinuxAMD64(first.Path); err != nil {
		return AutobahnRunnerReceipt{}, err
	}
	rootAfter, _, err := digestTree(root, true)
	if err != nil || rootAfter != rootBefore {
		return AutobahnRunnerReceipt{}, finding("AUTOBAHN_RUNNER_TOOLCHAIN_DRIFT", "$.go_root", "Go toolchain changed during runner build")
	}
	if _, err := boundArtifact("autobahn-fixed-supervisor-source", source.Path, AutobahnRunnerSourceDigest, 1<<20); err != nil {
		return AutobahnRunnerReceipt{}, err
	}
	return AutobahnRunnerReceipt{
		SchemaVersion: "1.0.0", Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT", IndependentReviewClaimed: false,
		Qualification: "QUALIFIED_NOT_PROMOTED", Source: source, GoExecutable: goExecutable, GoVersion: AutobahnRelayGoVersion,
		GoRootDigest: rootBefore, Binary: first, WSTestPath: AutobahnWSTestPath, WSTestDigest: AutobahnWSTestDigest,
		InterpreterPath: AutobahnPyPyPath, InterpreterDigest: AutobahnPyPyDigest, RepeatableBuild: true,
		LinuxAMD64StaticELF: true, SourceUnchanged: true, ToolchainUnchanged: true,
	}, nil
}

func buildRunnerOnce(ctx context.Context, goRoot, work, goExecutable, source, name string) (AutobahnArtifactBinding, error) {
	directory := filepath.Join(work, name)
	cache, home, temporary := filepath.Join(directory, "cache"), filepath.Join(directory, "home"), filepath.Join(directory, "tmp")
	if err := os.Mkdir(directory, 0o700); err != nil {
		return AutobahnArtifactBinding{}, finding("AUTOBAHN_RUNNER_BUILD_FAILED", directory, err.Error())
	}
	for _, path := range []string{cache, home, temporary} {
		if err := os.Mkdir(path, 0o700); err != nil {
			return AutobahnArtifactBinding{}, finding("AUTOBAHN_RUNNER_BUILD_FAILED", path, err.Error())
		}
	}
	output := filepath.Join(directory, "autobahn-runner-linux-amd64")
	result, err := runBounded(ctx, directory, relayBuildEnvironment(goRoot, cache, home, temporary), goExecutable,
		"build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", output, source)
	if err != nil {
		return AutobahnArtifactBinding{}, finding("AUTOBAHN_RUNNER_BUILD_FAILED", "$.go_build", boundedDetail(result, err))
	}
	return boundArtifactAnyDigest("autobahn-fixed-supervisor-linux-amd64", output, 32<<20)
}

func exactAutobahnRunner(receipt AutobahnRunnerReceipt) bool {
	return receipt.Source.Digest == AutobahnRunnerSourceDigest && receipt.Binary.Digest == AutobahnRunnerBinaryDigest &&
		receipt.GoVersion == AutobahnRelayGoVersion && receipt.GoRootDigest == AutobahnRelayGoRootDigest &&
		receipt.WSTestPath == AutobahnWSTestPath && receipt.WSTestDigest == AutobahnWSTestDigest &&
		receipt.InterpreterPath == AutobahnPyPyPath && receipt.InterpreterDigest == AutobahnPyPyDigest &&
		receipt.Assurance == "OWNER_ATTESTED_NOT_INDEPENDENT" && !receipt.IndependentReviewClaimed &&
		receipt.Qualification == "QUALIFIED_NOT_PROMOTED" && receipt.RepeatableBuild && receipt.LinuxAMD64StaticELF &&
		receipt.SourceUnchanged && receipt.ToolchainUnchanged && receipt.Binary.Bytes > 0 && receipt.Binary.Links == 1 &&
		receipt.GoExecutable.Digest != intake.DigestBytes(nil)
}
