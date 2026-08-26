package lab

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	AutobahnEndpointVersion         = "1.0.0"
	AutobahnEndpointClass           = "AutobahnEndpoint"
	AutobahnEndpointAgent           = "verified-java-websocket-port-1.6.0"
	AutobahnSLF4JAPIDigest          = "sha256:e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9"
	AutobahnSLF4JAPIPOMDigest       = "sha256:51805cfda80ca2ac82041b906d9865d39e9823e358a0eeb62379dfed475c1571"
	AutobahnSLF4JAPILicenseDigest   = "sha256:4e7f90c86ab51278228bce153122f1d8df30149d13ce9ef524c8444a84c32dcc"
	AutobahnFrozenClosureDigest     = "sha256:19518e08afbbd7a0dfbf893c713158487db85ea945ae1b8145897e200a007590"
	AutobahnSLF4JAPIRelativePath    = "repository/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar"
	AutobahnSLF4JAPIPOMRelativePath = "repository/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.pom"
	autobahnEndpointMaximumOutput   = 4 << 20
	autobahnEndpointMaximumArtifact = 32 << 20
)

// AutobahnEndpointSourceDigest is updated only when the deliberately thin,
// noninteractive adapter source is reviewed as part of this qualification.
const AutobahnEndpointSourceDigest = "sha256:43540e7f047158238bf227a816ffab2f8faf93c96368ed004b539eb7bfec0a46"

type AutobahnEndpointBuildConfig struct {
	SourcePath       string
	JDKHome          string
	RuntimePath      string
	ClosureDirectory string
	WorkDirectory    string
}

type AutobahnArtifactBinding struct {
	ObjectID string `json:"object_id"`
	Path     string `json:"path"`
	Digest   string `json:"digest"`
	Bytes    int64  `json:"bytes"`
	Links    uint64 `json:"links"`
}

type AutobahnEndpointReceipt struct {
	SchemaVersion            string                  `json:"schema_version"`
	Assurance                string                  `json:"assurance"`
	IndependentReviewClaimed bool                    `json:"independent_review_claimed"`
	Source                   AutobahnArtifactBinding `json:"source"`
	RuntimeSource            AutobahnArtifactBinding `json:"runtime_source"`
	RuntimeCopy              AutobahnArtifactBinding `json:"runtime_copy"`
	Support                  AutobahnArtifactBinding `json:"support"`
	SupportMetadata          AutobahnArtifactBinding `json:"support_metadata"`
	SupportLicenseDigest     string                  `json:"support_license_digest"`
	Adapter                  AutobahnArtifactBinding `json:"adapter"`
	ClosureManifestDigest    string                  `json:"closure_manifest_digest"`
	Javac                    AutobahnArtifactBinding `json:"javac"`
	Java                     AutobahnArtifactBinding `json:"java"`
	Jar                      AutobahnArtifactBinding `json:"jar"`
	RuntimeSourceUnchanged   bool                    `json:"runtime_source_unchanged"`
	RuntimeByteCopy          bool                    `json:"runtime_byte_copy"`
	SelfTestPassed           bool                    `json:"self_test_passed"`
}

func BuildAutobahnEndpoint(ctx context.Context, config AutobahnEndpointBuildConfig) (AutobahnEndpointReceipt, error) {
	if ctx == nil {
		return AutobahnEndpointReceipt{}, finding("INVALID_AUTOBAHN_ENDPOINT_CONFIG", "$", "context is required")
	}
	work, err := cleanAbsoluteDirectory(config.WorkDirectory, "$.work_directory")
	if err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	closure, err := cleanAbsoluteDirectory(config.ClosureDirectory, "$.closure_directory")
	if err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	for field, value := range map[string]string{"$.source_path": config.SourcePath, "$.runtime_path": config.RuntimePath, "$.jdk_home": config.JDKHome} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsRune(value, 0) {
			return AutobahnEndpointReceipt{}, finding("INVALID_PATH", field, "path must be clean and absolute")
		}
	}
	if err := requireRealDirectory(closure); err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	closureDigest, _, err := digestTree(closure, true)
	if err != nil || closureDigest != AutobahnFrozenClosureDigest {
		return AutobahnEndpointReceipt{}, finding("CACHE_CLOSURE_MISMATCH", "$.closure_directory", "support must come from the exact qualified frozen dependency closure")
	}
	supportPath := filepath.Join(closure, filepath.FromSlash(AutobahnSLF4JAPIRelativePath))
	source, err := boundArtifact("autobahn-endpoint-source", config.SourcePath, AutobahnEndpointSourceDigest, 1<<20)
	if err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	runtimeBeforeInfo, err := os.Lstat(config.RuntimePath)
	if err != nil {
		return AutobahnEndpointReceipt{}, finding("MISSING_FILE", config.RuntimePath, err.Error())
	}
	runtime, err := boundArtifact("java-websocket-runtime-jar", config.RuntimePath, JavaWebSocketRuntimeDigest, autobahnEndpointMaximumArtifact)
	if err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	support, err := boundArtifact("slf4j-api-2.0.13-qualified-closure", supportPath, AutobahnSLF4JAPIDigest, autobahnEndpointMaximumArtifact)
	if err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	supportMetadata, supportLicenseDigest, err := verifySLF4JQualification(closure, supportPath)
	if err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	if err := prepareEmptyBuildDirectory(work); err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	classes := filepath.Join(work, "classes")
	home := filepath.Join(work, "home")
	if err := os.Mkdir(classes, 0o700); err != nil {
		return AutobahnEndpointReceipt{}, finding("AUTOBAHN_ENDPOINT_BUILD_FAILED", classes, err.Error())
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		return AutobahnEndpointReceipt{}, finding("AUTOBAHN_ENDPOINT_BUILD_FAILED", home, err.Error())
	}
	runtimeCopyPath := filepath.Join(work, "Java-WebSocket-1.6.0.jar")
	if err := copyExactRegular(runtime.Path, runtimeCopyPath, runtime.Digest); err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	runtimeCopy, err := boundArtifact("java-websocket-runtime-byte-copy", runtimeCopyPath, JavaWebSocketRuntimeDigest, autobahnEndpointMaximumArtifact)
	if err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	if sameFilesystemIdentity(runtime.Path, runtimeCopy.Path) {
		return AutobahnEndpointReceipt{}, finding("RUNTIME_COPY_NOT_INDEPENDENT", "$.runtime_copy", "runtime must be copied as bytes, never linked")
	}
	runtimeAfterInfo, err := os.Lstat(config.RuntimePath)
	if err != nil || !os.SameFile(runtimeBeforeInfo, runtimeAfterInfo) || linkCount(runtimeBeforeInfo) != 1 || linkCount(runtimeAfterInfo) != 1 || runtimeBeforeInfo.Size() != runtimeAfterInfo.Size() {
		return AutobahnEndpointReceipt{}, finding("CONCURRENT_FILE_DRIFT", config.RuntimePath, "accepted runtime identity or link count changed during byte copy")
	}
	if _, err := boundArtifact("java-websocket-runtime-jar", config.RuntimePath, JavaWebSocketRuntimeDigest, autobahnEndpointMaximumArtifact); err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	javacPath := filepath.Join(config.JDKHome, "bin", "javac")
	javaPath := filepath.Join(config.JDKHome, "bin", "java")
	jarPath := filepath.Join(config.JDKHome, "bin", "jar")
	javac, err := boundArtifactAnyDigest("openjdk-17.0.19-javac", javacPath, 256<<20)
	if err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	java, err := boundArtifactAnyDigest("openjdk-17.0.19-java", javaPath, 256<<20)
	if err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	jar, err := boundArtifactAnyDigest("openjdk-17.0.19-jar", jarPath, 256<<20)
	if err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	environment := []string{
		"HOME=" + home, "JAVA_HOME=" + config.JDKHome, "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
		"PATH=" + filepath.Join(config.JDKHome, "bin"), "SOURCE_DATE_EPOCH=0", "TZ=UTC",
	}
	classpath := runtimeCopy.Path + string(os.PathListSeparator) + support.Path
	if _, err := runBounded(ctx, work, environment, javac.Path,
		"--release", "17", "-encoding", "UTF-8", "-Xlint:all", "-Werror", "-cp", classpath,
		"-d", classes, source.Path); err != nil {
		return AutobahnEndpointReceipt{}, finding("AUTOBAHN_ENDPOINT_BUILD_FAILED", "$.javac", err.Error())
	}
	adapterPath := filepath.Join(work, "autobahn-endpoint.jar")
	if _, err := runBounded(ctx, work, environment, jar.Path,
		"--create", "--file", adapterPath, "--date=2026-01-01T00:00:00Z", "--main-class", AutobahnEndpointClass,
		"-C", classes, "."); err != nil {
		return AutobahnEndpointReceipt{}, finding("AUTOBAHN_ENDPOINT_BUILD_FAILED", "$.jar", err.Error())
	}
	adapter, err := boundArtifactAnyDigest("autobahn-endpoint-adapter", adapterPath, autobahnEndpointMaximumArtifact)
	if err != nil {
		return AutobahnEndpointReceipt{}, err
	}
	selfOutput, err := runBounded(ctx, work, environment, java.Path,
		"-cp", adapter.Path+string(os.PathListSeparator)+runtimeCopy.Path+string(os.PathListSeparator)+support.Path,
		AutobahnEndpointClass, "selftest", "--adapter", adapter.Path, "--adapter-digest", adapter.Digest,
		"--runtime", runtimeCopy.Path, "--support", support.Path)
	if err != nil || !strings.Contains(string(selfOutput), "SELFTEST_PASS runtime="+JavaWebSocketRuntimeDigest+" support="+AutobahnSLF4JAPIDigest+" adapter="+adapter.Digest) {
		return AutobahnEndpointReceipt{}, finding("AUTOBAHN_ENDPOINT_SELFTEST_FAILED", "$.self_test", boundedDetail(selfOutput, err))
	}
	return AutobahnEndpointReceipt{
		SchemaVersion: AutobahnEndpointVersion, Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT", IndependentReviewClaimed: false,
		Source: source, RuntimeSource: runtime, RuntimeCopy: runtimeCopy, Support: support, SupportMetadata: supportMetadata,
		SupportLicenseDigest: supportLicenseDigest, Adapter: adapter,
		ClosureManifestDigest: closureDigest, Javac: javac, Java: java, Jar: jar,
		RuntimeSourceUnchanged: true, RuntimeByteCopy: true, SelfTestPassed: true,
	}, nil
}

func verifySLF4JQualification(closure, jarPath string) (AutobahnArtifactBinding, string, error) {
	pomPath := filepath.Join(closure, filepath.FromSlash(AutobahnSLF4JAPIPOMRelativePath))
	pom, err := boundArtifact("slf4j-api-2.0.13-qualified-pom", pomPath, AutobahnSLF4JAPIPOMDigest, 1<<20)
	if err != nil {
		return AutobahnArtifactBinding{}, "", err
	}
	jarBytes, err := readBoundedRegular(jarPath, autobahnEndpointMaximumArtifact)
	if err != nil {
		return AutobahnArtifactBinding{}, "", err
	}
	reader, err := zip.NewReader(bytes.NewReader(jarBytes), int64(len(jarBytes)))
	if err != nil || len(reader.File) == 0 || len(reader.File) > 4096 {
		return AutobahnArtifactBinding{}, "", finding("SUPPORT_QUALIFICATION_MISMATCH", jarPath, "support JAR is not a bounded ZIP archive")
	}
	var license []byte
	for _, member := range reader.File {
		if member.Name != "META-INF/LICENSE.txt" {
			continue
		}
		if license != nil || member.UncompressedSize64 > 64<<10 || !member.Mode().IsRegular() {
			return AutobahnArtifactBinding{}, "", finding("SUPPORT_QUALIFICATION_MISMATCH", jarPath, "support JAR license member is duplicate or unsafe")
		}
		file, err := member.Open()
		if err != nil {
			return AutobahnArtifactBinding{}, "", finding("SUPPORT_QUALIFICATION_MISMATCH", jarPath, err.Error())
		}
		license, err = io.ReadAll(io.LimitReader(file, 64<<10+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || uint64(len(license)) != member.UncompressedSize64 {
			return AutobahnArtifactBinding{}, "", finding("SUPPORT_QUALIFICATION_MISMATCH", jarPath, "support JAR license member is truncated")
		}
	}
	if intake.DigestBytes(license) != AutobahnSLF4JAPILicenseDigest {
		return AutobahnArtifactBinding{}, "", finding("SUPPORT_QUALIFICATION_MISMATCH", jarPath, "embedded support license differs from the qualified bytes")
	}
	return pom, AutobahnSLF4JAPILicenseDigest, nil
}

func prepareEmptyBuildDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return finding("WORK_DIRECTORY_NOT_EMPTY", path, "endpoint build directory must be newly created")
		}
		return finding("AUTOBAHN_ENDPOINT_BUILD_FAILED", path, err.Error())
	}
	return nil
}

func boundArtifact(objectID, path, expected string, maximum int64) (AutobahnArtifactBinding, error) {
	artifact, err := boundArtifactAnyDigest(objectID, path, maximum)
	if err != nil {
		return AutobahnArtifactBinding{}, err
	}
	if artifact.Digest != expected {
		return AutobahnArtifactBinding{}, finding("ARTIFACT_DIGEST_MISMATCH", path, "artifact differs from its exact qualification digest")
	}
	return artifact, nil
}

func boundArtifactAnyDigest(objectID, path string, maximum int64) (AutobahnArtifactBinding, error) {
	if !idPattern.MatchString(objectID) || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return AutobahnArtifactBinding{}, finding("INVALID_AUTOBAHN_ARTIFACT", path, "artifact identity and path must be exact")
	}
	data, err := readBoundedRegular(path, maximum)
	if err != nil {
		return AutobahnArtifactBinding{}, err
	}
	info, err := os.Lstat(path)
	if err != nil || linkCount(info) != 1 {
		return AutobahnArtifactBinding{}, finding("UNSAFE_FILE", path, "artifact must have exactly one filesystem link")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return AutobahnArtifactBinding{}, finding("UNSAFE_FILE", path, "artifact path must not traverse symlinks")
	}
	return AutobahnArtifactBinding{ObjectID: objectID, Path: path, Digest: intake.DigestBytes(data), Bytes: int64(len(data)), Links: linkCount(info)}, nil
}

func copyExactRegular(source, destination, expectedDigest string) error {
	data, err := readBoundedRegular(source, autobahnEndpointMaximumArtifact)
	if err != nil {
		return err
	}
	if intake.DigestBytes(data) != expectedDigest {
		return finding("ARTIFACT_DIGEST_MISMATCH", source, "source differs before byte copy")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return finding("AUTOBAHN_ENDPOINT_BUILD_FAILED", destination, err.Error())
	}
	written, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(data) {
		return finding("AUTOBAHN_ENDPOINT_BUILD_FAILED", destination, "runtime byte copy was incomplete")
	}
	copied, err := readBoundedRegular(destination, autobahnEndpointMaximumArtifact)
	if err != nil || intake.DigestBytes(copied) != expectedDigest {
		return finding("RUNTIME_COPY_DIGEST_MISMATCH", destination, "runtime byte copy differs from accepted source")
	}
	return nil
}

func sameFilesystemIdentity(left, right string) bool {
	leftInfo, leftErr := os.Lstat(left)
	rightInfo, rightErr := os.Lstat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if b.buffer.Len() > b.limit-len(data) {
		remaining := b.limit - b.buffer.Len()
		if remaining > 0 {
			_, _ = b.buffer.Write(data[:remaining])
		}
		return len(data), errors.New("process output exceeded fixed bound")
	}
	return b.buffer.Write(data)
}

func runBounded(ctx context.Context, directory string, environment []string, executable string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = directory
	command.Env = append([]string(nil), environment...)
	output := &boundedBuffer{limit: autobahnEndpointMaximumOutput}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if err != nil {
		return output.buffer.Bytes(), fmt.Errorf("fixed operation failed: %w: %s", err, boundedString(output.buffer.String(), 2048))
	}
	return output.buffer.Bytes(), nil
}

func boundedDetail(output []byte, err error) string {
	value := strings.TrimSpace(string(output))
	if err != nil {
		value = err.Error() + ": " + value
	}
	if value == "" {
		value = "fixed endpoint operation did not produce its success marker"
	}
	return boundedString(value, 2048)
}

func boundedString(value string, maximum int) string {
	value = strings.Map(func(character rune) rune {
		if character < 0x20 && character != '\n' && character != '\t' || character == 0x7f {
			return '?'
		}
		return character
	}, value)
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}

func parsePositiveBounded(value string, maximum int) (int, error) {
	number, err := strconv.Atoi(value)
	if err != nil || number < 1 || number > maximum {
		return 0, fmt.Errorf("value must be in 1..%d", maximum)
	}
	return number, nil
}

var _ io.Writer = (*boundedBuffer)(nil)
