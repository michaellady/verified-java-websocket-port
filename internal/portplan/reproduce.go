package portplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The canonical intake was derived with the pinned Homebrew JDK. Cloud verification uses a
// second, digest-pinned Eclipse Temurin distribution and must reproduce its own exact receipt plus
// the canonical semantic content. No other 17.0.19 distribution is accepted.
const (
	PinnedJavacVersion               = "17.0.19"
	pinnedHomebrewJavacVendor        = "Homebrew"
	pinnedHomebrewJavacVendorVersion = "Homebrew"
	pinnedTemurinJavacVendor         = "Eclipse Adoptium"
	pinnedTemurinJavacVendorVersion  = "Temurin-17.0.19+10"
	pinnedHomebrewJavac              = "homebrew-17.0.19"
	pinnedTemurinJavac               = "temurin-17.0.19+10-linux-amd64"
)

// SLF4JAPIJarURL is the Maven Central immutable URL for the sole non-JDK compile input.
const SLF4JAPIJarURL = "https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar"

// SLF4JAPIJarFileName is where the digest-verified jar lives inside the quarantine.
const SLF4JAPIJarFileName = "slf4j-api-2.0.13.jar"

// EnsureSLF4JAPIJar materializes the compile-classpath jar under root/.quarantine, re-acquiring
// it from Maven Central when absent. The bytes must hash to the US-002-qualified digest before
// any use; every failure is typed and fail-closed.
func EnsureSLF4JAPIJar(root string) (string, error) {
	quarantine := filepath.Join(root, QuarantineDirectory)
	jarPath := filepath.Join(quarantine, SLF4JAPIJarFileName)
	if err := os.MkdirAll(quarantine, 0o755); err != nil {
		return "", fmt.Errorf("QUARANTINE_UNWRITABLE: %w", err)
	}
	content, err := os.ReadFile(jarPath)
	if os.IsNotExist(err) {
		client := &http.Client{Timeout: 90 * time.Second}
		response, getErr := client.Get(SLF4JAPIJarURL)
		if getErr != nil {
			return "", fmt.Errorf("SLF4J_UNAVAILABLE_OFFLINE: %w", getErr)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return "", fmt.Errorf("SLF4J_UNAVAILABLE_OFFLINE: HTTP %d", response.StatusCode)
		}
		content, err = io.ReadAll(io.LimitReader(response.Body, 4<<20))
		if err != nil {
			return "", fmt.Errorf("SLF4J_UNAVAILABLE_OFFLINE: %w", err)
		}
		if err := os.WriteFile(jarPath, content, 0o644); err != nil {
			return "", fmt.Errorf("QUARANTINE_UNWRITABLE: %w", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("QUARANTINE_UNREADABLE: %w", err)
	}
	digest := sha256.Sum256(content)
	computed := "sha256:" + hex.EncodeToString(digest[:])
	if computed != SLF4JAPIJarSHA256 {
		return "", fmt.Errorf("SLF4J_JAR_DIGEST_MISMATCH: computed %s, US-002-qualified digest"+
			" is %s", computed, SLF4JAPIJarSHA256)
	}
	return jarPath, nil
}

// VerifyOracleReproduction regenerates the semantic identity report with the pinned javac, the
// committed tool source, and the digest-verified classpath (via the java-semantic-oracle
// Makefile, whose require-inputs gate re-checks the jar identity). Homebrew reproduces the
// canonical report byte for byte. Temurin reproduces a separate committed report byte for byte,
// then must match every canonical JSON field except the explicitly different vendor string. A
// declaration-level tamper therefore fails closed even when every file hash still matches. Every
// failure is typed; callers must fail, never skip.
func VerifyOracleReproduction(root, oraclePath string) error {
	javacPath, err := exec.LookPath("javac")
	if err != nil {
		return fmt.Errorf("JAVAC_UNAVAILABLE: no javac on PATH: %w", err)
	}
	versionOutput, err := exec.Command(javacPath, "-J-XshowSettings:properties", "-version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("JAVAC_UNAVAILABLE: javac identity probe failed: %w", err)
	}
	distribution, err := pinnedJavacDistribution(versionOutput)
	if err != nil {
		return err
	}
	makePath, err := exec.LookPath("make")
	if err != nil {
		return fmt.Errorf("JAVAC_UNAVAILABLE: no make on PATH to drive the oracle build: %w", err)
	}

	root, err = filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("ORACLE_REGENERATION_FAILED: %w", err)
	}
	treePath, err := EnsureQuarantinedSource(root)
	if err != nil {
		return err
	}
	jarPath, err := EnsureSLF4JAPIJar(root)
	if err != nil {
		return err
	}

	workDirectory, err := os.MkdirTemp("", "oracle-reproduction-*")
	if err != nil {
		return fmt.Errorf("ORACLE_REGENERATION_FAILED: %w", err)
	}
	defer os.RemoveAll(workDirectory)
	regeneratedPath := filepath.Join(workDirectory, "semantic-ids.json")

	oracleDirectory := filepath.Join(root, "java-semantic-oracle")
	command := exec.Command(makePath, "-C", oracleDirectory, "run",
		"JAVA_SOURCE_ROOT="+filepath.Join(treePath, "src", "main", "java"),
		"SLF4J_API_JAR="+jarPath,
		"OUTPUT="+regeneratedPath,
		"BUILD_DIR="+filepath.Join(workDirectory, "build"),
	)
	output, err := command.CombinedOutput()
	if err != nil {
		tail := string(output)
		if len(tail) > 600 {
			tail = tail[len(tail)-600:]
		}
		return fmt.Errorf("ORACLE_REGENERATION_FAILED: %w: %s", err, tail)
	}

	regenerated, err := os.ReadFile(regeneratedPath)
	if err != nil {
		return fmt.Errorf("ORACLE_REGENERATION_FAILED: %w", err)
	}
	expectedPath := oraclePath
	if distribution == pinnedTemurinJavac {
		expectedPath = filepath.Join(root, EvidenceDirectory, TemurinOracleEvidenceDocument)
	}
	committed, err := os.ReadFile(expectedPath)
	if err != nil {
		return fmt.Errorf("ORACLE_REPRODUCTION_MISMATCH: cannot read %s: %w", expectedPath, err)
	}
	if !bytes.Equal(regenerated, committed) {
		return fmt.Errorf("ORACLE_REPRODUCTION_MISMATCH: the pinned javac regenerates a report"+
			" that differs from %s; the committed declarations are not what the compiler"+
			" derives from the pinned tree", expectedPath)
	}
	if distribution == pinnedTemurinJavac {
		canonical, err := os.ReadFile(oraclePath)
		if err != nil {
			return fmt.Errorf("ORACLE_REPRODUCTION_MISMATCH: cannot read %s: %w", oraclePath, err)
		}
		if err := verifyOracleSemanticParity(canonical, committed); err != nil {
			return err
		}
	}
	return nil
}

func pinnedJavacDistribution(output []byte) (string, error) {
	lines := map[string]bool{}
	for _, line := range strings.Split(string(output), "\n") {
		lines[strings.TrimSpace(line)] = true
	}
	if !lines["javac "+PinnedJavacVersion] {
		return "", fmt.Errorf("JAVAC_UNAVAILABLE: javac identity is missing %q", "javac "+PinnedJavacVersion)
	}
	for _, candidate := range []struct {
		name, vendor, vendorVersion string
	}{
		{pinnedHomebrewJavac, pinnedHomebrewJavacVendor, pinnedHomebrewJavacVendorVersion},
		{pinnedTemurinJavac, pinnedTemurinJavacVendor, pinnedTemurinJavacVendorVersion},
	} {
		if lines["java.vendor = "+candidate.vendor] && lines["java.vendor.version = "+candidate.vendorVersion] {
			return candidate.name, nil
		}
	}
	return "", fmt.Errorf("JAVAC_UNAVAILABLE: javac distribution is not one of the two pinned identities")
}

func verifyOracleSemanticParity(canonical, alternate []byte) error {
	normalize := func(document []byte, expectedVendor string) ([]byte, error) {
		var value map[string]any
		if err := json.Unmarshal(document, &value); err != nil {
			return nil, err
		}
		vendor, ok := value["jdk_vendor"].(string)
		if !ok || vendor != expectedVendor {
			return nil, fmt.Errorf("oracle vendor is %q, want %q", vendor, expectedVendor)
		}
		delete(value, "jdk_vendor")
		return json.Marshal(value)
	}
	canonicalSemantic, canonicalErr := normalize(canonical, pinnedHomebrewJavacVendor)
	alternateSemantic, alternateErr := normalize(alternate, pinnedTemurinJavacVendor)
	if canonicalErr != nil || alternateErr != nil || !bytes.Equal(canonicalSemantic, alternateSemantic) {
		return fmt.Errorf("ORACLE_REPRODUCTION_MISMATCH: pinned Homebrew and Temurin reports differ beyond compiler vendor provenance")
	}
	return nil
}
