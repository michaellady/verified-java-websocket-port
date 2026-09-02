package javabind

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ObserveConfig names every external artifact the executed lane needs. Every
// path is explicit and absolute: the lane can only consume promoted artifacts.
type ObserveConfig struct {
	RepoRoot       string
	Java           string
	Javac          string
	JarTool        string
	RuntimeJAR     string
	SLF4JAPI       string
	JavaSourceRoot string
	WorkDir        string
}

// Validate rejects a configuration that would let an unpinned artifact in.
func (c ObserveConfig) Validate() error {
	for name, path := range map[string]string{
		"repo root": c.RepoRoot, "java": c.Java, "javac": c.Javac, "jar": c.JarTool,
		"runtime jar": c.RuntimeJAR, "slf4j api": c.SLF4JAPI, "java source root": c.JavaSourceRoot,
		"work dir": c.WorkDir,
	} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("javabind: %s must be a clean absolute path, got %q", name, path)
		}
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("javabind: %s: %w", name, err)
		}
	}
	return nil
}

// Observer executes scenarios against the pinned runtime.
type Observer struct {
	config        ObserveConfig
	adapter       string
	mutantDriver  string
	pinnedRuntime string
	toolchain     Toolchain
}

// MutantDriverSource is the project-owned entry point used for mutant and
// control runs. It is compiled alongside the java-oracle sources into a separate
// archive; the baseline adapter archive never contains it.
const MutantDriverSource = "assurance/formal/java-binding/MutantOracleMain.java"

// NewObserver compiles the checked-in java-oracle adapter against the pinned
// runtime JAR and returns an observer bound to it.
func NewObserver(ctx context.Context, config ObserveConfig) (*Observer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	runtimeDigest, err := fileDigest(config.RuntimeJAR)
	if err != nil {
		return nil, err
	}
	sources, err := filepath.Glob(filepath.Join(config.RepoRoot, "java-oracle", "src", "main", "java", "*.java"))
	if err != nil || len(sources) == 0 {
		return nil, fmt.Errorf("javabind: java-oracle sources are missing: %v", err)
	}
	sort.Strings(sources)
	digests := make([]string, 0, len(sources))
	for _, source := range sources {
		digest, err := fileDigest(source)
		if err != nil {
			return nil, err
		}
		digests = append(digests, digest)
	}
	classes := filepath.Join(config.WorkDir, "adapter-classes")
	if err := os.MkdirAll(classes, 0o755); err != nil {
		return nil, err
	}
	// javac -Xlint:path warns on a classpath entry with no .jar spelling, and the
	// promoted object is content-addressed. Compile through a local .jar link.
	compileRuntime := filepath.Join(config.WorkDir, "java-websocket-runtime.jar")
	if _, err := os.Lstat(compileRuntime); err != nil {
		if err := os.Symlink(config.RuntimeJAR, compileRuntime); err != nil {
			return nil, err
		}
	}
	args := []string{"--release", "17", "-encoding", "UTF-8", "-Xlint:all", "-Werror", "-cp", compileRuntime, "-d", classes}
	args = append(args, sources...)
	if err := runTool(ctx, config.Javac, args...); err != nil {
		return nil, err
	}
	adapter := filepath.Join(config.WorkDir, "java-oracle.jar")
	if err := runTool(ctx, config.JarTool, "--create", "--file", adapter, "--main-class", "OracleMain", "-C", classes, "."); err != nil {
		return nil, err
	}
	adapterDigest, err := fileDigest(adapter)
	if err != nil {
		return nil, err
	}
	// The mutant driver archive is the java-oracle sources plus the one
	// project-owned entry point that takes its expected runtime digest as an
	// argument. Baselines never load it.
	driverSource := filepath.Join(config.RepoRoot, filepath.FromSlash(MutantDriverSource))
	driverDigest, err := fileDigest(driverSource)
	if err != nil {
		return nil, err
	}
	driverClasses := filepath.Join(config.WorkDir, "mutant-driver-classes")
	if err := os.MkdirAll(driverClasses, 0o755); err != nil {
		return nil, err
	}
	driverArgs := []string{"--release", "17", "-encoding", "UTF-8", "-Xlint:all", "-Werror", "-cp", compileRuntime, "-d", driverClasses}
	driverArgs = append(driverArgs, sources...)
	driverArgs = append(driverArgs, driverSource)
	if err := runTool(ctx, config.Javac, driverArgs...); err != nil {
		return nil, err
	}
	mutantDriver := filepath.Join(config.WorkDir, "java-oracle-mutant-driver.jar")
	if err := runTool(ctx, config.JarTool, "--create", "--file", mutantDriver, "--main-class", "MutantOracleMain", "-C", driverClasses, "."); err != nil {
		return nil, err
	}
	mutantDriverDigest, err := fileDigest(mutantDriver)
	if err != nil {
		return nil, err
	}
	supportDigest, err := fileDigest(config.SLF4JAPI)
	if err != nil {
		return nil, err
	}
	version, err := toolVersion(ctx, config.Java)
	if err != nil {
		return nil, err
	}
	return &Observer{
		config:        config,
		adapter:       adapter,
		mutantDriver:  mutantDriver,
		pinnedRuntime: runtimeDigest,
		toolchain: Toolchain{
			OS:                    runtime.GOOS,
			Arch:                  runtime.GOARCH,
			JavaVersion:           version,
			AdapterSourceDigests:  digests,
			AdapterJarSHA256:      adapterDigest,
			MutantDriverSHA256:    driverDigest,
			MutantDriverJarSHA256: mutantDriverDigest,
			RuntimeSupportSHA256:  []string{supportDigest},
		},
	}, nil
}

// Toolchain reports the executing environment.
func (o *Observer) Toolchain() Toolchain { return o.toolchain }

// ExecuteBaseline runs one scenario through the unmodified java-oracle adapter
// against the pinned runtime JAR, with the adapter's own digest pin intact.
func (o *Observer) ExecuteBaseline(ctx context.Context, scenario Scenario) (Run, error) {
	return o.execute(ctx, scenario, o.adapter, o.config.RuntimeJAR, "OracleMain", nil)
}

// ExecuteAgainstArchive runs one scenario through the mutant driver against a
// repackaged runtime archive whose digest the caller computed. The driver
// refuses to start unless the runtime it actually loaded has that digest.
func (o *Observer) ExecuteAgainstArchive(ctx context.Context, scenario Scenario, archive, archiveDigest string) (Run, error) {
	hex := strings.TrimPrefix(archiveDigest, "sha256:")
	return o.execute(ctx, scenario, o.mutantDriver, archive, "MutantOracleMain", []string{hex})
}

func (o *Observer) execute(ctx context.Context, scenario Scenario, driver, runtimeArchive, mainClass string, args []string) (Run, error) {
	line, digest, err := EncodeRequest(scenario)
	if err != nil {
		return Run{}, err
	}
	classpath := []string{driver, runtimeArchive, o.config.SLF4JAPI}
	invocation := []string{"-Xms16m", "-Xmx256m", "-Dslf4j.internal.verbosity=ERROR",
		"-cp", strings.Join(classpath, string(os.PathListSeparator)), mainClass}
	invocation = append(invocation, args...)
	command := exec.CommandContext(ctx, o.config.Java, invocation...)
	// A fixed, minimal environment: JAVA_TOOL_OPTIONS and locale settings inherited
	// from a developer shell would both perturb output and pollute stderr.
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.Stdin = bytes.NewReader(append(line, '\n'))
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return Run{}, fmt.Errorf("javabind: adapter process failed for %q: %v: %s", scenario.ScenarioID, err, truncate(stderr.String()))
	}
	if stderr.Len() != 0 {
		return Run{}, fmt.Errorf("javabind: adapter emitted diagnostics for %q: %s", scenario.ScenarioID, truncate(stderr.String()))
	}
	output := stdout.Bytes()
	if len(output) == 0 || output[len(output)-1] != '\n' || bytes.Count(output, []byte{'\n'}) != 1 {
		return Run{}, fmt.Errorf("javabind: adapter must emit exactly one newline-terminated record for %q", scenario.ScenarioID)
	}
	response := output[:len(output)-1]
	return Run{
		ScenarioID:       scenario.ScenarioID,
		RequestCanonical: string(line),
		RequestDigest:    digest,
		ResponseLine:     string(response),
		ResponseDigest:   Digest(response),
	}, nil
}

// ResolveConstructs resolves every chain member of one binding in the pinned
// source and returns the constructs plus the file bytes they were resolved in.
func (o *Observer) ResolveConstructs(binding Binding, catalog Catalog) ([]SourceConstruct, []byte, error) {
	path := filepath.Join(o.config.JavaSourceRoot, binding.SourceFile)
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("javabind: pinned source %q: %w", binding.SourceFile, err)
	}
	fileDigestValue := Digest(file)
	catalogBinding, ok := catalog.JavaBinding(binding.ObligationID)
	if !ok {
		return nil, nil, fmt.Errorf("javabind: catalog has no java binding for %q", binding.ObligationID)
	}
	_, catalogMember, descriptor := SymbolDescriptor(catalogBinding.ProductionSymbol)

	constructs := make([]SourceConstruct, 0, len(binding.Chain))
	for index, member := range binding.Chain {
		var decl Declaration
		var err error
		if member == binding.DeclaringType {
			decl, err = ResolveType(file, binding.DeclaringType)
		} else {
			decl, err = ResolveMember(file, binding.DeclaringType, member)
		}
		if err != nil {
			return nil, nil, err
		}
		construct := SourceConstruct{
			ObligationID:           binding.ObligationID,
			ChainMember:            member,
			IsChainRoot:            index == 0,
			SourceFile:             binding.SourceFile,
			FileSHA256:             fileDigestValue,
			Start:                  decl.Start,
			End:                    decl.End,
			SpanSHA256:             decl.SpanDigest(file),
			StructureFingerprint:   decl.StructureFingerprint(file),
			DeclaredParameterTypes: decl.ParameterTypes,
			DeclaredReturnType:     decl.ReturnType,
			HasBody:                decl.HasBody,
		}
		if construct.DeclaredParameterTypes == nil {
			construct.DeclaredParameterTypes = []string{}
		}
		if index == 0 {
			if catalogMember != "" && catalogMember != member {
				return nil, nil, fmt.Errorf("javabind: binding %q roots its chain at %q but the catalog declares member %q",
					binding.ObligationID, member, catalogMember)
			}
			construct.CatalogDescriptor = descriptor
			construct.DescriptorAgreement = DescriptorAgreement(decl, descriptor)
		}
		constructs = append(constructs, construct)
	}
	return constructs, file, nil
}

// ApplyMutation splices one mutation into the pinned file bytes. It refuses any
// mutation whose removed bytes do not hash to the recorded value or whose offset
// falls outside the bound span.
func ApplyMutation(file []byte, construct SourceConstruct, mutation Mutation) ([]byte, MutationApplication, error) {
	absolute := construct.Start + mutation.RelativeOffset
	if absolute < construct.Start || absolute+mutation.Length > construct.End {
		return nil, MutationApplication{}, fmt.Errorf("javabind: mutation %q at [%d,%d) is outside the bound span [%d,%d)",
			mutation.MutationID, absolute, absolute+mutation.Length, construct.Start, construct.End)
	}
	removed := file[absolute : absolute+mutation.Length]
	if got := Digest(removed); got != mutation.RemovedSHA256 {
		return nil, MutationApplication{}, fmt.Errorf("javabind: mutation %q expects to remove %s but the pinned source holds %s",
			mutation.MutationID, mutation.RemovedSHA256, got)
	}
	mutated := make([]byte, 0, len(file)-mutation.Length+len(mutation.Replacement))
	mutated = append(mutated, file[:absolute]...)
	mutated = append(mutated, mutation.Replacement...)
	mutated = append(mutated, file[absolute+mutation.Length:]...)
	return mutated, MutationApplication{
		MutationID:        mutation.MutationID,
		ObligationID:      construct.ObligationID,
		ChainMember:       mutation.ChainMember,
		SourceFile:        construct.SourceFile,
		AbsoluteOffset:    absolute,
		Length:            mutation.Length,
		RemovedSHA256:     mutation.RemovedSHA256,
		ReplacementSHA256: Digest([]byte(mutation.Replacement)),
		MutatedFileSHA256: Digest(mutated),
	}, nil
}

// BuildRuntimeVariant compiles one version of a pinned source file — mutated or
// unmutated — and repackages it over a copy of the pinned runtime archive. It
// returns the archive path and its digest.
//
// Building the control the same way as the mutant is the point: the control run
// isolates the source edit from the act of recompiling and repackaging, so a
// baseline-versus-mutant difference cannot be blamed on the toolchain.
func (o *Observer) BuildRuntimeVariant(ctx context.Context, variantID, sourceFile string, contents []byte) (string, string, error) {
	dir := filepath.Join(o.config.WorkDir, "variants", variantID)
	target := filepath.Join(dir, "src", filepath.FromSlash(sourceFile))
	classes := filepath.Join(dir, "classes")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(classes, 0o755); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(target, contents, 0o644); err != nil {
		return "", "", err
	}
	compileRuntime := filepath.Join(o.config.WorkDir, "java-websocket-runtime.jar")
	classpath := strings.Join([]string{compileRuntime, o.config.SLF4JAPI}, string(os.PathListSeparator))
	if err := runTool(ctx, o.config.Javac, "--release", "17", "-encoding", "UTF-8", "-nowarn",
		"-cp", classpath, "-d", classes, target); err != nil {
		return "", "", fmt.Errorf("javabind: variant %q does not compile: %w", variantID, err)
	}
	archive := filepath.Join(dir, "java-websocket-variant.jar")
	digest, err := RepackageRuntime(o.config.RuntimeJAR, classes, archive)
	if err != nil {
		return "", "", err
	}
	if digest == o.pinnedRuntime {
		return "", "", fmt.Errorf("javabind: variant %q repackaged to the pinned archive digest", variantID)
	}
	return archive, digest, nil
}

// ReadPinnedSource returns the bytes of one file of the pinned Java tree.
func (o *Observer) ReadPinnedSource(sourceFile string) ([]byte, error) {
	return os.ReadFile(filepath.Join(o.config.JavaSourceRoot, filepath.FromSlash(sourceFile)))
}

func runTool(ctx context.Context, tool string, args ...string) error {
	command := exec.CommandContext(ctx, tool, args...)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s: %v: %s", filepath.Base(tool), err, truncate(stderr.String()))
	}
	return nil
}

func toolVersion(ctx context.Context, java string) (string, error) {
	command := exec.CommandContext(ctx, java, "-version")
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", err
	}
	line := strings.SplitN(strings.TrimSpace(stderr.String()), "\n", 2)[0]
	return strings.TrimSpace(line), nil
}

func fileDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return Digest(data), nil
}

func truncate(text string) string {
	text = strings.TrimSpace(text)
	if len(text) > 2000 {
		return text[:2000] + "…"
	}
	return text
}

// NowUTC is the single timestamp source, so a receipt cannot pick up local time.
func NowUTC() string { return time.Now().UTC().Format(time.RFC3339) }
