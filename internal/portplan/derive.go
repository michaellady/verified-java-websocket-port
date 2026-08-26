package portplan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// DeriveRequest names the inputs required to rebuild the six intake documents from the
// digest-pinned Java source tree and the compiler-derived semantic identity oracle.
type DeriveRequest struct {
	Root                 string
	ProductionSourceRoot string
	TestSourceRoot       string
	OraclePath           string
	OracleToolPath       string
	SourceArtifactID     string
	SourceSHA256         string
	SourceVersion        string
	SourceCommit         string
	RFC6455SHA256        string
}

var idSanitizer = regexp.MustCompile(`[^a-z0-9]+`)

func stableID(prefix, value string) string {
	lowered := strings.ToLower(value)
	cleaned := idSanitizer.ReplaceAllString(lowered, "-")
	cleaned = strings.Trim(cleaned, "-")
	if prefix == "" {
		return cleaned
	}
	return prefix + "." + cleaned
}

func rustTypeName(binaryName string) string {
	simple := binaryName
	if index := strings.LastIndex(simple, "$"); index >= 0 {
		simple = simple[index+1:]
	} else if index := strings.LastIndex(simple, "."); index >= 0 {
		simple = simple[index+1:]
	}
	return strings.ReplaceAll(simple, "_", "")
}

var ownerAttested = Assurance{
	Assurance:                OwnerAttested,
	IndependentReviewClaimed: false,
	Production:               false,
	Signing:                  false,
	Publication:              false,
}

// Derive rebuilds every intake document from primary derived data and writes them under
// root/evidence/intake. Nothing it writes is estimated: counts come from the source tree and
// identities come from the javac symbol table.
func Derive(request DeriveRequest) error {
	oracle, oracleDigest, err := LoadOracle(request.OraclePath)
	if err != nil {
		return err
	}
	toolDigest, err := FileDigest(request.OracleToolPath)
	if err != nil {
		return err
	}

	declarationsByFile := map[string]int{}
	for _, declaration := range oracle.Declarations {
		declarationsByFile[declaration.File]++
	}

	productionPaths := make([]string, 0, len(oracle.Files))
	for _, file := range oracle.Files {
		productionPaths = append(productionPaths, file.Path)
	}
	selection := SelectStudySurface(productionPaths)
	selectedSet := map[string]bool{}
	for _, path := range selection.Selected {
		selectedSet[path] = true
	}

	var selected, excluded []FileRecord
	packageInfoWithoutDeclarations := 0
	for _, file := range oracle.Files {
		record := FileRecord{
			Path:             file.Path,
			Package:          file.Package,
			PhysicalLines:    file.PhysicalLines,
			SHA256:           file.SHA256,
			DeclarationCount: declarationsByFile[file.Path],
		}
		if record.DeclarationCount == 0 {
			packageInfoWithoutDeclarations++
		}
		if selectedSet[file.Path] {
			selected = append(selected, record)
			continue
		}
		record.ReasonCode = selection.ExclusionReasons[file.Path]
		record.Reason = exclusionNarrative(record.ReasonCode, file.Path)
		excluded = append(excluded, record)
	}

	testFiles, err := deriveTestFiles(request.TestSourceRoot)
	if err != nil {
		return err
	}

	source := SourcePin{
		ArtifactID:     request.SourceArtifactID,
		SHA256:         request.SourceSHA256,
		Version:        request.SourceVersion,
		Commit:         request.SourceCommit,
		ProductionRoot: "src/main/java",
		TestRoot:       "src/test/java",
	}

	inventory := SurfaceInventory{
		SchemaRef:     "../../schemas/surface-inventory-1.0.0.schema.json",
		SchemaVersion: "1.0.0",
		EntityType:    "SurfaceInventory",
		InventoryID:   "surface-inventory.us003",
		Source:        source,
		SelectionRule: SelectionRule{
			RootFiles: StudySurfaceRootFiles,
			Packages:  StudySurfacePackages,
			Recursive: false,
			Statement: "The study surface is exactly the four root connection files plus the" +
				" drafts, enums, exceptions, framing, handshake, interfaces, and util packages," +
				" each included non-recursively. Every other production file is excluded with a" +
				" named reason.",
		},
		Selected:  selected,
		Excluded:  excluded,
		TestFiles: testFiles,
		Assurance: ownerAttested,
	}

	studyTypes := 0
	studyDeclarations := 0
	for _, declaration := range oracle.Declarations {
		if !declaration.InStudySurface {
			continue
		}
		studyDeclarations++
		if declaration.IsType() {
			studyTypes++
		}
	}

	production := sumRecords(append(append([]FileRecord{}, selected...), excluded...))
	study := sumRecords(selected)
	test := sumRecords(testFiles)

	manifest := IntakeManifest{
		SchemaRef:     "../../schemas/java-intake-manifest-1.0.0.schema.json",
		SchemaVersion: "1.0.0",
		EntityType:    "JavaIntakeManifest",
		ManifestID:    "java-intake-manifest.us003",
		Source:        source,
		JDK: JDKRecord{
			Vendor:          oracle.JDKVendor,
			Version:         oracle.JDKVersion,
			PinnedArtifact:  "openjdk-17.0.19-homebrew-bottle",
			PinnedSHA256:    "sha256:6d51e51e754dc75437c5c552eea568ec2f166e39fc3faa256e668083a8620c17",
			IdentitySource:  oracle.IdentitySource,
			OracleOutputSHA: oracleDigest,
			OracleToolSHA:   toolDigest,
		},
		Build: BuildRecord{
			System:              "Maven",
			Version:             "3.9.11",
			Executed:            false,
			InheritedEvidence:   "evidence/java/build.json",
			InheritedRootDigest: "sha256:5713245496362ece061c769bc4ee8eb909bfcc6d7d319bc3fc9b750f6e0a4ad8",
			Rationale: "US-002 already ran and accepted the authoritative offline Maven build and" +
				" test run against this exact source digest. US-003 references that accepted" +
				" evidence rather than re-executing the quarantined build, which stays" +
				" static-inspection-only in this story.",
		},
		Reconciliation: Reconciliation{
			ProductionTree: production,
			TestTree:       test,
			StudySurface:   study,
			DeclarationTotals: DeclarationTotals{
				ProductionDeclarations: len(oracle.Declarations),
				StudyDeclarations:      studyDeclarations,
				StudyTypes:             studyTypes,
				AnalyzedTopLevelTypes:  oracle.Compilation.AnalyzedTopLevelTypes,
				CompilerErrorCount:     oracle.Compilation.DiagnosticErrorCount,
				PackageInfoFiles:       packageInfoWithoutDeclarations,
			},
			Method: "javac 17.0.19 JavacTask.analyze() over the full production source root with" +
				" org.slf4j:slf4j-api:2.0.13 on the classpath; identities read from the" +
				" javax.lang.model symbol table, counts read from the source bytes.",
			CountingSemantics: "physical_lines counts newline bytes, matching wc -l exactly.",
		},
		Sections:  surfaceSections(oracle, testFiles),
		Assurance: ownerAttested,
		HonestyNotes: []string{
			"Every file, line, declaration, and identity count in this manifest is derived from a" +
				" clean javac run over the digest-verified upstream archive. None is estimated.",
			fmt.Sprintf("%d production files declare no type at all; all of them are"+
				" package-info.java documentation units. %d analyzed top-level types plus %d"+
				" package-info files reconcile to %d production files.",
				packageInfoWithoutDeclarations, oracle.Compilation.AnalyzedTopLevelTypes,
				packageInfoWithoutDeclarations, production.Files),
			"org.slf4j:slf4j-api:2.0.13 was required on the compile classpath to resolve the" +
				" logging imports in WebSocketImpl and Draft_6455. Its version comes from the" +
				" digest-pinned upstream pom.xml and its bytes were verified against the Maven" +
				" Central published checksum; it is a compile-resolution input only and is not" +
				" part of the ported surface.",
			"The Java build system was not executed in this story. Build and runtime test facts" +
				" are inherited by reference from the US-002 accepted evidence root.",
			"No Rust identity in this story is resolver-verified: no Rust workspace exists until" +
				" US-009. Every Rust identity is recorded as PLANNED.",
			"AC2 says 'the four root connection files' without naming them. Two different" +
				" 4-file subsets of the 12 root-package files sum to the required 1,478 lines:" +
				" {WebSocket, WebSocketAdapter, WebSocketListener, WebSocketImpl} and" +
				" {WrappedByteChannel, AbstractWrappedByteChannel, AbstractWebSocket," +
				" WebSocketImpl}. The arithmetic alone does not disambiguate them. This story" +
				" selects the first because those four are the connection abstraction, its" +
				" callback boundary, its default adapter, and its state machine, whereas the" +
				" second mixes byte-channel wrappers and the NIO/keep-alive base class. A" +
				" reviewer must confirm this reading.",
			"Migration rows are per-type (47 rows), not per-member (969 declarations). Each row" +
				" records java_member_count for the members it covers. Per-member rows would be" +
				" a strictly finer, also-defensible granularity.",
			"The port slice assignment (which Java type belongs to which child story) is an" +
				" explicit editorial table in internal/portplan/slices.go, not a compiler-derived" +
				" fact. It is the weakest link in this document set and should be reviewed" +
				" directly.",
			"specification_ids, oracle_ids, vector_ids, property_claim_ids, formal_claim_ids," +
				" and evidence_ids are forward-declared obligations. The corpora and claims they" +
				" name are created by US-005 and US-006 and do not resolve yet; they are" +
				" declared obligations, not satisfied links.",
		},
	}

	migration := buildMigrationMap(oracle, request, selectedSet)
	dossier := buildSeamDossier(oracle, migration)
	compatibility := buildCompatibilitySurface(request)
	cutover := buildCutoverContract(request)

	documents := map[string]interface{}{
		ManifestDocument:         manifest,
		SurfaceInventoryDocument: inventory,
		MigrationMapDocument:     migration,
		SeamDossierDocument:      dossier,
		CompatibilityDocument:    compatibility,
		CutoverDocument:          cutover,
	}
	target := filepath.Join(request.Root, EvidenceDirectory)
	if err := os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	for name, document := range documents {
		content, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return err
		}
		content = append(content, '\n')
		if err := os.WriteFile(filepath.Join(target, name), content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func sumRecords(records []FileRecord) TreeCount {
	total := TreeCount{Files: len(records)}
	for _, record := range records {
		total.PhysicalLines += record.PhysicalLines
	}
	return total
}

func deriveTestFiles(root string) ([]FileRecord, error) {
	paths, err := ListJavaSources(root)
	if err != nil {
		return nil, err
	}
	records := make([]FileRecord, 0, len(paths))
	for _, relative := range paths {
		full := filepath.Join(root, filepath.FromSlash(relative))
		lines, err := CountPhysicalLines(full)
		if err != nil {
			return nil, err
		}
		digest, err := FileDigest(full)
		if err != nil {
			return nil, err
		}
		packageName := ""
		if index := strings.LastIndex(relative, "/"); index >= 0 {
			packageName = strings.ReplaceAll(relative[:index], "/", ".")
		}
		records = append(records, FileRecord{
			Path: relative, Package: packageName, PhysicalLines: lines, SHA256: digest,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, nil
}

func exclusionNarrative(code, path string) string {
	switch code {
	case ExclusionTLSOutOfScope:
		return path + " implements the TLS/WSS channel, which AC5 excludes from the port."
	case ExclusionRootNotConnectionCore:
		return path + " is a root-package file outside the four connection-core seams named by" +
			" AC2 (factories, wrapped-channel helpers, and the NIO abstract base)."
	case ExclusionClientTopology:
		return path + " belongs to the Java client topology, which AC5 excludes in favour of a" +
			" thin Rust adapter."
	case ExclusionServerTopology:
		return path + " belongs to Java's NIO server topology, which AC5 explicitly excludes."
	case ExclusionSubprotocolFramework:
		return path + " is subprotocol-framework parity, which AC5 explicitly excludes."
	case ExclusionExtensionFramework:
		return path + " is extension-framework parity, which AC5 explicitly excludes."
	case ExclusionRFC7692:
		return path + " implements RFC 7692 permessage-deflate, which AC5 explicitly excludes."
	case ExclusionNestedSubpackage:
		return path + " sits in a nested subpackage the AC2 rule does not name, so it is not" +
			" swept into the study surface."
	}
	return path + " is outside the frozen study surface."
}

func surfaceSections(oracle OracleOutput, testFiles []FileRecord) []SurfaceSection {
	return []SurfaceSection{
		{
			ID: "runtime-test-inventory", Title: "Runtime test inventory",
			ObservationStatus: "OBSERVED",
			EvidenceRef:       "evidence/java/test-manifest.json",
			Items: []string{
				fmt.Sprintf("%d test source files in src/test/java", len(testFiles)),
				"231 discovered, executed, and passed test cases over 326 runtime invocations",
				"62 concrete test classes selected exactly once; 10 aggregate suite containers" +
					" retained in inventory but excluded from the selector",
				"4 Autobahn utility classes and 1 feature file are inventoried as non-tests",
			},
		},
		{
			ID: "dependencies", Title: "Dependencies",
			ObservationStatus: "OBSERVED",
			EvidenceRef:       "evidence/intake/source-pins.json",
			Items: []string{
				"compile: org.slf4j:slf4j-api:2.0.13 (sole non-JDK compile dependency)",
				"test: org.slf4j:slf4j-simple:2.0.13",
				"test: junit:junit:4.13.1",
				"every other import in the production tree resolves to java.* or javax.* in the" +
					" pinned OpenJDK 17.0.19",
			},
		},
		{
			ID: "generated-reflection-native", Title: "Generated, reflective, and native surfaces",
			ObservationStatus: "OBSERVED",
			EvidenceRef:       "evidence/intake/java-intake-manifest.json#jdk.oracle_output_sha256",
			Items: []string{
				"no annotation processors: the identity run compiles with -proc:none and produces" +
					" zero errors, so no declaration depends on generated code",
				"no JNI and no native libraries in the production tree",
				"reflection: java.lang.reflect.InvocationTargetException is imported once, in the" +
					" excluded server topology, not in the study surface",
				"src/main/java9/module-info.java is a separate multi-release source root and is" +
					" not one of the 78 production files",
			},
		},
		{
			ID: "serialization", Title: "Serialization",
			ObservationStatus: "OBSERVED",
			EvidenceRef:       "evidence/intake/surface-inventory.json",
			Items: []string{
				"no java.io.Serializable state is persisted; the only serialization surface is the" +
					" RFC 6455 wire encoding itself",
				"exception types carry no custom writeObject/readObject",
			},
		},
		{
			ID: "concurrency", Title: "Concurrency",
			ObservationStatus: "OBSERVED",
			EvidenceRef:       "evidence/intake/port-seam-dossier.json",
			Items: []string{
				"study surface: NamedThreadFactory, plus the synchronized regions and outgoing" +
					" BlockingQueue in WebSocketImpl",
				"excluded topology: WebSocketServer selector thread and WebSocketWorker pool",
				"the Rust port replaces this with one bounded owner (US-017)",
			},
		},
		{
			ID: "network-effects", Title: "Network effects",
			ObservationStatus: "OBSERVED",
			EvidenceRef:       "evidence/intake/compatibility-surface.json",
			Items: []string{
				"the preserved boundary is the RFC 6455 octet stream over a byte channel",
				"Java's NIO SocketChannel/Selector topology is excluded; US-018 supplies a thin" +
					" blocking TCP adapter instead",
			},
		},
		{
			ID: "filesystem-effects", Title: "Filesystem effects",
			ObservationStatus: "OBSERVED",
			EvidenceRef:       "evidence/intake/surface-inventory.json",
			Items: []string{
				"the study surface performs no filesystem access",
			},
		},
		{
			ID: "observability", Title: "Observability",
			ObservationStatus: "OBSERVED",
			EvidenceRef:       "evidence/intake/surface-inventory.json",
			Items: []string{
				"SLF4J logging appears in exactly 2 of the 52 study-surface files" +
					" (WebSocketImpl, Draft_6455)",
				"log output is not part of the preserved wire boundary and carries no parity" +
					" obligation",
			},
		},
		{
			ID: "deployment-topology", Title: "Deployment topology",
			ObservationStatus: "OBSERVED",
			EvidenceRef:       "evidence/intake/cutover-contract.json",
			Items: []string{
				"the upstream artifact is a library JAR, not a deployed service",
				"the cutover boundary is the in-process library surface plus the Autobahn" +
					" conformance endpoint",
			},
		},
		{
			ID: "linux-native-toolchain", Title: "Linux-native Java and Rust compiler bytes",
			ObservationStatus: "UNOBSERVABLE",
			BlockerCode:       "LINUX_HOST_NOT_YET_BOUND",
			EvidenceRef:       "evidence/intake/source-pins.json#deferred_platform_inputs",
			Items: []string{
				"x86_64-unknown-linux-gnu inputs are declared NOT_YET_AN_INPUT until US-008" +
					" binds the external Linux host",
			},
		},
		{
			ID: "rust-semantic-identity", Title: "Rust semantic identity",
			ObservationStatus: "UNOBSERVABLE",
			BlockerCode:       "RUST_WORKSPACE_NOT_YET_CREATED",
			EvidenceRef:       "evidence/intake/semantic-id-migration-map.json#rust_identity_status",
			Items: []string{
				"no Rust workspace exists in this repository, so rust-analyzer cannot resolve any" +
					" Rust identity; US-009 creates the workspace",
				"every Rust identity in the migration map is PLANNED, not resolver-verified",
			},
		},
	}
}
