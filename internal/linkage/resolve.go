package linkage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/portplan"
)

// Repository-relative artifact homes.
const (
	VerificationPath = "evidence/linkage/rust-identity-verification.json"
	DAGPath          = "evidence/linkage/evidence-dag.json"
	migrationMapPath = "evidence/intake/semantic-id-migration-map.json"
	proofTargetsPath = "assurance/formal/proof-targets.json"
)

// rustSourceDirs are the workspace source roots the excluded-name probe scans.
var rustSourceDirs = []string{
	"rust/ws-core/src",
	"rust/ws-driver/src",
	"rust/ws-testee/src",
}

var ownerAttested = Assurance{
	Assurance:                "OWNER_ATTESTED_NOT_INDEPENDENT",
	IndependentReviewClaimed: false,
	Production:               false,
	Publication:              false,
	Signing:                  false,
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fileDigest reads a repository-relative file and returns its bytes and digest.
func fileDigest(root, rel string) ([]byte, string, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return nil, "", err
	}
	return data, digestBytes(data), nil
}

// declarationPattern builds the deterministic scan regex for one symbol.
func declarationPattern(rustPath, declKind string) (*regexp.Regexp, error) {
	segments := strings.Split(rustPath, "::")
	name := segments[len(segments)-1]
	visibility := `(?:pub(?:\([a-z ]+\))?\s+)?`
	switch declKind {
	case "struct":
		return regexp.MustCompile(`(?m)^\s*` + visibility + `struct\s+` + name + `\b`), nil
	case "enum":
		return regexp.MustCompile(`(?m)^\s*` + visibility + `enum\s+` + name + `\b`), nil
	case "trait":
		return regexp.MustCompile(`(?m)^\s*` + visibility + `trait\s+` + name + `\b`), nil
	case "type_alias":
		return regexp.MustCompile(`(?m)^\s*` + visibility + `type\s+` + name + `\s*=`), nil
	case "fn", "method":
		return regexp.MustCompile(`(?m)^\s*` + visibility + `(?:const\s+)?fn\s+` + name + `\s*[(<]`), nil
	case "enum_variant":
		return regexp.MustCompile(`(?m)^\s+` + name + `\s*[,({]`), nil
	default:
		return nil, fmt.Errorf("unknown decl kind %q for %s", declKind, rustPath)
	}
}

// resolveSymbol verifies one landed symbol against the tree and records its
// declaration site and the declaring file's blob digest at verification time.
func resolveSymbol(root, rustPath string) (ResolvedSymbol, error) {
	spec, known := symbolCatalog[rustPath]
	if !known {
		return ResolvedSymbol{}, fmt.Errorf("symbol %s is not in the catalog", rustPath)
	}
	content, digest, err := fileDigest(root, spec.File)
	if err != nil {
		return ResolvedSymbol{}, fmt.Errorf("symbol %s: %w", rustPath, err)
	}
	text := string(content)
	segments := strings.Split(rustPath, "::")
	if spec.DeclKind == "method" || spec.DeclKind == "enum_variant" {
		if len(segments) < 2 {
			return ResolvedSymbol{}, fmt.Errorf("symbol %s: %s needs an owner segment", rustPath, spec.DeclKind)
		}
		owner := segments[len(segments)-2]
		ownerKeyword := `(?:impl\b[^\n{]*\b|struct\s+|enum\s+|trait\s+)`
		ownerPattern := regexp.MustCompile(`(?m)^\s*(?:pub(?:\([a-z ]+\))?\s+)?` + ownerKeyword + owner + `\b`)
		if !ownerPattern.MatchString(text) {
			return ResolvedSymbol{}, fmt.Errorf("symbol %s: owner %s not declared in %s", rustPath, owner, spec.File)
		}
	}
	pattern, err := declarationPattern(rustPath, spec.DeclKind)
	if err != nil {
		return ResolvedSymbol{}, err
	}
	location := pattern.FindStringIndex(text)
	if location == nil {
		return ResolvedSymbol{}, fmt.Errorf("symbol %s: no %s declaration found in %s", rustPath, spec.DeclKind, spec.File)
	}
	line := strings.Count(text[:location[0]], "\n") + 1
	declarationLine := text[location[0]:]
	if newline := strings.IndexByte(declarationLine, '\n'); newline >= 0 {
		declarationLine = declarationLine[:newline]
	}
	return ResolvedSymbol{
		RustPath:    rustPath,
		DeclKind:    spec.DeclKind,
		File:        spec.File,
		Line:        line,
		Declaration: strings.TrimSpace(declarationLine),
		SHA256:      digest,
	}, nil
}

// confirmExclusions asserts that none of the capability-excluded Java names
// landed as a Rust declaration anywhere in the workspace sources.
func confirmExclusions(root string) error {
	for _, probe := range excludedNameProbes {
		pattern := regexp.MustCompile(`(?m)^\s*(?:pub(?:\([a-z ]+\))?\s+)?(?:struct|enum|trait|type|fn)\s+` + probe + `\b`)
		for _, dir := range rustSourceDirs {
			absolute := filepath.Join(root, filepath.FromSlash(dir))
			err := filepath.WalkDir(absolute, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() || !strings.HasSuffix(path, ".rs") {
					return nil
				}
				content, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if pattern.Match(content) {
					return fmt.Errorf("excluded name %s is declared in %s", probe, path)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// loadMigrationMap reads the frozen US-003 map and its digest.
func loadMigrationMap(root string) (*portplan.MigrationMap, string, error) {
	content, digest, err := fileDigest(root, migrationMapPath)
	if err != nil {
		return nil, "", err
	}
	var document portplan.MigrationMap
	if err := json.Unmarshal(content, &document); err != nil {
		return nil, "", err
	}
	return &document, digest, nil
}

// BuildVerification derives the rust-identity-verification artifact from the
// frozen migration map and the real Rust tree. It is a pure function of the
// repository bytes.
func BuildVerification(root string) (*VerificationDocument, error) {
	migration, mapDigest, err := loadMigrationMap(root)
	if err != nil {
		return nil, err
	}
	covered := map[string]bool{}
	rows := make([]VerificationRow, 0, len(migration.Rows))
	totals := VerificationTotals{RowsTotal: len(migration.Rows)}
	for _, mapRow := range migration.Rows {
		mapping, known := rowMappings[mapRow.ID]
		if !known {
			return nil, fmt.Errorf("migration row %s has no linkage mapping", mapRow.ID)
		}
		covered[mapRow.ID] = true
		row := VerificationRow{
			RowID:                 mapRow.ID,
			JavaSemanticID:        mapRow.JavaSemanticID,
			PlannedRustSemanticID: mapRow.RustSemanticID,
			Disposition:           mapping.Disposition,
			LandedSymbols:         []ResolvedSymbol{},
			Rationale:             mapping.Rationale,
		}
		if mapping.Disposition == dispositionExcluded {
			if mapRow.Status != "IN_SCOPE_SEMANTIC_ITEM_CAPABILITY_EXCLUDED" {
				return nil, fmt.Errorf("row %s mapped capability_excluded but map status is %s", mapRow.ID, mapRow.Status)
			}
			if err := confirmExclusions(root); err != nil {
				return nil, err
			}
			row.RustIdentityVerified = false
			totals.ExcludedConfirmed++
			rows = append(rows, row)
			continue
		}
		if len(mapping.Symbols) == 0 {
			return nil, fmt.Errorf("row %s carries no landed symbols", mapRow.ID)
		}
		for _, rustPath := range mapping.Symbols {
			resolved, err := resolveSymbol(root, rustPath)
			if err != nil {
				return nil, fmt.Errorf("row %s: %w", mapRow.ID, err)
			}
			row.LandedSymbols = append(row.LandedSymbols, resolved)
		}
		if mapping.Disposition == dispositionExact && mapping.Symbols[0] != mapRow.RustSemanticID {
			return nil, fmt.Errorf("row %s claims exact but landed %s != planned %s",
				mapRow.ID, mapping.Symbols[0], mapRow.RustSemanticID)
		}
		row.RustIdentityVerified = true
		totals.Verified++
		switch mapping.Disposition {
		case dispositionExact:
			totals.Exact++
		case dispositionRelocated:
			totals.Relocated++
		case dispositionRenamed:
			totals.Renamed++
		case dispositionAbsorbed:
			totals.Absorbed++
		default:
			return nil, fmt.Errorf("row %s carries unknown disposition %q", mapRow.ID, mapping.Disposition)
		}
		rows = append(rows, row)
	}
	for id := range rowMappings {
		if !covered[id] {
			return nil, fmt.Errorf("linkage mapping %s matches no migration row", id)
		}
	}
	return &VerificationDocument{
		Schema:        "../../schemas/rust-identity-verification-1.0.0.schema.json",
		SchemaVersion: "1.0.0",
		EntityType:    "RustIdentityVerification",
		DocumentID:    "rust-identity-verification.e2-linkage",
		MapRef: MapRef{
			Path:       migrationMapPath,
			MapID:      migration.MapID,
			MapVersion: migration.MapVersion,
			SHA256:     mapDigest,
		},
		FrozenMapDisclosure: "The US-003 migration map is a frozen derived document: its 1.0.0 schema pins" +
			" rust_identity_verified to const false, portplan's TestDeriveReproducesCommittedEvidence pins its" +
			" bytes to the Java-only derivation pipeline, and assurance/formal/proof-targets.json digest-pins" +
			" it. Its rows therefore still read rust_identity_verified=false BY CONSTRUCTION. This overlay is" +
			" the resolver verification the map's blocker statement requires: every row's planned Rust identity" +
			" is verified here against the real merged tree, with the truthful landed mapping and a rationale" +
			" wherever the implementation landed an identity differently than the plan. Flipping the in-map" +
			" bits would require an owner-authorized US-003 schema/derivation refreeze plus a US-006" +
			" proof-targets digest refreeze; this layer does not perform either.",
		Resolver: ResolverStatement{
			Method:   "deterministic declaration scan (internal/linkage resolveSymbol)",
			Strength: "declaration-scan (reviewed-glancer class), not rust-analyzer semantic resolution",
			Statement: "Each landed symbol is verified by scanning its declaring file for the exact declaration" +
				" form (struct/enum/trait/type-alias/fn/method/enum-variant, with owner-impl presence checked" +
				" for members) and recording the file, line, declaration text, and the file's sha256 at" +
				" verification time. The migration map's planned_resolver names rust-analyzer; running it was" +
				" not part of this layer, so this record claims reviewed-glancer strength, never semantic" +
				" resolver strength. The companion Go tests re-run this scan on every test execution, so a" +
				" moved or deleted symbol turns this artifact stale loudly.",
		},
		Rows:      rows,
		Summary:   totals,
		Assurance: ownerAttested,
	}, nil
}

// proofTargetsDocument is the minimal read model of the frozen US-006 plan.
type proofTargetsDocument struct {
	Targets []struct {
		TargetID          string `json:"target_id"`
		Title             string `json:"title"`
		ProductionSymbols []struct {
			SymbolID      string `json:"symbol_id"`
			PlannedSymbol string `json:"planned_symbol"`
		} `json:"production_symbols"`
	} `json:"targets"`
}

// BuildDAG derives the linkage evidence DAG from the verification document,
// the frozen proof targets, the frozen migration map, and the tree.
func BuildDAG(root string, verification *VerificationDocument) (*DAGDocument, error) {
	targetsContent, _, err := fileDigest(root, proofTargetsPath)
	if err != nil {
		return nil, err
	}
	var targets proofTargetsDocument
	if err := json.Unmarshal(targetsContent, &targets); err != nil {
		return nil, err
	}
	migration, _, err := loadMigrationMap(root)
	if err != nil {
		return nil, err
	}

	nodes := map[string]DAGNode{}
	edgeSet := map[DAGEdge]bool{}
	addNode := func(node DAGNode) { nodes[node.ID] = node }
	addEdge := func(from, to, kind string) { edgeSet[DAGEdge{From: from, To: to, Kind: kind}] = true }
	addSymbol := func(rustPath string) error {
		if _, exists := nodes[rustPath]; exists {
			return nil
		}
		resolved, err := resolveSymbol(root, rustPath)
		if err != nil {
			return err
		}
		addNode(DAGNode{
			ID:       rustPath,
			Kind:     "symbol",
			RustPath: resolved.RustPath,
			DeclKind: resolved.DeclKind,
			File:     resolved.File,
			Line:     resolved.Line,
			SHA256:   resolved.SHA256,
		})
		return nil
	}

	for story, title := range storyTitles {
		addNode(DAGNode{ID: story, Kind: "story", Title: title})
	}
	for id, spec := range evidenceCatalog {
		_, digest, err := fileDigest(root, spec.Path)
		if err != nil {
			return nil, fmt.Errorf("evidence %s: %w", id, err)
		}
		addNode(DAGNode{ID: id, Kind: "evidence", Title: spec.Title, Path: spec.Path, SHA256: digest, Lineage: spec.Lineage})
	}
	for story, evidenceIDs := range storyEvidence {
		if _, exists := nodes[story]; !exists {
			return nil, fmt.Errorf("story %s carries evidence but no node", story)
		}
		for _, evidenceID := range evidenceIDs {
			if _, exists := evidenceCatalog[evidenceID]; !exists {
				return nil, fmt.Errorf("story %s cites unknown evidence %s", story, evidenceID)
			}
			addEdge(story, evidenceID, "evidenced_by")
		}
	}

	rowByID := map[string]VerificationRow{}
	for _, row := range verification.Rows {
		rowByID[row.RowID] = row
	}
	for _, mapRow := range migration.Rows {
		row, exists := rowByID[mapRow.ID]
		if !exists {
			return nil, fmt.Errorf("migration row %s missing from the verification document", mapRow.ID)
		}
		addNode(DAGNode{
			ID:          row.RowID,
			Kind:        "migration_row",
			JavaID:      row.JavaSemanticID,
			Disposition: row.Disposition,
		})
		for _, slice := range mapRow.PortSlices {
			if _, known := storyTitles[slice.ChildStoryID]; !known {
				return nil, fmt.Errorf("row %s binds unknown story %s", mapRow.ID, slice.ChildStoryID)
			}
			addEdge(slice.ChildStoryID, row.RowID, "owns")
		}
		for _, symbol := range row.LandedSymbols {
			if err := addSymbol(symbol.RustPath); err != nil {
				return nil, err
			}
			addEdge(row.RowID, symbol.RustPath, "maps_to")
		}
	}

	for story, symbols := range storySymbols {
		for _, rustPath := range symbols {
			if err := addSymbol(rustPath); err != nil {
				return nil, err
			}
			addEdge(story, rustPath, "implements")
		}
	}

	boundSymbolIDs := map[string]bool{}
	for _, target := range targets.Targets {
		addNode(DAGNode{ID: target.TargetID, Kind: "proof_target", Title: target.Title})
		addEdge(target.TargetID, "evidence.linkage.proof-targets", "declared_in")
		for _, planned := range target.ProductionSymbols {
			binding, known := proofTargetSymbolBindings[planned.SymbolID]
			if !known {
				return nil, fmt.Errorf("proof-target symbol %s has no landed binding", planned.SymbolID)
			}
			boundSymbolIDs[planned.SymbolID] = true
			if _, exists := nodes[planned.SymbolID]; !exists {
				addNode(DAGNode{
					ID:          planned.SymbolID,
					Kind:        "planned_symbol",
					Title:       planned.PlannedSymbol,
					Disposition: binding.Disposition,
					Lineage:     binding.Rationale,
				})
			}
			addEdge(target.TargetID, planned.SymbolID, "declares")
			for _, rustPath := range binding.Symbols {
				if err := addSymbol(rustPath); err != nil {
					return nil, fmt.Errorf("proof-target symbol %s: %w", planned.SymbolID, err)
				}
				addEdge(planned.SymbolID, rustPath, "landed_as")
			}
		}
	}
	for symbolID := range proofTargetSymbolBindings {
		if !boundSymbolIDs[symbolID] {
			return nil, fmt.Errorf("landed binding %s matches no proof-target production symbol", symbolID)
		}
	}

	orderedNodes := make([]DAGNode, 0, len(nodes))
	for _, node := range nodes {
		orderedNodes = append(orderedNodes, node)
	}
	sort.Slice(orderedNodes, func(i, j int) bool { return orderedNodes[i].ID < orderedNodes[j].ID })
	orderedEdges := make([]DAGEdge, 0, len(edgeSet))
	for edge := range edgeSet {
		orderedEdges = append(orderedEdges, edge)
	}
	sort.Slice(orderedEdges, func(i, j int) bool {
		if orderedEdges[i].From != orderedEdges[j].From {
			return orderedEdges[i].From < orderedEdges[j].From
		}
		if orderedEdges[i].To != orderedEdges[j].To {
			return orderedEdges[i].To < orderedEdges[j].To
		}
		return orderedEdges[i].Kind < orderedEdges[j].Kind
	})

	return &DAGDocument{
		Schema:        "../../schemas/linkage-evidence-dag-1.0.0.schema.json",
		SchemaVersion: "1.0.0",
		EntityType:    "LinkageEvidenceDAG",
		DAGID:         "linkage-evidence-dag.e2",
		Scope: "Additive linkage layer closing dossier gap G7: story, migration-row, planned-symbol, and" +
			" implemented-symbol nodes binding the US-006 proof targets and the US-009..US-018 stories to the" +
			" exact shipped Rust symbols and their verifying in-repo evidence. The frozen US-004 owner-only" +
			" lifecycle DAG at assurance/evidence-dag.json is a sealed exact closure (internal/assurance blocks" +
			" node drift) and is deliberately untouched; this DAG lives beside it.",
		Nonclaim: "No story acceptance is claimed by this DAG. Evidence nodes carry their honest lineage" +
			" (reference-model-derived corpus expectations remain pending live-oracle confirmation; the" +
			" abstract model check remains proved-model-only; the proof-target plan remains a plan). Single" +
			" owner, no independent review.",
		Nodes:     orderedNodes,
		Edges:     orderedEdges,
		Assurance: ownerAttested,
	}, nil
}

// marshalDocument renders an artifact deterministically.
func marshalDocument(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// WriteArtifacts derives and writes both linkage artifacts. Used only by the
// sanctioned LINKAGE_REGENERATE=1 path in the tests.
func WriteArtifacts(root string) error {
	verification, err := BuildVerification(root)
	if err != nil {
		return err
	}
	dag, err := BuildDAG(root, verification)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "evidence", "linkage"), 0o755); err != nil {
		return err
	}
	for _, artifact := range []struct {
		path  string
		value any
	}{
		{VerificationPath, verification},
		{DAGPath, dag},
	} {
		encoded, err := marshalDocument(artifact.value)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(artifact.path)), encoded, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Verify re-derives both artifacts and compares them byte-for-byte with the
// committed files, returning typed findings (empty means verified).
func Verify(root string) []string {
	var findings []string
	verification, err := BuildVerification(root)
	if err != nil {
		return []string{"LINKAGE_DERIVATION_FAILED: " + err.Error()}
	}
	dag, err := BuildDAG(root, verification)
	if err != nil {
		return []string{"LINKAGE_DERIVATION_FAILED: " + err.Error()}
	}
	for _, artifact := range []struct {
		path    string
		value   any
		missing string
		drifted string
	}{
		{VerificationPath, verification, "LINKAGE_VERIFICATION_MISSING", "LINKAGE_VERIFICATION_DRIFTED"},
		{DAGPath, dag, "LINKAGE_DAG_MISSING", "LINKAGE_DAG_DRIFTED"},
	} {
		committed, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(artifact.path)))
		if err != nil {
			findings = append(findings, artifact.missing+": "+err.Error())
			continue
		}
		derived, err := marshalDocument(artifact.value)
		if err != nil {
			findings = append(findings, "LINKAGE_DERIVATION_FAILED: "+err.Error())
			continue
		}
		if string(committed) != string(derived) {
			findings = append(findings, artifact.drifted+": committed bytes are not what the tree derives; regenerate deliberately with LINKAGE_REGENERATE=1")
		}
	}
	return findings
}
