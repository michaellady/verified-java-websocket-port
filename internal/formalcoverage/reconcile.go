package formalcoverage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Mapping states for the reconciliation. They are a closed vocabulary: an
// obligation is either mapped onto at least one target or it is not, and the
// "not" case is the interesting one, so it gets a name of its own rather than
// an empty list nobody reads.
const (
	MappingMapped             = "MAPPED"
	MappingObligationNoTarget = "UNMAPPED_OBLIGATION_NAMES_NO_PLANNED_TARGET"
	MappingTargetNoObligation = "UNMAPPED_TARGET_NAMED_BY_NO_OBLIGATION"
	BasisAgreementExact       = "BASIS_PIN_MATCHES_FILE_ON_DISK"
	BasisAgreementDrifted     = "BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK"
	BasisAgreementPathAbsent  = "BASIS_PIN_PATH_IS_ABSENT_FROM_THIS_PLANE"
	BasisAgreementNotDeclared = "NO_BASIS_PIN_DECLARED_FOR_THIS_PATH"
	RustPathPresent           = "SOURCE_PATH_EXISTS_ON_THIS_PLANE"
	RustPathAbsent            = "SOURCE_PATH_ABSENT_FROM_THIS_PLANE"
	RustNamespaceAgrees       = "NAMESPACE_NAMES_A_CRATE_SHIPPED_BY_THIS_PLANE"
	RustNamespaceDisagrees    = "NAMESPACE_NAMES_NO_CRATE_SHIPPED_BY_THIS_PLANE"
)

// ObligationMapping is one obligation's side of the reconciliation.
type ObligationMapping struct {
	ObligationID    string   `json:"obligation_id"`
	SurfaceIDs      []string `json:"surface_ids"`
	CatalogSymbol   string   `json:"catalog_java_production_symbol"`
	JavaKey         string   `json:"java_key"`
	TargetIDs       []string `json:"proof_target_ids"`
	TargetSymbolIDs []string `json:"proof_target_symbol_ids"`
	State           string   `json:"mapping_state"`
}

// TargetMapping is one proof target's side of the reconciliation.
type TargetMapping struct {
	TargetID          string   `json:"target_id"`
	FormalClaimID     string   `json:"formal_claim_id"`
	PropertyClaimRefs []string `json:"property_claim_refs"`
	JavaKeys          []string `json:"java_keys"`
	ObligationIDs     []string `json:"obligation_ids"`
	State             string   `json:"mapping_state"`
}

// SharedAnchor records the one fact that makes the join legitimate: both
// documents are anchored to the same digest-pinned Java archive.
type SharedAnchor struct {
	CatalogArchiveSHA256       string `json:"catalog_java_binding_archive_sha256"`
	ProofTargetArchiveSHA256   string `json:"proof_target_quarantined_archive_sha256"`
	Agree                      bool   `json:"agree"`
	CatalogDistinctJavaDigests int    `json:"catalog_distinct_java_source_digests"`
	TargetDistinctJavaDigests  int    `json:"proof_target_distinct_java_file_digests"`
	Note                       string `json:"note"`
}

// BasisPin records whether the catalog's declared denominator basis still
// matches the file on disk.
type BasisPin struct {
	Path         string `json:"path"`
	DeclaredSHA  string `json:"catalog_declared_sha256"`
	DeclaredBlob string `json:"catalog_declared_git_blob"`
	OnDiskSHA    string `json:"on_disk_sha256"`
	OnDiskBlob   string `json:"on_disk_git_blob"`
	Agreement    string `json:"agreement"`
}

// RustBindingCheck records, per distinct catalog Rust source path, whether that
// path and namespace exist in the shipped tree at all.
type RustBindingCheck struct {
	SourcePath        string   `json:"catalog_source_path"`
	ProductionSymbols []string `json:"catalog_production_symbols"`
	ObligationCount   int      `json:"obligation_count"`
	PathState         string   `json:"path_state"`
	NamespaceRoot     string   `json:"namespace_root"`
	NamespaceState    string   `json:"namespace_state"`
	ShippedCrates     []string `json:"shipped_crate_namespaces"`
	// PathCorrespondence and NamespaceCorrespondence say what the two states
	// above MEAN. Absent-on-this-plane is an observation about this tree; on
	// its own it does not say whether the catalog is wrong or whether it is
	// simply about a different tree. These two fields carry that difference,
	// read from the plane-correspondence record.
	PathCorrespondence      string `json:"path_correspondence_state"`
	NamespaceCorrespondence string `json:"namespace_correspondence_state"`
	MeasurableHere          bool   `json:"measurable_on_this_plane"`
}

// ReconciliationCounts are the derived numbers. Every one is a count of rows,
// never a weighted score.
type ReconciliationCounts struct {
	Obligations                    int `json:"obligations"`
	ProofTargets                   int `json:"proof_targets"`
	ObligationsMapped              int `json:"obligations_mapped_to_at_least_one_target"`
	ObligationsWithNoTarget        int `json:"obligations_with_no_proof_target"`
	TargetsMapped                  int `json:"targets_named_by_at_least_one_obligation"`
	TargetsWithNoObligation        int `json:"targets_named_by_no_obligation"`
	CatalogDistinctJavaKeys        int `json:"catalog_distinct_java_keys"`
	TargetDistinctJavaKeys         int `json:"proof_target_distinct_java_keys"`
	JavaKeysInBoth                 int `json:"java_keys_in_both"`
	JavaKeysCatalogOnly            int `json:"java_keys_catalog_only"`
	JavaKeysTargetOnly             int `json:"java_keys_proof_target_only"`
	PropertyClaimRefs              int `json:"property_claim_references"`
	DistinctPropertyClaimRefs      int `json:"distinct_property_claim_references"`
	PlannedProductionSymbols       int `json:"planned_production_symbols"`
	PlannedSymbolsResolverVerified int `json:"planned_symbols_resolver_verified"`
	MigrationBindings              int `json:"migration_bindings"`
	MigrationBindingsVerified      int `json:"migration_bindings_rust_identity_verified"`
	RustBindingPathsAbsent         int `json:"catalog_rust_binding_rows_whose_source_path_is_absent"`
	RustBindingNamespacesAbsent    int `json:"catalog_rust_binding_rows_whose_namespace_is_absent"`
	RustBindingRowsMeasurableHere  int `json:"catalog_rust_binding_rows_measurable_on_this_plane"`
}

// Reconciliation is the derived checked mapping between the two denominators.
type Reconciliation struct {
	SchemaVersion    string               `json:"schema_version"`
	DocumentID       string               `json:"document_id"`
	EntityType       string               `json:"entity_type"`
	Statement        string               `json:"statement"`
	JoinRule         string               `json:"join_rule"`
	Assurance        Assurance            `json:"assurance"`
	Catalog          ArtifactIdentity     `json:"catalog"`
	ProofTargets     ArtifactIdentity     `json:"proof_targets"`
	PlaneRecord      ArtifactIdentity     `json:"plane_correspondence"`
	CatalogPlane     PlaneIdentity        `json:"catalog_is_about_this_plane"`
	SharedAnchor     SharedAnchor         `json:"shared_java_anchor"`
	BasisPins        []BasisPin           `json:"catalog_declared_basis_pins"`
	Counts           ReconciliationCounts `json:"counts"`
	Obligations      []ObligationMapping  `json:"obligations"`
	Targets          []TargetMapping      `json:"targets"`
	JavaKeysBoth     []string             `json:"java_keys_in_both"`
	JavaKeysCatalog  []string             `json:"java_keys_catalog_only"`
	JavaKeysTarget   []string             `json:"java_keys_proof_target_only"`
	RustBindingCheck []RustBindingCheck   `json:"catalog_rust_binding_checks"`
	NotClaims        []string             `json:"not_claims"`
}

// CrateLibNamespace returns the Rust library namespace a crate manifest
// actually ships: its [lib] name when it declares one, and otherwise its
// [package] name with hyphens replaced, which is what `use` resolves against.
//
// It is deliberately NOT the directory name. On the plane the vendored catalog
// came from, the directory rust/connection-core ships the library
// `websocket_core`; on this plane the directory rust/ws-core ships `ws_core`
// and says so explicitly in a [lib] name its manifest comments call canonical.
// A checker that read directory names would report namespaces no crate has and
// miss namespaces every crate has -- the directory name standing in for the
// crate identity. Reading the manifest is the difference between a name that
// looks right and the identity the compiler resolves against.
func CrateLibNamespace(manifest []byte) string {
	section, pkg, lib := "", "", ""
	for _, raw := range strings.Split(string(manifest), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != "name" {
			continue
		}
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		switch section {
		case "[package]":
			if pkg == "" {
				pkg = value
			}
		case "[lib]":
			if lib == "" {
				lib = value
			}
		}
	}
	if lib != "" {
		return lib
	}
	return strings.ReplaceAll(pkg, "-", "_")
}

// shippedCrateNamespaces lists the Rust library namespaces the workspace
// actually ships. It is derived from each crate's own manifest, never from the
// directory the crate happens to sit in, and never asserted.
func shippedCrateNamespaces(root string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, "rust"))
	if err != nil {
		return nil, err
	}
	var namespaces []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifest, err := os.ReadFile(filepath.Join(root, "rust", entry.Name(), "Cargo.toml"))
		if err != nil {
			continue
		}
		namespace := CrateLibNamespace(manifest)
		if namespace == "" {
			continue
		}
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	return namespaces, nil
}

// Reconcile derives the whole reconciliation from the two denominators and the
// shipped tree. It is the only place these counts are produced.
func Reconcile(root string) (Reconciliation, error) {
	catalogBytes, catalogIdentity, err := LoadArtifact(root, CatalogPath)
	if err != nil {
		return Reconciliation{}, err
	}
	if catalogIdentity.SHA256 != CatalogSHA256 || catalogIdentity.GitBlob != CatalogGitBlob {
		return Reconciliation{}, fmt.Errorf("formalcoverage: the catalog on disk is %s/%s, not the vendored Codex catalog %s/%s",
			catalogIdentity.SHA256, catalogIdentity.GitBlob, CatalogSHA256, CatalogGitBlob)
	}
	catalog, err := DecodeCatalog(catalogBytes)
	if err != nil {
		return Reconciliation{}, err
	}
	planBytes, planIdentity, err := LoadArtifact(root, ProofTargetsPath)
	if err != nil {
		return Reconciliation{}, err
	}
	plan, err := DecodeProofTargets(planBytes)
	if err != nil {
		return Reconciliation{}, err
	}
	// The plane record is an INPUT to the reconciliation, not a commentary on
	// it: without it there is no way to say whether an unresolved Rust name is
	// a defect or a plane mismatch, and a reconciliation that guessed would be
	// the original error in a new place. A record that does not check out
	// refuses the whole derivation rather than annotating it.
	planeFindings, planeDoc, err := VerifyPlaneCorrespondence(root)
	if err != nil {
		return Reconciliation{}, err
	}
	if len(planeFindings) > 0 {
		return Reconciliation{}, fmt.Errorf("formalcoverage: the plane-correspondence record does not check out (%d findings, first: %s/%s: %s)",
			len(planeFindings), planeFindings[0].Subject, planeFindings[0].Check, planeFindings[0].Detail)
	}
	_, planeIdentity, err := LoadArtifact(root, PlaneCorrespondencePath)
	if err != nil {
		return Reconciliation{}, err
	}
	planeStates := planeDoc.States()

	// --- the join, on the one key both documents carry -------------------
	catalogByKey := map[JavaKey][]string{}
	for _, binding := range catalog.JavaBindings {
		key := CatalogJavaKey(binding.ProductionSymbol)
		catalogByKey[key] = append(catalogByKey[key], binding.ObligationID)
	}
	type targetRef struct {
		targetID string
		symbolID string
	}
	targetByKey := map[JavaKey][]targetRef{}
	for _, target := range plan.Targets {
		for _, symbol := range target.ProductionSymbols {
			for _, member := range symbol.JavaAuthorityMember {
				key := TargetJavaKey(member)
				targetByKey[key] = append(targetByKey[key], targetRef{target.TargetID, symbol.SymbolID})
			}
		}
	}

	obligations := make([]ObligationMapping, 0, CatalogDenominator)
	targetToObligations := map[string]map[string]bool{}
	for _, obligation := range catalog.Obligations {
		binding, ok := catalog.JavaBinding(obligation.ObligationID)
		if !ok {
			return Reconciliation{}, fmt.Errorf("formalcoverage: catalog has no java binding for %q", obligation.ObligationID)
		}
		key := CatalogJavaKey(binding.ProductionSymbol)
		row := ObligationMapping{
			ObligationID:  obligation.ObligationID,
			SurfaceIDs:    append([]string(nil), obligation.SurfaceIDs...),
			CatalogSymbol: binding.ProductionSymbol,
			JavaKey:       string(key),
			State:         MappingObligationNoTarget,
		}
		targets := map[string]bool{}
		symbols := map[string]bool{}
		for _, ref := range targetByKey[key] {
			targets[ref.targetID] = true
			symbols[ref.symbolID] = true
			if targetToObligations[ref.targetID] == nil {
				targetToObligations[ref.targetID] = map[string]bool{}
			}
			targetToObligations[ref.targetID][obligation.ObligationID] = true
		}
		row.TargetIDs = sortedKeys(targets)
		row.TargetSymbolIDs = sortedKeys(symbols)
		if len(row.TargetIDs) > 0 {
			row.State = MappingMapped
		}
		obligations = append(obligations, row)
	}
	sort.Slice(obligations, func(i, j int) bool { return obligations[i].ObligationID < obligations[j].ObligationID })

	targets := make([]TargetMapping, 0, ProofTargetDenominator)
	propertyRefs := 0
	distinctPropertyRefs := map[string]bool{}
	plannedSymbols := 0
	resolverVerified := 0
	migrationBindings := 0
	migrationVerified := 0
	targetKeyCount := map[JavaKey]bool{}
	for _, target := range plan.Targets {
		keys := map[string]bool{}
		for _, symbol := range target.ProductionSymbols {
			plannedSymbols++
			if symbol.Resolution.State == "RESOLVER_VERIFIED" && symbol.Resolution.ResolvedSymbol != nil {
				resolverVerified++
			}
			for _, member := range symbol.JavaAuthorityMember {
				key := TargetJavaKey(member)
				keys[string(key)] = true
				targetKeyCount[key] = true
			}
		}
		for _, binding := range target.MigrationBindings {
			migrationBindings++
			if binding.RustIdentityVerified {
				migrationVerified++
			}
		}
		propertyRefs += len(target.PropertyClaimRefs)
		for _, ref := range target.PropertyClaimRefs {
			distinctPropertyRefs[ref] = true
		}
		row := TargetMapping{
			TargetID:          target.TargetID,
			FormalClaimID:     target.FormalClaimID,
			PropertyClaimRefs: append([]string(nil), target.PropertyClaimRefs...),
			JavaKeys:          sortedKeys(keys),
			ObligationIDs:     sortedKeys(targetToObligations[target.TargetID]),
			State:             MappingTargetNoObligation,
		}
		if len(row.ObligationIDs) > 0 {
			row.State = MappingMapped
		}
		targets = append(targets, row)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].TargetID < targets[j].TargetID })

	// --- the key sets, published rather than summarised -------------------
	var both, catalogOnly, targetOnly []string
	for key := range catalogByKey {
		if _, ok := targetByKey[key]; ok {
			both = append(both, string(key))
		} else {
			catalogOnly = append(catalogOnly, string(key))
		}
	}
	for key := range targetByKey {
		if _, ok := catalogByKey[key]; !ok {
			targetOnly = append(targetOnly, string(key))
		}
	}
	sort.Strings(both)
	sort.Strings(catalogOnly)
	sort.Strings(targetOnly)

	// --- the shared Java anchor ------------------------------------------
	catalogDigests := map[string]bool{}
	archive := ""
	for _, binding := range catalog.JavaBindings {
		catalogDigests[binding.SourceSHA256] = true
		if binding.Identity.ArchiveSHA256 != nil {
			archive = *binding.Identity.ArchiveSHA256
		}
	}
	targetDigests := map[string]bool{}
	for _, target := range plan.Targets {
		for _, anchor := range target.JavaAuthority {
			targetDigests[anchor.SHA256] = true
		}
	}
	anchor := SharedAnchor{
		CatalogArchiveSHA256:       archive,
		ProofTargetArchiveSHA256:   plan.Sources.QuarantinedJavaTree.ArchiveSHA256,
		Agree:                      archive == plan.Sources.QuarantinedJavaTree.ArchiveSHA256 && archive != "",
		CatalogDistinctJavaDigests: len(catalogDigests),
		TargetDistinctJavaDigests:  len(targetDigests),
		Note: "Both denominators are anchored to the same digest-pinned Java-WebSocket archive, which is what makes " +
			"the Java-construct join legitimate. They are not anchored to it with the same resolution: the catalog " +
			"gives all 24 java_bindings one whole-archive digest, so its Java column distinguishes no two obligations " +
			"by content, while the proof-target plan gives its Java authority per-file digests and file:line spans.",
	}

	// --- the catalog's own declared basis pins ----------------------------
	var basisPins []BasisPin
	for _, basis := range catalog.DenominatorBasis {
		pin := BasisPin{Path: basis.Path, DeclaredSHA: basis.SHA256, DeclaredBlob: basis.Git.Blob, Agreement: BasisAgreementNotDeclared}
		data, identity, err := LoadArtifact(root, basis.Path)
		if err != nil {
			// A pin whose path is not on this plane has NOT drifted. Drift is a
			// claim that the pinned file changed; absence is a claim about which
			// tree the pin is about, and the two must not share a code. Reading
			// them as one is absence standing in for defect.
			pin.OnDiskSHA = "PATH_ABSENT"
			pin.Agreement = BasisAgreementDrifted
			if errors.Is(err, fs.ErrNotExist) {
				pin.Agreement = BasisAgreementPathAbsent
			}
			basisPins = append(basisPins, pin)
			continue
		}
		_ = data
		pin.OnDiskSHA = identity.SHA256
		pin.OnDiskBlob = identity.GitBlob
		if identity.SHA256 == basis.SHA256 && identity.GitBlob == basis.Git.Blob {
			pin.Agreement = BasisAgreementExact
		} else {
			pin.Agreement = BasisAgreementDrifted
		}
		basisPins = append(basisPins, pin)
	}
	sort.Slice(basisPins, func(i, j int) bool { return basisPins[i].Path < basisPins[j].Path })

	// --- the catalog's Rust column, against the shipped tree --------------
	crates, err := shippedCrateNamespaces(root)
	if err != nil {
		return Reconciliation{}, err
	}
	crateSet := map[string]bool{}
	for _, crate := range crates {
		crateSet[crate] = true
	}
	byPath := map[string]*RustBindingCheck{}
	pathsAbsent, namespacesAbsent, measurableHere := 0, 0, 0
	for _, binding := range catalog.RustBindings {
		check, ok := byPath[binding.SourcePath]
		if !ok {
			check = &RustBindingCheck{SourcePath: binding.SourcePath, ShippedCrates: crates, PathState: RustPathAbsent, NamespaceState: RustNamespaceDisagrees}
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(binding.SourcePath))); err == nil {
				check.PathState = RustPathPresent
			}
			check.NamespaceRoot = strings.Split(binding.ProductionSymbol, "::")[0]
			if crateSet[check.NamespaceRoot] {
				check.NamespaceState = RustNamespaceAgrees
			}
			check.PathCorrespondence = planeStates.ByPath[binding.SourcePath]
			check.NamespaceCorrespondence = planeStates.ByNamespace[check.NamespaceRoot]
			// Measurable here requires BOTH correspondences to be established.
			// One established half is not half a subject; it is a subject
			// nobody has finished naming.
			check.MeasurableHere = AuthorisesMeasurement(check.PathCorrespondence) &&
				AuthorisesMeasurement(check.NamespaceCorrespondence)
			byPath[binding.SourcePath] = check
		}
		check.ObligationCount++
		if !contains(check.ProductionSymbols, binding.ProductionSymbol) {
			check.ProductionSymbols = append(check.ProductionSymbols, binding.ProductionSymbol)
		}
		if check.PathState == RustPathAbsent {
			pathsAbsent++
		}
		if check.NamespaceState == RustNamespaceDisagrees {
			namespacesAbsent++
		}
		if check.MeasurableHere {
			measurableHere++
		}
	}
	var rustChecks []RustBindingCheck
	for _, check := range byPath {
		sort.Strings(check.ProductionSymbols)
		rustChecks = append(rustChecks, *check)
	}
	sort.Slice(rustChecks, func(i, j int) bool { return rustChecks[i].SourcePath < rustChecks[j].SourcePath })

	counts := ReconciliationCounts{
		Obligations:                    len(obligations),
		ProofTargets:                   len(targets),
		CatalogDistinctJavaKeys:        len(catalogByKey),
		TargetDistinctJavaKeys:         len(targetKeyCount),
		JavaKeysInBoth:                 len(both),
		JavaKeysCatalogOnly:            len(catalogOnly),
		JavaKeysTargetOnly:             len(targetOnly),
		PropertyClaimRefs:              propertyRefs,
		DistinctPropertyClaimRefs:      len(distinctPropertyRefs),
		PlannedProductionSymbols:       plannedSymbols,
		PlannedSymbolsResolverVerified: resolverVerified,
		MigrationBindings:              migrationBindings,
		MigrationBindingsVerified:      migrationVerified,
		RustBindingPathsAbsent:         pathsAbsent,
		RustBindingNamespacesAbsent:    namespacesAbsent,
		RustBindingRowsMeasurableHere:  measurableHere,
	}
	for _, row := range obligations {
		if row.State == MappingMapped {
			counts.ObligationsMapped++
		} else {
			counts.ObligationsWithNoTarget++
		}
	}
	for _, row := range targets {
		if row.State == MappingMapped {
			counts.TargetsMapped++
		} else {
			counts.TargetsWithNoObligation++
		}
	}
	if counts.ObligationsMapped+counts.ObligationsWithNoTarget != CatalogDenominator {
		return Reconciliation{}, fmt.Errorf("formalcoverage: obligation mapping states do not sum to the denominator")
	}
	if counts.TargetsMapped+counts.TargetsWithNoObligation != ProofTargetDenominator {
		return Reconciliation{}, fmt.Errorf("formalcoverage: target mapping states do not sum to the plan size")
	}

	return Reconciliation{
		SchemaVersion: "1.0.0",
		DocumentID:    "us023-denominator-reconciliation",
		EntityType:    "FormalDenominatorReconciliation",
		Statement: "A checked mapping between the two formal denominators this repository carries: the immutable " +
			"24-obligation catalog (assurance/formal/obligation-catalog.json, vendored from the Codex plane) and the " +
			"10-target US-006 proof-target plan (assurance/formal/proof-targets.json). Every obligation maps to zero " +
			"or more targets and every target to zero or more obligations. Obligations with no target and targets " +
			"with no obligation are published as named lists, never summarised into a percentage. The catalog's " +
			"Rust column is read against BOTH the tree it is about and the tree it is being read on: " +
			"catalog_rust_binding_checks reports what this plane holds AND what the plane-correspondence record " +
			"says that absence means, so an unresolved name is never reported as a defect in the catalog when it " +
			"is a mismatch between planes.",
		JoinRule: "Join key: the pinned-Java construct key `DeclaringType#memberName`, derived from the catalog's " +
			"java_bindings[].production_symbol on one side and the plan's targets[].production_symbols[]." +
			"java_authority_members[] on the other. The parameter list is deliberately NOT part of the key: the " +
			"catalog's JVM descriptors are known to disagree with the pinned source's actual parameter lists " +
			"(docs/java-formal-binding-design.md section 3.2), so joining on them would silently shrink the mapping. " +
			"The Rust symbols are NOT a join key and are not used as one — see catalog_rust_binding_checks for why.",
		Assurance:        DefaultAssurance(),
		Catalog:          catalogIdentity,
		ProofTargets:     planIdentity,
		PlaneRecord:      planeIdentity,
		CatalogPlane:     planeDoc.OriginPlane,
		SharedAnchor:     anchor,
		BasisPins:        basisPins,
		Counts:           counts,
		Obligations:      obligations,
		Targets:          targets,
		JavaKeysBoth:     both,
		JavaKeysCatalog:  catalogOnly,
		JavaKeysTarget:   targetOnly,
		RustBindingCheck: rustChecks,
		NotClaims: []string{
			"A mapping is not coverage. That an obligation maps onto a proof target says only that both documents " +
				"name the same pinned-Java construct; it says nothing about whether any proof exists, was executed, " +
				"or reaches the required strength.",
			"An unmapped obligation is not necessarily an uncovered behaviour, and a mapped one is not necessarily a " +
				"covered one. The mapping reports what the two documents say about each other, nothing more.",
			"The join is on the Java side only. The two documents' Rust columns do not join at all, and this " +
				"artifact records that as a finding rather than papering over it with a name-normalising rule.",
			"That the catalog's Rust source paths and namespaces are absent HERE is not a finding about the " +
				"catalog. The catalog is vendored from another plane and its Rust column resolves cleanly on that " +
				"plane; " + PlaneCorrespondencePath + " records the crate-by-crate evidence. The finding is that " +
				"no correspondence between the two planes has been established, so these rows are not measurable " +
				"here -- which is a question for the owner, not a defect to repair.",
		},
	}, nil
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
