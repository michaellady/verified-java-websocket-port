package javabind

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Paths are the repository-relative locations of the artifacts this package
// owns. They are constants so the tool and its tests cannot drift apart.
const (
	SpecPath       = "assurance/formal/java-binding-spec.json"
	CatalogPath    = "assurance/formal/obligation-catalog.json"
	ReceiptPath    = "evidence/java/formal-bindings/receipt.json"
	ProjectionPath = "evidence/java/formal-bindings/coverage-projection.json"
)

// LoadArtifact reads one repository artifact and returns its bytes and identity.
func LoadArtifact(root, relative string) ([]byte, ArtifactIdentity, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return nil, ArtifactIdentity{}, err
	}
	return data, ArtifactIdentity{Path: relative, SHA256: Digest(data)}, nil
}

// Observe executes every scenario the spec declares, baseline and mutant, and
// returns the receipt. It never reads the previous receipt, so it cannot
// accidentally reproduce a stale value.
func Observe(ctx context.Context, config ObserveConfig) (Receipt, Spec, Catalog, error) {
	specBytes, specIdentity, err := LoadArtifact(config.RepoRoot, SpecPath)
	if err != nil {
		return Receipt{}, Spec{}, Catalog{}, err
	}
	spec, err := DecodeSpec(specBytes)
	if err != nil {
		return Receipt{}, Spec{}, Catalog{}, err
	}
	catalogBytes, catalogIdentity, err := LoadArtifact(config.RepoRoot, CatalogPath)
	if err != nil {
		return Receipt{}, Spec{}, Catalog{}, err
	}
	if catalogIdentity.SHA256 != spec.Catalog.SHA256 {
		return Receipt{}, Spec{}, Catalog{}, fmt.Errorf("javabind: the catalog on disk is %s but the spec pins %s", catalogIdentity.SHA256, spec.Catalog.SHA256)
	}
	catalog, err := DecodeCatalog(catalogBytes)
	if err != nil {
		return Receipt{}, Spec{}, Catalog{}, err
	}
	observer, err := NewObserver(ctx, config)
	if err != nil {
		return Receipt{}, Spec{}, Catalog{}, err
	}

	receipt := Receipt{
		SchemaVersion: "1.0.0",
		ReceiptID:     "java-formal-bindings",
		GeneratedAt:   NowUTC(),
		Assurance:     DefaultAssurance(),
		Spec:          specIdentity,
		Catalog:       catalogIdentity,
		PinnedSource:  spec.PinnedSource,
		PinnedRuntime: spec.PinnedRuntime,
		Toolchain:     observer.Toolchain(),
	}

	// Every scenario the spec declares runs once, unmutated.
	scenarios := append([]Scenario(nil), spec.Scenarios...)
	sort.Slice(scenarios, func(i, j int) bool { return scenarios[i].ScenarioID < scenarios[j].ScenarioID })
	for _, scenario := range scenarios {
		run, err := observer.ExecuteBaseline(ctx, scenario)
		if err != nil {
			return Receipt{}, Spec{}, Catalog{}, err
		}
		run.RunID = "baseline/" + scenario.ScenarioID
		run.Variant = VariantBaseline
		receipt.Runs = append(receipt.Runs, run)
	}

	bindings := append([]Binding(nil), spec.Bindings...)
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].ObligationID < bindings[j].ObligationID })
	for _, binding := range bindings {
		constructs, file, err := observer.ResolveConstructs(binding, catalog)
		if err != nil {
			return Receipt{}, Spec{}, Catalog{}, err
		}
		receipt.SourceConstructs = append(receipt.SourceConstructs, constructs...)

		for _, mutation := range binding.Mutations() {
			var member SourceConstruct
			found := false
			for _, construct := range constructs {
				if construct.ChainMember == mutation.ChainMember {
					member = construct
					found = true
				}
			}
			if !found {
				return Receipt{}, Spec{}, Catalog{}, fmt.Errorf("javabind: mutation %q names chain member %q, which did not resolve", mutation.MutationID, mutation.ChainMember)
			}
			mutated, application, err := ApplyMutation(file, member, mutation)
			if err != nil {
				return Receipt{}, Spec{}, Catalog{}, err
			}
			scenario, ok := spec.Scenario(mutation.ScenarioID)
			if !ok {
				return Receipt{}, Spec{}, Catalog{}, fmt.Errorf("javabind: mutation %q names unknown scenario %q", mutation.MutationID, mutation.ScenarioID)
			}
			// The control isolates the edit from the act of recompiling and
			// repackaging: same compiler, same archive surgery, unmutated source.
			controlArchive, controlDigest, err := observer.BuildRuntimeVariant(ctx, mutation.MutationID+"/control", binding.SourceFile, file)
			if err != nil {
				return Receipt{}, Spec{}, Catalog{}, err
			}
			mutantArchive, mutantDigest, err := observer.BuildRuntimeVariant(ctx, mutation.MutationID+"/mutant", binding.SourceFile, mutated)
			if err != nil {
				return Receipt{}, Spec{}, Catalog{}, err
			}
			if controlDigest == mutantDigest {
				return Receipt{}, Spec{}, Catalog{}, fmt.Errorf("javabind: mutation %q produced a runtime identical to its control", mutation.MutationID)
			}
			application.ControlRuntime = controlDigest
			application.MutantRuntime = mutantDigest
			receipt.Mutations = append(receipt.Mutations, application)

			controlRun, err := observer.ExecuteAgainstArchive(ctx, scenario, controlArchive, controlDigest)
			if err != nil {
				return Receipt{}, Spec{}, Catalog{}, err
			}
			controlRun.RunID = "control/" + mutation.MutationID
			controlRun.Variant = "CONTROL:" + mutation.MutationID
			receipt.Runs = append(receipt.Runs, controlRun)

			mutantRun, err := observer.ExecuteAgainstArchive(ctx, scenario, mutantArchive, mutantDigest)
			if err != nil {
				return Receipt{}, Spec{}, Catalog{}, err
			}
			mutantRun.RunID = "mutant/" + mutation.MutationID
			mutantRun.Variant = "MUTANT:" + mutation.MutationID
			receipt.Runs = append(receipt.Runs, mutantRun)
		}
	}
	return receipt, spec, catalog, nil
}

// Verify recomputes the projection from the retained artifacts alone. It needs
// no JVM and no quarantined tree.
func Verify(root string) (Projection, error) {
	specBytes, specIdentity, err := LoadArtifact(root, SpecPath)
	if err != nil {
		return Projection{}, err
	}
	spec, err := DecodeSpec(specBytes)
	if err != nil {
		return Projection{}, err
	}
	catalogBytes, catalogIdentity, err := LoadArtifact(root, CatalogPath)
	if err != nil {
		return Projection{}, err
	}
	catalog, err := DecodeCatalog(catalogBytes)
	if err != nil {
		return Projection{}, err
	}
	receiptBytes, receiptIdentity, err := LoadArtifact(root, ReceiptPath)
	if err != nil {
		return Projection{}, err
	}
	receipt, err := DecodeReceipt(receiptBytes)
	if err != nil {
		return Projection{}, err
	}
	if receipt.Spec.SHA256 != specIdentity.SHA256 {
		return Projection{}, fmt.Errorf("javabind: the receipt was produced from spec %s but the spec on disk is %s", receipt.Spec.SHA256, specIdentity.SHA256)
	}
	return Derive(spec, receipt, catalog, specIdentity, catalogIdentity, receiptIdentity)
}

// MarshalArtifact renders an artifact the way this repository stores JSON:
// two-space indentation with a trailing newline.
func MarshalArtifact(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
