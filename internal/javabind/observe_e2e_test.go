//go:build javabinde2e

package javabind

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestExecutedLaneReproducesTheRetainedReceipt crosses the whole boundary again:
// it rebuilds the adapter, re-resolves every declaration span from the pinned
// Java tree, re-applies every canary, re-runs every baseline, control and mutant
// against the pinned runtime, and requires the response bytes and the source
// identities to reproduce the retained receipt exactly.
//
// The explicit environment is mandatory so this lane can only consume promoted,
// digest-pinned artifacts:
//
//	JAVABIND_E2E_JAVA, JAVABIND_E2E_JAVAC, JAVABIND_E2E_JAR_TOOL,
//	JAVABIND_E2E_RUNTIME_JAR, JAVABIND_E2E_SLF4J_API, JAVABIND_E2E_JAVA_SOURCE_ROOT
func TestExecutedLaneReproducesTheRetainedReceipt(t *testing.T) {
	config := ObserveConfig{
		RepoRoot:       repoRoot(t),
		Java:           requiredPath(t, "JAVABIND_E2E_JAVA"),
		Javac:          requiredPath(t, "JAVABIND_E2E_JAVAC"),
		JarTool:        requiredPath(t, "JAVABIND_E2E_JAR_TOOL"),
		RuntimeJAR:     requiredPath(t, "JAVABIND_E2E_RUNTIME_JAR"),
		SLF4JAPI:       requiredPath(t, "JAVABIND_E2E_SLF4J_API"),
		JavaSourceRoot: requiredPath(t, "JAVABIND_E2E_JAVA_SOURCE_ROOT"),
		WorkDir:        t.TempDir(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	fresh, _, _, err := Observe(ctx, config)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	_, _, retained, _, _, _ := loadAllForE2E(t)

	if len(fresh.Runs) != len(retained.Runs) {
		t.Fatalf("fresh run count %d, retained %d", len(fresh.Runs), len(retained.Runs))
	}
	for _, run := range fresh.Runs {
		found := false
		for _, previous := range retained.Runs {
			if previous.RunID != run.RunID {
				continue
			}
			found = true
			if previous.RequestCanonical != run.RequestCanonical {
				t.Fatalf("run %q request bytes changed", run.RunID)
			}
			if previous.ResponseLine != run.ResponseLine {
				t.Fatalf("run %q response bytes changed:\n retained %s\n fresh    %s", run.RunID, previous.ResponseLine, run.ResponseLine)
			}
		}
		if !found {
			t.Fatalf("run %q is not in the retained receipt", run.RunID)
		}
	}
	for _, construct := range fresh.SourceConstructs {
		previous, ok := retained.Construct(construct.ObligationID, construct.ChainMember)
		if !ok {
			t.Fatalf("construct %s#%s is not retained", construct.ObligationID, construct.ChainMember)
		}
		if previous.SpanSHA256 != construct.SpanSHA256 ||
			previous.FileSHA256 != construct.FileSHA256 ||
			previous.Start != construct.Start || previous.End != construct.End ||
			previous.StructureFingerprint != construct.StructureFingerprint ||
			previous.DescriptorAgreement != construct.DescriptorAgreement {
			t.Fatalf("construct %s#%s identity changed", construct.ObligationID, construct.ChainMember)
		}
	}
	for _, mutation := range fresh.Mutations {
		previous, ok := retained.MutationApplication(mutation.MutationID)
		if !ok {
			t.Fatalf("mutation %q is not retained", mutation.MutationID)
		}
		if previous.AbsoluteOffset != mutation.AbsoluteOffset ||
			previous.RemovedSHA256 != mutation.RemovedSHA256 ||
			previous.MutatedFileSHA256 != mutation.MutatedFileSHA256 {
			t.Fatalf("mutation %q application changed", mutation.MutationID)
		}
	}
}

// TestPinnedSourceTreeMatchesTheReceipt re-resolves the bound declarations
// straight out of the quarantined tree and requires every recorded span digest
// to recompute. This is the check the self-contained lane cannot perform.
func TestPinnedSourceTreeMatchesTheReceipt(t *testing.T) {
	spec, _, retained, _, _, _ := loadAllForE2E(t)
	sourceRoot := requiredPath(t, "JAVABIND_E2E_JAVA_SOURCE_ROOT")
	for _, binding := range spec.Bindings {
		file, err := os.ReadFile(filepath.Join(sourceRoot, filepath.FromSlash(binding.SourceFile)))
		if err != nil {
			t.Fatalf("pinned source %q: %v", binding.SourceFile, err)
		}
		for _, member := range binding.Chain {
			decl, err := ResolveMember(file, binding.DeclaringType, member)
			if err != nil {
				t.Fatalf("resolve %s#%s: %v", binding.DeclaringType, member, err)
			}
			recorded, ok := retained.Construct(binding.ObligationID, member)
			if !ok {
				t.Fatalf("no retained construct for %s#%s", binding.ObligationID, member)
			}
			if decl.SpanDigest(file) != recorded.SpanSHA256 {
				t.Fatalf("%s#%s span digest does not recompute from the pinned tree", binding.DeclaringType, member)
			}
			if Digest(file) != recorded.FileSHA256 {
				t.Fatalf("%s file digest does not recompute from the pinned tree", binding.SourceFile)
			}
		}
	}
}

func requiredPath(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" || !filepath.IsAbs(value) {
		t.Fatalf("%s must be set to an absolute path for the javabinde2e lane", name)
	}
	if _, err := os.Stat(value); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return value
}

func loadAllForE2E(t *testing.T) (Spec, Catalog, Receipt, ArtifactIdentity, ArtifactIdentity, ArtifactIdentity) {
	t.Helper()
	spec, receipt, catalog, specID, catalogID, receiptID := loadAll(t)
	return spec, catalog, receipt, specID, catalogID, receiptID
}
