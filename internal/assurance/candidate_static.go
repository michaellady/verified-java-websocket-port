package assurance

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	candidateManifestPath = "assurance/candidate-manifest.json"
	candidateClaimsPath   = "assurance/candidate-claims.json"
	candidateAttemptsPath = "evidence/us023/attempts.json"
	formalCatalogPath     = "assurance/formal/obligation-catalog.json"
	parityReplayPath      = "evidence/parity-replay.json"
	formalProjectionPath  = "evidence/formal-coverage.json"
	formalReportPath      = "reports/formal-coverage.md"
	parityReportPath      = "docs/us023-parity-coverage.md"
	rootNodeID            = "root.us023-candidate"
)

var candidateSchemaPaths = []string{
	"schemas/us023-attempts-1.0.0.schema.json",
	"schemas/us023-candidate-manifest-1.0.0.schema.json",
	"schemas/us023-claims-1.0.0.schema.json",
	"schemas/us023-formal-obligations-1.0.0.schema.json",
	"schemas/us023-parity-replay-1.0.0.schema.json",
	"schemas/us023-review-receipt-1.0.0.schema.json",
}

var reviewPaths = []string{
	"assurance/reviews/codex.json",
	"assurance/reviews/human.json",
	"assurance/reviews/qa.json",
	"assurance/reviews/reality.json",
}

var evidenceFamilies = []string{
	"RFC", "AUTOBAHN", "HANDSHAKE", "DIFFERENTIAL", "PROPERTY", "FUZZ",
	"RUNTIME", "FORMAL", "CONCURRENCY", "MUTATION", "HIDDEN", "SEALED",
}

var candidateNonclaims = []string{
	"NO_CUTOVER",
	"NO_CUTOVER_READY",
	"NO_CURRENT_RUST_CONTROL_HIDDEN_EXECUTION",
	"NO_CURRENT_RUST_CONTROL_SEALED_EXECUTION",
	"NO_INDEPENDENT_REVIEW",
	"NO_LIVE_AUTOBAHN_RERUN",
	"NO_PERFORMANCE_RESULT",
	"NO_PRODUCTION",
	"NO_PROTECTED_CASE_ACCESS",
	"NO_PUBLICATION",
	"NO_SIGNING",
	"NO_UNAVAILABLE_TOOL_PASS",
}

type gateContract struct {
	ID        string
	Criterion string
	Subject   string
}

var gateContracts = []gateContract{
	{ID: "gate.ac1.darwin-arm64", Criterion: "AC-1", Subject: "darwin/arm64"},
	{ID: "gate.ac1.linux-arm64", Criterion: "AC-1", Subject: "linux/arm64"},
	{ID: "gate.ac1.java-build", Criterion: "AC-1", Subject: "java"},
	{ID: "gate.ac1.java-62-tests", Criterion: "AC-1", Subject: "java"},
	{ID: "gate.ac1.rust-debug-build", Criterion: "AC-1", Subject: "rust"},
	{ID: "gate.ac1.rust-release-build", Criterion: "AC-1", Subject: "rust"},
	{ID: "gate.ac1.rust-tests", Criterion: "AC-1", Subject: "rust"},
	{ID: "gate.ac1.rust-fmt", Criterion: "AC-1", Subject: "rust"},
	{ID: "gate.ac1.rust-clippy", Criterion: "AC-1", Subject: "rust"},
	{ID: "gate.ac1.go-tests", Criterion: "AC-1", Subject: "assurance-tooling"},
	{ID: "gate.ac1.go-vet", Criterion: "AC-1", Subject: "assurance-tooling"},
	{ID: "gate.ac1.unsafe", Criterion: "AC-1", Subject: "rust"},
	{ID: "gate.ac1.dependencies", Criterion: "AC-1", Subject: "rust"},
	{ID: "gate.ac1.licenses", Criterion: "AC-1", Subject: "rust"},
	{ID: "gate.ac1.vulnerabilities", Criterion: "AC-1", Subject: "rust"},
	{ID: "gate.ac1.lockfile", Criterion: "AC-1", Subject: "rust/Cargo.lock"},
	{ID: "gate.ac1.no-stub", Criterion: "AC-1", Subject: "shipped-rust"},
	{ID: "gate.ac1.source-membership", Criterion: "AC-1", Subject: "target-tree"},
	{ID: "gate.ac1.test-membership", Criterion: "AC-1", Subject: "target-tree"},
	{ID: "gate.ac1.zero-silent-skip", Criterion: "AC-1", Subject: "test-denominator"},
	{ID: "gate.ac1.test-reconciliation", Criterion: "AC-1", Subject: "java-rust-test-manifests"},
	{ID: "gate.ac2.rfc", Criterion: "AC-2", Subject: "RFC"},
	{ID: "gate.ac2.autobahn", Criterion: "AC-2", Subject: "AUTOBAHN"},
	{ID: "gate.ac2.handshake", Criterion: "AC-2", Subject: "HANDSHAKE"},
	{ID: "gate.ac2.differential", Criterion: "AC-2", Subject: "DIFFERENTIAL"},
	{ID: "gate.ac2.property", Criterion: "AC-2", Subject: "PROPERTY"},
	{ID: "gate.ac2.fuzz", Criterion: "AC-2", Subject: "FUZZ"},
	{ID: "gate.ac2.runtime", Criterion: "AC-2", Subject: "RUNTIME"},
	{ID: "gate.ac2.formal", Criterion: "AC-2", Subject: "FORMAL"},
	{ID: "gate.ac2.concurrency", Criterion: "AC-2", Subject: "CONCURRENCY"},
	{ID: "gate.ac2.mutation", Criterion: "AC-2", Subject: "MUTATION"},
	{ID: "gate.ac2.hidden", Criterion: "AC-2", Subject: "HIDDEN"},
	{ID: "gate.ac2.sealed", Criterion: "AC-2", Subject: "SEALED"},
	{ID: "gate.ac3.denominator", Criterion: "AC-3", Subject: "formal-obligations"},
	{ID: "gate.ac3.java-bindings", Criterion: "AC-3", Subject: "java"},
	{ID: "gate.ac3.rust-bindings", Criterion: "AC-3", Subject: "rust"},
	{ID: "gate.ac3.refinement", Criterion: "AC-3", Subject: "production-refinement"},
	{ID: "gate.ac3.mutation-sensitivity", Criterion: "AC-3", Subject: "formal-mutations"},
	{ID: "gate.ac4.content-dag", Criterion: "AC-4", Subject: "candidate-dag"},
	{ID: "gate.ac4.git-bindings", Criterion: "AC-4", Subject: "git-objects"},
	{ID: "gate.ac4.deterministic-replay", Criterion: "AC-4", Subject: "candidate-replay"},
	{ID: "gate.ac5.codex-review", Criterion: "AC-5", Subject: "codex-review"},
	{ID: "gate.ac5.human-review", Criterion: "AC-5", Subject: "human-review"},
	{ID: "gate.ac5.independent-host", Criterion: "AC-5", Subject: "independent-host"},
}

var blockerCodes = map[string]bool{
	"GATE_NOT_EXECUTED":                       true,
	"BLOCKING_PLATFORM_NOT_EXECUTED":          true,
	"TOOL_UNAVAILABLE":                        true,
	"JAVA_SOURCE_OBJECT_UNAVAILABLE":          true,
	"AUTOBAHN_AUTHORITY_CONSUMED_NO_RERUN":    true,
	"CURRENT_RUST_AUTOBAHN_NOT_EXECUTED":      true,
	"CURRENT_RUST_PROTECTED_NOT_EXECUTED":     true,
	"PROTECTED_CONTROL_NOT_EXECUTED":          true,
	"INDEPENDENT_HOST_UNAVAILABLE":            true,
	"HUMAN_REVIEW_NOT_EXECUTED":               true,
	"SOLE_OWNER_NOT_INDEPENDENT":              true,
	"FORMAL_BACKEND_UNAVAILABLE":              true,
	"FORMAL_REFINEMENT_DISCONNECTED":          true,
	"FORMAL_BOUND_OR_ASSUMPTION_INCOMPATIBLE": true,
	"FORMAL_STRENGTH_OVERSTATED":              true,
	"UNRESOLVED_FINDING":                      true,
	"UNRESOLVED_DIVERGENCE":                   true,
	"MUTATION_SURVIVOR":                       true,
}

var candidateNodeKinds = map[string]bool{
	"SOURCE": true, "TEST": true, "LOCKFILE": true, "TOOL": true,
	"CORPUS_PUBLIC_PROJECTION": true, "CONFIG": true, "MIGRATION_MAP": true,
	"DOSSIER": true, "COMPATIBILITY_SURFACE": true, "DELTA_LEDGER": true,
	"CLAIMS": true, "ATTEMPTS": true, "EVIDENCE": true, "FORMAL_CATALOG": true,
	"SCHEMA": true, "HISTORICAL_DAG": true, "ROOT_INPUT": true,
}

func nodeKind(file string) string {
	switch {
	case file == candidateClaimsPath:
		return "CLAIMS"
	case file == candidateAttemptsPath:
		return "ATTEMPTS"
	case file == formalCatalogPath:
		return "FORMAL_CATALOG"
	case file == "assurance/evidence-dag.json":
		return "HISTORICAL_DAG"
	case file == "evidence/intake/semantic-id-migration-map.json":
		return "MIGRATION_MAP"
	case strings.Contains(file, "port-seam-dossier.json"):
		return "DOSSIER"
	case strings.Contains(file, "compatibility-surface.json"):
		return "COMPATIBILITY_SURFACE"
	case strings.Contains(file, "behavior-delta-ledger.json"):
		return "DELTA_LEDGER"
	case strings.HasPrefix(file, "schemas/"):
		return "SCHEMA"
	case strings.HasSuffix(file, ".rs") && strings.Contains(file, "/src/"):
		return "SOURCE"
	case strings.HasSuffix(file, ".rs") && strings.Contains(file, "/tests/"):
		return "TEST"
	case file == "rust/Cargo.lock":
		return "LOCKFILE"
	case strings.HasPrefix(file, "internal/assurance/candidate") || strings.HasPrefix(file, "cmd/assurectl/") || strings.HasPrefix(file, "cmd/candidategen/"):
		return "TOOL"
	case strings.HasPrefix(file, "corpora/"):
		return "CORPUS_PUBLIC_PROJECTION"
	case strings.HasSuffix(file, ".toml") || strings.HasSuffix(file, "Cargo.toml"):
		return "CONFIG"
	default:
		return "EVIDENCE"
	}
}

func nodeFamily(file string) string {
	switch {
	case strings.Contains(file, "autobahn") || strings.Contains(file, "us019"):
		return "AUTOBAHN"
	case strings.Contains(file, "handshake") || strings.Contains(file, "us010") || strings.Contains(file, "us011"):
		return "HANDSHAKE"
	case strings.Contains(file, "differential") || strings.Contains(file, "us020"):
		return "DIFFERENTIAL"
	case strings.Contains(file, "property"):
		return "PROPERTY"
	case strings.Contains(file, "fuzz"):
		return "FUZZ"
	case strings.Contains(file, "runtime"):
		return "RUNTIME"
	case strings.Contains(file, "formal"):
		return "FORMAL"
	case strings.Contains(file, "concurrency"):
		return "CONCURRENCY"
	case strings.Contains(file, "mutation"):
		return "MUTATION"
	case file == "corpora/hidden/manifest.json":
		return "HIDDEN"
	case file == "corpora/sealed/manifest.json":
		return "SEALED"
	case strings.Contains(file, "rfc") || strings.Contains(file, "corpora/frame"):
		return "RFC"
	default:
		return "STRUCTURAL"
	}
}

func expectedCandidatePaths(targetPaths, contentPaths []string) []string {
	seen := map[string]bool{}
	add := func(file string) { seen[file] = true }
	for _, file := range targetPaths {
		switch {
		case strings.HasPrefix(file, "rust/") && (strings.Contains(file, "/src/") || strings.Contains(file, "/tests/") || strings.Contains(file, "/fuzz-seeds/") || strings.HasSuffix(file, "Cargo.toml") || file == "rust/Cargo.lock" || file == "rust/rust-toolchain.toml" || file == "rust/dependency-inventory.toml" || file == "rust/dependency-policy.toml"):
			add(file)
		case strings.HasPrefix(file, "schemas/") && strings.HasSuffix(file, ".json"):
			add(file)
		case strings.HasPrefix(file, "corpora/") && (strings.HasPrefix(file, "corpora/public/") || strings.HasPrefix(file, "corpora/handshake/") || strings.HasPrefix(file, "corpora/frame/") || file == "corpora/hidden/manifest.json" || file == "corpora/sealed/manifest.json"):
			add(file)
		case strings.HasPrefix(file, "evidence/") && file != parityReplayPath && file != formalProjectionPath:
			add(file)
		case strings.HasPrefix(file, "assurance/formal/") && !strings.Contains(file, "/fixtures/"):
			add(file)
		case strings.HasPrefix(file, "assurance/concurrency/"):
			add(file)
		case file == "assurance/evidence-dag.json" || file == "assurance/evidence-model.json" || file == "assurance/lifecycle.json" || file == "assurance/developer-tools/port-seam-dossier.json" || file == "assurance/developer-tools/compatibility-surface.json" || file == "assurance/developer-tools/behavior-delta-ledger.json":
			add(file)
		}
	}
	for _, file := range contentPaths {
		if strings.HasPrefix(file, "internal/assurance/candidate") || strings.HasPrefix(file, "cmd/candidategen/") || strings.HasPrefix(file, "cmd/assurectl/") || contains(candidateSchemaPaths, file) || file == candidateClaimsPath || file == candidateAttemptsPath || file == formalCatalogPath {
			add(file)
		}
	}
	paths := make([]string, 0, len(seen))
	for file := range seen {
		paths = append(paths, file)
	}
	sort.Strings(paths)
	return paths
}

func pathNodeID(file string) string {
	replacer := strings.NewReplacer("/", ".", "_", "-", " ", "-")
	return "file." + replacer.Replace(file)
}

func sortedUnique(values []string) bool {
	for index, value := range values {
		if value == "" || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

func candidateRootAbsolute(root string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", fmt.Errorf("repository root must be a clean absolute path")
	}
	return root, nil
}
