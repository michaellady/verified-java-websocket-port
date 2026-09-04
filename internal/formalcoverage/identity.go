// Package formalcoverage reconciles the two formal denominators this
// repository carries — the immutable 24-obligation catalog and the 10-target
// US-006 proof-target plan — and derives the US-023 AC3 formal-coverage
// reports over the reconciled result.
//
// Nothing here proves anything, about Java or about Rust. It reads artifacts
// that already exist, joins them on keys both of them actually carry, and
// reports what the join exposes. Where the two documents disagree the
// disagreement is published; it is never normalised away, and it is never
// rounded into a coverage number.
//
// See docs/us023-formal-coverage.md for the claim ceiling.
package formalcoverage

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Repository-relative locations of every artifact this package reads or writes.
// They are constants so the command and its tests cannot drift apart.
const (
	CatalogPath        = "assurance/formal/obligation-catalog.json"
	ProofTargetsPath   = "assurance/formal/proof-targets.json"
	BindingSpecPath    = "assurance/formal/java-binding-spec.json"
	ProjectionPath     = "evidence/java/formal-bindings/coverage-projection.json"
	LinkagePath        = "evidence/linkage/rust-identity-verification.json"
	ReceiptPath        = "evidence/java/formal-bindings/receipt.json"
	ReconciliationPath = "assurance/formal/denominator-reconciliation.json"
	CorrectionPath     = "assurance/formal/catalog-correction-proposal.json"
	ReportJSONPath     = "evidence/formal/us023-coverage-report.json"
	ReportMarkdownPath = "evidence/formal/us023-coverage-report.md"
)

// CatalogDenominator is the size of the immutable semantic-obligation catalog.
// It is a constant because the catalog is immutable; a catalog of a different
// size is a different denominator and must fail loudly rather than rescale a
// percentage.
const CatalogDenominator = 24

// ProofTargetDenominator is the size of the US-006 proof-target plan.
const ProofTargetDenominator = 10

// CatalogSHA256 and CatalogGitBlob are the vendored Codex catalog's identity.
// They are asserted, never recomputed into, so a silent revendoring fails.
const (
	CatalogSHA256  = "sha256:21112518f48443b4e20ecae537bed72b8c9e19167ad00bc6f325bff9374cdf59"
	CatalogGitBlob = "be929320dc8f6e52a357a6124bc17fa1db197d2b"
)

// Digest returns the project-canonical "sha256:<hex>" spelling.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// GitBlobID computes the Git object name of a blob with the given contents, so
// a vendored artifact can be checked against the object id it has in the branch
// it was read from. sha1 is the object format this repository's Git uses; it is
// an identity lookup, not a security control.
func GitBlobID(data []byte) string {
	hasher := sha1.New() //nolint:gosec // Git object identity, not a security digest
	fmt.Fprintf(hasher, "blob %d\x00", len(data))
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}

// ArtifactIdentity names one input by path and content. Both the sha256 and the
// git blob id are carried: the first is what the rest of the programme quotes,
// the second is what makes a vendored file comparable to the branch it came
// from.
type ArtifactIdentity struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	GitBlob string `json:"git_blob"`
}

// LoadArtifact reads one repository artifact and returns its bytes and identity.
func LoadArtifact(root, relative string) ([]byte, ArtifactIdentity, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return nil, ArtifactIdentity{}, err
	}
	return data, ArtifactIdentity{Path: relative, SHA256: Digest(data), GitBlob: GitBlobID(data)}, nil
}

// MarshalArtifact renders a derived artifact deterministically: two-space
// indentation and a trailing newline, matching the repository's other JSON
// evidence.
func MarshalArtifact(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// Assurance is the fixed honesty block every artifact this package writes
// carries. It is not configurable.
type Assurance struct {
	Assurance              string `json:"assurance"`
	IndependentReviewClaim bool   `json:"independent_review_claimed"`
	Production             bool   `json:"production"`
	Publication            bool   `json:"publication"`
	Signing                bool   `json:"signing"`
}

// DefaultAssurance is owner-attested, not independent, not production.
func DefaultAssurance() Assurance {
	return Assurance{Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT"}
}
