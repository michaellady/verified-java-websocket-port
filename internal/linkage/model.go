// Package linkage closes the AC5-class symbol-linkage gap (US-010..US-016
// dossier gap G7) with two additive, deterministic evidence artifacts:
//
//   - evidence/linkage/rust-identity-verification.json — a per-row resolver
//     verification of the US-003 migration map's planned Rust identities
//     against the real merged Rust tree (file, declaration, line, blob
//     digest at verification time), including the truthful landed mapping
//     wherever the implementation landed an identity differently than the
//     plan (renamed, relocated, absorbed), with a rationale per row.
//   - evidence/linkage/evidence-dag.json — a linkage evidence DAG with
//     story, migration-row, symbol, proof-target, and evidence nodes that
//     binds the US-006 proof targets and the US-009..US-018 stories to the
//     exact implemented Rust symbols and their verifying evidence files.
//
// Both artifacts are pure functions of the repository tree: the tests
// re-derive them and compare byte-for-byte, so any drift (a moved symbol, a
// changed evidence file) turns the linkage evidence stale loudly. Regenerate
// deliberately with LINKAGE_REGENERATE=1 (see linkage_test.go).
//
// The frozen US-003 migration map itself is NOT mutated: its 1.0.0 schema
// pins rust_identity_verified to const false, portplan's
// TestDeriveReproducesCommittedEvidence pins its bytes to the Java-only
// derivation, and assurance/formal/proof-targets.json digest-pins it. This
// overlay records the resolver verification that the map's own blocker
// statement requires, without tampering with those freezes. Likewise the
// US-004 owner-only lifecycle DAG at assurance/evidence-dag.json is a frozen
// exact closure (internal/assurance blocks any node drift) and is untouched.
package linkage

// VerificationDocument is the persisted shape of
// evidence/linkage/rust-identity-verification.json.
type VerificationDocument struct {
	Schema              string             `json:"$schema"`
	SchemaVersion       string             `json:"schema_version"`
	EntityType          string             `json:"entity_type"`
	DocumentID          string             `json:"document_id"`
	MapRef              MapRef             `json:"map_ref"`
	FrozenMapDisclosure string             `json:"frozen_map_disclosure"`
	Resolver            ResolverStatement  `json:"resolver"`
	Rows                []VerificationRow  `json:"rows"`
	Summary             VerificationTotals `json:"summary"`
	Assurance           Assurance          `json:"assurance"`
}

// MapRef pins the migration map this verification covers.
type MapRef struct {
	Path       string `json:"path"`
	MapID      string `json:"map_id"`
	MapVersion string `json:"map_version"`
	SHA256     string `json:"sha256"`
}

// ResolverStatement discloses exactly how identities were verified.
type ResolverStatement struct {
	Method    string `json:"method"`
	Strength  string `json:"strength"`
	Statement string `json:"statement"`
}

// VerificationRow is the resolver verdict for one migration-map row.
type VerificationRow struct {
	RowID                 string           `json:"row_id"`
	JavaSemanticID        string           `json:"java_semantic_id"`
	PlannedRustSemanticID string           `json:"planned_rust_semantic_id"`
	Disposition           string           `json:"disposition"`
	RustIdentityVerified  bool             `json:"rust_identity_verified"`
	LandedSymbols         []ResolvedSymbol `json:"landed_symbols"`
	Rationale             string           `json:"rationale"`
}

// ResolvedSymbol is one landed Rust symbol verified against the tree.
type ResolvedSymbol struct {
	RustPath    string `json:"rust_path"`
	DeclKind    string `json:"decl_kind"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Declaration string `json:"declaration"`
	SHA256      string `json:"sha256"`
}

// VerificationTotals summarizes the row dispositions.
type VerificationTotals struct {
	RowsTotal         int `json:"rows_total"`
	Verified          int `json:"verified"`
	ExcludedConfirmed int `json:"excluded_confirmed"`
	Exact             int `json:"exact"`
	Relocated         int `json:"relocated"`
	Renamed           int `json:"renamed"`
	Absorbed          int `json:"absorbed"`
}

// Assurance mirrors the repository-wide single-owner posture stanza.
type Assurance struct {
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	Production               bool   `json:"production"`
	Publication              bool   `json:"publication"`
	Signing                  bool   `json:"signing"`
}

// DAGDocument is the persisted shape of evidence/linkage/evidence-dag.json.
type DAGDocument struct {
	Schema        string    `json:"$schema"`
	SchemaVersion string    `json:"schema_version"`
	EntityType    string    `json:"entity_type"`
	DAGID         string    `json:"dag_id"`
	Scope         string    `json:"scope_statement"`
	Nonclaim      string    `json:"nonclaim"`
	Nodes         []DAGNode `json:"nodes"`
	Edges         []DAGEdge `json:"edges"`
	Assurance     Assurance `json:"assurance"`
}

// DAGNode is one node of the linkage DAG. Optional attributes are populated
// per kind: symbol nodes carry the resolved identity, evidence nodes carry
// the digest-pinned file, row nodes carry the Java identity, story and
// proof-target nodes carry titles.
type DAGNode struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Title       string `json:"title,omitempty"`
	RustPath    string `json:"rust_path,omitempty"`
	DeclKind    string `json:"decl_kind,omitempty"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	JavaID      string `json:"java_semantic_id,omitempty"`
	Disposition string `json:"disposition,omitempty"`
	Lineage     string `json:"lineage,omitempty"`
	Path        string `json:"path,omitempty"`
}

// DAGEdge is one directed edge of the linkage DAG.
type DAGEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}
