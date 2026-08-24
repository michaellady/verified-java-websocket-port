# US-001 immutable input intake

## Outcome

The candidate intake catalog is complete for inputs that exist before the external Linux host is bound. All source, standard, suite, macOS toolchain, developer-tool, frozen-contract, and exact Autobahn image bytes were acquired by pinned locator and verified against the retained digest. Downloaded executables and the container were not executed.

Promotion remains blocked. This is intentional and is the only supportable result with the current evidence:

- The exact required Autobahn linux/amd64 image has 740 unique vulnerability rules: 12 critical, 147 high, 181 medium, 321 low, and 79 unspecified.
- OSV returned no matches for the ten retained queries, but generic-package ecosystem coverage is incomplete and is not treated as proof of absence.
- The `existing-identities-only` policy requires real cryptographic actions, authoritative role and revocation projections, unused protected-ledger nonces, and two independent approvals. None have been supplied.
- Child US-001 authorizes no publication, release tag, protected access, port implementation, benchmark sampling, or container execution.

The external x86_64 Linux Java/Rust toolchain is explicitly not represented as promoted. It does not become an input until child US-008 binds the independent Linux host.

## Retained evidence

The public projection is under `evidence/intake/`:

- `source-pins.json` closes the 23-artifact immutable catalog, URLs, digests, byte sizes, licenses, provenance, replay, lifecycle, and authorized repository binding.
- `toolchain-pins.json` records seven executable inputs with embedded binary hashes, dependency lock graphs, SBOM/vulnerability links, licenses, provenance, replay, expiration, rotation, and revocation state.
- `sbom.json` links each executable to a CycloneDX-derived component. The exact Autobahn image produced 460 components in the retained Docker SBOM scan.
- `vulnerability-snapshot.json` retains the OSV response and exact-image Docker Scout summary.
- `promotion-receipts.json` is explicitly a blocker/request receipt with zero accepted objects, zero publication actions, zero protected reads, and zero candidate-authored signatures.

The complete compressed CycloneDX and SARIF outputs are retained in the company-scoped HQ evidence store. The public projection records their raw and compressed SHA-256 digests, sizes, scanner identities, and replay commands without exposing protected authorization data.

## Trust boundary

`intakectl verify` strictly parses and closes the public graph, but cannot authorize promotion. `VerifyAuthorizedEvidenceDir` is the only code path that can clear the protected-caller gate. It requires authority data supplied out of band and enforces:

- Ed25519 verification over the complete object, stage, action, actor, role, tenant, artifact root, policy, sandbox, publication intent, time, nonce, role snapshot, and revocation snapshot;
- three distinct existing actors for steward, implementer, and attestor roles;
- qualification sandbox access only for the port implementer and only to `quarantined-source`;
- independent promotion only by the release attestor;
- atomic nonce consumption before promotion;
- no publication intent for US-001;
- atomic content-addressed batch promotion with idempotent replay.

The public evidence never supplies its own authoritative identity, role, revocation, or nonce-ledger truth.

## Adversarial coverage

Tests deny duplicate/unknown/null/trailing JSON; scope drift; owner/URL drift; mutable locators; digest drift; missing classification; role conflicts; revoked identities; invalid or mutated signatures; replayed nonces under concurrency; expiration errors; unauthorized sandbox/publication intent; floating/wrong-platform OCI descriptors; traversal; absolute paths; unsafe links and special files; undeclared executables; nested archives; ZIP expansion bombs; case/normalization collisions; duplicate paths; graph gaps; corrupt accepted objects; and partial batch failure.

## Required external resolution

An existing method/schema steward and port implementer must independently review and sign the candidate stages. A distinct existing release attestor must review the full vulnerability snapshot, record an explicit scoped disposition, and sign independent promotion. Two independent approvals and protected authoritative projections must be present. Until then, the expected command result is `BLOCKED`, and the child PRD story remains `passes:false`.
