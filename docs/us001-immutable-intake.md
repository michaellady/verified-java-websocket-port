# US-001 immutable input intake

## Outcome

The candidate intake catalog is complete for inputs that exist before the external Linux host is bound. All source, standard, suite, macOS toolchain, developer-tool, frozen-contract, and exact Autobahn image bytes were acquired by pinned locator and verified against the retained digest. Downloaded executables and the container were not executed.

The exact 23-object set was promoted under the repository owner's protected single-owner authority:

- The exact required Autobahn linux/amd64 image has 740 unique vulnerability rules: 12 critical, 147 high, 181 medium, 321 low, and 79 unspecified.
- OSV returned no matches for the ten retained queries, but generic-package ecosystem coverage is incomplete and is not treated as proof of absence.
- The frozen `foundation-1.0.0` policy is amended for this child by the exact `java-websocket-single-owner-1.0.0` contract. The amendment permits the one repository owner to act under each required stage role. It does not claim independent review.
- The owner supplied four real signatures plus authoritative role and revocation projections outside the repository. The protected transaction validated them and consumed the four nonces in one durable atomic batch.
- Child US-001 authorizes no publication, release tag, protected access, port implementation, benchmark sampling, or container execution.

The committed receipt records `SINGLE_OWNER_PROMOTED_NO_INDEPENDENT_REVIEW`, assurance ceiling `OWNER_ATTESTED_NOT_INDEPENDENT`, promotion-store root `sha256:5713245496362ece061c769bc4ee8eb909bfcc6d7d319bc3fc9b750f6e0a4ad8`, 23 accepted objects, zero publication actions, and zero protected-access actions. The final public evidence root is `sha256:d0fcc851c23233c645895a2fe862128ff576676da10d00c409165707ab0b482a`. Production use and publication remain unauthorized.

The external x86_64 Linux Java/Rust toolchain is explicitly not represented as promoted. It does not become an input until child US-008 binds the independent Linux host.

## Retained evidence

The public projection is under `evidence/intake/`:

- `source-pins.json` closes the 23-artifact immutable catalog, URLs, digests, byte sizes, licenses, provenance, replay, lifecycle, and authorized repository binding.
- `toolchain-pins.json` records seven executable inputs with embedded binary hashes, dependency lock graphs, SBOM/vulnerability links, licenses, provenance, replay, expiration, rotation, and revocation state.
- `sbom.json` links each executable to a CycloneDX-derived component. The exact Autobahn image produced 460 components in the retained Docker SBOM scan.
- `vulnerability-snapshot.json` retains the OSV response and exact-image Docker Scout summary.
- `promotion-receipts.json` is the completed single-owner promotion receipt. It retains the four owner-signed actions and records 23 accepted objects, zero publication actions, and zero protected-access actions without embedding private key material or authoritative snapshots.
- `contracts/toolchain-promotion-single-owner-amendment.json` is an exact copy of the governing parent amendment, digest `sha256:ee247975a3a2cf10e8d93221df85505b8ed882630a5658662e9d716afe617cec`. It supersedes only role incompatibility, approval count, and the promotion-stage name; the frozen base policy is unchanged.

The complete compressed CycloneDX and SARIF outputs are retained in the company-scoped HQ evidence store. The public projection records their raw and compressed SHA-256 digests, sizes, scanner identities, and replay commands without exposing protected authorization data.

## Trust boundary

`intakectl verify` strictly parses and closes the public graph, but cannot authorize promotion. `VerifyAuthorizedEvidenceDir` is the only code path that can clear the protected-caller gate. It requires authority data supplied out of band and enforces:

- Ed25519 verification over the complete object, stage, action, actor, role, tenant, artifact root, base-policy digest, amendment digest, sandbox, publication intent, risk disposition, time, nonce, role snapshot, and revocation snapshot;
- the exact owner `github:michaellady`, permitted by protected authority to act under the steward, implementer, and attestor action roles;
- qualification sandbox access only for the port implementer and only to `quarantined-source`;
- owner promotion only under the release-attestor action role;
- a signed disposition binding the exact vulnerability snapshot, Autobahn image digest, 12 critical and 147 high counts, and `QUARANTINED_LABORATORY_QUALIFICATION_ONLY` scope, with production use and publication both false;
- atomic all-or-nothing nonce-batch consumption as one fsynced, content-addressed manifest after every action and every materialized byte has passed validation;
- no publication intent for US-001;
- atomic content-addressed batch promotion with idempotent replay.

The public evidence never supplies its own authoritative identity, role, revocation, or nonce-ledger truth.

## Adversarial coverage

Tests deny duplicate/unknown/null/trailing JSON; scope drift; owner/URL drift; mutable locators; digest drift; missing classification; role conflicts; revoked identities; invalid or mutated signatures; replayed nonces under concurrency; expiration errors; unauthorized sandbox/publication intent; floating/wrong-platform OCI descriptors; traversal; absolute paths; unsafe links and special files; undeclared executables; nested archives; ZIP expansion bombs; case/normalization collisions; duplicate paths; graph gaps; corrupt accepted objects; and partial batch failure.

## Protected owner signing and promotion path

The protected operator constructs a request matching `schemas/owner-action-request-1.0.0.schema.json`. Its artifact digest is the candidate payload root, its vulnerability digest is the exact retained `vulnerability-snapshot.json` digest, its role/revocation digests come from protected authoritative snapshots, and it contains four fresh nonces plus a risk rationale. The Ed25519 private key must remain outside the repository. It may be read from an owner-only regular file:

```sh
go run ./cmd/intakectl sign-owner-actions \
  --request /protected/path/owner-action-request.json \
  --private-key-file /protected/path/owner-ed25519.hex
```

For native HQ vault injection, pass only the environment-variable name. `hq secrets exec` supplies the value directly to the child; `intakectl` unsets it immediately after reading it and never logs it:

```sh
hq secrets --company open-source-projects exec --only OWNER_ED25519_PRIVATE_KEY -- \
  go run ./cmd/intakectl sign-owner-actions \
    --request /protected/path/owner-action-request.json \
    --private-key-env OWNER_ED25519_PRIVATE_KEY
```

The signing command emits only the four signed public action records. It does not generate a key, assign identity, or supply authoritative snapshot truth. The file and environment options are mutually exclusive.

The external authority projection must match `schemas/owner-authority-1.0.0.schema.json`, remain owner-only and outside all candidate/materialization/promotion paths, and bind the exact owner public key plus authoritative role and revocation snapshot digests. The materialization manifest must match `schemas/input-materialization-1.0.0.schema.json`; its 23 entries may appear in any array order and are resolved by unique artifact id. Duplicate, missing, and unknown ids are denied. Ordinary artifacts must exactly match the frozen `source-pins.json` identities, digests, and byte sizes. The Autobahn entry instead materializes the retained linux/amd64 OCI **manifest blob** with digest `sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074` and its own bounded blob size, not the OCI archive tar byte size.

After separately materializing those bytes without executing them, the protected operator invokes the complete transaction:

```sh
go run ./cmd/intakectl promote-owner-inputs \
  --evidence-dir /absolute/repository/evidence/intake \
  --authority-file /protected/path/owner-authority.json \
  --signed-actions-file /protected/path/signed-owner-actions.json \
  --materialization-manifest /protected/path/input-materialization.json \
  --materialization-root /protected/materialized-inputs \
  --nonce-ledger /protected/durable-nonce-ledger \
  --promotion-store /protected/content-addressed-inputs
```

This command validates every declared byte and frozen pin before consuming the four nonces, calls `VerifyAuthorizedEvidenceDir`, transactionally promotes the 23 objects, rechecks immutable snapshots of all five evidence files, and atomically replaces `promotion-receipts.json` only after promotion succeeds without evidence drift. If evidence drifts after authorization or store promotion, the receipt remains unchanged while the already-durable nonce batch and content-addressed store root remain; recovery must inspect that idempotent store state and use freshly signed nonces. A final public verification remains fail-closed with `OWNER_RISK_DISPOSITION_REQUIRED` and `PROTECTED_CALLER_REQUIRED`; protected authority is never inferred from candidate-authored evidence.

The live protected transaction completed and independently rehashed all 23 accepted objects against the content-addressed manifest. One nonce batch was durably consumed. The public command intentionally remains `BLOCKED` with only `OWNER_RISK_DISPOSITION_REQUIRED` and `PROTECTED_CALLER_REQUIRED`: protected authority is not projected back into candidate-authored evidence, and the successful protected receipt does not authorize production use or publication.
