# US-007 sandbox and release-firewall isolation design

Status: candidate transport implemented; historical Docker sbx feasibility
validation retained; acceptance blocked on a universally imposed external
resource envelope. This remains a quarantined laboratory result and does not
authorize production use, signing, publication, or independent review.

Assurance: `OWNER_ATTESTED_NOT_INDEPENDENT`.
`independent_review_claimed` is `false`. Production access, signing,
publication, and any additional Autobahn run are not authorized.

## Retained live Docker sbx result

The protected parent executed the exact candidate snapshot
`f1860a4bd0420c8073aec8980cfcf3d118e1ea5a` through Docker sbx v0.39.0 in
`--clone` mode. The shell template was pinned to linux/arm64 manifest
`sha256:1e642f7fadebcbff3d8de67114e9b42a5971ba9b4287ebffa1d05662f5a0f5ec`;
the multi-platform index digest is retained separately as
`sha256:c183a8ba03cdb30011c73f555c773c5712b84c6ea066f18409253dcab2cfe799`.
Creation used 2 CPUs, 2 GiB outer memory, and an explicit sandbox-scoped
wildcard deny rule. The external operator bounded wall time and captured
output, while isolated canary commands exercised the retained CPU, memory,
process, file-descriptor, output, workspace, and wall limits. That validates
the canary profile; it does not prove the complete retained envelope is imposed
externally on every future hostile workload. Until that is implemented and
observed, US-007 remains `SANDBOX_ENFORCEMENT_UNAVAILABLE/BLOCK`.

Docker clone mode necessarily exposes one localhost-only ephemeral Git-daemon
bridge and one internal `mcpgateway` control token. The protected inspect
receipt inventories those separately from workload capabilities: zero host
environment variables, user/service secrets, registered MCP servers, shared
skills, user-published ports, protected mounts, and host Docker sockets were
accepted. Any additional control-plane member is a mismatch. The scoped
wildcard deny overrides Docker's shell-kit provider allowance, and both the
policy check and in-VM network canary proved effective denial.

The owner key remained in HQ secret injection outside the candidate repository
and microVM. The external operator self-hashed, obtained an owner-signed exact
executable-closure promotion, atomically consumed distinct nonces in a durable
protected ledger, signed the exact sbx request, ran the closed non-Autobahn
canary suite, recursively classified the public projection, removed the exact
sandbox, and proved post-removal absence. The complete protected record remains
outside this repository. Its classifier-approved public projection is retained
at `evidence/sbx-validation.json` with digest
`sha256:930b9073555f24d4013773f3f81e7bc354442ded9795812e2888907c4853b6b7`.
Autobahn reruns performed by US-007 remain zero.

## Decision

Add one project-owned security gate around the already accepted intake, lab,
and assurance modules. The gate has three ordered phases:

1. take one root-confined, immutable snapshot and transactionally promote it
   from candidate input to a quarantined content-addressed root without
   executing candidate bytes;
2. bind every possible executable to an independently created promotion record
   and allow an enumerated operation to run only inside a disposable capability
   envelope; and
3. after the sandbox is gone, pull a bounded artifact set into a private
   staging root, recursively classify the exact public projection, and produce
   a content-addressed projection that has no publication capability.

The gate is a producer of evidence for the existing `internal/assurance`
lifecycle. It is not a second evidence DAG, retry system, role model, or
publication system. An owner may attest the mechanics and promote quarantined
inputs, but cannot create independent review or raise the assurance ceiling.

The original and sole owner-authorized remediation receipts in
`evidence/java/autobahn-baseline.json` are immutable inputs. The remediation
allowance is exhausted. US-007 must verify their digests and the
`NO_FURTHER_RERUNS_AUTHORIZED` disposition statically; no test, fixture,
operator command, or recovery path may invoke `RunAutobahnQualification`,
Docker, the Autobahn image, its Python stack, or a container entrypoint.

## Inherited contracts and narrow adapters

US-007 reuses these completed seams without modifying them:

| Existing seam | Allowed US-007 use | Explicitly not allowed |
|---|---|---|
| `internal/intake` | `DecodeStrict`, `CanonicalJSON`, `DigestBytes`, `InspectTar`, `InspectZip`, and `PromoteDirectory`; verify the retained public intake before binding a promotion | copying its archive, signature, nonce, or promotion logic; treating public evidence as protected authority |
| `internal/lab` | `LoadAcceptedRoot`, `AcceptedRoot.Object`/`Objects`, `DecodeSandboxPlan`, `BuildExecutionSpec`, and `DecodeSandboxReceipt` through concrete adapter functions | editing its operation registry; rerunning US-002; treating a legacy receipt as sufficient for the stronger US-007 envelope |
| `internal/assurance` | call `Verify` and `Replay` against the same one-read project snapshot; retain the normalized verdict and roots | a parallel lifecycle, schema, DAG, reviewer identity, retry policy, or more permissive interpretation of its findings |

The security gate may import these packages directly because it is in the same
Go module. Adapters remain concrete functions. No speculative Go `interface`
is introduced. An inherited error is preserved with its inherited code when
one exists; the security gate must not silently rename it to a more permissive
finding.

US-001's accepted input root
`sha256:5713245496362ece061c769bc4ee8eb909bfcc6d7d319bc3fc9b750f6e0a4ad8`
and public evidence root
`sha256:d0fcc851c23233c645895a2fe862128ff576676da10d00c409165707ab0b482a`
are upstream bindings, not publication authority. The US-004 canonical result
may honestly remain `BLOCKED` on its two inherited independent-attestation
findings while US-007 mechanics pass.

## Threat model

### Assets

- protected and sealed cases, expected outputs, raw diagnostics, and canonical
  evidence;
- owner credentials, signing keys, nonce ledgers, authority snapshots, release
  tokens, production credentials, and machine identity;
- company isolation, especially the boundary around `open-source-projects`;
- immutable source, toolchain, dependency, policy, review, and receipt bytes;
- the exact public projection and its provenance chain;
- host availability: CPU, memory, processes, file descriptors, disk, inodes,
  output, wall time, mounts, and network state.

### Adversaries and assumptions

All candidate source, build metadata, archives, dependencies, Maven plugins,
annotation processors, Rust build scripts, proc macros, developer-tool imports,
Autobahn Python/container bytes, container metadata, test output, and diagnostics
are adversarial. A candidate may race path inspection, exploit normalization,
request ambient environment, fork indefinitely, fill storage, emit credentials,
or try to smuggle protected data into a public descendant.

Project-owned Go control code and the pinned OS sandbox supervisor are part of
the trusted computing base only after their exact executable digests have their
own promotion records. A successful process exit, candidate-authored receipt,
container label, file extension, Git tracking state, or owner assertion alone
is never evidence that isolation held.

The following are never in the sandbox namespace or environment: a home
directory from the invoking user, credential/keychain sockets, SSH/GPG agents,
Docker or container-runtime sockets, cloud metadata, signing services,
production endpoints, protected/canonical evidence roots, public release
staging, or another company's root.

### Trust boundaries

```text
untrusted candidate bytes
        |
        v  static, root-confined, no execution
private quarantine staging --atomic rename--> accepted quarantine CAS
                                                |
                                  promotion-bound operation plan
                                                v
                                     disposable sandbox
                           (no secrets, protected data, or public output)
                                                |
                                  bounded classified artifact pull
                                                v
                                  private release-firewall staging
                         recursive classification + protected checker
                                                |
                                  safe projection CAS (not published)
                                                |
                                  existing assurance lifecycle
                                                |
                              separate owner publication authorization
```

No edge points from the sandbox to protected stores, signing authority, the
public projection, production, or another company. Publication is a later,
separately authorized consumer of an accepted projection digest; neither
`internal/securitygate` nor `cmd/securityctl` has a publish or sign operation.

## Primitive Test

| Capability | Atomicity | Bitter Lesson | ZFC | Placement |
|---|---|---|---|---|
| root-confined one-read snapshots, bounded streaming, digesting, and metadata comparison | substitution or concurrent mutation can corrupt the accepted snapshot | still required with a stronger model | filesystem transport | Go in `internal/securitygate`, using `os.OpenRoot` and inherited digest/canonical primitives |
| archive metadata inspection | deterministic over retained bytes | still required | parsing and bounds enforcement | inherited `internal/intake` through a narrow adapter |
| all-or-none content-addressed quarantine and projection promotion | partial visibility and concurrent writers require an atomic commit | still required | filesystem transport | inherited `intake.PromoteDirectory` plus a project manifest |
| start/kill/wait an enumerated sandbox operation and collect bounded metrics | process groups and cleanup require atomic ownership | still required | process transport | Go supervisor path; never shell and never arbitrary argv |
| select a fixed platform canary | a closed enum prevents command smuggling | still required | deterministic transport | Go; canary meaning and expected result are policy data |
| decide which executable classes, capabilities, classifications, detectors, resource ceilings, or dispositions are acceptable | not an atomic transport problem | better models and reviewers can improve it | security judgment | reviewed JSON policies |
| decide whether a discrepancy is tolerable or evidence is sufficient for release | not atomic | explicitly benefits from human judgment | cognition | owner/reviewer layer and existing assurance lifecycle |
| scan the exact staged byte projection against declarative detectors | deterministic over one snapshot | still required | data validation | Go engine; detector definitions and allow/deny decisions in JSON |

The narrow Go module is warranted for atomic filesystem/process transport and
deterministic validation. It must not contain hidden allowlists, severity
judgment, retry decisions, or publication policy. No new shell script is
needed.

## Target layout

Implementation is limited to this slice, plus wiring the resulting evidence
node into the existing US-004 lifecycle:

```text
security/
  sandbox-policy.json
  ingestion-policy.json
  release-firewall.json
  fixtures/
    cases.json
    ingestion/                    # inert JSON manifests and in-memory archive recipes
    inventory/                    # inert Maven/Cargo/LSP/container metadata
    sandbox/                      # plans and synthetic/controlled-canary observations
    release/                      # virtual projection trees and public canaries
schemas/
  security-sandbox-policy-1.0.0.schema.json
  security-ingestion-policy-1.0.0.schema.json
  security-release-firewall-1.0.0.schema.json
  security-fixture-catalog-1.0.0.schema.json
  security-validation-1.0.0.schema.json
evidence/
  security-validation.json
  sbx-validation.json                 # externally classified live sbx projection
cmd/securityctl/
  main.go
  main_test.go
internal/securitygate/
  gate.go
  snapshot.go
  ingest.go
  inventory.go
  sandbox.go
  projection.go
  *_test.go
```

`security/fixtures/cases.json` is the single closed fixture catalog. The other
fixture files contain inputs, never expected judgments. Expected code and
disposition live in the catalog. `evidence/security-validation.json` is a
retained result, not a source of policy truth.

The implementation must update the existing `assurance/evidence-model.json`,
`assurance/lifecycle.json`, `assurance/evidence-dag.json`, checkpoint, and
public contract only through the existing US-004 regeneration protocol. The
security evidence is one typed node. It does not introduce another root,
failure envelope, attempt sequence, or authorization graph.

## Deep-module interface and CLI

The package exposes a small concrete surface:

```go
type Request struct {
    RootPath       string
    Operation      string // VERIFY, INGEST, VERIFY_SANDBOX, PROJECT
    CandidateRoot string // accepted-root digest, never an arbitrary executable path
    FixtureID      string // tests only; must occur in the closed catalog
}

type Verdict struct {
    State                    string
    SecurityEvidenceRoot     string
    QuarantineRoot           string
    ProjectionRoot           string
    Findings                 []Finding
    Assurance                string
    IndependentReviewClaimed bool
    PublicationAuthorized    bool
}

func Verify(ctx context.Context, request Request) (Verdict, error)
func Ingest(ctx context.Context, request Request) (Verdict, error)
func VerifySandbox(ctx context.Context, request Request) (Verdict, error)
func RunControlledCanary(ctx context.Context, request CanaryRequest) (SandboxReceipt, error)
func Project(ctx context.Context, request Request) (Verdict, error)
```

All functions first load the same policy snapshot. `Verify` and
`VerifySandbox` are read-only.
`Ingest` and `Project` may write only to caller-supplied, policy-bound private
transaction roots after root disjointness checks; their sole durable output is
an accepted content-addressed root. `RunControlledCanary` validates only the
candidate-side request transport and then always returns
`PROTECTED_CALLER_REQUIRED/BLOCK`. The external protected operator owns launch,
authority verification, nonce consumption, and authoritative receipts. There
is no candidate-accessible launcher, general command, argv, shell, environment,
URL, container image, or plugin parameter.

`cmd/securityctl` accepts only:

```text
securityctl verify --root ROOT
securityctl ingest --root ROOT --accepted-root DIGEST --store STORE
securityctl verify-sandbox --root ROOT --plan RELATIVE --receipt RELATIVE
securityctl project --root ROOT --candidate-root DIGEST --store STORE
```

It emits canonical JSON and exits nonzero for any finding. A separately
protected operator may have a private fixed-canary dispatch, but candidate code
cannot supply that operator or turn a structurally valid receipt into launch
authority. `go run` is not an authoritative invocation: the executed
`securityctl` and sandbox supervisor digests must be in the executable inventory
and promotion closure.

## Root confinement and immutable snapshots

Every input root is a specific absolute path narrower than `/`, opened with
`os.OpenRoot`, and compared for overlap before any content read. Policy and
evidence members use slash-relative canonical paths. Absolute paths,
backslashes, NULs, empty/dot/parent components, doubled separators, device
names, and an entry outside the opened root are rejected.

Authoritative build input is an existing content-addressed accepted root loaded
with `lab.LoadAcceptedRoot`; a mutable working tree never becomes build input.
For candidate directory fixtures and initial staging, the reader applies all of
these rules:

1. walk without following links and reject a mount-device change;
2. require real directories and bounded single-link regular files;
3. reject symlinks, hard links (`nlink != 1`), sockets, FIFOs, devices, and
   unknown types before opening content;
4. open relative to the root, compare device/inode/mode/link count/size and
   modification/change timestamps across `lstat -> open/fstat -> read ->
   fstat/lstat`;
5. stream each source file exactly once into an exclusive private staging blob
   while computing SHA-256, byte quotas, static detectors, and archive type;
6. build a canonical manifest from those staged bytes and never re-read the
   source path; all later inspection reads only digest-addressed staging blobs;
7. reject any concurrent identity or metadata change and destroy the private
   staging transaction.

Policy/evidence JSON is similarly read exactly once into an in-memory
evaluation snapshot. The gate passes those retained bytes or a digest-bound
temporary snapshot to its adapters; it never asks intake, lab, and assurance to
re-read a candidate-controlled path at different times.

Path collision keys are computed per segment as Unicode NFC of full case fold.
Every segment must already be valid UTF-8 and NFC. Two distinct byte paths with
the same collision key, including case-only or composed/decomposed variants,
are rejected. The manifest retains both the original byte-safe path and the
collision key so replay is platform-independent.

## `security/ingestion-policy.json`

Schema version is exactly `1.0.0`; unknown or duplicate fields are rejected.
The document contains these closed sections:

- `scope`: company `open-source-projects`, project and laboratory
  `verified-java-websocket-port`, repository owner/URL, US-001 accepted-root
  and evidence-root digests, and `default_classification: QUARANTINED`;
- `source_modes`: authoritative mode `ACCEPTED_CONTENT_ADDRESSED_ROOT` and
  test-only mode `DISPOSABLE_FIXTURE_ROOT`; neither has an execute action;
- `paths`: slash-relative, UTF-8 NFC, NFC-casefold collision keys,
  `no_symlinks`, `single_link_only`, `same_device`, `no_special_files`, and
  maximum depth/component/path lengths;
- `quotas`: maximum files, directories, bytes per file, total bytes, archive
  entries, expanded bytes, nested depth, and expansion ratio, all positive and
  no larger than the inherited intake ceilings;
- `archives`: exact TAR/ZIP/JAR/VSIX media detection by magic, no extraction to
  host, declared nested archives only, and an executable declaration map passed
  to `intake.InspectTar`/`InspectZip`;
- `provenance`: required company/project/source artifact/digest/promotion root,
  complete parent chain, immutable locator, classification, and no absolute
  local path;
- `transaction`: private mode `0700`, exclusive staged blobs, fsync order,
  canonical manifest object, same-filesystem atomic rename, idempotent exact
  replay, read-back verification, and no partial accepted root;
- `finding_registry`: the exact ingestion/inventory codes and dispositions in
  the registry below.

The promoted object batch uses inherited `intake.PromoteDirectory`. It contains
one `candidate-manifest` object and one object named
`blob.<lowercase-sha256>` per unique file digest. The candidate manifest maps
each canonical path to blob object, size, media kind, executable classification,
source provenance, and collision key. Promotion succeeds only if
`lab.LoadAcceptedRoot` reopens the resulting root and reproduces the exact
manifest and blob set. A failed or killed transaction leaves no accepted
manifest and returns `PARTIAL_PROMOTION/QUARANTINE`.

## Hostile executable inventory and promotion binding

The candidate manifest has a closed `hostile_executables` array. Static
discovery is exhaustive over the retained snapshot and emits an inventory item
even when an executable will not be used. Every item contains:

```text
id, class, source_path_or_component, digest, byte_size, discovered_by,
declared_entrypoint, dependency_lock_root, sbom_ref, vulnerability_ref,
license_ref, provenance_ref, promotion_receipt_ref, promotion_scope,
expires_at, revoked, allowed_operation_ids
```

The exact classes are:

- `MAVEN_CORE`, `MAVEN_PLUGIN`, `MAVEN_EXTENSION`,
  `MAVEN_ANNOTATION_PROCESSOR`, and `JVM_DEPENDENCY`;
- `RUST_TOOLCHAIN`, `CARGO_BUILD_SCRIPT`, `RUST_PROC_MACRO`,
  `CARGO_RUNNER_OR_WRAPPER`, and `RUST_DEPENDENCY`;
- `JDT_LS_IMPORT`, `RUST_ANALYZER_IMPORT`, `GLANCER_IMPORT`, and
  `LANGUAGE_SERVER_PLUGIN`;
- `AUTOBAHN_PYTHON_RUNTIME`, `AUTOBAHN_PYTHON_DISTRIBUTION`,
  `AUTOBAHN_SCRIPT`, `CONTAINER_ENTRYPOINT`, `CONTAINER_COMMAND`,
  `CONTAINER_LAYER`, and `CONTAINER_RUNTIME_HELPER`;
- `ARCHIVE_DECODER`, `ARCHIVE_DECLARED_EXECUTABLE`, `SECURITYCTL`, and
  `SANDBOX_SUPERVISOR`.

Maven discovery covers build/plugin management, reporting, extensions,
compiler processor paths and processor flags, lifecycle/plugin prefixes,
profiles, parent/BOM resolution, and the complete resolved dependency closure.
Rust discovery covers every workspace member, `package.build`, conventional
`build.rs`, proc-macro crate, target-specific dependency, Cargo config runner,
rustc/rustdoc wrapper, linker, and complete `Cargo.lock` closure. Missing lock
closure is not interpreted as “no executable.” Language servers are hostile
importers: their binary, plugins, workspace/config inputs, imported build
servers, cache, and spawned tools require promotion and a separate disposable
profile. Their observations keep empty assurance claims and gate effects as
required by US-004.

Container discovery is static over the exact promoted linux/amd64 manifest,
config, and layer descriptors. Entrypoint and command strings are data only.
US-007 never starts them. Autobahn's Python runtime, installed distributions,
console scripts, suite scripts, runner, relay, endpoint, and image layers are
enumerated but have `allowed_operation_ids: []` because the rerun disposition
is closed.

An executable is promoted only when an external protected launcher verifies a
two-statement owner record: port-implementer qualification followed by
release-attestor executable promotion, with distinct nonces. The signed subject
binds the exact executable digest, roles `SECURITYCTL` and
`SANDBOX_SUPERVISOR`, operation `CONTROLLED_CANARY`, company/project/lab,
the exact sandbox-policy digest, current security-evidence root, retained
US-001 public-evidence and accepted roots, and scope
`QUARANTINED_LABORATORY_QUALIFICATION_ONLY`. Production, publication, and
independent-review claims are false.

`internal/intake` provides canonical Ed25519 verification and atomic durable
nonce transport for a caller-supplied `TrustedAuthority`. Those primitives do
not establish where the authority came from. In particular, matching the
retained key ID does not prove historical key continuity: candidate-controlled
code can pair that ID and the required owner actor with an attacker public key
and internally valid attacker signatures. The repository therefore never
treats locally supplied authority/signatures as launch proof. It returns
`PROTECTED_CALLER_REQUIRED/BLOCK` before nonce consumption or execution. The
external launcher must provide the protected trust anchor and durable ledger,
verify the two statements, then bind the same opened executable file to launch.

The repository does not currently wire a promotion record into
`ControlledCanaryRequest` or `ExecuteControlledCanary`, because doing so would
turn a self-consistent candidate authority into a self-authenticating shortcut.
`PreflightExecutablePromotionCandidate` is only a non-authorizing
candidate-side structural preflight; it can never grant launch authority.
Absent promotion remains `UNPROMOTED_EXECUTABLE/QUARANTINE`; a structurally or
semantically changed record is `EXECUTABLE_PROMOTION_MISMATCH/QUARANTINE`; a
closed valid-looking record remains `PROTECTED_CALLER_REQUIRED/BLOCK`; and
unproved OS enforcement remains `SANDBOX_ENFORCEMENT_UNAVAILABLE/BLOCK`.

The protected launcher also owns the irreducible executable identity boundary:
open with no-follow semantics, reject symlinks and multiple hard links, hash the
opened regular file, retain that handle/identity across verification, and launch
those exact bytes without a path-reopen TOCTOU window. Repository code binds an
exact digest but cannot prove that later external launch operation. Under the
approved single-owner amendment none of this means independently reviewed.
Every later use plan must bind inventory root, item digest, promotion record
digest, operation ID, scope, and non-revoked/non-expired state. Missing, extra,
mutable, dangling, cross-company, expired, or differently bound items deny
before sandbox creation.

## `security/sandbox-policy.json`

Schema version is exactly `1.0.0`. The sandbox policy contains only closed
operation profiles. Each profile binds the inventory root, exact executable
IDs, argument template, input/output classifications, resource envelope, and
platform supervisor profile. Candidate data cannot add an operation.

The mandatory capability envelope is:

- disposable user, mount, PID, IPC, UTS, and network namespaces or an attested
  platform-equivalent profile; `no_new_privs`; non-root UID/GID; empty ambient
  capabilities; no setuid, ptrace, host devices, host PID/IPC, keychain/agent
  sockets, container socket, or cloud metadata;
- read-only digest-addressed source and tool roots; read-only root filesystem;
  fresh private workspace, cache, output, home, and temp roots; all roots
  disjoint; no mount or inherited descriptor outside the exact allowlist;
- no protected-held-out, sealed, canonical-evidence, release-signing,
  production, public-output, or cross-company mount; root/device identity and a
  normalized mount-table digest are captured before execution;
- an exact environment-name allowlist with deterministic locale/time values;
  environment values are not inherited; `secrets: none`; receipts contain only
  names and a digest, never values;
- deny-all network for build, test, analyzer, evidence, and canary operations.
  Dependency acquisition is a distinct quarantined operation with an audited
  fixed gateway and exact digest promotion; acquired bytes are never consumed
  by that same operation. Authoritative builds use only the resulting
  read-only content-addressed cache with egress denied;
- bounded wall and CPU time, memory, PIDs, open files, output bytes, workspace
  bytes, cache bytes, disk blocks, inodes, and core size. The supervisor owns a
  process group/cgroup and kills the complete tree on any breach;
- output is never mounted at a public path. A broker pulls only cataloged files
  after process-tree termination, applies per-file and aggregate limits, marks
  them `QUARANTINED`, and records omissions/truncation as a blocking capture
  failure rather than silently accepting partial evidence;
- cleanup verifies zero live PIDs, removed namespaces/cgroup, detached mounts,
  deleted network namespace/interfaces, removed writable roots, closed file
  descriptors, and no content-addressed cache mutation. Cleanup failure is a
  release-revoking finding.

If the required platform enforcement cannot be proven, the result is
`SANDBOX_ENFORCEMENT_UNAVAILABLE/BLOCK`; it must not fall back to an ordinary
host process. Existing `lab.SandboxPlan` and `lab.SandboxReceipt` validation is
an additional compatibility check for existing Maven/Java operations. It is
not a substitute for the stronger receipt below.

### Sandbox receipt

Each immutable attempt produces a security sandbox receipt with:

```text
schema_version, attempt_id, prior_attempt_id, company, project,
policy_digest, plan_digest, accepted_root_digest, inventory_root_digest,
promotion_receipt_digests, securityctl_digest, supervisor_digest,
platform_identity, namespace_ids, cgroup_id, seccomp_or_profile_digest,
mount_table_before_digest, forbidden_mount_count, environment_names,
environment_digest, secret_value_count, inherited_fd_count,
started_at, finished_at, exit_code, termination_reason,
network_attempts_by_class, allowed_endpoint_count,
observed_cpu, memory, pids, open_files, output, workspace, cache, disk, inodes,
source_before_digest, source_after_digest, cache_before_digest,
cache_after_digest, artifact_manifest_digest, artifact_capture_complete,
cleanup_started_at, cleanup_finished_at, live_pids_after, mounts_after,
interfaces_after, writable_roots_removed, cleanup_complete,
assurance, independent_review_claimed
```

`termination_reason` is one of `EXITED`, `WALL_LIMIT`, `CPU_LIMIT`,
`MEMORY_LIMIT`, `PID_LIMIT`, `FD_LIMIT`, `OUTPUT_LIMIT`, `WORKSPACE_LIMIT`,
`CACHE_LIMIT`, `DISK_LIMIT`, `INODE_LIMIT`, `POLICY_DENIAL`, or
`SUPERVISOR_FAILURE`. A limit canary passes only when its exact reason is
observed, the complete process tree is dead within the cleanup bound, and all
post-cleanup counts are zero. A normal exit does not prove a resource control.

The receipt is valid only when source digests match, an offline cache is
unchanged, all observed values are within policy or have the exact expected
limit termination, artifact capture is complete, and cleanup is complete. The
receipt always states `OWNER_ATTESTED_NOT_INDEPENDENT` and
`independent_review_claimed:false`.

## Safe sandbox canaries

Isolation is tested with a separately promoted, project-owned `securityctl`
canary implementation, never with upstream Maven, Java, Rust, Python, archive,
or container bytes. The supervisor accepts these fixed IDs only:

```text
ENV_SENTINEL_ABSENT, PROTECTED_SENTINEL_DENIED, SOURCE_WRITE_DENIED,
NETWORK_SOCKET_DENIED, CPU_BOUND, MEMORY_BOUND, PID_BOUND, FD_BOUND,
OUTPUT_BOUND, WORKSPACE_BOUND, CACHE_WRITE_DENIED, WALL_BOUND, CLEAN_EXIT
```

The secret and protected-store checks use random, non-secret sentinel values
and a temporary canary directory outside the sandbox mount allowlist. No real
secret or protected corpus is read. `NETWORK_SOCKET_DENIED` asks the kernel for
a socket under the deny-all profile and expects a policy denial; it sends no
packet and needs no external endpoint. Resource canaries use fixed internal Go
loops/allocations/file creation, and are run one at a time inside a disposable
fixture sandbox. They cannot select arbitrary code or paths. Tests of receipt
validation use inert JSON observations and do not execute even these canaries.

## `security/release-firewall.json`

Schema version is exactly `1.0.0`. The policy binds the fixed company/project,
the three security policy digests, the accepted quarantine root, and an exact
projection manifest schema. Its closed classifications are the inherited five
values: `PUBLIC`, `PUBLIC_DERIVED`, `INTERNAL`, `PROTECTED_HELD_OUT`, and
`QUARANTINED`.

Projection is pull-only after sandbox cleanup. A canonical projection manifest
enumerates every source descendant and every staged descendant with path,
kind, source digest, output digest, byte size, classification, include/exclude
decision, transformation ID, and provenance parents. Directories are entries,
not implied containers. Every child must have exactly one classified parent,
and every parent directory is recursively closed. Unlisted, duplicate,
case/normalization-colliding, late-created, or digest-drifting descendants deny.

Only regular single-link files classified `PUBLIC` or `PUBLIC_DERIVED` may be
included. Symlinks, hard links, special files, caches, raw logs, crash dumps,
temporary files, compiled outputs not explicitly declared, and files with a
provenance gap are never copied. The staged projection is built from the
manifest into a new private root, reopened through `os.OpenRoot`, recursively
walked and rehashed, scanned, and atomically promoted as a content-addressed
projection only if the actual tree exactly equals the manifest.

The content scan is byte-oriented and streaming. Declarative detectors cover:

- protected/sealed case labels and canary tokens;
- expected output, answer, oracle-result, and golden-result fields;
- raw diagnostic/log/trace/core/heap/profile fields and file signatures;
- sensitive actor, tenant, invocation/session, filesystem, host, email, and
  machine identifiers, while allowing reviewed public semantic identifiers;
- credential/private-key/token/cookie/password/authorization patterns and
  high-entropy assignments;
- cache/build-state signatures and directories for Maven, Cargo, Java, Rust,
  language servers, containers, and the security gate;
- absolute local paths and unredacted provenance locations.

Detector exceptions are exact path + detector + matched-byte digest tuples in
policy and require an owner action; a free-form regex suppression is forbidden.
Binary or unknown media cannot bypass scanning: it must have an exact public
artifact declaration and scanner profile or is unclassified.

The project scanner never mounts protected corpora. A separate trusted
protected classifier receives the already bounded staged projection through a
one-way broker and returns a signed receipt binding projection root, protected
fingerprint-set version, zero matches, policy digest, company/project, expiry,
and nonce. Its fingerprint set and signing material never enter the repository,
sandbox, or `securityctl`. Missing, stale, self-authored, cross-company, or
nonzero-match receipts fail closed. The public evidence records only safe
receipt identity/digests and counts.

The eventual broker is an owner-started local process outside the candidate
sandbox. It accepts exactly one canonical projection manifest plus its
digest-addressed file stream on anonymous file descriptors and returns exactly
one bounded JSON receipt on a different descriptor. It accepts no candidate
command, path, URL, or callback and has no publication/signing role beyond its
dedicated classifier receipt key. Before that broker can satisfy a real
projection, a protected authority policy must pin its public key, checker
identity, receipt schema, maximum request/response bytes, validity window,
revocation state, and durable nonce ledger. The current
`release-firewall.json` deliberately contains only
`protected_checker_required:true`; no external classifier identity or key is
provisioned, so every real projection remains
`PROTECTED_CLASSIFIER_UNAVAILABLE/BLOCK`. No placeholder or synthetic key is
treated as that missing authority. A future test-only checker may use a pinned
synthetic key and public canary fingerprint set, but its receipt must be labeled
`SYNTHETIC_NON_CLAIM` and can never satisfy a real projection.

A passed firewall produces a safe projection CAS and
`publication_authorized:false`. A separate owner publication action must bind
that exact projection root, the security evidence root, the existing assurance
snapshot, and any still-required independent attestations. Because this project
is currently owner-only and the canonical lifecycle is blocked, US-007 cannot
perform that action.

## Closed finding registry

The union of the three policy `finding_registry` sections is exact. Duplicate
codes with different dispositions, an unknown emitted code, or a code absent
from the existing assurance failure registry when projected into the lifecycle
is `INVALID_SECURITY_POLICY/BLOCK`. Implementation may add a code only by
editing the reviewed policy, schema-valid fixture catalog, and lifecycle
mapping together.

| Code | Disposition | Meaning |
|---|---|---|
| `INVALID_SECURITY_POLICY` | `BLOCK` | malformed, unknown, duplicate, or internally inconsistent policy/registry |
| `UNSUPPORTED_POLICY_VERSION` | `BLOCK` | schema or policy version is not exactly frozen |
| `ROOT_CONFINEMENT_FAILED` | `QUARANTINE` | root/path/device boundary cannot be proven |
| `IMMUTABLE_SNAPSHOT_FAILED` | `QUARANTINE` | input identity or metadata changed during the one source read |
| `POLICY_DIGEST_MISMATCH` | `QUARANTINE` | plan, evidence, or receipt is bound to different policy bytes |
| `STALE_SECURITY_POLICY` | `INVALIDATE` | policy, promotion, classifier, or inventory validity expired |
| `STATIC_EXECUTION_FORBIDDEN` | `QUARANTINE` | static intake requested or observed candidate execution |
| `PATH_TRAVERSAL` | `QUARANTINE` | relative path escapes or has forbidden components |
| `ABSOLUTE_PATH` | `QUARANTINE` | candidate or provenance uses a host-absolute path |
| `NONCANONICAL_PATH` | `QUARANTINE` | invalid UTF-8, non-NFC, backslash, device, or noncanonical path |
| `UNSAFE_SYMLINK` | `QUARANTINE` | any candidate or projection symbolic link |
| `HARD_LINK_DENIED` | `QUARANTINE` | a file has more than one link |
| `SPECIAL_FILE_DENIED` | `QUARANTINE` | socket, FIFO, device, or unknown file type |
| `NORMALIZATION_COLLISION` | `QUARANTINE` | two paths share an NFC-casefold key |
| `DUPLICATE_ENTRY` | `QUARANTINE` | duplicate path, object, inventory, or manifest member |
| `ARCHIVE_LIMIT_EXCEEDED` | `QUARANTINE` | entry, depth, size, or expansion bound exceeded |
| `NESTED_ARCHIVE_DENIED` | `QUARANTINE` | undeclared nested archive content |
| `UNDECLARED_EXECUTABLE` | `QUARANTINE` | executable mode/content is absent from inventory policy |
| `QUOTA_EXCEEDED` | `QUARANTINE` | non-archive file/directory/byte/inode quota exceeded |
| `DIGEST_MISMATCH` | `QUARANTINE` | retained bytes differ from their declared digest |
| `PARTIAL_PROMOTION` | `QUARANTINE` | an all-or-none ingest/projection commit cannot be proven |
| `PROMOTION_BINDING_MISMATCH` | `QUARANTINE` | accepted root, action, inventory, scope, or use plan differs |
| `UNCLASSIFIED_INPUT` | `QUARANTINE` | candidate member lacks a closed classification |
| `CROSS_COMPANY_REFERENCE` | `QUARANTINE` | company/project/provenance/path scope crosses the tenant boundary |
| `DANGLING_PROVENANCE` | `QUARANTINE` | a provenance parent is missing or unreachable |
| `PROVENANCE_DIGEST_MISMATCH` | `QUARANTINE` | provenance parent bytes/root do not match |
| `EXECUTABLE_INVENTORY_INCOMPLETE` | `QUARANTINE` | static discovery and declared executable closure differ |
| `UNPROMOTED_EXECUTABLE` | `QUARANTINE` | an executable lacks the required protected owner promotion record |
| `EXECUTABLE_PROMOTION_MISMATCH` | `QUARANTINE` | executable bytes/use differ from their promotion receipt |
| `PROTECTED_CALLER_REQUIRED` | `BLOCK` | repository-local authority cannot prove protected key custody, continuity, ledger, or launch provenance |
| `MUTABLE_EXECUTABLE_REFERENCE` | `QUARANTINE` | tag, range, repository head, or unresolved locator is used |
| `EXECUTABLE_USE_NOT_BOUND` | `QUARANTINE` | operation plan does not bind inventory and promotion roots |
| `AUTOBAHN_RERUN_FORBIDDEN` | `BLOCK` | any plan attempts a third or otherwise unauthorized Autobahn run |
| `CANONICAL_EVIDENCE_MUTATION` | `REVOKE` | either retained US-002 receipt or rerun disposition changed |
| `SANDBOX_ENFORCEMENT_UNAVAILABLE` | `BLOCK` | the required supervisor/capability proof is unavailable |
| `SANDBOX_CAPABILITY_MISMATCH` | `QUARANTINE` | plan/profile omits or widens a required capability restriction |
| `SECRET_ACCESS_DENIED` | `QUARANTINE` | environment, descriptor, or plan exposes a secret capability |
| `FORBIDDEN_MOUNT_EXPOSED` | `REVOKE` | protected, signing, production, public, or cross-company mount was observed |
| `NETWORK_POLICY_VIOLATION` | `QUARANTINE` | denied egress was possible/observed or audit is incomplete |
| `FORBIDDEN_CAPABILITY_OBSERVED` | `REVOKE` | privilege, socket, descriptor, device, namespace, or host capability escaped policy |
| `RESOURCE_LIMIT_EXCEEDED` | `QUARANTINE` | measured use exceeded a declared resource ceiling |
| `RESOURCE_TERMINATION_MISSING` | `QUARANTINE` | a limit canary did not terminate for the exact expected reason |
| `SOURCE_MUTATION_DETECTED` | `QUARANTINE` | accepted read-only source changed |
| `CACHE_CLOSURE_MISMATCH` | `QUARANTINE` | offline cache content differs before/after or from its pin |
| `ARTIFACT_CAPTURE_INCOMPLETE` | `QUARANTINE` | output pull was missing, truncated, over limit, or unclassified |
| `SANDBOX_CLEANUP_INCOMPLETE` | `REVOKE` | process, namespace, mount, network, descriptor, or writable residue remains |
| `SANDBOX_RECEIPT_INVALID` | `QUARANTINE` | receipt is candidate-authored, ambiguous, incomplete, or misbound |
| `TCB_EXECUTABLE_MISMATCH` | `QUARANTINE` | securityctl/supervisor/tool digest differs from promotion |
| `PUBLIC_DESCENDANT_UNCLASSIFIED` | `BLOCK` | any source or staged descendant lacks one exact classification |
| `PUBLIC_PROJECTION_DRIFT` | `REVOKE` | materialized public tree differs from the reviewed exact manifest |
| `PROTECTED_PUBLICATION_DISCLOSURE` | `REVOKE` | public projection reaches or contains protected/sealed material |
| `EXPECTED_OUTPUT_DISCLOSURE` | `REVOKE` | expected/golden/oracle answers occur in public bytes |
| `RAW_DIAGNOSTIC_DISCLOSURE` | `REVOKE` | raw diagnostics, traces, dumps, or unredacted logs occur in public bytes |
| `IDENTIFIER_DISCLOSURE` | `REVOKE` | protected actor, host, tenant, session, path, email, or machine identifier leaked |
| `CREDENTIAL_DISCLOSURE` | `REVOKE` | credential, private key, token, cookie, password, or authorization value leaked |
| `CACHE_DISCLOSURE` | `REVOKE` | cache/build/language-server/container/security-gate state is projected |
| `PUBLIC_PROVENANCE_GAP` | `BLOCK` | included public bytes lack complete immutable derivation |
| `PROTECTED_CLASSIFIER_UNAVAILABLE` | `BLOCK` | protected-side checker receipt is missing, stale, invalid, or wrongly scoped |
| `PROTECTED_CLASSIFIER_REJECTED` | `REVOKE` | protected-side checker reported one or more matches |
| `ASSURANCE_CEILING_EXCEEDED` | `REVOKE` | evidence claims independence or assurance above the owner-only ceiling |
| `PUBLICATION_AUTHORITY_MISSING` | `BLOCK` | no separately authorized owner action binds the exact roots |
| `PUBLICATION_NOT_AUTHORIZED` | `BLOCK` | US-007 or fixture attempts publication rather than safe projection |

No US-007 code automatically retries. An infrastructure retry, when permitted
by the inherited lifecycle, is a new immutable attempt and receipt. The closed
Autobahn disposition overrides every generic transient retry rule.

## Fixture catalog and safe proof mechanisms

Every fixture is `SYNTHETIC_NON_CLAIM`, company/project scoped, digest-bound,
and contains no real credential, protected corpus, expected output, or hostile
executable. Filesystem link fixtures are created only inside `t.TempDir()` with
an in-root public sentinel target. Archive fixtures are generated in memory
from inert text and inspected without extraction. Maven, Cargo, language-server,
and container fixtures are text metadata; none is resolved, imported, built,
loaded, or started.

The closed catalog contains at least these exact cases:

| Fixture ID | Attack/control | Expected result |
|---|---|---|
| `good-benign-ingest` | canonical inert source manifest | accepted quarantine root, no finding |
| `static-exec-request` | intake action requests a hook | `STATIC_EXECUTION_FORBIDDEN/QUARANTINE` |
| `path-traversal` / `absolute-path` | `..`, backslash, or host path | `PATH_TRAVERSAL` or `ABSOLUTE_PATH`, `QUARANTINE` |
| `symlink` / `hard-link` / `special-file` | link or FIFO descriptor in disposable root | `UNSAFE_SYMLINK`, `HARD_LINK_DENIED`, or `SPECIAL_FILE_DENIED`, `QUARANTINE` |
| `archive-bomb` / `nested-archive` | declared metadata exceeds bound or undeclared inert nested bytes | `ARCHIVE_LIMIT_EXCEEDED` or `NESTED_ARCHIVE_DENIED`, `QUARANTINE` |
| `case-collision` / `unicode-collision` | distinct paths share collision key | `NORMALIZATION_COLLISION/QUARANTINE` |
| `quota-breach` | virtual manifest exceeds one bound | `QUOTA_EXCEEDED/QUARANTINE` |
| `partial-promotion` | injected fsync/rename fault before accepted manifest | `PARTIAL_PROMOTION/QUARANTINE`, zero visible accepted root |
| `digest-mismatch` | inert blob differs from declaration | `DIGEST_MISMATCH/QUARANTINE` |
| `dangling-provenance` / `cross-company-provenance` | absent parent or changed company | `DANGLING_PROVENANCE` or `CROSS_COMPANY_REFERENCE`, `QUARANTINE` |
| `maven-plugin`, `annotation-processor`, `rust-build-script`, `proc-macro`, `language-server-import`, `autobahn-python`, `container-entrypoint` | discovered executable has no use-bound promotion | `UNPROMOTED_EXECUTABLE/QUARANTINE`; bytes are never executed |
| `autobahn-third-run` | operation references the closed image/runner | `AUTOBAHN_RERUN_FORBIDDEN/BLOCK` before process or Docker API access |
| `receipt-mutation` | one retained Autobahn attempt digest/disposition changes | `CANONICAL_EVIDENCE_MUTATION/REVOKE` |
| `good-sandbox-canaries` | controlled fixed canaries produce exact complete receipt | pass mechanics, no upstream bytes executed |
| `network-probe` | fixed socket syscall is denied, while forged allow receipt is supplied separately | real canary records denial; forged receipt is `NETWORK_POLICY_VIOLATION/QUARANTINE` |
| `secret-probe` | random sentinel is not present | pass only with `secret_value_count:0`; forged presence is `SECRET_ACCESS_DENIED/QUARANTINE` |
| `protected-store-probe` | temporary public canary root outside mount set cannot be opened | pass on policy denial; forged exposure is `FORBIDDEN_MOUNT_EXPOSED/REVOKE` |
| `cpu-bomb`, `memory-bomb`, `pid-bomb`, `fd-bomb`, `disk-bomb`, `output-bomb`, `wall-bomb` | fixed project-owned bounded canary | exact limit termination plus cleanup; otherwise `RESOURCE_TERMINATION_MISSING/QUARANTINE` |
| `cleanup-residue` | synthetic post-cleanup PID/mount/interface remains | `SANDBOX_CLEANUP_INCOMPLETE/REVOKE` |
| `capture-failure` | expected bounded artifact missing/truncated | `ARTIFACT_CAPTURE_INCOMPLETE/QUARANTINE` |
| `good-safe-projection` | complete public/public-derived inert tree and zero-match protected receipt | safe projection root succeeds, `publication_authorized:false` |
| `protected-leak`, `expected-output-leak`, `raw-diagnostic-leak`, `identifier-leak`, `credential-leak`, `cache-leak` | public canary tokens shaped for each detector | corresponding release finding with `REVOKE` |
| `provenance-gap` / `unclassified-descendant` | included byte lacks parent or child classification | `PUBLIC_PROVENANCE_GAP/BLOCK` or `PUBLIC_DESCENDANT_UNCLASSIFIED/BLOCK` |
| `late-public-mutation` | staged byte/tree changes after scan | `PUBLIC_PROJECTION_DRIFT/REVOKE` |
| `independence-claim` | fixture sets independent review or higher assurance | `ASSURANCE_CEILING_EXCEEDED/REVOKE` |
| `publication-attempt` | fixture asks gate to publish/sign | `PUBLICATION_NOT_AUTHORIZED/BLOCK` |

The good end-to-end fixture combines `good-benign-ingest`, a fully promoted
synthetic no-op executable, controlled canary receipts, and
`good-safe-projection`. “Build succeeds” means the promoted project-owned no-op
operation exits in the sandbox and yields a classified inert artifact. It does
not run Maven, Java, Rust, Python, an archive payload, a container, or Autobahn.

## Acceptance and E2E mapping

| Requirement | Concrete policy/control | Fixtures and retained evidence |
|---|---|---|
| AC1: static intake executes nothing; builds use read-only source, isolated CAS caches, no secrets, bounds, deny-default egress, and no protected/signing/production/cross-company mounts | ingestion `source_modes` has no execute action; sandbox closed operations, capability envelope, promotion-bound source/cache, deny-all authoritative network, environment and mount allowlists, resource/cleanup receipt | `static-exec-request`, good canaries, network/secret/protected probes, every resource fixture; `security-validation.intake`, `.sandbox_attempts`, and `.cleanup` |
| AC2: enumerate and promote Maven, processor, Rust, dependency, LSP, Autobahn, archive, and container executables | closed inventory classes, static discovery reconciliation, exact promotion/use bindings, US-002 no-rerun override | every inventory fixture plus `autobahn-third-run`; `security-validation.executable_inventory` and `.autobahn_receipt_closure` |
| AC3: transactional ingestion rejects paths, links, specials, bombs, collisions, quotas, partials, digests, and bad provenance | root-confined one-read snapshot, inherited archive adapters, canonical collision key, bounded CAS transaction and read-back | all ingestion fixtures; `security-validation.ingestion_cases` and accepted root or zero-visible-root receipt |
| AC4: exact public projection recursively classifies and denies protected cases, expected output, diagnostics, identifiers, credentials, caches, gaps, and unclassified descendants | release manifest closure, byte scanners, protected-side receipt, staged-tree equality, atomic safe projection with no publish operation | good projection and every release leak/gap/mutation fixture; `security-validation.release_firewall` |
| AC5: adversarial fixtures prove denial, absence, termination, cleanup, fail-closed capture, and zero leakage | fixed project-owned canaries plus inert verifier fixtures; receipts require exact negative/termination/cleanup observations | network, secret, protected root, resource, cleanup, capture, leak fixtures; full case result array in `security-validation` |
| E2E hostile archives and links | static in-memory archive recipe and disposable in-root link metadata | exact ingest findings; no extraction/execution |
| E2E build hooks | inert POM/Cargo/LSP/container metadata discovers unpromoted executable | exact inventory finding before sandbox creation |
| E2E network/secret/protected probes | fixed promoted canaries and forged-receipt negatives | kernel/profile denial and supervisor receipt; no real secret/protected data |
| E2E resource bombs | fixed bounded canary enums, cgroup/process-tree ownership | exact termination reason and complete cleanup receipt |
| E2E public-output leaks | public synthetic canary tokens and protected classifier stub with pinned test key | exact release finding and zero projection root |
| E2E benign build and safe projection | promoted project-owned no-op canary and complete inert public tree | accepted quarantine and projection roots, but publication remains false |

## `evidence/security-validation.json`

The retained evidence schema is closed and strict. It contains:

- story/scope, commit, timestamps, the three exact policy digests, schema
  digests, fixture catalog digest, and closed finding-registry digest;
- intake source/evidence/accepted roots, one-read snapshot manifest digest,
  object counts/bytes, archive counts, transaction ID, and atomic promotion
  receipt;
- executable inventory root, class counts, promotion receipt digests, zero
  unpromoted uses, and the pinned `securityctl`/supervisor identities;
- each immutable sandbox attempt, plan and receipt digest, canary ID, expected
  and actual termination, bounded observations, artifact manifest, and cleanup
  result;
- projection source/staged/final roots, recursive entry/classification counts,
  detector version/results, protected-classifier receipt digest/count, complete
  provenance root, and `publication_authorized:false`;
- every fixture ID, input digest, expected and actual code/disposition, CLI exit,
  and a `matched` boolean; omitted catalog cases are invalid evidence;
- the exact two original and two remediation Autobahn attempt digests,
  `consumed_remediation_attempts_per_mode:1`,
  `further_reruns_authorized:false`, and `reruns_performed_by_us007:0`;
- the existing assurance Verify/Replay verdict roots and normalized findings;
- quality command, exit, output digest, mutation check, and runtime metadata;
- final `mechanics_state`, `assurance`, `independent_review_claimed`,
  `production`, `signing`, and `publication` fields.

A mechanically passing story records
`mechanics_state: PASS_CANONICAL_ASSURANCE_BLOCKED`,
`assurance: OWNER_ATTESTED_NOT_INDEPENDENT`,
`independent_review_claimed:false`, `production:false`, `signing:false`, and
`publication:false`. It does not rewrite the existing assurance verdict to
accepted.

## TDD sequence

Implementation follows RED -> GREEN -> REFACTOR, with no upstream execution:

1. add strict schemas and failing tests for unknown/duplicate fields, policy
   digest closure, scope, registry uniqueness, and owner-only ceiling;
2. add root/path/link/special/collision/quota/one-read race tests, then implement
   the confined snapshot transport;
3. add in-memory TAR/ZIP/JAR recipes for traversal, limits, nested content, and
   executable declarations, then wire the inherited intake adapters;
4. add transaction fault points before blob fsync, manifest fsync, rename, and
   read-back; prove no partial root, idempotent replay, and concurrent exact
   callers before implementing promotion;
5. add Maven/Rust/LSP/Autobahn/container metadata tables and prove complete
   inventory/promotion/use reconciliation without resolving or running them;
6. add sandbox plan and receipt negatives for every capability/resource field,
   keep candidate transport non-authorizing, and separately run the fixed
   project-owned canaries through the protected operator on the supported
   platform;
7. add recursive virtual projection and scanner cases for every leak/gap class,
   protected receipt validation, and late mutation before implementing staged
   projection;
8. add the combined benign/no-op E2E and all hostile fixture rows through both
   the package and CLI; require exact normalized code/disposition equality;
9. add the security evidence node through the US-004 regeneration path and
   prove `assurance.Verify`/`Replay` equality and the unchanged owner-only
   blocked ceiling;
10. refactor only after all red cases are green; freeze policy, schemas, fixture
    catalog, executable identities, and evidence roots.

Tests must inject filesystem/supervisor faults through package-private function
variables or a concrete fake transport. They must not weaken production checks,
sleep for races, access network, create links outside `t.TempDir()`, expose real
secrets/protected data, or treat a forged receipt as enforcement proof.

## Exact quality and E2E gates

These are implementation-phase commands, not commands executed during this
design phase. The operator must first prove that the selected test set contains
no Java/Rust/Python/container/Autobahn launcher. Run from the target repository:

```text
go test ./internal/securitygate ./cmd/securityctl -count=1
go test -race ./internal/securitygate ./cmd/securityctl -count=1
go vet ./internal/securitygate ./cmd/securityctl
go build ./cmd/securityctl
go test ./internal/securitygate -run '^TestUS007Acceptance_' -count=1
go test ./internal/securitygate -run '^TestUS007E2E_InertAttackMatrix$' -count=1
go test ./internal/securitygate -run '^TestUS007E2E_ControlledCanaries$' -count=1
securityctl verify --root .
```

`TestUS007E2E_ControlledCanaries` is skipped with a typed
`PROTECTED_CALLER_REQUIRED/BLOCK` because candidate tests cannot acquire the
external launch authority. A skip cannot pass acceptance. External validation
runs only the fixed Go canary IDs, and acceptance additionally requires proof
that the complete resource envelope is imposed outside each hostile workload.
No generic `go test ./...` is accepted as a substitute because unrelated
packages include Java-process and Autobahn-capable harnesses. After security
acceptance is recorded, a separate reviewed whole-repository Go quality pass
may run only with an explicit exclusion/proof that those launch paths cannot
activate; Maven, Java, Rust build/proc-macro, Python, Docker, container, live
Autobahn, network probe, production, publication, and push commands remain
forbidden in US-007.

The E2E gate additionally records before/after `git status --short`, hashes of
all retained policies/fixtures/evidence, zero mutation of the two US-002
Autobahn receipt sets, zero new Autobahn attempts, zero protected-store reads,
zero network packets from deny-all canaries, zero signing/publication actions,
and exact catalog coverage. Every bad case exits nonzero with exactly its
cataloged normalized finding. The benign case may create only private temporary
CAS roots and must delete them after a complete cleanup receipt.

## Implementation stop conditions and residual risks

Stop rather than weaken policy when:

- the runtime cannot prove the namespace/profile, resource, mount, network, or
  cleanup envelope;
- an executable class cannot be enumerated or bound to exact promoted bytes;
- the original/remediation Autobahn receipt digests or no-rerun disposition
  differ;
- root confinement, one-read identity, transaction durability, protected
  classifier identity, company provenance, or recursive projection closure is
  ambiguous;
- the assurance adapters disagree, an inherited schema drifts, or any result
  claims independent review;
- a safe fixture would require executing candidate or upstream bytes.

Residual risks after implementation are the promoted supervisor/OS kernel TCB,
detector false negatives, incomplete static discovery for a newly introduced
build-system feature, confidentiality of protected-checker fingerprints, and
the sole-owner governance model. They are bounded by exact executable and
policy pins, a closed operation/inventory registry, a protected-side zero-match
receipt, immutable evidence, and the assurance ceiling; they are not eliminated
or described as independent certification.

## Security design review runtime metadata

This architecture phase was performed with the security-scanner worker
contract and the company reviewer-model policy in scope. Runtime metadata
provided by the orchestrator is:

```json
{
  "provider": "OpenAI",
  "requested_model": "gpt-5.6-sol",
  "requested_reasoning_effort": "xhigh",
  "task_session_path": "/root/us007_security_design",
  "actual_deployment_identifier": "not_exposed",
  "runtime_session_uuid": "not_exposed",
  "assurance": "OWNER_ATTESTED_NOT_INDEPENDENT",
  "independent_review_claimed": false
}
```

The platform did not expose a deployment identifier or runtime session UUID;
none is invented. This metadata identifies the architecture pass and is not an
independent security attestation.
