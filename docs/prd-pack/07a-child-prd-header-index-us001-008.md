Java-to-Rust port PRD pack, part 7 of 7: the Java-WebSocket child laboratory PRD — header, story index, and the full text of all 27 child stories.

(part 7a of 7)

## 7. Child laboratory PRD: verified-java-websocket-port

Location: the verified-java-websocket-port project folder next to the parent, under the same company (prd.json updated 2026-08-28T14:10:45Z).
Branch: feature/verified-java-websocket-port. Code repo: repos/public/verified-java-websocket-port.
Status: completed, completionScope STORY_EXECUTION_COMPLETE (owner-attested; independent acceptance is master US-008 and remains open).
Inherits: templates/child-prd/laboratory-template.json; lab manifest laboratories/java-websocket/manifest.json.

**Description:** Produce an independently replayable, evidence-bearing safe-Rust reimplementation of Java-WebSocket v1.6.0's RFC 6455 client/server Sans-I/O core and thin conformance adapters.

**Goal:** Use Java-WebSocket v1.6.0 as the first real-source laboratory to produce a complete safe-Rust RFC 6455 Sans-I/O port and a claim-scoped, independently replayable evidence bundle that exercises the reusable Java-to-Rust method.

A sibling verified-java-websocket-port-claude (branch claude/feature/verified-java-websocket-port, updated 2026-08-25) has the same 27 stories with 9 marked done; it is the Claude-runtime variant and is not the canonical child.

### Child story index

| ID | Pri | Local passes | Depends on | Title |
|---|---:|---|---|---|
| US-001 | 1 | done | — | Promote every immutable laboratory input |
| US-002 | 1 | done | US-001, US-007 | Establish the fresh Java authority and Autobahn baseline |
| US-003 | 1 | done | US-001, US-002 | Freeze intake, compatibility, semantic IDs, and port seams |
| US-004 | 1 | done | US-001 | Instantiate the inherited evidence lifecycle |
| US-005 | 1 | done | US-002, US-003, US-004 | Calibrate public, hidden, sealed, and handshake corpora |
| US-006 | 1 | done | US-003, US-004 | Qualify implementation-linked proof and concurrency seams |
| US-007 | 1 | done | US-001, US-004 | Prove sandbox and release-firewall isolation |
| US-008 | 1 | done | US-001, US-002, US-003, US-004 | Pre-register controlled Java and Rust resource benchmarks |
| US-009 | 2 | done | US-001, US-002, US-003, US-004, US-005, US-006, US-007, US-008 | Establish the safe Rust ConnectionCore contract |
| US-010 | 2 | done | US-009 | Implement the client opening-handshake slice |
| US-011 | 2 | done | US-009, US-010 | Implement the server opening-handshake slice |
| US-012 | 2 | done | US-009 | Implement canonical framing, masking, and allocation limits |
| US-013 | 2 | done | US-012 | Deliver strict text and binary messages |
| US-014 | 2 | done | US-012, US-013 | Reassemble fragmented messages with bounded state |
| US-015 | 2 | done | US-012, US-014 | Implement ping and pong control behavior |
| US-016 | 2 | done | US-012, US-013, US-014, US-015 | Complete close, EOF, and terminal-state behavior |
| US-017 | 2 | done | US-009, US-012, US-013, US-014, US-015, US-016 | Drive bounded concurrent commands through one owner |
| US-018 | 2 | done | US-010, US-011, US-012, US-013, US-014, US-015, US-016, US-017 | Add thin blocking TCP client and server adapters |
| US-019 | 2 | done | US-018 | Pass both pinned Autobahn conformance modes |
| US-020 | 2 | done | US-005, US-010, US-011, US-012, US-013, US-014, US-015, US-016, US-017, US-018, US-019 | Close Java and Rust differential divergences |
| US-021 | 2 | done | US-020 | Close property, fuzz, and runtime evidence |
| US-022 | 2 | done | US-005, US-020, US-021 | Pass normalized mutation and protected evaluation |
| US-023 | 2 | done | US-006, US-007, US-008, US-019, US-020, US-021, US-022 | Freeze the complete parity candidate |
| US-024 | 3 | done | US-023 | Refine idiomatic Rust without changing parity |
| US-025 | 3 | done | US-008, US-024 | Decide every preregistered resource envelope |
| US-026 | 3 | done | US-023, US-024, US-025 | Rehearse shadow, canary, soak, and Java rollback |
| US-027 | 3 | done | US-026 | Independently accept and project the complete child snapshot |

### Child stories — full text

### US-001 — Promote every immutable laboratory input
**Priority:** 1 | **Passes:** true | **Depends on:** none | **Labels:** preflight, provenance, supply-chain, security

As the repository owner, I want every source, standard, suite, toolchain, container, schema, policy, and developer-tool byte promoted under an explicit owner-attested policy so that no later claim executes an untrusted or floating input.

**Acceptance criteria:**
- The laboratory manifest's Java-WebSocket v1.6.0 commit/tree/archive/JAR/POM/license, RFC 6455 text, Autobahn v25.10.1 source/image/case registry, OpenJDK 17.0.19, Maven 3.9.11, Rust 1.95.0, frozen Lab Zero template, and promotion policy are each acquired by immutable URL and verified digest.
- Acquisition, quarantine, qualification, and owner promotion bind the frozen foundation policy plus the exact java-websocket-single-owner-1.0.0 amendment. The repository owner may sign every action role, and the result is labeled OWNER_ATTESTED_NOT_INDEPENDENT; signatures, unused nonces, expiry, revocation, exact vulnerability disposition, port-implementer-action-only qualification sandbox access, and release-attestor-action-only publication remain mandatory.
- Every executable input has a dependency lock graph, SBOM, vulnerability snapshot, license/provenance record, mirror or replay source, expiration, rotation, and revocation state before promotion.
- The promoted Autobahn image descriptor is exactly linux/amd64 manifest sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074; no floating tag can satisfy the gate.
- Traversal, unsafe link, special file, archive bomb, normalization collision, digest mismatch, cross-company reference, replayed authorization, role conflict, and unclassified artifact fixtures fail closed with typed findings.

### US-002 — Establish the fresh Java authority and Autobahn baseline
**Priority:** 1 | **Passes:** true | **Depends on:** US-001, US-007 | **Labels:** preflight, java, oracle, autobahn

As the oracle custodian, I want a fresh authoritative Java build, test inventory, neutral adapter, and Autobahn baseline so that Rust is compared with an executable release rather than stale reports or source intuition.

**Acceptance criteria:**
- The exact v1.6.0 source builds and tests under promoted OpenJDK 17.0.19 and Maven 3.9.11 in the accepted US-007 untrusted-build profile with isolated caches, a private in-VM clone from read-only host source, no secrets or host Docker socket, bounded resources, and audited deny-by-default egress; accepting the retained Autobahn receipts does not authorize another Autobahn run.
- Static annotations, Maven discovery, executed tests, passed, failed, skipped, filtered, timed-out, and quarantined counts reconcile exactly; the retained upstream feature file and executable Autobahn utilities are classified instead of silently counted as tests.
- A thin out-of-process Java JSONL adapter accepts role, state, byte chunks, local actions, and limits and emits normalized state transitions, semantic frames/events, close details, errors, and consumed/buffered byte counts without modifying upstream production source.
- Fresh Java client and server Autobahn runs expand and execute the exact in-scope selectors 1.* through 7.* and 10.*; categories 9.*, 12.*, and 13.* remain visible declared exclusions, and all selected cases reconcile exactly.
- Every Java/RFC/Autobahn disagreement is preserved in the append-only Behavior Delta Ledger; Java is never treated as normative when it conflicts with RFC 6455.

### US-003 — Freeze intake, compatibility, semantic IDs, and port seams
**Priority:** 1 | **Passes:** true | **Depends on:** US-001, US-002 | **Labels:** preflight, intake, semantic-map, scope

As the port implementer, I want the exact Java behavior surface and migration seams frozen before translation so that every Rust slice has an observable source and evidence obligation.

**Acceptance criteria:**
- A JavaIntakeManifest reconciles the 78-file/12,317-line production tree, 79-file/9,838-line test tree, runtime test inventory, dependencies, generated/reflection/native surfaces, serialization, concurrency, network, filesystem, observability, and deployment topology.
- The selected study surface is exactly the four root connection files plus drafts, enums, exceptions, framing, handshake, interfaces, and util packages—52 files and 6,916 physical lines—with every exclusion named.
- Every versioned MigrationMap row binds Java compiler/JDT semantic identity to a Rust rust-analyzer or reviewed-Glancer identity, applicability, known non-equivalence, source revision/query, port slice, touched files, RFC/oracle/vector/property/formal/evidence IDs, and status.
- The Port Seam Dossier inventories public and internal boundaries, handshakes, frames, ownership, buffers, queues, threads, callbacks, wire formats, limits, time/randomness, and adapter seams; no implementation story has an unresolved touched surface.
- CompatibilitySurface and CutoverContract preserve the RFC 6455 wire boundary and normalized command/event behavior while explicitly excluding TLS/WSS, proxies, reconnect, Android, RFC 7692, Java API parity, Java's NIO topology, and extension/subprotocol framework parity.

### US-004 — Instantiate the inherited evidence lifecycle
**Priority:** 1 | **Passes:** true | **Depends on:** US-001 | **Labels:** preflight, evidence, lifecycle, replay

As the method steward, I want the frozen Laboratory Zero evidence model instantiated for WebSocket so that every claim, failure, retry, stale edge, and publication byte is deterministic and replayable.

**Acceptance criteria:**
- The child instantiates the accepted canonical schemas for sources, surfaces, migration maps, dossiers, deltas, compatibility, cutover, oracles, corpora, traces, claims, formal obligations, evidence runs, mutations, benchmarks, developer-tool runs, attempts, snapshots, failures, authorizations, classifications, and staleness edges without weakening them.
- A typed failure registry is frozen, and every operation emits its universal failure envelope with one of RETRY, DEGRADE_NON_ASSURANCE, BLOCK, INVALIDATE, QUARANTINE, or REVOKE; only named transient infrastructure failures may retry and every retry is a new immutable attempt.
- The resumable content-addressed DAG rejects cycles, dangling/unreachable evidence, digest or role mismatch, stale dependencies, mutable artifact substitution, cross-company edges, and a public root that can reach protected cases, outputs, or raw diagnostics.
- JDT LS 1.60.0, rust-analyzer 2026-08-17.4, and the mutually exclusive bounded Glancer v0.1.1 trial emit DeveloperToolRun records with empty assurance claims and gate effects; failure or fallback cannot satisfy or veto authoritative gates.
- Good lifecycle fixtures reach only the allowed state, while bad receipts, zero-obligation formal artifacts, missing evidence, post-review mutation, stale pins, role conflict, and leakage canaries fail closed with stable codes.

### US-005 — Calibrate public, hidden, sealed, and handshake corpora
**Priority:** 1 | **Passes:** true | **Depends on:** US-002, US-003, US-004 | **Labels:** preflight, corpus, held-out, handshake

As the held-out custodian, I want language-independent corpora calibrated before Rust implementation so that passing results discriminate real behavior from stubs, mutants, leaks, and suite gaps.

**Acceptance criteria:**
- Neutral scenarios encode role, connection state, arbitrary byte chunks, local commands, limits, expected semantic events/frames, close details, errors, and consumed/buffered counts without embedding Java or Rust test-runner semantics.
- A separate RFC-derived opening-handshake corpus covers valid and invalid client/server requests, responses, keys, accept values, versions, methods/statuses, tokenized headers, duplicates, partial input, and configured byte/header limits because Autobahn has no registered category-0 cases at the pin.
- Public development, hidden validation, and sealed final tiers are distinct; candidate execution uses the accepted US-007 Docker sbx workload profile with no network, shared skills, local MCP, secrets, or protected-store mounts, while the protected custodian/classifier remains outside that sandbox and enforces monotonic query/diagnostic budgets, rotation, probing detection, and anti-evasion canaries.
- The preimplementation calibration gate requires the pinned Java oracle to pass 100% of the generated behavior corpus, an inert reference target to fail, seeded language-neutral reference-model mutants to be killed with nonzero inventories, two deterministic generation runs to reconcile exactly, and no protected evidence to rescue a public failure. Full committed-handshake execution, live Rust/stub and Java/Rust binary-mutant execution, sealed-network observation, and candidate rerun reconciliation are deferred to US-020 through US-022, where the required Rust binaries and protected evaluation path exist; they do not block freezing this preimplementation corpus.
- Corpus manifests record exact expected, selected, executed, passed, failed, skipped, filtered, and timed-out counts plus artifact digests and classifications; any mismatch blocks.

### US-006 — Qualify implementation-linked proof and concurrency seams
**Priority:** 1 | **Passes:** true | **Depends on:** US-003, US-004 | **Labels:** preflight, formal, concurrency, claim-scope

As an assurance reviewer, I want consequential proof targets and tool limits fixed before the Rust representation freezes so that formal language cannot outrun shipped-code evidence.

**Acceptance criteria:**
- The production target plan names the shipped mask function and frame-header decoder for mask equation/involution, canonical 7/16/64-bit length encoding, checked arithmetic, allocation caps, control constraints, and role masking; conformance and differential paths must invoke those exact symbols.
- Every selected backend executes through the accepted US-007 Docker sbx workload profile and records the exact sbx CLI/daemon, template, policy, tool, input, and output digests together with method, expected-property inventory, nonzero obligations, known-good and known-bad canaries, bounds, assumptions/provenance, unsupported constructs, trusted base, required artifacts, outcomes, and deterministic replay.
- The accepted finite mask prototype establishes only bounded evidence; unavailable Kani, Loom, or other backends block their own claims and cannot be represented as skips or inferred success.
- Any abstract connection-state model for Connecting/Open/Closing/Closed remains proved-model only; it cannot establish production Rust without a reviewed composition/refinement link, and a proof-only duplicate implementation is prohibited.
- The concurrency plan fixes actions and bounds for command enqueue, inbound frame/close, outbound flush, shutdown, callback delivery, backpressure, fairness, tasks, schedules, and preemptions and classifies Loom-style exploration as systematic testing rather than proof.

### US-007 — Prove sandbox and release-firewall isolation
**Priority:** 1 | **Passes:** true | **Depends on:** US-001, US-004 | **Labels:** preflight, security, sandbox, privacy

As the security owner, I want hostile Java, Rust, container, dependency, and evidence execution isolated so that source or tools cannot reach secrets, protected corpora, signing authority, or public output.

**Acceptance criteria:**
- Static intake executes no repository code. Hostile workloads run only through a pinned Docker sbx shell microVM created with --clone from the authorized repository, an exact template digest, explicit outer CPU and memory limits, and a complete externally imposed per-workload envelope for CPU time, memory, processes, file descriptors, output, workspace/disk, and wall time. The sandbox imports zero host-environment or user/service secrets, exposes no host Docker socket, shared skills, or registered/local MCP server, applies deny-all network policy, and mounts no protected/canonical/signing/production/cross-company path. Receipts separately inventory Docker's fixed internal mcpgateway control token and localhost-only ephemeral clone Git bridge; those platform necessities are not user credentials, MCP registrations, or user-published ports and may appear only as the exact observed one-plus-one control-plane closure. The receipt derives observed enforcement from the external supervisor and binds the sbx CLI and daemon versions, template, policy, platform, input root, output root, resource limits, control-plane closure, start/end state, and cleanup result; a workload-authored boolean or self-applied limit is not proof.
- Maven plugins and annotation processors, Rust build.rs and proc macros, dependencies, language-server imports, Autobahn's legacy Python stack, archives, container entrypoints, proof tools, fuzzers, and mutation runners are enumerated hostile executables and owner-promoted before use under the sole-owner amendment. Promotion is OWNER_ATTESTED_NOT_INDEPENDENT with independent_review_claimed:false and binds the exact executable closure; candidate code cannot authorize its own launch.
- Transactional ingestion rejects traversal, unsafe symlinks, hard links, special files, archive bombs, Unicode/case/normalization collisions, quota breaches, partial promotion, digest mismatch, and dangling or cross-company provenance.
- A protected launcher and classifier outside the candidate repository and sbx trust zone authenticates the current owner-scoped authority, nonce, revocation state, input root, and exact reopened public projection; it recursively classifies and scans every descendant and denies protected cases, expected outputs, raw diagnostics, identifiers, credentials, caches, provenance gaps, or unclassified bytes. Sole ownership is permitted, but the classifier result cannot be represented as independent review.
- Non-Autobahn adversarial good/bad canaries inside sbx prove deny-all egress, secret and protected-store absence, CPU/memory/process/disk/time termination, fail-closed artifact capture, removal with sbx rm, post-removal absence, and zero host/protected leakage, while one owner-promoted benign build and one safe public projection succeed. Canary-local limits establish feasibility only; passing also requires the complete envelope to be imposed outside every hostile workload. These canaries do not rerun Autobahn.

### US-008 — Pre-register controlled Java and Rust resource benchmarks
**Priority:** 1 | **Passes:** true | **Depends on:** US-001, US-002, US-003, US-004 | **Labels:** preflight, performance, statistics, preregistration

As the performance owner, I want workloads, environments, metrics, hypotheses, and statistics frozen before samples or tuning so that resource claims cannot be selected after results are known.

**Acceptance criteria:**
- The preimplementation benchmark plan freezes the black-box TCP comparison boundary, six exact workload-byte generators, endpoint definitions, pair order, fixed sample count, primary macOS 26.4.1 Apple M4 Pro environment, and the required fields for a provenance-distinct dedicated or exclusively reserved Linux x86_64 host. Docker sbx may isolate build/test preparation but must not host measured benchmark samples because microVM overhead would change the declared boundary. This preregistration story may pass once the owner-selected Tier-1 confirmation-host class/image, exact pipeline tool pins, complete binding meter, and fail-closed HOST_BINDING_PENDING state are frozen; instance-specific host observations, future Java/Rust executable digests, and measurement/analyzer identities must bind and make the verifier fully green in US-025 before the first sample. No nonexistent Rust source, executable, measurement, or completed host is fabricated.
- Workloads separately cover opening handshake/clean close, small text echo, fragmented 64 KiB binary echo, ping/pong/close control mix, cap-before-allocation rejection, and bounded concurrent connection/command pressure with fixed rates, concurrency, operations, durations, inputs, and outputs.
- Each workload uses exactly five excluded warmup pairs and exactly 30 measured pairs in deterministic SHA-256-seeded randomized Java/Rust order; extension, replacement, optional stopping, outlier deletion, missing/extra pairs, and aggregate-only decisions are forbidden.
- For every preregistered endpoint, analysis computes all 30 paired natural-log Rust/Java ratios, the arithmetic mean and sample standard deviation, the two-sided 95% Student-t interval with 29 degrees of freedom, and exponentiated bounds. A frozen one-sample log-ratio power model uses alpha 0.025, power at least 0.8, maximum log-ratio SD 0.10, named memory/non-regression alternatives, a 5% reference-drift envelope, background CPU at most 2%, and fail-closed thermal/power/identity rules.
- Peak RSS and steady RSS each require upper 95% CI at most 0.8; CPU time, startup-to-ready, latency p50/p95/p99, allocated bytes, and allocation count each require upper CI at most 1.0; throughput requires lower CI at least 1.0 on every workload. Canonical raw pairs bind the plan, workload, order, environments, tools, future Java/Rust source/executable/adapter digests, and independently rebuilt analyzer; altered summaries, omissions, mismatches, nonfinite values, or raw-versus-summary disagreement are INCONCLUSIVE and blocking.
