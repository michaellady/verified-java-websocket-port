Java-to-Rust port PRD pack, part 6b of 7: PRD metadata sections continued (performanceRequirements through threatModel).

### performanceRequirements

Every laboratory pre-registers a material memory-improvement hypothesis and per-workload non-regression envelopes for peak and steady RSS, working set, bytes and allocations per operation, Java GC time and pauses, startup, CPU, throughput, latency distributions, cache and disk, and any target-relevant energy or cost. Java and Rust run in randomized paired order on the same pinned hardware, OS, CPU/power/NUMA/thermal configuration, allocator, toolchain, workload distributions, warmup and cache states. Raw samples, confidence intervals, effect sizes, equivalence margins, power, outlier policy, and profiles are retained; tuning and confirmation corpora are separate; insufficient power is INCONCLUSIVE; aggregate wins cannot hide regressions; and at least one independent confirmation machine class is required before a cutover-readiness claim.

### integrations

- GitHub — program, four public Rust laboratory repositories, protected verification storage, and mike-skills feature branches/PRs; credentials not provisioned yet
- Standards and neutral suites — Autobahn/RFC 6455, CommonMark specification examples, JSON Schema Test Suite, h2spec/RFCs, and selected independent implementations; exact revisions pinned per child PRD
- Rust verification toolchain — selected per production-code obligation after US-005 rather than hard-coded globally
- Docker sbx — verified macOS microVM profile for hostile build, test, proof, fuzz, mutation, and candidate-agent execution; exact version, template, policy, and receipts bind per child
- Java authority and navigation — pinned project JDK plus Maven or Gradle compiler and tests are authoritative; pinned Eclipse JDT Language Server is the mandatory non-assurance semantic-navigation baseline
- Rust language intelligence — pinned rust-analyzer is the mandatory baseline; pinned Rust Glancer is a mutually exclusive experimental profile with rust-src and auto-update disabled; both emit DeveloperToolRun non-assurance evidence
- Evidence storage and verification — Git-managed schemas, immutable public blob or release storage, separately protected held-out storage, two independent snapshot verifiers, signed action and attestation records, and deterministic replay bundles
- Related-work provenance — pinned reference repositories listed in research/related-skill-repositories.md inform independently re-expressed requirements; THIRD_PARTY_NOTICES.md and a provenance ledger govern any adapted material
- HQ — company board, orchestrator, knowledge/search, workers, secrets/grants, and handoffs; local-only company until separately designated

### securityNotes

Treat all candidate repositories, source text, dependencies, build scripts, annotation processors, proc macros, LSP imports, archives, agent output, and evidence as hostile. Static intake has no build execution or secrets; builds and other hostile workloads run in disposable pinned sandbox profiles with private clones from read-only host source, isolated caches, bounded CPU/memory/process/disk/time, deny-by-default network, zero host-environment or user/service-secret import, no host Docker socket, no shared skills or registered/local MCP servers, and no protected data or signing authority. Runtime-internal control tokens and clone bridges must be explicitly inventoried and cannot carry workload credentials or arbitrary access; Docker sbx's verified macOS profile has exactly one fixed mcpgateway token and one localhost-only clone Git bridge. Docker sbx is not promotion authority or a protected classifier. Every executable input passes signed acquisition, quarantine, qualification, and policy-required promotion with digest, provenance, lock graph, SBOM, vulnerability state, mirror, expiry, rotation, and revocation; sole-owner child amendments stay OWNER_ATTESTED_NOT_INDEPENDENT. Transactional ingestion rejects traversal, unsafe links, special files, archive bombs, normalization collisions, invalid encodings, quota breaches, digest mismatch, partial promotion, dangling edges, and cross-company references. The external release firewall classifies and recursively scans exact reopened public bytes. Protected evaluation enforces privacy and diagnostic budgets, probing and leakage detection, sealed network denial, anti-evasion checks, case rotation, and separate identities, storage, caches, credentials, and trust zone. Project-owned Rust forbids unsafe; dependency unsafe is an enumerated reviewed trusted base.

### rolloutStrategy

Foundation execution ends with independently accepted Laboratory Zero before WebSocket planning. Private skill draft follows accepted WebSocket; isolated CommonMark and contamination-safe baseline-vs-skill forward tests precede public v1; the immutable two-lab GeneralizationDecision may require JSON Schema before publication without mutating dependencies. JSON Schema and HTTP/2 harden later releases. Skill releases use candidate, accepted, published, stale, superseded, and revoked states with last-accepted fallback. Port adoption uses SOURCE_QUALIFIED, SEMANTICALLY_VERIFIED, OPERATIONALLY_VERIFIED, SHADOW_VERIFIED, CANARY_VERIFIED, and CUTOVER_READY, with target-specific holds, automatic abort, Java fallback, state reconciliation, rollback drill, and soak. Every release and snapshot remains pin-able and replayable; latest is never the only runnable version.

### monitoringNotes

Structured events propagate snapshot, claim, evidence, run, attempt, actor, role, tool, corpus, trace, and cutover IDs through every stage. Scheduled jobs rerun conformance, differential, normalized PIT/cargo-mutants, formal canaries and obligation checks, fuzz/property corpora, flakes, security and disclosure, public replay, performance confirmation, staleness, and upstream source/spec/suite/schema/policy/JDK/Rust/LSP/tool/platform canaries. Alerts cover integrity or privacy breach, missing evidence, invalid transition, stale or revoked claim, repeated probe, proof drift, mutation survivor, benchmark regression, failed replay, canary mismatch, capacity breach, and rollback failure. The claim explorer shows why blocked, replay command, lab scorecard, scoped badge, minimized counterexample, freshness, current and fallback snapshots, and runbook link. Weekly review examines all alerts plus held-out rotation age and unresolved Behavior Delta entries.

### assuranceLabels

- observed
- differential
- bounded
- proved-model
- proved-production/refinement

### snapshotStates

- PROPOSED
- QUALIFIED
- CANDIDATE
- ACCEPTED
- PUBLISHED
- BLOCKED
- STALE
- SUPERSEDED
- REVOKED

### productionReadinessStates

- SOURCE_QUALIFIED
- SEMANTICALLY_VERIFIED
- OPERATIONALLY_VERIFIED
- SHADOW_VERIFIED
- CANARY_VERIFIED
- CUTOVER_READY

### errorDispositions

- RETRY
- DEGRADE_NON_ASSURANCE
- BLOCK
- INVALIDATE
- QUARANTINE
- REVOKE

### artifactClassifications

- PUBLIC
- PUBLIC_DERIVED
- INTERNAL
- PROTECTED_HELD_OUT
- QUARANTINED

### languageIntelligenceProfiles

- **javaBaseline:** Pinned Eclipse JDT Language Server for navigation only; authoritative results come from the pinned project JDK plus Maven or Gradle compiler and tests
- **rustBaseline:** Pinned rust-analyzer
- **rustExperimental:** Pinned Rust Glancer, mutually exclusive with rust-analyzer, initially v0.1.1 commit 9502e2a6044bd95731c4de7467b46bd7859af8ac unless freshly reviewed at laboratory kickoff
- **evidenceClass:** DeveloperToolRun
- **assuranceClaims:** []

### delightOpportunities

- Why-blocked legend for every blocked or lowered claim
- Copy-paste deterministic replay command for every public claim
- Cross-laboratory comparison scorecard
- Claim-scoped freshness-aware assurance badge
- Minimized-counterexample view
- Evidence freshness, fallback, supersession, and revocation indicator

### threatModel

- {"threat":"Hostile repository execution and prompt injection","likelihood":"high","impact":"high","mitigation":"Two-stage hardened quarantine with deny-by-default sandboxing and separate protected evaluator"}
- {"threat":"Toolchain or dependency supply-chain compromise","likelihood":"medium","impact":"high","mitigation":"Signed acquisition, quarantine, qualification, promotion, mirroring, expiry, and revocation"}
- {"threat":"Evidence, secret, cross-company, or held-out disclosure","likelihood":"high","impact":"high","mitigation":"Fail-closed artifact classification, recursive release firewall, privacy budgets, and case rotation"}
- {"threat":"Identity impersonation, object access, role conflict, or attestation replay","likelihood":"medium","impact":"high","mitigation":"Short-lived workload identity, object-scoped authorization, signed action envelopes, nonces, and append-only audit"}
- {"threat":"Path traversal, archive bomb, malformed evidence, or resource exhaustion","likelihood":"high","impact":"high","mitigation":"Transactional bounded ingestion gateway with quarantine and atomic promotion"}
