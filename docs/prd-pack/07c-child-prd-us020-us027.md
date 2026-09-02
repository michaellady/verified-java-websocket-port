(part 7c of 7) Java-WebSocket child laboratory PRD, child stories US-020 through US-027 — end of the PRD pack.

### US-020 — Close Java and Rust differential divergences
**Priority:** 2 | **Passes:** true | **Depends on:** US-005, US-010, US-011, US-012, US-013, US-014, US-015, US-016, US-017, US-018, US-019 | **Labels:** verification, differential, oracle, parity

As a compatibility reviewer, I want every neutral scenario run against pinned Java and Rust and adjudicated by the oracle hierarchy so that parity is complete without preserving Java defects.

**Acceptance criteria:**
- Every public neutral scenario runs with identical role, initial state, bytes, chunk boundaries, local actions, and limits against the out-of-process Java oracle and Rust core/driver; observations normalize state, semantic frames/events, close details, errors, and consumed/buffered counts.
- RFC 6455 is rank one, in-scope Autobahn is rank two, independent neutral expectations are rank three, Java observation is rank four, and Rust observation is rank five; agreement between Java and Rust cannot override a higher oracle.
- Every mismatch is minimized, reproducible, and appended to the Behavior Delta Ledger as Java quirk, Rust defect, or underspecified behavior with finding/adjudication evidence and no rewritten history.
- All in-scope migration rows and compatibility items have at least one differential vector and zero unresolved mismatch, flake, missing observation, or normalization collision.
- Seeded Java-quirk emulation, Rust semantic defect, event-order, error-class, close-initiator, consumed-byte, and normalization-collision variants are detected.

### US-021 — Close property, fuzz, and runtime evidence
**Priority:** 2 | **Passes:** true | **Depends on:** US-020 | **Labels:** verification, property, fuzz, runtime

As a verification engineer, I want generative and runtime evidence over every shipped protocol seam so that cases beyond fixed examples expose panics, hangs, leaks, invariant violations, and state drift.

**Acceptance criteria:**
- Properties cover encode/decode semantic round trips, mask equation/involution, canonical length forms, chunk-boundary invariance, cap-before-allocation, strict UTF-8, fragmentation transitions, control interleaving, close at-most-once, and deterministic replay with documented generator domains and shrinkers.
- Fuzz targets cover handshake client/server, frame decode, message/UTF-8, fragment/control sequences, close/EOF, and owner-driver command/byte schedules; seeds include RFC vectors, Autobahn failures, Java tests, differentials, mutants, and minimized regressions.
- Each target has a pinned engine/toolchain, dictionary/corpus digest, minimum bounded campaign, timeout/OOM/crash policy, artifact capture, replay command, and exact target manifest; unavailable tooling blocks instead of skipping.
- Runtime checks on both blocking platforms cover debug/release tests, panic freedom, bounded memory/queues, deadlock/hang timeout, race tooling where supported, file-descriptor cleanup, process cleanup, and repeat-flake reconciliation.
- Every discovered failure is minimized and promoted to public regression when safe or retained as protected evidence; zero unresolved crash, hang, panic, leak, flake, or invariant violation remains.

### US-022 — Pass normalized mutation and protected evaluation
**Priority:** 2 | **Passes:** true | **Depends on:** US-005, US-020, US-021 | **Labels:** verification, mutation, held-out, sealed

As the held-out custodian, I want Java PIT, Rust cargo-mutants, hidden, and sealed evidence normalized and independently reviewed so that neither surviving defects nor evaluator leakage can hide behind aggregate scores.

**Acceptance criteria:**
- PIT and cargo-mutants run from promoted tool/dependency graphs against the declared production and test surfaces and normalize killed, survived, not-executed, uncovered, timeout, tool-failure, flaky, equivalent, and technically-unviable dispositions into one signed denominator.
- Eligible mutation score is 100% with zero MISSED; every equivalent or technically unviable classification remains visible in the denominator, has technical evidence, and receives independent explicit review.
- No requirement-bearing Java or Rust test is deleted, weakened, skipped, filtered, or replaced because a mutant or runtime makes it inconvenient; no-stub and test-manifest reconciliation run before and after mutation.
- Hidden and sealed runs use separate identities, filesystems, caches, credentials, signing keys, and workspaces; candidate execution denies network/protected-store APIs, enforces monotonic budgets and anti-evasion, and releases only policy-limited diagnostics.
- Pinned Java passes 100%, empty/stub Rust and planted mutants fail, the candidate passes, all cases reconcile, and zero protected case, output, raw diagnostic, or oracle secret enters public artifacts.

### US-023 — Freeze the complete parity candidate
**Priority:** 2 | **Passes:** true | **Depends on:** US-006, US-007, US-008, US-019, US-020, US-021, US-022 | **Labels:** parity, snapshot, review, quality-gate

As the program owner, I want one immutable parity snapshot after all semantic and assurance gates so that refinement starts from a complete, reviewable candidate rather than a moving implementation.

**Acceptance criteria:**
- Authoritative Java and Rust builds/tests, formatting, Clippy, lint, unsafe prohibition, dependency/license/vulnerability review, no-stub, no-deleted-test, zero-silent-skip, and exact test-manifest reconciliation pass on both blocking platforms.
- In-scope RFC/Autobahn, handshake, differential, property, fuzz, runtime, formal, concurrency, mutation, hidden, and sealed evidence is complete, content-addressed, connected to shipped Rust, within its honest assurance ceiling, and has zero unresolved finding or divergence.
- An immutable language-neutral formal-obligation catalog maps every in-scope obligation separately to exact shipped Java and Rust production symbols and records each side's evidence strength, method, bounds, assumptions, trusted base, tool/input/output digests, refinement link, and counterexample or mutation sensitivity. A canonical machine-readable formal-coverage report and a human-readable coverage-style report expose Java coverage, Rust coverage, paired comparable coverage, production linkage, refinement coverage, bound parity, counterexample sensitivity, and every blocking gap; no weighted aggregate may hide a blocking obligation, and evidence below the obligation's required strength blocks the freeze.
- The exact source, lockfile, tools, corpora, configs, migration map, dossier, compatibility surface, delta ledger, claims, attempts, artifacts, and roots form one immutable candidate DAG with deterministic replay and typed why-blocked status.
- A fresh human review and one declared-final isolated Codex review over the complete candidate find no blocking correctness, security, or acceptance defect; only blocking findings may be remediated and targeted regression plus parent gates run without another full-diff loop.
- The candidate remains internal and non-published; protected data stays separate and no performance, cutover, or CUTOVER_READY claim is made yet.

### US-024 — Refine idiomatic Rust without changing parity
**Priority:** 3 | **Passes:** true | **Depends on:** US-023 | **Labels:** refinement, rust, replay, parity-preservation

As a Rust maintainer, I want a separate refinement phase after parity freeze so that architecture and resource improvements cannot silently redefine behavior or erase accepted evidence.

**Acceptance criteria:**
- Refinement may deepen modules, reduce coupling/allocation/copies, improve ownership, error types, or adapter ergonomics but must preserve the ConnectionCore command/event contract, exclusions, limits, public corpus, Java differential normalization, and every requirement-bearing test.
- Before/after replay proves identical normalized behavior for all public conformance/differential/property/fuzz/runtime cases; hidden/sealed confirmation reruns under custodian control and exact manifests reconcile.
- Formal and concurrency evidence still calls the exact shipped symbols or supplies an independently reviewed equivalence argument and drift test; any disconnected proof blocks.
- No test, mutant, bound, threshold, workload, exclusion, error class, or assurance label is weakened; any intended semantic change enters the append-only delta ledger and reopens every affected gate.
- Formatting, Clippy, tests, unsafe/dependency gates, no-stub/no-deleted-test, mutation, fresh review, and deterministic replay pass for the refined source.

### US-025 — Decide every preregistered resource envelope
**Priority:** 3 | **Passes:** true | **Depends on:** US-008, US-024 | **Labels:** performance, benchmark, independent-confirmation, quality-gate

As the performance owner, I want the refined Rust and retained Java adapters measured on both declared hosts so that each workload independently proves or fails the material-memory and non-regression hypotheses.

**Acceptance criteria:**
- The exact preregistered protocol predates all raw/tuning samples. Immediately before the first sample, it binds the accepted Java and refined Rust source, executable, dependency-lock, thin-TCP adapter, workload, analyzer, measurement-tool, primary-host, and independently assigned Linux-host digests; power, thermal, isolation, cache, process, and drift preconditions pass. Build/test preparation may use the accepted Docker sbx profile, but measured pairs run directly on the preregistered native hosts from promoted artifact digests and record that sbx is outside the measurement boundary.
- Exactly 30 valid measured pairs per workload and host run in the predeclared randomized order after exactly five excluded warmup pairs, with all canonical raw CPU, peak/steady RSS, throughput, startup, latency p50/p95/p99, allocated-byte/count, file-descriptor, and Java-GC observations retained and no extension, replacement, deletion, or optional stopping.
- Every workload independently meets both peak and steady memory upper 95% CI <=0.8; CPU time, startup, each latency quantile, allocated bytes, and allocation count upper CI <=1.0; throughput lower CI >=1.0; and preregistered power >=0.8 on primary and confirmation evidence. Aggregate wins cannot hide any endpoint failure.
- A provenance-distinct reviewer rebuilds the pinned analyzer and recomputes counts, paired log ratios, Student-t intervals, power, drift/noise checks, and every decision from raw records. Missing, extra, duplicated, reordered, nonpositive, nonfinite, identity-mismatched, altered-summary, raw-summary-disagreeing, noisy, underpowered, environment-drifted, or output-mismatched data is INCONCLUSIVE and blocking.
- Profiles and regressions link to shipped symbols without changing the registered workload or accepted protocol behavior; any tuning change reruns the affected parity, mutation, formal, and protected gates.

### US-026 — Rehearse shadow, canary, soak, and Java rollback
**Priority:** 3 | **Passes:** true | **Depends on:** US-023, US-024, US-025 | **Labels:** cutover, shadow, canary, rollback

As the cutover owner, I want a production-shaped but disposable exact-snapshot rehearsal so that operational confidence includes side effects, capacity, automatic abort, reconciliation, soak, and retained Java fallback.

**Acceptance criteria:**
- The CutoverContract binds the exact refined snapshot, RFC 6455 boundary, blocking platforms, production-shaped loopback environment, workload/capacity envelope, observability, side-effect policy, readiness ladder, and Java fallback executable.
- Shadow sends copied inputs to Java and Rust while suppressing or idempotently isolating effects and compares semantic behavior plus resources; mismatch, error, capacity, or stale-evidence thresholds abort automatically without advancing state.
- Canary routes the declared bounded share to Rust, uses idempotency keys where applicable, monitors behavior/resources/errors/backpressure, and exercises an injected mismatch that aborts, routes to Java, and preserves the failed attempt.
- State and effects reconcile after fallback, Java remains executable, rollback is drilled within the declared bound, the fixed workload soaks for the preregistered interval, and no SOURCE_QUALIFIED through CUTOVER_READY state is skipped.
- CUTOVER_READY remains boundary-, snapshot-, platform-, and environment-scoped; this laboratory does not authorize live production deployment or Java removal, which require separate explicit independently attested decisions.

### US-027 — Independently accept and project the complete child snapshot
**Priority:** 3 | **Passes:** true | **Depends on:** US-026 | **Labels:** acceptance, independent-replay, public-projection, closeout

As an independent verifier, I want a clean-checkout replay and safe public projection so that master US-008 receives a provenance-distinct, freshness-aware result rather than self-attestation.

**Acceptance criteria:**
- A provenance-distinct clean environment receives only the immutable verification request, promoted public artifacts, protected evaluator access through its own custodian identity, and replay instructions; it independently rebuilds and reruns every blocking child gate.
- Human, declared-final Codex, and clean-reality receipts bind the same review subject, candidate snapshot, toolchains, policies, corpora, evidence roots, findings, environment, and result; self-review, receipt replay, post-review mutation, or mixed subjects block.
- Independent replay passes authoritative builds/tests, external/differential/property/fuzz/runtime/formal/concurrency/mutation/held-out/performance/cutover gates with exact manifests, zero unexplained finding/divergence/flake/survivor, and honest claim ceilings.
- Independent clean replay recomputes formal coverage from the immutable obligation catalog and provenance-bound receipts, reproduces the canonical report digest and human-readable projection, and rejects missing or disconnected target mappings, post-review mutation, incompatible bounds or assumptions, and overstated evidence strength.
- The release firewall emits only the local safe public projection: snapshot root, scoped claims/badge, scorecard, why-blocked state, deterministic public replay, minimized public counterexamples, freshness/fallback/supersession/revocation status, and no protected cases/outputs/raw diagnostics.
- Every child story and child quality gate is passes:true before the child can return ACCEPTED to master US-008; repository creation, external publication, live deployment, and Java removal remain separately authorized actions.
