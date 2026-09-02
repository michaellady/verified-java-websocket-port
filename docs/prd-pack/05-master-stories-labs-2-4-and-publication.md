Java-to-Rust port PRD pack, part 5 of 7: full text of the remaining master stories US-010 through US-019 (CommonMark, the publication gate, cross-runtime forward tests, v1 publication, JSON Schema, Netty HTTP/2, and the retrospective). All are passes:false and blocked behind US-008.

### US-010 — Pin CommonMark and generate its isolated child PRD
**Priority:** 3 | **Passes:** false | **Depends on:** US-004, US-005, US-009 | **Labels:** laboratory-2, planning, forward-test | **Worker:** ["architect","dev-qa-tester","reality-checker"]

As the program owner, I want the deterministic-parser laboratory planned by a fresh agent using only the draft skill and task-local target context so that transfer is measured rather than coached.

**Acceptance criteria:**
- The commonmark-java source commit, CommonMark specification version/examples, independent comparator versions, Java/Rust toolchains, supported platforms, and benchmark corpus are immutable pins.
- Fresh source inspection defines a complete standards-core parser and HTML-renderer boundary; extension modules and Java API compatibility are included or excluded explicitly rather than inferred from the initial 9–10K LOC planning estimate.
- A fresh session with no WebSocket conversation context uses only the private draft skill and CommonMark task-local context to create companies/open-source-projects/projects/verified-commonmark-port/prd.json.
- The child PRD covers ambiguity resolution, AST and rendering invariants, exact source locations if in scope, Unicode and line-ending semantics, differential minimization, full spec examples, fuzz/property/mutation/held-out evidence, production-code proof seams, pre-registered resource performance, semantic-ID migration map, Port Seam Dossier, Behavior Delta Ledger, retained Java oracle, consumer cutover and rollback rehearsal, parity, and refinement.
- The child PRD inherits the Laboratory Zero security, evidence, failure, staleness, JDT LS, rust-analyzer, mutually exclusive Glancer, public/hidden/sealed corpus, independent replay, publication-firewall, and hostile-workload isolation capabilities without target-specific weakening; it uses the pinned Docker sbx profile where supported or blocks until an equivalent runtime is qualified.
- Every manual rescue, unclear instruction, missing template, WebSocket-specific assumption, and runtime discrepancy is captured as forward-test evidence rather than silently fixed before scoring.
- An independent plan review verifies the child stories are one-session vertical slices and pauses US-011 until the child project is fully complete.

**E2E tests:**
- Given the pinned CommonMark manifest and a clean runtime context, when the private skill drives deep planning, then the resulting child PRD validates, declares a complete observable boundary, maps every in-scope spec category to evidence, and records all interventions made outside the skill.

**Files:** laboratories/commonmark/manifest.json, companies/open-source-projects/projects/verified-commonmark-port/prd.json, companies/open-source-projects/projects/verified-commonmark-port/README.md, forward-tests/commonmark-planning.json

**Notes:** A contaminated, non-scoring exploratory preflight on 2026-08-28 pinned commonmark-java 0.30.0 at commit 64037cf982f2b12a4a2fa1c5a75c6d3f4ab979bf and tree b5fc1ec442b4a7bcb2352925b57d4d57b128427e. The clean detached checkout contains 135 core production Java files / 11,550 lines, 221 all-module production files / 16,437 lines, and 300 tracked Java files / 27,193 lines; this invalidates the original 9–10K whole-target estimate. On Maven 3.9.16 and OpenJDK 17.0.19, the real core reactor path passed with 2,253 tests, zero failures/errors, one skip, and all 652 CommonMark 0.31.2 examples passing the explicit Markdown-renderer loop; the standard and CRLF parameterized parser suites also executed despite misleading collapsed per-class XML totals. The proposed first boundary is core parser + normalized mutable AST + exact source spans + HTML renderer option matrix, with extensions, Java API/binary compatibility, Markdown/text renderers, and extension SPIs explicitly deferred to named later boundaries. The exploratory report is workspace/reports/port-java-to-rust-forward-tests/commonmark-contaminated-preflight.md. Because the producing session had WebSocket and prior CommonMark context, it does not satisfy the fresh-session criterion, does not create the child PRD, earns no forward-test score, and leaves US-010 passes:false. [The 2026-08-28 denominator correction paragraph shared by every story is omitted here; it is reproduced in part 2.]

### US-011 — Independently accept CommonMark and measure skill transfer
**Priority:** 3 | **Passes:** false | **Depends on:** US-010 | **Labels:** laboratory-2, acceptance, forward-test, external-gate | **Worker:** ["code-reviewer","codex-reviewer","reality-checker","security-scanner","performance-benchmarker"]

As an independent reviewer, I want the second complete laboratory audited with the same claim discipline and its skill interventions scored so that publication depends on demonstrated transfer.

**Acceptance criteria:**
- Every CommonMark child story and gate passes before the audit starts; otherwise this story records the external block and makes no acceptance decision.
- All in-scope specification examples and neutral comparisons pass; differential mismatches are zero or explicitly resolved by the oracle policy; AST/render properties, fuzzing, runtime checks, held-out cases, implementation-linked formal checks, and manifest reconciliation pass.
- Project-owned Rust has no unsafe code; eligible mutation score is 100% with independently classified equivalents/unviables; security review and zero-flake requirements pass.
- Pre-registered paired workloads demonstrate a material memory improvement and meet every per-workload CPU, throughput, startup, latency, allocation, and resource non-regression envelope on the primary environment plus an independent confirmation environment, or the milestone remains blocked with an analyzed regression or INCONCLUSIVE result.
- The CommonMark consumer-integration rehearsal proves input, output, error, Unicode, file and stream, state, operational, rollback, and observability behavior at the declared replacement boundary and records the highest supported production-readiness state without implying Java API parity unless explicitly in scope.
- The forward-test score reports how many required decisions the skill elicited, missed, misstated, or required manual rescue for, separated by portable-core, runtime-adapter, and CommonMark-profile failures.
- Every reusable correction is proposed against the skill and replayed against the frozen WebSocket acceptance fixtures before being accepted.
- Two fresh adversarial reviewers confirm the CommonMark assurance case and the no-regression replay evidence.

**E2E tests:**
- Given clean checkouts of both accepted laboratories and the revised draft skill, when independent verification reruns the pinned evidence and cross-lab regression fixtures, then both manifests pass with zero skipped cases, zero unexplained mismatches, zero missed eligible mutants, and no weakened historical claim.

**Files:** laboratories/commonmark/acceptance.md, laboratories/commonmark/evidence-manifest.json, forward-tests/commonmark-completion.json, port-ledger.jsonl, skill-revisions.jsonl

**Notes:** External gate: do not execute until the CommonMark child project is complete.

### US-012 — Decide whether two contrasting laboratories justify public v1
**Priority:** 3 | **Passes:** false | **Depends on:** US-008, US-011 | **Labels:** investigation, publication-gate, pre-flight | **Worker:** ["reality-checker","architect","code-reviewer","codex-reviewer"]

As the program owner, I want the two-laboratory generalization premise tested against predefined transfer criteria so that publication is not driven by schedule or sunk cost.

**Acceptance criteria:**
- Before examining the conclusion, the report defines minimum diversity and transfer criteria across oracle strength, concurrency, parsing, state, recursion, error behavior, formal seam, platform variance, and runtime portability.
- WebSocket and CommonMark decisions are mapped into portable, profile-specific, target-specific, contradicted, and still-untested categories with evidence IDs.
- The report explicitly analyzes missing coverage from recursive declarative evaluation and multiplexed flow-control state that the queued JSON Schema and HTTP/2 laboratories would add.
- An independent reviewer attempts to construct at least three plausible Java projects for which the draft skill would make a materially wrong decision and records whether existing classification gates catch them.
- The immutable GeneralizationDecision outcome is PUBLISH_V1, REQUIRE_LAB_3, or REDESIGN. REQUIRE_LAB_3 causes the policy engine to block publication until an accepted US-016 snapshot exists without mutating story dependencies; REDESIGN blocks US-013 and points to the smallest failed preflight.
- The decision records policy version, complete input snapshot, reviewer identities, role-separation proof, counterexamples, decision rationale, affected claims, and valid next transitions in metadata.decisions and the skill revision ledger; invalid transition or dependency mutation is rejected.

**E2E tests:**
- Given the frozen two-laboratory evidence and adversarial counterexamples, when the generalization rubric is applied by two independent reviewers, then they reach the same publication outcome or the disagreement is classified and publication remains blocked.

**Files:** research/two-lab-generalization-gate.md, skill-revisions.jsonl

**Notes:** Resolves premise challenge 3. The default rollout expects PUBLISH_V1, but the evidence—not the prior preference—controls this gate. US-013 and US-014 must query the accepted decision artifact rather than rewrite their dependsOn arrays.

### US-013 — Run protected cross-runtime forward tests of the release candidate
**Priority:** 3 | **Passes:** false | **Depends on:** US-003, US-006, US-011, US-012 | **Labels:** skill, held-out, cross-runtime, publication-gate | **Worker:** ["dev-qa-tester","reality-checker","code-reviewer","codex-reviewer"]

As a prospective user, I want fresh Claude Code and Codex agents to follow the candidate skill on unseen Java-to-Rust tasks so that runtime portability and procedural compliance are demonstrated independently.

**Acceptance criteria:**
- The held-out lane selects materially different tasks not used to author the skill, records their provenance and oracle strength, and prevents both executing agents from seeing cases, expected outputs, prior transcripts, or laboratory-specific rescue notes.
- Fresh Claude Code and Codex sessions use the same version-pinned portable skill core with only documented runtime adapters and target-local context. On the verified macOS lane each agent runs in a pinned Docker sbx microVM clone with no shared skill store, registered/local MCP server, host-environment or user/service-secret import, protected mounts, or effective network egress; the skill is supplied as a content-pinned task input rather than a shared host capability. Docker's fixed internal mcpgateway control token and localhost clone Git bridge are separately inventoried and cannot carry workload credentials, MCP registrations, or arbitrary ports.
- Each run is bound to an immutable Agent Run Contract and scored on provenance handling, Java intake, semantic-ID mapping, Port Seam Dossier, Behavior Delta Ledger, cutover-boundary definition, migration-mode choice, source inventory, oracle hierarchy, semantic-gap detection, formal-seam discipline, LSP non-assurance treatment, test-execution reconciliation, resource-performance and rollback design, claim accuracy, fail-closed behavior, and artifact validity.
- Both runtimes satisfy all mandatory steps with zero undeclared manual interventions; refusal, empty or malformed output, hallucinated reference, unsupported capability, unauthorized tool use, context leakage, incomplete run, or intervention invalidates the attempt, remains visible, and becomes a skill defect followed by a revised-skill clean rerun.
- The skill is evaluated on contamination-safe projects in isolated translation-only and skill-assisted arms with public development, hidden validation, and sealed final corpora; candidate agents run inside the qualified sandbox, while case selection, expected outputs, grading, privacy budgets, and protected classification remain in a separate trust zone. Sealed runs deny network access and detect source execution, wrappers, JVM, JNI, FFI, source-binary reuse, test discovery, and other evasion, and the report publishes measured uplift and negative results.
- The revised skill is replayed against WebSocket and CommonMark frozen fixtures after every correction, and historical assurance claims remain unchanged.
- Independent reviewers approve the cross-runtime report and US-006's premise is marked resolved only after these release-candidate runs pass.

**E2E tests:**
- Given two unseen fixtures and isolated fresh runtime sessions, when the release-candidate skill executes, then both runtimes produce schema-valid complete preflight and evidence bundles, correctly refuse any deliberately under-specified task, and pass the protected evaluator without case leakage.

**Files:** forward-tests/release-candidate/, reports/cross-runtime-release-candidate.md, skill-revisions.jsonl

**Notes:** If US-012 requires laboratory 3, add US-016 to this story's dependencies before execution.

### US-014 — Publish port-java-to-rust v1 to mike-skills
**Priority:** 4 | **Passes:** false | **Depends on:** US-013 | **Labels:** skill, publication, v1 | **Worker:** ["knowledge-curator","security-scanner","code-reviewer","codex-reviewer"]

As an open-source maintainer, I want the independently validated skill published with precise assurance language and reproducible examples so that others can use it without inheriting overstated claims.

**Acceptance criteria:**
- The publication candidate passes the mike-skills and skill-creator validation workflows in both Claude Code and Codex and contains no company-private path, protected test, credential, private transcript, or unpublished repository reference.
- Documentation explains supported migration modes, Java intake, semantic-ID migration maps, Port Seam Dossiers, Behavior Delta Ledgers, cutover contracts and readiness ladder, oracle-strength profiles, claim labels, formal-method limits, evidence schemas, JDT LS and Rust LSP non-assurance profiles, resource-performance protocol, fail-closed gates, first-party unsafe policy, rollback, and how to adapt when no neutral language-independent suite exists.
- WebSocket and CommonMark case studies link immutable source, skill, port, model, evidence, and review revisions and clearly distinguish model claims, Java observations, Rust proofs/checks, and end-to-end composition claims.
- The release notes list known limitations, untested project classes, host-adapter differences, trusted-computing-base assumptions, and the queued JSON Schema/HTTP2 hardening plan.
- The fail-closed release firewall recursively scans the exact public derivative root for secrets, identifiers, absolute paths, prompt transcripts, protected-case fingerprints, embedded content, license restrictions, and cross-company references; redaction creates a new linked digest and the independent release attestor approves the exact public bytes.
- A signed or content-addressed release tag is created only after independent review and all publication policy gates pass; the previous private tag remains pin-able for rollback and revocation never rewrites historical evidence.
- The public claim explorer provides why-blocked explanations, one copy-paste replay command, a laboratory comparison scorecard, claim-scoped and freshness-aware assurance badges, minimized counterexamples, evidence freshness and revocation status, and no badge stronger than its Program Snapshot and cutover boundary.
- A clean installation and miniature port smoke test succeeds in both supported runtimes from the public artifact, and an independent verifier reconstructs the public snapshot root without access to protected outputs.

**E2E tests:**
- Given a clean machine or isolated environment for each runtime, when port-java-to-rust v1 is installed from the published mike-skills tag and run on the public miniature fixture, then it completes the expected preflight/evidence workflow with no local HQ dependency or undocumented setup.

**Files:** mike-skills/skills/port-java-to-rust/, releases/v1-evidence.json, reports/v1-publication-review.md

**Notes:** Publication is conditional on US-012. Use a feature branch and PR in mike-skills; do not publish directly from HQ root.

### US-015 — Pin JSON Schema and generate its just-in-time child PRD
**Priority:** 5 | **Passes:** false | **Depends on:** US-011 | **Labels:** laboratory-3, planning, hardening | **Worker:** ["architect","dev-qa-tester","security-scanner","performance-benchmarker"]

As the program owner, I want a recursive declarative-evaluator laboratory deeply planned from its current pinned sources so that the published method is tested against references, annotations, and diagnostic semantics.

**Acceptance criteria:**
- The networknt/json-schema-validator source, one explicit JSON Schema draft/profile, official test-suite revision, Java/Rust toolchains, supported platforms, comparator policy, and benchmark corpus are immutable pins.
- Fresh source inspection chooses and measures a complete semantic boundary near the current 18–22K LOC estimate; vocabulary support, reference resolution, formats, annotations, diagnostics, remote retrieval, and optional integrations are each explicitly in or out.
- The current public or candidate skill, with only task-local context, generates companies/open-source-projects/projects/verified-json-schema-port/prd.json in a fresh session.
- The child PRD addresses recursive evaluation, cycles, reference identity, numeric/string/Unicode edge cases, schema/resource resolution, output/error stability, official tests, differential/metamorphic/fuzz/mutation/held-out evidence, production-code proof seams, pre-registered resource performance, semantic-ID migration map, Port Seam Dossier, Behavior Delta Ledger, retained Java oracle, consumer cutover and rollback rehearsal, parity, and refinement.
- The child PRD inherits the Laboratory Zero security, evidence, failure, staleness, JDT LS, rust-analyzer, mutually exclusive Glancer, public/hidden/sealed corpus, independent replay, publication-firewall, and hostile-workload isolation capabilities without target-specific weakening; it uses the pinned Docker sbx profile where supported or blocks until an equivalent runtime is qualified.
- An independent plan review verifies honest completeness, one-session vertical stories, no network nondeterminism hidden inside the semantic core, and no reuse of expected held-out behavior.
- The master pauses US-016 until the child project and its release soak are complete.

**E2E tests:**
- Given the pinned JSON Schema manifest and a fresh skill-driven planning session, when the child PRD is validated, then every official suite group and in-scope vocabulary maps to implementation and evidence stories, and every excluded behavior is machine-readable.

**Files:** laboratories/json-schema/manifest.json, companies/open-source-projects/projects/verified-json-schema-port/prd.json, companies/open-source-projects/projects/verified-json-schema-port/README.md, forward-tests/json-schema-planning.json

**Notes:** Normally follows v1 publication, but US-012 may promote it into the v1 publication gate.

### US-016 — Accept JSON Schema and harden the skill
**Priority:** 5 | **Passes:** false | **Depends on:** US-015 | **Labels:** laboratory-3, acceptance, hardening, external-gate | **Worker:** ["code-reviewer","codex-reviewer","reality-checker","security-scanner","performance-benchmarker"]

As an independent reviewer, I want the third laboratory audited and its transfer failures replayed across earlier ports so that recursive evaluation strengthens rather than destabilizes the method.

**Acceptance criteria:**
- Every JSON Schema child story and release gate passes before this audit begins; otherwise the story records the external block.
- All in-scope official tests, declared differential/metamorphic properties, fuzz/runtime/formal/held-out checks, test-manifest reconciliation, first-party unsafe prohibition, zero-flake, 100% normalized eligible mutation, security, pre-registered material-memory and per-workload performance gates, and production-shaped consumer cutover and rollback rehearsal pass.
- Every skill change derived from the laboratory is classified as portable, oracle-profile, declarative-evaluator profile, or target-specific and is replayed against frozen WebSocket and CommonMark evidence.
- The audit identifies whether reference/cycle semantics changed the evidence schema or assurance taxonomy and migrates historical artifacts without silently rewriting prior results.
- Fresh Claude Code and Codex spot checks confirm the revised skill still follows the portable runtime contract.
- A versioned post-v1 release or v1-blocking candidate is approved according to the US-012 decision.

**E2E tests:**
- Given all three frozen laboratory fixtures and the revised skill, when the cross-lab regression and schema-migration suites run, then every prior and new evidence manifest validates, historical results remain reproducible, and no accepted claim is weakened.

**Files:** laboratories/json-schema/acceptance.md, laboratories/json-schema/evidence-manifest.json, forward-tests/json-schema-completion.json, skill-revisions.jsonl

**Notes:** External gate: do not execute until the JSON Schema child project is complete.

### US-017 — Pin Netty HTTP/2 and generate its just-in-time child PRD
**Priority:** 6 | **Passes:** false | **Depends on:** US-016 | **Labels:** laboratory-4, planning, hardening | **Worker:** ["architect","dev-qa-tester","security-scanner","performance-benchmarker"]

As the program owner, I want the hardest multiplexed-protocol laboratory scoped and planned honestly so that the method is tested against nested state, flow control, HPACK, and teardown races without claiming to port all Netty.

**Acceptance criteria:**
- The Netty source commit, exact codec-http2 package boundary, RFC versions, h2spec version/profile, interop peers, Java/Rust toolchains, supported platforms, and benchmark/stress environment are immutable pins.
- Fresh source inspection measures and declares a complete HTTP/2 codec-subsystem boundary near the current 25–33K LOC estimate; all dependencies on other Netty modules are replaced, wrapped, or excluded explicitly.
- The current skill and task-local context generate companies/open-source-projects/projects/verified-netty-http2-port/prd.json in a fresh isolated session.
- The child PRD covers connection preface/settings, frame codec, HPACK, stream lifecycle, dependency/priority behavior if in scope, connection and stream flow control, errors, GOAWAY/reset, concurrency and teardown, h2spec/interop/differential/fuzz/formal/schedule/mutation/held-out evidence, resource limits, pre-registered resource performance, semantic-ID migration map, Port Seam Dossier, Behavior Delta Ledger, retained Java oracle, shadow/canary cutover and rollback rehearsal, parity, and refinement.
- The child PRD inherits the Laboratory Zero security, evidence, failure, staleness, JDT LS, rust-analyzer, mutually exclusive Glancer, public/hidden/sealed corpus, independent replay, publication-firewall, and hostile-workload isolation capabilities without target-specific weakening; it uses the pinned Docker sbx profile where supported or blocks until an equivalent runtime is qualified.
- The formal plan separates connection and stream models, identifies their composition boundary, and refuses to claim whole-system proof from component models without a checked refinement/composition argument.
- An independent plan review confirms the project is named and documented as a complete HTTP/2 codec-subsystem port, not a Netty port, and pauses US-018 until all child gates pass.

**E2E tests:**
- Given the pinned HTTP/2 manifest and generated child PRD, when plan validation runs, then every in-scope frame, state transition, flow-control invariant, error path, and teardown behavior maps to a vertical story plus independent evidence, with no undeclared Netty dependency.

**Files:** laboratories/netty-http2/manifest.json, companies/open-source-projects/projects/verified-netty-http2-port/prd.json, companies/open-source-projects/projects/verified-netty-http2-port/README.md, forward-tests/netty-http2-planning.json

**Notes:** Estimated narrow protocol core: 18,436 physical Java LOC; complete codec subsystem likely 25–33K; full module: 32,672. Recount from the pinned source.

### US-018 — Accept HTTP/2 and publish the hardened skill release
**Priority:** 6 | **Passes:** false | **Depends on:** US-017 | **Labels:** laboratory-4, acceptance, hardening, publication, external-gate | **Worker:** ["code-reviewer","codex-reviewer","reality-checker","security-scanner","performance-benchmarker"]

As an independent reviewer, I want the hardest laboratory audited and the four-lab method released only after composition, concurrency, and performance evidence survive adversarial review.

**Acceptance criteria:**
- Every HTTP/2 child story and release gate passes before this audit begins; otherwise the story records the external block.
- All in-scope h2spec and interop cases, differential traces, fuzz/runtime/formal/schedule/held-out checks, manifest reconciliation, first-party unsafe prohibition, zero flakes, 100% normalized eligible mutation, security, resource, and pre-registered material-memory and per-workload performance gates pass.
- Connection, stream, HPACK, and flow-control proof claims identify their exact production-code link and composition assumptions; no component result is promoted to an unproven whole-subsystem claim.
- Adversarial teardown, cancellation, backpressure, peer misbehavior, resource exhaustion, and platform runs have zero unexplained failure or hang.
- A production-shaped HTTP/2 shadow and canary rehearsal validates side-effect handling, protocol behavior, state and flow-control compatibility, observability, capacity, automatic abort, Java fallback, reconciliation, and rollback before any CUTOVER_REHEARSED claim is accepted.
- Every skill/schema change replays successfully across the frozen WebSocket, CommonMark, and JSON Schema fixtures and preserves historical evidence versions.
- A fresh held-out task in both Claude Code and Codex passes before the hardened mike-skills release is tagged, documented, and made the recommended version.

**E2E tests:**
- Given all four accepted laboratories and the hardened release candidate, when independent clean-room reruns execute the full cross-lab regression, platform, and held-out manifests, then every claim validates at its declared assurance level and all historical skill tags remain reproducible.

**Files:** laboratories/netty-http2/acceptance.md, laboratories/netty-http2/evidence-manifest.json, reports/four-lab-assurance-review.md, releases/hardened-evidence.json, skill-revisions.jsonl

**Notes:** External gate: do not execute until the HTTP/2 child project is complete and soaked.

### US-019 — Run the four-laboratory retrospective and freeze the reproducible method
**Priority:** 7 | **Passes:** false | **Depends on:** US-018 | **Labels:** retrospective, documentation, maintenance | **Worker:** ["knowledge-curator","reality-checker","architect"]

As the maintainer of the published skill, I want the full program retrospectively audited so that reusable lessons, rejected approaches, calibration data, and future maintenance obligations remain durable.

**Acceptance criteria:**
- The retrospective compares planned versus actual scope, Java and Rust LOC, calendar time, compute/model cost, human review effort, defects by semantic-gap category, mutation survivors, flaky evidence, memory and performance changes, intake discoveries, cutover and rollback results, security failures, and release-tail effort for all four laboratories. Formal-method yield is compared separately through per-language obligation coverage, paired comparable coverage, production linkage, refinement coverage, bound and assumption differences, counterexample sensitivity, and blocking gaps; no single weighted score may conceal a failed obligation.
- Every skill rule maps to repeated evidence or an explicit safety rationale; one-off target advice is moved into a profile/case study and obsolete rules are deprecated with migration notes.
- Rejected approaches—including full formalization of arbitrary Java, disconnected proof-only implementations, silent test skipping, placeholder-driven compilation, all-Netty scope, and unconditional big-bang migration—are recorded with evidence.
- A maintenance runbook defines upstream source, suite, schema, policy, JDK, Rust toolchain, JDT LS, rust-analyzer, Glancer, proof-tool, dependency, and platform canaries; signed baseline promotion; skill regression cadence; held-out rotation; staleness propagation; disclosure and key incidents; claim suspension and revocation; and fallback to the last accepted snapshot.
- The final skill decision rule defaults Java comprehension to JDT LS and Rust comprehension to rust-analyzer, offers Glancer only as an evidence-backed mutually exclusive experimental profile, documents all measured keep or fallback outcomes, and never frames language tooling as formal verification.
- Long-term governance defines semantic versions and compatibility windows for schemas, policy, validators, evidence, badges, and skills; independent promotion and release quorum, deprecation and migration, vulnerability response, historical replay, archive retention, and the conditions for retiring a claim or laboratory.
- The company knowledge base receives only stable reusable findings, public docs match the shipped artifacts, and every repository README points to the current claim/evidence index.
- An independent reviewer can reproduce the program index and verify every released skill version from immutable sources without access to private expected outputs.

**E2E tests:**
- Given a clean environment and the public reproducibility index, when an independent reviewer follows the runbook, then all public manifests and releases validate, protected evidence is referenced without disclosure, and every normative skill instruction resolves to supporting evidence or an explicit safety rationale.

**Files:** RETROSPECTIVE.md, docs/maintenance-runbook.md, docs/evidence-index.md, port-ledger.jsonl, skill-revisions.jsonl

**Notes:** Use /retro, /learn, and /document-release during execution; do not write stable company knowledge until findings survive the four-lab review.
