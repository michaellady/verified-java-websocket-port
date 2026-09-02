Java-to-Rust port PRD pack from HQ, part 1 of 6: program structure, topology, and the master story index with current status. Parts 2 to 6 follow with the full text of every story, the PRD metadata sections, and the Java-WebSocket child lab PRD.

# verified-java-to-rust-port — PRD pack (copied from HQ)

Snapshot taken 2026-09-01 from HQ. Canonical location: the enterprise-vibe-code company's projects folder, project `verified-java-to-rust-port` (prd.json last updated 2026-08-29T12:22:36Z).
Branch: `feature/verified-java-to-rust-port`. Base branch: `main`. Company: enterprise-vibe-code.
Note: an older duplicate of this project folder also lives under the open-source-projects company (last changed 2026-08-26); the enterprise-vibe-code copy is the one hq-sync keeps current.

## 1. What the program is

**Description:** Develop and publish a portable Java-to-Rust porting skill by deriving it from independently audited, maximally verified ports in four contrasting laboratories.

**Goal:** Codify a repeatable, evidence-backed Java-to-Rust porting method and publish it as a portable Claude Code and Codex skill after it succeeds on complete, materially different open-source laboratories.

## 2. PRD structure (prd.json)

Top-level keys:

| Key | Type | Notes |
|---|---|---|
| name | string | verified-java-to-rust-port |
| description | string | one-line program description |
| branchName | string | feature/verified-java-to-rust-port |
| userStories | array (24) | the master stories, listed in Section 4 |
| metadata | object (39 keys) | goal, success criteria, review policy, quality gates, assurance semantics, threat model, decisions, execution notes, laboratories |

Each story has: id, title, description, priority, dependsOn, acceptanceCriteria, e2eTests, files, labels, worker_preference, model_hint, notes, passes.

Metadata sections (all reproduced in Section 6): goal, successCriteria, reviewPolicy, qualityGates, baseBranch, relatedWorkers, knowledge, audiences, currentSolution, nonGoals, dataModel, authModel, architectureNotes, sandboxRuntimeProfile, performanceRequirements, integrations, securityNotes, rolloutStrategy, monitoringNotes, assuranceLabels, snapshotStates, productionReadinessStates, errorDispositions, artifactClassifications, languageIntelligenceProfiles, delightOpportunities, threatModel, openQuestions, decisions, postImplementation, executionNotes, laboratories.

## 3. Program topology

Repositories (from program-registry.json):

| Id | Repo | Kind | Status | Visibility | License |
|---|---|---|---|---|---|
| program-evidence | michaellady/verified-java-to-rust | program | planned | PUBLIC | Apache-2.0 |
| lab-java-websocket | michaellady/verified-java-websocket-port | laboratory | existing | PUBLIC | Apache-2.0 |
| lab-commonmark | michaellady/verified-commonmark-port | laboratory | planned | PUBLIC | Apache-2.0 |
| lab-json-schema | michaellady/verified-json-schema-port | laboratory | planned | PUBLIC | Apache-2.0 |
| lab-netty-http2 | michaellady/verified-netty-http2-port | laboratory | planned | PUBLIC | Apache-2.0 |
| protected-held-out | michaellady/verified-java-to-rust-held-out | held-out | planned | PRIVATE | PROPRIETARY |
| skill-publication | michaellady/mike-skills | publication | existing | PUBLIC | UNLICENSED (publication blocked until a license is adopted) |

Source pins:

- **java-websocket-v1.6.0**: https://github.com/TooTallNate/Java-WebSocket @ da3cf2a777aed862f2f5b5cf060cae7969958667 (v1.6.0), license MIT, Java: Eclipse Temurin 17; source release 7 plus Java 9 multi-release classes, build: Apache Maven 3.9.11
- **commonmark-java-0.30.0**: https://github.com/commonmark/commonmark-java @ 64037cf982f2b12a4a2fa1c5a75c6d3f4ab979bf (commonmark-parent-0.30.0), license BSD-2-Clause, Java: Zulu OpenJDK 11, build: Apache Maven Wrapper 3.6.3
- **networknt-json-schema-validator-2.0.7**: https://github.com/networknt/json-schema-validator @ f8c76599c0bda42a72ff1c905e8d99ab4fcf59db (2.0.7), license Apache-2.0, Java: Eclipse Temurin 17, build: Apache Maven 3.9.11
- **netty-4.2.15-http2**: https://github.com/netty/netty @ a41f7b289ce1d697c50846f3ade3983e22b2ed40 (netty-4.2.15.Final), license Apache-2.0, Java: OpenJDK 11 build profile; Java 8 bytecode target, build: Apache Maven Wrapper 3.9.11

Laboratory sequence (Laboratory Zero has passed; source labs run in this order):

| Order | Java source | Planned Java LOC | Independent oracle | Child project |
|---:|---|---:|---|---|
| 0 | Laboratory Zero (miniature synthetic lab) | — | built-in | laboratories/lab-zero/ in the parent |
| 1 | TooTallNate/Java-WebSocket | 6–7K | RFC 6455 and Autobahn | verified-java-websocket-port |
| 2 | commonmark/commonmark-java | 9–10K | CommonMark spec examples and independent implementations | verified-commonmark-port |
| 3 | networknt/json-schema-validator | 18–22K | JSON Schema Test Suite and pinned drafts | verified-json-schema-port |
| 4 | netty/netty codec-http2 | 25–33K | h2spec, HTTP/2 RFCs, and interop | verified-netty-http2-port |

Project folder layout (parent):

```
README.md                 full PRD rendered as markdown (also has per-story status write-ups)
prd.json                  the PRD (this pack is derived from it)
brainstorm.md             pre-PRD brainstorm
program-registry.json     repositories + source pins
provenance-ledger.jsonl   related-work provenance ledger
references.md, THIRD_PARTY_NOTICES.md
cmd/                      Go CLIs: foundationctl, labzero, labzero-assurance, labzero-benchmark, labzero-formal, lspe2e, runtimefixture, runtimetrial
foundation/               Go: evidence, intake, provenance, proof seams, runtime contract, forward test, validators
protocol/                 Go: assurance protocol runner (canonical transport, gateway, policy, promotion, runner)
internal/                 lspharness, runtimeoutput, runtimeprovenance, testsupport
schemas/                  JSON schemas: evidence model 1.0/1.1, java-intake, port-seam-dossier, compatibility-surface, behavior-delta-ledger, cutover-contract, developer-tool-run, forward-test, language-intelligence-profile, lsp-execution-evidence, navigation-corpus, profile-switching, evolution
docs/                     assurance-levels, error-registry, held-out-oracle, laboratory-zero-report, production-readiness, related-work-adoption, security-boundaries
policies/                 related-work-provenance.json, toolchain-promotion.json, amendments/
fixtures/                 adversarial, cutover, evidence, held-out, intake, lsp, policy, provenance, skill-runtime, traces
laboratories/             lab-zero/, java-websocket/ (manifest.json)
templates/child-prd/      frozen laboratory-template.json inherited by every child lab PRD
profiles/lsp/             pinned JDT LS / rust-analyzer / Rust Glancer qualification evidence
research/                 research briefs, per-story TDD evidence, landscape scans
mapping-evaluations/, models/, proofs/, validators/, journal/
```

## 4. Master story index

Status column is the local PRD passes flag (the live work-mesh board was not reachable from this machine).

| ID | Pri | Local passes | Depends on | Title |
|---|---:|---|---|---|
| US-001 | 1 | done | — | Establish the multi-repository program and provenance boundary |
| US-002 | 1 | done | US-001 | Define the evidence model and claim-scoped assurance levels |
| US-003 | 1 | done | US-001, US-002 | Create the independent and held-out verification lane |
| US-004 | 1 | done | US-002 | Test whether useful formal contracts can be derived without proving Java |
| US-005 | 1 | done | US-002 | Validate a consequential shipped-Rust proof seam for every laboratory |
| US-006 | 1 | done | US-002 | Prove the portable Claude Code and Codex skill contract |
| US-024 | 1 | done | US-001 | Record related-work provenance and license-safe adoption boundaries |
| US-020 | 1 | done | US-001, US-002 | Define Java intake, compatibility, and production-cutover contracts |
| US-021 | 1 | done | US-001, US-002 | Qualify the Java and Rust language-intelligence profiles |
| US-022 | 1 | done | US-002, US-003, US-004, US-005, US-006, US-024, US-020, US-021 | Build and adversarially validate the assurance protocol runner |
| US-023 | 1 | done | US-003, US-004, US-005, US-006, US-024, US-020, US-021, US-022 | Run Laboratory Zero through the complete evidence and cutover lifecycle |
| US-007 | 2 | done | US-001, US-003, US-004, US-005, US-023 | Pin Java-WebSocket and generate its just-in-time child PRD |
| US-008 | 2 | open | US-007 | Independently accept the completed Java-WebSocket laboratory |
| US-009 | 2 | open | US-006, US-008 | Extract the private port-java-to-rust draft skill |
| US-010 | 3 | open | US-004, US-005, US-009 | Pin CommonMark and generate its isolated child PRD |
| US-011 | 3 | open | US-010 | Independently accept CommonMark and measure skill transfer |
| US-012 | 3 | open | US-008, US-011 | Decide whether two contrasting laboratories justify public v1 |
| US-013 | 3 | open | US-003, US-006, US-011, US-012 | Run protected cross-runtime forward tests of the release candidate |
| US-014 | 4 | open | US-013 | Publish port-java-to-rust v1 to mike-skills |
| US-015 | 5 | open | US-011 | Pin JSON Schema and generate its just-in-time child PRD |
| US-016 | 5 | open | US-015 | Accept JSON Schema and harden the skill |
| US-017 | 6 | open | US-016 | Pin Netty HTTP/2 and generate its just-in-time child PRD |
| US-018 | 6 | open | US-017 | Accept HTTP/2 and publish the hardened skill release |
| US-019 | 7 | open | US-018 | Run the four-laboratory retrospective and freeze the reproducible method |

Reading the board: US-001 through US-006, US-020 through US-024, and US-007 are recorded done. US-008 (independent acceptance of the Java-WebSocket lab) is the current gate and is deliberately still open: the child lab records 27/27 stories complete under owner-attested scope, but the master's strong independent-acceptance criteria are not met (0/26 strongly accepted, 24 formal obligations blocked, no independent custodian, no two-host resource envelope, cutover blocked). Everything from US-009 onward waits on it.

## Child laboratory index: verified-java-websocket-port

Location: the verified-java-websocket-port project folder next to the parent, under the same company (prd.json updated 2026-08-28T14:10:45Z). Branch: feature/verified-java-websocket-port. Code repo: repos/public/verified-java-websocket-port. Status: completed, completionScope STORY_EXECUTION_COMPLETE (owner-attested; independent acceptance is master US-008 and remains open). Inherits templates/child-prd/laboratory-template.json; lab manifest laboratories/java-websocket/manifest.json. A sibling verified-java-websocket-port-claude (branch claude/feature/verified-java-websocket-port, updated 2026-08-25) has the same 27 stories with 9 marked done; it is the Claude-runtime variant and is not the canonical child.

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

## Skill output so far

The port-java-to-rust skill folder under the enterprise-vibe-code company exists as a private, experimental draft (US-009 target): SKILL.md, CHANGELOG.md, references/workflow.md, references/oracle-and-assurance.md, references/runtime-isolation.md, references/websocket-lab-decisions.md, assets/assurance-case.md, assets/port-ledger.md. Its own header says it is informed by one owner-attested lab and is not yet an independently accepted or publishable method.
