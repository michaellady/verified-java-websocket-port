# PRD pack (copied from HQ)

Verbatim copies of the `verified-java-to-rust-port` PRD pack as delivered to
the goal-loop session by a bridge session on 2026-09-02, seven parts (the
pack was announced as six and grew to seven at part 4). **COMPLETE as of
2026-09-02**: all seven parts received, including the child laboratory PRD
whose 27 stories are this repository's own acceptance criteria. Snapshot
taken 2026-09-01 from HQ; master `prd.json` last updated 2026-08-29T12:22:36Z,
child `prd.json` 2026-08-28T14:10:45Z. These files are a rendering of the PRD,
not the byte-exact `prd.json`; digests recorded elsewhere against `prd.json`
bytes cannot be recomputed from them. Parts are added as they arrive.

| Part | File | Content |
| --- | --- | --- |
| 1 | `01-structure-and-index.md` | program structure, topology, master and child story indexes with status |
| 2 | `02-master-stories-foundation.md` | master stories US-001 to US-006 and US-024 in full (foundation wave) |
| 3 | `03-master-stories-intake-lsp-protocol-labzero.md` | master stories US-020 to US-023 (intake and cutover contracts, language-intelligence profiles, protocol runner, Laboratory Zero) and US-007 (this port's child-PRD generation) in full |
| 4 | `04-master-stories-acceptance-gate-and-skill-draft.md` | master US-008 (the open independent-acceptance gate for this laboratory, passes:false, with its running status log) and US-009 (the private skill-draft extraction, passes:false) in full |
| 5 | `05-master-stories-labs-2-4-and-publication.md` | master US-010 to US-019: CommonMark, the two-lab publication gate, cross-runtime forward tests, v1 publication, JSON Schema, Netty HTTP/2, and the retrospective — all passes:false, all behind US-008 |
| 6a | `06a-prd-metadata-goal-through-sandbox.md` | PRD metadata: goal, successCriteria, reviewPolicy, the 18 quality gates, relatedWorkers, knowledge, audiences, nonGoals, dataModel, authModel, architectureNotes, sandboxRuntimeProfile |
| 6b | `06b-prd-metadata-performance-through-threats.md` | PRD metadata: performanceRequirements, integrations, securityNotes, rolloutStrategy, monitoringNotes, assurance labels, snapshot and readiness states, error dispositions, artifact classifications, language-intelligence profiles, threatModel |
| 6c | `06c-prd-metadata-questions-decisions-execution.md` | PRD metadata: openQuestions, the 21 owner decisions, postImplementation, executionNotes (the programme waves), laboratories |
| 7a | `07a-child-prd-header-index-us001-008.md` | **the child laboratory PRD** — header, the 27-story index, and child US-001 to US-008 in full |
| 7b | `07b-child-prd-us009-us019.md` | child US-009 to US-019 in full (ConnectionCore through both Autobahn conformance modes) |
| 7c | `07c-child-prd-us020-us027.md` | child US-020 to US-027 in full (differential closure through independent acceptance) |

## What part 7 changes

Parts 7a to 7c are **this repository's own acceptance criteria**. Until they
arrived the story board in `.claude/GOAL-LOOP.md` was PROVISIONAL and the loop
was forbidden from inventing criteria. It no longer is: every child story now
has its criteria in full, verbatim, here.

Two cautions when reading them:

- **Master US-019 and child US-019 are different stories.** The master's
  US-019 is the four-laboratory retrospective; the child's is "Pass both
  pinned Autobahn conformance modes". Every "US-0nn" in the goal loop's board
  and queue is a CHILD story unless it says master.
- **The child PRD records all 27 stories as `passes: true` with
  completionScope STORY_EXECUTION_COMPLETE, and that is owner-attested, not
  independent.** Master US-008 is the independent acceptance gate and is open;
  its own status log reads 0 of 26 child entries strongly accepted. A child
  story marked done is not a story that has passed independent acceptance.
