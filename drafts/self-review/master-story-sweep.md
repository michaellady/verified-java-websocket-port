# master-story and PRD-metadata sweep — the half of the specification the amendment cannot reach

phase: F010-class sweep over the master stories and PRD metadata
date: 2026-09-04
branch: `claude/story-sweep-master`, worktree `/home/user/vjwp-stories`,
based on mainline `claude/feature/verified-java-websocket-port` at `6986e95`.
Every count below was recomputed in this worktree. Every exit code was read from
the process.

**What this closes.** `drafts/self-review/story-criterion-sweep.md` §5 names its
own two largest limits: *"the master PRD was not swept"* — the metadata parts
`06a`/`06b`/`06c` not at all and the master stories `02`–`05` not at all — and,
sharper, that its negative *"is not robust to a narrower reading of the
amendment"*. This record sweeps the corpus that sweep excluded, and it runs the
robustness test that sweep declined.

**The answer in one line.** TWO instances, both new, both in documents no Go
file, no gate and no self-review record in this repository has ever cited; and
the structural reason they were missed is that **the 2026-08-27 amendment
reaches nothing in this corpus at all**, so every clearance here rests on a
plane-scoped instrument rather than a document-scoped one.

---

## 1. The corpus, derived

### 1a. Master stories — 24 stories, 184 acceptance-criterion bullets

Derived, not read off a list. `find docs -type f` returns 23 files, of which the
PRD pack is `docs/prd-pack/*.md` (12 files). Parts `02`–`05` are the master
stories by the pack's own part table (`docs/prd-pack/README.md`). A parser over
those four files takes each `### US-NNN — <title>` header, then every `- ` bullet
between the literal line `**Acceptance criteria:**` and the next `**`-prefixed
block:

| file | stories | AC bullets |
|---|---:|---:|
| `02-master-stories-foundation.md` | 7 (US-001…US-006, US-024) | 58 |
| `03-master-stories-intake-lsp-protocol-labzero.md` | 5 (US-020…US-023, US-007) | 39 |
| `04-master-stories-acceptance-gate-and-skill-draft.md` | 2 (US-008, US-009) | 16 |
| `05-master-stories-labs-2-4-and-publication.md` | 10 (US-010…US-019) | 71 |
| **total** | **24** | **184** |

**Cross-checked against the PRD's own count.** `01-structure-and-index.md` §2
declares `userStories | array (24)`, and its §4 index lists exactly those 24 ids.
The derivation and the document's self-description agree, so 24 is a total and
not a floor.

### 1b. PRD metadata — 32 sections reproduced, and the PRD declares 39 keys

`grep -h "^### " docs/prd-pack/06[abc]-*.md` returns **32** section names.
`01-structure-and-index.md` §2 declares `metadata | object (39 keys)` and then
lists the sections *"all reproduced in Section 6"* — that list is **32 names**,
and it matches the 32 headings byte-for-byte in both directions (no name in the
list is missing from the pack; no heading in the pack is absent from the list).

**So seven metadata keys exist in the master `prd.json` and are not in this
repository.** The metadata half of this corpus is a **floor of 32/39**, not a
total. I cannot name the seven: `prd.json` lives at HQ, and `README.md` says the
pack *"is a rendering of the PRD, not the byte-exact `prd.json`"*. This is the
sweep's largest single ceiling and it is stated again in §6.

### 1c. What is NOT in the corpus, and why

`01-structure-and-index.md` and `README.md` are pack navigation — a topology
table, a story index with status, a part table. They carry no acceptance
criterion and no normative clause; I read both in full to establish that rather
than assuming it. `docs/prd-pack/07{a,b,c}` are the child PRD, which is the
prior sweep's corpus and not re-swept here.

---

## 2. The structural fact that makes this corpus different

**The 2026-08-27 amendment reaches no criterion in this corpus.**

`evidence/governance/decisions/us010-016-ac-amendment-owner-decision-2026-08-27.json`
(sha256 `26849b5ea74006504d18507ac694c00e882e7fd37d4cd8c8502ea824e96ea974`,
recomputed here) amends *"every AC clause of **US-010..US-016**"*. Two
independent reasons put this corpus outside it:

1. **Namespace.** `docs/prd-pack/README.md` warns in its own voice that
   *"Master US-019 and child US-019 are different stories … Every 'US-0nn' … is
   a CHILD story unless it says master."* The amendment's `context` names
   *"mask/noncanonical-length rejection, RFC close-code table + echo matching,
   RFC handshake validation gate, automatic-pong policy, control payload caps"*
   — every one a **child** US-010..US-016 subject. The **master's** US-010..
   US-016 are Pin CommonMark, Accept CommonMark, the two-lab publication gate,
   cross-runtime forward tests, Publish v1, Pin JSON Schema, Accept JSON Schema.
   The amendment is unambiguously about the child namespace.
2. **Instrument type.** Even read at its widest, it amends *AC clauses*. The two
   findings below sit in a metadata `nonGoals` bullet and in a master story
   outside US-010..US-016. Neither is an AC clause of US-010..US-016 under
   either namespace.

**Consequence, and it is the whole point of this sweep.** The prior sweep's
clearances lean on that amendment — its own §5 says *"if the owner reads
'requires rejecting, transforming, or augmenting' more narrowly than I have,
several of those clearances reopen at once."* Mine cannot lean on it at all.
Every clearance in this corpus that needs an instrument needs a different one:
`us009-us008-owner-decisions-2026-08-27.json` key `us009_normativity`, choice
`JAVA_FAITHFUL_PLUS_SAFE`. That decision's own `plane` field reads
**`"verified-java-websocket-port-claude (Claude authority plane)"`** — it is a
child-plane record. Whether a child-plane decision amends a master-plane
document is the interpretive question §4 tests, and it is the only one that
matters here.

---

## 3. The findings

Both were grepped against the decision store before being called findings, per
the rule F010's addendum 3 paid for. With `VJWP_PROTECTED_STORE` exported,

```
grep -rli "nongoal|oracle priority|oracle-priority|prd-pack|oracle hierarchy" \
  evidence/governance/decisions/
```

returns **exit 1, no matches**, and `grep -rli "master"` over the same directory
returns exactly one file, `company-move-record.json`, which is about a company
folder move. **No standing owner decision in the store names the master PRD, its
nonGoals, its metadata, or any master story.**

### Finding 1 (filed as F018) — the master nonGoal that forbids the port's whole stance

`docs/prd-pack/06a-prd-metadata-goal-through-sandbox.md:91`, the fourth
`nonGoals` bullet:

> Do not preserve undocumented Java quirks when a declared standard or neutral
> suite has higher oracle priority

**Measured, by the repository's own machinery.** `go run ./cmd/oraclerankctl
--root .` regenerates `evidence/oracle-hierarchy/adjudication-register.json`
**byte-identically** (`git status --porcelain` empty afterwards) and prints:

```
640 propositions, 589 Java/Rust agreements, 39 overridden by a higher oracle
```

The register's `accounting` block reads `higher_oracle_overrides: 41`,
`java_rust_consensus: 589`, `java_rust_consensus_overridden: 39`. Those 39 split:

| governing oracle | verdict Java+Rust agree on | governing verdict | count |
|---|---|---|---:|
| rank2 in-scope Autobahn (a **neutral suite**) | NON-STRICT | OK | 20 |
| rank1 RFC 6455 (a **declared standard**) | open | closed | 18 |
| rank3 neutral expectation | closing | closed | 1 |

That is the nonGoal's trigger condition — a declared standard or neutral suite
outranking a preserved Java behaviour — measured at **39** by a gate this
repository runs, not argued.

**And the quirks are Java's accidents, in the ledger's own hashed words.**
Recomputed over `evidence/java/behavior-delta-ledger.json` (59 records; 52
`unresolved`, 3 `adopt-java`, 3 `fix-in-port`, 1 `intentional-correction`), **26**
rationales assert an RFC requirement. **I first published 31 here from a loose
regex that also matched the substring `violat`, and the corrected number is
lower on two counts, both of which I had to check rather than assume.** Seven of
the 26 run the OTHER way — safe strengthenings where the port is *stricter* than
Java (sequences 36, 37, 38, the client-side handshake budgets, and 45, 46, 47, the
server-side budget corrections that supersede 14, 15, 16; plus 19, ws_core's
deliberate non-emulation of the untested negative-length path) — and that is
exactly the direction error the prior sweep documented against itself. One more
is superseded. **The honest count is 18 live records where the RFC requires
something and the port follows Java instead**: sequences 1, 2, 3, 4, 5, 6, 8,
17, 18, 23, 25, 29, 39, 42, 44, 48, 50, 53. Six verbatim:

- seq 1 — *"the RFC requires a Host header; the live pinned Java server accepted
  the request with no Host header (never examined)"*
- seq 6 — *"the RFC requires a base64 16-byte key; the live pinned Java server
  accepted a non-base64 key"*
- seq 17 — *"the RFC requires rejecting non-minimal length encodings with 1002;
  the pinned Java runtime performs no minimality check"*
- seq 18 — *"the RFC requires rejecting role-inappropriate masking with 1002;
  the pinned Java runtime accepts either masking toward either role"*
- seq 25 — *"the RFC requires a pong response to every ping; the pinned
  runtime's oracle-observable core never auto-pongs"*
- seq 48 — the class record, *"eighteen scenarios across ten families"*

"Never examined", "performs no minimality check" — these are accidental
behaviours of the Java implementation, which is what an *undocumented* quirk is.

**The clause has never been read.** `grep -rn "undocumented Java quirks"` over
the whole tree returns **1 hit: the PRD line itself.** `grep -rn "higher oracle
priority"` returns the same single line. Exactly one Go **package** in the
repository cites a master story at all — `internal/mutdenom`, at `model.go:403`
and `check.go:499`, both about US-002's dual-blind rule. (I first wrote "one Go
file" from a filename-only grep; widening it to the phrase
`master (prd|story|us-0)` returns those two files and nothing else.) Every other
PRD citation in Go points at `docs/prd-pack/07c-child-prd-us020-us027.md`.

Full argument, both readings, and the timeline that bears on them:
`drafts/self-review/findings/F018-a-master-nongoal-no-decision-reaches.md`.

### Finding 2 (filed as F019) — master US-020 AC5, hidden behind a name collision

`docs/prd-pack/03-master-stories-intake-lsp-protocol-labzero.md:13`:

> A Behavior Delta Ledger classifies every Java/Rust/spec disagreement as
> preserve, intentionally-correct with authoritative before-and-after evidence,
> or unresolved; **unresolved deltas block completion** and a refutation or
> later pass never erases the original finding or adjudication history.

**Recomputed.** 52 of 59 ledger records carry `disposition: "unresolved"`, while
`internal/deltaledger/definitions.go:23-29` states in production code that the
token is a spelling forced by the frozen 1.0.0 schema and that the divergence is
*"deliberately retained … not resolved"* — which is AC5's **`preserve`**.
Counting the records whose hashed rationale carries that retention marker:
**45** of the 52 are `preserve` by the port's own account, **7** are not, and of
those 7 three are superseded, leaving **4 live** (sequences 33, 35, 49, 53). So
the classification the artifact publishes is the criterion's term for neither
group, and `internal/lab/ledger.go:78-80` defines the very same token the other
way — *"no adjudication has been made … the decision is owed"*.

**AC5's blocking half is NOT breached here, and I corrected that claim before
filing.** I first wrote this as "the child declared `STORY_EXECUTION_COMPLETE`
with 52 unresolved deltas standing". `docs/prd-pack/01-structure-and-index.md:121`
refutes it: the 27/27 completion belongs to the **canonical** child, and *"a
sibling verified-java-websocket-port-claude (branch
`claude/feature/verified-java-websocket-port` …) has the same 27 stories with
**9 marked done**; it is the Claude-runtime variant and is not the canonical
child."* **This repository is that sibling** — its mainline branch is that
branch, every decision in the store carries `"plane":
"verified-java-websocket-port-claude"`, and `.claude/GOAL-LOOP.md:780` records
`Stories with passes: true | 9 (per handoff)`. This plane has declared no
completion for AC5 to block. The finding is therefore narrower than the one I
drafted, and F019 records the wrong version rather than deleting it.

**What does hold is that the blocking rule has no mechanism.**
`grep -rn "DispositionUnresolved"` over the tree returns six non-test lines in
three files; the only one that reads the value in a conditional,
`internal/deltaledger/adjudication.go:157`, uses it as a *permission* (a record
with no `mismatch_class` must be `unresolved`), never as a refusal.
`internal/lab/evidence.go:830-864` is the ledger's readiness verifier and it
checks supersession-link equality, `unledgered_disagreements == 0`,
`records_without_mismatch_class` against the chain, and that `status` is inside
`{READY, BLOCKED_PENDING_BASELINE}` — and nothing about unresolved dispositions.
The committed `status` **is** `BLOCKED_PENDING_BASELINE`, but
`assurance/concurrency/plan.json`'s `append_blocker` says why in its own words:
*"the Autobahn baseline is BLOCKED (0/247 both modes …), so ledger status stays
BLOCKED_PENDING_BASELINE."* A different condition entirely.

**The name collision is why four passes missed it.** `internal/ac5class` exists,
is named for "US-020 AC5", and its own header says
`US-020 AC5 (docs/prd-pack/07c-child-prd-us020-us027.md) names seven defect
classes`. That is the **child's** US-020 AC5. The **master's** US-020 AC5 is a
different clause in a different document, and its distinguishing phrase
`intentionally-correct` appears **exactly once in the repository** — in the
master PRD. A package named for the criterion made the criterion look covered.

Full argument, the floor of 4 that survives even the generous reading, and the
two contradictory in-tree definitions of `unresolved`:
`drafts/self-review/findings/F019-a-criterion-hidden-behind-its-own-namesake.md`.

---

## 4. The robustness test — every clearance re-run under the narrowest reading

This is the half the prior sweep declined, and it is the reason this record
exists. For each criterion cleared, the question is: **did the clearance need an
interpretive instrument, or did it rest on a measurement?**

### 4a. Clearances that rest on measurement and cannot flip

Nothing an owner rules changes any of these; they are facts about the tree.

| criterion | measurement | reading |
|---|---|---|
| `nonGoals` "Do not use first-party unsafe Rust" | `forbid(unsafe_code)` present in all five crates; `grep -rn "unsafe "` over `rust/*/src/` returns **1** line, a doc comment | satisfied |
| `qualityGates` "No undeclared stub, `todo!`, `unimplemented!` …" | `grep -rn "todo!\|unimplemented!" rust/*/src/` returns **0**; `#[ignore]` in `rust/` returns **0** | satisfied |
| `nonGoals` "Do not require TLS/WSS, RFC 7692 …, proxies, reconnect, Android, or Java API parity"; master US-007 AC2's exclusion list | `grep -rniE "\btls\b\|\bwss\b\|\bproxy\b\|reconnect\|permessage\|deflate\|android"` over `rust/*/src/`, unfiltered, returns exactly **1** line — `rust/ws-testee/src/lib.rs:9`, the doc comment declaring their absence (*"no TLS, proxy, reconnect, async runtime"*). Zero implementations | satisfied |
| master US-021 AC6, master US-023 AC2, `qualityGates` "LSP output is DeveloperToolRun with `assurance_claims: []`" | every `assurance_claims` in `assurance/` is `[]`; the three schemas pin `maxItems: 0` | satisfied |
| master US-020 AC5 **second half** — "never erases the original finding or adjudication history" | frozen prefix through sequence 35 intact; `supersessions` carries 6 links (14→45, 15→46, 16→47, 34→57, 55→58, 58→59), all superseded records still in the chain | satisfied |
| `architectureNotes` "every Java/Rust/spec disagreement enters the Behavior Delta Ledger"; `qualityGates` "Zero unexplained … differential mismatches" | `unledgered_disagreements` recomputes to **0** | satisfied |

### 4b. Clearances that FLIP under the narrowest defensible reading

These are the real product of this sweep. Each clears today; each stops clearing
if the narrow reading is taken. **Both findings above are in this class, which is
why they are filed as findings rather than as violations.**

| criterion | what the generous reading supplies | the narrowest defensible reading | flips? |
|---|---|---|---|
| **`nonGoals` #4** (F018) | *undocumented* = undocumented anywhere, and all 39 are documented in the ledger; and `JAVA_FAITHFUL_PLUS_SAFE` states the owner's stance for every behavioural question the port asks | *undocumented* describes the quirk in **Java's** documentation, which the ledger cannot retroactively supply; and a decision whose own `plane` is the child plane does not amend a master-plane nonGoal | **yes** |
| **master US-020 AC5** vocabulary half (F019) | the 52 `unresolved` are a frozen-vocabulary artifact meaning `preserve`, per `internal/deltaledger/definitions.go:23-29` and the 1.2.0 schema's own mapping onto `PRESERVE / INTENTIONALLY_CORRECT / UNRESOLVED`, so only 4 live records are truly unresolved | the ledger's face value is what AC5 reads, and `internal/lab/ledger.go:78-80` defines the very term as *"no adjudication has been made. The mismatch stands and the decision is owed"*, so 45 records are misclassified | **yes** — and the published 52 is the criterion's number under neither reading |
| **master US-020 AC5** blocking half — *"unresolved deltas block completion"* | this plane has declared no completion (9/27, not the canonical child's 27/27), so there is nothing for the rule to block | the rule has **no mechanism at all** in the tree, so it could not fire if this plane did declare completion | **no breach either way** — this is a missing gate, not a violation, and F019 says so after I corrected the opposite claim |
| **master US-004 AC3** — the divergence ledger must carry *"independent attestations"* | US-004 governs the **parent's** formal preflight, whose Files list is parent-side; this lab's ledger is not its subject | the clause is written generally over *"every … Java-only quirk, standards divergence"*, and this lab's ledger is an instance carrying none | **yes** — but a **standing published block already covers it**: the child is `OWNER_ATTESTED_NOT_INDEPENDENT` and master US-008 records *0/26 strongly accepted*. Not filed; re-filing it would be the false positive the task warns about |
| **`nonGoals` #17 / master US-024 AC2** — no closely adapted material without attribution and required notices | `THIRD_PARTY_NOTICES.md` and `references.md` are **parent** artifacts by `01-structure-and-index.md`'s own project layout, and US-024's Files list is parent-side | this repository is public, `LICENSE` is Apache-2.0, the pinned source is MIT, and `find . -iname "*NOTICE*"` returns **nothing** | **yes** — but it is a **publication-gate** obligation (master US-014 AC5, `postImplementation`) and publication is blocked. Recorded as a residual, not filed |
| **`qualityGates` #18** — no requirement-bearing test skipped because the runtime makes it inconvenient | the 37 `t.Skip` sites are harness-environment guards (*"not in a git checkout"*, *"symlinks unavailable"*, *"no allowances declared"*), not requirement-bearing tests | *"symlinks unavailable"* is a runtime inconvenience by the clause's own words | **partially** — Rust is 0 either way; the Go residual is 37 and is named here rather than cleared silently |

### 4c. A clearance I checked and would not let flip

**`nonGoals` #10** — *"Do not treat compilation, … a green aggregate command, LSP
diagnostics, model agreement, or document completeness as evidence of behavioral
completeness."* This is the nearest thing in the corpus to a clause condemning
this repository's own working style, and the temptation to file it is exactly
F010's mirror error: condemning against a clause it satisfies, because
condemning is the expected direction. It satisfies it. `completionScope
STORY_EXECUTION_COMPLETE` is owner-attested and is separated from acceptance
everywhere it appears; master US-008 is `passes: false` with its blockers
enumerated; the Autobahn baseline is carried as `BLOCKED 0/247` rather than
inferred from a green suite; and `cmd/taskgraphctl` refuses a node whose only
evidence is a `command` with `UNVERIFIABLE_DONE`, which is this clause built
into a gate. **No conflict, and I am recording that I looked.**

---

## 5. The rest of the corpus, said as coverage rather than waved at

Of the 184 master AC bullets, the subject of **most** is an artifact in the
**parent** repository — `program-registry.json`, `foundation/`, `protocol/`,
`laboratories/lab-zero/`, `mike-skills/`, `forward-tests/`. A criterion whose
subject does not exist here cannot be violated here, and the F010 class needs a
criterion that forbids something **this port does**.

- **US-001, US-002, US-003, US-005, US-006, US-021, US-022, US-023, US-024** —
  foundation and protocol-runner deliverables. Their Files lists are parent-side
  without exception. The clauses that reach into a child (US-002 AC4's common
  gate profile, US-003's corpus tiers, US-021 AC6's DeveloperToolRun rule) are
  cleared in §4a or are unrun gates named in §6.
- **US-004** — the formal preflight. AC3 is the §4b row above.
- **US-020** — AC5 is Finding 2. AC7 (readiness ladder, no state skipped) and AC8
  (the pinned Java executable stays runnable) are satisfied: no readiness state is
  claimed past the ladder's foot — master US-008's own Notes record *"US-026
  remains CUTOVER_BLOCKED without live traffic, measured rollback/soak, or
  executable Java fallback drill"* — and the oracle is rebuildable from
  `java-oracle/` against the pinned jar (`java-oracle/pom.xml:28-29`,
  `org.java-websocket:Java-WebSocket`). AC9 lowers a ceiling rather than
  forbidding a behaviour.
- **US-007** — this lab's planning story. AC2's exclusion list is §4a. AC5's
  *"explicit oracle-priority and divergence policy"* is satisfied by child US-020
  AC2 and `internal/oraclerank`. AC1/AC3/AC4/AC6/AC7 constrain the child PRD's
  authoring, which happened at HQ.
- **US-008** — the acceptance gate. Its criteria are things the audit must
  **find**, not things the port must **avoid**; the story's own Notes enumerate
  what is missing. Nothing here is F010-class by direction.
- **US-009** — the skill draft, in `mike-skills`. Not in this repository.
- **US-010 through US-019** — CommonMark, JSON Schema, Netty HTTP/2, publication
  and the retrospective. `passes: false`, all behind US-008. The only clauses
  that touch this lab are consumers of its evidence (US-011 AC7 replays against
  *"the frozen WebSocket acceptance fixtures"*; US-012 AC2 maps WebSocket
  decisions; US-014 AC3 links its case study). None forbids a port behaviour.
- **PRD metadata** — the 32 reproduced sections. Twenty are enumerations or
  descriptions with no prohibition (`assuranceLabels`, `snapshotStates`,
  `productionReadinessStates`, `errorDispositions`, `artifactClassifications`,
  `laboratories`, `knowledge`, `audiences`, `relatedWorkers`, `baseBranch`,
  `delightOpportunities`, `openQuestions`, `postImplementation`, `dataModel`,
  `integrations`, `threatModel`, `monitoringNotes`, `rolloutStrategy`,
  `languageIntelligenceProfiles`, `goal`). The twelve with normative force —
  `qualityGates` (18 clauses), `nonGoals` (17 clauses), `decisions` (21 owner
  decisions), `successCriteria`, `reviewPolicy`, `architectureNotes`,
  `securityNotes`, `authModel`, `currentSolution`, `sandboxRuntimeProfile`,
  `performanceRequirements`, `executionNotes` — were read clause by clause and
  land in §3, §4a, §4b, §4c or §6.

**One metadata `decisions` entry deserves naming, because it points the other
way.** *"How are verification failures handled?"* → *"Fail closed: disagreements,
flakes, exclusions, timeouts, proof mismatches, mutation survivors, resource
breaches, and security findings **block until explicitly classified**"* (decided
2026-08-22 by Mike Lady). This is a standing owner decision that **reinforces**
master US-020 AC5 rather than clearing it. The grep-the-decisions rule is not
only a false-positive filter; it can strengthen a finding, and here it does.

---

## 6. Ceiling — what this sweep did not cover, and why

Each item is a real limit, not a hedge.

1. **The metadata corpus is a floor of 32 of 39 keys.** Seven keys of the master
   `prd.json` metadata object are declared in `01-structure-and-index.md` §2 and
   are not reproduced in the pack. I cannot name them, because `prd.json` is not
   in this repository and the pack is *"a rendering … not the byte-exact
   prd.json"*. **A criterion living in one of those seven keys is invisible to
   this sweep.** This is the single largest hole and no work inside this
   repository can close it.
2. **The master story corpus is a total, but its *text* is a rendering.** The
   README says digests recorded against `prd.json` bytes cannot be recomputed
   from these files. So 24/184 is exact for the pack and unverified against HQ.
   A clause edited at HQ after the 2026-09-01 snapshot is not here.
3. **Both findings turn on a reading, and I have not resolved either.** F018
   turns on what *undocumented* modifies; F019 on whether the ledger's face value
   or its documented intent is what AC5 reads. Both are owner questions and §4b
   states each side. I decline to answer them, and neither finding claims the
   port is wrong — each claims that its correctness is currently an
   interpretation rather than a fact.
4. **The protected store was read only as committed bytes.** With
   `VJWP_PROTECTED_STORE` exported I read
   `evidence/governance/decisions/`. `evidence/governance/owner-decision-digests.json`
   states in its own words that the authoritative records *"live in the workspace
   orchestrator's immutable protected store and are deliberately NOT committed"*.
   I verified the amendment by recomputing the sha256 of the committed copy
   (`26849b5e…`, matching the digest every ledger rationale asserts); I did not
   recompute against the orchestrator's copy. **A decision that exists only in
   the orchestrator store and bears on a master criterion would not have been
   found by my grep.**
5. **No owner gate was triggered.** No AWS run, no benchmark, no Autobahn re-run.
   Every wire claim rests on committed evidence plus the local Go/Rust suites.
   The 20 Autobahn rows inside F018's 39 come from
   `evidence/autobahn/native-x86_64-provenance/`, a committed run I did not
   re-execute and am not authorised to.
6. **rank1 is bound to a recorded reading, not to the RFC.** The register says so
   itself, and the disclosure matters to F018's 18 rank-one rows:
   `rank1-rfc6455` is `CONTENT_BOUND_TO_RECORDED_READING`, and *"a misreading
   would pass this gate unchanged."* F018's rank-one count inherits that
   weakness; its rank-two Autobahn count does not.
7. **I did not sweep the child PRD**, did not re-measure the prior sweep's two
   instances, and changed no Rust source. `git status --porcelain -- rust/` is
   empty in this worktree.
8. **One head, one platform.** Linux x86_64 at `6986e95`.
9. **The 37 Go `t.Skip` sites were classified by their skip message, not by
   executing each.** §4b names the residual rather than clearing it.
10. **This sweep sees ONE of the two child planes.** `01-structure-and-index.md:121`
    records that the canonical child (27/27, `STORY_EXECUTION_COMPLETE`) and this
    Claude-runtime sibling (9/27) are different projects with the same 27 stories.
    Every artifact I recomputed — the 59-record ledger, the 640-proposition
    register, the 63-record decision store — is **this plane's**. A master
    criterion breached by the canonical child's ledger or its evidence is
    invisible from here, and the completion declaration master US-020 AC5's
    blocking rule would actually bind is that child's, not this one's. I read
    this line late and it refuted a claim I had already written; §3's Finding 2
    and F019 both carry the correction rather than the original.

---

## 7. Corpus and denominators — unchanged

Nothing was re-baselined. Recomputed and equal to the committed values:
**59** ledger records (52 `unresolved` / 3 `adopt-java` / 3 `fix-in-port` /
1 `intentional-correction`), `unledgered_disagreements` **0**,
`records_without_mismatch_class` **49**, **49** legacy adjudications
(27 `java-quirk` / 20 `underspecified-behavior` / 2 `rust-defect`), **640**
oracle-rank propositions with **39** overridden. `origin/codex/race-catchup` was
neither read nor written. `cmd/oraclerankctl` was run and its output was
**byte-identical** to the committed register, verified by an empty
`git status --porcelain`.

The master-story count **184** and metadata-section count **32** are new
denominators introduced by this record, derived mechanically in §1, and they
replace nothing.

## 8. Owner actions

1. **Rule on `nonGoals` #4 (F018).** Does the master PRD's *"Do not preserve
   undocumented Java quirks when a declared standard or neutral suite has higher
   oracle priority"* reach the 39 propositions the port's own register enrols? A
   YES makes 39 measured overrides a program-level nonGoal breach; a NO should
   say which reading of *undocumented* is intended, and whether a child-plane
   normativity decision can amend a master-plane nonGoal at all. **The port needs
   no change under either answer** — what changes is whether its stance is
   compliant or tolerated.
2. **Rule on master US-020 AC5 (F019).** Do the 52 `unresolved` dispositions
   count as AC5's `unresolved` on their face, or does
   `internal/deltaledger/definitions.go`'s account govern and make 45 of them
   `preserve`? The published 52 is the criterion's number under neither reading.
   Separately: should AC5's *"unresolved deltas block completion"* have a
   mechanism? It has none, and this plane is 9/27 rather than complete, so the
   absence has cost nothing yet. Under the most generous reading **4** live
   records (sequences 33, 35, 49, 53) remain unresolved, and sequence 53 is the
   only one of the four citing no owner decision at all.
3. **Supply the seven unreproduced metadata keys**, or confirm that none carries
   a criterion constraining port behaviour. Ceiling item 1 cannot be closed from
   inside this repository.

## 9. Gates

### 9a. Two runs were discarded before one was trusted, and why

**Run 1 — REFUSED, not failed, and a refusal is not a pass.**
`make -C rust gates` with only `VJWP_PROTECTED_STORE` exported stopped at
`go-suite`:

```
gate=go-suite result=REFUSED reason=".quarantine/ is not staged in this tree, so
  the packages that consume the pinned Java source cannot be told apart from ones
  that are genuinely broken. This is a refusal, not a failure, and not a skip."
  remedy="ln -s /home/user/verified-java-websocket-port/.quarantine ./.quarantine"
make: *** [Makefile:137: go-suite] Error 1        exit 2
```

Remedied exactly as the gate prescribes: the `.quarantine` symlink was created,
and `.gitignore:36` — which exists specifically because *"agents isolate by
symlinking .quarantine into their worktree"* — keeps it out of git. Verified with
`git check-ignore -v .quarantine` and an empty `git status --porcelain`. The
pinned JDK was also put on PATH (`javac 17.0.19`, against the container default
`javac 21.0.10`), because without it `internal/portplan` fails
`JAVAC_UNAVAILABLE` in a way that reads like a broken pin and is not.
**Nothing was relaxed to get past either condition.**

**Run 2 — DISCARDED as unattributable, which is the more interesting one.**
Run 2 was progressing normally when its log turned out to be shared. The head of
my own log file read:

```
VJWP_PROTECTED_STORE=/home/user/vjwp-prose/evidence/governance/decisions
make: Entering directory '/home/user/vjwp-prose/rust'
```

A **different session**, working in `/home/user/vjwp-prose`, was writing to the
same path in what is nominally a session-private scratchpad directory. Confirmed
from `/proc`: its process tree has `cwd=/home/user/vjwp-prose` and its wrapper
script runs the same `make -C rust gates`. My own run was alive and legitimate
throughout (`pid 5532 make -C rust gates cwd=/home/user/vjwp-stories`,
`pid 9331 formalplan.test cwd=/home/user/vjwp-stories/internal/formalplan`) — but
its **stdout and its exit file were no longer attributable to it**, and an exit
code I cannot attribute is not a measurement of my tree. It was discarded rather
than reported.

This is F012's class in a new place: F012 was two agents in one working *tree*;
this is two agents in one output *directory*, and it is quieter, because nothing
breaks — you simply read someone else's number and believe it. **The only reason
it was caught is that the log's first line names a worktree, so attribution was
checkable at all.** A log without that line would have been indistinguishable.

My processes were stopped by a kill scoped through `/proc/<pid>/cwd`, never by
pattern — four pids, every one verified under `/home/user/vjwp-stories` before
and after — and the other session's run was left untouched.

### 9b. The trusted run — exit 0

Re-run with output isolated to a uniquely named private directory and a header
line that makes attribution checkable, which is the whole lesson of 9a:

```
WORKTREE=/home/user/vjwp-stories
javac=javac 17.0.19
STORE=/home/user/vjwp-stories/evidence/governance/decisions
...
make: Leaving directory '/home/user/vjwp-stories/rust'
```

**`make -C rust gates` → exit 0**, read from `echo $?` written by the run's own
wrapper into that private file, never from a summary line.

- **89** `test result: ok` blocks; **51** `ok` Go package lines; **0** lines
  matching `FAILED|panic:|^--- FAIL`; zero `make: ***` lines.
- Every gate verdict, unique: `adapter-linkage`, `audit`, `canaries`,
  `dependency-inventory`, `fixture-liveness-guard`, `forbid-unsafe`, `go-suite`,
  `license`, `lockfile`, `msrv`, `pin-dangling`, `record-content-precondition`,
  `task-graph` — **all PASS**. `ac1-gates verdict=PASS gates_passed=8/8`.
- `go-suite packages=62 run=61 excluded=1`, and the one exclusion is declared
  and re-derived rather than skipped: `internal/lab`,
  *"CONTROLLED_CANARY requires Darwin sandbox-exec; PLATFORM_EXECUTOR_UNSUPPORTED"*
  — the standing `OA-macos-arm64-host` owner action, and the gate records that
  the excluded package was RUN and still fails, so the exclusion is measured.
- The ledger governance arm ran with the protected store **reachable**, not
  refused: *"owner-decision-digests.json equals the derivation and 7 governance
  record digest(s) recomputed from the protected store and matched."*

**The gate re-derived this sweep's own headline number.** Its final step is
`go run ./cmd/oraclerankctl --root . --check`, which printed:

> 640 propositions adjudicated; 589 Java/Rust agreements, **39** of them
> overridden by a higher oracle and every one enrolled in
> `evidence/oracle-hierarchy/adjudication-register.json`

That is F018's count of the master nonGoal's trigger condition, recomputed by the
repository's own gate in a run this record did not author. It is the strongest
form the measurement could take here.

**Timing, recorded because a reading without it invites a false regression
report.** The other session's concurrent gates run put nine competing processes
on four CPUs for part of this run: `internal/assurance` took 21.8s in a quiet
window and over 150s under that contention, consistent with the 3.6x slowdown
this repository already documents. `df -h /` read **9.3G available** before the
run, so no result here is a full disk wearing a regression's clothes.

## Status

COMPLETE. Two findings filed (F018, F019), two interpretation-dependent
clearances recorded without filing because standing blocks already cover them
(master US-004 AC3, `nonGoals` #17), one candidate examined and cleared in the
port's favour (`nonGoals` #10), and the corpus stated as a total for the master
stories (24 / 184) and a floor for the metadata (32 of 39).
